package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/manifest"
)

// TestReadAPIAnswersEveryKnownType pins the read API's four type surfaces to
// manifest.AllTypes. Each carried its own switch or struct listing seven
// types, so a stored crate 404'd on /packages/{type} and /packages/{type}/
// {name} and went missing without an error from /packages and /status: a
// client could not tell an ecosystem holding nothing from one the envelope
// had no key for. The test asserts against AllTypes rather than a list of its
// own, and covers every surface, because dropping a type from any one of them
// has to fail here.
func TestReadAPIAnswersEveryKnownType(t *testing.T) {
	s, _, _ := refreshTestServer(t)
	for _, typ := range manifest.AllTypes {
		pm := &manifest.PackageManifest{
			ConfigVersion: manifest.CurrentConfigVersion,
			Name:          "parity",
			Type:          typ,
			Versions:      []manifest.VersionEntry{{Version: "1.0.0"}},
		}
		if err := s.store.SavePackage(t.Context(), pm); err != nil {
			t.Fatalf("seed %q: %v", typ, err)
		}
	}

	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	get := func(t *testing.T, path string) (int, []byte) {
		t.Helper()
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return resp.StatusCode, body
	}

	code, body := get(t, "/api/v1/packages")
	if code != http.StatusOK {
		t.Fatalf("GET /api/v1/packages: status = %d, want 200", code)
	}
	var envelope map[string][]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}

	code, body = get(t, "/api/v1/status")
	if code != http.StatusOK {
		t.Fatalf("GET /api/v1/status: status = %d, want 200", code)
	}
	var status struct {
		EntryCount map[string]int `json:"entry_count"`
	}
	if err := json.Unmarshal(body, &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}

	for _, typ := range manifest.AllTypes {
		t.Run(typ, func(t *testing.T) {
			entries, ok := envelope[typ]
			if !ok {
				t.Errorf("GET /api/v1/packages: no %q key, so a client cannot tell an empty ecosystem from an unknown one", typ)
			} else if len(entries) == 0 {
				t.Errorf("GET /api/v1/packages: %q key is empty, but a %s package is stored", typ, typ)
			}

			if _, ok := status.EntryCount[typ]; !ok {
				t.Errorf("GET /api/v1/status: entry_count has no %q key, so a monitor under-reports the fleet by every %s entry", typ, typ)
			} else if status.EntryCount[typ] < 1 {
				t.Errorf("GET /api/v1/status: entry_count[%q] = %d, want at least 1", typ, status.EntryCount[typ])
			}

			for _, path := range []string{
				"/api/v1/packages/" + typ,
				"/api/v1/packages/" + typ + "/parity",
				"/api/v1/packages/" + typ + "/parity/1.0.0",
			} {
				if code, body := get(t, path); code != http.StatusOK {
					t.Errorf("GET %s: status = %d, want 200; body: %s", path, code, body)
				}
			}
		})
	}
}

// The read routes take no token, and a manifest url may carry the credential
// its upstream wants. The entry is an ordinary one: no generated, no
// contradiction, a 200 on every route. The password and the username are
// asserted apart because the username is withheld on purpose: a token written
// as https://<token>@host/ is a username to url.URL.Redacted.
func TestReadAPIWithholdsManifestURLUserinfo(t *testing.T) {
	const (
		user   = "audit-user"
		secret = "audit-secret"
		abi    = "FreeBSD:14:amd64"
	)
	s := hostedServer(t)
	addVersion(t, s, manifest.TypeFreeBSD, "private", manifest.VersionEntry{
		Version: abi,
		URL:     "https://" + user + ":" + secret + "@private-upstream.example/" + abi + "/latest",
	})

	for _, path := range []string{
		"/api/v1/packages",
		"/api/v1/packages/" + manifest.TypeFreeBSD,
		"/api/v1/packages/" + manifest.TypeFreeBSD + "/private",
		"/api/v1/packages/" + manifest.TypeFreeBSD + "/private/" + abi,
	} {
		t.Run(path, func(t *testing.T) {
			code, body := getStatusAndBody(t, s, path)
			if code != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200: %s", path, code, body)
			}
			if withheldFrom(body, secret) != "" {
				t.Errorf("GET %s publishes the url's password to a caller with no token: %s", path, body)
			}
			if withheldFrom(body, user) != "" {
				t.Errorf("GET %s publishes the url's username to a caller with no token: %s", path, body)
			}
			if !strings.Contains(body, "private-upstream.example/"+abi+"/latest") {
				t.Errorf("GET %s drops the url's host and path, which carry no credential and say where the entry comes from: %s", path, body)
			}
		})
	}

	pm, err := s.store.GetPackage(t.Context(), manifest.TypeFreeBSD, "private")
	if err != nil || pm == nil || !strings.Contains(pm.Versions[0].URL, secret) {
		t.Errorf("the stored url lost its credential after the reads, so the next fetch goes out anonymous: %+v, %v", pm, err)
	}
}

// Every form a url can carry userinfo in, on every read route, from a caller
// outside every admin range and with no Authorization header. The contracted
// fixture above is one form; a scheme-relative authority and a bare username
// are the ones a cut that only looks after "://" misses.
func TestReadAPIWithholdsUserinfoInEveryForm(t *testing.T) {
	const abi = "FreeBSD:14:amd64"
	for _, raw := range []string{
		"//audit-user:audit-secret@private-upstream.example/" + abi + "/latest",
		"//audit-user@private-upstream.example/" + abi + "/latest",
		"https://audit-user@private-upstream.example/" + abi + "/latest",
		"https:audit-user:audit-secret@private-upstream.example/" + abi + "/latest",
	} {
		t.Run(raw, func(t *testing.T) {
			s := hostedServer(t)
			addVersion(t, s, manifest.TypeFreeBSD, "private", manifest.VersionEntry{Version: abi, URL: raw})
			for _, path := range []string{
				"/api/v1/packages",
				"/api/v1/packages/" + manifest.TypeFreeBSD,
				"/api/v1/packages/" + manifest.TypeFreeBSD + "/private",
				"/api/v1/packages/" + manifest.TypeFreeBSD + "/private/" + abi,
			} {
				req := httptest.NewRequest(http.MethodGet, path, nil)
				req.RemoteAddr = "203.0.113.9:40000"
				rr := httptest.NewRecorder()
				s.Handler().ServeHTTP(rr, req)
				body := rr.Body.String()
				if rr.Code != http.StatusOK {
					t.Fatalf("GET %s = %d, want 200: %s", path, rr.Code, body)
				}
				if withheldFrom(body, "audit-secret") != "" {
					t.Errorf("GET %s publishes the url's password: %s", path, body)
				}
				if withheldFrom(body, "audit-user") != "" {
					t.Errorf("GET %s publishes the url's username: %s", path, body)
				}
			}
		})
	}
}

// The web UI names a binary's download by the last segment of the url the read
// API publishes. For a url with no path that segment was the authority, and the
// object is still stored under it, so the link built from the public url has
// to reach the stored object without the credential appearing anywhere the UI
// reads. getClientUrl in web/index.html is reproduced here: entry.filename,
// else entry.url.split('/').pop().
func TestBinaryDownloadLinkFromThePublicManifest(t *testing.T) {
	for _, raw := range []string{
		"https://audit-user:audit-secret@private-upstream.example",
		"//audit-user:audit-secret@private-upstream.example",
		"https://audit-user@private-upstream.example",
	} {
		t.Run(raw, func(t *testing.T) {
			s := hostedServer(t)
			ve := manifest.VersionEntry{Version: "1.0.0", URL: raw}
			addVersion(t, s, manifest.TypeBinary, "tool", ve)
			pm, err := s.store.GetPackage(t.Context(), manifest.TypeBinary, "tool")
			if err != nil {
				t.Fatal(err)
			}
			keys, err := manifest.ArtifactKeys(pm, ve)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.typeStore(manifest.TypeBinary).Put(t.Context(), keys[0], []byte("ELF")); err != nil {
				t.Fatal(err)
			}

			code, body := getStatusAndBody(t, s, "/api/v1/packages/binary/tool/1.0.0")
			if code != http.StatusOK {
				t.Fatalf("read: %d %s", code, body)
			}
			if withheldFrom(body, "audit-secret", "audit-user") != "" {
				t.Fatalf("the manifest the UI reads publishes userinfo: %s", body)
			}
			entry := decodeJSON(t, body)["versions"].([]any)[0].(map[string]any)
			filename, _ := entry["filename"].(string)
			if filename == "" {
				parts := strings.Split(entry["url"].(string), "/")
				filename = parts[len(parts)-1]
			}
			path := "/binaries/tool/1.0.0/" + filename
			code, got := getStatusAndBody(t, s, path)
			if code != http.StatusOK || got != "ELF" {
				t.Errorf("GET %s = %d %q, want 200 \"ELF\" from %s", path, code, got, keys[0])
			}
		})
	}
}

// git reads an authority where a browser does not: the scp form ends its host
// at the first ":" and "ssh://" at the first "/", so "#" and "?" are part of
// the username ssh is handed. Each marker is asserted on its own, on every
// route, from outside every admin range with no Authorization header.
func TestReadAPIWithholdsGitUserinfo(t *testing.T) {
	for _, raw := range []string{
		"audit-user#audit-secret@private-upstream.example:repo.git",
		"audit-user?audit-secret@private-upstream.example:repo.git",
		"audit-user@private-upstream.example:repo.git",
		"ssh://audit-user#audit-secret@private-upstream.example/repo.git",
		"ssh://audit-user%40private-upstream.example/repo.git",
	} {
		t.Run(raw, func(t *testing.T) {
			s := hostedServer(t)
			addVersion(t, s, manifest.TypeGit, "private", manifest.VersionEntry{Ref: "v1", URL: raw})
			for _, path := range []string{
				"/api/v1/packages",
				"/api/v1/packages/" + manifest.TypeGit,
				"/api/v1/packages/" + manifest.TypeGit + "/private",
				"/api/v1/packages/" + manifest.TypeGit + "/private/v1",
			} {
				req := httptest.NewRequest(http.MethodGet, path, nil)
				req.RemoteAddr = "203.0.113.9:40000"
				rr := httptest.NewRecorder()
				s.Handler().ServeHTTP(rr, req)
				body := rr.Body.String()
				if rr.Code != http.StatusOK {
					t.Fatalf("GET %s = %d, want 200: %s", path, rr.Code, body)
				}
				if withheldFrom(body, "audit-secret") != "" {
					t.Errorf("GET %s publishes the password half of %q: %s", path, raw, body)
				}
				if withheldFrom(body, "audit-user") != "" {
					t.Errorf("GET %s publishes the username of %q: %s", path, raw, body)
				}
			}
		})
	}
}

// Unversioned binary entries share one directory, so a download name derived
// from a redacted url can land on another entry's object. Starting from the
// manifest the UI reads, every entry's link has to return that entry's own
// bytes, with no credential in the manifest or the link. The fixture holds the
// redacted name as another entry's explicit filename, and two urls that redact
// to the same host.
func TestBinaryDownloadLinksReachTheirOwnBytes(t *testing.T) {
	s := hostedServer(t)
	pm := &manifest.PackageManifest{Type: manifest.TypeBinary, Name: "tool", Versions: []manifest.VersionEntry{
		{URL: "https://audit-user:" + "audit-secret@private-upstream.example"},
		{URL: "https://public.example/other", Filename: "private-upstream.example"},
		{URL: "https://other-user@private-upstream.example"},
		{URL: "audit-user#audit-secret@private-upstream.example"},
	}}
	if err := s.store.SavePackage(t.Context(), pm); err != nil {
		t.Fatal(err)
	}
	payloads := []string{"PRIVATE-ELF", "OTHER-ELF", "SECOND-PRIVATE-ELF", "SCHEMELESS-ELF"}
	for i, ve := range pm.Versions {
		keys, err := manifest.ArtifactKeys(pm, ve)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.typeStore(manifest.TypeBinary).Put(t.Context(), keys[0], []byte(payloads[i])); err != nil {
			t.Fatal(err)
		}
	}

	code, body := getStatusAndBody(t, s, "/api/v1/packages/binary/tool")
	if code != http.StatusOK {
		t.Fatalf("read: %d %s", code, body)
	}
	if withheldFrom(body, "audit-secret", "audit-user", "other-user") != "" {
		t.Fatalf("the manifest the UI reads publishes userinfo: %s", body)
	}
	for i, v := range decodeJSON(t, body)["versions"].([]any) {
		entry := v.(map[string]any)
		filename, _ := entry["filename"].(string)
		if filename == "" {
			parts := strings.Split(entry["url"].(string), "/")
			filename = parts[len(parts)-1]
		}
		path := "/binaries/tool/" + filename
		code, got := getStatusAndBody(t, s, path)
		if code != http.StatusOK || got != payloads[i] {
			t.Errorf("entry %d's UI link %s = %d %q, want 200 %q", i, path, code, got, payloads[i])
		}
	}

	for path, want := range map[string]string{
		"/binaries/tool/private-upstream.example":                         "OTHER-ELF",
		"/binaries/tool/audit-user:audit-secret@private-upstream.example": "PRIVATE-ELF",
	} {
		if code, got := getStatusAndBody(t, s, path); code != http.StatusOK || got != want {
			t.Errorf("stored path %s = %d %q, want %q", path, code, got, want)
		}
	}
}

// A download link read from the public manifest keeps reaching the bytes it
// was published for after the manifest changes, or answers 404. The artifacts
// come from builder.FetchBinaries against an upstream that serves each entry
// different bytes by its basic-auth username, since the binary fetch records
// nothing on the entry that tells two such entries apart; the links come from
// the read API as the web UI builds them.
func TestBinaryDownloadLinksSurviveManifestEdits(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _, _ := r.BasicAuth()
		body, ok := map[string]string{"first": "FIRST-ELF", "second": "SECOND-ELF", "third": "THIRD-ELF"}[user]
		if !ok {
			http.Error(w, "unknown user", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer upstream.Close()
	host := strings.TrimPrefix(upstream.URL, "http://")
	entry := func(user string) manifest.VersionEntry {
		return manifest.VersionEntry{URL: "http://" + user + ":audit-secret@" + host}
	}
	original := []manifest.VersionEntry{entry("first"), entry("second"), {URL: "https://public.example/" + host, Filename: host}}
	want := []string{"FIRST-ELF", "SECOND-ELF", "EXPLICIT-ELF"}

	links := func(t *testing.T, s *Server) []string {
		t.Helper()
		code, body := getStatusAndBody(t, s, "/api/v1/packages/binary/tool")
		if code != http.StatusOK {
			t.Fatalf("read: %d %s", code, body)
		}
		if withheldFrom(body, "audit-secret", "first", "second", "third") != "" {
			t.Fatalf("the manifest the UI reads publishes userinfo: %s", body)
		}
		var out []string
		for _, v := range decodeJSON(t, body)["versions"].([]any) {
			e := v.(map[string]any)
			name, _ := e["filename"].(string)
			if name == "" {
				parts := strings.Split(e["url"].(string), "/")
				name = parts[len(parts)-1]
			}
			out = append(out, "/binaries/tool/"+name)
		}
		return out
	}
	// fetch saves versions, runs the real fetch, and uploads what it produced
	// under the keys the uploader derives. An entry the fetch cannot reach is
	// put by hand: the explicit filename, and an edit's copied name.
	fetch := func(t *testing.T, s *Server, versions []manifest.VersionEntry, byHand map[string]string) {
		t.Helper()
		pm := &manifest.PackageManifest{Type: manifest.TypeBinary, Name: "tool", Versions: versions}
		if err := s.store.SavePackage(t.Context(), pm); err != nil {
			t.Fatal(err)
		}
		cfg := &builder.Config{BuildRoot: t.TempDir(), BuildEnvInfo: &manifest.BuildEnv{Platform: "linux/arm64"}}
		builder.FetchBinaries(cfg, s.store, "tool")
		for _, p := range builder.BinaryArtifactPaths(cfg, s.store, "tool") {
			content, err := os.ReadFile(p.Local)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.typeStore(manifest.TypeBinary).Put(t.Context(), p.ObjectKey, content); err != nil {
				t.Fatal(err)
			}
		}
		for name, content := range byHand {
			if err := s.typeStore(manifest.TypeBinary).Put(t.Context(), manifest.BinaryKey("tool", "", name), []byte(content)); err != nil {
				t.Fatal(err)
			}
		}
	}

	for _, tc := range []struct {
		label string
		edit  func(published []string) ([]manifest.VersionEntry, map[string]string)
	}{
		{"remove first", func([]string) ([]manifest.VersionEntry, map[string]string) {
			return original[1:], nil
		}},
		{"remove second", func([]string) ([]manifest.VersionEntry, map[string]string) {
			return []manifest.VersionEntry{original[0], original[2]}, nil
		}},
		{"reverse", func([]string) ([]manifest.VersionEntry, map[string]string) {
			return []manifest.VersionEntry{original[2], original[1], original[0]}, nil
		}},
		{"add a third credential ahead", func([]string) ([]manifest.VersionEntry, map[string]string) {
			return append([]manifest.VersionEntry{entry("third")}, original...), nil
		}},
		{"copy the first link as an explicit filename, then remove the first", func(published []string) ([]manifest.VersionEntry, map[string]string) {
			copied := strings.TrimPrefix(published[0], "/binaries/tool/")
			return []manifest.VersionEntry{{URL: "https://public.example/copy", Filename: copied}, original[1], original[2]},
				map[string]string{copied: "COPIED-ELF"}
		}},
	} {
		t.Run(tc.label, func(t *testing.T) {
			s := hostedServer(t)
			fetch(t, s, original, map[string]string{host: "EXPLICIT-ELF"})
			published := links(t, s)
			for i, link := range published {
				if code, got := getStatusAndBody(t, s, link); code != http.StatusOK || got != want[i] {
					t.Fatalf("entry %d's link %s = %d %q before the edit, want %q", i, link, code, got, want[i])
				}
			}

			versions, byHand := tc.edit(published)
			fetch(t, s, versions, byHand)
			for i, link := range published {
				code, got := getStatusAndBody(t, s, link)
				if code == http.StatusOK && got != want[i] {
					t.Errorf("entry %d's saved link %s now serves %q, want %q or a 404", i, link, got, want[i])
				}
			}
			for _, link := range links(t, s) {
				if code, got := getStatusAndBody(t, s, link); code != http.StatusOK || !strings.HasSuffix(got, "-ELF") {
					t.Errorf("after the edit, published link %s = %d %q", link, code, got)
				}
			}
		})
	}
}
