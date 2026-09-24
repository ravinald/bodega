package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
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

// pageClientURL runs the embedded page's own getClientUrl on one entry of a
// captured read-API response, which is the link the web UI offers for it.
func pageClientURL(t *testing.T, typ string, entry map[string]any) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node not on PATH; the page's own JavaScript went unexercised on a CI runner")
		}
		t.Skip("node not on PATH; the page's own JavaScript cannot be executed here")
	}
	src := webIndex(t)
	start, end := strings.Index(src, "<script>"), strings.LastIndex(src, "</script>")
	if start < 0 || end < 0 {
		t.Fatal("web/index.html: no <script> block found")
	}
	script := strings.Replace(src[start+len("<script>"):end], "\ninit();\n", "\n", 1)
	probe := "\nconsole.log(getClientUrl(process.env.PROBE_TYPE, JSON.parse(process.env.PROBE_ENTRY)));\n"
	path := filepath.Join(t.TempDir(), "client-url.cjs")
	if err := os.WriteFile(path, []byte(domStub+script+probe), 0o600); err != nil {
		t.Fatal(err)
	}
	entryJSON, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, path)
	cmd.Env = append(os.Environ(), "PROBE_TYPE="+typ, "PROBE_ENTRY="+string(entryJSON))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("run getClientUrl: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// A url whose raw last segment ends in something shaped like an alias tag is
// still the raw authority, so the filename published in its place is built
// from the public url. The entry is fetched for real from an upstream that
// demands exactly this username and password, read from outside every admin
// range with no token, linked by the page's own JavaScript, and downloaded.
func TestBinaryAliasCarriesNoUserinfoWhateverTheURLEndsIn(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "audit-user" || password != "audit-secret" {
			http.Error(w, "bad credentials", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("AUTHENTICATED-ELF"))
	}))
	defer upstream.Close()
	host := strings.TrimPrefix(upstream.URL, "http://")
	for _, suffix := range []string{"#~0123456789abcdef", "#~" + strings.Repeat("0123456789abcdef", 2), "?x=~" + strings.Repeat("0123456789abcdef", 2)} {
		t.Run(suffix, func(t *testing.T) {
			s := hostedServer(t)
			raw := "http://audit-user:audit-secret@" + host + suffix
			pm := &manifest.PackageManifest{Type: manifest.TypeBinary, Name: "tool", Versions: []manifest.VersionEntry{{Version: "1.0.0", URL: raw}}}
			if err := s.store.SavePackage(t.Context(), pm); err != nil {
				t.Fatal(err)
			}
			cfg := &builder.Config{BuildRoot: t.TempDir(), BuildEnvInfo: &manifest.BuildEnv{Platform: "linux/arm64"}}
			if sum := builder.FetchBinaries(cfg, s.store, "tool"); sum.Total != 1 || sum.Failures != 0 {
				t.Fatalf("fetch: %+v", sum)
			}
			for _, p := range builder.BinaryArtifactPaths(cfg, s.store, "tool") {
				data, err := os.ReadFile(p.Local)
				if err != nil {
					t.Fatal(err)
				}
				if err := s.typeStore(manifest.TypeBinary).Put(t.Context(), p.ObjectKey, data); err != nil {
					t.Fatal(err)
				}
			}

			var entry map[string]any
			for _, route := range []string{"/api/v1/packages", "/api/v1/packages/binary", "/api/v1/packages/binary/tool", "/api/v1/packages/binary/tool/1.0.0"} {
				req := httptest.NewRequest(http.MethodGet, route, nil)
				req.RemoteAddr = "203.0.113.9:40000"
				rr := httptest.NewRecorder()
				s.Handler().ServeHTTP(rr, req)
				body := rr.Body.String()
				if rr.Code != http.StatusOK {
					t.Fatalf("%s: %d %s", route, rr.Code, body)
				}
				if strings.Contains(body, "audit-secret") {
					t.Errorf("%s publishes the password: %s", route, body)
				}
				if strings.Contains(body, "audit-user") {
					t.Errorf("%s publishes the username: %s", route, body)
				}
				if route == "/api/v1/packages/binary/tool/1.0.0" {
					entry = decodeJSON(t, body)["versions"].([]any)[0].(map[string]any)
					entry["name"], entry["version"] = "tool", "1.0.0"
				}
			}

			link := pageClientURL(t, manifest.TypeBinary, entry)
			if strings.Contains(link, "audit-user") || strings.Contains(link, "audit-secret") {
				t.Fatalf("the web UI links to %s", link)
			}
			_, path, ok := strings.Cut(link, "/binaries/")
			if !ok {
				t.Fatalf("the web UI links to %s, not a binary download", link)
			}
			if code, got := getStatusAndBody(t, s, "/binaries/"+path); code != http.StatusOK || got != "AUTHENTICATED-ELF" {
				t.Errorf("GET /binaries/%s = %d %q, want the fetched bytes", path, code, got)
			}
			if stored, err := s.store.GetPackage(t.Context(), manifest.TypeBinary, "tool"); err != nil || stored.Versions[0].URL != raw {
				t.Fatalf("the stored url changed: %v", err)
			}
		})
	}
}

// A saved alias names one entry for as long as the server can authenticate it
// and nothing afterwards. The original is fetched for real from an upstream
// demanding its credentials, linked by the page's own JavaScript, and then
// copied: a second entry of the same version stores different bytes under the
// alias as an explicit filename, the way an import of a public manifest does.
// While the original is present the saved link reaches it; once it is removed
// the link is a 404, and it stays a 404 on a server built afresh after the
// pepper file changes and on one with no pepper at all. The copy is reachable
// throughout at the link the public manifest gives it.
func TestBinaryAliasNeverBecomesAStoredName(t *testing.T) {
	pepper := filepath.Join(t.TempDir(), "pepper")
	prev := audit.DefaultPepperPaths
	audit.DefaultPepperPaths = []string{pepper}
	t.Cleanup(func() { audit.DefaultPepperPaths = prev })

	serve := func(body string, user, password string) string {
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if u, p, _ := r.BasicAuth(); u != user || p != password {
				http.Error(w, "bad credentials", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(up.Close)
		return strings.TrimPrefix(up.URL, "http://")
	}
	original := manifest.VersionEntry{Version: "1.0.0", URL: "http://audit-user:audit-secret@" + serve("ORIGINAL-ELF", "audit-user", "audit-secret")}
	copyHost := serve("COPIED-ELF", "", "")

	for _, tc := range []struct {
		label   string
		keyless bool
	}{{"keyed", false}, {"keyless", true}} {
		t.Run(tc.label, func(t *testing.T) {
			if err := os.WriteFile(pepper, []byte(strings.Repeat("a", 64)), 0o600); err != nil {
				t.Fatal(err)
			}
			s := hostedServer(t)
			if tc.keyless {
				s.pepper = ""
			}
			objects := s.typeStore(manifest.TypeBinary)
			fetch := func(versions ...manifest.VersionEntry) {
				t.Helper()
				if err := s.store.SavePackage(t.Context(), &manifest.PackageManifest{Type: manifest.TypeBinary, Name: "tool", Versions: versions}); err != nil {
					t.Fatal(err)
				}
				cfg := &builder.Config{BuildRoot: t.TempDir(), BuildEnvInfo: &manifest.BuildEnv{Platform: "linux/arm64"}}
				if sum := builder.FetchBinaries(cfg, s.store, "tool"); sum.Failures != 0 {
					t.Fatalf("fetch: %+v", sum)
				}
				for _, p := range builder.BinaryArtifactPaths(cfg, s.store, "tool") {
					data, err := os.ReadFile(p.Local)
					if err != nil {
						t.Fatal(err)
					}
					if err := objects.Put(t.Context(), p.ObjectKey, data); err != nil {
						t.Fatal(err)
					}
				}
			}
			// links reads every entry as the web UI does, from outside every
			// admin range with no token, and returns the page's own link for
			// each in manifest order.
			links := func(srv *Server) []string {
				t.Helper()
				req := httptest.NewRequest(http.MethodGet, "/api/v1/packages/binary/tool", nil)
				req.RemoteAddr = "203.0.113.9:40000"
				rr := httptest.NewRecorder()
				srv.Handler().ServeHTTP(rr, req)
				if rr.Code != http.StatusOK {
					t.Fatalf("read: %d %s", rr.Code, rr.Body)
				}
				if withheldFrom(rr.Body.String(), "audit-secret", "audit-user") != "" {
					t.Fatalf("the manifest the UI reads publishes userinfo: %s", rr.Body)
				}
				var out []string
				for _, v := range decodeJSON(t, rr.Body.String())["versions"].([]any) {
					entry := v.(map[string]any)
					entry["name"] = "tool"
					_, path, ok := strings.Cut(pageClientURL(t, manifest.TypeBinary, entry), "/binaries/")
					if !ok {
						t.Fatalf("the web UI offers no binary link for %v", entry)
					}
					out = append(out, "/binaries/"+path)
				}
				return out
			}
			// expect requests path from srv and wants body, or a 404 when
			// body is empty.
			expect := func(srv *Server, when, path, body string) {
				t.Helper()
				rr := httptest.NewRecorder()
				srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
				switch {
				case body == "" && rr.Code != http.StatusNotFound:
					t.Errorf("%s: %s = %d %q, want 404", when, path, rr.Code, rr.Body)
				case body != "" && (rr.Code != http.StatusOK || rr.Body.String() != body):
					t.Errorf("%s: %s = %d %q, want %q", when, path, rr.Code, rr.Body, body)
				}
			}
			// A server with no pepper publishes aliases that resolve nowhere.
			keyed := func(body string) string {
				if tc.keyless {
					return ""
				}
				return body
			}

			fetch(original)
			saved := links(s)[0]
			published := strings.TrimPrefix(saved, "/binaries/tool/1.0.0/")
			if !manifest.IsBinaryAlias(published) {
				t.Fatalf("the original is published as %q, not an alias", published)
			}
			expect(s, "original alone", saved, keyed("ORIGINAL-ELF"))

			copied := manifest.VersionEntry{Version: "1.0.0", URL: "http://" + copyHost + "/copy", Filename: published}
			fetch(copied, original)
			expect(s, "copy ahead of the original", saved, keyed("ORIGINAL-ELF"))
			expect(s, "copy ahead of the original, the copy's own link", links(s)[0], keyed("COPIED-ELF"))

			fetch(copied)
			expect(s, "original removed", saved, "")
			expect(s, "original removed, the copy's own link", links(s)[0], keyed("COPIED-ELF"))

			if err := os.WriteFile(pepper, []byte(strings.Repeat("b", 64)), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := *s.cfg
			cfg.AuditDB = filepath.Join(t.TempDir(), "audit.db")
			rotated := newServer(&cfg, s.store, storage.NewSingle(objects), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
			t.Cleanup(func() { _ = rotated.auditDB.Close() })
			if rotated.pepper == "" || rotated.pepper == s.pepper {
				t.Fatalf("the rebuilt server did not load the rotated pepper")
			}
			expect(rotated, "after rotation", saved, "")
			expect(rotated, "after rotation, the copy's own link", links(rotated)[0], "COPIED-ELF")
			fetch(copied, original)
			expect(rotated, "after rotation with the original back", saved, "")
			expect(rotated, "after rotation with the original back, its new link", links(rotated)[1], "ORIGINAL-ELF")
		})
	}
}
