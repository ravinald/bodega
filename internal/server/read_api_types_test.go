package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
