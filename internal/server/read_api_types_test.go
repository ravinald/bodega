package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
