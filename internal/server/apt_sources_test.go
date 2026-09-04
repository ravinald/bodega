package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/aptsign"
	"github.com/ravinald/bodega/internal/aptsources"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/server"
	"github.com/ravinald/bodega/internal/storage"
)

// aptStatusBody is the apt half of /api/v1/status, decoded loosely: the test
// asserts against the wire shape a UI reads, not against the server's structs.
type aptStatusBody struct {
	Signed       bool     `json:"signed"`
	Fingerprints []string `json:"fingerprints"`
	KeyringURL   string   `json:"keyring_url"`
	Suites       []string `json:"suites"`
	PublicURL    string   `json:"public_url"`
	Sources      []struct {
		Signed  bool     `json:"signed"`
		Suite   string   `json:"suite"`
		URI     string   `json:"uri"`
		Deb822  string   `json:"deb822"`
		OneLine string   `json:"one_line"`
		Notes   []string `json:"notes"`
	} `json:"sources"`
}

// sourcesServer builds a server around an explicit config so the sources
// dimensions (suites, public_url, TLS) can be driven one at a time.
func sourcesServer(t *testing.T, cfg *config.Config) *httptest.Server {
	t.Helper()
	store := manifest.NewLocalStore(t.TempDir())
	_ = store.AddVersion(t.Context(), manifest.TypeApt, "pkg-a", manifest.VersionEntry{
		Version:  "1.0",
		Metadata: map[string]string{"Architecture": "amd64"},
	})
	srv := server.New(cfg, store, storage.NewSingle(memStore(nil)), ":0", nil)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func aptStatus(t *testing.T, ts *httptest.Server, headers map[string]string) aptStatusBody {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/api/v1/status", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/v1/status: %v", err)
	}
	defer resp.Body.Close()
	var body struct {
		Apt aptStatusBody `json:"apt"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	return body.Apt
}

// The served suites come off the config, one rendered block each. A literal
// "noble" on a jammy instance is a sources line naming a suite the server
// 404s, handed over by the page that is meant to be authoritative.
func TestStatusReportsServedSuites(t *testing.T) {
	ts := sourcesServer(t, &config.Config{AptCodename: "jammy", AptSuites: []string{"jammy", "noble"}})
	got := aptStatus(t, ts, nil)

	if strings.Join(got.Suites, ",") != "jammy,noble" {
		t.Fatalf("suites = %v, want [jammy noble]", got.Suites)
	}
	if len(got.Sources) != 2 {
		t.Fatalf("got %d sources blocks, want one per served suite", len(got.Sources))
	}
	for i, want := range []string{"jammy", "noble"} {
		if got.Sources[i].Suite != want {
			t.Errorf("sources[%d].suite = %q, want %q", i, got.Sources[i].Suite, want)
		}
		if !strings.Contains(got.Sources[i].Deb822, "Suites: "+want) {
			t.Errorf("sources[%d] deb822 does not name %q:\n%s", i, want, got.Sources[i].Deb822)
		}
	}
}

// With no key loaded the fallback is the only thing that works, and the
// consequence travels with it: [trusted=yes] is per-source, permanent and
// silent, and it propagates into whatever template pastes it.
func TestStatusUnsignedCarriesConsequence(t *testing.T) {
	ts := sourcesServer(t, &config.Config{AptCodename: "noble"})
	got := aptStatus(t, ts, nil)

	if got.Signed || got.KeyringURL != "" {
		t.Fatalf("no key installed but status reports signed=%v keyring=%q", got.Signed, got.KeyringURL)
	}
	src := got.Sources[0]
	if !strings.Contains(src.OneLine, "[trusted=yes]") {
		t.Errorf("unsigned one-line = %q, want the trusted=yes fallback", src.OneLine)
	}
	if strings.Contains(src.Deb822, "Signed-By") {
		t.Errorf("unsigned deb822 names a keyring that does not exist:\n%s", src.Deb822)
	}
	if len(src.Notes) == 0 {
		t.Error("trusted=yes shipped with no consequence beside it")
	}
}

// A signed instance must never be described with [trusted=yes]: that told the
// operator to turn verification off permanently for a repository that had a
// signature to check.
func TestStatusSignedEmitsSignedBy(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(aptsign.CredentialsEnv, dir)
	kr, err := aptsign.Generate("bodega test archive", "test@example.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := kr.WritePrivate(filepath.Join(dir, aptsign.KeyFileName)); err != nil {
		t.Fatalf("WritePrivate: %v", err)
	}

	ts := sourcesServer(t, &config.Config{AptCodename: "noble"})
	got := aptStatus(t, ts, nil)

	if !got.Signed {
		t.Fatal("key installed but status reports unsigned")
	}
	if strings.Join(got.Fingerprints, ",") != strings.Join(kr.Fingerprints(), ",") {
		t.Errorf("fingerprints = %v, want %v", got.Fingerprints, kr.Fingerprints())
	}
	if got.KeyringURL != aptsources.KeyringRoute {
		t.Errorf("keyring_url = %q, want %q", got.KeyringURL, aptsources.KeyringRoute)
	}
	src := got.Sources[0]
	if !strings.Contains(src.Deb822, "Signed-By: "+aptsources.ClientKeyringPath) {
		t.Errorf("signed instance emits no Signed-By:\n%s", src.Deb822)
	}
	if strings.Contains(src.OneLine, "trusted=yes") {
		t.Errorf("signed instance still hands over trusted=yes: %q", src.OneLine)
	}
}

// public_url is the only thing that knows the name a proxy publishes this
// server under, so it outranks both the request and the local TLS pair.
func TestStatusPublicURLBeatsRequest(t *testing.T) {
	ts := sourcesServer(t, &config.Config{AptCodename: "noble", PublicURL: "https://bodega.example.com/"})
	got := aptStatus(t, ts, map[string]string{"X-Forwarded-Proto": "http"})

	if got.PublicURL != "https://bodega.example.com" {
		t.Fatalf("public_url = %q, want the configured value with no trailing slash", got.PublicURL)
	}
	if !strings.HasPrefix(got.Sources[0].URI, "https://bodega.example.com/apt/") {
		t.Errorf("URI = %q, want the configured public URL", got.Sources[0].URI)
	}
	for _, note := range got.Sources[0].Notes {
		if note == aptsources.UnknownURLNote {
			t.Error("public_url is set but the placeholder note fired")
		}
	}
}

// With no public_url the request answers for itself. r.TLS is nil on every
// request behind a TLS-terminating proxy, so reading it alone prints http://
// for a deployment that is https everywhere a client can see.
func TestStatusFallsBackToForwardedProto(t *testing.T) {
	ts := sourcesServer(t, &config.Config{AptCodename: "noble"})

	plain := aptStatus(t, ts, nil)
	if !strings.HasPrefix(plain.PublicURL, "http://127.0.0.1:") {
		t.Errorf("public_url = %q, want the request's own origin", plain.PublicURL)
	}

	proxied := aptStatus(t, ts, map[string]string{"X-Forwarded-Proto": "https"})
	if !strings.HasPrefix(proxied.PublicURL, "https://127.0.0.1:") {
		t.Errorf("public_url = %q, want https from X-Forwarded-Proto", proxied.PublicURL)
	}
	if !strings.HasPrefix(proxied.Sources[0].URI, "https://") {
		t.Errorf("URI = %q, want https behind a terminating proxy", proxied.Sources[0].URI)
	}
}

// TestStatusNamesEntriesNoSuiteServes gives the silent drop a place to be
// seen. An entry naming an unserved suite is dropped by the generator and
// 404s at handleAptDists, and the client reports "Unable to locate package" —
// the message a typo produces. Nothing outside the server's own log said so,
// so an operator holding the API had no way to tell a missing package from a
// misspelled one.
func TestStatusNamesEntriesNoSuiteServes(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	if err := store.AddVersion(t.Context(), manifest.TypeApt, "stray", manifest.VersionEntry{
		Version:  "1.0",
		Suites:   []string{"jammy"},
		Metadata: map[string]string{"Architecture": "amd64"},
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	if err := store.AddVersion(t.Context(), manifest.TypeApt, "served", manifest.VersionEntry{
		Version:  "2.0",
		Suites:   []string{"noble"},
		Metadata: map[string]string{"Architecture": "amd64"},
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	cfg := &config.Config{ManifestDir: "manifests", AptCodename: "noble", AptSuites: []string{"noble"}}
	ts := httptest.NewServer(server.New(cfg, store, storage.NewSingle(memStore(nil)), ":0", nil).Handler())
	t.Cleanup(ts.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/api/v1/status", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/v1/status: %v", err)
	}
	defer resp.Body.Close()

	var body struct {
		Apt struct {
			Unserved []struct {
				Name    string   `json:"name"`
				Version string   `json:"version"`
				Suites  []string `json:"suites"`
			} `json:"unserved"`
			UnservedCount int `json:"unserved_count"`
		} `json:"apt"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Apt.UnservedCount != 1 {
		t.Fatalf("unserved_count = %d, want 1 (one entry in jammy, one in noble)", body.Apt.UnservedCount)
	}
	got := body.Apt.Unserved
	if len(got) != 1 || got[0].Name != "stray" || got[0].Version != "1.0" {
		t.Fatalf("unserved = %+v, want the jammy entry alone", got)
	}
	if len(got[0].Suites) != 1 || got[0].Suites[0] != "jammy" {
		t.Errorf("the row does not name the suite the entry asked for: %+v", got[0].Suites)
	}
}
