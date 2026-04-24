package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/server"
)

func TestAttestation_HTTPSRedirect(t *testing.T) {
	ts := attestationServer(t, manifest.VersionEntry{
		Version: "1.0.0",
		Metadata: map[string]string{
			server.MetaAttestationURI: "https://attest.example.com/sample@1.0.0.dsse.json",
		},
	})
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(ts.URL + "/api/v1/packages/npm/sample/1.0.0/attestation")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Location"), "attest.example.com") {
		t.Errorf("Location = %q", resp.Header.Get("Location"))
	}
}

func TestAttestation_MissingMetadataReturns404(t *testing.T) {
	ts := attestationServer(t, manifest.VersionEntry{Version: "1.0.0"})
	resp, err := http.Get(ts.URL + "/api/v1/packages/npm/sample/1.0.0/attestation")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAttestation_UnsupportedScheme(t *testing.T) {
	ts := attestationServer(t, manifest.VersionEntry{
		Version: "1.0.0",
		Metadata: map[string]string{
			server.MetaAttestationURI: "ftp://old.example.com/attest.json",
		},
	})
	resp, err := http.Get(ts.URL + "/api/v1/packages/npm/sample/1.0.0/attestation")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
}

// attestationServer spins up a one-off server with a single npm entry
// "sample" carrying the provided VersionEntry. Kept local to this test
// file because newTestServer's fixed catalog doesn't cover these cases.
func attestationServer(t *testing.T, ve manifest.VersionEntry) *httptest.Server {
	t.Helper()
	store := manifest.NewLocalStore(t.TempDir())
	if err := store.AddVersion(context.Background(), manifest.TypeNpm, "sample", ve); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	mock := &mockStore{objects: map[string]string{}}
	cfg := &config.Config{Bucket: "test-bucket", Region: "us-west-2", ManifestDir: "manifests", AptCodename: "noble"}
	srv := server.New(cfg, store, mock, ":0", nil)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}
