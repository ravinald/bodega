package server_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/server"
	"github.com/ravinald/bodega/internal/storage"
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
	mock := memStore(map[string]string{})
	cfg := &config.Config{Bucket: "test-bucket", Region: "us-west-2", ManifestDir: "manifests", AptCodename: "noble"}
	srv := server.New(cfg, store, storage.NewSingle(mock), ":0", nil)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// bucketStore is a Memory that answers to an s3:// label, which is what
// attestationStore matches an attestation_uri's bucket against. Memory's own
// label is "mem://N" and would match no URI any sync service writes.
type bucketStore struct {
	*storage.Memory
	label string
}

func (b bucketStore) Label() string { return b.label }

// attestationResolver is the two-backend resolver a real install has: the
// default bucket, and a second one an external authority writes envelopes to.
type attestationResolver struct {
	def, archive storage.ObjectStore
}

func (r attestationResolver) Default() storage.ObjectStore { return r.def }

func (r attestationResolver) ByName(name string) (storage.ObjectStore, error) {
	if name == "archive" {
		return r.archive, nil
	}
	return r.def, nil
}

func (r attestationResolver) Placement(string, string) storage.Decision {
	return storage.Decision{Name: storage.DefaultName}
}

func (r attestationResolver) ForType(string) storage.ObjectStore { return r.def }

func (r attestationResolver) Fanout(context.Context, string, []string) []storage.NamedStore {
	return r.All()
}

func (r attestationResolver) All() []storage.NamedStore {
	return []storage.NamedStore{
		{Name: storage.DefaultName, Store: r.def},
		{Name: "archive", Store: r.archive},
	}
}

// TestAttestation_S3URIResolvesByBucket is the decision #88 asked for. The
// envelope's location is recorded nowhere but the URI, so the bucket in the
// URI is what resolves it. Resolving through storage_by_type broke retrieval
// for artifacts nobody touched, every time that rule changed.
func TestAttestation_S3URIResolvesByBucket(t *testing.T) {
	def := bucketStore{Memory: memStore(map[string]string{
		"attest/sample.dsse.json": "wrong-backend",
	}), label: "s3://test-bucket"}
	archive := bucketStore{Memory: memStore(map[string]string{
		"attest/sample.dsse.json": "the-envelope",
	}), label: "s3://attest-bucket"}

	store := manifest.NewLocalStore(t.TempDir())
	if err := store.AddVersion(context.Background(), manifest.TypeNpm, "sample", manifest.VersionEntry{
		Version: "1.0.0",
		Metadata: map[string]string{
			server.MetaAttestationURI: "s3://attest-bucket/attest/sample.dsse.json",
		},
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	cfg := &config.Config{Bucket: "test-bucket", ManifestDir: "manifests", AptCodename: "noble"}
	srv := server.New(cfg, store, attestationResolver{def: def, archive: archive}, ":0", nil)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/api/v1/packages/npm/sample/1.0.0/attestation")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "the-envelope" {
		t.Errorf("served %q, want the copy in the bucket the URI names", string(body))
	}
}

// TestAttestation_S3URIFallsBackToTheTypeRule: a bucket no backend answers to
// is the state every install was in before backends were named, so it keeps
// the answer it had rather than becoming a 404.
func TestAttestation_S3URIFallsBackToTheTypeRule(t *testing.T) {
	ts := attestationServer(t, manifest.VersionEntry{
		Version: "1.0.0",
		Metadata: map[string]string{
			server.MetaAttestationURI: "s3://some-other-bucket/attest/sample.dsse.json",
		},
	})
	resp, err := http.Get(ts.URL + "/api/v1/packages/npm/sample/1.0.0/attestation")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	// The type rule's backend holds nothing at that key, so 404 rather than a
	// 502: the lookup ran, it just found no object.
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}
