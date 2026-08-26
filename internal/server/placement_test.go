package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/server"
	"github.com/ravinald/bodega/internal/storage"
)

const nginxPoolPath = "pool/main/n/nginx/nginx_1.0_amd64.deb"

// placementServer builds a server over two real local backends, seeds the same
// key in both with different bytes, and records recordedStorage on the one apt
// entry. Different bytes per backend is what makes the assertion meaningful:
// the body says which backend answered.
func placementServer(t *testing.T, recordedStorage string) *httptest.Server {
	t.Helper()
	defaultRoot, bulkRoot := t.TempDir(), t.TempDir()
	seed(t, defaultRoot, "packages/apt/"+nginxPoolPath, "from-default")
	seed(t, bulkRoot, "packages/apt/"+nginxPoolPath, "from-bulk")

	cfg := &config.Config{
		ManifestDir:    "manifests",
		AptCodename:    "noble",
		MetadataTTL:    "1h",
		StorageBackend: "local",
		StoragePath:    defaultRoot,
		StorageBackends: map[string]config.StorageSpec{
			"bulk": {Driver: "local", Path: bulkRoot},
		},
		StorageByType: map[string]string{manifest.TypeApt: "bulk"},
	}

	store := manifest.NewLocalStore(t.TempDir())
	if err := store.AddVersion(t.Context(), manifest.TypeApt, "nginx", manifest.VersionEntry{
		Version:    "1.0",
		SourceName: "nginx",
		Storage:    recordedStorage,
		Metadata: map[string]string{
			"Architecture": "amd64",
			"_pool_path":   nginxPoolPath,
		},
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	stores, err := storage.NewResolver(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	ts := httptest.NewServer(server.New(cfg, store, stores, ":0", nil).Handler())
	t.Cleanup(ts.Close)
	return ts
}

// TestEmptyStorageMeansDefaultNotHierarchy is the regression guard for the one
// rule the whole feature rests on.
//
// storage_by_type.apt says "bulk", so that is where the NEXT .deb is written.
// This entry was uploaded before any of that existed and its recorded name is
// empty, which means "default" — not "resolve via the hierarchy". If empty
// meant "resolve now", adding one config key would silently repoint every
// already-uploaded .deb at a backend that does not hold it.
func TestEmptyStorageMeansDefaultNotHierarchy(t *testing.T) {
	ts := placementServer(t, "")

	code, body := getBody(t, ts, "/apt/pool/main/n/nginx/nginx_1.0_amd64.deb")
	if code != http.StatusOK {
		t.Fatalf("GET pooled .deb = %d, want 200", code)
	}
	if body != "from-default" {
		t.Fatalf("served %q, want %q — an empty VersionEntry.Storage resolved through storage_by_type instead of meaning %q",
			body, "from-default", storage.DefaultName)
	}
}

// TestRecordedStorageWinsOverTheTypeRule is the other half: an entry that does
// name a backend is served from it, which is what makes placement per-version
// rather than per-config.
func TestRecordedStorageWinsOverTheTypeRule(t *testing.T) {
	ts := placementServer(t, "bulk")

	code, body := getBody(t, ts, "/apt/pool/main/n/nginx/nginx_1.0_amd64.deb")
	if code != http.StatusOK {
		t.Fatalf("GET pooled .deb = %d, want 200", code)
	}
	if body != "from-bulk" {
		t.Fatalf("served %q, want %q", body, "from-bulk")
	}
}

// TestUnknownRecordedStorageFailsRatherThanFallingBack pins that a name no
// backend answers to is an error. Falling back to the default would serve
// bytes under a digest recorded against another store, which is the signature
// the checksum machinery exists to flag.
func TestUnknownRecordedStorageFailsRatherThanFallingBack(t *testing.T) {
	ts := placementServer(t, "ghost")

	code, body := getBody(t, ts, "/apt/pool/main/n/nginx/nginx_1.0_amd64.deb")
	if code != http.StatusBadGateway {
		t.Fatalf("GET pooled .deb = %d (%q), want 502", code, body)
	}
	if body == "from-default" || body == "from-bulk" {
		t.Fatalf("served %q — an unknown recorded backend fell back instead of failing", body)
	}
}

func seed(t *testing.T, root, key, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
