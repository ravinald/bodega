package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/server"
	"github.com/ravinald/bodega/internal/storage"
)

// helmPlacementServer mirrors placementServer for the chart route. Both chart
// shapes are seeded in both backends under the key HelmChartKey writes, and
// recordedStorage lands on the prerelease entry alone: the stable entry
// records nothing, so it answers from the default and pins that the identity
// it resolves to has not moved.
func helmPlacementServer(t *testing.T, recordedStorage string) *httptest.Server {
	t.Helper()
	defaultRoot, bulkRoot := t.TempDir(), t.TempDir()
	for _, key := range []string{
		manifest.HelmChartKey("cert-manager", "1.14.0-rc.1"),
		manifest.HelmChartKey("cert-manager", "1.14.0"),
	} {
		seed(t, defaultRoot, key, "from-default")
		seed(t, bulkRoot, key, "from-bulk")
	}

	cfg := &config.Config{
		ManifestDir:    "manifests",
		AptCodename:    "noble",
		MetadataTTL:    "1h",
		StorageBackend: "local",
		StoragePath:    defaultRoot,
		StorageBackends: map[string]config.StorageSpec{
			"bulk": {Driver: "local", Path: bulkRoot},
		},
	}

	store := manifest.NewLocalStore(t.TempDir())
	for _, ve := range []manifest.VersionEntry{
		{Version: "1.14.0-rc.1", Storage: recordedStorage},
		{Version: "1.14.0"},
	} {
		if err := store.AddVersion(t.Context(), manifest.TypeHelm, "cert-manager", ve); err != nil {
			t.Fatalf("AddVersion %s: %v", ve.Version, err)
		}
	}

	stores, err := storage.NewResolver(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	ts := httptest.NewServer(server.New(cfg, store, stores, ":0", nil).Handler())
	t.Cleanup(ts.Close)
	return ts
}

// TestHelmPrereleaseChartReadsTheRecordedBackend is the 404 'bodega pkg move
// helm cert-manager --to bulk' used to produce for a prerelease. versionStore
// resolves on the manifest name, so a lookup under "cert-manager-1.14.0" at
// "rc.1" matched no entry and fell back to the default backend.
func TestHelmPrereleaseChartReadsTheRecordedBackend(t *testing.T) {
	ts := helmPlacementServer(t, "bulk")

	code, body := getBody(t, ts, "/helm/charts/cert-manager-1.14.0-rc.1.tgz")
	if code != http.StatusOK {
		t.Fatalf("GET prerelease chart = %d (%q), want 200", code, body)
	}
	if body != "from-bulk" {
		t.Fatalf("served %q, want %q — the chart resolved through the type rule, not the backend its version entry names", body, "from-bulk")
	}
}

// TestHelmStableChartIdentityUnchanged is the other half. A version with no
// "-" of its own split correctly under the old rule, so it must still resolve
// to the same entry — and both shapes must still be served from the key
// HelmChartKey writes, because moving where an uploaded chart is read from is
// the failure this pins.
func TestHelmStableChartIdentityUnchanged(t *testing.T) {
	ts := helmPlacementServer(t, "bulk")

	code, body := getBody(t, ts, "/helm/charts/cert-manager-1.14.0.tgz")
	if code != http.StatusOK {
		t.Fatalf("GET stable chart = %d (%q), want 200", code, body)
	}
	if body != "from-default" {
		t.Fatalf("served %q, want %q — a stable version records no backend and answers from the default", body, "from-default")
	}
}
