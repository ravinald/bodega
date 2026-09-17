package builder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// pinEnv is a scratch build config with an audit database and a manifest store
// holding one package of the given type.
func pinEnv(t *testing.T, pm *manifest.PackageManifest) (*Config, *manifest.Store, *audit.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := audit.Open(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store := manifest.NewLocalStore(filepath.Join(dir, "manifests"))
	if err := store.SavePackage(t.Context(), pm); err != nil {
		t.Fatalf("SavePackage: %v", err)
	}
	return &Config{BuildRoot: dir, AuditDB: db}, store, db
}

// TestPinChecksumRecordsAndEnforces is B54's other half: the digest was written
// into the manifest by the same fetch that computed it and nowhere else, so
// `pkg checksum list` printed "No cached checksums" after all eight types had
// been fetched and there was nothing to enforce on the next fetch.
func TestPinChecksumRecordsAndEnforces(t *testing.T) {
	const (
		first  = "1111111111111111111111111111111111111111111111111111111111111111"
		second = "2222222222222222222222222222222222222222222222222222222222222222"
	)
	pm := &manifest.PackageManifest{
		Type:     manifest.TypeCargo,
		Name:     "itoa",
		Versions: []manifest.VersionEntry{{Version: "1.0.11"}},
	}
	cfg, store, db := pinEnv(t, pm)
	ve := pm.Versions[0]

	if err := cfg.updateVersionChecksum(t.Context(), store, manifest.TypeCargo, "itoa", ve, newSHA256Checksum(first), false); err != nil {
		t.Fatalf("first fetch: %v", err)
	}

	rows, err := db.ListChecksums(t.Context(), manifest.TypeCargo, "itoa")
	if err != nil {
		t.Fatalf("list checksums: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("first fetch recorded %d rows, want 1", len(rows))
	}
	if rows[0].Value != first || rows[0].PkgVersion != "1.0.11" {
		t.Errorf("row is %+v, want value %s at version 1.0.11", rows[0], first)
	}
	if rows[0].ObjectKey != manifest.CargoCrateKey("itoa", "1.0.11") {
		t.Errorf("row keyed on %q, not the object key the proxy verifies against", rows[0].ObjectKey)
	}
	// "computed" is the proxy's word for bytes an upstream served. A build row
	// claiming it would take an apt package bodega built out of the index.
	if rows[0].Source == "computed" {
		t.Errorf("a build-time pin claimed the proxy's source %q", rows[0].Source)
	}

	// Same digest again: the second fetch is enforced against the pin and agrees.
	if err := cfg.updateVersionChecksum(t.Context(), store, manifest.TypeCargo, "itoa", ve, newSHA256Checksum(first), true); err != nil {
		t.Fatalf("a re-fetch of identical bytes was refused: %v", err)
	}

	// Different digest: the upstream republished, and that is the whole point.
	err = cfg.updateVersionChecksum(t.Context(), store, manifest.TypeCargo, "itoa", ve, newSHA256Checksum(second), false)
	if err == nil {
		t.Fatal("a re-fetch with different bytes was accepted against a pinned digest")
	}
	if !strings.Contains(err.Error(), "itoa") || !strings.Contains(err.Error(), first) {
		t.Errorf("the refusal names neither the package nor the pinned digest: %v", err)
	}

	rows, err = db.ListChecksums(t.Context(), manifest.TypeCargo, "itoa")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Value != first {
		t.Errorf("the refused fetch changed the pin: %+v", rows)
	}
}

// TestPinChecksumSkipsPypi records the one type this cannot cover: wheels
// upload as a directory covering a whole dependency closure, so there is no
// per-version object to key a row on. It must be a quiet skip, not a fetch
// failure.
func TestPinChecksumSkipsPypi(t *testing.T) {
	pm := &manifest.PackageManifest{
		Type:     manifest.TypePypi,
		Name:     "six",
		Versions: []manifest.VersionEntry{{Version: "1.16.0"}},
	}
	cfg, _, db := pinEnv(t, pm)

	if err := cfg.pinChecksum(t.Context(), pm, pm.Versions[0], newSHA256Checksum("abc")); err != nil {
		t.Fatalf("pypi pin returned an error rather than skipping: %v", err)
	}
	rows, err := db.ListChecksums(t.Context(), manifest.TypePypi, "six")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("pypi recorded %d rows against no object key: %+v", len(rows), rows)
	}
}

// TestVerifyFetchedPinsAnAlreadyFetchedArtifact covers the path every fetch
// past the first actually takes. A build root holding the artifact answers
// "already fetched, skipping", which downloaded nothing and so checked
// nothing — so on a long-lived install the checksum cache stayed empty however
// many times the pipeline ran.
func TestVerifyFetchedPinsAnAlreadyFetchedArtifact(t *testing.T) {
	pm := &manifest.PackageManifest{
		Type:     manifest.TypeHelm,
		Name:     "podinfo",
		Versions: []manifest.VersionEntry{{Version: "6.7.0", URL: "https://example.invalid/podinfo-6.7.0.tgz"}},
	}
	cfg, store, db := pinEnv(t, pm)
	ve := pm.Versions[0]

	path := cfg.fetchedArtifact(manifest.TypeHelm, "podinfo", ve)
	if path == "" {
		t.Fatal("helm resolved no artifact path, so the skip path can check nothing")
	}
	body := []byte("chart bytes")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}

	// No digest on the entry yet: the skip path records one.
	if err := cfg.verifyFetched(t.Context(), store, manifest.TypeHelm, "podinfo", ve); err != nil {
		t.Fatalf("verifyFetched on an unpinned entry: %v", err)
	}
	rows, err := db.ListChecksums(t.Context(), manifest.TypeHelm, "podinfo")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Value != ComputeBytesSHA256(body) {
		t.Fatalf("the skip path recorded %+v, want the digest of the artifact on disk", rows)
	}

	// Tamper with the artifact in the build root. The next run takes the same
	// skip path and must refuse rather than upload it.
	stored, err := store.GetPackage(t.Context(), manifest.TypeHelm, "podinfo")
	if err != nil {
		t.Fatal(err)
	}
	pinned := stored.Versions[0]
	if pinned.Checksum == nil {
		t.Fatal("the manifest entry carries no checksum after a pin")
	}
	if err := os.WriteFile(path, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	err = cfg.verifyFetched(t.Context(), store, manifest.TypeHelm, "podinfo", pinned)
	if err == nil {
		t.Fatal("an artifact edited in the build root passed the skip path")
	}
	if !strings.Contains(err.Error(), "podinfo") {
		t.Errorf("the refusal does not name the package: %v", err)
	}
}
