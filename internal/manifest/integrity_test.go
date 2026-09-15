package manifest_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// seedStore writes one package manifest through the store and returns the
// store, its directory, and the path of the manifest on disk.
func seedStore(t *testing.T) (*manifest.Store, string, string) {
	t.Helper()
	dir := t.TempDir()
	store := manifest.NewLocalStore(dir)
	pm := &manifest.PackageManifest{
		Type:        manifest.TypeBinary,
		Name:        "hello-binary",
		Description: "a fixture",
		Versions:    []manifest.VersionEntry{{Version: "1.0.0", URL: "https://example.invalid/hello"}},
	}
	if err := store.SavePackage(t.Context(), pm); err != nil {
		t.Fatalf("SavePackage: %v", err)
	}
	if err := store.SaveIndex(t.Context()); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}
	return store, dir, filepath.Join(dir, "binary", "hello-binary", "manifest.json")
}

// resultFor returns the verdict for one store-relative path.
func resultFor(t *testing.T, results []manifest.IntegrityResult, path string) manifest.IntegrityResult {
	t.Helper()
	for _, r := range results {
		if r.Path == path {
			return r
		}
	}
	t.Fatalf("no verdict for %s in %d results", path, len(results))
	return manifest.IntegrityResult{}
}

// TestSavePackageWritesSidecar is the whole of B54's first half: the sidecar
// was never written, so VerifyMD5 compared against a file that did not exist
// and `pkg verify` answered yes to everything.
func TestSavePackageWritesSidecar(t *testing.T) {
	store, dir, manifestPath := seedStore(t)

	for _, name := range []string{
		filepath.Join("binary", "hello-binary", "manifest.json"),
		"index.json",
		"metrics.json",
	} {
		if _, err := os.Stat(filepath.Join(dir, name+".md5")); err != nil {
			t.Errorf("no sidecar for %s: %v", name, err)
		}
	}

	results, err := store.VerifyIntegrity(t.Context())
	if err != nil {
		t.Fatalf("VerifyIntegrity: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("VerifyIntegrity returned nothing for a store holding manifests")
	}
	for _, r := range results {
		if !r.Passed() {
			t.Errorf("%s: %s (%v)", r.Path, r.Status, r.Err)
		}
	}
	_ = manifestPath
}

// TestVerifyIntegrityCatchesTamper edits a manifest behind the store's back,
// which is what tampering looks like from the filesystem, and asserts the
// verdict names the package. It fails on a tree where SavePackage writes no
// sidecar: every result comes back UNVERIFIABLE there, never FAIL.
func TestVerifyIntegrityCatchesTamper(t *testing.T) {
	store, _, manifestPath := seedStore(t)

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(data), "a fixture", "tampered", 1)
	if tampered == string(data) {
		t.Fatal("the edit changed nothing, so the test would pass a store nobody tampered with")
	}
	if err := os.WriteFile(manifestPath, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}

	results, err := store.VerifyIntegrity(t.Context())
	if err != nil {
		t.Fatalf("VerifyIntegrity: %v", err)
	}
	got := resultFor(t, results, filepath.Join("binary", "hello-binary", "manifest.json"))
	if got.Status != manifest.IntegrityFail {
		t.Fatalf("edited manifest reported %s, want %s", got.Status, manifest.IntegrityFail)
	}
	if got.Passed() {
		t.Error("a FAIL verdict reported itself as passed")
	}
	if !strings.Contains(got.Path, "hello-binary") {
		t.Errorf("the verdict does not name the package: %s", got.Path)
	}
}

// TestVerifyIntegrityUnverifiable covers a manifest that predates sidecars:
// nothing to compare against, and that is not a pass.
func TestVerifyIntegrityUnverifiable(t *testing.T) {
	store, dir, manifestPath := seedStore(t)
	if err := os.Remove(manifestPath + ".md5"); err != nil {
		t.Fatal(err)
	}

	results, err := store.VerifyIntegrity(t.Context())
	if err != nil {
		t.Fatalf("VerifyIntegrity: %v", err)
	}
	got := resultFor(t, results, filepath.Join("binary", "hello-binary", "manifest.json"))
	if got.Status != manifest.IntegrityUnverifiable {
		t.Fatalf("sidecar-less manifest reported %s, want %s", got.Status, manifest.IntegrityUnverifiable)
	}
	if got.Passed() {
		t.Error("an UNVERIFIABLE verdict reported itself as passed")
	}

	if _, err := store.RestampMD5(t.Context(), manifest.TypeBinary); err != nil {
		t.Fatalf("RestampMD5: %v", err)
	}
	results, err = store.VerifyIntegrity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got := resultFor(t, results, filepath.Join("binary", "hello-binary", "manifest.json")); !got.Passed() {
		t.Errorf("after a re-stamp the manifest reported %s", got.Status)
	}
	_ = dir
}

// TestDeletePackageRemovesSidecar guards the other direction: a sidecar
// outliving its manifest would be walked as an unverifiable object forever.
func TestDeletePackageRemovesSidecar(t *testing.T) {
	store, dir, manifestPath := seedStore(t)
	if err := store.DeletePackage(t.Context(), manifest.TypeBinary, "hello-binary"); err != nil {
		t.Fatalf("DeletePackage: %v", err)
	}
	if _, err := os.Stat(manifestPath + ".md5"); !os.IsNotExist(err) {
		t.Errorf("sidecar survived the delete: %v", err)
	}
	_ = dir
}

// TestRestampMD5WholeStore is the --break-glass-update-md5 all path: the
// store-root files belong to no package type, so nothing narrower reaches them.
func TestRestampMD5WholeStore(t *testing.T) {
	store, dir, _ := seedStore(t)
	for _, name := range []string{"index.json.md5", "metrics.json.md5"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := store.RestampMD5(t.Context(), manifest.TypeBinary); err != nil {
		t.Fatalf("RestampMD5(binary): %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "index.json.md5")); !os.IsNotExist(err) {
		t.Error("a per-type re-stamp reached the store-root index.json")
	}

	stamped, err := store.RestampMD5(t.Context(), "")
	if err != nil {
		t.Fatalf("RestampMD5(all): %v", err)
	}
	if len(stamped) < 3 {
		t.Errorf("a whole-store re-stamp touched %d manifests: %v", len(stamped), stamped)
	}
	results, err := store.VerifyIntegrity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		if !r.Passed() {
			t.Errorf("%s: %s", r.Path, r.Status)
		}
	}
}

// failWriteBackend refuses the write of one named object and passes every other
// call through to the real backend.
type failWriteBackend struct {
	manifest.Backend
	fail string
}

func (b *failWriteBackend) Write(ctx context.Context, name string, data []byte) error {
	if name == b.fail {
		return fmt.Errorf("simulated write failure for %s", name)
	}
	return b.Backend.Write(ctx, name, data)
}

// TestSaveIndexReportsAMetricsSidecarFailure covers the half of "every manifest
// write emits its sidecar" that a green return can hide. SaveIndex wrote
// metrics through the same helper and then discarded its error, so a run whose
// sidecar write failed reported success and left metrics.json behind it with
// nothing to compare against.
func TestSaveIndexReportsAMetricsSidecarFailure(t *testing.T) {
	dir := t.TempDir()
	store := manifest.NewStore(&failWriteBackend{
		Backend: &manifest.LocalBackend{Dir: dir},
		fail:    "metrics.json.md5",
	})
	pm := &manifest.PackageManifest{
		Type:     manifest.TypeBinary,
		Name:     "hello-binary",
		Versions: []manifest.VersionEntry{{Version: "1.0.0"}},
	}
	if err := store.SavePackage(t.Context(), pm); err != nil {
		t.Fatalf("SavePackage: %v", err)
	}

	err := store.SaveIndex(t.Context())
	if err == nil {
		t.Fatal("SaveIndex reported success after the metrics sidecar write failed")
	}
	if !strings.Contains(err.Error(), "metrics.json.md5") {
		t.Errorf("the failure does not name the object that could not be written: %v", err)
	}

	results, verr := store.VerifyIntegrity(t.Context())
	if verr != nil {
		t.Fatalf("VerifyIntegrity: %v", verr)
	}
	got := resultFor(t, results, "metrics.json")
	if got.Status != manifest.IntegrityUnverifiable {
		t.Fatalf("metrics.json reported %s, want %s", got.Status, manifest.IntegrityUnverifiable)
	}
	if got.Passed() {
		t.Error("a sidecar-less metrics.json reported itself as passed")
	}
}
