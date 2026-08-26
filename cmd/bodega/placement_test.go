package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// twoBackendPlacer builds a placer over "default" and "bulk", both local, with
// byType as the placement rule.
func twoBackendPlacer(t *testing.T, byType map[string]string, replace bool) (*placer, *manifest.Store, *bytes.Buffer) {
	t.Helper()
	cfg := &config.Config{
		StorageBackend:  "local",
		StoragePath:     t.TempDir(),
		StorageBackends: map[string]config.StorageSpec{"bulk": {Driver: "local", Path: t.TempDir()}},
		StorageByType:   byType,
	}
	store := manifest.NewLocalStore(t.TempDir())
	out := &bytes.Buffer{}
	pl, err := newPlacer(context.Background(), cfg, store, out, replace)
	if err != nil {
		t.Fatalf("newPlacer: %v", err)
	}
	return pl, store, out
}

func addBinary(t *testing.T, store *manifest.Store, name, version, recorded string) {
	t.Helper()
	if err := store.AddVersion(t.Context(), manifest.TypeBinary, name, manifest.VersionEntry{
		Version: version,
		Storage: recorded,
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
}

func recordedStorage(t *testing.T, store *manifest.Store, typ, name, version string) string {
	t.Helper()
	pm, err := store.GetPackage(t.Context(), typ, name)
	if err != nil || pm == nil {
		t.Fatalf("GetPackage(%s/%s): %v", typ, name, err)
	}
	i := versionIndex(pm, version)
	if i < 0 {
		t.Fatalf("no version %q on %s/%s", version, typ, name)
	}
	return pm.Versions[i].Storage
}

// TestPlacementIsRecordedBeforeTheUpload pins the write order. A
// recorded-but-missing object is a state bodega status reports; an
// uploaded-but-unrecorded one is invisible.
func TestPlacementIsRecordedBeforeTheUpload(t *testing.T) {
	pl, store, _ := twoBackendPlacer(t, map[string]string{manifest.TypeBinary: "bulk"}, false)
	addBinary(t, store, "awscli", "2.0.0", "")

	st, err := pl.forVersion(t.Context(), manifest.TypeBinary, "awscli", "2.0.0", "binaries/awscli/2.0.0/awscli.zip")
	if err != nil {
		t.Fatalf("forVersion: %v", err)
	}
	if got := recordedStorage(t, store, manifest.TypeBinary, "awscli", "2.0.0"); got != "bulk" {
		t.Errorf("recorded storage = %q, want bulk — the name has to land before any bytes move", got)
	}
	if !strings.Contains(st.Label(), "file://") {
		t.Errorf("Label() = %q, want a local backend", st.Label())
	}
}

// TestDefaultPlacementStaysTheZeroValue keeps an existing manifest
// byte-identical when nothing about its placement changed.
func TestDefaultPlacementStaysTheZeroValue(t *testing.T) {
	pl, store, _ := twoBackendPlacer(t, nil, false)
	addBinary(t, store, "awscli", "2.0.0", "")

	if _, err := pl.forVersion(t.Context(), manifest.TypeBinary, "awscli", "2.0.0", "binaries/awscli/2.0.0/awscli.zip"); err != nil {
		t.Fatalf("forVersion: %v", err)
	}
	if got := recordedStorage(t, store, manifest.TypeBinary, "awscli", "2.0.0"); got != "" {
		t.Errorf("recorded storage = %q, want the zero value for the default backend", got)
	}
}

// TestReUploadHonorsTheRecordedName is hazard H3. Re-resolving would write new
// bytes to a new backend while the manifest named the old one.
func TestReUploadHonorsTheRecordedName(t *testing.T) {
	pl, store, _ := twoBackendPlacer(t, map[string]string{manifest.TypeBinary: "default"}, false)
	addBinary(t, store, "awscli", "2.0.0", "bulk")

	if _, err := pl.forVersion(t.Context(), manifest.TypeBinary, "awscli", "2.0.0", "binaries/awscli/2.0.0/awscli.zip"); err != nil {
		t.Fatalf("forVersion: %v", err)
	}
	if got := recordedStorage(t, store, manifest.TypeBinary, "awscli", "2.0.0"); got != "bulk" {
		t.Errorf("recorded storage = %q, want bulk — the rule change repointed an already-placed version", got)
	}
}

// TestReplacePlacementIsTheDeliberateCase covers the opt-out.
func TestReplacePlacementIsTheDeliberateCase(t *testing.T) {
	pl, store, _ := twoBackendPlacer(t, map[string]string{manifest.TypeBinary: "default"}, true)
	addBinary(t, store, "awscli", "2.0.0", "bulk")

	if _, err := pl.forVersion(t.Context(), manifest.TypeBinary, "awscli", "2.0.0", "binaries/awscli/2.0.0/awscli.zip"); err != nil {
		t.Fatalf("forVersion: %v", err)
	}
	if got := recordedStorage(t, store, manifest.TypeBinary, "awscli", "2.0.0"); got != "" {
		t.Errorf("recorded storage = %q, want the zero value after --replace-placement moved it to default", got)
	}
}

// TestForTypeRefusesToSplitADirectory is hazard H4. SyncDir has no per-version
// granularity, so a rule changed between two runs strands half a tree with no
// listing to reunite it.
func TestForTypeRefusesToSplitADirectory(t *testing.T) {
	pl, store, _ := twoBackendPlacer(t, map[string]string{manifest.TypeApt: "bulk"}, false)
	if err := store.AddVersion(t.Context(), manifest.TypeApt, "nginx", manifest.VersionEntry{Version: "1.0"}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	_, err := pl.forType(t.Context(), manifest.TypeApt)
	if err == nil {
		t.Fatal("forType proceeded with a changed type rule, splitting the tree")
	}
	for _, want := range []string{`nginx@1.0 (on "default")`, "--replace-placement"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to contain %q", err, want)
		}
	}
}

// TestForTypeStampsEveryVersionWithTheFlag checks the deliberate path repoints
// the whole tree, so no version is left naming a backend the rest abandoned.
func TestForTypeStampsEveryVersionWithTheFlag(t *testing.T) {
	pl, store, out := twoBackendPlacer(t, map[string]string{manifest.TypeApt: "bulk"}, true)
	for _, v := range []string{"1.0", "2.0"} {
		if err := store.AddVersion(t.Context(), manifest.TypeApt, "nginx", manifest.VersionEntry{Version: v}); err != nil {
			t.Fatalf("AddVersion: %v", err)
		}
	}

	if _, err := pl.forType(t.Context(), manifest.TypeApt); err != nil {
		t.Fatalf("forType: %v", err)
	}
	for _, v := range []string{"1.0", "2.0"} {
		if got := recordedStorage(t, store, manifest.TypeApt, "nginx", v); got != "bulk" {
			t.Errorf("nginx@%s recorded %q, want bulk", v, got)
		}
	}
	if !strings.Contains(out.String(), "still in their previous backend") {
		t.Errorf("no warning about the stranded objects; got %q", out.String())
	}
}

// TestNoNamedBackendsChangesNothing is the back-compat guard at the write
// side: with none of the new config keys, every placement is the default and
// no manifest gains a storage key.
func TestNoNamedBackendsChangesNothing(t *testing.T) {
	cfg := &config.Config{StorageBackend: "local", StoragePath: t.TempDir()}
	store := manifest.NewLocalStore(t.TempDir())
	pl, err := newPlacer(context.Background(), cfg, store, &bytes.Buffer{}, false)
	if err != nil {
		t.Fatalf("newPlacer: %v", err)
	}
	addBinary(t, store, "awscli", "2.0.0", "")
	if err := store.AddVersion(t.Context(), manifest.TypeApt, "nginx", manifest.VersionEntry{Version: "1.0"}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	if _, err := pl.forVersion(t.Context(), manifest.TypeBinary, "awscli", "2.0.0", "binaries/awscli/2.0.0/awscli.zip"); err != nil {
		t.Fatalf("forVersion: %v", err)
	}
	if _, err := pl.forType(t.Context(), manifest.TypeApt); err != nil {
		t.Fatalf("forType: %v", err)
	}
	if got := recordedStorage(t, store, manifest.TypeBinary, "awscli", "2.0.0"); got != "" {
		t.Errorf("binary recorded %q, want the zero value", got)
	}
	if got := recordedStorage(t, store, manifest.TypeApt, "nginx", "1.0"); got != "" {
		t.Errorf("apt recorded %q, want the zero value", got)
	}
	if got := pl.stores.Placement(manifest.TypeApt, ""); got.Name != storage.DefaultName {
		t.Errorf("Placement = %q, want %q", got.Name, storage.DefaultName)
	}
}

// TestPackagePolicyDecidesTheUploadTarget is the write-side half of the
// package level: the upload path must read PackageManifest.StoragePolicy and
// record its answer, or the field is a value nothing consults.
func TestPackagePolicyDecidesTheUploadTarget(t *testing.T) {
	pl, store, _ := twoBackendPlacer(t, nil, false)
	addBinary(t, store, "awscli", "2.0.0", "")

	pm, err := store.GetPackage(t.Context(), manifest.TypeBinary, "awscli")
	if err != nil || pm == nil {
		t.Fatalf("GetPackage: %v", err)
	}
	pm.StoragePolicy = "bulk"
	if err := store.SavePackage(t.Context(), pm); err != nil {
		t.Fatalf("SavePackage: %v", err)
	}

	st, err := pl.forVersion(t.Context(), manifest.TypeBinary, "awscli", "2.0.0", "binaries/awscli/2.0.0/awscli.zip")
	if err != nil {
		t.Fatalf("forVersion: %v", err)
	}
	if got := recordedStorage(t, store, manifest.TypeBinary, "awscli", "2.0.0"); got != "bulk" {
		t.Fatalf("recorded %q, want bulk — storage_policy did not reach the upload path", got)
	}
	if st == nil {
		t.Fatal("forVersion returned no store")
	}
}

// TestPackagePolicyOverridesTheTypeRuleOnUpload: with both set, the package
// wins. The rule exists for a package whose bytes must not go where the rest
// of its type goes, so losing to the type rule would defeat it entirely.
func TestPackagePolicyOverridesTheTypeRuleOnUpload(t *testing.T) {
	pl, store, _ := twoBackendPlacer(t, map[string]string{manifest.TypeBinary: "bulk"}, false)
	addBinary(t, store, "awscli", "2.0.0", "")

	pm, _ := store.GetPackage(t.Context(), manifest.TypeBinary, "awscli")
	pm.StoragePolicy = storage.DefaultName
	if err := store.SavePackage(t.Context(), pm); err != nil {
		t.Fatalf("SavePackage: %v", err)
	}

	if _, err := pl.forVersion(t.Context(), manifest.TypeBinary, "awscli", "2.0.0", "binaries/awscli/2.0.0/awscli.zip"); err != nil {
		t.Fatalf("forVersion: %v", err)
	}
	if got := recordedStorage(t, store, manifest.TypeBinary, "awscli", "2.0.0"); got != "" {
		t.Fatalf("recorded %q, want the zero value — storage_by_type beat the package policy", got)
	}
}

// TestValidateManifestRejectsAnUnknownStoragePolicy: an unknown name discovered
// at the next upload has no obvious connection back to the edit that caused it,
// so pkg edit and pkg import both refuse it before SavePackage.
func TestValidateManifestRejectsAnUnknownStoragePolicy(t *testing.T) {
	cfg := &config.Config{
		StorageBackend:  "local",
		StoragePath:     t.TempDir(),
		StorageBackends: map[string]config.StorageSpec{"bulk": {Driver: "local", Path: t.TempDir()}},
	}
	pm := &manifest.PackageManifest{Name: "netbox", Type: manifest.TypeGit, StoragePolicy: "archive"}

	err := validateManifest(pm, cfg)
	if err == nil {
		t.Fatal("validateManifest accepted a storage_policy naming no configured backend")
	}
	for _, want := range []string{"storage_policy", "archive", "default, bulk"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}

	pm.StoragePolicy = "bulk"
	if err := validateManifest(pm, cfg); err != nil {
		t.Errorf("validateManifest rejected a configured backend: %v", err)
	}
}
