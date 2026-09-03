package main

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/server"
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

	st, err := pl.ForVersion(t.Context(), manifest.TypeBinary, "awscli", "2.0.0", "binaries/awscli/2.0.0/awscli.zip")
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

	if _, err := pl.ForVersion(t.Context(), manifest.TypeBinary, "awscli", "2.0.0", "binaries/awscli/2.0.0/awscli.zip"); err != nil {
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

	if _, err := pl.ForVersion(t.Context(), manifest.TypeBinary, "awscli", "2.0.0", "binaries/awscli/2.0.0/awscli.zip"); err != nil {
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

	if _, err := pl.ForVersion(t.Context(), manifest.TypeBinary, "awscli", "2.0.0", "binaries/awscli/2.0.0/awscli.zip"); err != nil {
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

	_, err := pl.ForType(t.Context(), manifest.TypeApt)
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

	if _, err := pl.ForType(t.Context(), manifest.TypeApt); err != nil {
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

	if _, err := pl.ForVersion(t.Context(), manifest.TypeBinary, "awscli", "2.0.0", "binaries/awscli/2.0.0/awscli.zip"); err != nil {
		t.Fatalf("forVersion: %v", err)
	}
	if _, err := pl.ForType(t.Context(), manifest.TypeApt); err != nil {
		t.Fatalf("forType: %v", err)
	}
	if got := recordedStorage(t, store, manifest.TypeBinary, "awscli", "2.0.0"); got != "" {
		t.Errorf("binary recorded %q, want the zero value", got)
	}
	if got := recordedStorage(t, store, manifest.TypeApt, "nginx", "1.0"); got != "" {
		t.Errorf("apt recorded %q, want the zero value", got)
	}
	if got := pl.Stores().Placement(manifest.TypeApt, ""); got.Name != storage.DefaultName {
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

	st, err := pl.ForVersion(t.Context(), manifest.TypeBinary, "awscli", "2.0.0", "binaries/awscli/2.0.0/awscli.zip")
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

	if _, err := pl.ForVersion(t.Context(), manifest.TypeBinary, "awscli", "2.0.0", "binaries/awscli/2.0.0/awscli.zip"); err != nil {
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

	var warnings bytes.Buffer
	err := validateManifest(pm, cfg, &warnings)
	if err == nil {
		t.Fatal("validateManifest accepted a storage_policy naming no configured backend")
	}
	for _, want := range []string{"storage_policy", "archive", "default, bulk"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}

	pm.StoragePolicy = "bulk"
	if err := validateManifest(pm, cfg, &warnings); err != nil {
		t.Errorf("validateManifest rejected a configured backend: %v", err)
	}
}

// TestValidateManifestWarnsOnAnInertStoragePolicy: pypi uploads a whole
// directory, so its package level is never consulted and this policy will
// change nothing. Recording an inert field without comment is how an operator
// comes to believe a package has been placed.
//
// A warning rather than a refusal, because manifests already in the field
// carry these and failing would make 'pkg edit' refuse a file that was legal
// when it was written.
func TestValidateManifestWarnsOnAnInertStoragePolicy(t *testing.T) {
	cfg := &config.Config{
		StorageBackend:  "local",
		StoragePath:     t.TempDir(),
		StorageBackends: map[string]config.StorageSpec{"bulk": {Driver: "local", Path: t.TempDir()}},
	}

	var warnings bytes.Buffer
	pm := &manifest.PackageManifest{Name: "requests", Type: manifest.TypePypi, StoragePolicy: "bulk"}
	if err := validateManifest(pm, cfg, &warnings); err != nil {
		t.Fatalf("validateManifest: %v", err)
	}
	for _, want := range []string{"no effect", "storage_by_type.pypi"} {
		if !strings.Contains(warnings.String(), want) {
			t.Errorf("warning %q does not mention %q", warnings.String(), want)
		}
	}

	// A type placed per version gets no warning: the policy is honored there.
	warnings.Reset()
	npm := &manifest.PackageManifest{Name: "cli", Type: manifest.TypeNpm, StoragePolicy: "bulk"}
	if err := validateManifest(npm, cfg, &warnings); err != nil {
		t.Fatalf("validateManifest: %v", err)
	}
	if warnings.Len() != 0 {
		t.Errorf("warned about a storage_policy the npm write path honors: %q", warnings.String())
	}
}

// TestWritePlacementReportsWhatTheWritePathDoes is requirement 4's guard.
//
// 'bodega pkg storage' exists to answer "why did this package land there", and
// an operator reads it after the fact. Resolver.Placement honors a package
// policy for every type; the write path does not for pypi, because ForType
// uploads the whole wheel tree to one prefix and passes "". Printing the
// hierarchy's answer there reports a level no upload will ever use, which is
// worse than printing nothing.
func TestWritePlacementReportsWhatTheWritePathDoes(t *testing.T) {
	cfg := &config.Config{
		StorageBackend:  "local",
		StoragePath:     t.TempDir(),
		StorageBackends: map[string]config.StorageSpec{"bulk": {Driver: "local", Path: t.TempDir()}},
	}
	stores, err := storage.NewResolver(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	for _, typ := range []string{manifest.TypePypi} {
		d := writePlacement(stores, typ, "bulk")
		if d.Name != storage.DefaultName {
			t.Errorf("%s: writePlacement named %q, but forType writes to %q", typ, d.Name, storage.DefaultName)
		}
		if d.Level != storage.LevelDefault {
			t.Errorf("%s: level %v, want LevelDefault — no rule applied", typ, d.Level)
		}
		if d.IgnoredPolicy != "bulk" {
			t.Errorf("%s: the skipped policy was dropped rather than reported", typ)
		}
		if !strings.Contains(d.Reason(typ), "not consulted") {
			t.Errorf("%s: Reason %q does not say the policy was skipped", typ, d.Reason(typ))
		}
		if w := storagePolicyWarning(typ, "bulk"); !strings.Contains(w, "storage_by_type."+typ) {
			t.Errorf("%s: warning %q does not name the config key that would work", typ, w)
		}
	}

	// The seven per-version types: the policy decides and wins. apt and git
	// joined them when their uploaders started walking manifest entries.
	for _, typ := range []string{
		manifest.TypeBinary, manifest.TypeNpm, manifest.TypeCargo,
		manifest.TypeGomod, manifest.TypeHelm, manifest.TypeApt, manifest.TypeGit,
	} {
		d := writePlacement(stores, typ, "bulk")
		if d.Name != "bulk" || d.Level != storage.LevelPackage {
			t.Errorf("%s: writePlacement = %+v, want bulk at the package level", typ, d)
		}
		if d.IgnoredPolicy != "" {
			t.Errorf("%s: reported a policy as skipped that the write path honors", typ)
		}
		if storagePolicyWarning(typ, "bulk") != "" {
			t.Errorf("%s: warned about a policy the write path honors", typ)
		}
	}
}

// TestGitPlacementSurvivesTheHandoffToTheServer walks the chain the 404 in #67
// came out of, in one process: the placement writer repoints a git entry, the
// bytes end up on the named backend and nowhere else, and a server built from
// the same manifest serves them.
//
// 'bodega pkg move' refuses git, so 'build sync --replace-placement' is the
// only thing that writes VersionEntry.Storage for the type. It copies nothing,
// leaving the operator to re-upload and remove the originals; that is the same
// state --delete-source produces for a movable type, and it is what the
// seeding below reproduces.
//
// The type rule is dropped before the server starts. A rule still naming
// "bulk" would let a read resolving by type answer 200 as well, and the
// assertion would hold against the tree this test exists to fail on.
func TestGitPlacementSurvivesTheHandoffToTheServer(t *testing.T) {
	ctx := t.Context()
	defaultRoot, bulkRoot := t.TempDir(), t.TempDir()
	cfg := &config.Config{
		ManifestDir:     "manifests",
		AptCodename:     "noble",
		StorageBackend:  "local",
		StoragePath:     defaultRoot,
		StorageBackends: map[string]config.StorageSpec{"bulk": {Driver: "local", Path: bulkRoot}},
		StorageByType:   map[string]string{manifest.TypeGit: "bulk"},
	}

	store := manifest.NewLocalStore(t.TempDir())
	if err := store.AddVersion(ctx, manifest.TypeGit, "netbox", manifest.VersionEntry{
		Ref: "v4.5.5",
		URL: "https://github.com/netbox-community/netbox",
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	key := manifest.GitKey("netbox", "v4.5.5", false)
	writeFile(t, defaultRoot, key, "from-default")

	pl, err := newPlacer(ctx, cfg, store, &bytes.Buffer{}, true)
	if err != nil {
		t.Fatalf("newPlacer: %v", err)
	}
	if _, err := pl.ForType(ctx, manifest.TypeGit); err != nil {
		t.Fatalf("forType(git): %v", err)
	}
	if got := recordedStorage(t, store, manifest.TypeGit, "netbox", "v4.5.5"); got != "bulk" {
		t.Fatalf("recorded storage = %q, want %q after --replace-placement", got, "bulk")
	}

	writeFile(t, bulkRoot, key, "from-bulk")
	if err := os.Remove(filepath.Join(defaultRoot, filepath.FromSlash(key))); err != nil {
		t.Fatalf("remove the source object: %v", err)
	}

	delete(cfg.StorageByType, manifest.TypeGit)
	stores, err := storage.NewResolver(ctx, cfg)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	ts := httptest.NewServer(server.New(cfg, store, stores, ":0", nil).Handler())
	t.Cleanup(ts.Close)

	assertServes(t, ts.URL+"/git/netbox/netbox-v4.5.5.bundle", "from-bulk")
}
