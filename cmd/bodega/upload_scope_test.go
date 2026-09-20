package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/placement"
)

func scopeStore(t *testing.T) *manifest.Store {
	t.Helper()
	store := manifest.NewLocalStore(t.TempDir())
	if err := store.AddVersion(t.Context(), manifest.TypeBinary, "example-tool-v2", manifest.VersionEntry{
		Version: "2.15.0",
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	if err := store.AddVersion(t.Context(), manifest.TypePypi, "examplesdk", manifest.VersionEntry{
		Version: "1.26.0",
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	if err := store.SaveIndex(t.Context()); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}
	return store
}

func scopeConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		BuildRoot:       t.TempDir(),
		StorageBackend:  "local",
		StoragePath:     t.TempDir(),
		StorageBackends: map[string]config.StorageSpec{"bulk": {Driver: "local", Path: t.TempDir()}},
	}
}

func scopePlacer(t *testing.T, cfg *config.Config, store *manifest.Store) *placer {
	t.Helper()
	pl, err := newPlacer(t.Context(), cfg, store, &bytes.Buffer{}, false)
	if err != nil {
		t.Fatalf("newPlacer: %v", err)
	}
	return pl
}

// TestParseUploadArgsRefusesAMistypedType. 'bodega build upload gitt' failed on
// the unknown type before this command took a package name; read as a selector
// it would filter for a package nothing is called, upload nothing and exit 0.
func TestParseUploadArgsRefusesAMistypedType(t *testing.T) {
	_, _, err := parseUploadArgs([]string{"gitt"}, scopeStore(t))
	if err == nil {
		t.Fatal("parseUploadArgs accepted a name that is neither a type nor a package")
	}
	if !strings.Contains(err.Error(), "gitt") {
		t.Errorf("error = %q, want it to name what was not found", err)
	}
}

func TestParseUploadArgsSplitsTypesFromTheSelector(t *testing.T) {
	types, selector, err := parseUploadArgs([]string{manifest.TypeBinary, "example-tool-v2@2.15.0"}, scopeStore(t))
	if err != nil {
		t.Fatalf("parseUploadArgs: %v", err)
	}
	if len(types) != 1 || types[0] != manifest.TypeBinary {
		t.Errorf("types = %v, want [binary]", types)
	}
	if selector != "example-tool-v2@2.15.0" {
		t.Errorf("selector = %q, want the package and version", selector)
	}
}

func TestParseUploadArgsRefusesASecondPackage(t *testing.T) {
	_, _, err := parseUploadArgs([]string{manifest.TypeBinary, "example-tool-v2", "examplesdk"}, scopeStore(t))
	if err == nil {
		t.Fatal("parseUploadArgs accepted two package selectors")
	}
}

// TestStorageNeedsOneVersion: without one it is a package-level placement,
// which storage_policy already is.
func TestStorageNeedsOneVersion(t *testing.T) {
	cfg, store := scopeConfig(t), scopeStore(t)
	err := applyUploadScope(cfg, scopePlacer(t, cfg, store), []string{manifest.TypeBinary}, "example-tool-v2", "bulk")
	if err == nil {
		t.Fatal("--storage was accepted without a version")
	}
	if !strings.Contains(err.Error(), "pkg create") {
		t.Errorf("error = %q, want it to name the package-level surface that does exist", err)
	}
}

// TestStorageNeedsOneType: across every type it would place whatever package of
// that name each one happens to hold.
func TestStorageNeedsOneType(t *testing.T) {
	cfg, store := scopeConfig(t), scopeStore(t)
	err := applyUploadScope(cfg, scopePlacer(t, cfg, store), manifest.AllTypes, "example-tool-v2@2.15.0", "bulk")
	if err == nil {
		t.Fatal("--storage was accepted across every type")
	}
}

// TestStorageRefusesADirectoryPlacedType. A pypi version has no object of its
// own, so there is nothing for a per-version flag to place.
func TestStorageRefusesADirectoryPlacedType(t *testing.T) {
	cfg, store := scopeConfig(t), scopeStore(t)
	err := applyUploadScope(cfg, scopePlacer(t, cfg, store), []string{manifest.TypePypi}, "examplesdk@1.26.0", "bulk")
	if err == nil {
		t.Fatal("--storage was accepted for pypi")
	}
	if !strings.Contains(err.Error(), "storage_by_type.pypi") {
		t.Errorf("error = %q, want it to name what does place a pypi tree", err)
	}
}

// TestStorageRefusesAnUnconfiguredBackend. checkBackendName is what stops a
// name that resolves to nothing being recorded on the entry, where it would
// fail every later read rather than this command.
func TestStorageRefusesAnUnconfiguredBackend(t *testing.T) {
	cfg, store := scopeConfig(t), scopeStore(t)
	err := applyUploadScope(cfg, scopePlacer(t, cfg, store), []string{manifest.TypeBinary}, "example-tool-v2@2.15.0", "nowhere")
	if err == nil {
		t.Fatal("--storage was accepted for a backend no config defines")
	}
}

// TestConfirmPlacedFailsARunThatNeverReachedTheVersion. The flag reports
// success or it reports which version it did not find; it never reports
// success for a write that did not happen.
func TestConfirmPlacedFailsARunThatNeverReachedTheVersion(t *testing.T) {
	cfg, store := scopeConfig(t), scopeStore(t)
	pl := scopePlacer(t, cfg, store)
	if err := applyUploadScope(cfg, pl, []string{manifest.TypeBinary}, "example-tool-v2@2.15.0", "bulk"); err != nil {
		t.Fatalf("applyUploadScope: %v", err)
	}
	err := confirmPlaced(pl, manifest.TypeBinary, "example-tool-v2@2.15.0", "bulk")
	if err == nil {
		t.Fatal("confirmPlaced passed a run that placed nothing")
	}
	for _, want := range []string{"example-tool-v2", "2.15.0", "bulk"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to name %s", err, want)
		}
	}
}

func TestPrintDriftNamesTheMoveForEachRow(t *testing.T) {
	out := &bytes.Buffer{}
	printDrift(out, []placement.DriftRow{
		{Type: manifest.TypeBinary, Package: "example-tool-v2", Version: "2.15.0", On: "default", Rule: "bulk"},
		{Type: manifest.TypePypi, Package: "examplesdk", Version: "1.26.0", On: "default", Rule: "archive"},
	})
	got := out.String()
	for _, want := range []string{
		"TYPE", "PACKAGE", "VERSION", "ON", "RULE",
		"bodega pkg move binary example-tool-v2@2.15.0 --to bulk",
		"storage_by_type.pypi",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("printDrift output missing %q:\n%s", want, got)
		}
	}
}

func TestPrintDriftSaysSoWhenNothingDrifted(t *testing.T) {
	out := &bytes.Buffer{}
	printDrift(out, nil)
	if !strings.Contains(out.String(), "No drift") {
		t.Errorf("printDrift(nil) = %q, want it to say the catalog agrees", out.String())
	}
}

// placeFixture points the process at a config with a second backend, seeds one
// binary entry recorded nowhere, and writes its artifact under build_root. It
// returns the two storage paths and the manifest store the command will load.
func placeFixture(t *testing.T) (defaultPath, bulkPath, manifestDir string) {
	t.Helper()
	buildRoot := t.TempDir()
	defaultPath, bulkPath, manifestDir = t.TempDir(), t.TempDir(), t.TempDir()

	body, err := json.Marshal(map[string]any{
		"build_root":      buildRoot,
		"storage_backend": "local",
		"storage_path":    defaultPath,
		"manifest_dir":    manifestDir,
		"storage_backends": map[string]any{
			"bulk": map[string]string{"driver": "local", "path": bulkPath},
		},
	})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfgPath, body, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(config.EnvConfigFile, cfgPath)
	t.Setenv(config.EnvBuildRoot, "")
	t.Setenv(config.EnvManifestDir, "")
	t.Setenv(config.EnvBucket, "")

	artifact := filepath.Join(buildRoot, "binaries", "example-tool-v2", "2.15.0", "example-tool.zip")
	if err := os.MkdirAll(filepath.Dir(artifact), 0o755); err != nil {
		t.Fatalf("mkdir binaries: %v", err)
	}
	if err := os.WriteFile(artifact, []byte("example-tool"), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	store := manifest.NewLocalStore(manifestDir)
	if err := store.AddVersion(t.Context(), manifest.TypeBinary, "example-tool-v2", manifest.VersionEntry{
		Version:  "2.15.0",
		Filename: "example-tool.zip",
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	if err := store.SaveIndex(t.Context()); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}
	return defaultPath, bulkPath, manifestDir
}

// TestSyncStorageWritesTheNamedBackendAndRecordsIt runs the composed path the
// flag, the selector, the placer and the local backend all meet on. Each of
// them is covered alone above; none of those covers the one that matters,
// which is whether the bytes land on the backend the operator named.
func TestSyncStorageWritesTheNamedBackendAndRecordsIt(t *testing.T) {
	defaultPath, bulkPath, manifestDir := placeFixture(t)

	cmd := newSyncCmd(&globalFlags{})
	cmd.SetArgs([]string{manifest.TypeBinary, "example-tool-v2@2.15.0", "--storage", "bulk"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("bodega build sync binary example-tool-v2@2.15.0 --storage bulk: %v", err)
	}

	key := filepath.FromSlash(manifest.BinaryKey("example-tool-v2", "2.15.0", "example-tool.zip"))
	if _, err := os.Stat(filepath.Join(bulkPath, key)); err != nil {
		t.Errorf("nothing landed on the named backend: %v", err)
	}
	if _, err := os.Stat(filepath.Join(defaultPath, key)); err == nil {
		t.Error("the artifact landed on the default backend too; --storage names one destination")
	}

	pm, err := manifest.NewLocalStore(manifestDir).GetPackage(t.Context(), manifest.TypeBinary, "example-tool-v2")
	if err != nil || pm == nil {
		t.Fatalf("GetPackage: %v", err)
	}
	if pm.Versions[0].Storage != "bulk" {
		t.Errorf("recorded storage = %q, want bulk: an unrecorded write is one no read can find",
			pm.Versions[0].Storage)
	}
}

// TestSyncStorageFailsWhenTheVersionIsNotThere closes the quiet failure end to
// end: one digit wrong and the artifact goes where the rule says, with the
// command reporting the upload it did do.
func TestSyncStorageFailsWhenTheVersionIsNotThere(t *testing.T) {
	_, bulkPath, _ := placeFixture(t)

	cmd := newSyncCmd(&globalFlags{})
	cmd.SetArgs([]string{manifest.TypeBinary, "example-tool-v2@2.15.1", "--storage", "bulk"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	err := cmd.Execute()
	if err == nil {
		t.Fatal("sync reported success for a version it never placed")
	}
	if !strings.Contains(err.Error(), "2.15.1") {
		t.Errorf("error = %q, want it to name the version that was not found", err)
	}
	if _, statErr := os.Stat(filepath.Join(bulkPath, filepath.FromSlash(
		manifest.BinaryKey("example-tool-v2", "2.15.0", "example-tool.zip")))); statErr == nil {
		t.Error("a mistyped version still wrote to the named backend")
	}
}
