package builder

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// helper: create a regular file (and parent dirs) with dummy content.
func touchFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte("test"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// helper: create a directory.
func mkDir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func TestCheckBinaryStage_NotFetched(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	ve := manifest.VersionEntry{URL: "https://example.com/example-tool.zip"}
	s := CheckBinaryStage(cfg, "example-tool", ve)
	if s.Fetched || s.Built || s.Packaged {
		t.Errorf("expected all false when file absent, got %+v", s)
	}
}

func TestCheckBinaryStage_Fetched(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	ve := manifest.VersionEntry{URL: "https://example.com/example-tool.zip"}
	d := buildDirs(root)
	touchFile(t, filepath.Join(d.binaries, "example-tool", "example-tool.zip"))

	s := CheckBinaryStage(cfg, "example-tool", ve)
	if !s.Fetched || !s.Built || !s.Packaged {
		t.Errorf("expected all true when file present, got %+v", s)
	}
}

func TestCheckBinaryStage_Versioned(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	ve := manifest.VersionEntry{Version: "2.13.0", URL: "https://example.com/example-tool.zip"}
	d := buildDirs(root)

	// File NOT at versioned path → not fetched.
	touchFile(t, filepath.Join(d.binaries, "example-tool", "example-tool.zip"))
	s := CheckBinaryStage(cfg, "example-tool", ve)
	if s.Fetched {
		t.Error("expected Fetched=false when file at unversioned path but version is set")
	}

	// File at versioned path → fetched.
	touchFile(t, filepath.Join(d.binaries, "example-tool", "2.13.0", "example-tool.zip"))
	s = CheckBinaryStage(cfg, "example-tool", ve)
	if !s.Fetched {
		t.Error("expected Fetched=true when file at versioned path")
	}
}

func TestBinaryDestPath_NoVersion(t *testing.T) {
	root := t.TempDir()
	d := buildDirs(root)
	ve := manifest.VersionEntry{URL: "https://example.com/tool.tar.gz"}
	got, err := binaryDestPath(d, "tool", ve)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(d.binaries, "tool", "tool.tar.gz")
	if got != want {
		t.Errorf("binaryDestPath (no version) = %q, want %q", got, want)
	}
}

func TestBinaryDestPath_WithVersion(t *testing.T) {
	root := t.TempDir()
	d := buildDirs(root)
	ve := manifest.VersionEntry{Version: "v1.2", URL: "https://example.com/tool.tar.gz"}
	got, err := binaryDestPath(d, "tool", ve)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(d.binaries, "tool", "v1.2", "tool.tar.gz")
	if got != want {
		t.Errorf("binaryDestPath (versioned) = %q, want %q", got, want)
	}
}

func TestBinaryDestPath_FilenameOverride(t *testing.T) {
	root := t.TempDir()
	d := buildDirs(root)
	ve := manifest.VersionEntry{Filename: "custom-name.bin", URL: "https://example.com/original.bin"}
	got, err := binaryDestPath(d, "tool", ve)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(d.binaries, "tool", "custom-name.bin")
	if got != want {
		t.Errorf("binaryDestPath (filename override) = %q, want %q", got, want)
	}
}

func TestCheckGitStage_Empty(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	ve := manifest.VersionEntry{URL: "https://github.com/widget/widget", Ref: "v4.0.0", Source: "clone"}
	s := CheckGitStage(cfg, "widget", ve)
	if s.Fetched || s.Packaged {
		t.Errorf("expected all false when nothing on disk, got %+v", s)
	}
}

func TestCheckGitStage_Fetched(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	ve := manifest.VersionEntry{URL: "https://github.com/widget/widget", Ref: "v4.0.0", Source: "clone"}
	d := buildDirs(root)

	mkDir(t, gitBareDir(d, "widget", ve))
	s := CheckGitStage(cfg, "widget", ve)
	if !s.Fetched {
		t.Error("expected Fetched=true when bare repo dir exists")
	}
	if s.Packaged {
		t.Error("expected Packaged=false when bundle absent")
	}
}

func TestCheckGitStage_Packaged(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	ve := manifest.VersionEntry{URL: "https://github.com/widget/widget", Ref: "v4.0.0", Source: "clone"}
	d := buildDirs(root)

	mkDir(t, gitBareDir(d, "widget", ve))
	bundlePath := filepath.Join(d.bundles, "widget", "widget-"+ve.Ref+".bundle")
	writeBundle(t, bundlePath, true)

	s := CheckGitStage(cfg, "widget", ve)
	if !s.Fetched {
		t.Error("expected Fetched=true")
	}
	if !s.Packaged {
		t.Error("expected Packaged=true when the bundle carries a HEAD")
	}
}

// A bundle with no HEAD clones into an empty repository. The packaging stage
// rewrites one only while the stage check calls it unpackaged, so this is the
// path that repairs an artifact built before HEAD was packaged.
func TestCheckGitStage_PackagedBundleWithoutHEAD(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	ve := manifest.VersionEntry{URL: "https://github.com/widget/widget", Ref: "v4.0.0", Source: "clone"}
	d := buildDirs(root)

	mkDir(t, gitBareDir(d, "widget", ve))
	writeBundle(t, filepath.Join(d.bundles, "widget", "widget-"+ve.Ref+".bundle"), false)

	s := CheckGitStage(cfg, "widget", ve)
	if !s.Built {
		t.Error("expected Built=true: the file is on disk")
	}
	if s.Packaged {
		t.Error("expected Packaged=false when the bundle carries no HEAD")
	}
}

// writeBundle writes a bundle header, with or without a HEAD ref. Only the
// header is read by the stage check, so the pack is a stand-in.
func writeBundle(t *testing.T, path string, withHEAD bool) {
	t.Helper()
	const id = "0f11ee6918f41a04c201eceeadf612a377bc7fbc"
	body := "# v2 git bundle\n"
	if withHEAD {
		body += id + " HEAD\n"
	}
	body += id + " refs/tags/v4.0.0\n\nPACK"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestGitBareDir(t *testing.T) {
	root := t.TempDir()
	d := buildDirs(root)
	ve := manifest.VersionEntry{Ref: "v4.0.0", Source: "clone"}
	got := gitBareDir(d, "widget", ve)
	want := filepath.Join(d.repos, "widget", "widget-v4.0.0.git") // single-segment name: no "--" replacement needed
	if got != want {
		t.Errorf("gitBareDir = %q, want %q", got, want)
	}
}

func TestAptSourceDir_NoVersion(t *testing.T) {
	root := t.TempDir()
	d := buildDirs(root)
	ve := manifest.VersionEntry{URL: "https://example.com/example-corp/widget-utils"}
	got := aptSourceDir(d, "efs-utils", ve)
	want := filepath.Join(d.sources, "efs-utils")
	if got != want {
		t.Errorf("aptSourceDir (no version) = %q, want %q", got, want)
	}
}

func TestAptSourceDir_WithVersion(t *testing.T) {
	root := t.TempDir()
	d := buildDirs(root)
	ve := manifest.VersionEntry{Version: "2.0.1", URL: "https://example.com/example-corp/widget-utils"}
	got := aptSourceDir(d, "efs-utils", ve)
	want := filepath.Join(d.sources, "efs-utils-2.0.1")
	if got != want {
		t.Errorf("aptSourceDir (versioned) = %q, want %q", got, want)
	}
}

func TestAptSourceDir_SourceNameOverride(t *testing.T) {
	root := t.TempDir()
	d := buildDirs(root)
	ve := manifest.VersionEntry{SourceName: "amazon-efs-utils", Version: "2.0.1", URL: "https://example.com/example-corp/widget-utils"}
	got := aptSourceDir(d, "efs-utils", ve)
	want := filepath.Join(d.sources, "amazon-efs-utils-2.0.1")
	if got != want {
		t.Errorf("aptSourceDir (source_name + version) = %q, want %q", got, want)
	}
}

func TestCheckAptStage_Empty(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	ve := manifest.VersionEntry{URL: "https://example.com/example-corp/widget-utils", BuildCmd: "make deb"}
	s := CheckAptStage(cfg, "efs-utils", ve)
	if s.Fetched || s.Built || s.Packaged {
		t.Errorf("expected all false when nothing on disk, got %+v", s)
	}
}

func TestCheckAptStage_SourceBuildFetched(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	ve := manifest.VersionEntry{URL: "https://example.com/example-corp/widget-utils", BuildCmd: "make deb"}
	d := buildDirs(root)

	mkDir(t, aptSourceDir(d, "efs-utils", ve))
	s := CheckAptStage(cfg, "efs-utils", ve)
	if !s.Fetched {
		t.Error("expected Fetched=true when clone dir exists")
	}
	if s.Built {
		t.Error("expected Built=false when no .deb in clone dir")
	}
}

func TestCheckAptStage_SourceBuildBuilt(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	ve := manifest.VersionEntry{URL: "https://example.com/example-corp/widget-utils", BuildCmd: "make deb"}
	d := buildDirs(root)

	cloneDir := aptSourceDir(d, "efs-utils", ve)
	mkDir(t, cloneDir)
	touchFile(t, filepath.Join(cloneDir, "efs-utils_2.0.deb"))

	s := CheckAptStage(cfg, "efs-utils", ve)
	if !s.Fetched || !s.Built {
		t.Errorf("expected Fetched+Built=true when .deb present, got %+v", s)
	}
}

func TestCheckAptStage_SourceBuildOtherRefNotFetched(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	ve := manifest.VersionEntry{URL: "https://example.com/example-corp/widget-utils", BuildCmd: "make deb", Ref: "v2.0.1"}
	d := buildDirs(root)

	cloneDir := aptSourceDir(d, "efs-utils", ve)
	mkDir(t, filepath.Join(cloneDir, ".git"))
	if err := os.WriteFile(aptRefMarkerPath(cloneDir), []byte("v2.0.0"), 0o644); err != nil {
		t.Fatal(err)
	}
	touchFile(t, filepath.Join(cloneDir, "efs-utils_2.0.deb"))

	if s := CheckAptStage(cfg, "efs-utils", ve); s.Fetched || s.Built {
		t.Errorf("a clone recorded at v2.0.0 counted for ref v2.0.1: %+v", s)
	}
	ve.Ref = "v2.0.0"
	if s := CheckAptStage(cfg, "efs-utils", ve); !s.Fetched || !s.Built {
		t.Errorf("a clone recorded at the entry's ref did not count: %+v", s)
	}
}

func TestCheckAptStage_AptGetFetched(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	// No URL → apt-get download entry.
	ve := manifest.VersionEntry{}
	d := buildDirs(root)

	// .deb goes in per-package subdirectory.
	pkgDir := filepath.Join(d.sources, "curl")
	mkDir(t, pkgDir)
	touchFile(t, filepath.Join(pkgDir, "curl_7.0_amd64.deb"))
	s := CheckAptStage(cfg, "curl", ve)
	if !s.Fetched || !s.Built {
		t.Errorf("expected Fetched+Built=true for apt-get entry with .deb present, got %+v", s)
	}
}

func TestPypiWheelsDir(t *testing.T) {
	root := t.TempDir()
	d := buildDirs(root)
	got := pypiWheelsDir(d)
	if got != d.wheels {
		t.Errorf("pypiWheelsDir = %q, want %q", got, d.wheels)
	}
}

func TestCheckPypiStage_Empty(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	store := manifest.NewLocalStore(root)
	s := CheckPypiStage(cfg, store)
	if s.Fetched || s.Built || s.Packaged {
		t.Errorf("expected all false when nothing on disk, got %+v", s)
	}
}

func TestCheckPypiStage_Fetched(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	store := manifest.NewLocalStore(root)

	touchFile(t, filepath.Join(root, "combined-requirements.txt"))
	if CheckPypiStage(cfg, store).Fetched {
		t.Error("expected Fetched=false with no resolved closure for the build to read")
	}
	touchFile(t, pypiLockPath(root))
	s := CheckPypiStage(cfg, store)
	if !s.Fetched {
		t.Error("expected Fetched=true when the requirements and the closure both exist")
	}
	if s.Built {
		t.Error("expected Built=false when no .whl files")
	}
}

func TestCheckPypiStage_Built(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	store := manifest.NewLocalStore(root)
	d := buildDirs(root)

	touchFile(t, filepath.Join(root, "combined-requirements.txt"))
	touchFile(t, pypiLockPath(root))
	wheelsDir := pypiWheelsDir(d)
	touchFile(t, filepath.Join(wheelsDir, "somepackage-1.0-py3-none-any.whl"))

	s := CheckPypiStage(cfg, store)
	if !s.Fetched || !s.Built {
		t.Errorf("expected Fetched+Built=true when .whl present, got %+v", s)
	}
	if s.Packaged {
		t.Error("expected Packaged=false when MANIFEST.sha256 absent")
	}
}

func TestCheckPypiStage_Packaged(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	store := manifest.NewLocalStore(root)
	d := buildDirs(root)

	touchFile(t, filepath.Join(root, "combined-requirements.txt"))
	touchFile(t, pypiLockPath(root))
	wheelsDir := pypiWheelsDir(d)
	whl := filepath.Join(wheelsDir, "somepackage-1.0-py3-none-any.whl")
	touchFile(t, whl)
	writeWheelManifest(t, wheelsDir, whl)

	s := CheckPypiStage(cfg, store)
	if !s.Fetched || !s.Built || !s.Packaged {
		t.Errorf("expected all true when MANIFEST.sha256 attests the wheels on disk, got %+v", s)
	}
}

// writeWheelManifest writes the MANIFEST.sha256 PackagePypi would write for
// exactly the wheels named.
func writeWheelManifest(t *testing.T, wheelsDir string, whls ...string) {
	t.Helper()
	var body strings.Builder
	for _, whl := range whls {
		sum, err := computeFileSHA256(whl)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&body, "%s  %s\n", sum, filepath.Base(whl))
	}
	if err := os.WriteFile(filepath.Join(wheelsDir, "MANIFEST.sha256"), []byte(body.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// R7: MANIFEST.sha256 existing is not MANIFEST.sha256 being true. A build that
// changed the wheel set leaves a file attesting the old one, and the cascade
// reads Packaged off it and skips the stage that would correct it.
func TestCheckPypiStageRefusesAStaleWheelManifest(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	store := manifest.NewLocalStore(root)
	d := buildDirs(root)
	wheelsDir := pypiWheelsDir(d)

	touchFile(t, filepath.Join(root, "combined-requirements.txt"))
	touchFile(t, pypiLockPath(root))
	old := filepath.Join(wheelsDir, "six-1.17.0-py3-none-any.whl")
	touchFile(t, old)
	writeWheelManifest(t, wheelsDir, old)

	if s := CheckPypiStage(cfg, store); !s.Packaged {
		t.Fatalf("a manifest that does reconcile was rejected: %+v", s)
	}

	// The re-pin: the old wheel goes, the new one arrives, the checksums do
	// not move.
	if err := os.Remove(old); err != nil {
		t.Fatal(err)
	}
	touchFile(t, filepath.Join(wheelsDir, "six-1.16.0-py3-none-any.whl"))
	if s := CheckPypiStage(cfg, store); s.Packaged {
		t.Error("a MANIFEST.sha256 naming neither wheel on disk was reported packaged")
	}

	// Same set, edited bytes.
	whl := filepath.Join(wheelsDir, "six-1.16.0-py3-none-any.whl")
	writeWheelManifest(t, wheelsDir, whl)
	if err := os.WriteFile(whl, []byte("other bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if s := CheckPypiStage(cfg, store); s.Packaged {
		t.Error("a MANIFEST.sha256 whose digest the wheel contradicts was reported packaged")
	}
}

func TestMergeSummaries_Nil(t *testing.T) {
	s := MergeSummaries(nil, nil)
	if s.Total != 0 || s.Failures != 0 {
		t.Errorf("MergeSummaries(nil,nil): want zero, got %+v", s)
	}
}

func TestMergeSummaries(t *testing.T) {
	a := &Summary{Total: 2, Failures: 1}
	b := &Summary{Total: 3, Failures: 0}
	got := MergeSummaries(a, b)
	if got.Total != 5 || got.Failures != 1 {
		t.Errorf("MergeSummaries: want Total=5 Failures=1, got %+v", got)
	}
}

func TestBinaryArtifactPaths(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	d := buildDirs(root)

	// Set up the store with packages.
	store := manifest.NewLocalStore(root)

	// Seed the store with binary packages.
	ctx := t.Context()
	if err := store.AddVersion(ctx, manifest.TypeBinary, "tool-a", manifest.VersionEntry{
		URL: "https://example.com/tool-a.zip",
	}); err != nil {
		t.Fatalf("AddVersion tool-a: %v", err)
	}
	if err := store.AddVersion(ctx, manifest.TypeBinary, "tool-b", manifest.VersionEntry{
		Version: "v2.0",
		URL:     "https://example.com/tool-b.tar.gz",
	}); err != nil {
		t.Fatalf("AddVersion tool-b: %v", err)
	}
	if err := store.AddVersion(ctx, manifest.TypeBinary, "tool-c", manifest.VersionEntry{
		URL: "https://example.com/tool-c.bin",
	}); err != nil {
		t.Fatalf("AddVersion tool-c: %v", err)
	}
	if err := store.SaveIndex(ctx); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}

	// Put tool-a and tool-b on disk.
	touchFile(t, filepath.Join(d.binaries, "tool-a", "tool-a.zip"))
	touchFile(t, filepath.Join(d.binaries, "tool-b", "v2.0", "tool-b.tar.gz"))

	paths := BinaryArtifactPaths(cfg, store, "")
	if len(paths) != 2 {
		t.Fatalf("expected 2 artifact paths, got %d: %v", len(paths), paths)
	}

	// Verify S3 keys.
	keyMap := make(map[string]string)
	for _, p := range paths {
		keyMap[p.ObjectKey] = p.Local
	}
	if _, ok := keyMap["binaries/tool-a/tool-a.zip"]; !ok {
		t.Error("missing S3 key binaries/tool-a/tool-a.zip")
	}
	if _, ok := keyMap["binaries/tool-b/v2.0/tool-b.tar.gz"]; !ok {
		t.Error("missing S3 key binaries/tool-b/v2.0/tool-b.tar.gz")
	}
}

// TestAptArtifactPathsResolveWithoutPoolPath covers the entry PackageApt could
// not stamp: control extraction failed, or the entry predates _pool_path
// entirely. It has to resolve to the key the server will look for, because a
// silent skip here turns a package that used to upload into one that no longer
// does, with nothing saying so.
func TestAptArtifactPathsResolveWithoutPoolPath(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	d := buildDirs(root)
	store := manifest.NewLocalStore(root)
	ctx := t.Context()

	if err := store.AddVersion(ctx, manifest.TypeApt, "stamped", manifest.VersionEntry{
		Version:  "1.0",
		Metadata: map[string]string{"_pool_path": "pool/main/s/stamped/stamped_1.0_amd64.deb"},
	}); err != nil {
		t.Fatalf("AddVersion stamped: %v", err)
	}
	if err := store.AddVersion(ctx, manifest.TypeApt, "bare", manifest.VersionEntry{
		Version:  "2.0",
		Metadata: map[string]string{"Architecture": "arm64"},
	}); err != nil {
		t.Fatalf("AddVersion bare: %v", err)
	}
	touchFile(t, filepath.Join(d.aptRepo, "pool", "main", "s", "stamped", "stamped_1.0_amd64.deb"))
	touchFile(t, filepath.Join(d.aptRepo, "pool", "main", "b", "bare", "bare_2.0_arm64.deb"))

	got := map[string]bool{}
	for _, p := range AptArtifactPaths(cfg, store, "") {
		got[p.ObjectKey] = true
	}
	for _, want := range []string{
		"packages/apt/pool/main/s/stamped/stamped_1.0_amd64.deb",
		"packages/apt/pool/main/b/bare/bare_2.0_arm64.deb",
	} {
		if !got[want] {
			t.Errorf("no artifact path for %q; got %v", want, got)
		}
	}
}

// TestGitArtifactPathsCoverBundlesAndReleases pins that the local path and the
// object key are derived from the same (name, ref, release) triple. A bundle
// uploaded under a release's key, or the reverse, 404s on a route that already
// recovered the ref correctly.
func TestGitArtifactPathsCoverBundlesAndReleases(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	d := buildDirs(root)
	store := manifest.NewLocalStore(root)
	ctx := t.Context()

	if err := store.AddVersion(ctx, manifest.TypeGit, "org/cloned", manifest.VersionEntry{
		Ref: "main", Source: "clone", URL: "https://example.com/org/cloned",
	}); err != nil {
		t.Fatalf("AddVersion cloned: %v", err)
	}
	if err := store.AddVersion(ctx, manifest.TypeGit, "tagged", manifest.VersionEntry{
		Ref: "v1.2.3", Source: "release", URL: "https://example.com/tagged",
	}); err != nil {
		t.Fatalf("AddVersion tagged: %v", err)
	}
	touchFile(t, filepath.Join(d.bundles, "org--cloned", "org--cloned-main.bundle"))
	touchFile(t, filepath.Join(d.bundles, "tagged", "tagged-v1.2.3.tar.gz"))

	got := map[string]bool{}
	for _, p := range GitArtifactPaths(cfg, store, "") {
		got[p.ObjectKey] = true
	}
	for _, want := range []string{
		manifest.GitKey("org/cloned", "main", false),
		manifest.GitKey("tagged", "v1.2.3", true),
	} {
		if !got[want] {
			t.Errorf("no artifact path for %q; got %v", want, got)
		}
	}
}

// writeBytes writes data at path, creating its parent directories.
func writeBytes(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// builtAptKinds is one built efs-utils 2.0 per entry kind CheckAptStage
// distinguishes. Each returns the entry and the .deb locateDebFile finds.
var builtAptKinds = []struct {
	kind  string
	build func(t *testing.T, d dirs, debBytes []byte) (manifest.VersionEntry, string)
}{
	{"git source build", func(t *testing.T, d dirs, b []byte) (manifest.VersionEntry, string) {
		ve := manifest.VersionEntry{Version: "2.0", URL: "https://example.com/example-corp/efs-utils", BuildCmd: "make deb", Ref: "v2.0.0"}
		cloneDir := aptSourceDir(d, "efs-utils", ve)
		mkDir(t, filepath.Join(cloneDir, ".git"))
		if err := os.WriteFile(aptRefMarkerPath(cloneDir), []byte(ve.Ref), 0o644); err != nil {
			t.Fatal(err)
		}
		deb := filepath.Join(cloneDir, "efs-utils_2.0_all.deb")
		writeBytes(t, deb, b)
		return ve, deb
	}},
	{"direct URL", func(t *testing.T, d dirs, b []byte) (manifest.VersionEntry, string) {
		ve := manifest.VersionEntry{Version: "2.0", URL: "https://example.com/efs-utils_2.0_all.deb"}
		deb := filepath.Join(d.sources, "efs-utils", "efs-utils_2.0_all.deb")
		writeBytes(t, deb, b)
		return ve, deb
	}},
	{"apt-get source build", func(t *testing.T, d dirs, b []byte) (manifest.VersionEntry, string) {
		ve := manifest.VersionEntry{Version: "2.0", BuildCmd: "dpkg-buildpackage -b -uc -us"}
		mkDir(t, aptSourceDir(d, "efs-utils", ve))
		deb := filepath.Join(d.sources, "efs-utils_2.0_all.deb")
		writeBytes(t, deb, b)
		return ve, deb
	}},
	{"apt-get download", func(t *testing.T, d dirs, b []byte) (manifest.VersionEntry, string) {
		ve := manifest.VersionEntry{Version: "2.0"}
		deb := filepath.Join(d.sources, "efs-utils", "efs-utils_2.0_all.deb")
		writeBytes(t, deb, b)
		return ve, deb
	}},
}

func TestCheckAptStage_PackagedMatchesPoolCopy(t *testing.T) {
	for _, k := range builtAptKinds {
		t.Run(k.kind, func(t *testing.T) {
			root := t.TempDir()
			cfg := &Config{BuildRoot: root}
			d := buildDirs(root)
			ve, deb := k.build(t, d, []byte("efs-utils 2.0 bytes"))
			if got, err := locateDebFile(d, "efs-utils", ve); err != nil || got != deb {
				t.Fatalf("fixture: locateDebFile = %q, %v; want %q", got, err, deb)
			}

			if s := CheckAptStage(cfg, "efs-utils", ve); !s.Built || s.Packaged {
				t.Fatalf("before the copy: %+v, want Built and not Packaged", s)
			}
			writeBytes(t, filepath.Join(d.aptRepo, filepath.FromSlash(aptPoolRelPath("efs-utils", filepath.Base(deb)))), []byte("efs-utils 2.0 bytes"))
			if s := CheckAptStage(cfg, "efs-utils", ve); !s.Packaged {
				t.Errorf("the pool holds this version's bytes at its pool path: %+v, want Packaged", s)
			}
		})
	}
}

func TestCheckAptStage_PackagedIgnoresOtherPoolFiles(t *testing.T) {
	built := []byte("efs-utils 2.0 bytes")
	pool := func(d dirs, rel string) string { return filepath.Join(d.aptRepo, filepath.FromSlash(rel)) }
	for _, k := range builtAptKinds {
		for _, c := range []struct {
			name  string
			place func(t *testing.T, d dirs)
		}{
			{"flat copy", func(t *testing.T, d dirs) {
				writeBytes(t, pool(d, "pool/main/e/efs-utils_2.0_all.deb"), built)
			}},
			{"prefix package flat", func(t *testing.T, d dirs) {
				writeBytes(t, pool(d, "pool/main/e/efs-utils-extra_1.0_all.deb"), built)
			}},
			{"prefix package nested", func(t *testing.T, d dirs) {
				writeBytes(t, pool(d, aptPoolRelPath("efs-utils-extra", "efs-utils-extra_1.0_all.deb")), built)
				writeBytes(t, pool(d, "pool/main/e/efs-utils/efs-utils-extra_1.0_all.deb"), built)
			}},
			{"same path, other bytes", func(t *testing.T, d dirs) {
				writeBytes(t, pool(d, aptPoolRelPath("efs-utils", "efs-utils_2.0_all.deb")), []byte("efs-utils 2.0 built at another ref"))
			}},
			{"another version only", func(t *testing.T, d dirs) {
				writeBytes(t, pool(d, aptPoolRelPath("efs-utils", "efs-utils_1.9_all.deb")), built)
			}},
		} {
			t.Run(k.kind+"/"+c.name, func(t *testing.T) {
				root := t.TempDir()
				cfg := &Config{BuildRoot: root}
				d := buildDirs(root)
				ve, _ := k.build(t, d, built)
				c.place(t, d)
				if s := CheckAptStage(cfg, "efs-utils", ve); !s.Built || s.Packaged {
					t.Errorf("%+v, want Built and not Packaged", s)
				}
			})
		}
	}
}

func TestCheckAptStage_PackagedRequiresBuilt(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	ve := manifest.VersionEntry{URL: "https://example.com/example-corp/widget-utils", BuildCmd: "make deb", Ref: "v2.0.1"}
	d := buildDirs(root)

	cloneDir := aptSourceDir(d, "efs-utils", ve)
	mkDir(t, filepath.Join(cloneDir, ".git"))
	if err := os.WriteFile(aptRefMarkerPath(cloneDir), []byte("v2.0.0"), 0o644); err != nil {
		t.Fatal(err)
	}
	touchFile(t, filepath.Join(cloneDir, "efs-utils_2.0.deb"))
	touchFile(t, filepath.Join(d.aptRepo, filepath.FromSlash(aptPoolRelPath("efs-utils", "efs-utils_2.0.deb"))))

	if s := CheckAptStage(cfg, "efs-utils", ve); s.Built || s.Packaged {
		t.Errorf("a clone recorded at v2.0.0 with its .deb in the pool counted for ref v2.0.1: %+v", s)
	}
	ve.Ref = "v2.0.0"
	if s := CheckAptStage(cfg, "efs-utils", ve); !s.Built || !s.Packaged {
		t.Errorf("the same tree at the entry's ref did not read as packaged: %+v", s)
	}
}

// aptSourceEntry is efs-utils as an apt-get source build: build_cmd, no url.
func aptSourceEntry(version string) manifest.VersionEntry {
	return manifest.VersionEntry{Version: version, BuildCmd: "dpkg-buildpackage -us -uc"}
}

func TestLocateDebFileAptSourceSelectsItsOwnDeb(t *testing.T) {
	d := buildDirs(t.TempDir())
	for _, f := range []string{"aaa_1.0_all.deb", "efs-utils-extra_2.0_all.deb", "efs-utils_1.0_all.deb", "efs-utils_2.0_all.deb"} {
		touchFile(t, filepath.Join(d.sources, f))
	}
	mkDir(t, filepath.Join(d.sources, "efs-utils-2.0"))
	want := filepath.Join(d.sources, "efs-utils_2.0_all.deb")

	for _, version := range []string{"2.0", "1:2.0"} {
		got, err := locateDebFile(d, "efs-utils", aptSourceEntry(version))
		if err != nil || got != want {
			t.Errorf("version %s: locateDebFile = %q, %v; want %q", version, got, err, want)
		}
	}
}

func TestLocateDebFileAptSourceNoMatchNamesCandidates(t *testing.T) {
	d := buildDirs(t.TempDir())
	touchFile(t, filepath.Join(d.sources, "aaa_1.0_all.deb"))
	mkDir(t, filepath.Join(d.sources, "efs-utils-2.0"))

	got, err := locateDebFile(d, "efs-utils", aptSourceEntry("2.0"))
	if err == nil {
		t.Fatalf("locateDebFile = %q, want an error: no .deb is efs-utils 2.0", got)
	}
	for _, want := range []string{"efs-utils", "2.0", "aaa_1.0_all.deb", "deb_glob", d.sources} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}

func TestLocateDebFileAptSourceRefusesAmbiguous(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files []string
		glob  string
	}{
		{"default selection", []string{"efs-utils_2.0_amd64.deb", "efs-utils_2.0_arm64.deb"}, ""},
		{"deb_glob", []string{"aaa_1.0_all.deb", "efs-utils_2.0_all.deb"}, "../*.deb"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := buildDirs(t.TempDir())
			for _, f := range tc.files {
				touchFile(t, filepath.Join(d.sources, f))
			}
			ve := aptSourceEntry("2.0")
			ve.DebGlob = tc.glob
			mkDir(t, aptSourceDir(d, "efs-utils", ve))

			got, err := locateDebFile(d, "efs-utils", ve)
			if err == nil {
				t.Fatalf("locateDebFile = %q, want an error naming %v", got, tc.files)
			}
			for _, want := range append(tc.files, "deb_glob") {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not name %q", err, want)
				}
			}
		})
	}
}

func TestCheckAptStageAptSourceNotBuiltByAnotherEntry(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	d := buildDirs(cfg.rootFor(manifest.TypeApt))
	ve := aptSourceEntry("2.0")
	touchFile(t, filepath.Join(d.sources, "aaa_1.0_all.deb"))
	mkDir(t, aptSourceDir(d, "efs-utils", ve))

	if s := CheckAptStage(cfg, "efs-utils", ve); !s.Fetched || s.Built {
		t.Errorf("with only aaa's .deb: %+v, want Fetched and not Built", s)
	}
	touchFile(t, filepath.Join(d.sources, "efs-utils_2.0_all.deb"))
	if s := CheckAptStage(cfg, "efs-utils", ve); !s.Built {
		t.Errorf("with efs-utils_2.0_all.deb present: %+v, want Built", s)
	}
}

func TestBuildAptAptSourceFindsTheParentDeb(t *testing.T) {
	for _, tc := range []struct {
		buildCmd string
		failures int
	}{
		{"touch ../efs-utils_2.0_all.deb", 0},
		{"true", 1},
	} {
		t.Run(tc.buildCmd, func(t *testing.T) {
			ve := manifest.VersionEntry{Version: "2.0", BuildCmd: tc.buildCmd}
			cfg, store, _ := pinEnv(t, &manifest.PackageManifest{Type: manifest.TypeApt, Name: "efs-utils", Versions: []manifest.VersionEntry{ve}})
			var log strings.Builder
			cfg.Stdout = &log
			d := buildDirs(cfg.rootFor(manifest.TypeApt))
			mkDir(t, aptSourceDir(d, "efs-utils", ve))
			touchFile(t, filepath.Join(d.sources, "aaa_1.0_all.deb"))

			sum := BuildApt(cfg, store, "efs-utils")
			if sum.Failures != tc.failures || len(sum.Results) != 1 {
				t.Fatalf("failures = %d over %d results, want %d over 1\n%s", sum.Failures, len(sum.Results), tc.failures, log.String())
			}
			res := sum.Results[0]
			if tc.failures == 0 {
				want := filepath.Join(d.sources, "efs-utils_2.0_all.deb")
				if len(res.Artifacts) != 1 || res.Artifacts[0] != want {
					t.Errorf("artifacts = %v, want [%s]", res.Artifacts, want)
				}
				return
			}
			if res.Err == nil || !strings.Contains(res.Err.Error(), "aaa_1.0_all.deb") {
				t.Errorf("failure %v does not name aaa_1.0_all.deb", res.Err)
			}
		})
	}
}

func TestPackageAptAptSourceEntriesKeepTheirOwnDeb(t *testing.T) {
	aaa := &manifest.PackageManifest{Type: manifest.TypeApt, Name: "aaa", Versions: []manifest.VersionEntry{aptSourceEntry("1.0")}}
	efs := &manifest.PackageManifest{Type: manifest.TypeApt, Name: "efs-utils", Versions: []manifest.VersionEntry{aptSourceEntry("2.0")}}
	cfg, store, _ := pinEnv(t, aaa)
	if err := store.SavePackage(t.Context(), efs); err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	cfg.Stdout = &log
	d := buildDirs(cfg.rootFor(manifest.TypeApt))
	mkDir(t, aptSourceDir(d, "aaa", aaa.Versions[0]))
	mkDir(t, aptSourceDir(d, "efs-utils", efs.Versions[0]))
	writeTestDeb(t, filepath.Join(d.sources, "aaa_1.0_all.deb"), "aaa", "1.0", "aaa")
	efsDeb := filepath.Join(d.sources, "efs-utils_2.0_all.deb")
	writeTestDeb(t, efsDeb, "efs-utils", "2.0", "efs-utils")

	if sum := PackageApt(cfg, store, ""); sum.Failures != 0 {
		t.Fatalf("PackageApt failed: %+v\n%s", sum.Results, log.String())
	}

	poolDir := filepath.Join(d.aptRepo, "pool", "main", "e", "efs-utils")
	entries, err := os.ReadDir(poolDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) != 1 || names[0] != "efs-utils_2.0_all.deb" {
		t.Fatalf("%s holds %v, want only efs-utils_2.0_all.deb", poolDir, names)
	}
	poolSum, err := fileSHA256(filepath.Join(poolDir, names[0]))
	if err != nil {
		t.Fatal(err)
	}
	if built, _ := fileSHA256(efsDeb); built != poolSum {
		t.Errorf("pool copy %s, built .deb %s: different bytes", poolSum, built)
	}
	stored, err := store.GetPackage(t.Context(), manifest.TypeApt, "efs-utils")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := stored.Versions[0].Metadata["_pool_path"], aptPoolRelPath("efs-utils", "efs-utils_2.0_all.deb"); got != want {
		t.Errorf("_pool_path = %q, want %q", got, want)
	}
}

func TestFetchAptSourcePicksItsOwnDsc(t *testing.T) {
	shims := t.TempDir()
	argvLog := filepath.Join(shims, "dpkg-source.log")
	for name, body := range map[string]string{
		"apt-get":     "#!/bin/sh\nexit 0\n",
		"dpkg-source": "#!/bin/sh\necho \"$@\" >> " + argvLog + "\n[ -f \"$2\" ] || exit 1\nmkdir -p \"$3\"\n",
	} {
		if err := os.WriteFile(filepath.Join(shims, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", shims+string(os.PathListSeparator)+os.Getenv("PATH"))

	for _, tc := range []struct {
		name    string
		dscs    []string
		wantArg string
	}{
		{"own dsc beside a prefix sibling", []string{"efs-utils-extra_1.0.dsc", "efs-utils_2.0.dsc"}, "efs-utils_2.0.dsc"},
		{"only a prefix sibling", []string{"efs-utils-extra_1.0.dsc"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_ = os.Remove(argvLog)
			ve := aptSourceEntry("2.0")
			cfg, store, _ := pinEnv(t, &manifest.PackageManifest{Type: manifest.TypeApt, Name: "efs-utils", Versions: []manifest.VersionEntry{ve}})
			var log strings.Builder
			cfg.Stdout = &log
			d := buildDirs(cfg.rootFor(manifest.TypeApt))
			for _, f := range tc.dscs {
				touchFile(t, filepath.Join(d.sources, f))
			}

			sum := FetchApt(cfg, store, "efs-utils")
			calls, _ := os.ReadFile(argvLog)
			lines := strings.Split(strings.TrimSpace(string(calls)), "\n")
			if tc.wantArg != "" {
				if sum.Failures != 0 {
					t.Fatalf("fetch failed: %+v\n%s", sum.Results, log.String())
				}
				if len(lines) != 1 || filepath.Base(strings.Fields(lines[0])[1]) != tc.wantArg {
					t.Errorf("dpkg-source calls %q, want one with %s", calls, tc.wantArg)
				}
				return
			}
			if sum.Failures != 1 || len(sum.Results) != 1 || sum.Results[0].Err == nil {
				t.Fatalf("fetch did not fail: %+v\n%s", sum.Results, log.String())
			}
			if err := sum.Results[0].Err.Error(); !strings.Contains(err, "efs-utils-extra_1.0.dsc") {
				t.Errorf("error %q does not name efs-utils-extra_1.0.dsc", err)
			}
			if len(calls) != 0 {
				t.Errorf("dpkg-source ran: %q", calls)
			}
		})
	}
}
