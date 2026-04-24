package builder

import (
	"os"
	"path/filepath"
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
	ve := manifest.VersionEntry{URL: "https://example.com/awscli.zip"}
	s := CheckBinaryStage(cfg, "awscli", ve)
	if s.Fetched || s.Built || s.Packaged {
		t.Errorf("expected all false when file absent, got %+v", s)
	}
}

func TestCheckBinaryStage_Fetched(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	ve := manifest.VersionEntry{URL: "https://example.com/awscli.zip"}
	d := buildDirs(root)
	touchFile(t, filepath.Join(d.binaries, "awscli", "awscli.zip"))

	s := CheckBinaryStage(cfg, "awscli", ve)
	if !s.Fetched || !s.Built || !s.Packaged {
		t.Errorf("expected all true when file present, got %+v", s)
	}
}

func TestCheckBinaryStage_Versioned(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	ve := manifest.VersionEntry{Version: "2.13.0", URL: "https://example.com/awscli.zip"}
	d := buildDirs(root)

	// File NOT at versioned path → not fetched.
	touchFile(t, filepath.Join(d.binaries, "awscli", "awscli.zip"))
	s := CheckBinaryStage(cfg, "awscli", ve)
	if s.Fetched {
		t.Error("expected Fetched=false when file at unversioned path but version is set")
	}

	// File at versioned path → fetched.
	touchFile(t, filepath.Join(d.binaries, "awscli", "2.13.0", "awscli.zip"))
	s = CheckBinaryStage(cfg, "awscli", ve)
	if !s.Fetched {
		t.Error("expected Fetched=true when file at versioned path")
	}
}

func TestBinaryDestPath_NoVersion(t *testing.T) {
	root := t.TempDir()
	d := buildDirs(root)
	ve := manifest.VersionEntry{URL: "https://example.com/tool.tar.gz"}
	got := binaryDestPath(d, "tool", ve)
	want := filepath.Join(d.binaries, "tool", "tool.tar.gz")
	if got != want {
		t.Errorf("binaryDestPath (no version) = %q, want %q", got, want)
	}
}

func TestBinaryDestPath_WithVersion(t *testing.T) {
	root := t.TempDir()
	d := buildDirs(root)
	ve := manifest.VersionEntry{Version: "v1.2", URL: "https://example.com/tool.tar.gz"}
	got := binaryDestPath(d, "tool", ve)
	want := filepath.Join(d.binaries, "tool", "v1.2", "tool.tar.gz")
	if got != want {
		t.Errorf("binaryDestPath (versioned) = %q, want %q", got, want)
	}
}

func TestBinaryDestPath_FilenameOverride(t *testing.T) {
	root := t.TempDir()
	d := buildDirs(root)
	ve := manifest.VersionEntry{Filename: "custom-name.bin", URL: "https://example.com/original.bin"}
	got := binaryDestPath(d, "tool", ve)
	want := filepath.Join(d.binaries, "tool", "custom-name.bin")
	if got != want {
		t.Errorf("binaryDestPath (filename override) = %q, want %q", got, want)
	}
}

func TestBinaryS3Key_NoVersion(t *testing.T) {
	ve := manifest.VersionEntry{URL: "https://example.com/tool.tar.gz"}
	got := binaryS3Key("tool", ve)
	want := "binaries/tool/tool.tar.gz"
	if got != want {
		t.Errorf("binaryS3Key (no version) = %q, want %q", got, want)
	}
}

func TestBinaryS3Key_WithVersion(t *testing.T) {
	ve := manifest.VersionEntry{Version: "v1.2", URL: "https://example.com/tool.tar.gz"}
	got := binaryS3Key("tool", ve)
	want := "binaries/tool/v1.2/tool.tar.gz"
	if got != want {
		t.Errorf("binaryS3Key (versioned) = %q, want %q", got, want)
	}
}

func TestCheckGitStage_Empty(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	ve := manifest.VersionEntry{URL: "https://github.com/netbox/netbox", Ref: "v4.0.0", Source: "clone"}
	s := CheckGitStage(cfg, "netbox", ve)
	if s.Fetched || s.Packaged {
		t.Errorf("expected all false when nothing on disk, got %+v", s)
	}
}

func TestCheckGitStage_Fetched(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	ve := manifest.VersionEntry{URL: "https://github.com/netbox/netbox", Ref: "v4.0.0", Source: "clone"}
	d := buildDirs(root)

	mkDir(t, gitBareDir(d, "netbox", ve))
	s := CheckGitStage(cfg, "netbox", ve)
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
	ve := manifest.VersionEntry{URL: "https://github.com/netbox/netbox", Ref: "v4.0.0", Source: "clone"}
	d := buildDirs(root)

	mkDir(t, gitBareDir(d, "netbox", ve))
	bundlePath := filepath.Join(d.bundles, "netbox", "netbox-"+ve.Ref+".bundle")
	touchFile(t, bundlePath)

	s := CheckGitStage(cfg, "netbox", ve)
	if !s.Fetched {
		t.Error("expected Fetched=true")
	}
	if !s.Packaged {
		t.Error("expected Packaged=true when bundle file exists")
	}
}

func TestGitBareDir(t *testing.T) {
	root := t.TempDir()
	d := buildDirs(root)
	ve := manifest.VersionEntry{Ref: "v4.0.0", Source: "clone"}
	got := gitBareDir(d, "netbox", ve)
	want := filepath.Join(d.repos, "netbox", "netbox-v4.0.0.git") // single-segment name: no "--" replacement needed
	if got != want {
		t.Errorf("gitBareDir = %q, want %q", got, want)
	}
}

func TestAptSourceDir_NoVersion(t *testing.T) {
	root := t.TempDir()
	d := buildDirs(root)
	ve := manifest.VersionEntry{URL: "https://github.com/aws/efs-utils"}
	got := aptSourceDir(d, "efs-utils", ve)
	want := filepath.Join(d.sources, "efs-utils")
	if got != want {
		t.Errorf("aptSourceDir (no version) = %q, want %q", got, want)
	}
}

func TestAptSourceDir_WithVersion(t *testing.T) {
	root := t.TempDir()
	d := buildDirs(root)
	ve := manifest.VersionEntry{Version: "2.0.1", URL: "https://github.com/aws/efs-utils"}
	got := aptSourceDir(d, "efs-utils", ve)
	want := filepath.Join(d.sources, "efs-utils-2.0.1")
	if got != want {
		t.Errorf("aptSourceDir (versioned) = %q, want %q", got, want)
	}
}

func TestAptSourceDir_SourceNameOverride(t *testing.T) {
	root := t.TempDir()
	d := buildDirs(root)
	ve := manifest.VersionEntry{SourceName: "amazon-efs-utils", Version: "2.0.1", URL: "https://github.com/aws/efs-utils"}
	got := aptSourceDir(d, "efs-utils", ve)
	want := filepath.Join(d.sources, "amazon-efs-utils-2.0.1")
	if got != want {
		t.Errorf("aptSourceDir (source_name + version) = %q, want %q", got, want)
	}
}

func TestCheckAptStage_Empty(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	ve := manifest.VersionEntry{URL: "https://github.com/aws/efs-utils", BuildCmd: "make deb"}
	s := CheckAptStage(cfg, "efs-utils", ve)
	if s.Fetched || s.Built || s.Packaged {
		t.Errorf("expected all false when nothing on disk, got %+v", s)
	}
}

func TestCheckAptStage_SourceBuildFetched(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	ve := manifest.VersionEntry{URL: "https://github.com/aws/efs-utils", BuildCmd: "make deb"}
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
	ve := manifest.VersionEntry{URL: "https://github.com/aws/efs-utils", BuildCmd: "make deb"}
	d := buildDirs(root)

	cloneDir := aptSourceDir(d, "efs-utils", ve)
	mkDir(t, cloneDir)
	touchFile(t, filepath.Join(cloneDir, "efs-utils_2.0.deb"))

	s := CheckAptStage(cfg, "efs-utils", ve)
	if !s.Fetched || !s.Built {
		t.Errorf("expected Fetched+Built=true when .deb present, got %+v", s)
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

func TestPypiS3Prefix(t *testing.T) {
	got := pypiS3Prefix()
	want := "pypi/wheels/"
	if got != want {
		t.Errorf("pypiS3Prefix = %q, want %q", got, want)
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
	s := CheckPypiStage(cfg, store)
	if !s.Fetched {
		t.Error("expected Fetched=true when combined-requirements.txt exists")
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
	wheelsDir := pypiWheelsDir(d)
	touchFile(t, filepath.Join(wheelsDir, "somepackage-1.0-py3-none-any.whl"))
	touchFile(t, filepath.Join(wheelsDir, "MANIFEST.sha256"))

	s := CheckPypiStage(cfg, store)
	if !s.Fetched || !s.Built || !s.Packaged {
		t.Errorf("expected all true when MANIFEST.sha256 present, got %+v", s)
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
		keyMap[p.S3Key] = p.Local
	}
	if _, ok := keyMap["binaries/tool-a/tool-a.zip"]; !ok {
		t.Error("missing S3 key binaries/tool-a/tool-a.zip")
	}
	if _, ok := keyMap["binaries/tool-b/v2.0/tool-b.tar.gz"]; !ok {
		t.Error("missing S3 key binaries/tool-b/v2.0/tool-b.tar.gz")
	}
}
