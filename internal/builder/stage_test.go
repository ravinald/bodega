package builder

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scaleapi/bodega/internal/manifest"
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

// ---------------------------------------------------------------------------
// Binary stage check
// ---------------------------------------------------------------------------

func TestCheckBinaryStage_NotFetched(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	entry := manifest.BinaryEntry{Name: "awscli", URL: "https://example.com/awscli.zip"}
	s := CheckBinaryStage(cfg, entry)
	if s.Fetched || s.Built || s.Packaged {
		t.Errorf("expected all false when file absent, got %+v", s)
	}
}

func TestCheckBinaryStage_Fetched(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	entry := manifest.BinaryEntry{Name: "awscli", URL: "https://example.com/awscli.zip"}
	d := buildDirs(root)
	touchFile(t, filepath.Join(d.binaries, "awscli", "awscli.zip"))

	s := CheckBinaryStage(cfg, entry)
	if !s.Fetched || !s.Built || !s.Packaged {
		t.Errorf("expected all true when file present, got %+v", s)
	}
}

func TestCheckBinaryStage_Versioned(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	entry := manifest.BinaryEntry{Name: "awscli", Version: "2.13.0", URL: "https://example.com/awscli.zip"}
	d := buildDirs(root)

	// File NOT at versioned path → not fetched.
	touchFile(t, filepath.Join(d.binaries, "awscli", "awscli.zip"))
	s := CheckBinaryStage(cfg, entry)
	if s.Fetched {
		t.Error("expected Fetched=false when file at unversioned path but version is set")
	}

	// File at versioned path → fetched.
	touchFile(t, filepath.Join(d.binaries, "awscli", "2.13.0", "awscli.zip"))
	s = CheckBinaryStage(cfg, entry)
	if !s.Fetched {
		t.Error("expected Fetched=true when file at versioned path")
	}
}

// ---------------------------------------------------------------------------
// Binary path helpers
// ---------------------------------------------------------------------------

func TestBinaryDestPath_NoVersion(t *testing.T) {
	root := t.TempDir()
	d := buildDirs(root)
	entry := manifest.BinaryEntry{Name: "tool", URL: "https://example.com/tool.tar.gz"}
	got := binaryDestPath(d, entry)
	want := filepath.Join(d.binaries, "tool", "tool.tar.gz")
	if got != want {
		t.Errorf("binaryDestPath (no version) = %q, want %q", got, want)
	}
}

func TestBinaryDestPath_WithVersion(t *testing.T) {
	root := t.TempDir()
	d := buildDirs(root)
	entry := manifest.BinaryEntry{Name: "tool", Version: "v1.2", URL: "https://example.com/tool.tar.gz"}
	got := binaryDestPath(d, entry)
	want := filepath.Join(d.binaries, "tool", "v1.2", "tool.tar.gz")
	if got != want {
		t.Errorf("binaryDestPath (versioned) = %q, want %q", got, want)
	}
}

func TestBinaryDestPath_FilenameOverride(t *testing.T) {
	root := t.TempDir()
	d := buildDirs(root)
	entry := manifest.BinaryEntry{Name: "tool", Filename: "custom-name.bin", URL: "https://example.com/original.bin"}
	got := binaryDestPath(d, entry)
	want := filepath.Join(d.binaries, "tool", "custom-name.bin")
	if got != want {
		t.Errorf("binaryDestPath (filename override) = %q, want %q", got, want)
	}
}

func TestBinaryS3Key_NoVersion(t *testing.T) {
	entry := manifest.BinaryEntry{Name: "tool", URL: "https://example.com/tool.tar.gz"}
	got := binaryS3Key(entry)
	want := "binaries/tool/tool.tar.gz"
	if got != want {
		t.Errorf("binaryS3Key (no version) = %q, want %q", got, want)
	}
}

func TestBinaryS3Key_WithVersion(t *testing.T) {
	entry := manifest.BinaryEntry{Name: "tool", Version: "v1.2", URL: "https://example.com/tool.tar.gz"}
	got := binaryS3Key(entry)
	want := "binaries/tool/v1.2/tool.tar.gz"
	if got != want {
		t.Errorf("binaryS3Key (versioned) = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// Git stage check and path helpers
// ---------------------------------------------------------------------------

func TestCheckGitStage_Empty(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	entry := manifest.GitEntry{Name: "netbox", URL: "https://github.com/netbox/netbox", Ref: "v4.0.0", Source: "clone"}
	s := CheckGitStage(cfg, entry)
	if s.Fetched || s.Packaged {
		t.Errorf("expected all false when nothing on disk, got %+v", s)
	}
}

func TestCheckGitStage_Fetched(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	entry := manifest.GitEntry{Name: "netbox", URL: "https://github.com/netbox/netbox", Ref: "v4.0.0", Source: "clone"}
	d := buildDirs(root)

	mkDir(t, gitBareDir(d, entry))
	s := CheckGitStage(cfg, entry)
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
	entry := manifest.GitEntry{Name: "netbox", URL: "https://github.com/netbox/netbox", Ref: "v4.0.0", Source: "clone"}
	d := buildDirs(root)

	mkDir(t, gitBareDir(d, entry))
	bundlePath := filepath.Join(d.bundles, entry.Name, entry.Name+"-"+entry.Ref+".bundle")
	touchFile(t, bundlePath)

	s := CheckGitStage(cfg, entry)
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
	entry := manifest.GitEntry{Name: "netbox", Ref: "v4.0.0", Source: "clone"}
	got := gitBareDir(d, entry)
	want := filepath.Join(d.repos, "netbox", "netbox-v4.0.0.git") // single-segment name: no "--" replacement needed
	if got != want {
		t.Errorf("gitBareDir = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// APT stage check and path helpers
// ---------------------------------------------------------------------------

func TestAptSourceDir_NoVersion(t *testing.T) {
	root := t.TempDir()
	d := buildDirs(root)
	entry := manifest.AptEntry{Name: "efs-utils", URL: "https://github.com/aws/efs-utils"}
	got := aptSourceDir(d, entry)
	want := filepath.Join(d.sources, "efs-utils")
	if got != want {
		t.Errorf("aptSourceDir (no version) = %q, want %q", got, want)
	}
}

func TestAptSourceDir_WithVersion(t *testing.T) {
	root := t.TempDir()
	d := buildDirs(root)
	entry := manifest.AptEntry{Name: "efs-utils", Version: "2.0.1", URL: "https://github.com/aws/efs-utils"}
	got := aptSourceDir(d, entry)
	want := filepath.Join(d.sources, "efs-utils-2.0.1")
	if got != want {
		t.Errorf("aptSourceDir (versioned) = %q, want %q", got, want)
	}
}

func TestAptSourceDir_SourceNameOverride(t *testing.T) {
	root := t.TempDir()
	d := buildDirs(root)
	entry := manifest.AptEntry{Name: "efs-utils", SourceName: "amazon-efs-utils", Version: "2.0.1", URL: "https://github.com/aws/efs-utils"}
	got := aptSourceDir(d, entry)
	want := filepath.Join(d.sources, "amazon-efs-utils-2.0.1")
	if got != want {
		t.Errorf("aptSourceDir (source_name + version) = %q, want %q", got, want)
	}
}

func TestCheckAptStage_Empty(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	entry := manifest.AptEntry{Name: "efs-utils", URL: "https://github.com/aws/efs-utils"}
	s := CheckAptStage(cfg, entry)
	if s.Fetched || s.Built || s.Packaged {
		t.Errorf("expected all false when nothing on disk, got %+v", s)
	}
}

func TestCheckAptStage_SourceBuildFetched(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	entry := manifest.AptEntry{Name: "efs-utils", URL: "https://github.com/aws/efs-utils"}
	d := buildDirs(root)

	mkDir(t, aptSourceDir(d, entry))
	s := CheckAptStage(cfg, entry)
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
	entry := manifest.AptEntry{Name: "efs-utils", URL: "https://github.com/aws/efs-utils"}
	d := buildDirs(root)

	cloneDir := aptSourceDir(d, entry)
	mkDir(t, cloneDir)
	touchFile(t, filepath.Join(cloneDir, "efs-utils_2.0.deb"))

	s := CheckAptStage(cfg, entry)
	if !s.Fetched || !s.Built {
		t.Errorf("expected Fetched+Built=true when .deb present, got %+v", s)
	}
}

func TestCheckAptStage_AptGetFetched(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	// No URL → apt-get download entry.
	entry := manifest.AptEntry{Name: "curl"}
	d := buildDirs(root)

	touchFile(t, filepath.Join(d.sources, "curl_7.0_amd64.deb"))
	s := CheckAptStage(cfg, entry)
	if !s.Fetched || !s.Built {
		t.Errorf("expected Fetched+Built=true for apt-get entry with .deb present, got %+v", s)
	}
}

// ---------------------------------------------------------------------------
// PyPI stage check and path helpers
// ---------------------------------------------------------------------------

func TestPypiWheelsDir_NoVersion(t *testing.T) {
	root := t.TempDir()
	d := buildDirs(root)
	pypi := manifest.PypiManifest{}
	got := pypiWheelsDir(d, pypi)
	if got != d.wheels {
		t.Errorf("pypiWheelsDir (no version) = %q, want %q", got, d.wheels)
	}
}

func TestPypiWheelsDir_WithVersion(t *testing.T) {
	root := t.TempDir()
	d := buildDirs(root)
	pypi := manifest.PypiManifest{Version: "v4.5.5"}
	got := pypiWheelsDir(d, pypi)
	want := filepath.Join(d.wheels, "v4.5.5")
	if got != want {
		t.Errorf("pypiWheelsDir (versioned) = %q, want %q", got, want)
	}
}

func TestPypiS3Prefix_NoVersion(t *testing.T) {
	pypi := manifest.PypiManifest{}
	got := pypiS3Prefix(pypi)
	want := "pypi/wheels/"
	if got != want {
		t.Errorf("pypiS3Prefix (no version) = %q, want %q", got, want)
	}
}

func TestPypiS3Prefix_WithVersion(t *testing.T) {
	pypi := manifest.PypiManifest{Version: "v4.5.5"}
	got := pypiS3Prefix(pypi)
	want := "pypi/wheels/v4.5.5/"
	if got != want {
		t.Errorf("pypiS3Prefix (versioned) = %q, want %q", got, want)
	}
}

func TestCheckPypiStage_Empty(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	store := &manifest.Store{Pypi: manifest.PypiManifest{}}
	s := CheckPypiStage(cfg, store)
	if s.Fetched || s.Built || s.Packaged {
		t.Errorf("expected all false when nothing on disk, got %+v", s)
	}
}

func TestCheckPypiStage_Fetched(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	store := &manifest.Store{Pypi: manifest.PypiManifest{}}

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
	store := &manifest.Store{Pypi: manifest.PypiManifest{Version: "v4.5.5"}}
	d := buildDirs(root)

	touchFile(t, filepath.Join(root, "combined-requirements.txt"))
	wheelsDir := pypiWheelsDir(d, store.Pypi)
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
	store := &manifest.Store{Pypi: manifest.PypiManifest{Version: "v4.5.5"}}
	d := buildDirs(root)

	touchFile(t, filepath.Join(root, "combined-requirements.txt"))
	wheelsDir := pypiWheelsDir(d, store.Pypi)
	touchFile(t, filepath.Join(wheelsDir, "somepackage-1.0-py3-none-any.whl"))
	touchFile(t, filepath.Join(wheelsDir, "MANIFEST.sha256"))

	s := CheckPypiStage(cfg, store)
	if !s.Fetched || !s.Built || !s.Packaged {
		t.Errorf("expected all true when MANIFEST.sha256 present, got %+v", s)
	}
}

// ---------------------------------------------------------------------------
// MergeSummaries
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// BinaryArtifactPaths
// ---------------------------------------------------------------------------

func TestBinaryArtifactPaths(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	d := buildDirs(root)

	entries := []manifest.BinaryEntry{
		{Name: "tool-a", URL: "https://example.com/tool-a.zip"},
		{Name: "tool-b", Version: "v2.0", URL: "https://example.com/tool-b.tar.gz"},
		{Name: "tool-c", URL: "https://example.com/tool-c.bin"}, // not downloaded
	}
	store := &manifest.Store{Binary: entries}

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
