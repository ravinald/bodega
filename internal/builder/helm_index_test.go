package builder

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/ravinald/bodega/internal/manifest"
)

// A chart with two built versions must render one mapping key with both
// releases beneath it. A key repeated per release is not last-wins: every YAML
// parser in the path, helm's included, refuses the whole document.
func TestPackageHelmWritesOneKeyPerChart(t *testing.T) {
	root := t.TempDir()
	manifestDir := t.TempDir()
	cfg := &Config{BuildRoot: root, ManifestDir: manifestDir, Stdout: io.Discard}
	store := manifest.NewLocalStore(manifestDir)
	ctx := context.Background()

	versions := []string{"1.14.0", "1.15.0"}
	d := buildDirs(root)
	for _, v := range versions {
		ve := manifest.VersionEntry{Version: v}
		if err := store.AddVersion(ctx, manifest.TypeHelm, "cert-manager", ve); err != nil {
			t.Fatalf("add version %s: %v", v, err)
		}
		touchFile(t, helmLocalPath(d, "cert-manager", ve))
	}

	if s := PackageHelm(cfg, store); s.Failures != 0 {
		t.Fatalf("PackageHelm reported %d failure(s)", s.Failures)
	}

	raw, err := os.ReadFile(filepath.Join(d.charts, "index.yaml"))
	if err != nil {
		t.Fatalf("read index.yaml: %v", err)
	}

	var doc struct {
		APIVersion string                   `yaml:"apiVersion"`
		Entries    map[string][]interface{} `yaml:"entries"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("index.yaml does not parse, which is how helm refuses the whole repository: %v\n%s", err, raw)
	}
	if len(doc.Entries) != 1 {
		t.Fatalf("want 1 chart key, got %d: %v", len(doc.Entries), doc.Entries)
	}
	if got := len(doc.Entries["cert-manager"]); got != len(versions) {
		t.Fatalf("want %d releases under cert-manager, got %d", len(versions), got)
	}
}

// readOnlyDir makes dir unwritable for the rest of the test and restores it
// before TempDir's cleanup has to delete what is inside. root ignores the mode,
// so the test cannot observe a refusal there.
func readOnlyDir(t *testing.T, dir string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root writes through a read-only directory")
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
}

// An index.yaml that cannot be created is a failed package stage. Logged and
// dropped, it left `build upload helm` exiting 0 over a repository with no
// index, and every client 404ing on /helm/index.yaml.
func TestPackageHelmFailsWhenTheIndexCannotBeCreated(t *testing.T) {
	root := t.TempDir()
	manifestDir := t.TempDir()
	cfg := &Config{BuildRoot: root, ManifestDir: manifestDir, Stdout: io.Discard}
	store := manifest.NewLocalStore(manifestDir)
	d := buildDirs(root)
	if err := os.MkdirAll(d.charts, 0o755); err != nil {
		t.Fatal(err)
	}
	readOnlyDir(t, d.charts)

	s := PackageHelm(cfg, store)
	if !s.HasFailures() {
		t.Fatalf("PackageHelm over a read-only charts directory reported no failure: %+v", s)
	}
	if err := s.FirstError(); err == nil || !strings.Contains(err.Error(), "index.yaml") || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("FirstError = %v, want the index.yaml permission error", err)
	}
}

// A charts directory the fetch cannot create fails the stage once, rather than
// returning an empty summary that reads as nothing to do.
func TestFetchHelmFailsWhenTheChartsDirectoryCannotBeCreated(t *testing.T) {
	root := t.TempDir()
	manifestDir := t.TempDir()
	cfg := &Config{BuildRoot: root, ManifestDir: manifestDir, Stdout: io.Discard}
	store := manifest.NewLocalStore(manifestDir)
	if err := store.AddVersion(context.Background(), manifest.TypeHelm, "podinfo", manifest.VersionEntry{Version: "6.0.0"}); err != nil {
		t.Fatal(err)
	}
	readOnlyDir(t, root)

	s := FetchHelm(cfg, store, "")
	if s.Failures != 1 {
		t.Fatalf("FetchHelm reported %d failure(s), want 1: %+v", s.Failures, s)
	}
	if err := s.FirstError(); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("FirstError = %v, want the mkdir permission error", err)
	}
}

// A run with nothing selected has nothing to fail.
func TestPackageHelmWithNoChartsSucceeds(t *testing.T) {
	root := t.TempDir()
	manifestDir := t.TempDir()
	cfg := &Config{BuildRoot: root, ManifestDir: manifestDir, Stdout: io.Discard}
	if err := os.MkdirAll(buildDirs(root).charts, 0o755); err != nil {
		t.Fatal(err)
	}
	if s := PackageHelm(cfg, manifest.NewLocalStore(manifestDir)); s.HasFailures() || s.FirstError() != nil {
		t.Fatalf("PackageHelm with no charts failed: %v", s.FirstError())
	}
}
