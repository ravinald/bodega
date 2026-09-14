package builder

import (
	"context"
	"io"
	"os"
	"path/filepath"
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
