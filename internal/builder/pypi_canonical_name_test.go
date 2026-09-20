package builder

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// The six names B75 names, with the form PEP 503 canonicalizes each to. The
// builder held its own copy of this rule that collapsed one separator at a time
// and left "a__b" as "a--b", so a distribution the store spelled one way was a
// different package here.
var canonicalPypiCases = map[string]string{
	"Django":              "django",
	"zope.interface":      "zope-interface",
	"ruamel.yaml":         "ruamel-yaml",
	"django_cors_headers": "django-cors-headers",
	"a__b":                "a-b",
	"A.B_c":               "a-b-c",
}

// Every name the builder reads out of a filename reaches the same key the store
// composes a path from: a wheel, an sdist and a "===" pin are three spellings of
// one distribution.
func TestBuilderNamesADistributionTheSameWayTheStoreDoes(t *testing.T) {
	for in, want := range canonicalPypiCases {
		if got := manifest.CanonicalPypiName(in); got != want {
			t.Errorf("CanonicalPypiName(%q) = %q, want %q", in, got, want)
		}
		if got, _, ok := parseWheelName(in + "-1.0.0-py3-none-any.whl"); !ok || got != want {
			t.Errorf("parseWheelName(%q wheel) = %q (ok %v), want %q", in, got, ok, want)
		}
		if got, _, ok := parsePypiArtifactName(in + "-1.0.0.tar.gz"); !ok || got != want {
			t.Errorf("parsePypiArtifactName(%q sdist) = %q (ok %v), want %q", in, got, ok, want)
		}
	}
}

// A distribution cataloged under its canonical name is explicit in the graph
// whatever spelling its own METADATA carries. The builder's copy of the rule
// left the store key and the wheel key one hyphen apart, which displayed an
// explicitly cataloged package as a transitive dependency of something.
func TestWheelScanTagsACanonicallyStoredPackageExplicit(t *testing.T) {
	for in, canonical := range canonicalPypiCases {
		dir := t.TempDir()
		writeTestWheel(t, dir, in, "1.0.0")

		store := manifest.NewLocalStore(t.TempDir())
		if err := store.SavePackage(t.Context(), &manifest.PackageManifest{
			Name: in, Type: manifest.TypePypi,
			Versions: []manifest.VersionEntry{{Version: "1.0.0"}},
		}); err != nil {
			t.Fatalf("save pypi/%s: %v", in, err)
		}

		graph, err := ScanWheelMetadata(dir, store)
		if err != nil {
			t.Fatalf("scan wheels for %s: %v", in, err)
		}
		info, ok := graph.Packages[canonical]
		if !ok {
			t.Fatalf("graph for %q holds %v, want a %q entry", in, keysOf(graph.Packages), canonical)
		}
		if !info.Explicit {
			t.Errorf("%q is cataloged and its wheel reads as transitive", in)
		}
	}
}

func keysOf(m map[string]PypiPackageInfo) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// writeTestWheel writes a minimal wheel whose METADATA names dist verbatim,
// which is what pip's own build back-ends do: PEP 427 spells the filename with
// underscores and METADATA carries the published spelling.
func writeTestWheel(t *testing.T, dir, dist, version string) {
	t.Helper()
	path := filepath.Join(dir, dist+"-"+version+"-py3-none-any.whl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()

	zw := zip.NewWriter(f)
	w, err := zw.Create(dist + "-" + version + ".dist-info/METADATA")
	if err != nil {
		t.Fatalf("create METADATA in %s: %v", path, err)
	}
	if _, err := w.Write([]byte("Name: " + dist + "\nVersion: " + version + "\n")); err != nil {
		t.Fatalf("write METADATA in %s: %v", path, err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close %s: %v", path, err)
	}
}
