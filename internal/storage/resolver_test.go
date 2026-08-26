package storage

import (
	"go/build"
	"strings"
	"testing"
)

func TestSingleResolverDefaultAndByName(t *testing.T) {
	def := NewMemory()
	r := NewSingle(def)

	if r.Default() != ObjectStore(def) {
		t.Fatal("Default() did not return the wrapped store")
	}

	// The rule the whole design rests on: an empty recorded name means the
	// default backend, never "resolve through the config hierarchy". Every
	// artifact uploaded before named backends existed has an empty name.
	for _, name := range []string{"", DefaultName} {
		got, err := r.ByName(name)
		if err != nil {
			t.Fatalf("ByName(%q): %v", name, err)
		}
		if got != ObjectStore(def) {
			t.Fatalf("ByName(%q) did not return the default store", name)
		}
	}
}

func TestSingleResolverUnknownNameErrors(t *testing.T) {
	r := NewSingle(NewMemory())
	got, err := r.ByName("bulk")
	if err == nil {
		t.Fatal("ByName of an unconfigured name returned nil error; a silent fallback would serve bytes from the wrong backend")
	}
	if got != nil {
		t.Fatalf("ByName of an unconfigured name returned a store %v, want nil", got)
	}
	if !strings.Contains(err.Error(), "bulk") {
		t.Fatalf("error %q does not name the backend that was asked for", err)
	}
}

func TestSingleResolverPlacementIsAlwaysDefault(t *testing.T) {
	r := NewSingle(NewMemory())
	for _, typ := range []string{"apt", "pypi", ""} {
		if got := r.Placement(typ, ""); got.Name != DefaultName || got.Level != LevelDefault {
			t.Fatalf("Placement(%q) = %+v, want %q at LevelDefault", typ, got, DefaultName)
		}
	}
}

func TestSingleResolverFanoutAndAll(t *testing.T) {
	def := NewMemory()
	r := NewSingle(def)

	for _, tc := range []struct {
		name string
		got  []NamedStore
	}{
		{"Fanout", r.Fanout(t.Context(), "apt", nil)},
		{"All", r.All()},
	} {
		if len(tc.got) != 1 {
			t.Fatalf("%s returned %d backends, want 1", tc.name, len(tc.got))
		}
		if tc.got[0].Name != DefaultName {
			t.Fatalf("%s named the backend %q, want %q", tc.name, tc.got[0].Name, DefaultName)
		}
		if tc.got[0].Store != ObjectStore(def) {
			t.Fatalf("%s did not carry the default store", tc.name)
		}
	}
}

func TestSingleResolverForTypeIsDefault(t *testing.T) {
	def := NewMemory()
	r := NewSingle(def)
	if r.ForType("apt") != ObjectStore(def) {
		t.Fatal("ForType did not return the default store")
	}
}

// TestStorageDoesNotImportManifest guards the cycle the codebase already
// dodges with function pointers in manifest/backend.go: manifest reaches
// storage through them, so storage naming manifest would close the loop. The
// check is deliberately on direct imports only — internal/s3 imports manifest,
// so a transitive assertion would fail on a dependency this package does not
// control.
func TestStorageDoesNotImportManifest(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("read package imports: %v", err)
	}
	const forbidden = "github.com/ravinald/bodega/internal/manifest"
	for _, imports := range [][]string{pkg.Imports, pkg.TestImports, pkg.XTestImports} {
		for _, imp := range imports {
			if imp == forbidden {
				t.Fatalf("internal/storage imports %s; placement lives in internal/server precisely so it does not", forbidden)
			}
		}
	}
}
