package builder

import (
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// overriddenConfig gives every type its own root, so a path resolved through
// the wrong root lands somewhere no assertion accepts.
func overriddenConfig(t *testing.T) (*Config, map[string]string) {
	t.Helper()
	base := t.TempDir()
	roots := map[string]string{}
	for _, typ := range manifest.AllTypes {
		roots[typ] = filepath.Join(base, typ+"-root")
	}
	cfg := &Config{
		BuildRoot:     filepath.Join(base, "build"),
		AptRoot:       roots[manifest.TypeApt],
		GitRoot:       roots[manifest.TypeGit],
		PypiRoot:      roots[manifest.TypePypi],
		BinaryRoot:    roots[manifest.TypeBinary],
		GomodRoot:     roots[manifest.TypeGomod],
		HelmRoot:      roots[manifest.TypeHelm],
		NpmRoot:       roots[manifest.TypeNpm],
		CargoRoot:     roots[manifest.TypeCargo],
		FreeBSDRoot:   roots[manifest.TypeFreeBSD],
		DistfilesRoot: roots[manifest.TypeDistfiles],
	}
	for _, typ := range manifest.AllTypes {
		if cfg.rootFor(typ) != roots[typ] {
			t.Fatalf("%s: overriddenConfig sets no *_root the builder reads; add the new override here", typ)
		}
	}
	return cfg, roots
}

func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && filepath.IsLocal(rel)
}

// TestResetPathsCoverEveryType fails when a type in manifest.AllTypes writes
// its artifacts somewhere reset does not clear, or when reset resolves a type's
// paths through any root but that type's own override.
func TestResetPathsCoverEveryType(t *testing.T) {
	cfg, roots := overriddenConfig(t)
	cleared := ResetPaths(cfg)
	for _, typ := range manifest.AllTypes {
		paths := typeResetPaths(cfg, typ)
		if len(paths) == 0 {
			t.Errorf("%s: reset clears nothing for this type; add it to typeResetPaths", typ)
			continue
		}
		for _, p := range paths {
			if !within(roots[typ], p) {
				t.Errorf("%s: reset path %s is outside the type's root %s", typ, p, roots[typ])
			}
			if !slices.ContainsFunc(cleared, func(rp ResetPath) bool { return rp.Path == p && slices.Contains(rp.Types, typ) }) {
				t.Errorf("%s: %s missing from ResetPaths", typ, p)
			}
		}
		art := ArtifactDir(cfg, typ)
		if !slices.ContainsFunc(paths, func(p string) bool { return p == art || within(p, art) }) {
			t.Errorf("%s: ArtifactDir %s is not under any path reset clears: %v", typ, art, paths)
		}
	}
}

// TestResetPathsCoverEveryBuildDir fails when buildDirs grows a directory that
// no type's reset paths name, which is how cargo, freebsd and distfiles were
// left behind.
func TestResetPathsCoverEveryBuildDir(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{BuildRoot: root}
	cleared := map[string][]string{}
	for _, rp := range ResetPaths(cfg) {
		cleared[rp.Path] = rp.Types
	}

	v := reflect.ValueOf(buildDirs(root))
	for i := range v.NumField() {
		dir := v.Field(i).String()
		if _, ok := cleared[dir]; !ok {
			t.Errorf("dirs.%s (%s) is written by a builder and cleared by no type's reset paths", v.Type().Field(i).Name, dir)
		}
	}

	if got := cleared[filepath.Join(root, "sources")]; !slices.Equal(got, []string{manifest.TypeGit, manifest.TypeApt}) {
		t.Errorf("sources under a shared root: types = %v, want [git apt] listed once", got)
	}
}
