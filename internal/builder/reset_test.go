package builder

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
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

// rootJoins returns the first path element of every filepath.Join in this
// package's sources whose base is a type's root: the identifier root or
// buildRoot, or a call to rootFor. Those are the paths a stage writes beside
// dirs, which is where the pypi wheelhouse and build venv were missed.
func rootJoins(t *testing.T) map[string][]string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	found := map[string][]string{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) < 2 || !isSelector(call.Fun, "filepath", "Join") || !isRootExpr(call.Args[0]) {
				return true
			}
			pos := fset.Position(call.Pos()).String()
			lit, ok := call.Args[1].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				t.Errorf("%s: filepath.Join onto a root with a non-literal element; reset cannot know what it names", pos)
				return true
			}
			elem, _ := strconv.Unquote(lit.Value)
			found[elem] = append(found[elem], pos)
			return true
		})
	}
	return found
}

func isSelector(e ast.Expr, pkg, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg
}

func isRootExpr(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name == "root" || v.Name == "buildRoot"
	case *ast.CallExpr:
		sel, ok := v.Fun.(*ast.SelectorExpr)
		return ok && sel.Sel.Name == "rootFor"
	}
	return false
}

// TestResetPathsCoverEveryRootJoin reads the builders rather than the reset
// list, so a stage that writes a new path under a type's root fails here
// before an operator finds it surviving a reset.
func TestResetPathsCoverEveryRootJoin(t *testing.T) {
	joins := rootJoins(t)
	for _, want := range []string{"wheelhouse", "build-venv", "sources", "combined-requirements.txt"} {
		if _, ok := joins[want]; !ok {
			t.Fatalf("the source scan found no join onto a root for %q; it is no longer reading the builders", want)
		}
	}

	root := t.TempDir()
	cleared := ResetPaths(&Config{BuildRoot: root})
	for elem, where := range joins {
		p := filepath.Join(root, elem)
		if !slices.ContainsFunc(cleared, func(rp ResetPath) bool { return rp.Path == p || within(rp.Path, p) }) {
			t.Errorf("%s is written under a type's root (%s) and cleared by no type's reset paths", elem, strings.Join(where, ", "))
		}
	}
}

// TestResetPathsPypiStageDirsFollowOverride pins the two pypi stage paths
// outside dirs to pypi_root, with the other types' roots moved elsewhere.
func TestResetPathsPypiStageDirsFollowOverride(t *testing.T) {
	cfg, roots := overriddenConfig(t)
	cleared := ResetPaths(cfg)
	for _, p := range []string{pypiWheelhouseDir(roots[manifest.TypePypi]), pypiVenvDir(roots[manifest.TypePypi])} {
		if !slices.ContainsFunc(cleared, func(rp ResetPath) bool {
			return rp.Path == p && slices.Equal(rp.Types, []string{manifest.TypePypi})
		}) {
			t.Errorf("%s missing from ResetPaths under pypi_root", p)
		}
	}
}
