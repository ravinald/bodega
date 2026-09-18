package config_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"testing"
)

// configLoadAllowlist names the test functions permitted to call config.Load
// with no BODEGA_CONFIG_FILE in force, keyed "<dir>/<file>:<func>" and carrying
// the reason. A case belongs here only when reading the installed config file
// is the thing under test; everything else sets the override.
var configLoadAllowlist = map[string]string{
	// The fallback order is what this one exercises. It reassigns the
	// systemConfigFile and userConfigFile seams to paths under t.TempDir() and
	// blanks the override on purpose, so the rows with no override still read
	// a scratch file rather than /etc.
	"internal/config/resolve_test.go:TestConfigPathMatrix": "drives ConfigPath's candidate list through its test seams",
}

// config.Load with no override resolves through ConfigPath, which falls back to
// /etc/bodega/config.json. On a bare runner that path is absent and the
// fallback is invisible; on a host with bodega installed it is root-owned, and
// the test fails for a reason the change under test never touched. That is how
// a suite teaches people to ignore its own red.
//
// #320 was one instance. This is the scan, so the next one fails here with a
// file and a function name instead of arriving as a permission error from a
// package nobody was editing.
func TestEveryTestIsolatesTheConfigFile(t *testing.T) {
	// Keyed by directory and package: an external _test package cannot call the
	// internal one's helpers, so merging their function sets would credit a
	// caller with an isolation it has no way to reach.
	type scope struct{ dir, pkg string }
	funcs := map[scope]map[string]*testFunc{}

	fset := token.NewFileSet()
	// cmd/ as well as internal/: the commands are where a test drives the real
	// cobra tree, and #320's surviving half was one of them.
	for _, tree := range []string{"internal", "cmd"} {
		// os.Root rather than filepath.WalkDir: the walk and the read are
		// scoped to the tree and cannot follow a symlink out of it.
		root, err := os.OpenRoot(path.Join("..", "..", tree))
		if err != nil {
			t.Fatalf("open %s/: %v", tree, err)
		}
		err = fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			// "." or "_" leading the name is what the go tool itself ignores,
			// so a file it will never compile must not be able to fail the
			// parse below. An AppleDouble ._x.go sidecar is a NUL-filled
			// resource fork, and one syntax error aborts the whole walk.
			if base := d.Name(); base != "." && (strings.HasPrefix(base, ".") || strings.HasPrefix(base, "_")) {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return fs.SkipDir
				}
				return nil
			}
			// Every .go file, not only the tests: in cmd/bodega a test reaches
			// config.Load through the non-test helper loadConfig, so a graph
			// built from test files alone stops at the test and reports green.
			if !strings.HasSuffix(p, ".go") {
				return nil
			}
			body, readErr := fs.ReadFile(root.FS(), p)
			if readErr != nil {
				return readErr
			}
			file, parseErr := parser.ParseFile(fset, p, body, 0)
			if parseErr != nil {
				return parseErr
			}
			qual := path.Join(tree, p)
			sc := scope{dir: path.Dir(qual), pkg: file.Name.Name}
			if funcs[sc] == nil {
				funcs[sc] = map[string]*testFunc{}
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil || fn.Recv != nil {
					continue
				}
				funcs[sc][fn.Name.Name] = inspectFunc(fset, qual, sc.pkg, fn)
			}
			return nil
		})
		_ = root.Close()
		if err != nil {
			t.Fatalf("walk %s/: %v", tree, err)
		}
	}

	// Only the entry points are judged. A helper that calls Load is isolated by
	// whichever test called it, and flagging the helper would name a line whose
	// caller is already doing the right thing.
	var bad []string
	for _, pkgFuncs := range funcs {
		for name, fn := range pkgFuncs {
			if !isEntryPoint(name) {
				continue
			}
			if !reaches(pkgFuncs, name, map[string]bool{}, func(f *testFunc) bool { return f.callsLoad }) {
				continue
			}
			// Blanking the override counts as not setting it: ConfigPath reads
			// an empty value as unset and walks back to /etc. It is a
			// deliberate act rather than an omission, so it needs a reason on
			// the allowlist even where the same test sets a real path on
			// another row.
			if reaches(pkgFuncs, name, map[string]bool{}, func(f *testFunc) bool { return f.setsEnv }) &&
				!reaches(pkgFuncs, name, map[string]bool{}, func(f *testFunc) bool { return f.blanksEnv }) {
				continue
			}
			if _, ok := configLoadAllowlist[fn.file+":"+name]; ok {
				continue
			}
			bad = append(bad, fmt.Sprintf("%s:%d: %s", fn.file, fn.line, name))
		}
	}
	sort.Strings(bad)
	for _, b := range bad {
		t.Errorf("%s calls config.Load without setting config.EnvConfigFile, "+
			"so it reads /etc/bodega/config.json on a host that has bodega installed", b)
	}
}

type testFunc struct {
	file      string
	line      int
	callsLoad bool
	setsEnv   bool
	blanksEnv bool
	calls     []string
}

func isEntryPoint(name string) bool {
	for _, prefix := range []string{"Test", "Benchmark", "Fuzz", "Example"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// reaches walks the same-package call graph. Both the Load call and the
// override commonly sit in a helper rather than in the test body, and the
// helpers are where the pattern already lives: openConfigForm, loadedFrom,
// writeConfig, loadApt.
func reaches(pkgFuncs map[string]*testFunc, name string, seen map[string]bool, want func(*testFunc) bool) bool {
	fn, ok := pkgFuncs[name]
	if !ok || seen[name] {
		return false
	}
	seen[name] = true
	if want(fn) {
		return true
	}
	for _, callee := range fn.calls {
		if reaches(pkgFuncs, callee, seen, want) {
			return true
		}
	}
	return false
}

func inspectFunc(fset *token.FileSet, file, pkg string, fn *ast.FuncDecl) *testFunc {
	out := &testFunc{file: file, line: fset.Position(fn.Pos()).Line}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			if id, ok := fun.X.(*ast.Ident); ok && id.Name == "config" && fun.Sel.Name == "Load" {
				out.callsLoad = true
			}
			if fun.Sel.Name == "Setenv" && len(call.Args) == 2 && namesConfigFileEnv(call.Args[0]) {
				if isEmptyString(call.Args[1]) {
					out.blanksEnv = true
				} else {
					out.setsEnv = true
				}
			}
		case *ast.Ident:
			// Inside package config the bare identifier is config.Load.
			if pkg == "config" && fun.Name == "Load" {
				out.callsLoad = true
			}
			out.calls = append(out.calls, fun.Name)
		}
		return true
	})
	return out
}

func namesConfigFileEnv(arg ast.Expr) bool {
	switch a := arg.(type) {
	case *ast.SelectorExpr:
		return a.Sel.Name == "EnvConfigFile"
	case *ast.Ident:
		return a.Name == "EnvConfigFile"
	case *ast.BasicLit:
		return a.Value == `"BODEGA_CONFIG_FILE"`
	}
	return false
}

func isEmptyString(arg ast.Expr) bool {
	lit, ok := arg.(*ast.BasicLit)
	return ok && lit.Value == `""`
}
