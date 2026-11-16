// Package oracletest finds the native clients doctor's configuration ports
// are tested against, each at the release its port is of. Every test that
// holds a port's answer against a client's finds the client here, so one rule
// decides what a missing one means: the test skips, except where
// BODEGA_ORACLES=required says the clients were installed for it, as the CI
// test job does from verified releases, and there it fails. A skip there
// would pass the port with nothing compared. The other CI jobs run the same
// tests on hosts nothing installed the clients on, so CI=true alone cannot
// be the signal.
//
// A client that is installed and will not say its version, or says another,
// counts as missing: a port of one release proves nothing against another.
package oracletest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The releases the ports are of. .github/workflows/ci.yml installs the same
// ones for the test job.
const (
	NodeVersion   = "v26.13.0"
	NpmVersion    = "11.20.0"
	GitVersion    = "2.54"
	PipVersion    = "26.2.1"
	PythonVersion = "3.15"
	HelmVersion   = "v4.3.0"
	GoVersion     = "go1.27.4"
)

type lookup struct {
	path, problem string
}

var (
	mu    sync.Mutex
	cache = map[string]lookup{}
)

// find resolves bin on PATH and asks it for its version with args. match
// reports whether the trimmed output is the pinned release.
func find(t testing.TB, bin, pin string, match func(out string) bool, args ...string) string {
	t.Helper()
	key := bin + "\x00" + strings.Join(args, "\x00") + "\x00" + os.Getenv("PATH")
	mu.Lock()
	r, ok := cache[key]
	if !ok {
		r = probe(bin, pin, match, args)
		cache[key] = r
	}
	mu.Unlock()
	if r.problem == "" {
		return r.path
	}
	if os.Getenv("BODEGA_ORACLES") == "required" {
		t.Fatalf("BODEGA_ORACLES=required, which says this oracle is installed: %s", r.problem)
	}
	t.Skip(r.problem)
	return ""
}

func probe(bin, pin string, match func(string) bool, args []string) lookup {
	path, err := exec.LookPath(bin)
	if err != nil {
		return lookup{problem: fmt.Sprintf("the native %s oracle needs %s, and %s is not on PATH (%v)", pin, pin, bin, err)}
	}
	out, err := exec.Command(path, args...).Output()
	got := strings.TrimSpace(string(out))
	if err != nil || !match(got) {
		return lookup{problem: fmt.Sprintf("the port is of %s, and %s %s answers %q (%v)", pin, path, strings.Join(args, " "), got, err)}
	}
	return lookup{path: path}
}

// Node returns the Node v26.13.0 the NODE_OPTIONS lexer is of.
func Node(t testing.TB) string {
	t.Helper()
	return find(t, "node", "Node "+NodeVersion, func(out string) bool { return out == NodeVersion }, "--version")
}

// Npm returns the npm 11.20.0 the npmrc reader and the option types are of.
func Npm(t testing.TB) string {
	t.Helper()
	return find(t, "npm", "npm "+NpmVersion, func(out string) bool { return out == NpmVersion }, "--version")
}

// Git returns the Git 2.54 the configuration port is of.
func Git(t testing.TB) string {
	t.Helper()
	return find(t, "git", "Git "+GitVersion, func(out string) bool { return strings.HasPrefix(out, "git version "+GitVersion+".") }, "version")
}

// Pip returns a python3 whose pip is the 26.2.1 the pip port is of, to run
// as python3 -m pip.
func Pip(t testing.TB) string {
	t.Helper()
	return find(t, "python3", "pip "+PipVersion, func(out string) bool { return strings.HasPrefix(out, "pip "+PipVersion+" ") }, "-m", "pip", "--version")
}

// Python returns the python3 whose configparser the tests read a file with.
func Python(t testing.TB) string {
	t.Helper()
	return find(t, "python3", "Python "+PythonVersion, func(out string) bool { return strings.HasPrefix(out, "Python "+PythonVersion+".") }, "--version")
}

// Helm returns the Helm v4.3.0 the repositories.yaml loader is of.
func Helm(t testing.TB) string {
	t.Helper()
	return find(t, "helm", "Helm "+HelmVersion, func(out string) bool { return out == HelmVersion || strings.HasPrefix(out, HelmVersion+"+") }, "version", "--short")
}

// Go returns the go command of the toolchain go.mod names, whose GOPROXY and
// go.env reading the port is of.
func Go(t testing.TB) string {
	t.Helper()
	return find(t, "go", GoVersion, func(out string) bool { return out == GoVersion }, "env", "GOVERSION")
}

// QuietGo turns Go telemetry off for a go command run with HOME=home. Left
// on, each go command under a fresh HOME starts a detached child that keeps
// writing counter files there after the command exits, and the test's
// TempDir cleanup then fails on a directory that is no longer empty.
func QuietGo(t testing.TB, home string) {
	t.Helper()
	for _, config := range []string{filepath.Join(home, ".config"), filepath.Join(home, "Library", "Application Support")} {
		dir := filepath.Join(config, "go", "telemetry")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "mode"), []byte("off\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
