// Package oracletest finds the native clients doctor's configuration ports
// are tested against, each at the release its port is of. Every test that
// holds a port's answer against a client's finds the client here, so one rule
// decides what a missing one means: on a developer's machine the test skips,
// and in CI, where the test job installs each client from a verified release,
// it fails. A skip there would pass the port with nothing compared.
//
// A client that is installed and will not say its version, or says another,
// counts as missing: a port of one release proves nothing against another.
package oracletest

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
)

// The releases the ports are of. .github/workflows/ci.yml installs the same
// ones for the test job.
const (
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
	if os.Getenv("CI") == "true" {
		t.Fatalf("in CI, where the test job installs this oracle: %s", r.problem)
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
