package host

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/clientconf"
)

// TestFirstHit covers the substring-scan logic that underlies every
// client-config check. The per-check functions are thin wrappers; testing
// firstHit directly avoids OS-state dependencies.
func TestFirstHit(t *testing.T) {
	dir := t.TempDir()

	clean := filepath.Join(dir, "clean.conf")
	if err := os.WriteFile(clean, []byte("index-url = http://bodega.internal/pypi/simple/\n"), 0o644); err != nil {
		t.Fatalf("write clean: %v", err)
	}

	dirty := filepath.Join(dir, "dirty.conf")
	if err := os.WriteFile(dirty, []byte("index-url = https://pypi.org/simple/\n"), 0o644); err != nil {
		t.Fatalf("write dirty: %v", err)
	}

	tests := []struct {
		name       string
		paths      []string
		markers    []string
		wantPath   string
		wantMarker string
	}{
		{
			name:    "no markers match",
			paths:   []string{clean},
			markers: publicUpstreams["pip"],
		},
		{
			name:       "first file matches",
			paths:      []string{dirty, clean},
			markers:    publicUpstreams["pip"],
			wantPath:   dirty,
			wantMarker: "pypi.org",
		},
		{
			name:       "later file matches when earlier missing",
			paths:      []string{filepath.Join(dir, "missing"), dirty},
			markers:    publicUpstreams["pip"],
			wantPath:   dirty,
			wantMarker: "pypi.org",
		},
		{
			name:    "missing files only",
			paths:   []string{filepath.Join(dir, "nope")},
			markers: publicUpstreams["pip"],
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := firstHit(tt.paths, tt.markers)
			if got.path != tt.wantPath {
				t.Errorf("path: got %q want %q", got.path, tt.wantPath)
			}
			if got.marker != tt.wantMarker {
				t.Errorf("marker: got %q want %q", got.marker, tt.wantMarker)
			}
		})
	}
}

// TestCheckGoproxyEnv exercises every branch of the GOPROXY classifier and
// of the resolution in front of it, with the environment and the user config
// directory stubbed so no developer's own go env file is read.
func TestCheckGoproxyEnv(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write("good", "GOPROXY=http://bodega/go\n")
	lastWins := write("last", "GOPROXY=https://proxy.golang.org\nGOPROXY=http://bodega/go\n")
	indented := write("indented", " GOPROXY=http://bodega/go\n")
	emptied := write("emptied", "GOPROXY=\n")
	fileDirect := write("direct", "GOPROXY=direct\n")
	filePipe := write("pipe", "GOPROXY=http://bodega/go|direct\n")
	fileSpaced := write("spaced", "GOPROXY=http://bodega/go , direct\n")
	fileOffFirst := write("offfirst", "GOPROXY=http://bodega/go,off,direct\n")
	cfgDir := filepath.Join(dir, "cfg")
	if err := os.MkdirAll(filepath.Join(cfgDir, "go"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "go", "env"), []byte("GOPROXY=http://bodega/go\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		env       map[string]string
		configDir string
		dirErr    error
		want      Status
	}{
		{name: "unset, no file", env: map[string]string{"GOENV": filepath.Join(dir, "absent")}, want: StatusWarn},
		{name: "direct fallthrough", env: map[string]string{"GOPROXY": "http://bodega/go,direct"}, want: StatusWarn},
		{name: "references proxy.golang.org", env: map[string]string{"GOPROXY": "https://proxy.golang.org,direct"}, want: StatusWarn},
		{name: "bodega-only with off", env: map[string]string{"GOPROXY": "http://bodega/go,off"}, want: StatusOK},
		{name: "standalone direct", env: map[string]string{"GOPROXY": "direct"}, want: StatusWarn},
		{name: "pipe fallback to direct", env: map[string]string{"GOPROXY": "http://bodega/go|direct"}, want: StatusWarn},
		{name: "whitespace around direct", env: map[string]string{"GOPROXY": "http://bodega/go ,\tdirect "}, want: StatusWarn},
		{name: "pipe fallback to proxy.golang.org", env: map[string]string{"GOPROXY": "http://bodega/go|https://proxy.golang.org"}, want: StatusWarn},
		{name: "off stops the walk before direct", env: map[string]string{"GOPROXY": "http://bodega/go,off,direct"}, want: StatusOK},
		{name: "off stops the walk before proxy.golang.org", env: map[string]string{"GOPROXY": "http://bodega/go|off|https://proxy.golang.org"}, want: StatusOK},
		{name: "list with no entries", env: map[string]string{"GOPROXY": " , | "}, want: StatusWarn},
		{name: "file: standalone direct", env: map[string]string{"GOENV": fileDirect}, want: StatusWarn},
		{name: "file: pipe fallback to direct", env: map[string]string{"GOENV": filePipe}, want: StatusWarn},
		{name: "file: whitespace around direct", env: map[string]string{"GOENV": fileSpaced}, want: StatusWarn},
		{name: "file: off stops the walk before direct", env: map[string]string{"GOENV": fileOffFirst}, want: StatusOK},
		{name: "environment direct overrides a safe file", env: map[string]string{"GOENV": good, "GOPROXY": "direct"}, want: StatusWarn},
		{name: "environment pipe fallback overrides a safe file", env: map[string]string{"GOENV": good, "GOPROXY": "http://bodega/go|direct"}, want: StatusWarn},
		{name: "safe environment overrides an unsafe file", env: map[string]string{"GOENV": fileDirect, "GOPROXY": "http://bodega/go"}, want: StatusOK},
		{name: "env file via GOENV", env: map[string]string{"GOENV": good}, want: StatusOK},
		{name: "env file at the default path", configDir: cfgDir, want: StatusOK},
		{name: "environment overrides a safe file", env: map[string]string{"GOENV": good, "GOPROXY": "https://proxy.golang.org"}, want: StatusWarn},
		{name: "last assignment wins", env: map[string]string{"GOENV": lastWins}, want: StatusOK},
		{name: "indented line is not an assignment", env: map[string]string{"GOENV": indented}, want: StatusWarn},
		{name: "file empties the value", env: map[string]string{"GOENV": emptied}, want: StatusWarn},
		{name: "GOENV=off reads no file", env: map[string]string{"GOENV": "off"}, configDir: cfgDir, want: StatusWarn},
		{name: "unreadable file is not a measurement", env: map[string]string{"GOENV": dir}, want: StatusSkip},
		{name: "no config dir is not a measurement", dirErr: errors.New("$HOME is not defined"), want: StatusSkip},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getenv := func(k string) string { return tt.env[k] }
			configDir := func() (string, error) { return tt.configDir, tt.dirErr }
			got := checkGoproxy(getenv, configDir)
			if got.Status != tt.want {
				t.Errorf("status: got %v want %v (detail=%q)", got.Status, tt.want, got.Detail)
			}
		})
	}
}

// TestGoproxyCheckAcceptsTheRenderedEnvFile installs what clientconf hands a
// Go client, through the real environment, and asks doctor about it. The file
// sets GOPROXY for the go command without any shell exporting it, so a check
// reading only the environment warned about the setup bodega itself
// advertises. go env GOPROXY is asked too, when go is on PATH, so the check
// and the toolchain are held to the same answer.
func TestGoproxyCheckAcceptsTheRenderedEnvFile(t *testing.T) {
	const base = "http://bodega.example.com"
	envFile := filepath.Join(t.TempDir(), "env")
	if err := os.WriteFile(envFile, []byte(clientconf.Gomod(base).Content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOENV", envFile)
	t.Setenv("GOPROXY", "")
	_ = os.Unsetenv("GOPROXY")

	if got := CheckGoproxyEnv(); got.Status != StatusOK {
		t.Errorf("rendered env file: got %v, want OK (detail=%q)", got.Status, got.Detail)
	}
	if goBin, err := exec.LookPath("go"); err == nil {
		out, err := exec.Command(goBin, "env", "GOPROXY").Output()
		if err != nil {
			t.Fatalf("go env GOPROXY: %v", err)
		}
		if got := strings.TrimSpace(string(out)); got != clientconf.GoProxy(base) {
			t.Errorf("go env GOPROXY = %q, want %q: the toolchain does not read the rendered file as doctor does", got, clientconf.GoProxy(base))
		}
	}

	for _, override := range []string{clientconf.GoProxy(base) + ",direct", clientconf.GoProxy(base) + "|direct", "direct"} {
		t.Setenv("GOPROXY", override)
		if got := CheckGoproxyEnv(); got.Status != StatusWarn {
			t.Errorf("unsafe environment override %q: got %v, want WARN (detail=%q)", override, got.Status, got.Detail)
		}
	}
}

// TestFindingIsFinding verifies the boolean classification used by the
// doctor command's exit-code logic.
func TestFindingIsFinding(t *testing.T) {
	cases := []struct {
		status Status
		want   bool
	}{
		{StatusOK, false},
		{StatusNA, false},
		{StatusWarn, true},
		{StatusFail, true},
	}
	for _, c := range cases {
		t.Run(string(c.status), func(t *testing.T) {
			if got := (Finding{Status: c.status}).IsFinding(); got != c.want {
				t.Errorf("IsFinding(%v) = %v want %v", c.status, got, c.want)
			}
		})
	}
}

// TestAllChecksRunCleanly exercises every registered check on the host
// running the tests. The goal is not to assert a particular status (which
// depends on the host) but to ensure no check panics, leaks file handles,
// or returns an empty Check field.
func TestAllChecksRunCleanly(t *testing.T) {
	for _, fn := range AllChecks() {
		f := fn()
		if f.Check == "" {
			t.Errorf("check returned empty Check identifier: %+v", f)
		}
		if f.Status == "" {
			t.Errorf("check %q returned empty Status: %+v", f.Check, f)
		}
		if f.Detail == "" {
			t.Errorf("check %q returned empty Detail: %+v", f.Check, f)
		}
	}
}
