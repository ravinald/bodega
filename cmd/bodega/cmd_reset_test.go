package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// TestManifestDirIgnoresExecutableSiblings pins the manifest root against the
// layout that made the shipped config lie: /opt/bodega/bin/bodega beside
// /opt/bodega/manifests. The resolver probed <exeDir>/manifests and
// <exeDir>/../manifests before storage_path, so an ordinary install served a
// directory the config never named while _comment_manifest_dir promised that a
// backup of storage_path was a backup of the whole repository.
//
// It runs the real binary because the probe read os.Executable(): a test
// calling Load in-process asks about the test binary's directory, which is
// wherever `go test` put it.
func TestManifestDirIgnoresExecutableSiblings(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the bodega binary")
	}

	root := t.TempDir()
	binDir := filepath.Join(root, "probe", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	sibling := filepath.Join(root, "probe", "manifests")
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatalf("mkdir sibling manifests: %v", err)
	}

	bin := filepath.Join(binDir, "bodega")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	store := filepath.Join(root, "store")
	cfgPath := filepath.Join(root, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"storage_path":`+quoteJSON(store)+`}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// reset names the manifest root before it asks for anything. Answering the
	// audit prompt "n" and the confirmation word with a wrong one leaves every
	// path on disk untouched.
	cmd := exec.Command(bin, "reset")
	cmd.Env = append(os.Environ(), "BODEGA_CONFIG_FILE="+cfgPath)
	cmd.Stdin = strings.NewReader("n\nno\n")
	out, _ := cmd.CombinedOutput()

	want := filepath.Join(store, "manifests")
	if !strings.Contains(string(out), want) {
		t.Errorf("reset did not name %q as the manifest root:\n%s", want, out)
	}
	if strings.Contains(string(out), sibling) {
		t.Errorf("reset named the executable's sibling %q as the manifest root:\n%s", sibling, out)
	}
}

// quoteJSON renders a path as a JSON string.
func quoteJSON(s string) string {
	return `"` + strings.ReplaceAll(s, `\`, `\\`) + `"`
}

// TestResetNamesOverrideOutsideBuildRoot runs the real prompt against a config
// whose helm_root sits outside build_root, answers the confirmation wrongly,
// and checks the override's directory was named and left on disk.
func TestResetNamesOverrideOutsideBuildRoot(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the bodega binary")
	}

	root := t.TempDir()
	buildRoot := filepath.Join(root, "build")
	helmRoot := filepath.Join(root, "elsewhere")
	charts := filepath.Join(helmRoot, "charts")
	if err := os.MkdirAll(charts, 0o755); err != nil {
		t.Fatalf("mkdir charts: %v", err)
	}

	bin := filepath.Join(root, "bodega")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	cfgPath := filepath.Join(root, "config.json")
	body := `{"storage_path":` + quoteJSON(filepath.Join(root, "store")) +
		`,"build_root":` + quoteJSON(buildRoot) +
		`,"helm_root":` + quoteJSON(helmRoot) + `}`
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := exec.Command(bin, "reset")
	cmd.Env = append(os.Environ(), "BODEGA_CONFIG_FILE="+cfgPath)
	cmd.Stdin = strings.NewReader("n\nno\n")
	out, _ := cmd.CombinedOutput()

	prompt, _, _ := strings.Cut(string(out), "to confirm")
	if !strings.Contains(prompt, charts+"  (helm_root)") {
		t.Errorf("prompt did not name %s as outside build_root:\n%s", charts, out)
	}
	if !strings.Contains(prompt, filepath.Join(buildRoot, "cargo")) {
		t.Errorf("prompt did not name the cargo tree under build_root:\n%s", out)
	}
	if _, err := os.Stat(charts); err != nil {
		t.Errorf("a refused confirmation removed %s: %v", charts, err)
	}
}

func TestResetTargetsMarkOutside(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{BuildRoot: filepath.Join(root, "build"), CargoRoot: filepath.Join(root, "cargo-elsewhere")}
	var sawCargo bool
	for _, tg := range resetTargets(cfg) {
		wantOutside := strings.HasPrefix(tg.Path, cfg.CargoRoot)
		if tg.Outside != wantOutside {
			t.Errorf("%s: Outside = %v, want %v", tg.Path, tg.Outside, wantOutside)
		}
		sawCargo = sawCargo || tg.Path == filepath.Join(cfg.CargoRoot, "cargo")
	}
	if !sawCargo {
		t.Errorf("cargo_root override not among reset targets")
	}
}

// TestClearResetTargetsReportsFailure pins that one path reset cannot remove
// withholds "Build artifacts cleared." and is named with its error, while the
// rest are still removed and named.
func TestClearResetTargetsReportsFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the directory mode this test relies on")
	}
	root := t.TempDir()
	ok := filepath.Join(root, "ok")
	locked := filepath.Join(root, "locked")
	stuck := filepath.Join(locked, "stuck")
	for _, d := range []string{ok, stuck} {
		if err := os.MkdirAll(filepath.Join(d, "x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	targets := []resetTarget{
		{ResetPath: builder.ResetPath{Path: ok}},
		{ResetPath: builder.ResetPath{Path: stuck}},
		{ResetPath: builder.ResetPath{Path: filepath.Join(root, "absent")}},
	}
	var stdout, stderr bytes.Buffer
	if got := clearResetTargets(&stdout, &stderr, targets); got != 1 {
		t.Fatalf("failed = %d, want 1\nstdout:\n%s\nstderr:\n%s", got, &stdout, &stderr)
	}
	if !strings.Contains(stdout.String(), "Removed "+ok) {
		t.Errorf("removed path not named:\n%s", &stdout)
	}
	if strings.Contains(stdout.String(), "Build artifacts cleared.") {
		t.Errorf("claimed success with a path left behind:\n%s", &stdout)
	}
	if !strings.Contains(stderr.String(), "could not remove "+stuck+": ") {
		t.Errorf("failed path not named with its error:\n%s", &stderr)
	}
	if _, err := os.Stat(ok); !os.IsNotExist(err) {
		t.Errorf("%s still present: %v", ok, err)
	}

	stdout.Reset()
	if got := clearResetTargets(&stdout, &stderr, targets[:1]); got != 0 || !strings.Contains(stdout.String(), "Build artifacts cleared.") {
		t.Errorf("all-absent run: failed = %d, stdout:\n%s", got, &stdout)
	}
}

// TestResetOverrideKeysExist pins the "<type>_root" names the prompt prints to
// keys config.json actually reads.
func TestResetOverrideKeysExist(t *testing.T) {
	keys := map[string]bool{}
	ct := reflect.TypeOf(config.Config{})
	for i := range ct.NumField() {
		name, _, _ := strings.Cut(ct.Field(i).Tag.Get("json"), ",")
		keys[name] = true
	}
	for _, typ := range manifest.AllTypes {
		if !keys[typ+"_root"] {
			t.Errorf("reset names %s_root for type %s, but config.json has no such key", typ, typ)
		}
	}
}

var confirmWord = regexp.MustCompile(`Type "([^"]+)" to confirm: $`)

// runConfirmedReset drives the real prompt: "n" to the audit question, then
// the printed confirmation word, or "no" when refuse is set. It returns the
// combined output and the exit code.
//
// The environment carries no BODEGA_, BOOTSTRAP_ or REPO_BUCKET variable,
// because each outranks config.json and one inherited from the developer's
// shell would point a confirmed reset at a real tree.
func runConfirmedReset(t *testing.T, bin, cfgPath string, refuse bool) (string, int) {
	t.Helper()
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "BODEGA_") || strings.HasPrefix(kv, "BOOTSTRAP_") || strings.HasPrefix(kv, "REPO_BUCKET=") {
			continue
		}
		env = append(env, kv)
	}
	cmd := exec.Command(bin, "reset")
	cmd.Env = append(env, "BODEGA_CONFIG_FILE="+cfgPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { err := cmd.Wait(); _ = pw.Close(); done <- err }()

	var out bytes.Buffer
	r := bufio.NewReader(pr)
	_, _ = io.WriteString(stdin, "n\n")
	for {
		b, err := r.ReadByte()
		if err != nil {
			t.Fatalf("reset ended before asking for the confirmation word:\n%s", &out)
		}
		out.WriteByte(b)
		if m := confirmWord.FindSubmatch(out.Bytes()); m != nil {
			answer := string(m[1])
			if refuse {
				answer = "no"
			}
			_, _ = io.WriteString(stdin, answer+"\n")
			break
		}
	}
	_, _ = io.Copy(&out, r)
	err = <-done
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return out.String(), exit.ExitCode()
	} else if err != nil {
		t.Fatalf("reset: %v", err)
	}
	return out.String(), 0
}

// TestResetClearsAndReloads runs a confirmed reset against the real binary
// with every pypi stage path seeded under an external pypi_root, and counts
// the reloads it sends to the PID file's process, which is this test. A reset
// that removed the manifests has to reload a running server whether or not
// every build path went, and one refused at the prompt changed nothing and
// must not.
func TestResetClearsAndReloads(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the bodega binary")
	}

	hup := make(chan os.Signal, 8)
	signal.Notify(hup, syscall.SIGHUP)
	t.Cleanup(func() { signal.Stop(hup) })

	bin := filepath.Join(t.TempDir(), "bodega")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	for _, tc := range []struct {
		name       string
		lock       bool
		refuse     bool
		wantExit   int
		wantReload int
	}{
		{name: "success", wantReload: 1},
		{name: "one path locked", lock: true, wantExit: 1, wantReload: 1},
		{name: "refused", refuse: true, wantExit: 1, wantReload: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.lock && os.Geteuid() == 0 {
				t.Skip("root ignores the directory mode this case relies on")
			}
			base := t.TempDir()
			buildRoot := filepath.Join(base, "build")
			pypiRoot := filepath.Join(base, "pypi-elsewhere")
			manifests := filepath.Join(base, "manifests")
			logDir := filepath.Join(base, "log")
			pypiPaths := []string{
				filepath.Join(pypiRoot, "wheels"),
				filepath.Join(pypiRoot, "wheelhouse"),
				filepath.Join(pypiRoot, "build-venv"),
			}
			freebsd := filepath.Join(buildRoot, "freebsd")
			for _, d := range append([]string{freebsd, manifests, logDir}, pypiPaths...) {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(d, "sentinel"), []byte("fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(logDir, "bodega.pid"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.lock {
				if err := os.Chmod(freebsd, 0o500); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(freebsd, 0o755) })
			}
			cfgPath := filepath.Join(base, "config.json")
			body := `{"storage_backend":"local","storage_path":` + quoteJSON(filepath.Join(base, "store")) +
				`,"build_root":` + quoteJSON(buildRoot) +
				`,"pypi_root":` + quoteJSON(pypiRoot) +
				`,"manifest_dir":` + quoteJSON(manifests) +
				`,"log_dir":` + quoteJSON(logDir) + `}`
			if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}

			out, code := runConfirmedReset(t, bin, cfgPath, tc.refuse)
			if code != tc.wantExit {
				t.Errorf("exit = %d, want %d\n%s", code, tc.wantExit, out)
			}

			prompt, _, _ := strings.Cut(out, "to confirm")
			for _, p := range pypiPaths {
				if !strings.Contains(prompt, p+"  (pypi_root)") {
					t.Errorf("prompt did not name %s as outside build_root:\n%s", p, out)
				}
				_, err := os.Stat(p)
				switch {
				case tc.refuse && err != nil:
					t.Errorf("a refused confirmation removed %s: %v", p, err)
				case !tc.refuse && !os.IsNotExist(err):
					t.Errorf("%s survived a confirmed reset: %v", p, err)
				case !tc.refuse && !strings.Contains(out, "Removed "+p+"\n"):
					t.Errorf("reset removed %s without naming it:\n%s", p, out)
				}
			}
			if cleared := strings.Contains(out, "Build artifacts cleared."); cleared != (tc.wantExit == 0) {
				t.Errorf("\"Build artifacts cleared.\" printed = %v with exit %d:\n%s", cleared, code, out)
			}
			if _, err := os.Stat(manifests); os.IsNotExist(err) == tc.refuse {
				t.Errorf("manifest dir present = %v, refused = %v", err == nil, tc.refuse)
			}

			got := 0
			deadline := time.After(time.Second)
		count:
			for {
				select {
				case <-hup:
					got++
				case <-deadline:
					break count
				}
			}
			if got != tc.wantReload {
				t.Errorf("reload signals = %d, want %d\n%s", got, tc.wantReload, out)
			}
		})
	}
}
