package host

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// writeTree builds a host root holding files.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, body := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func assertFinding(t *testing.T, got Finding, want Status, detail ...string) {
	t.Helper()
	if got.Status != want {
		t.Fatalf("status = %s, want %s (detail: %s)", got.Status, want, got.Detail)
	}
	for _, d := range detail {
		if !strings.Contains(got.Detail, d) {
			t.Errorf("detail %q does not mention %q", got.Detail, d)
		}
	}
}

// onGuest reports a ports tree at /usr/ports.
func onGuest(p string) bool { return strings.HasPrefix(p, "/usr/ports/") }

// toolOnPath puts an executable named name, which fails the test's purpose
// only by existing, on a PATH holding nothing else.
func toolOnPath(t *testing.T, names ...string) {
	t.Helper()
	bin := t.TempDir()
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)
}

// Neither FreeBSD check reads a verdict from pkg or make, so neither reports
// OK: with the tool installed the row warns unchecked and names the command
// the operator runs, and it is N/A only where nothing fetches.
func TestFreeBSDChecksLeaveTheVerdictToTheOperator(t *testing.T) {
	ran := func(string, string, ...string) ([]byte, error) {
		t.Error("a FreeBSD check ran a host tool")
		return nil, nil
	}
	t.Setenv("PORTSDIR", "")
	t.Setenv("MAKEFLAGS", "")
	none := func(string) bool { return false }

	toolOnPath(t)
	assertFinding(t, checkPkgRepos("freebsd", ran), StatusNA, "pkg is not on PATH")
	assertFinding(t, checkMakeConf("freebsd", ran, onGuest), StatusNA, "make is not on PATH")

	toolOnPath(t, "pkg", "make")
	pkg := checkPkgRepos("freebsd", ran)
	assertFinding(t, pkg, StatusWarn, toolUnchecked, "doctor does not run pkg")
	if !strings.Contains(pkg.Remediation, "pkg -vv") || !strings.Contains(pkg.Remediation, "--write-pkg-repo") {
		t.Errorf("remediation = %q", pkg.Remediation)
	}

	mk := checkMakeConf("freebsd", ran, onGuest)
	assertFinding(t, mk, StatusWarn, toolUnchecked, "doctor does not run make")
	if !strings.Contains(mk.Remediation, "make -C /usr/ports/ports-mgmt/pkg -V MASTER_SITE_OVERRIDE -V MASTER_SITE_BACKUP") {
		t.Errorf("remediation = %q", mk.Remediation)
	}
	assertFinding(t, checkMakeConf("freebsd", ran, none), StatusNA, "no ports tree: /usr/ports/Mk/bsd.port.mk does not exist")

	// A make.conf, a PORTSDIR or a MAKEFLAGS that can name another tree
	// leaves "no tree" unproven.
	confOnly := func(p string) bool { return p == makeConfPath }
	assertFinding(t, checkMakeConf("freebsd", ran, confOnly), StatusWarn, toolUnchecked)
	t.Setenv("MAKEFLAGS", "PORTSDIR=/elsewhere")
	assertFinding(t, checkMakeConf("freebsd", ran, none), StatusWarn, toolUnchecked)
	t.Setenv("MAKEFLAGS", "")
	t.Setenv("PORTSDIR", "/elsewhere")
	assertFinding(t, checkMakeConf("freebsd", ran, none), StatusNA, "/elsewhere/Mk/bsd.port.mk")
	assertFinding(t, checkMakeConf("freebsd", ran, func(p string) bool { return strings.HasPrefix(p, "/elsewhere/") }), StatusWarn, "doctor does not run make")
}

func TestRunToolReportsWhatFailed(t *testing.T) {
	if _, err := runTool("", "bodega-doctor-no-such-tool"); !errors.Is(err, exec.ErrNotFound) {
		t.Errorf("err = %v, want exec.ErrNotFound", err)
	}
	out, err := runTool("in\n", "sh", "-c", "cat; echo first >&2; echo second >&2; exit 3")
	if string(out) != "in\n" {
		t.Errorf("stdout = %q, want the stdin echoed", out)
	}
	if err == nil || !strings.Contains(err.Error(), "exit status 3: first; second") {
		t.Errorf("err = %v, want the exit status and stderr on one line", err)
	}
}

// testWaitDelay stands in for toolWaitDelay in the runTool timing tests. A
// case that waits out the delay and one that does not differ by 10s, which
// a slow process start on a shared CI VM cannot close.
const testWaitDelay = 10 * time.Second

// The upper bounds in the runTool timing tests only guard against a hang.
// testHeadroom is what a loaded CI VM gets over the expected return; 5s
// failed a clean exit there at 17.89s. testTimeoutBound covers a call that
// times out after testTimeout and then waits out testWaitDelay,
// testDelayBound one that only waits out testWaitDelay.
//
// A hung runTool returns when the sleep holding its pipes exits, so the
// bounds catch a hang only while testHold outlasts every one of them.
// testHold derives from the largest bound plus testHoldMargin, so raising
// testWaitDelay or testHeadroom raises the hold with them, and
// TestRunToolHoldOutlastsTheBounds fails if an edit breaks that.
const (
	testTimeout      = time.Second
	testHeadroom     = 30 * time.Second
	testDelayBound   = testWaitDelay + testHeadroom
	testTimeoutBound = testTimeout + testWaitDelay + testHeadroom
	testHoldMargin   = 10 * time.Second
	testHold         = testTimeoutBound + testHoldMargin
)

// testHoldArg is testHold as sleep(1) takes it, rounded up to whole seconds
// so the conversion never shortens the hold.
var testHoldArg = strconv.FormatInt(int64((testHold+time.Second-1)/time.Second), 10)

func TestRunToolHoldOutlastsTheBounds(t *testing.T) {
	for _, bound := range []time.Duration{testDelayBound, testTimeoutBound, testWaitDelay / 2} {
		if testHold < bound+testHoldMargin {
			t.Errorf("testHold %s is not %s past the bound %s: a hang would return within it", testHold, testHoldMargin, bound)
		}
	}
	if testHoldMargin < 10*time.Second {
		t.Errorf("testHoldMargin %s is under 10s", testHoldMargin)
	}
}

// A makefile's != assignment runs under sh, whose children hold make's
// pipes. The timeout has to end the whole tree and return on time, and a
// child left running after a clean exit is ended too.
func TestRunToolEndsTheProcessTree(t *testing.T) {
	pidfile := filepath.Join(t.TempDir(), "pid")
	gone := func(t *testing.T) {
		t.Helper()
		data, err := os.ReadFile(pidfile)
		if err != nil {
			t.Fatal(err)
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil {
			t.Fatal(err)
		}
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			if syscall.Kill(pid, 0) != nil {
				return
			}
		}
		t.Errorf("descendant %d still running after runTool returned", pid)
	}

	t.Run("timeout", func(t *testing.T) {
		start := time.Now()
		_, err := runToolWaiting(testTimeout, testWaitDelay, "", "sh", "-c", `sleep "$2" & echo $! >"$1"; sleep "$2"; true`, "sh", pidfile, testHoldArg)
		// Expected: testTimeout, then the end of the group closes the
		// pipes. testTimeoutBound allows testWaitDelay as well, plus
		// testHeadroom. A tree left running holds the pipes until the
		// testHold sleep exits, and testHold outlasting the bound is what
		// lets the bound catch that hang.
		if elapsed := time.Since(start); elapsed > testTimeoutBound {
			t.Errorf("returned after %s, want at most %s", elapsed, testTimeoutBound)
		}
		if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("sh did not answer within %s", testTimeout)) {
			t.Errorf("err = %v", err)
		}
		gone(t)
	})
	t.Run("clean exit", func(t *testing.T) {
		start := time.Now()
		out, _ := runToolWaiting(time.Minute, testWaitDelay, "", "sh", "-c", `echo answer; sleep "$2" & echo $! >"$1"`, "sh", pidfile, testHoldArg)
		// Expected: testWaitDelay, since the background sleep holds stdout.
		// The lower bound proves the delay applied. testDelayBound adds
		// testHeadroom over it. A hang returns at the testHold sleep's exit
		// or the one-minute timeout, whichever comes first, and testHold
		// outlasting the bound is what lets the bound catch it.
		if elapsed := time.Since(start); elapsed < testWaitDelay || elapsed > testDelayBound {
			t.Errorf("returned after %s, want between %s and %s", elapsed, testWaitDelay, testDelayBound)
		}
		if string(out) != "answer\n" {
			t.Errorf("stdout = %q", out)
		}
		gone(t)
	})
}

// detachEnv makes the test binary, run as a tool, start a sleep in a session
// of its own, as daemon(8) does, and write the sleep's pid where the test
// can find it.
const detachEnv = "BODEGA_TEST_DETACH"

func TestDetachHelper(t *testing.T) {
	mode := os.Getenv(detachEnv)
	if mode == "" {
		return
	}
	child := exec.Command("sleep", testHoldArg)
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if mode != "closed" {
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv(detachEnv+"_PID"), []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
		t.Fatal(err)
	}
	if mode == "wait" {
		_ = child.Wait()
	}
}

// A process that leaves the tool's process group and session is still the
// tool's: runTool returns within its bound and leaves it neither running nor
// a zombie, and a process doctor started some other way is not touched.
// Only FreeBSD's reaper can follow a process across setsid, and doctor runs
// tools only there.
func TestRunToolEndsDetachedDescendants(t *testing.T) {
	if runtime.GOOS != "freebsd" {
		t.Skip("descendants that call setsid are owned through procctl(2) reaping, which is FreeBSD's")
	}
	bystander := exec.Command("sleep", testHoldArg)
	bystander.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := bystander.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bystander.Process.Kill(); _ = bystander.Wait() })

	for _, c := range []struct {
		mode     string
		timeout  time.Duration
		min, max time.Duration
		timeOut  bool
	}{
		// Expected: testTimeout, then ending the subtree closes the pipes.
		// testTimeoutBound allows testWaitDelay as well, plus testHeadroom.
		// The detached sleep runs for testHold, and testHold outlasting the
		// bound is what lets the bound catch a hang.
		{"wait", testTimeout, 0, testTimeoutBound, true},
		// Expected: testWaitDelay, since the detached sleep holds stdout.
		// testDelayBound adds testHeadroom over it, and testHold outlasting
		// the bound is what lets the bound catch a hang.
		{"hold", time.Minute, testWaitDelay, testDelayBound, false},
		// Expected: near zero, since nothing holds the pipes. Half the wait
		// delay leaves 5s of headroom and still fails a run that waits it out.
		{"closed", time.Minute, 0, testWaitDelay / 2, false},
	} {
		t.Run(c.mode, func(t *testing.T) {
			pidfile := filepath.Join(t.TempDir(), "pid")
			t.Setenv(detachEnv, c.mode)
			t.Setenv(detachEnv+"_PID", pidfile)
			start := time.Now()
			_, err := runToolWaiting(c.timeout, testWaitDelay, "", os.Args[0], "-test.run=^TestDetachHelper$")
			if elapsed := time.Since(start); elapsed < c.min || elapsed > c.max {
				t.Errorf("returned after %s, want between %s and %s", elapsed, c.min, c.max)
			}
			if timedOut := err != nil && strings.Contains(err.Error(), "did not answer within"); timedOut != c.timeOut {
				t.Errorf("err = %v", err)
			}
			data, err := os.ReadFile(pidfile)
			if err != nil {
				t.Fatal(err)
			}
			pid, err := strconv.Atoi(string(data))
			if err != nil {
				t.Fatal(err)
			}
			if syscall.Kill(pid, 0) == nil {
				_ = syscall.Kill(pid, syscall.SIGKILL)
				t.Errorf("detached descendant %d outlived runTool", pid)
			}
		})
	}
	if err := bystander.Process.Signal(syscall.Signal(0)); err != nil {
		t.Errorf("a process runTool did not start was ended: %v", err)
	}
}

func TestMakeConfSitesComeFromTheRenderer(t *testing.T) {
	names, route := makeConfSites()
	if !slices.Equal(names, []string{"MASTER_SITE_OVERRIDE", "MASTER_SITE_BACKUP"}) {
		t.Errorf("names = %v", names)
	}
	if route != "/distfiles/@${BODEGA_DISTFILES_ENV}/${DIST_SUBDIR}/" {
		t.Errorf("route = %q", route)
	}
}

func TestAptSourcesNAWithoutApt(t *testing.T) {
	assertFinding(t, checkAptSources(t.TempDir(), "linux"), StatusNA, "/etc/apt")

	// <root>/etc is a regular file, so stat of <root>/etc/apt fails with
	// ENOTDIR, which is not fs.ErrNotExist: the check measured nothing.
	notDir := writeTree(t, map[string]string{"/etc": "not a directory\n"})
	skipped := checkAptSources(notDir, "linux")
	assertFinding(t, skipped, StatusSkip, "/etc/apt", "not a directory")
	if skipped.Remediation == "" {
		t.Error("a SKIPPED apt-sources row carries no remediation, so the Could not run: block cannot say what it needed")
	}

	empty := t.TempDir()
	if err := os.MkdirAll(filepath.Join(empty, "etc", "apt"), 0o755); err != nil {
		t.Fatal(err)
	}
	assertFinding(t, checkAptSources(empty, "linux"), StatusOK)

	public := writeTree(t, map[string]string{"/etc/apt/sources.list": "deb http://deb.debian.org/debian bookworm main\n"})
	assertFinding(t, checkAptSources(public, "linux"), StatusWarn, "deb.debian.org")
	assertFinding(t, checkAptSources(public, "darwin"), StatusNA)
}

// debianSources is Debian 13's cloud-image debian.sources, whose URIs name
// no host: apt reads the hosts from the mirror lists they point at.
const debianSources = `Types: deb deb-src
URIs: mirror+file:///etc/apt/mirrors/debian.list
Suites: trixie trixie-updates trixie-backports
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb deb-src
URIs: mirror+file:///etc/apt/mirrors/debian-security.list
Suites: trixie-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
`

// ubuntuSources is Ubuntu 24.04's ubuntu.sources as the cloud image ships it.
const ubuntuSources = `## See the sources.list(5) manual page for further settings.
Types: deb
URIs: http://us.archive.ubuntu.com/ubuntu/
Suites: noble noble-updates noble-backports
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: http://security.ubuntu.com/ubuntu/
Suites: noble-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
`

func TestAptSourcesReadsSourcesAsApt(t *testing.T) {
	mirrors := map[string]string{
		"/etc/apt/mirrors/debian.list":          "https://deb.debian.org/debian\n",
		"/etc/apt/mirrors/debian-security.list": "# security archive\nhttps://security.debian.org/debian-security\tpriority:1\n",
	}
	tree := func(files map[string]string) string {
		all := map[string]string{}
		for k, v := range mirrors {
			all[k] = v
		}
		for k, v := range files {
			all[k] = v
		}
		return writeTree(t, all)
	}

	debian := tree(map[string]string{"/etc/apt/sources.list.d/debian.sources": debianSources})
	assertFinding(t, checkAptSources(debian, "linux"), StatusWarn, "deb.debian.org", "/etc/apt/mirrors/debian.list", "debian.sources")

	disabled := strings.ReplaceAll(debianSources, "Components: main\n", "Components: main\nEnabled: no\n")
	assertFinding(t, checkAptSources(tree(map[string]string{"/etc/apt/sources.list.d/debian.sources": disabled}), "linux"), StatusOK)

	security := tree(map[string]string{
		"/etc/apt/sources.list.d/debian.sources": strings.Replace(debianSources, "Components: main\n", "Components: main\nEnabled: no\n", 1),
	})
	assertFinding(t, checkAptSources(security, "linux"), StatusWarn, "security.debian.org", "debian-security.list")

	missing := writeTree(t, map[string]string{"/etc/apt/sources.list.d/debian.sources": debianSources})
	skipped := checkAptSources(missing, "linux")
	assertFinding(t, skipped, StatusSkip, "/etc/apt/mirrors/debian.list", "no such file")
	if skipped.Remediation == "" {
		t.Error("a SKIPPED apt-sources row carries no remediation")
	}

	oneLine := writeTree(t, map[string]string{
		"/etc/apt/sources.list.d/security.list": "deb http://security.debian.org/debian-security trixie-security main\n",
	})
	assertFinding(t, checkAptSources(oneLine, "linux"), StatusWarn, "security.debian.org", "security.list")

	oneLineMirror := tree(map[string]string{
		"/etc/apt/sources.list": "deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] mirror+file:/etc/apt/mirrors/debian.list trixie main\n",
	})
	assertFinding(t, checkAptSources(oneLineMirror, "linux"), StatusWarn, "deb.debian.org", "debian.list")

	commented := writeTree(t, map[string]string{
		"/etc/apt/sources.list": "# deb http://archive.ubuntu.com/ubuntu noble main\n" +
			"deb [ arch=amd64 ] https://bodega.internal/apt/ubuntu noble main # was archive.ubuntu.com\n",
		"/etc/apt/sources.list.d/ubuntu.sources": "# URIs: http://archive.ubuntu.com/ubuntu\nTypes: deb\nURIs: https://bodega.internal/apt/ubuntu\nSuites: noble\n",
	})
	assertFinding(t, checkAptSources(commented, "linux"), StatusOK)

	ubuntu := writeTree(t, map[string]string{"/etc/apt/sources.list.d/ubuntu.sources": ubuntuSources})
	assertFinding(t, checkAptSources(ubuntu, "linux"), StatusWarn, "archive.ubuntu.com", "ubuntu.sources")

	off := writeTree(t, map[string]string{
		"/etc/apt/sources.list.d/ubuntu.sources": strings.ReplaceAll(ubuntuSources, "Types: deb\n", "Types: deb\nEnabled: no\n"),
	})
	assertFinding(t, checkAptSources(off, "linux"), StatusOK)
}

func TestPublicHostMatchesHostNotSubstring(t *testing.T) {
	markers := publicUpstreams["apt"]
	for uri, want := range map[string]string{
		"http://archive.ubuntu.com/ubuntu":            "archive.ubuntu.com",
		"http://us.archive.ubuntu.com/ubuntu":         "archive.ubuntu.com",
		"https://DEB.Debian.org./debian":              "deb.debian.org",
		"https://security.debian.org/debian-security": "security.debian.org",
		"http://notarchive.ubuntu.com.example/ubuntu": "",
		"https://mirror.example/archive.ubuntu.com/":  "",
		"https://bodega.internal/apt/deb.debian.org":  "",
		"cdrom:[Debian GNU/Linux 13]/":                "",
		"tor+https://deb.debian.org/debian":           "deb.debian.org",
	} {
		if got := publicHost(uri, markers); got != want {
			t.Errorf("publicHost(%q) = %q, want %q", uri, got, want)
		}
	}
}

func TestChecksAgainstFixtureRootPerOS(t *testing.T) {
	tree := map[string]string{
		"/etc/apt/sources.list.d/ubuntu.sources": "URIs: http://archive.ubuntu.com/ubuntu\n",
		"/usr/local/etc/pip.conf":                "[global]\nindex-url = https://pypi.org/simple\n",
		"/usr/local/etc/npmrc":                   "registry=https://registry.npmjs.org/\n",
	}
	home := "/home/op"
	unreached := func(string, string, ...string) ([]byte, error) {
		t.Fatal("a check off FreeBSD ran a tool")
		return nil, nil
	}
	type row struct {
		check string
		run   func(root, goos string) Finding
		linux Status
		bsd   Status
	}
	rows := []row{
		{"apt-sources", checkAptSources, StatusWarn, StatusNA},
		{"pip-config", func(root, goos string) Finding { return checkPipConfig(root, goos, home) }, StatusOK, StatusWarn},
		{"npm-config", func(root, goos string) Finding { return checkNpmConfig(root, goos, home) }, StatusOK, StatusWarn},
	}
	root := writeTree(t, tree)
	for _, r := range rows {
		for goos, want := range map[string]Status{"linux": r.linux, "freebsd": r.bsd} {
			t.Run(r.check+"/"+goos, func(t *testing.T) {
				got := r.run(root, goos)
				if got.Check != r.check {
					t.Errorf("check = %q, want %q", got.Check, r.check)
				}
				assertFinding(t, got, want)
			})
		}
	}
	for _, goos := range []string{"linux", "darwin"} {
		assertFinding(t, checkPkgRepos(goos, unreached), StatusNA)
		assertFinding(t, checkMakeConf(goos, unreached, onGuest), StatusNA)
	}

	// The paths the FreeBSD rows read on their own, with nothing else in
	// the tree that could produce the same answer.
	pip := writeTree(t, map[string]string{"/usr/local/pip.conf": "index-url = https://pypi.org/simple\n"})
	assertFinding(t, checkPipConfig(pip, "freebsd", ""), StatusWarn, "/usr/local/pip.conf")
	npm := writeTree(t, map[string]string{"/home/op/.npmrc": "registry=https://registry.npmjs.org/\n"})
	assertFinding(t, checkNpmConfig(npm, "freebsd", home), StatusWarn, ".npmrc")
}
