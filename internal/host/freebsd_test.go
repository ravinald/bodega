package host

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

// toolRun is one recorded command: its standard output, exit status and
// standard error.
type toolRun struct {
	stdout, stderr string
	exit           int
}

// loadToolFixture reads testdata/freebsd/<name>.txt. Each file was written
// on freebsd-client (FreeBSD 15.1-RELEASE, pkg 2.8.4) by a script that
// rebuilt the case under a scratch directory and ran pkg and make with the
// argv doctor uses, pointing them at the scratch files through REPOS_DIR,
// __MAKE_CONF, MAKESYSPATH and MAKEFLAGS in their environment. A section
// "@@ <label> exit=<n>" holds a command's standard output and
// "@@ <label> stderr" its standard error. Labels: pkg (pkg -vv), portsdir
// (make -C / -f /dev/null -V ${PORTSDIR}), values (make -C <port> -V ...)
// and recipe (make -C <port> -f Makefile -f - _bodega_doctor_sites).
func loadToolFixture(t *testing.T, name string) map[string]*toolRun {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "freebsd", name+".txt"))
	if err != nil {
		t.Fatal(err)
	}
	runs := map[string]*toolRun{}
	var cur *strings.Builder
	var lines []string
	flush := func() {
		if cur != nil && len(lines) > 0 {
			cur.WriteString(strings.Join(lines, "\n") + "\n")
		}
		lines = nil
	}
	var stdout, stderr = map[string]*strings.Builder{}, map[string]*strings.Builder{}
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		head, ok := strings.CutPrefix(line, "@@ ")
		if !ok {
			lines = append(lines, line)
			continue
		}
		flush()
		label, rest, _ := strings.Cut(head, " ")
		if runs[label] == nil {
			runs[label] = &toolRun{}
			stdout[label], stderr[label] = &strings.Builder{}, &strings.Builder{}
		}
		if code, ok := strings.CutPrefix(rest, "exit="); ok {
			runs[label].exit, _ = strconv.Atoi(code)
			cur = stdout[label]
		} else {
			cur = stderr[label]
		}
	}
	flush()
	for label, r := range runs {
		r.stdout, r.stderr = stdout[label].String(), stderr[label].String()
	}
	return runs
}

// replay answers each command a check runs from recorded output, and fails
// the test on a command nothing recorded.
func replay(t *testing.T, runs map[string]*toolRun) toolRunner {
	return func(stdin, name string, args ...string) ([]byte, error) {
		label := name
		switch {
		case name == "make" && slices.Contains(args, "/dev/null"):
			label = "portsdir"
		case name == "make" && slices.Contains(args, "-"):
			label = "recipe"
			if !strings.HasPrefix(stdin, recipeTarget+": .PHONY\n") {
				t.Errorf("recipe makefile = %q", stdin)
			}
		case name == "make":
			label = "values"
		}
		r, ok := runs[label]
		if !ok {
			t.Fatalf("no recorded output for %s %s", name, strings.Join(args, " "))
		}
		if r.exit != 0 {
			return []byte(r.stdout), fmt.Errorf("exit status %d: %s", r.exit, oneLine(r.stderr))
		}
		return []byte(r.stdout), nil
	}
}

// onGuest reports the files the capture host had: a ports tree at
// /usr/ports holding ports-mgmt/pkg, and the scratch tree R6-V was
// captured in, whose Mk links to it.
func onGuest(p string) bool {
	return strings.HasPrefix(p, "/usr/ports/") || strings.HasPrefix(p, "/tmp/b101-r6v/ports/")
}

func TestPkgReposAsksPkg(t *testing.T) {
	t.Run("upstream host", func(t *testing.T) {
		got := checkPkgRepos("freebsd", replay(t, loadToolFixture(t, "upstream-pkg")))
		assertFinding(t, got, StatusWarn,
			"FreeBSD-ports is enabled and fetches from pkg+https://pkg.FreeBSD.org/FreeBSD:15:aarch64/quarterly",
			"FreeBSD-ports-kmods is enabled",
			"no enabled repository points at a bodega /freebsd/ route",
			toolLimit)
		if strings.Contains(got.Detail, "FreeBSD-base") {
			t.Errorf("detail names FreeBSD-base, which pkg -vv reports disabled: %s", got.Detail)
		}
	})
	t.Run("bodega host", func(t *testing.T) {
		got := checkPkgRepos("freebsd", replay(t, loadToolFixture(t, "bodega-pkg")))
		assertFinding(t, got, StatusOK, "bodega-latest", toolLimit)
	})
	t.Run("a profile route is bodega's", func(t *testing.T) {
		out := "\nRepositories:\n  bodega-web: { \n    url             : \"https://b/freebsd-profile/web/FreeBSD:15:aarch64/latest\",\n    enabled         : yes,\n  }\n"
		got := checkPkgRepos("freebsd", func(string, string, ...string) ([]byte, error) { return []byte(out), nil })
		assertFinding(t, got, StatusOK, "bodega-web")
	})
	t.Run("an enabled value pkg never prints", func(t *testing.T) {
		out := "\nRepositories:\n  bodega: { \n    url             : \"https://b/freebsd/x/latest\",\n    enabled         : maybe,\n  }\n"
		got := checkPkgRepos("freebsd", func(string, string, ...string) ([]byte, error) { return []byte(out), nil })
		assertFinding(t, got, StatusWarn, "enabled: maybe")
	})
	t.Run("a nested object does not end the repository", func(t *testing.T) {
		out := "\nRepositories:\n  FreeBSD: { \n    env             : {\n    }\n    url             : \"https://pkg.FreeBSD.org/x\",\n    enabled         : yes,\n  }\n"
		got := checkPkgRepos("freebsd", func(string, string, ...string) ([]byte, error) { return []byte(out), nil })
		assertFinding(t, got, StatusWarn, "FreeBSD is enabled and fetches from https://pkg.FreeBSD.org/x")
	})
	t.Run("pkg not on PATH", func(t *testing.T) {
		got := checkPkgRepos("freebsd", func(string, string, ...string) ([]byte, error) {
			return nil, &exec.Error{Name: "pkg", Err: exec.ErrNotFound}
		})
		assertFinding(t, got, StatusNA, "pkg is not on PATH")
	})
}

func TestMakeConfAsksMake(t *testing.T) {
	t.Run("upstream host", func(t *testing.T) {
		got := checkMakeConf("freebsd", replay(t, loadToolFixture(t, "upstream-make")), onGuest)
		assertFinding(t, got, StatusWarn, "/usr/ports/ports-mgmt/pkg", "BODEGA_DISTFILES_ENV is empty",
			`MASTER_SITE_BACKUP="http://distcache.FreeBSD.org/ports-distfiles/" is not every site`, toolLimit)
	})
	t.Run("bodega host", func(t *testing.T) {
		got := checkMakeConf("freebsd", replay(t, loadToolFixture(t, "bodega-make")), onGuest)
		assertFinding(t, got, StatusOK, "for environment unsupported", "both from make -V and at recipe time", toolLimit)
	})
	t.Run("no ports tree", func(t *testing.T) {
		got := checkMakeConf("freebsd", replay(t, loadToolFixture(t, "upstream-make")), func(string) bool { return false })
		assertFinding(t, got, StatusNA, "/usr/ports/Mk/bsd.port.mk does not exist")
	})
	t.Run("a tree without the probe port", func(t *testing.T) {
		got := checkMakeConf("freebsd", replay(t, loadToolFixture(t, "upstream-make")), func(p string) bool { return strings.HasSuffix(p, "bsd.port.mk") })
		assertFinding(t, got, StatusWarn, "has no ports-mgmt/pkg")
	})
	t.Run("PORTSDIR from make", func(t *testing.T) {
		var asked []string
		run := func(stdin, name string, args ...string) ([]byte, error) {
			if slices.Contains(args, "/dev/null") {
				return []byte("/srv/ports\n"), nil
			}
			asked = append(asked, args[1])
			return nil, errors.New("stop")
		}
		checkMakeConf("freebsd", run, func(string) bool { return true })
		if len(asked) == 0 || asked[0] != "/srv/ports/ports-mgmt/pkg" {
			t.Errorf("make ran in %v, want /srv/ports/ports-mgmt/pkg", asked)
		}
	})
	t.Run("make not on PATH", func(t *testing.T) {
		got := checkMakeConf("freebsd", func(string, string, ...string) ([]byte, error) {
			return nil, &exec.Error{Name: "make", Err: exec.ErrNotFound}
		}, onGuest)
		assertFinding(t, got, StatusNA, "make is not on PATH")
	})
	t.Run("recipes not run under -n", func(t *testing.T) {
		runs := loadToolFixture(t, "bodega-make")
		runs["recipe"].stdout = strings.ReplaceAll(runs["recipe"].stdout, recipeMark, "echo "+recipeMark)
		got := checkMakeConf("freebsd", replay(t, runs), onGuest)
		assertFinding(t, got, StatusWarn, "at recipe time: make printed something other than one value per variable")
	})
}

// withSite rewrites what make printed for one site variable in a capture,
// in both the make -V and the recipe reading.
func withSite(runs map[string]*toolRun, name, site string) {
	names, _ := makeConfSites()
	lines := strings.Split(runs["values"].stdout, "\n")
	lines[slices.Index(names, name)] = site
	runs["values"].stdout = strings.Join(lines, "\n")
	var recipe []string
	for _, l := range strings.Split(runs["recipe"].stdout, "\n") {
		if strings.HasPrefix(l, recipeMark+name+"=") {
			l = recipeMark + name + "=" + site
		}
		recipe = append(recipe, l)
	}
	runs["recipe"].stdout = strings.Join(recipe, "\n")
}

// The appended distfile name has to land in bodega's route path, over a
// transport bodega serves. The negative sites are what make printed on
// freebsd-client for make.conf values a fetch sends elsewhere: with a query
// or fragment, fetch-url-list put the file name after the ? or #.
func TestMakeConfSiteReachesTheRoute(t *testing.T) {
	cases := []struct {
		site string
		want Status
	}{
		{"https://bodega.example/distfiles/@unsupported//", StatusOK},
		{"https://bodega.example/distfiles/@unsupported/", StatusOK},
		{"http://bodega.example:8080/distfiles/@unsupported/", StatusOK},
		{"https://bodega.example/bodega/distfiles/@unsupported/", StatusOK},
		{"https://bodega.example/distfiles/@unsupported/ https://b2.example/distfiles/@unsupported//", StatusOK},
		{"https://b/distfiles/@unsupported//?mirror=/", StatusWarn},
		{"https://b/distfiles/@unsupported/?/", StatusWarn},
		{"https://b/distfiles/@unsupported//#mirror/", StatusWarn},
		{"ftp://b/distfiles/@unsupported//", StatusWarn},
		{"file:///distfiles/@unsupported//", StatusWarn},
		{"/distfiles/@unsupported//", StatusWarn},
		{"https://b/distfiles/@unsupported/../../x/distfiles/@unsupported/", StatusWarn},
		{"https://mirror.example/x/https://b/distfiles/@unsupported//", StatusWarn},
		{"https://b/distfiles/@unsupported///", StatusWarn},
		{"https://b/distfiles/@other//", StatusWarn},
	}
	names, _ := makeConfSites()
	for _, name := range names {
		for _, c := range cases {
			t.Run(name+"="+c.site, func(t *testing.T) {
				runs := loadToolFixture(t, "bodega-make")
				withSite(runs, name, c.site)
				got := checkMakeConf("freebsd", replay(t, runs), onGuest)
				if c.want == StatusWarn {
					assertFinding(t, got, StatusWarn, name+"=", toolLimit)
					return
				}
				assertFinding(t, got, StatusOK, toolLimit)
			})
		}
	}
}

func TestPkgRepoURLReachesTheRoute(t *testing.T) {
	cases := map[string]Status{
		"https://b/freebsd/FreeBSD:15:aarch64/latest":             StatusOK,
		"http://b/freebsd/FreeBSD:15:aarch64/latest":              StatusOK,
		"pkg+https://b/freebsd/FreeBSD:15:aarch64/latest":         StatusOK,
		"https://b/freebsd-profile/web/FreeBSD:15:aarch64/latest": StatusOK,
		"ftp://b/freebsd/FreeBSD:15:aarch64/latest":               StatusWarn,
		"file:///freebsd/FreeBSD:15:aarch64/latest":               StatusWarn,
		"https://b/freebsd/FreeBSD:15:aarch64/latest?x=/":         StatusWarn,
		"https://b/freebsd/FreeBSD:15:aarch64/latest#x":           StatusWarn,
		"https://b/freebsd/../mirror/latest":                      StatusWarn,
		"https://m/mirror/?/freebsd/x":                            StatusWarn,
		"https://pkg.FreeBSD.org/freebsd/x":                       StatusWarn,
	}
	for u, want := range cases {
		t.Run(u, func(t *testing.T) {
			out := "\nRepositories:\n  bodega: { \n    url             : \"" + u + "\",\n    enabled         : yes,\n  }\n"
			got := checkPkgRepos("freebsd", func(string, string, ...string) ([]byte, error) { return []byte(out), nil })
			assertFinding(t, got, want, toolLimit)
		})
	}
}

// Every way either check can return on FreeBSD states the limit of asking
// the tools, and only a finding drawn from the tools' answer claims to
// certify anything.
func TestChecksStateTheirScope(t *testing.T) {
	fail := func(string, string, ...string) ([]byte, error) { return nil, errors.New("exit status 1: failed") }
	absent := func(string, string, ...string) ([]byte, error) {
		return nil, &exec.Error{Name: "tool", Err: exec.ErrNotFound}
	}
	failAt := func(label string) toolRunner {
		runs := loadToolFixture(t, "bodega-make")
		runs[label].exit = 1
		return replay(t, runs)
	}
	relative := func(stdin, name string, args ...string) ([]byte, error) { return []byte("ports\n"), nil }
	unmeasured := map[string]Finding{
		"pkg absent":           checkPkgRepos("freebsd", absent),
		"pkg failure":          checkPkgRepos("freebsd", fail),
		"make absent":          checkMakeConf("freebsd", absent, onGuest),
		"make locator failure": checkMakeConf("freebsd", fail, onGuest),
		"relative PORTSDIR":    checkMakeConf("freebsd", relative, onGuest),
		"no ports tree":        checkMakeConf("freebsd", replay(t, loadToolFixture(t, "bodega-make")), func(string) bool { return false }),
		"no probe port":        checkMakeConf("freebsd", replay(t, loadToolFixture(t, "bodega-make")), func(p string) bool { return strings.HasSuffix(p, "bsd.port.mk") }),
		"make -V failure":      checkMakeConf("freebsd", failAt("values"), onGuest),
		"make recipe failure":  checkMakeConf("freebsd", failAt("recipe"), onGuest),
		"make locator timeout": checkMakeConf("freebsd", func(string, string, ...string) ([]byte, error) {
			return nil, errors.New("make did not answer within 30s")
		}, onGuest),
	}
	for name, got := range unmeasured {
		t.Run(name, func(t *testing.T) {
			assertFinding(t, got, got.Status, toolUnmeasured)
			if strings.Contains(got.Detail, toolLimit) {
				t.Errorf("detail claims to certify a configuration it never measured: %s", got.Detail)
			}
		})
	}
	measured := map[string]Finding{
		"pkg OK":    checkPkgRepos("freebsd", replay(t, loadToolFixture(t, "bodega-pkg"))),
		"pkg WARN":  checkPkgRepos("freebsd", replay(t, loadToolFixture(t, "upstream-pkg"))),
		"make OK":   checkMakeConf("freebsd", replay(t, loadToolFixture(t, "bodega-make")), onGuest),
		"make WARN": checkMakeConf("freebsd", replay(t, loadToolFixture(t, "upstream-make")), onGuest),
	}
	for name, got := range measured {
		t.Run(name, func(t *testing.T) { assertFinding(t, got, got.Status, toolLimit) })
	}
}

// A port with a DIST_SUBDIR of its own, as make printed it for devel/gh
// under the bodega make.conf on freebsd-client.
func TestDistfilesSitesAtCarriesDistSubdir(t *testing.T) {
	site := "https://bodega.example/distfiles/@unsupported/go/devel_gh/gh-v2.83.2/"
	if !distfilesSitesAt(site, "unsupported", "go/devel_gh/gh-v2.83.2") {
		t.Errorf("%s is the route for DIST_SUBDIR=go/devel_gh/gh-v2.83.2", site)
	}
	if distfilesSitesAt(site, "unsupported", "") {
		t.Errorf("%s is not the route for an empty DIST_SUBDIR", site)
	}
	if distfilesSitesAt("https://bodega.example/distfiles/@unsupported//", "unsupported", "go/devel_gh/gh-v2.83.2") {
		t.Error("a site without the port's DIST_SUBDIR is not its route")
	}
}

// TestF28RemandsWarn replays every false OK the eleven F28 review remands
// recorded against the parser these checks replaced, named R<remand>-<finding>,
// with what pkg and make printed for the same files on freebsd-client, and
// every one warns. Findings not replayed, and why:
//
//   - R3-L was a false WARN, not a false OK: a client check including a
//     helper lost track of where its value came from. make prints bodega's
//     route for it, so asking make answers OK, which is correct.
//
// R6-V's relative .sinclude finds other.mk through make's search of the
// directory it runs in, so its fixture places other.mk in the probe port of
// a scratch PORTSDIR whose Mk links to /usr/ports/Mk.
//
// R3-J and R7-X are the two where make -V prints bodega's route and a fetch
// uses the mirror: MAKEFLAGS=-e hands the environment's value back at recipe
// time, and a .BEGIN recipe reassigns the sites before any target runs. The
// recipe read is what catches them.
func TestF28RemandsWarn(t *testing.T) {
	pkgCases := map[string]string{
		"R1-A": "FreeBSD is enabled and fetches from https://pkg.FreeBSD.org/FreeBSD:15:aarch64/quarterly",
		"R1-B": "no enabled repository points at a bodega /freebsd/ route",
		"R2-E": "FreeBSD is enabled and fetches from https://pkg.FreeBSD.org/x",
		"R2-F": "no enabled repository points at a bodega /freebsd/ route",
		"R3-I": "FreeBSD is enabled and fetches from https://pkg.FreeBSD.org/x",
		"R4-M": "FreeBSD is enabled and fetches from https://pkg.FreeBSD.org/x",
		"R4-N": "pkg -vv failed (exit status 1: pkg: invalid url:",
		"R5-Q": "FreeBSD is enabled and fetches from https://pkg.FreeBSD.org/x",
		"R6-T": "FreeBSD is enabled and fetches from https://pkg.FreeBSD.org/x",
		"R7-W": "FreeBSD is enabled and fetches from https://pkg.FreeBSD.org/x",
	}
	for name, detail := range pkgCases {
		t.Run(name, func(t *testing.T) {
			assertFinding(t, checkPkgRepos("freebsd", replay(t, loadToolFixture(t, name))), StatusWarn, detail)
		})
	}

	mirror := `"https://mirror.example/" is not every site`
	makeCases := map[string]string{
		"R1-C":                   mirror,
		"R1-D":                   `MASTER_SITE_OVERRIDE="https://mirror.example/"`,
		"R2-G":                   `"https://mirror.example/ https://b/distfiles/@abc//" is not every site`,
		"R2-H":                   "BODEGA_DISTFILES_ENV is empty",
		"R3-J":                   "at recipe time: MASTER_SITE_OVERRIDE=" + `"https://mirror.example/"`,
		"R3-K":                   mirror,
		"R4-O":                   mirror,
		"R4-O-export-literal":    mirror,
		"R4-P":                   "BODEGA_DISTFILES_ENV is empty",
		"R5-R":                   mirror,
		"R5-R-export-all":        mirror,
		"R5-S":                   mirror,
		"R6-U":                   mirror,
		"R6-V":                   mirror,
		"R7-X":                   "at recipe time: MASTER_SITE_OVERRIDE=" + `"https://mirror.example/"`,
		"R7-Y":                   mirror,
		"R8-Z-env-posix-1":       "BODEGA_DISTFILES_ENV is empty",
		"R8-Z-env-posix-empty":   "BODEGA_DISTFILES_ENV is empty",
		"R8-Z-makeflags-D-posix": "BODEGA_DISTFILES_ENV is empty",
		"R8-Z-makeflags-posix-1": "BODEGA_DISTFILES_ENV is empty",
		"R9-AA":                  "BODEGA_DISTFILES_ENV is empty",
		"R10-AB-make-conf":       "BODEGA_DISTFILES_ENV is empty",
		"R10-AB-posix":           "BODEGA_DISTFILES_ENV is empty",
		"R10-AB-site":            "-V failed (exit status 1",
		"R11-AC-empty":           "-V failed (exit status 1",
		"R11-AC-unreachable":     "BODEGA_DISTFILES_ENV is empty",
		"R11-AC-dirdeps":         "make -V PORTSDIR failed (exit status 1",
	}
	for name, detail := range makeCases {
		t.Run(name, func(t *testing.T) {
			assertFinding(t, checkMakeConf("freebsd", replay(t, loadToolFixture(t, name)), onGuest), StatusWarn, detail)
		})
	}

	// Every fixture in the directory is replayed above or is one of the two
	// host captures, so a capture nobody wired in fails here.
	entries, err := os.ReadDir(filepath.Join("testdata", "freebsd"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ".txt")
		_, p := pkgCases[name]
		_, m := makeCases[name]
		if !p && !m && !slices.Contains([]string{"bodega-pkg", "upstream-pkg", "bodega-make", "upstream-make"}, name) {
			t.Errorf("testdata/freebsd/%s is replayed by no test", e.Name())
		}
	}
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
		_, err := runToolWithin(time.Second, "", "sh", "-c", `sleep 40 & echo $! >"$1"; sleep 40; true`, "sh", pidfile)
		if elapsed := time.Since(start); elapsed > time.Second+toolWaitDelay+time.Second {
			t.Errorf("returned after %s", elapsed)
		}
		if err == nil || !strings.Contains(err.Error(), "sh did not answer within 1s") {
			t.Errorf("err = %v", err)
		}
		gone(t)
	})
	t.Run("clean exit", func(t *testing.T) {
		start := time.Now()
		out, _ := runToolWithin(time.Minute, "", "sh", "-c", `echo answer; sleep 40 & echo $! >"$1"`, "sh", pidfile)
		if elapsed := time.Since(start); elapsed > toolWaitDelay+time.Second {
			t.Errorf("returned after %s", elapsed)
		}
		if string(out) != "answer\n" {
			t.Errorf("stdout = %q", out)
		}
		gone(t)
	})
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
