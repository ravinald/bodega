package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/pkgrepos"
)

// toolRunner runs a command under doctor's own environment, with stdin as
// its standard input, and returns what it wrote to standard output. The
// FreeBSD checks ask pkg and make rather than reading their configuration,
// because every reimplementation of either tool's parsing disagreed with the
// tool somewhere, and each disagreement was a false OK. Tests replay
// captured output through the same type.
type toolRunner func(stdin, name string, args ...string) ([]byte, error)

// toolTimeout bounds one pkg or make run. Both answer in well under a second
// on a stock host; a makefile that blocks must not hang doctor.
const toolTimeout = 30 * time.Second

func runTool(stdin, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), toolTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	switch {
	case err == nil:
		return out, nil
	case ctx.Err() != nil:
		return out, fmt.Errorf("%s did not answer within %s", name, toolTimeout)
	case stderr.Len() > 0:
		return out, fmt.Errorf("%w: %s", err, oneLine(stderr.String()))
	}
	return out, err
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(strings.TrimSpace(s), "\n", "; ")), " ")
}

// toolLimit is what asking the tools cannot certify: pkg and make answer for
// the environment doctor itself runs in, and nothing else.
const toolLimit = "this certifies the configuration doctor ran under; a fetch started with a different environment or MAKEFLAGS is not covered"

// CheckPkgRepos reports whether every repository pkg will use is bodega's.
func CheckPkgRepos() Finding { return checkPkgRepos(runtime.GOOS, runTool) }

func checkPkgRepos(goos string, run toolRunner) Finding {
	f := Finding{Check: "pkg-repos"}
	if goos != "freebsd" {
		f.Status = StatusNA
		f.Detail = "pkg repositories are FreeBSD-only; check not applicable on this platform"
		return f
	}
	f.Remediation = "bodega doctor --write-pkg-repo --url <bodega> writes " + pkgrepos.ClientConfPath + " with the bodega repository and the overrides that disable upstream; confirm with pkg -vv"
	out, err := run("", "pkg", "-vv")
	switch {
	case errors.Is(err, exec.ErrNotFound):
		f.Status = StatusNA
		f.Detail = "pkg is not on PATH, so this host has no pkg repositories to check"
		f.Remediation = ""
		return f
	case err != nil:
		f.Status = StatusWarn
		f.Detail = "pkg -vv failed (" + err.Error() + "), so doctor cannot establish which repositories pkg uses; every pkg command on this host is likely failing the same way"
		f.Remediation = "fix what pkg reports, then run doctor again; " + f.Remediation
		return f
	}

	var problems, bodega []string
	for _, r := range pkgVVRepos(string(out)) {
		switch {
		case r.enabled == "no":
		case r.enabled != "yes":
			problems = append(problems, fmt.Sprintf("pkg -vv prints enabled: %s for %s, which doctor cannot read as on or off", r.enabled, r.name))
		case pkgBodegaURL(r.url):
			bodega = append(bodega, r.name)
		default:
			problems = append(problems, fmt.Sprintf("%s is enabled and fetches from %s", r.name, r.url))
		}
	}
	if len(bodega) == 0 {
		problems = append(problems, "no enabled repository points at a bodega /freebsd/ route")
	}
	if len(problems) > 0 {
		f.Status = StatusWarn
		f.Detail = "pkg -vv: " + strings.Join(problems, "; ") + "; " + toolLimit
		return f
	}
	f.Status = StatusOK
	f.Remediation = ""
	f.Detail = "pkg -vv enables only bodega repositories (" + strings.Join(bodega, ", ") + "); " + toolLimit
	return f
}

type pkgVVRepo struct{ name, url, enabled string }

// pkgVVRepos reads the Repositories section pkg -vv prints after its own
// configuration parsing: a name line ending in "{" at two spaces of indent,
// then one "key : value," line per field.
func pkgVVRepos(out string) []pkgVVRepo {
	_, section, ok := strings.Cut(out, "\nRepositories:\n")
	if !ok {
		return nil
	}
	var repos []pkgVVRepo
	var cur *pkgVVRepo
	for _, line := range strings.Split(section, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") && strings.HasSuffix(t, "{"):
			repos = append(repos, pkgVVRepo{name: strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(t, "{"), ": "))})
			cur = &repos[len(repos)-1]
		case strings.TrimRight(line, " ") == "  }":
			cur = nil
		case cur != nil:
			key, val, ok := strings.Cut(t, ":")
			if !ok {
				continue
			}
			val = strings.TrimSuffix(strings.TrimSpace(val), ",")
			if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
				val = val[1 : len(val)-1]
			}
			switch strings.TrimSpace(key) {
			case "url":
				cur.url = val
			case "enabled":
				cur.enabled = val
			}
		}
	}
	return repos
}

// pkgBodegaURL reports whether a repository URL is one of bodega's pkg
// routes: /freebsd/<abi>/<repo> as published, or
// /freebsd-profile/<profile>/<abi>/<repo> filtered for a profile. The host
// is not compared, because doctor runs without knowing which URL clients
// reach bodega at, but FreeBSD's own is never bodega.
func pkgBodegaURL(raw string) bool {
	u, err := url.Parse(strings.TrimPrefix(raw, "pkg+"))
	if err != nil || u.Host == "" || strings.EqualFold(u.Hostname(), "pkg.FreeBSD.org") {
		return false
	}
	return strings.HasPrefix(u.Path, "/freebsd/") || strings.HasPrefix(u.Path, "/freebsd-profile/")
}

// makeConfSites are the variables clientconf.MakeConf assigns and the route
// each must end with, read out of the rendered file so the check and the
// renderer cannot disagree about either.
func makeConfSites() (names []string, route string) {
	for _, l := range strings.Split(clientconf.MakeConf("").Content, "\n") {
		name, val, ok := strings.Cut(l, "?=")
		if !ok {
			continue
		}
		names = append(names, strings.TrimSpace(name))
		route = strings.TrimSpace(val)
	}
	return names, route
}

const (
	distfilesEnvVar = "BODEGA_DISTFILES_ENV"
	distSubdirVar   = "DIST_SUBDIR"

	// probePort is the port make evaluates the sites in. Every ports tree
	// carries it, and it sets no DIST_SUBDIR of its own, so a DIST_SUBDIR
	// make reports there came from make.conf, the environment or MAKEFLAGS.
	probePort = "ports-mgmt/pkg"

	// recipeTarget and recipeMark name the target doctor adds to the port
	// and the prefix on each line it prints, which is how its output is
	// told apart from the banners make -j prints around a job.
	recipeTarget = "_bodega_doctor_sites"
	recipeMark   = "bodega-doctor:"
)

// CheckMakeConf reports whether ports on this FreeBSD host fetch distfiles
// through bodega, as make computes the fetch sites for a port.
func CheckMakeConf() Finding { return checkMakeConf(runtime.GOOS, runTool, exists) }

func checkMakeConf(goos string, run toolRunner, present func(string) bool) Finding {
	f := Finding{Check: "make-conf"}
	if goos != "freebsd" {
		f.Status = StatusNA
		f.Detail = "make.conf is read by FreeBSD's ports framework; check not applicable on this platform"
		return f
	}
	names, route := makeConfSites()
	vars := append(append([]string(nil), names...), distfilesEnvVar, distSubdirVar)
	f.Remediation = "end /etc/make.conf with the FreeBSD ports lines under Client configuration in docs/usage.md: " +
		strings.Join(names, " and ") + " set to <bodega>" + route + ", then .include of " + clientconf.DistfilesCheckPath +
		"; confirm with make -C <port> -V " + strings.Join(names, " -V ")

	// PORTSDIR is unset outside bsd.port.mk unless make.conf, the
	// environment or MAKEFLAGS set it, and bsd.port.mk defaults it to
	// /usr/ports.
	out, err := run("", "make", "-C", "/", "-f", "/dev/null", "-V", "${PORTSDIR}")
	switch {
	case errors.Is(err, exec.ErrNotFound):
		f.Status = StatusNA
		f.Detail = "make is not on PATH, so nothing on this host fetches distfiles through the ports framework"
		f.Remediation = ""
		return f
	case err != nil:
		f.Status = StatusWarn
		f.Detail = "make -V PORTSDIR failed (" + err.Error() + "), so doctor cannot establish which ports tree make reads"
		return f
	}
	portsdir := strings.TrimSpace(string(out))
	if portsdir == "" {
		portsdir = "/usr/ports"
	}
	switch {
	case !path.IsAbs(portsdir):
		f.Status = StatusWarn
		f.Detail = "make reports PORTSDIR=" + portsdir + ", which is relative, so doctor cannot establish which ports tree a fetch reads"
		return f
	case !present(filepath.Join(portsdir, "Mk", "bsd.port.mk")):
		f.Status = StatusNA
		f.Detail = "no ports tree: " + filepath.Join(portsdir, "Mk", "bsd.port.mk") + " does not exist"
		f.Remediation = ""
		return f
	}
	port := filepath.Join(portsdir, probePort)
	if !present(filepath.Join(port, "Makefile")) {
		f.Status = StatusWarn
		f.Detail = "the ports tree at " + portsdir + " has no " + probePort + ", the port doctor asks make to evaluate the fetch sites in"
		f.Remediation = "restore " + probePort + " in " + portsdir + " and run doctor again"
		return f
	}

	args := []string{"-C", port}
	for _, v := range vars {
		args = append(args, "-V", "${"+v+"}")
	}
	out, err = run("", "make", args...)
	if err != nil {
		f.Status = StatusWarn
		f.Detail = "make -C " + port + " -V failed (" + err.Error() + "), so doctor cannot establish what ports fetch from"
		return f
	}
	parsed := makeVLines(string(out), vars)

	// A fetch expands the sites inside a recipe, where MAKEFLAGS=-e hands
	// the environment's value back and a .BEGIN recipe may have reassigned
	// them; make -V sees neither. So the same variables are read a second
	// time from a recipe of a target doctor adds after the port's Makefile.
	var mk strings.Builder
	mk.WriteString(recipeTarget + ": .PHONY\n")
	for _, v := range vars {
		fmt.Fprintf(&mk, "\t@echo %s%s=${%s:Q}\n", recipeMark, v, v)
	}
	out, err = run(mk.String(), "make", "-C", port, "-f", "Makefile", "-f", "-", recipeTarget)
	if err != nil {
		f.Status = StatusWarn
		f.Detail = "make -C " + port + " " + recipeTarget + " failed (" + err.Error() + "), so doctor cannot establish what a fetch's recipes see"
		return f
	}
	recipe := makeRecipeLines(string(out), vars)

	views := []makeView{{"make -V", parsed}, {"at recipe time", recipe}}
	if parsed != nil && maps.Equal(parsed, recipe) {
		views = []makeView{{"make", parsed}}
	}
	var problems []string
	for _, view := range views {
		if view.vals == nil {
			problems = append(problems, view.label+": make printed something other than one value per variable asked for")
			continue
		}
		problems = append(problems, siteProblems(view.label, names, view.vals)...)
	}
	if len(problems) > 0 {
		f.Status = StatusWarn
		f.Detail = "in " + port + ": " + strings.Join(problems, "; ") + "; " + toolLimit
		return f
	}
	f.Status = StatusOK
	f.Remediation = ""
	f.Detail = "in " + port + ", make sends " + strings.Join(names, " and ") + " to bodega's distfiles route for environment " +
		parsed[distfilesEnvVar] + ", both from make -V and at recipe time; " + toolLimit
	return f
}

// siteProblems judges one set of values make computed. The expected route
// is the rendered one with BODEGA_DISTFILES_ENV and DIST_SUBDIR expanded to
// the values make gave them. An empty BODEGA_DISTFILES_ENV is reported
// alongside the sites, not instead of them, so the operator sees where a
// fetch goes.
func siteProblems(label string, names []string, vals map[string]string) []string {
	env := vals[distfilesEnvVar]
	var problems []string
	route := "/distfiles/@" + env + "/"
	if env == "" {
		problems = append(problems, label+": "+distfilesEnvVar+" is empty, so no client check set it")
		route = "/distfiles/@${" + distfilesEnvVar + "}/"
	}
	for _, n := range names {
		if !distfilesSitesAt(vals[n], env, vals[distSubdirVar]) {
			problems = append(problems, fmt.Sprintf("%s: %s=%q is not every site at bodega's %s route", label, n, vals[n], route))
		}
	}
	return problems
}

// distfilesSitesAt reports whether every site in a value make computed is a
// URL whose path ends at bodega's distfiles route for env and subdir. One
// site that is not is a fallback do-fetch.sh will try. With DIST_SUBDIR
// empty the route's two slashes meet, and bsd.port.mk strips one of them
// from MASTER_SITE_BACKUP, so both forms are the route.
func distfilesSitesAt(v, env, subdir string) bool {
	sites := strings.Fields(v)
	if len(sites) == 0 {
		return false
	}
	want := "/distfiles/@" + env + "/"
	if subdir != "" {
		want += subdir + "/"
	}
	for _, s := range sites {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return false
		}
		if !strings.HasSuffix(u.Path, want) && (subdir != "" || !strings.HasSuffix(u.Path, want+"/")) {
			return false
		}
	}
	return true
}

// makeVLines maps make -V output, one line per variable in the order asked,
// or returns nil when the line count disagrees.
func makeVLines(out string, vars []string) map[string]string {
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != len(vars) {
		return nil
	}
	m := map[string]string{}
	for i, v := range vars {
		m[v] = lines[i]
	}
	return m
}

// makeRecipeLines maps the marked lines the added target prints, or returns
// nil when any variable is missing. Under -n make prints the commands
// instead of running them, and no line then carries the mark.
func makeRecipeLines(out string, vars []string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		rest, ok := strings.CutPrefix(line, recipeMark)
		if !ok {
			continue
		}
		if name, val, ok := strings.Cut(rest, "="); ok {
			m[name] = val
		}
	}
	for _, v := range vars {
		if _, ok := m[v]; !ok {
			return nil
		}
	}
	return m
}

// makeView is one reading of the variables: from make -V, or from a recipe.
type makeView struct {
	label string
	vals  map[string]string
}
