package host

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/pkgrepos"
)

// toolRunner runs a host command and returns its standard output. The
// FreeBSD checks take one and never call it. Which repositories pkg enables
// and which sites a port fetches from are what pkg and make compute, and
// doctor does not start a binary found on PATH to reach a verdict: nothing
// proves that binary authentic, doctor often runs as root, and make runs the
// != assignments and .BEGIN recipes of every makefile it reads. The
// parameter stays so a test can hand a check the real runner and show that
// nothing ran.
type toolRunner func(stdin, name string, args ...string) ([]byte, error)

// toolUnchecked opens the detail of a row that names what the operator has
// to ask the tool themselves, because doctor read no verdict from it.
const toolUnchecked = "unchecked: "

// CheckPkgRepos reports that pkg's repositories are the operator's to
// confirm on a FreeBSD host with pkg installed.
func CheckPkgRepos() Finding { return checkPkgRepos(runtime.GOOS, nil) }

func checkPkgRepos(goos string, _ toolRunner) Finding {
	f := Finding{Check: "pkg-repos"}
	if goos != "freebsd" {
		f.Status = StatusNA
		f.Detail = "pkg repositories are FreeBSD-only; check not applicable on this platform"
		return f
	}
	if _, err := exec.LookPath("pkg"); err != nil {
		f.Status = StatusNA
		f.Detail = "pkg is not on PATH, so this host has no pkg repositories to check"
		return f
	}
	f.Status = StatusWarn
	f.Detail = toolUnchecked + "doctor does not run pkg, and the repositories pkg enables are what pkg itself merges from pkg.conf, every REPOS_DIR, repos_state and its environment, which doctor does not reproduce; whether every enabled repository is bodega's is not established"
	f.Remediation = "run pkg -vv as the user that installs packages and confirm every repository it prints with enabled: yes has a url under bodega's /freebsd/ or /freebsd-profile/ route; " +
		"bodega doctor --write-pkg-repo --url <bodega> writes " + pkgrepos.ClientConfPath + " with the bodega repository and the overrides that disable upstream"
	return f
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
	makeConfPath = "/etc/make.conf"

	// probePort is the port the remediation evaluates the sites in. Every
	// ports tree carries it, and it sets no DIST_SUBDIR of its own.
	probePort = "ports-mgmt/pkg"
)

// CheckMakeConf reports that the sites ports fetch distfiles from are the
// operator's to confirm on a FreeBSD host with a ports tree or a make.conf.
func CheckMakeConf() Finding { return checkMakeConf(runtime.GOOS, nil, exists) }

func checkMakeConf(goos string, _ toolRunner, present func(string) bool) Finding {
	f := Finding{Check: "make-conf"}
	if goos != "freebsd" {
		f.Status = StatusNA
		f.Detail = "make.conf is read by FreeBSD's ports framework; check not applicable on this platform"
		return f
	}
	if _, err := exec.LookPath("make"); err != nil {
		f.Status = StatusNA
		f.Detail = "make is not on PATH, so nothing on this host fetches distfiles through the ports framework"
		return f
	}
	// bsd.port.mk defaults PORTSDIR to /usr/ports; make.conf, the
	// environment and MAKEFLAGS are what can move it. Only with none of the
	// three in play does a missing default tree mean no tree.
	portsdir := os.Getenv("PORTSDIR")
	if portsdir == "" {
		portsdir = "/usr/ports"
	}
	marker := filepath.Join(portsdir, "Mk", "bsd.port.mk")
	if !present(marker) && !present(makeConfPath) && !strings.Contains(os.Getenv("MAKEFLAGS"), "PORTSDIR") {
		f.Status = StatusNA
		f.Detail = "no ports tree: " + marker + " does not exist, and neither " + makeConfPath + " nor MAKEFLAGS names another"
		return f
	}
	names, route := makeConfSites()
	f.Status = StatusWarn
	f.Detail = toolUnchecked + "doctor does not run make, and the sites a port fetches from are what make computes from " + makeConfPath +
		", the files it includes, the environment and MAKEFLAGS, which doctor does not reproduce; whether every fetch goes to bodega's distfiles route is not established"
	f.Remediation = "end " + makeConfPath + " with the FreeBSD ports lines under Client configuration in docs/usage.md: " +
		strings.Join(names, " and ") + " set to <bodega>" + route + ", then .include of " + clientconf.DistfilesCheckPath +
		"; confirm as the user that builds ports with make -C " + filepath.Join(portsdir, probePort) + " -V " + strings.Join(names, " -V ")
	return f
}
