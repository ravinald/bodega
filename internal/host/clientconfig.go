package host

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/ravinald/bodega/internal/clientconf"
)

// publicUpstreams maps each package-manager check to the substrings that, if
// present in its config file, indicate the host is configured to fetch from
// the public registry rather than a bodega instance. These are textual
// markers — not URL parsing — so the check is robust against TOML/YAML/INI
// quoting differences.
var publicUpstreams = map[string][]string{
	"apt":   {"archive.ubuntu.com", "security.ubuntu.com", "deb.debian.org", "packages.debian.org", "ports.ubuntu.com"},
	"pip":   {"pypi.org", "files.pythonhosted.org"},
	"cargo": {"crates.io", "static.crates.io"},
	"npm":   {"registry.npmjs.org", "registry.npmjs.com"},
	"gomod": {"proxy.golang.org", "sum.golang.org"},
}

// CheckAptSources scans /etc/apt/sources.list and /etc/apt/sources.list.d
// for references to public Debian/Ubuntu mirrors. A locked-down host should
// have these rewritten to point at a bodega apt endpoint.
func CheckAptSources() Finding { return checkAptSources("", runtime.GOOS) }

// root prefixes every path the check reads and goos stands in for
// runtime.GOOS, so a test can drive both systems against a fixture tree.
func checkAptSources(root, goos string) Finding {
	f := Finding{Check: "apt-sources"}
	if goos != "linux" {
		f.Status = StatusNA
		f.Detail = "apt is Linux-only; check not applicable on this platform"
		return f
	}

	dir := filepath.Join(root, "/etc/apt/sources.list.d")
	paths := []string{filepath.Join(root, "/etc/apt/sources.list")}
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			n := e.Name()
			if !strings.HasSuffix(n, ".list") && !strings.HasSuffix(n, ".sources") {
				continue
			}
			paths = append(paths, filepath.Join(dir, n))
		}
	}

	hit := firstHit(paths, publicUpstreams["apt"])
	if hit.path == "" {
		f.Status = StatusOK
		f.Detail = "no public apt mirrors referenced in /etc/apt/sources.list[.d]"
		return f
	}
	f.Status = StatusWarn
	f.Detail = "apt configured to fetch from " + hit.marker + " (in " + hit.path + "); bypasses bodega's apt proxy"
	f.Remediation = "rewrite sources to point at the bodega apt endpoint"
	return f
}

// CheckPipConfig scans pip's config files for direct PyPI references.
func CheckPipConfig() Finding {
	home, _ := os.UserHomeDir()
	return checkPipConfig("", runtime.GOOS, home)
}

// pipPaths lists the files pip reads, system-wide first. On FreeBSD pip's
// global search is /etc/xdg/pip/pip.conf, /etc/pip.conf and
// sys.prefix/pip.conf (measured with `pip config debug`, py312-pip 23.3.2 on
// 15.1-RELEASE). /usr/local/etc/pip.conf is read by nothing, and is scanned
// anyway because it is where the ports convention puts a file, so an operator
// who wrote one there is shown it rather than told the host is clean.
func pipPaths(goos, home string) []string {
	paths := []string{"/etc/pip.conf"}
	if goos == "freebsd" {
		paths = append(paths, "/etc/xdg/pip/pip.conf", "/usr/local/pip.conf", "/usr/local/etc/pip.conf")
	}
	if home != "" {
		paths = append(paths,
			filepath.Join(home, ".pip", "pip.conf"),
			filepath.Join(home, ".config", "pip", "pip.conf"),
			filepath.Join(home, "Library", "Application Support", "pip", "pip.conf"),
		)
	}
	return paths
}

func checkPipConfig(root, goos, home string) Finding {
	f := Finding{Check: "pip-config"}
	hit := firstHit(rooted(root, pipPaths(goos, home)), publicUpstreams["pip"])
	if hit.path == "" {
		f.Status = StatusOK
		f.Detail = "no pip config references public PyPI"
		return f
	}
	f.Status = StatusWarn
	f.Detail = "pip configured to fetch from " + hit.marker + " (in " + hit.path + "); bypasses bodega's pypi proxy"
	f.Remediation = "set index-url in " + hit.path + " to the bodega /pypi/simple endpoint"
	return f
}

// CheckCargoConfig scans Cargo's config files for crates.io references.
func CheckCargoConfig() Finding {
	f := Finding{Check: "cargo-config"}
	home, _ := os.UserHomeDir()
	var paths []string
	if home != "" {
		paths = []string{
			filepath.Join(home, ".cargo", "config.toml"),
			filepath.Join(home, ".cargo", "config"),
		}
	}

	hit := firstHit(paths, publicUpstreams["cargo"])
	if hit.path == "" {
		f.Status = StatusOK
		f.Detail = "no cargo config references crates.io directly"
		return f
	}
	f.Status = StatusWarn
	f.Detail = "cargo configured to fetch from " + hit.marker + " (in " + hit.path + "); bypasses bodega's cargo proxy"
	f.Remediation = "replace [source.crates-io] in " + hit.path + " with a [source] block pointing at the bodega /cargo endpoint"
	return f
}

// CheckNpmConfig scans .npmrc files for direct registry.npmjs.org references.
func CheckNpmConfig() Finding {
	home, _ := os.UserHomeDir()
	return checkNpmConfig("", runtime.GOOS, home)
}

// npmPaths lists the npmrc files npm reads. The global one is
// $PREFIX/etc/npmrc, and the FreeBSD package's prefix is /usr/local.
func npmPaths(goos, home string) []string {
	paths := []string{"/etc/npmrc"}
	if goos == "freebsd" {
		paths = append(paths, "/usr/local/etc/npmrc")
	}
	if home != "" {
		paths = append(paths, filepath.Join(home, ".npmrc"))
	}
	return paths
}

func checkNpmConfig(root, goos, home string) Finding {
	f := Finding{Check: "npm-config"}
	hit := firstHit(rooted(root, npmPaths(goos, home)), publicUpstreams["npm"])
	if hit.path == "" {
		f.Status = StatusOK
		f.Detail = "no .npmrc references public registry.npmjs.org"
		return f
	}
	f.Status = StatusWarn
	f.Detail = "npm configured to fetch from " + hit.marker + " (in " + hit.path + "); bypasses bodega's npm proxy"
	f.Remediation = "set registry= in " + hit.path + " to the bodega /npm endpoint"
	return f
}

// rooted prefixes each path with root, and returns paths unchanged when root
// is empty.
func rooted(root string, paths []string) []string {
	if root == "" {
		return paths
	}
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = filepath.Join(root, p)
	}
	return out
}

// CheckGoproxyEnv reports whether the GOPROXY the go command will use
// includes a direct or off-bodega upstream. The Go toolchain's default GOPROXY
// of "https://proxy.golang.org,direct" bypasses bodega entirely.
//
// The value is resolved the way the go command resolves it, not read from the
// environment alone: a non-empty GOPROXY in the environment wins, then the go
// env file (`go env -w`), which is the form bodega's clientconf hands out and
// which no shell exports.
func CheckGoproxyEnv() Finding {
	return checkGoproxy(os.Getenv, os.UserConfigDir)
}

func checkGoproxy(getenv func(string) string, configDir func() (string, error)) Finding {
	f := Finding{Check: "goproxy-env"}

	val, source := getenv("GOPROXY"), "the environment"
	if val == "" {
		file, err := goEnvFile(getenv, configDir)
		if err != nil {
			f.Status = StatusSkip
			f.Detail = "GOPROXY unset in the environment and the go env file could not be located: " + err.Error()
			f.Remediation = "set GOENV to the go env file's path, or HOME, and run doctor again"
			return f
		}
		if file != "" {
			fileVal, found, err := readGoEnvFile(file, "GOPROXY")
			if err != nil {
				f.Status = StatusSkip
				f.Detail = "GOPROXY unset in the environment and " + file + " could not be read: " + err.Error()
				f.Remediation = "run doctor as the user whose go env file that is, or check its permissions"
				return f
			}
			if found {
				val, source = fileVal, file
			}
		}
	}

	reached := reachableProxies(val)
	public, direct := "", false
	for _, entry := range reached {
		switch {
		case entry == "direct":
			direct = true
		case public == "" && strings.Contains(entry, "proxy.golang.org"):
			public = entry
		}
	}

	switch {
	case val == "":
		f.Status = StatusWarn
		f.Detail = "GOPROXY unset in the environment and the go env file; Go falls back to proxy.golang.org,direct which bypasses bodega"
		f.Remediation = "go env -w GOPROXY=" + clientconf.GoProxy("http://<bodega>")
	case len(reached) == 0:
		f.Status = StatusWarn
		f.Detail = "GOPROXY=" + strconv.Quote(val) + " (from " + source + ") lists no proxy; the go command refuses every module download"
		f.Remediation = "go env -w GOPROXY=" + clientconf.GoProxy("http://<bodega>")
	case public != "":
		f.Status = StatusWarn
		f.Detail = "GOPROXY=" + val + " (from " + source + ") reaches " + public + " directly"
		f.Remediation = "remove proxy.golang.org from GOPROXY; keep only the bodega endpoint and ,off (not ,direct)"
	case direct:
		f.Status = StatusWarn
		f.Detail = "GOPROXY=" + val + " (from " + source + ") reaches direct; Go fetches from upstream VCS instead of bodega"
		f.Remediation = "replace direct with off so cache misses fail loudly instead of bypassing bodega"
	default:
		f.Status = StatusOK
		f.Detail = "GOPROXY=" + val + " (from " + source + "; no fall-through to public upstreams)"
	}
	return f
}

// reachableProxies returns the GOPROXY entries the go command can reach, in
// order, walking the list as cmd/go/internal/modfetch does: entries separated
// by ',' or '|', each trimmed, empties skipped, and the walk ending at "off" or
// "direct" inclusive, since nothing after either is ever consulted. The
// separator only decides which errors fall through, and a fall-through to
// direct or proxy.golang.org bypasses bodega either way.
func reachableProxies(val string) []string {
	var reached []string
	for _, entry := range strings.FieldsFunc(val, func(r rune) bool { return r == ',' || r == '|' }) {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		reached = append(reached, entry)
		if entry == "off" || entry == "direct" {
			break
		}
	}
	return reached
}

// goEnvFile is the file `go env -w` writes: $GOENV, or go/env under the user
// config directory. "" means GOENV=off, where the go command reads no file.
func goEnvFile(getenv func(string) string, configDir func() (string, error)) (string, error) {
	switch file := getenv("GOENV"); file {
	case "off":
		return "", nil
	case "":
	default:
		return file, nil
	}
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	if dir == "" {
		return "", errors.New("no user config directory")
	}
	return filepath.Join(dir, "go", "env"), nil
}

// readGoEnvFile returns key's value from a go env file, parsed as the go
// command parses it: KEY=VALUE lines, untrimmed, the last assignment winning,
// anything not opening with an uppercase letter skipped. A file that does not
// exist is no value rather than an error, because that is what the go command
// makes of it.
func readGoEnvFile(path, key string) (string, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	var val string
	var found bool
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok || line[0] < 'A' || line[0] > 'Z' || k != key {
			continue
		}
		val, found = v, true
	}
	return val, found, nil
}

// scanHit records the first config file that contains a public-upstream
// marker and which marker matched.
type scanHit struct {
	path   string
	marker string
}

// firstHit scans each path in order and returns the first marker that
// appears in its contents. Missing or unreadable files are skipped silently
// — the check is best-effort.
func firstHit(paths, markers []string) scanHit {
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		text := string(data)
		for _, m := range markers {
			if strings.Contains(text, m) {
				return scanHit{path: p, marker: m}
			}
		}
	}
	return scanHit{}
}
