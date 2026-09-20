package host

import (
	"os"
	"path/filepath"
	"strings"
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
func CheckAptSources() Finding {
	f := Finding{Check: "apt-sources"}

	paths := []string{"/etc/apt/sources.list"}
	if entries, err := os.ReadDir("/etc/apt/sources.list.d"); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			n := e.Name()
			if !strings.HasSuffix(n, ".list") && !strings.HasSuffix(n, ".sources") {
				continue
			}
			paths = append(paths, filepath.Join("/etc/apt/sources.list.d", n))
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
	f := Finding{Check: "pip-config"}
	home, _ := os.UserHomeDir()
	paths := []string{
		"/etc/pip.conf",
	}
	if home != "" {
		paths = append(paths,
			filepath.Join(home, ".pip", "pip.conf"),
			filepath.Join(home, ".config", "pip", "pip.conf"),
			filepath.Join(home, "Library", "Application Support", "pip", "pip.conf"),
		)
	}

	hit := firstHit(paths, publicUpstreams["pip"])
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
	f := Finding{Check: "npm-config"}
	home, _ := os.UserHomeDir()
	paths := []string{"/etc/npmrc"}
	if home != "" {
		paths = append(paths, filepath.Join(home, ".npmrc"))
	}

	hit := firstHit(paths, publicUpstreams["npm"])
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

// CheckGoproxyEnv reports whether GOPROXY is set to a value that includes a
// direct or off-bodega upstream. The Go toolchain's default GOPROXY of
// "https://proxy.golang.org,direct" bypasses bodega entirely.
func CheckGoproxyEnv() Finding {
	f := Finding{Check: "goproxy-env"}

	val := os.Getenv("GOPROXY")
	switch {
	case val == "":
		f.Status = StatusWarn
		f.Detail = "GOPROXY unset; Go falls back to proxy.golang.org,direct which bypasses bodega"
		f.Remediation = "export GOPROXY=http://<bodega>/gomod"
	case strings.Contains(val, "proxy.golang.org"):
		f.Status = StatusWarn
		f.Detail = "GOPROXY=" + val + " references proxy.golang.org directly"
		f.Remediation = "remove proxy.golang.org from GOPROXY; keep only the bodega endpoint and ,off (not ,direct)"
	case strings.Contains(val, ",direct"):
		f.Status = StatusWarn
		f.Detail = "GOPROXY=" + val + " ends in ,direct; Go will fall through to upstream VCS on cache miss"
		f.Remediation = "replace ,direct with ,off so cache misses fail loudly instead of bypassing bodega"
	default:
		f.Status = StatusOK
		f.Detail = "GOPROXY=" + val + " (no fall-through to public upstreams)"
	}
	return f
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
