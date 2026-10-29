package host

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/ravinald/bodega/internal/clientconf"
)

// publicUpstreams maps each package-manager check to the substrings that, if
// present in its config file, indicate the host is configured to fetch from
// the public registry rather than a bodega instance. These are textual
// markers — not URL parsing — so the check is robust against TOML/YAML/INI
// quoting differences. apt is the exception: its sources are parsed, and each
// marker is matched against a URI's host and that host's subdomains.
var publicUpstreams = map[string][]string{
	"apt":   {"archive.ubuntu.com", "security.ubuntu.com", "deb.debian.org", "security.debian.org", "packages.debian.org", "ports.ubuntu.com"},
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
	if _, err := os.Stat(filepath.Join(root, "/etc/apt")); errors.Is(err, fs.ErrNotExist) {
		f.Status = StatusNA
		f.Detail = "/etc/apt is absent; apt is not installed on this host"
		return f
	} else if err != nil {
		f.Status = StatusSkip
		f.Detail = "could not inspect /etc/apt: " + err.Error()
		f.Remediation = "run doctor as a user that can stat /etc/apt, or repair the path the error names"
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

	var unread *aptMirrorError
	for _, p := range paths {
		uris, err := aptSourceURIs(p)
		if err != nil {
			continue
		}
		for _, uri := range uris {
			mirror, ok := aptMirrorFile(uri)
			if !ok {
				if m := publicHost(uri, publicUpstreams["apt"]); m != "" {
					return aptWarn(f, m, p)
				}
				continue
			}
			mpath := filepath.Join(root, mirror)
			mirrors, err := aptMirrorURIs(mpath)
			if err != nil {
				if unread == nil {
					unread = &aptMirrorError{path: mpath, source: p, err: err}
				}
				continue
			}
			for _, m := range mirrors {
				if host := publicHost(m, publicUpstreams["apt"]); host != "" {
					return aptWarn(f, host, mpath+", the mirror list "+p+" names")
				}
			}
		}
	}
	// A public host found anywhere is a measured bypass, so it outranks a
	// mirror list that could not be read.
	if unread != nil {
		f.Status = StatusSkip
		f.Detail = "could not read apt mirror list " + unread.path + " (named by mirror+file in " + unread.source + "): " + unread.err.Error()
		f.Remediation = "run doctor as a user that can read " + unread.path + ", or correct the mirror+file URI in " + unread.source
		return f
	}
	f.Status = StatusOK
	f.Detail = "no public apt mirrors referenced in /etc/apt/sources.list[.d]"
	return f
}

func aptWarn(f Finding, marker, where string) Finding {
	f.Status = StatusWarn
	f.Detail = "apt configured to fetch from " + marker + " (in " + where + "); bypasses bodega's apt proxy"
	f.Remediation = "rewrite sources to point at the bodega apt endpoint"
	return f
}

type aptMirrorError struct {
	path, source string
	err          error
}

// aptSourceURIs returns the URIs apt would fetch from in one sources file:
// deb822 stanzas for a .sources file, one-line entries for anything else.
// Comments and stanzas with Enabled: no are dropped, as apt drops them.
func aptSourceURIs(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(path, ".sources") {
		return deb822URIs(string(data)), nil
	}
	return oneLineURIs(string(data)), nil
}

func deb822URIs(text string) []string {
	var out, uris []string
	enabled := true
	field := ""
	flush := func() {
		if enabled {
			out = append(out, uris...)
		}
		uris, enabled, field = nil, true, ""
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.TrimSpace(line) == "":
			flush()
			continue
		case strings.HasPrefix(line, "#"):
			continue
		case line[0] == ' ' || line[0] == '\t':
			if field == "uris" {
				uris = append(uris, strings.Fields(line)...)
			}
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			field = ""
			continue
		}
		field = strings.ToLower(strings.TrimSpace(name))
		switch field {
		case "uris":
			uris = append(uris, strings.Fields(value)...)
		case "enabled":
			enabled = !aptFalse(strings.TrimSpace(value))
		}
	}
	flush()
	return out
}

// aptFalse mirrors apt's StringToBool for the spellings that mean no.
func aptFalse(v string) bool {
	switch strings.ToLower(v) {
	case "no", "false", "without", "off", "disable":
		return true
	}
	return false
}

// oneLineURIs reads "deb [options] uri suite [component...]" entries. apt
// cuts each line at its first '#'.
func oneLineURIs(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		if len(fields) < 2 || (fields[0] != "deb" && fields[0] != "deb-src") {
			continue
		}
		rest := fields[1:]
		if strings.HasPrefix(rest[0], "[") {
			for len(rest) > 0 && !strings.HasSuffix(rest[0], "]") {
				rest = rest[1:]
			}
			if len(rest) > 0 {
				rest = rest[1:]
			}
		}
		if len(rest) > 0 {
			out = append(out, rest[0])
		}
	}
	return out
}

// aptMirrorFile returns the path a mirror+file URI names, which apt reads
// for the list of URIs it actually fetches from.
func aptMirrorFile(uri string) (string, bool) {
	u, err := url.Parse(uri)
	if err != nil || !strings.EqualFold(u.Scheme, "mirror+file") {
		return "", false
	}
	return u.Path, true
}

// aptMirrorURIs reads a mirror list: one URI per line, optionally followed by
// tab-separated metadata, with '#' lines as comments.
func aptMirrorURIs(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.Fields(line)[0])
	}
	return out, nil
}

// publicHost returns the marker that uri's host is, or is a subdomain of.
func publicHost(uri string, markers []string) string {
	u, err := url.Parse(uri)
	if err != nil {
		return ""
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return ""
	}
	for _, m := range markers {
		if host == m || strings.HasSuffix(host, "."+m) {
			return m
		}
	}
	return ""
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

// rubyTools is what the rubygems check reads from the host, so a test can
// stand in for gem and for the environment Bundler resolves its config from.
type rubyTools struct {
	lookPath   func(string) (string, error)
	gemSources func(gem string) (string, error)
	getenv     func(string) string
	home       string
}

// CheckRubygems reports whether gem or Bundler still fetch from
// rubygems.org. ok is false on a host with neither installed, where the row
// would describe a client nobody runs.
func CheckRubygems() (f Finding, ok bool) {
	home, _ := os.UserHomeDir()
	return checkRubygems(rubyTools{lookPath: exec.LookPath, gemSources: runGemSources, getenv: os.Getenv, home: home})
}

// runGemSources asks gem itself, because the list it uses merges the system
// gemrc, ~/.gemrc (or its XDG location) and every file $GEMRC names, and
// falls back to rubygems.org when none of them sets :sources:.
func runGemSources(gem string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, gem, "sources", "--list").Output()
	if err != nil {
		return "", fmt.Errorf("%s sources --list: %w", gem, err)
	}
	return string(out), nil
}

func checkRubygems(t rubyTools) (Finding, bool) {
	gem, gemErr := t.lookPath("gem")
	_, bundleErr := t.lookPath("bundle")
	if gemErr != nil && bundleErr != nil {
		return Finding{}, false
	}
	f := Finding{Check: "rubygems"}
	var found, unread, clean []string
	if gemErr == nil {
		switch out, err := t.gemSources(gem); {
		case err != nil:
			unread = append(unread, "gem's sources could not be listed: "+err.Error())
		case rubygemsOrgSource(out) != "":
			found = append(found, "gem sources lists "+rubygemsOrgSource(out))
		default:
			clean = append(clean, "gem sources")
		}
	}
	if bundleErr == nil {
		switch mirror, from, err := bundlerMirror(t.getenv, t.home); {
		case err != nil:
			unread = append(unread, "Bundler's config could not be read: "+err.Error())
		case mirror == "":
			found = append(found, "Bundler has no mirror for https://rubygems.org, so a Gemfile naming it fetches from rubygems.org")
		case isRubygemsOrg(mirror):
			found = append(found, "Bundler's mirror for https://rubygems.org is "+mirror+" (in "+from+")")
		default:
			clean = append(clean, "Bundler's mirror ("+mirror+")")
		}
	}
	switch {
	case len(found) > 0:
		f.Status = StatusWarn
		f.Detail = strings.Join(append(found, unread...), "; ") + "; bypasses bodega's rubygems proxy"
		f.Remediation = "bodega doctor --configure rubygems --apply --url <bodega base URL>"
	case len(unread) > 0:
		f.Status = StatusSkip
		f.Detail = strings.Join(unread, "; ")
		f.Remediation = "run doctor as the user whose gem and Bundler config these are, or repair what the error names"
	default:
		f.Status = StatusOK
		f.Detail = strings.Join(clean, " and ") + " name no rubygems.org"
	}
	return f, true
}

// rubygemsOrgSource is the first source `gem sources --list` prints on
// rubygems.org, or "". The list is one URL per line under a banner.
func rubygemsOrgSource(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if src := strings.TrimSpace(line); isRubygemsOrg(src) {
			return src
		}
	}
	return ""
}

func isRubygemsOrg(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == "rubygems.org" || strings.HasSuffix(host, ".rubygems.org")
}

// Bundler's keys for a mirror of https://rubygems.org, and for one of every
// source. Bundler writes the first with the trailing slash it normalizes a
// source URL to; the second form is what a hand-edited file may hold.
var bundlerMirrorKeys = []string{
	"BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/",
	"BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG",
	"BUNDLE_MIRROR__ALL",
}

// bundlerMirror resolves Bundler's mirror for https://rubygems.org the way
// Bundler does outside an application: the environment first, then the user
// config file, which $BUNDLE_USER_CONFIG or $BUNDLE_USER_HOME relocates. An
// application's own .bundle/config can override both, and doctor runs in no
// application. from names where the value came from.
func bundlerMirror(getenv func(string) string, home string) (mirror, from string, err error) {
	for _, k := range bundlerMirrorKeys {
		if v := getenv(k); v != "" {
			return v, "the environment", nil
		}
	}
	path := getenv("BUNDLE_USER_CONFIG")
	switch {
	case path != "":
	case getenv("BUNDLE_USER_HOME") != "":
		path = filepath.Join(getenv("BUNDLE_USER_HOME"), "config")
	case home != "":
		path = filepath.Join(home, ".bundle", "config")
	default:
		return "", "", nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	values := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ": ")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if uq, err := strconv.Unquote(v); err == nil {
			v = uq
		} else {
			v = strings.Trim(v, "'")
		}
		values[strings.TrimSpace(k)] = v
	}
	for _, k := range bundlerMirrorKeys {
		if v := values[k]; v != "" {
			return v, path, nil
		}
	}
	return "", "", nil
}

// mavenTools is what the maven check reads from the host, so a test can
// stand in for which build tools are on PATH and where their homes are.
type mavenTools struct {
	lookPath func(string) (string, error)
	getenv   func(string) string
	home     string
}

// CheckMaven reports whether Maven and Gradle resolve through bodega: Maven
// by a <mirror> of * in ~/.m2/settings.xml, Gradle by bodega's init script.
// ok is false on a host with neither tool, where the row would describe a
// client nobody runs. A distribution a wrapper downloaded counts as
// installed, since a CI runner building with ./mvnw or ./gradlew often has
// neither tool on PATH.
func CheckMaven() (f Finding, ok bool) {
	home, _ := os.UserHomeDir()
	return checkMaven(mavenTools{lookPath: exec.LookPath, getenv: os.Getenv, home: home})
}

func checkMaven(t mavenTools) (Finding, bool) {
	gradleHome := t.getenv("GRADLE_USER_HOME")
	if gradleHome == "" && t.home != "" {
		gradleHome = filepath.Join(t.home, ".gradle")
	}
	m2 := ""
	if t.home != "" {
		m2 = filepath.Join(t.home, ".m2")
	}
	mvn := toolPresent(t.lookPath, "mvn", m2)
	gradle := toolPresent(t.lookPath, "gradle", gradleHome)
	if !mvn && !gradle {
		return Finding{}, false
	}
	f := Finding{Check: "maven"}
	var found, unread, clean []string
	if mvn {
		path := filepath.Join(m2, "settings.xml")
		switch mirror, others, err := mavenMirror(path); {
		case err != nil:
			unread = append(unread, err.Error())
		case mirror == "":
			found = append(found, path+" has no bodega mirror of *, so Maven fetches from every repository a POM names")
		case len(others) > 0:
			found = append(found, path+" lists "+strings.Join(others, ", ")+" beside bodega's mirror, and Maven sends the repositories each names there")
		default:
			clean = append(clean, "Maven's mirror ("+mirror+")")
		}
	}
	if gradle {
		path := filepath.Join(gradleHome, "init.d", "bodega.gradle")
		switch repo, err := gradleInitURL(path); {
		case errors.Is(err, fs.ErrNotExist) && t.getenv("GRADLE_USER_HOME") != "":
			found = append(found, "no "+path+", so Gradle fetches from every repository a build names (GRADLE_USER_HOME moves init.d away from the ~/.gradle the plan writes, so copy bodega.gradle there)")
		case errors.Is(err, fs.ErrNotExist):
			found = append(found, "no "+path+", so Gradle fetches from every repository a build names")
		case err != nil:
			unread = append(unread, "Gradle's init script could not be read: "+err.Error())
		case repo == "":
			found = append(found, path+" sets no bodega repository")
		default:
			clean = append(clean, "Gradle's init script ("+repo+")")
		}
	}
	switch {
	case len(found) > 0:
		f.Status = StatusWarn
		f.Detail = strings.Join(append(found, unread...), "; ") + "; bypasses bodega's maven proxy"
		f.Remediation = "bodega doctor --configure maven --apply --url <bodega base URL>"
	case len(unread) > 0:
		f.Status = StatusSkip
		f.Detail = strings.Join(unread, "; ")
		f.Remediation = "run doctor as the user whose Maven and Gradle config these are, or repair what the error names"
	default:
		f.Status = StatusOK
		f.Detail = strings.Join(clean, " and ") + " point at bodega"
	}
	return f, true
}

// toolPresent reports whether name is on PATH, or its wrapper has downloaded
// a distribution under home/wrapper/dists.
func toolPresent(lookPath func(string) (string, error), name, home string) bool {
	if _, err := lookPath(name); err == nil {
		return true
	}
	if home == "" {
		return false
	}
	entries, err := os.ReadDir(filepath.Join(home, "wrapper", "dists"))
	return err == nil && len(entries) > 0
}

// mavenMirror reads settings.xml's mirrors: the url of the one bodega's plan
// writes (id bodega, mirrorOf *), and every other mirror, each of which takes
// the repositories it names ahead of a * pattern. A missing file has no
// mirror and is no error.
func mavenMirror(path string) (mirror string, others []string, err error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, fmt.Errorf("%s could not be read: %w", path, err)
	}
	var doc struct {
		Mirrors []struct {
			ID       string `xml:"id"`
			MirrorOf string `xml:"mirrorOf"`
			URL      string `xml:"url"`
		} `xml:"mirrors>mirror"`
	}
	if err := xml.Unmarshal(data, &doc); err != nil {
		return "", nil, fmt.Errorf("%s is not XML Maven can read: %w", path, err)
	}
	for _, m := range doc.Mirrors {
		id, of := strings.TrimSpace(m.ID), strings.TrimSpace(m.MirrorOf)
		if id == "bodega" && of == "*" && mirror == "" {
			mirror = strings.TrimSpace(m.URL)
			continue
		}
		others = append(others, fmt.Sprintf("mirror %q (mirrorOf %s)", id, of))
	}
	return mirror, others, nil
}

// gradleInitURL is the repository bodega's init script at path sets, or ""
// when the file sets none.
func gradleInitURL(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "def bodegaUrl = '"); ok {
			if v, ok = strings.CutSuffix(v, "'"); ok && v != "" {
				return v, nil
			}
		}
	}
	return "", nil
}

// composerTools is what the composer check reads from the host, so a test
// can stand in for whether composer is on PATH and where its home resolves.
type composerTools struct {
	lookPath func(string) (string, error)
	home     func() string
}

// CheckComposer reports whether Composer's global config.json sends every
// project to bodega: a composer repository at a /composer route, with
// packagist.org disabled. ok is false on a host with no composer on PATH,
// where the row would describe a client nobody runs.
func CheckComposer() (f Finding, ok bool) {
	home, _ := os.UserHomeDir()
	return checkComposer(composerTools{lookPath: exec.LookPath, home: func() string { return clientconf.HostComposerHome(home) }})
}

func checkComposer(t composerTools) (Finding, bool) {
	if _, err := t.lookPath("composer"); err != nil {
		return Finding{}, false
	}
	f := Finding{Check: "composer"}
	dir := t.home()
	if dir == "" {
		f.Status = StatusSkip
		f.Detail = "neither COMPOSER_HOME nor HOME is set, so Composer's global config.json could not be located"
		f.Remediation = "run doctor with HOME set to the account whose Composer config this is"
		return f, true
	}
	path := filepath.Join(dir, "config.json")
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		f.Status = StatusWarn
		f.Detail = "no " + path + ", so Composer fetches every package from packagist.org; bypasses bodega's composer proxy"
		f.Remediation = "bodega doctor --configure composer --apply --url <bodega base URL>"
		return f, true
	case err != nil:
		f.Status = StatusSkip
		f.Detail = path + " could not be read: " + err.Error()
		f.Remediation = "run doctor as the user whose Composer config this is, or repair what the error names"
		return f, true
	}
	repos, err := clientconf.ReadComposerRepos(data)
	if err != nil {
		f.Status = StatusSkip
		f.Detail = path + " is not JSON Composer can read: " + err.Error()
		f.Remediation = "repair " + path + ", then run doctor again; composer itself refuses to run with it"
		return f, true
	}
	var found []string
	if repos.Bodega == "" {
		found = append(found, path+" names no composer repository at a bodega /composer route")
	}
	if !repos.PackagistOff {
		found = append(found, path+" leaves packagist.org enabled, so a package bodega does not answer for resolves from Packagist")
	}
	var steps []string
	if len(found) > 0 {
		steps = append(steps, "bodega doctor --configure composer --apply --url <bodega base URL>")
	}
	for _, u := range repos.OnPackagist {
		found = append(found, path+" lists a composer repository at "+u+", which is Packagist under another name")
	}
	// --configure keeps every repository the operator added, so it cannot
	// clear these; only removing the entry does.
	if len(repos.OnPackagist) > 0 {
		steps = append(steps, "remove the composer repository at "+strings.Join(repos.OnPackagist, " and at ")+" from "+path)
	}
	if len(found) > 0 {
		f.Status = StatusWarn
		f.Detail = strings.Join(found, "; ") + "; bypasses bodega's composer proxy"
		f.Remediation = strings.Join(steps, ", then ")
		return f, true
	}
	f.Status = StatusOK
	f.Detail = path + " sends Composer to " + repos.Bodega + " with packagist.org disabled"
	return f, true
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

// OCIHost is what the container runtime checks read from the host: how a
// runtime's command is found, and the directory the /etc paths sit under,
// "" for the host's own. A test stands in for both.
type OCIHost struct {
	LookPath func(string) (string, error)
	Root     string
	// Home is the home directory of the user whose podman pulls the check
	// judges, and RegistriesConf CONTAINERS_REGISTRIES_CONF, which names
	// the main registries.conf in place of the system one.
	Home           string
	RegistriesConf string
}

const ociRemedy = "bodega doctor --configure oci --apply --url <bodega base URL>"

// Check reports, for each container runtime on PATH, whether it pulls
// through bodega: Docker's registry-mirrors, containerd's hosts.toml for
// docker.io and the config_path that makes containerd read it, and a
// registries.conf mirror for podman, buildah and CRI-O. base is bodega's
// URL when doctor knows it; with none, any mirror counts, since doctor
// cannot tell bodega's from another. A runtime not on PATH gets no row.
func (t OCIHost) Check(base string) []Finding {
	host := ""
	if u, err := url.Parse(base); err == nil {
		host = u.Host
	}
	var out []Finding
	for _, rt := range []string{clientconf.RuntimeDocker, clientconf.RuntimeContainerd, clientconf.RuntimePodman} {
		present := false
		for _, bin := range clientconf.RuntimeBinaries[rt] {
			if _, err := t.LookPath(bin); err == nil {
				present = true
			}
		}
		if !present {
			continue
		}
		var f Finding
		switch rt {
		case clientconf.RuntimeDocker:
			f = checkDockerMirror(filepath.Join(t.Root, clientconf.DockerDaemonPath), host)
		case clientconf.RuntimeContainerd:
			f = checkContainerdHosts(t.Root, host)
		case clientconf.RuntimePodman:
			f = t.checkRegistriesConf(host)
		}
		f.Check = "oci-" + rt
		if f.IsFinding() && f.Remediation == "" {
			f.Remediation = ociRemedy
		}
		out = append(out, f)
	}
	return out
}

// mirrorIsBodega reports whether a mirror URL or location names host, or,
// with no host to compare, whether there is a mirror at all.
func mirrorIsBodega(mirror, host string) bool {
	if host == "" {
		return mirror != ""
	}
	m := strings.TrimPrefix(strings.TrimPrefix(mirror, "https://"), "http://")
	return m == host || strings.HasPrefix(m, host+"/")
}

func checkDockerMirror(path, host string) Finding {
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Finding{Status: StatusWarn, Detail: "no " + path + ", so dockerd pulls Docker Hub images from Docker Hub; bypasses bodega's registry"}
	case err != nil:
		return Finding{Status: StatusSkip, Detail: path + " could not be read: " + err.Error(), Remediation: "run doctor as root, which owns " + path}
	}
	var doc struct {
		Mirrors []string `json:"registry-mirrors"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return Finding{Status: StatusSkip, Detail: path + " is not JSON dockerd can read: " + err.Error(), Remediation: "repair " + path + "; dockerd refuses to start with it"}
	}
	for _, m := range doc.Mirrors {
		if mirrorIsBodega(m, host) {
			return Finding{Status: StatusOK, Detail: path + " mirrors Docker Hub through " + m + " (Docker Hub only; other registries are containerd's or podman's)"}
		}
	}
	if len(doc.Mirrors) == 0 {
		return Finding{Status: StatusWarn, Detail: path + " sets no registry-mirrors, so dockerd pulls Docker Hub images from Docker Hub; bypasses bodega's registry"}
	}
	return Finding{Status: StatusWarn, Detail: path + " mirrors Docker Hub through " + strings.Join(doc.Mirrors, ", ") + ", none of them bodega at " + host + "; bypasses bodega's registry"}
}

func checkContainerdHosts(root, host string) Finding {
	cfgPath := filepath.Join(root, clientconf.ContainerdConfigPath)
	data, err := os.ReadFile(cfgPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Finding{Status: StatusWarn, Detail: "no " + cfgPath + ", so containerd's CRI plugin has no config_path and reads no hosts.toml; bypasses bodega's registry"}
	case err != nil:
		return Finding{Status: StatusSkip, Detail: cfgPath + " could not be read: " + err.Error(), Remediation: "run doctor as root, which owns " + cfgPath}
	}
	if _, err := clientconf.ReadContainerdConfig(data); err != nil {
		return Finding{Status: StatusSkip, Detail: cfgPath + " is not a config.toml containerd can load: " + err.Error(), Remediation: "repair " + cfgPath + "; containerd refuses to start with it"}
	}
	cfg, err := clientconf.ResolveContainerdConfig(root, clientconf.ContainerdConfigPath, data)
	if err != nil {
		return Finding{Status: StatusSkip, Detail: cfgPath + " is not judged: " + err.Error(), Remediation: "repair or remove the import it names, or set config_path = \"" + clientconf.ContainerdCertsDir + "\" in that file's CRI registry table, then run " + ociRemedy}
	}
	src := filepath.Join(root, cfg.Source)
	switch {
	case cfg.CRIDisabled:
		return Finding{Status: StatusSkip, Detail: cfgPath + " disables the CRI plugin, so nothing here pulls through containerd's registry configuration; the oci-docker row covers dockerd"}
	case cfg.ConfigPath == "" && cfg.Legacy != "":
		return Finding{Status: StatusSkip, Detail: cfgPath + " routes CRI pulls through the deprecated " + cfg.Legacy + " rather than config_path, which doctor does not judge",
			Remediation: "move " + cfg.Legacy + " into hosts.toml files under " + clientconf.ContainerdCertsDir + " and remove it, then run " + ociRemedy}
	case cfg.ConfigPath == "":
		return Finding{Status: StatusWarn, Detail: src + " sets no config_path, so containerd's CRI plugin reads no hosts.toml; bypasses bodega's registry"}
	}
	// containerd takes the first config_path root holding a directory for
	// the registry, docker.io or else _default, and reads only that one.
	var roots []string
	dir := ""
	for _, r := range strings.Split(cfg.ConfigPath, ":") {
		if r == "" {
			continue
		}
		roots = append(roots, r)
		for _, ns := range []string{"docker.io", "_default"} {
			if p := filepath.Join(root, r, ns); dir == "" {
				if _, err := os.Stat(p); err == nil {
					dir = p
				}
			}
		}
	}
	certs := filepath.Join(root, clientconf.ContainerdCertsDir)
	if dir == "" {
		f := Finding{Status: StatusWarn, Detail: "config_path in " + src + " names " + cfg.ConfigPath + ", which holds no docker.io or _default directory, so containerd pulls Docker Hub images from Docker Hub; bypasses bodega's registry"}
		if !slices.Contains(roots, clientconf.ContainerdCertsDir) {
			f.Remediation = "add " + clientconf.ContainerdCertsDir + " to config_path in " + src + " (config_path = \"" + cfg.ConfigPath + ":" + clientconf.ContainerdCertsDir + "\"), run " + ociRemedy + ", then systemctl restart containerd"
		}
		return f
	}
	f := judgeContainerdHosts(filepath.Join(dir, "hosts.toml"), host)
	if f.IsFinding() && filepath.Dir(dir) != certs {
		f.Remediation = "containerd reads " + dir + ", the first config_path root with a directory for docker.io; name bodega in its hosts.toml, or put " + clientconf.ContainerdCertsDir + " first in config_path in " + src + " and systemctl restart containerd"
	}
	return f
}

// judgeContainerdHosts reads the hosts.toml containerd uses for docker.io.
// containerd tries its hosts in file order and the upstream server last, so
// bodega must be the first host that may pull.
func judgeContainerdHosts(path, host string) Finding {
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Finding{Status: StatusWarn, Detail: "no " + path + ", so containerd pulls Docker Hub images from Docker Hub; bypasses bodega's registry"}
	case err != nil:
		return Finding{Status: StatusSkip, Detail: path + " could not be read: " + err.Error(), Remediation: "run doctor as root, or repair what the error names"}
	}
	var doc struct {
		Host map[string]struct {
			Capabilities []string `toml:"capabilities"`
		} `toml:"host"`
	}
	md, err := toml.Decode(string(data), &doc)
	if err != nil {
		return Finding{Status: StatusSkip, Detail: path + " is not TOML containerd can load: " + err.Error(), Remediation: "repair " + path + "; containerd fails every Docker Hub pull while it stands"}
	}
	for _, k := range md.Keys() {
		if len(k) != 2 || k[0] != "host" {
			continue
		}
		caps := doc.Host[k[1]].Capabilities
		if caps != nil && !slices.Contains(caps, "pull") {
			continue
		}
		if !mirrorIsBodega(k[1], host) {
			return Finding{Status: StatusWarn, Detail: path + " sends containerd's Docker Hub pulls to " + k[1] + " before bodega" + inHost(host) + "; bypasses bodega's registry"}
		}
		return Finding{Status: StatusOK, Detail: path + " sends containerd's Docker Hub pulls to " + k[1]}
	}
	return Finding{Status: StatusWarn, Detail: path + " names no host at bodega" + inHost(host) + ", so containerd pulls Docker Hub images from Docker Hub; bypasses bodega's registry"}
}

// containersRegistry is the part of a containers-registries.conf(5)
// [[registry]] table that decides where a tag pull goes.
type containersRegistry struct {
	Prefix             string `toml:"prefix"`
	Location           string `toml:"location"`
	MirrorByDigestOnly bool   `toml:"mirror-by-digest-only"`
	Mirrors            []struct {
		Location       string `toml:"location"`
		PullFromMirror string `toml:"pull-from-mirror"`
	} `toml:"mirror"`
	source string
}

// registriesConfFiles lists the files podman, buildah and CRI-O read, in the
// order they apply, per containers-registries.conf.d(5): the main file, then
// the system drop-ins, then the user's. A user's own registries.conf
// replaces the main file and every system file with it.
func (t OCIHost) registriesConfFiles() []string {
	userDir := ""
	if t.Home != "" {
		userDir = filepath.Join(t.Home, ".config/containers/registries.conf.d")
		if user := filepath.Join(t.Home, ".config/containers/registries.conf"); t.RegistriesConf == "" {
			if _, err := os.Stat(user); err == nil {
				drop, _ := filepath.Glob(filepath.Join(userDir, "*.conf"))
				return append([]string{user}, drop...)
			}
		}
	}
	main := filepath.Join(t.Root, "/etc/containers/registries.conf")
	if t.RegistriesConf != "" {
		main = t.RegistriesConf
	}
	files := []string{main}
	drop, _ := filepath.Glob(filepath.Join(t.Root, filepath.Dir(clientconf.RegistriesConfDropIn), "*.conf"))
	files = append(files, drop...)
	if userDir != "" {
		drop, _ = filepath.Glob(filepath.Join(userDir, "*.conf"))
		files = append(files, drop...)
	}
	return files
}

// checkRegistriesConf resolves the [[registry]] tables the way the runtimes
// do (a later file replaces a table with the same prefix whole, the first
// one in a file wins inside it) and judges every table a docker.io pull can
// match, since the longest matching prefix is the one used. A table for
// docker.io itself must be among them.
func (t OCIHost) checkRegistriesConf(host string) Finding {
	effective := map[string]containersRegistry{}
	files := t.registriesConfFiles()
	for i, path := range files {
		data, err := os.ReadFile(path)
		switch {
		case i == 0 && errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			return Finding{Status: StatusSkip, Detail: path + " could not be read: " + err.Error(), Remediation: "run doctor as the user whose pulls it judges, or as root for " + filepath.Dir(clientconf.RegistriesConfDropIn)}
		}
		var doc struct {
			Registries []containersRegistry `toml:"registry"`
			V1         map[string]any       `toml:"registries"`
		}
		if _, err := toml.Decode(string(data), &doc); err != nil {
			return Finding{Status: StatusSkip, Detail: path + " is not TOML podman can load: " + err.Error(), Remediation: "repair " + path + "; podman refuses to pull while it stands"}
		}
		if doc.V1 != nil {
			return Finding{Status: StatusSkip, Detail: path + " uses the version 1 [registries.*] format, which doctor does not judge", Remediation: "rewrite " + path + " as [[registry]] tables, then run " + ociRemedy}
		}
		seen := map[string]bool{}
		for _, r := range doc.Registries {
			if r.Prefix == "" {
				r.Prefix = r.Location
			}
			if seen[r.Prefix] {
				continue
			}
			seen[r.Prefix] = true
			r.source = path
			effective[r.Prefix] = r
		}
	}
	var prefixes []string
	for p := range effective {
		if p == "docker.io" || strings.HasPrefix(p, "docker.io/") {
			prefixes = append(prefixes, p)
		}
	}
	sort.Strings(prefixes)
	if len(prefixes) == 0 {
		return Finding{Status: StatusWarn, Detail: "no registries.conf podman reads (" + strings.Join(files, ", ") + ") defines docker.io, so podman, buildah and CRI-O pull Docker Hub images from Docker Hub; bypasses bodega's registry"}
	}
	dropIn := filepath.Join(t.Root, clientconf.RegistriesConfDropIn)
	// A table applies only to the names its prefix matches, so only one for
	// docker.io itself covers every Docker Hub repository; narrower ones
	// are overrides inside it.
	whole, ok := effective["docker.io"]
	if !ok {
		return Finding{Status: StatusWarn, Detail: "the registries.conf files podman reads define only " + strings.Join(prefixes, ", ") + " and no table for docker.io itself, so podman, buildah and CRI-O pull every other Docker Hub repository from Docker Hub; bypasses bodega's registry"}
	}
	for _, p := range prefixes {
		r := effective[p]
		first := r.tagMirror()
		if mirrorIsBodega(first, host) {
			continue
		}
		via := "with no mirror a tag pull uses"
		if first != "" {
			via = "with " + first + " as its first mirror"
		}
		f := Finding{Status: StatusWarn, Detail: r.source + " defines " + p + " " + via + ", not bodega" + inHost(host) + ", and podman, buildah and CRI-O read it in place of any earlier table for " + p + "; bypasses bodega's registry"}
		if r.source != dropIn {
			f.Remediation = "edit or remove the [[registry]] for " + p + " in " + r.source + ", which overrides " + dropIn + ", then run " + ociRemedy
		}
		return f
	}
	return Finding{Status: StatusOK, Detail: whole.source + " mirrors " + whole.Prefix + " through " + whole.tagMirror()}
}

// tagMirror is the first mirror a tag pull tries, "" when none may serve
// one: mirror-by-digest-only and pull-from-mirror = "digest-only" each keep
// a tag pull on the registry itself.
func (r containersRegistry) tagMirror() string {
	for _, m := range r.Mirrors {
		if !r.MirrorByDigestOnly && m.PullFromMirror != "digest-only" {
			return m.Location
		}
	}
	return ""
}

func inHost(host string) string {
	if host == "" {
		return ""
	}
	return " (" + host + ")"
}

// RpmHost is what the dnf check reads, so a test can stand in for each: how
// to find dnf, dnf's main configuration file, and the directories dnf reads
// .repo files from when that file sets no reposdir.
type RpmHost struct {
	LookPath func(string) (string, error)
	MainConf string
	Dirs     []string
}

const rpmRemedy = "bodega doctor --configure rpm --apply --url <bodega base URL>"

// Check reports every enabled dnf repository that fetches from anywhere but
// bodega's /rpm/ route. With no base it cannot tell bodega's repositories
// from others, so it names the ones it could not place rather than passing
// them. ok is false on a host with no dnf, which gets no row.
func (t RpmHost) Check(base string) (f Finding, ok bool) {
	if _, err := t.LookPath("dnf"); err != nil {
		return Finding{}, false
	}
	f.Check = "dnf-repos"
	conf, err := clientconf.ReadDnfConfig(t.MainConf, t.Dirs)
	if err != nil {
		f.Status, f.Detail = StatusSkip, err.Error()
		f.Remediation = "run doctor as root, or repair the file named"
		return f, true
	}
	around, unverified := clientconf.RpmBypasses(conf.Repos, base)
	const noBase = "with no bodega URL to compare against, these may or may not be bodega's"
	switch {
	case len(around) == 0 && len(unverified) == 0:
		f.Status, f.Detail = StatusOK, "every enabled dnf repository fetches through bodega"
	case len(around) == 0:
		f.Status = StatusSkip
		f.Detail = fmt.Sprintf("%s (%d): %s", noBase, len(unverified), describeYumRepos(unverified))
		f.Remediation = "pass --url <bodega base URL>, or set public_url in the config file"
	default:
		f.Status = StatusWarn
		f.Detail = fmt.Sprintf("enabled dnf repositories fetching around bodega (%d): %s; bypasses bodega's rpm proxy",
			len(around), describeYumRepos(around))
		if len(unverified) > 0 {
			f.Detail += fmt.Sprintf("; %s (%d): %s", noBase, len(unverified), describeYumRepos(unverified))
		}
		f.Remediation = rpmRemedy + "; a repository bodega does not serve is disabled with dnf config-manager --set-disabled <id>"
	}
	// A skipped file is a warning even when everything dnf loads passes: dnf
	// warns about it on every run, and the repositories in it come back,
	// unchecked, the moment someone repairs it.
	if len(conf.Skipped) > 0 {
		skipped := make([]string, len(conf.Skipped))
		files := make([]string, len(conf.Skipped))
		for i, s := range conf.Skipped {
			skipped[i] = fmt.Sprintf("%s (%v)", s.File, s.Err)
			files[i] = s.File
		}
		detail := fmt.Sprintf("dnf skips %d malformed .repo file(s), so no repository in them is loaded or checked: %s",
			len(skipped), strings.Join(skipped, ", "))
		fix := "repair or remove " + strings.Join(files, ", ") + ", then re-run doctor"
		switch {
		case f.Status == StatusWarn:
			f.Detail, f.Remediation = f.Detail+"; "+detail, f.Remediation+"; "+fix
		case f.Remediation != "":
			f.Detail, f.Remediation = detail+"; "+f.Detail, fix+"; "+f.Remediation
		default:
			f.Detail, f.Remediation = detail+"; "+f.Detail, fix
		}
		f.Status = StatusWarn
	}
	return f, true
}

func describeYumRepos(repos []clientconf.YumRepo) string {
	parts := make([]string, len(repos))
	for i, r := range repos {
		where := "no baseurl"
		if len(r.URLs) > 0 {
			where = strings.Join(r.URLs, " ")
		}
		parts[i] = fmt.Sprintf("%s (%s: %s)", r.ID, filepath.Base(r.File), where)
	}
	return strings.Join(parts, ", ")
}
