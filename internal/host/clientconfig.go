package host

import (
	"bufio"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

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
	for _, u := range repos.OnPackagist {
		found = append(found, path+" lists a composer repository at "+u+", which is Packagist under another name")
	}
	if len(found) > 0 {
		f.Status = StatusWarn
		f.Detail = strings.Join(found, "; ") + "; bypasses bodega's composer proxy"
		f.Remediation = "bodega doctor --configure composer --apply --url <bodega base URL>"
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
