package host

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

// rubyFixture stands in for a host's gem and bundle: which are on PATH, what
// `gem sources --list` prints, and the home Bundler's user config sits in.
func rubyFixture(t *testing.T, tools []string, sources string, env map[string]string) rubyTools {
	t.Helper()
	return rubyTools{
		lookPath: func(name string) (string, error) {
			for _, tool := range tools {
				if tool == name {
					return "/usr/bin/" + name, nil
				}
			}
			return "", exec.ErrNotFound
		},
		gemSources: func(string) (string, error) { return sources, nil },
		getenv:     func(k string) string { return env[k] },
		home:       t.TempDir(),
	}
}

const bodegaGemSources = "*** CURRENT SOURCES ***\n\nhttps://bodega.internal/rubygems/\n"

func TestCheckRubygemsGivesNoRowWithoutGemOrBundle(t *testing.T) {
	if f, ok := checkRubygems(rubyFixture(t, nil, "", nil)); ok {
		t.Errorf("no gem and no bundle gave a row: %+v", f)
	}
}

func TestCheckRubygemsWarnsOnRubygemsOrg(t *testing.T) {
	both := []string{"gem", "bundle"}
	configured := func(t *testing.T) rubyTools {
		r := rubyFixture(t, both, bodegaGemSources, nil)
		r.home = t.TempDir()
		for _, c := range clientconf.Rubygems("https://bodega.internal") {
			if c.Label != "Bundler mirror" {
				continue
			}
			path := filepath.Join(r.home, strings.TrimPrefix(c.Path(clientconf.OSLinux), "~/"))
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(c.Content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return r
	}

	f, ok := checkRubygems(configured(t))
	if !ok || f.Status != StatusOK {
		t.Fatalf("the files clientconf renders = %+v, want OK", f)
	}

	r := configured(t)
	r.gemSources = func(string) (string, error) { return "*** CURRENT SOURCES ***\n\nhttps://rubygems.org/\n", nil }
	f, _ = checkRubygems(r)
	if f.Status != StatusWarn || !strings.Contains(f.Detail, "gem sources lists https://rubygems.org/") || !strings.Contains(f.Remediation, "--configure rubygems") {
		t.Errorf("gem sources on rubygems.org = %+v, want a warning naming the source and --configure rubygems", f)
	}

	f, _ = checkRubygems(rubyFixture(t, []string{"bundle"}, "", nil))
	if f.Status != StatusWarn || !strings.Contains(f.Detail, "Bundler has no mirror") || strings.Contains(f.Detail, "gem sources") {
		t.Errorf("bundle alone with no mirror = %+v, want a warning about Bundler alone", f)
	}

	f, _ = checkRubygems(rubyFixture(t, []string{"bundle"}, "", map[string]string{"BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/": "https://index.rubygems.org/"}))
	if f.Status != StatusWarn || !strings.Contains(f.Detail, "the environment") {
		t.Errorf("a mirror back onto rubygems.org = %+v, want a warning naming the environment", f)
	}

	f, _ = checkRubygems(rubyFixture(t, []string{"bundle"}, "", map[string]string{"BUNDLE_MIRROR__ALL": "https://bodega.internal/rubygems/"}))
	if f.Status != StatusOK {
		t.Errorf("BUNDLE_MIRROR__ALL on bodega = %+v, want OK", f)
	}

	r = rubyFixture(t, []string{"gem"}, "", nil)
	r.gemSources = func(string) (string, error) { return "", errors.New("exit status 1") }
	f, _ = checkRubygems(r)
	if f.Status != StatusSkip || !strings.Contains(f.Detail, "exit status 1") {
		t.Errorf("gem sources failing = %+v, want SKIPPED with the error", f)
	}
}

// mavenFixture stands in for a host's mvn and gradle: which are on PATH, and
// a home holding whatever files the case writes.
func mavenFixture(t *testing.T, tools []string, env map[string]string) mavenTools {
	t.Helper()
	return mavenTools{
		lookPath: func(name string) (string, error) {
			if slices.Contains(tools, name) {
				return "/usr/bin/" + name, nil
			}
			return "", exec.ErrNotFound
		},
		getenv: func(k string) string { return env[k] },
		home:   t.TempDir(),
	}
}

func writeUnder(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// F87 R4: no mvn and no gradle, and no distribution a wrapper downloaded,
// gives no row.
func TestCheckMavenGivesNoRowWithoutMvnOrGradle(t *testing.T) {
	m := mavenFixture(t, nil, nil)
	writeUnder(t, m.home, ".m2/settings.xml", "<settings/>")
	if f, ok := checkMaven(m); ok {
		t.Errorf("no mvn and no gradle gave a row: %+v", f)
	}
}

// F87 R4: the row warns while either tool's file is missing or does not
// point at bodega, and is OK with the files clientconf renders.
func TestCheckMavenWarnsUntilBothFilesPointAtBodega(t *testing.T) {
	configured := func(t *testing.T, tools []string) mavenTools {
		m := mavenFixture(t, tools, nil)
		for _, f := range clientconf.Maven("https://bodega.internal", nil) {
			writeUnder(t, m.home, strings.TrimPrefix(f.Path(clientconf.OSLinux), "~/"), f.Content)
		}
		return m
	}
	both := []string{"mvn", "gradle"}

	f, ok := checkMaven(configured(t, both))
	if !ok || f.Status != StatusOK || !strings.Contains(f.Detail, "https://bodega.internal/maven/") {
		t.Fatalf("the files clientconf renders = %+v, want OK naming the URL", f)
	}

	f, ok = checkMaven(mavenFixture(t, both, nil))
	if !ok || f.Status != StatusWarn || !strings.Contains(f.Detail, "settings.xml has no bodega mirror") ||
		!strings.Contains(f.Detail, "bodega.gradle, so Gradle") || !strings.Contains(f.Remediation, "--configure maven") {
		t.Errorf("neither file = %+v, want a warning naming both and --configure maven", f)
	}

	m := configured(t, both)
	writeUnder(t, m.home, ".m2/settings.xml", "<settings><mirrors>"+
		"<mirror><id>bodega</id><mirrorOf>*</mirrorOf><url>https://bodega.internal/maven/</url></mirror>"+
		"<mirror><id>nexus</id><mirrorOf>central</mirrorOf><url>https://n/</url></mirror></mirrors></settings>")
	if f, _ = checkMaven(m); f.Status != StatusWarn || !strings.Contains(f.Detail, `mirror "nexus" (mirrorOf central)`) {
		t.Errorf("a second mirror beside bodega's = %+v, want a warning naming it", f)
	}

	m = configured(t, []string{"gradle"})
	writeUnder(t, m.home, ".gradle/init.d/bodega.gradle", "// emptied by hand\n")
	if f, _ = checkMaven(m); f.Status != StatusWarn || !strings.Contains(f.Detail, "sets no bodega repository") || strings.Contains(f.Detail, "settings.xml") {
		t.Errorf("gradle alone with a hollow init script = %+v, want a warning about Gradle alone", f)
	}

	m = mavenFixture(t, []string{"gradle"}, nil)
	m.getenv = func(k string) string {
		if k == "GRADLE_USER_HOME" {
			return filepath.Join(m.home, "gh")
		}
		return ""
	}
	for _, f := range clientconf.Maven("https://bodega.internal", nil) {
		writeUnder(t, m.home, strings.TrimPrefix(f.Path(clientconf.OSLinux), "~/"), f.Content)
	}
	if f, _ = checkMaven(m); f.Status != StatusWarn || !strings.Contains(f.Detail, "GRADLE_USER_HOME") {
		t.Errorf("an init script ~/.gradle under a moved GRADLE_USER_HOME = %+v, want a warning naming the variable", f)
	}

	m = mavenFixture(t, nil, nil)
	writeUnder(t, m.home, ".m2/wrapper/dists/apache-maven-3.9.9-bin/x/README", "")
	if f, ok = checkMaven(m); !ok || f.Status != StatusWarn || !strings.Contains(f.Detail, "Maven fetches") {
		t.Errorf("a Maven a wrapper downloaded, with no settings.xml = %+v, want a warning", f)
	}

	m = mavenFixture(t, []string{"mvn"}, nil)
	writeUnder(t, m.home, ".m2/settings.xml", "<settings><mirrors>")
	if f, _ = checkMaven(m); f.Status != StatusSkip || !strings.Contains(f.Detail, "not XML Maven can read") {
		t.Errorf("an unreadable settings.xml = %+v, want SKIPPED naming the parse", f)
	}
}

func composerFixture(installed bool, dir string) composerTools {
	return composerTools{
		lookPath: func(name string) (string, error) {
			if installed && name == "composer" {
				return "/usr/bin/composer", nil
			}
			return "", exec.ErrNotFound
		},
		home: func() string { return dir },
	}
}

// F95 R3: no composer on PATH gives no row, whatever config.json says.
func TestCheckComposerGivesNoRowWithoutComposer(t *testing.T) {
	dir := t.TempDir()
	writeUnder(t, dir, "config.json", `{"repositories":{"packagist.org":true}}`)
	if f, ok := checkComposer(composerFixture(false, dir)); ok {
		t.Errorf("no composer gave a row: %+v", f)
	}
}

// F95 R3: the row warns while the global config.json is missing, names no
// bodega repository, leaves packagist.org on or lists Packagist under another
// name, and is OK with the file clientconf renders. Each warning's remediation
// is one that clears it: --configure keeps the operator's repositories, so a
// Packagist alias is named for removal instead.
func TestCheckComposerWarnsUntilConfigPointsAtBodega(t *testing.T) {
	planned := clientconf.Composer("https://bodega.internal").Content
	const configure = "--configure composer"
	const remove = "remove the composer repository at https://repo.packagist.org from "
	for _, c := range []struct {
		name, config string
		status       Status
		want         string
		fix          []string
		notFix       string
	}{
		{"missing", "", StatusWarn, "fetches every package from packagist.org", []string{configure}, ""},
		{"auth only", `{"config":{"github-oauth":{"github.com":"x"}}}`, StatusWarn, "names no composer repository at a bodega /composer route", []string{configure}, "remove"},
		{"packagist on", `{"repositories":{"bodega":{"type":"composer","url":"https://bodega.internal/composer"}}}`, StatusWarn, "leaves packagist.org enabled", []string{configure}, "remove"},
		{"packagist renamed", `{"repositories":[{"type":"composer","url":"https://bodega.internal/composer"},{"type":"composer","url":"https://repo.packagist.org"},{"packagist.org":false}]}`, StatusWarn, "Packagist under another name", []string{remove}, configure},
		{"packagist renamed and on", `{"repositories":[{"type":"composer","url":"https://repo.packagist.org"}]}`, StatusWarn, "Packagist under another name", []string{configure, ", then " + remove}, ""},
		{"unreadable", `{"repositories":`, StatusSkip, "not JSON Composer can read", nil, ""},
		{"configured", planned, StatusOK, "sends Composer to https://bodega.internal/composer with packagist.org disabled", nil, ""},
	} {
		dir := t.TempDir()
		if c.config != "" {
			writeUnder(t, dir, "config.json", c.config)
		}
		f, ok := checkComposer(composerFixture(true, dir))
		if !ok || f.Check != "composer" || f.Status != c.status || !strings.Contains(f.Detail, c.want) {
			t.Errorf("%s: %+v (row %v), want %s naming %q", c.name, f, ok, c.status, c.want)
		}
		for _, w := range c.fix {
			if !strings.Contains(f.Remediation, w) {
				t.Errorf("%s: remediation %q, want it to name %q", c.name, f.Remediation, w)
			}
		}
		if c.notFix != "" && strings.Contains(f.Remediation, c.notFix) {
			t.Errorf("%s: remediation %q names %q, which does not clear this warning", c.name, f.Remediation, c.notFix)
		}
	}
}

// F99 R4: containerd needs a hosts.toml naming bodega and a config_path that
// makes the CRI plugin read it; podman needs a registries.conf mirror at
// bodega. Each turns OK once the plan's file is in place.
func TestCheckOCIContainerdAndPodman(t *testing.T) {
	root := t.TempDir()
	on := OCIHost{Root: root, LookPath: func(name string) (string, error) { return "/usr/bin/" + name, nil }}
	write := func(p, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, p), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	status := func() map[string]Finding {
		out := map[string]Finding{}
		for _, f := range on.Check("https://bodega.internal") {
			out[f.Check] = f
		}
		return out
	}
	got := status()
	for _, c := range []string{"oci-docker", "oci-containerd", "oci-podman"} {
		if got[c].Status != StatusWarn || !strings.Contains(got[c].Remediation, "--configure oci") {
			t.Errorf("%s on a bare host = %+v, want WARN naming --configure oci", c, got[c])
		}
	}
	for _, f := range clientconf.OCIClient("https://bodega.internal", map[string]string{"docker.io": "https://registry-1.docker.io"}) {
		write(f.Path(clientconf.OSLinux), f.Content)
	}
	write(clientconf.ContainerdConfigPath, "version = 2\n")
	if f := status()["oci-containerd"]; f.Status != StatusWarn || !strings.Contains(f.Detail, "sets no config_path") {
		t.Errorf("containerd with no config_path = %+v, want WARN", f)
	}
	write(clientconf.ContainerdConfigPath, clientconf.ContainerdConfig("https://bodega.internal").Content)
	for c, f := range status() {
		if f.Status != StatusOK {
			t.Errorf("%s after the plan's files = %+v, want OK", c, f)
		}
	}
	if f := (OCIHost{Root: root, LookPath: on.LookPath}).Check("https://other.internal")[2]; f.Status != StatusWarn {
		t.Errorf("podman mirroring another host = %+v, want WARN", f)
	}
}

// ociFixture roots a scratch host for the oci checks and writes its files.
func ociFixture(t *testing.T) (string, func(p, content string)) {
	t.Helper()
	root := t.TempDir()
	return root, func(p, content string) {
		t.Helper()
		full := p
		if !strings.HasPrefix(p, root) {
			full = filepath.Join(root, p)
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func ociCheck(t *testing.T, h OCIHost, check string) Finding {
	t.Helper()
	for _, f := range h.Check("https://bodega.internal") {
		if f.Check == check {
			return f
		}
	}
	t.Fatalf("no %s row", check)
	return Finding{}
}

func onlyRuntime(name string) func(string) (string, error) {
	return func(n string) (string, error) {
		if n == name {
			return "/usr/bin/" + n, nil
		}
		return "", errors.New("absent")
	}
}

// F99 R4: containerd is judged by the hosts.toml in the directory its CRI
// config_path makes it read, not by bodega's certs.d copy.
func TestCheckOCIContainerdReadsTheEffectiveConfigPath(t *testing.T) {
	bodegaHosts := clientconf.ContainerdHosts("https://bodega.internal", "docker.io", "https://registry-1.docker.io").Content
	other := "server = \"https://registry-1.docker.io\"\n\n[host.\"https://other.internal\"]\n  capabilities = [\"pull\", \"resolve\"]\n"
	cri := "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\n"
	cases := []struct {
		name   string
		files  map[string]string
		status Status
		says   string
		remedy string
	}{
		{"custom path, bodega only in certs.d", map[string]string{
			"/etc/containerd/certs.d/docker.io/hosts.toml": bodegaHosts,
			clientconf.ContainerdConfigPath:                cri + "config_path = \"/srv/certs\"\n",
		}, StatusWarn, "/srv/certs, which holds no docker.io", `config_path = "/srv/certs:/etc/containerd/certs.d"`},
		{"custom path holding bodega", map[string]string{
			"/srv/certs/docker.io/hosts.toml": bodegaHosts,
			clientconf.ContainerdConfigPath:   cri + "config_path = \"/srv/certs\"\n",
		}, StatusOK, "/srv/certs/docker.io/hosts.toml sends", ""},
		{"an earlier root shadows certs.d", map[string]string{
			"/srv/certs/docker.io/hosts.toml":              other,
			"/etc/containerd/certs.d/docker.io/hosts.toml": bodegaHosts,
			clientconf.ContainerdConfigPath:                cri + "config_path = \"/srv/certs:/etc/containerd/certs.d\"\n",
		}, StatusWarn, "to https://other.internal before bodega", "put /etc/containerd/certs.d first"},
		{"second root used when the first has no docker.io", map[string]string{
			"/srv/certs/quay.io/hosts.toml":                other,
			"/etc/containerd/certs.d/docker.io/hosts.toml": bodegaHosts,
			clientconf.ContainerdConfigPath:                cri + "config_path = \"/srv/certs:/etc/containerd/certs.d\"\n",
		}, StatusOK, "certs.d/docker.io/hosts.toml sends", ""},
		{"_default fallback", map[string]string{
			"/etc/containerd/certs.d/_default/hosts.toml": bodegaHosts,
			clientconf.ContainerdConfigPath:               cri + "config_path = \"/etc/containerd/certs.d\"\n",
		}, StatusOK, "_default/hosts.toml sends", ""},
		{"docker.io directory without hosts.toml", map[string]string{
			"/etc/containerd/certs.d/docker.io/ca.crt": "",
			clientconf.ContainerdConfigPath:            cri + "config_path = \"/etc/containerd/certs.d\"\n",
		}, StatusWarn, "no ", ociRemedy},
		{"no config.toml", map[string]string{
			"/etc/containerd/certs.d/docker.io/hosts.toml": bodegaHosts,
		}, StatusWarn, "has no config_path", ociRemedy},
		{"another plugin's config_path", map[string]string{
			"/etc/containerd/certs.d/docker.io/hosts.toml": bodegaHosts,
			clientconf.ContainerdConfigPath:                "version = 2\n[plugins.\"io.containerd.other.v1\".registry]\nconfig_path = \"/etc/containerd/certs.d\"\n",
		}, StatusWarn, "sets no config_path", ociRemedy},
		{"quoted key", map[string]string{
			"/etc/containerd/certs.d/docker.io/hosts.toml": bodegaHosts,
			clientconf.ContainerdConfigPath:                cri + "\"config_path\" = \"/etc/containerd/certs.d\" # \"x\"\n",
		}, StatusOK, "sends containerd's Docker Hub pulls to https://bodega.internal", ""},
		{"invalid config.toml", map[string]string{
			clientconf.ContainerdConfigPath: cri + "config_path = \"\"\n\"config_path\" = \"\"\n",
		}, StatusSkip, "not a config.toml containerd can load", "repair"},
		{"CRI disabled", map[string]string{
			clientconf.ContainerdConfigPath: "disabled_plugins = [\"cri\"]\n",
		}, StatusSkip, "disables the CRI plugin", ""},
		{"legacy mirrors", map[string]string{
			clientconf.ContainerdConfigPath: cri + "[plugins.\"io.containerd.grpc.v1.cri\".registry.mirrors.\"docker.io\"]\nendpoint = [\"https://bodega.internal\"]\n",
		}, StatusSkip, "deprecated mirrors", "hosts.toml"},
		{"capabilities without pull", map[string]string{
			"/etc/containerd/certs.d/docker.io/hosts.toml": "[host.\"https://bodega.internal\"]\n  capabilities = [\"resolve\"]\n",
			clientconf.ContainerdConfigPath:                cri + "config_path = \"/etc/containerd/certs.d\"\n",
		}, StatusWarn, "names no host at bodega", ociRemedy},
	}
	for _, c := range cases {
		root, write := ociFixture(t)
		for p, content := range c.files {
			write(p, content)
		}
		f := ociCheck(t, OCIHost{Root: root, LookPath: onlyRuntime("containerd")}, "oci-containerd")
		if f.Status != c.status || !strings.Contains(f.Detail, c.says) || !strings.Contains(f.Remediation, c.remedy) {
			t.Errorf("%s: %+v, want %s saying %q, remedy %q", c.name, f, c.status, c.says, c.remedy)
		}
	}
}

// F99 R4: podman is judged on the registries the runtimes resolve: a later
// file replaces a table with the same prefix whole, the longest prefix a
// pull matches is the one used, and a user's registries.conf stands in for
// every system file.
func TestCheckOCIPodmanResolvesRegistriesConfPrecedence(t *testing.T) {
	bodega := clientconf.RegistriesConf("https://bodega.internal", []string{"docker.io", "quay.io"}).Content
	direct := "[[registry]]\nprefix = \"docker.io\"\nlocation = \"docker.io\"\n"
	cases := []struct {
		name   string
		files  map[string]string
		env    string
		status Status
		says   string
		remedy string
	}{
		{"bodega alone", map[string]string{clientconf.RegistriesConfDropIn: bodega}, "", StatusOK, "99-bodega.conf mirrors docker.io through bodega.internal/docker.io", ""},
		{"a later drop-in replaces docker.io", map[string]string{
			clientconf.RegistriesConfDropIn:                    bodega,
			"/etc/containers/registries.conf.d/zz-direct.conf": direct,
		}, "", StatusWarn, "zz-direct.conf defines docker.io with no mirror", "in " + "<root>/etc/containers/registries.conf.d/zz-direct.conf"},
		{"a later drop-in for another registry", map[string]string{
			clientconf.RegistriesConfDropIn:                    bodega,
			"/etc/containers/registries.conf.d/zz-direct.conf": "[[registry]]\nlocation = \"quay.io\"\n",
		}, "", StatusOK, "mirrors docker.io", ""},
		{"an earlier drop-in is replaced by bodega's", map[string]string{
			clientconf.RegistriesConfDropIn:                    bodega,
			"/etc/containers/registries.conf.d/10-direct.conf": direct,
		}, "", StatusOK, "99-bodega.conf mirrors docker.io", ""},
		{"the main file is overridden by bodega's drop-in", map[string]string{
			clientconf.RegistriesConfDropIn:   bodega,
			"/etc/containers/registries.conf": direct,
		}, "", StatusOK, "99-bodega.conf mirrors docker.io", ""},
		{"a longer docker.io prefix with no mirror", map[string]string{
			clientconf.RegistriesConfDropIn:                     bodega,
			"/etc/containers/registries.conf.d/50-library.conf": "[[registry]]\nprefix = \"docker.io/library\"\nlocation = \"docker.io/library\"\n",
		}, "", StatusWarn, "defines docker.io/library with no mirror", "50-library.conf"},
		{"another mirror first", map[string]string{
			clientconf.RegistriesConfDropIn: "[[registry]]\nprefix = \"docker.io\"\nlocation = \"docker.io\"\n[[registry.mirror]]\nlocation = \"other.internal/docker.io\"\n[[registry.mirror]]\nlocation = \"bodega.internal/docker.io\"\n",
		}, "", StatusWarn, "other.internal/docker.io as its first mirror", ociRemedy},
		{"digest-only mirror", map[string]string{
			clientconf.RegistriesConfDropIn: "[[registry]]\nprefix = \"docker.io\"\nlocation = \"docker.io\"\n[[registry.mirror]]\nlocation = \"bodega.internal/docker.io\"\npull-from-mirror = \"digest-only\"\n",
		}, "", StatusWarn, "with no mirror a tag pull uses", ociRemedy},
		{"user registries.conf hides the system files", map[string]string{
			clientconf.RegistriesConfDropIn:             bodega,
			"<home>/.config/containers/registries.conf": "unqualified-search-registries = [\"docker.io\"]\n",
		}, "", StatusWarn, "defines docker.io", ociRemedy},
		{"user drop-in after the system ones", map[string]string{
			clientconf.RegistriesConfDropIn:                      bodega,
			"<home>/.config/containers/registries.conf.d/a.conf": direct,
		}, "", StatusWarn, "a.conf defines docker.io with no mirror", "a.conf"},
		{"CONTAINERS_REGISTRIES_CONF names a main file", map[string]string{
			"<home>/main.conf": bodega,
		}, "<home>/main.conf", StatusOK, "main.conf mirrors docker.io", ""},
		{"version 1 format", map[string]string{
			"/etc/containers/registries.conf": "[registries.search]\nregistries = [\"docker.io\"]\n",
		}, "", StatusSkip, "version 1", "rewrite"},
		{"not TOML", map[string]string{
			clientconf.RegistriesConfDropIn: "[[registry\n",
		}, "", StatusSkip, "not TOML podman can load", "repair"},
	}
	for _, c := range cases {
		root, write := ociFixture(t)
		home := filepath.Join(root, "home")
		for p, content := range c.files {
			write(strings.Replace(p, "<home>", home, 1), content)
		}
		h := OCIHost{Root: root, Home: home, RegistriesConf: strings.Replace(c.env, "<home>", home, 1), LookPath: onlyRuntime("podman")}
		f := ociCheck(t, h, "oci-podman")
		remedy := strings.Replace(c.remedy, "<root>", root, 1)
		if f.Status != c.status || !strings.Contains(f.Detail, c.says) || !strings.Contains(f.Remediation, remedy) {
			t.Errorf("%s: %+v, want %s saying %q, remedy %q", c.name, f, c.status, c.says, remedy)
		}
	}
}

// F99 R4: containerd runs with the config_path its imports leave, so a
// main file naming certs.d proves nothing while an import replaces the CRI
// table, and an import doctor cannot load or judge is reported, not skipped.
func TestCheckOCIContainerdResolvesImports(t *testing.T) {
	bodegaHosts := clientconf.ContainerdHosts("https://bodega.internal", "docker.io", "https://registry-1.docker.io").Content
	cri := "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\n"
	importing := func(imp, path string) string {
		return "version = 2\nimports = [\"" + imp + "\"]\n" + cri[len("version = 2\n"):] + "config_path = \"" + path + "\"\n"
	}
	cases := []struct {
		name   string
		files  map[string]string
		status Status
		says   string
		remedy string
	}{
		{"relative import overrides config_path", map[string]string{
			clientconf.ContainerdConfigPath:       importing("conf.d/runtime.toml", clientconf.ContainerdCertsDir),
			"/etc/containerd/conf.d/runtime.toml": cri + "config_path = \"/srv/direct\"\n",
		}, StatusWarn, "conf.d/runtime.toml names /srv/direct, which holds no docker.io", "to config_path in "},
		{"globbed import overrides config_path", map[string]string{
			clientconf.ContainerdConfigPath:    importing("/etc/containerd/conf.d/*.toml", clientconf.ContainerdCertsDir),
			"/etc/containerd/conf.d/a.toml":    "version = 2\n[plugins.\"io.containerd.grpc.v1.other\"]\n",
			"/etc/containerd/conf.d/zz.toml":   cri + "config_path = \"/srv/direct\"\n",
			"/srv/direct/docker.io/hosts.toml": "server = \"https://registry-1.docker.io\"\n",
		}, StatusWarn, "names no host at bodega", "conf.d/zz.toml and systemctl restart containerd"},
		{"import names certs.d over a direct main file", map[string]string{
			clientconf.ContainerdConfigPath:       importing("conf.d/runtime.toml", "/srv/direct"),
			"/etc/containerd/conf.d/runtime.toml": cri + "config_path = \"/etc/containerd/certs.d\"\n",
		}, StatusOK, "certs.d/docker.io/hosts.toml sends", ""},
		{"nested import resolves against its own file", map[string]string{
			clientconf.ContainerdConfigPath:   importing("conf.d/a.toml", clientconf.ContainerdCertsDir),
			"/etc/containerd/conf.d/a.toml":   "imports = [\"b/c.toml\"]\n",
			"/etc/containerd/conf.d/b/c.toml": cri + "config_path = \"/srv/direct\"\n",
		}, StatusWarn, "conf.d/b/c.toml names /srv/direct", ""},
		{"import of another plugin keeps the main file's", map[string]string{
			clientconf.ContainerdConfigPath:       importing("conf.d/runtime.toml", clientconf.ContainerdCertsDir),
			"/etc/containerd/conf.d/runtime.toml": "version = 2\n[plugins.\"io.containerd.grpc.v1.other\"]\nx = 1\n",
		}, StatusOK, "certs.d/docker.io/hosts.toml sends", ""},
		{"missing import", map[string]string{
			clientconf.ContainerdConfigPath: importing("conf.d/runtime.toml", clientconf.ContainerdCertsDir),
		}, StatusSkip, "conf.d/runtime.toml, which could not be read", "repair or remove the import"},
		{"CRI table without config_path", map[string]string{
			clientconf.ContainerdConfigPath:       importing("conf.d/runtime.toml", clientconf.ContainerdCertsDir),
			"/etc/containerd/conf.d/runtime.toml": cri + "max_concurrent_downloads = 3\n",
		}, StatusSkip, "doctor cannot tell which runs here", "set config_path"},
		{"import in another format version", map[string]string{
			clientconf.ContainerdConfigPath:       importing("conf.d/runtime.toml", clientconf.ContainerdCertsDir),
			"/etc/containerd/conf.d/runtime.toml": "version = 3\n",
		}, StatusSkip, "does not judge", ""},
		{"versionless import names the short CRI id", map[string]string{
			clientconf.ContainerdConfigPath:       importing("conf.d/runtime.toml", clientconf.ContainerdCertsDir),
			"/etc/containerd/conf.d/runtime.toml": "[plugins.cri.registry]\nconfig_path = \"/srv/direct\"\n",
		}, StatusSkip, "conf.d/runtime.toml cannot be judged: it sets no version and holds [plugins.cri]", "repair or remove the import"},
		{"versionless import in the main file's own names", map[string]string{
			clientconf.ContainerdConfigPath:       importing("conf.d/runtime.toml", clientconf.ContainerdCertsDir),
			"/etc/containerd/conf.d/runtime.toml": cri[len("version = 2\n"):] + "config_path = \"/srv/direct\"\n",
		}, StatusWarn, "conf.d/runtime.toml names /srv/direct", ""},
		{"import disables CRI", map[string]string{
			clientconf.ContainerdConfigPath:       importing("conf.d/runtime.toml", clientconf.ContainerdCertsDir),
			"/etc/containerd/conf.d/runtime.toml": "disabled_plugins = [\"io.containerd.grpc.v1.cri\"]\n",
		}, StatusSkip, "disables the CRI plugin", ""},
	}
	for _, c := range cases {
		root, write := ociFixture(t)
		write("/etc/containerd/certs.d/docker.io/hosts.toml", bodegaHosts)
		for p, content := range c.files {
			write(p, content)
		}
		f := ociCheck(t, OCIHost{Root: root, LookPath: onlyRuntime("containerd")}, "oci-containerd")
		if f.Status != c.status || !strings.Contains(f.Detail, c.says) || !strings.Contains(f.Remediation, c.remedy) {
			t.Errorf("%s: %+v, want %s saying %q, remedy %q", c.name, f, c.status, c.says, c.remedy)
		}
	}

	root, write := ociFixture(t)
	write(clientconf.ContainerdConfigPath, importing("conf.d/runtime.toml", clientconf.ContainerdCertsDir))
	write("/etc/containerd/certs.d/docker.io/hosts.toml", bodegaHosts)
	write("/etc/containerd/conf.d/runtime.toml", cri+"config_path = \"/etc/containerd/certs.d\"\n")
	if err := os.Chmod(filepath.Join(root, "/etc/containerd/conf.d/runtime.toml"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(filepath.Join(root, "/etc/containerd/conf.d/runtime.toml")); err == nil {
		t.Skip("running as root; an unreadable import cannot be staged")
	}
	if f := ociCheck(t, OCIHost{Root: root, LookPath: onlyRuntime("containerd")}, "oci-containerd"); f.Status != StatusSkip || !strings.Contains(f.Detail, "could not be read") {
		t.Errorf("unreadable import: %+v, want a skip saying it could not be read", f)
	}
}

// F99 R4: a registries.conf table covers only the names its prefix
// matches, so a docker.io/library mirror leaves the rest of Docker Hub
// direct, while a docker.io mirror with the same override covers it all.
func TestCheckOCIPodmanRequiresRegistryWideCoverage(t *testing.T) {
	library := "[[registry]]\nprefix = \"docker.io/library\"\nlocation = \"docker.io/library\"\n[[registry.mirror]]\nlocation = \"bodega.internal/docker.io/library\"\n"
	whole := clientconf.RegistriesConf("https://bodega.internal", []string{"docker.io"}).Content
	cases := []struct {
		name, content string
		status        Status
		says          string
	}{
		{"library only", library, StatusWarn, "define only docker.io/library and no table for docker.io itself"},
		{"docker.io with a library override", whole + library, StatusOK, "mirrors docker.io through bodega.internal/docker.io"},
	}
	for _, c := range cases {
		root, write := ociFixture(t)
		write(clientconf.RegistriesConfDropIn, c.content)
		f := ociCheck(t, OCIHost{Root: root, LookPath: onlyRuntime("podman")}, "oci-podman")
		if f.Status != c.status || !strings.Contains(f.Detail, c.says) {
			t.Errorf("%s: %+v, want %s saying %q", c.name, f, c.status, c.says)
		}
		if c.status == StatusWarn && f.Remediation != ociRemedy {
			t.Errorf("%s: remedy %q, want %q", c.name, f.Remediation, ociRemedy)
		}
	}
}
