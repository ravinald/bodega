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
