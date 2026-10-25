package lockfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetect(t *testing.T) {
	for path, want := range map[string]Format{
		"web/package-lock.json":       NpmLock,
		"npm-shrinkwrap.json":         NpmLock,
		"requirements.txt":            Requirements,
		"deps/requirements-ci.txt":    Requirements,
		"go.sum":                      GoSum,
		"Cargo.lock":                  CargoLock,
		"app/Gemfile.lock":            GemfileLock,
		"gems.locked":                 GemfileLock,
		"app/gradle.lockfile":         GradleLock,
		"buildscript-gradle.lockfile": GradleLock,
		"gradle/dependency-locks/compileClasspath.lockfile": GradleLock,
	} {
		got, err := Detect(path)
		if err != nil || got != want {
			t.Errorf("Detect(%q) = %q, %v; want %q", path, got, err, want)
		}
	}
	if _, err := Detect("deps.lock"); err == nil || !strings.Contains(err.Error(), "--format") {
		t.Errorf("Detect(deps.lock) = %v, want an error naming --format", err)
	}
}

func TestParseNpm(t *testing.T) {
	data := `{
  "name": "app", "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0"},
    "node_modules/lodash": {"version": "4.17.21", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha1-AAAA sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="},
    "node_modules/a/node_modules/lodash": {"version": "4.17.21", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="},
    "node_modules/@scope/pkg": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/@scope/pkg/-/pkg-2.0.0.tgz"},
    "node_modules/alias": {"name": "real-name", "version": "1.0.0"},
    "node_modules/ws-member": {"link": true, "resolved": "packages/ws-member"},
    "node_modules/from-git": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/x/y.git#abc"}
  }
}`
	got, err := Parse(NpmLock, []byte(data))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	byName := map[string]Entry{}
	for _, e := range got {
		byName[e.Name] = e
	}
	if len(got) != 4 {
		t.Fatalf("got %d entries %+v; want lodash once, @scope/pkg, real-name and from-git", len(got), got)
	}
	l := byName["lodash"]
	if l.Version != "4.17.21" || len(l.Digests) != 1 || l.Digests[0].Algorithm != "sha512" ||
		!strings.HasPrefix(l.Digests[0].Value, "bf690311") {
		t.Errorf("lodash = %+v; want one sha512 digest in hex, the strongest of the two", l)
	}
	if byName["@scope/pkg"].Version != "2.0.0" || byName["real-name"].Version != "1.0.0" {
		t.Errorf("scoped or aliased entry misread: %+v", got)
	}
	if byName["from-git"].Unsupported == "" {
		t.Errorf("a git-resolved entry must be marked unsupported: %+v", byName["from-git"])
	}

	if _, err := Parse(NpmLock, []byte(`{"lockfileVersion": 1, "dependencies": {}}`)); err == nil {
		t.Error("a v1 lockfile must be refused rather than read as empty")
	}
}

func TestParseRequirements(t *testing.T) {
	data := `# pip-compile output
--index-url https://pypi.org/simple
Django==4.2.1 \
    --hash=sha256:AAAA \
    --hash=sha256:bbbb
zope.interface[test]==6.0 ; python_version >= "3.8" --hash=sha256:cccc
requests==2.31.0  # via app
private @ https://example.com/private-1.0.tar.gz
`
	got, err := Parse(Requirements, []byte(data))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("got %+v; want four entries", got)
	}
	if got[0].Name != "django" || got[0].Version != "4.2.1" || got[0].Line != 3 || len(got[0].Digests) != 2 || got[0].Digests[0].Value != "aaaa" {
		t.Errorf("django = %+v; want the canonical name, line 3 and both hashes lowercased", got[0])
	}
	if got[1].Name != "zope-interface" || got[1].Version != "6.0" || len(got[1].Digests) != 1 {
		t.Errorf("zope = %+v; want extras and the marker stripped", got[1])
	}
	if got[2].Name != "requests" || len(got[2].Digests) != 0 {
		t.Errorf("requests = %+v; want no digests", got[2])
	}
	if got[3].Unsupported == "" {
		t.Errorf("a direct URL reference must be unsupported: %+v", got[3])
	}

	for _, bad := range []string{"flask>=2.0\n", "-r base.txt\n", "-e .\n"} {
		if _, err := Parse(Requirements, []byte(bad)); err == nil {
			t.Errorf("Parse(%q) succeeded; an unpinned line or an include must be refused", bad)
		}
	}
}

func TestParseGoSum(t *testing.T) {
	data := `golang.org/x/mod v0.41.0 h1:abc=
golang.org/x/mod v0.41.0/go.mod h1:def=
golang.org/x/only-mod v1.0.0/go.mod h1:ghi=
`
	got, err := Parse(GoSum, []byte(data))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 || got[0].Name != "golang.org/x/mod" || got[0].Version != "v0.41.0" ||
		got[0].Digests[0] != (Digest{Algorithm: "h1", Value: "h1:abc="}) || got[0].Digests[0].String() != "h1:abc=" {
		t.Errorf("got %+v; want the zip line alone, /go.mod lines skipped", got)
	}
	if _, err := Parse(GoSum, []byte("golang.org/x/mod v0.41.0\n")); err == nil {
		t.Error("a line with no hash must be refused")
	}
}

func TestParseCargo(t *testing.T) {
	data := `version = 3

[[package]]
name = "app"
version = "0.1.0"
dependencies = [
 "serde",
]

[[package]]
name = "serde"
version = "1.0.190"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "91D3C334CA1EE894A2C6F6AD698FE8C435B76D504B13D436F0685D648D6D96F7"

[[package]]
name = "forked"
version = "0.2.0"
source = "git+https://github.com/x/forked?rev=abc#abc"
`
	got, err := Parse(CargoLock, []byte(data))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %+v; want serde and forked, the workspace member skipped", got)
	}
	if got[0].Name != "serde" || got[0].Version != "1.0.190" ||
		got[0].Digests[0].String() != "sha256:91d3c334ca1ee894a2c6f6ad698fe8c435b76d504b13d436f0685d648d6d96f7" {
		t.Errorf("serde = %+v", got[0])
	}
	if got[1].Unsupported == "" {
		t.Errorf("a git source must be unsupported: %+v", got[1])
	}
}

// The two fixtures are one Bundler 2.6.2 resolution of rack 3.1.8 and
// nokogiri 1.16.7 across six platforms, written before and after
// `bundle lock --add-checksums`. The second is the CHECKSUMS section Bundler
// 2.5 and later writes; the first is every lockfile older than that.
func readGemfileLock(t *testing.T, name string) []Entry {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(GemfileLock, data)
	if err != nil {
		t.Fatalf("Parse(%s): %v", name, err)
	}
	return got
}

func TestParseGemfileLock(t *testing.T) {
	for _, tc := range []struct {
		file      string
		checksums bool
	}{{"Gemfile.lock", false}, {"Gemfile-checksums.lock", true}} {
		t.Run(tc.file, func(t *testing.T) {
			got := readGemfileLock(t, tc.file)
			byKey := map[string]Entry{}
			for _, e := range got {
				if e.Type != "rubygems" || e.Unsupported != "" {
					t.Errorf("%s@%s = %+v; want a supported rubygems entry", e.Name, e.Version, e)
				}
				byKey[e.Name+"@"+e.Version] = e
			}
			// Six nokogiri builds, racc pulled in by them, and rack. The
			// dependency lines under each nokogiri spec name no pins.
			if len(got) != 8 {
				t.Fatalf("got %d entries %+v; want six nokogiri platform builds, racc and rack", len(got), got)
			}
			linux, ok := byKey["nokogiri@1.16.7-x86_64-linux"]
			if !ok {
				t.Fatalf("no nokogiri x86_64-linux build in %v; the platform belongs on the version, as the gem file names it", got)
			}
			if linux.Line != 14 {
				t.Errorf("nokogiri x86_64-linux on line %d, want 14", linux.Line)
			}
			rack := byKey["rack@3.1.8"]
			if !tc.checksums {
				for _, e := range got {
					if len(e.Digests) != 0 {
						t.Errorf("%s@%s carries %v from a lockfile with no CHECKSUMS", e.Name, e.Version, e.Digests)
					}
				}
				return
			}
			want := map[string]string{
				"rack@3.1.8":                   "d3fbcbca43dc2b43c9c6d7dfbac01667ae58643c42cea10013d0da970218a1b1",
				"nokogiri@1.16.7-x86_64-linux": "9e1e428641d5942af877c60b418c71163560e9feb4a5c4015f3230a8b86a40f6",
			}
			for key, sum := range want {
				e := byKey[key]
				if len(e.Digests) != 1 || e.Digests[0] != (Digest{Algorithm: "sha256", Value: sum}) {
					t.Errorf("%s digests = %v, want sha256:%s", key, e.Digests, sum)
				}
			}
			if rack.Digests[0].String() != "sha256:"+want["rack@3.1.8"] {
				t.Errorf("rack digest renders %q", rack.Digests[0].String())
			}
			for _, e := range got {
				if len(e.Digests) != 1 {
					t.Errorf("%s@%s has %d digests; every spec in this lockfile has one", e.Name, e.Version, len(e.Digests))
				}
			}
		})
	}
}

func TestParseGemfileLockMixedRemotes(t *testing.T) {
	mixed := "GEM\n  remote: https://gems.acme.internal/\n  remote: https://rubygems.org/\n  specs:\n    acme-internal (1.0.0)\n    rack (3.1.8)\n\nPLATFORMS\n  ruby\n"
	got, err := Parse(GemfileLock, []byte(mixed))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %+v; want acme-internal and rack", got)
	}
	for _, e := range got {
		if !strings.Contains(e.Unsupported, "https://gems.acme.internal/ is not rubygems.org") || strings.Contains(e.Unsupported, "https://rubygems.org/") {
			t.Errorf("%s = %q; want unsupported naming only the private remote, since the lockfile cannot attribute a spec to one remote", e.Name, e.Unsupported)
		}
	}

	for name, data := range map[string]string{
		"no remote":    "GEM\n  specs:\n    rack (3.1.8)\n",
		"rubygems.org": "GEM\n  remote: https://rubygems.org/\n  remote: http://rubygems.org\n  specs:\n    rack (3.1.8)\n",
	} {
		got, err := Parse(GemfileLock, []byte(data))
		if err != nil || len(got) != 1 {
			t.Fatalf("%s: Parse = %+v, %v", name, got, err)
		}
		if want := name == "no remote"; (got[0].Unsupported != "") != want {
			t.Errorf("%s: unsupported = %q; want unsupported=%v", name, got[0].Unsupported, want)
		}
	}
}

func TestParseGemfileLockSources(t *testing.T) {
	data := `GIT
  remote: https://github.com/example/widget.git
  revision: 0123456789abcdef0123456789abcdef01234567
  specs:
    widget (0.1.0)

PATH
  remote: engines/billing
  specs:
    billing (1.0.0)

GEM
  remote: https://gems.example.com/
  specs:
    private-gem (2.0.0)

GEM
  remote: https://rubygems.org/
  specs:
    rack (3.1.8)

CHECKSUMS
  billing (1.0.0)
  rack (3.1.8) sha256=D3FBCBCA43DC2B43C9C6D7DFBAC01667AE58643C42CEA10013D0DA970218A1B1
`
	got, err := Parse(GemfileLock, []byte(data))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	byName := map[string]Entry{}
	for _, e := range got {
		byName[e.Name] = e
	}
	if _, ok := byName["billing"]; ok || len(got) != 3 {
		t.Fatalf("got %+v; want widget, private-gem and rack, and no PATH gem", got)
	}
	if !strings.Contains(byName["widget"].Unsupported, "git source https://github.com/example/widget.git") {
		t.Errorf("widget = %+v; want a git source reported unsupported", byName["widget"])
	}
	if !strings.Contains(byName["private-gem"].Unsupported, "https://gems.example.com/ is not rubygems.org") {
		t.Errorf("private-gem = %+v; want another registry reported unsupported", byName["private-gem"])
	}
	if r := byName["rack"]; r.Unsupported != "" || len(r.Digests) != 1 || r.Digests[0].Value != strings.ToLower(r.Digests[0].Value) {
		t.Errorf("rack = %+v; want supported with its digest in lowercase hex", r)
	}

	if _, err := Parse(GemfileLock, []byte("CHECKSUMS\n  rack 3.1.8 sha256=ab\n")); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("a malformed CHECKSUMS line = %v; want an error naming its line", err)
	}
}

func readFixture(t *testing.T, format Format, name string) []Entry {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(format, data)
	if err != nil {
		t.Fatalf("Parse(%s): %v", name, err)
	}
	return got
}

// gradle.lockfile is what Gradle 8.10.2 wrote for a java project locking all
// configurations (spring-boot-dependencies as a platform, slf4j-api,
// caffeine, h2, junit-jupiter-api): one line per resolved module, the
// configurations after "=", and an "empty=" line naming the configurations
// that resolved nothing.
func TestParseGradleLock(t *testing.T) {
	got := readFixture(t, GradleLock, "gradle.lockfile")
	if len(got) != 11 {
		t.Fatalf("got %d entries %+v; want the eleven module lines and neither the comments nor empty=", len(got), got)
	}
	first, last := got[0], got[len(got)-1]
	if first.Type != "maven" || first.Name != "com.github.ben-manes.caffeine:caffeine" || first.Version != "3.1.8" || first.Line != 4 {
		t.Errorf("first = %+v; want com.github.ben-manes.caffeine:caffeine@3.1.8 from line 4", first)
	}
	if last.Name != "org.springframework.boot:spring-boot-dependencies" || last.Version != "3.3.0" || last.Line != 14 {
		t.Errorf("last = %+v; want the platform BOM at 3.3.0 from line 14", last)
	}
	for _, e := range got {
		if e.Unsupported != "" || len(e.Digests) != 0 || len(e.Classifiers) != 0 {
			t.Errorf("%s@%s = %+v; gradle.lockfile records neither digests nor classifiers", e.Name, e.Version, e)
		}
	}

	snap, err := Parse(GradleLock, []byte("com.example:lib:1.0-SNAPSHOT=runtimeClasspath\n"))
	if err != nil || len(snap) != 1 || !strings.Contains(snap[0].Unsupported, "SNAPSHOT") {
		t.Errorf("SNAPSHOT = %+v, %v; want it reported unsupported", snap, err)
	}

	for _, tc := range []struct{ body, want string }{
		{"# header\norg.slf4j:slf4j-api=compileClasspath\n", "line 2 of gradle.lockfile"},
		{"org.slf4j:slf4j-api:2.0.13:extra=compileClasspath\n", "line 1 of gradle.lockfile"},
		{"\n\norg/slf4j:slf4j-api:2.0.13=compileClasspath\n", "line 3 of gradle.lockfile"},
		{"org.slf4j:*:2.0.13=compileClasspath\n", "line 1 of gradle.lockfile"},
	} {
		if _, err := Parse(GradleLock, []byte(tc.body)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Parse(%q) = %v; want a refusal naming %q", tc.body, err, tc.want)
		}
	}
}

// dependency-list.txt is what 'mvn -q dependency:list -DoutputFile' wrote
// under Maven 3.9.9 and maven-dependency-plugin 3.7.0 for a project
// importing spring-boot-dependencies: the module suffix, an optional
// dependency, a classifier, and the test scope.
func TestParseMavenDependencyList(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "dependency-list.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := Sniff(data); !ok || f != MavenDependencyList {
		t.Errorf("Sniff = %q, %v; want the header line to name dependency-list", f, ok)
	}
	got := readFixture(t, MavenDependencyList, "dependency-list.txt")
	if len(got) != 13 {
		t.Fatalf("got %d entries %+v; want the thirteen resolved coordinates", len(got), got)
	}
	byName := map[string]Entry{}
	for _, e := range got {
		if e.Type != "maven" || e.Unsupported != "" {
			t.Errorf("%s@%s = %+v; want a supported maven entry", e.Name, e.Version, e)
		}
		byName[e.Name] = e
	}
	for name, want := range map[string]struct {
		version     string
		line        int
		classifiers string
	}{
		"org.slf4j:slf4j-api":                   {"2.0.13", 3, ""},
		"com.h2database:h2":                     {"2.2.224", 4, ""},
		"io.netty:netty-transport-native-epoll": {"4.1.110.Final", 5, "linux-x86_64"},
		"org.apiguardian:apiguardian-api":       {"1.1.2", 15, ""},
	} {
		e := byName[name]
		if e.Version != want.version || e.Line != want.line || strings.Join(e.Classifiers, ",") != want.classifiers {
			t.Errorf("%s = %+v; want %s from line %d with classifiers %q", name, e, want.version, want.line, want.classifiers)
		}
	}

	// The shapes the capture does not show: a second module's list after a
	// blank line, a test-jar, a classified aar, an import-scoped BOM, a
	// module with no dependencies, and a coordinate both lists name.
	multi := "\nThe following files have been resolved:\n   com.example:model:test-jar:tests:3.3.0:test\n" +
		"   org.springframework.boot:spring-boot-dependencies:pom:3.3.0:import\n\n" +
		"The following files have been resolved:\n   com.example:native-libs:aar:arm64:2.0:runtime\n" +
		"   com.example:model:test-jar:tests:3.3.0:test\n\nThe following files have been resolved:\n   none\n"
	got, err = Parse(MavenDependencyList, []byte(multi))
	if err != nil || len(got) != 3 {
		t.Fatalf("multi-module = %+v, %v; want three distinct coordinates", got, err)
	}
	if got[0].Name != "com.example:model" || strings.Join(got[0].Classifiers, ",") != "tests" ||
		got[1].Name != "org.springframework.boot:spring-boot-dependencies" || len(got[1].Classifiers) != 0 ||
		got[2].Name != "com.example:native-libs" || strings.Join(got[2].Classifiers, ",") != "arm64@aar" || got[2].Line != 7 {
		t.Errorf("multi-module = %+v; want the test-jar as tests, the BOM unclassified, and the aar as arm64@aar from line 7", got)
	}

	console := "[INFO] --- dependency:3.6.1:list (default-cli) @ app ---\n[INFO] \n[INFO] The following files have been resolved:\n" +
		"[INFO]    org.slf4j:slf4j-api:jar:2.0.13:compile:/home/ci/.m2/repository/org/slf4j/slf4j-api/2.0.13/slf4j-api-2.0.13.jar\n" +
		"[INFO]    com.example:lib:jar:1.0\n[INFO] \n[INFO] BUILD SUCCESS\n"
	if got, err := Parse(MavenDependencyList, []byte(console)); err != nil || len(got) != 2 ||
		got[0].Name != "org.slf4j:slf4j-api" || got[0].Version != "2.0.13" || got[1].Version != "1.0" {
		t.Errorf("console copy = %+v, %v; want slf4j-api 2.0.13 past its file name and lib 1.0 with no scope", got, err)
	}

	for _, tc := range []struct{ body, want string }{
		{"\nThe following files have been resolved:\n   org.slf4j:slf4j-api:2.0.13\n", "line 3 of the dependency:list output"},
		{"\nThe following files have been resolved:\n   ok:fine:jar:1.0:compile\n   a:b:c:d:e:f:g:h\n", "line 4 of the dependency:list output"},
		{"\nThe following files have been resolved:\n   org/x:y:jar:1.0:compile\n", "line 3 of the dependency:list output"},
		{"[INFO] BUILD SUCCESS\n", "has no \"The following files have been resolved:\" line"},
	} {
		if _, err := Parse(MavenDependencyList, []byte(tc.body)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Parse(%q) = %v; want a refusal naming %q", tc.body, err, tc.want)
		}
	}
}
