package lockfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetect(t *testing.T) {
	for path, want := range map[string]Format{
		"web/package-lock.json":    NpmLock,
		"npm-shrinkwrap.json":      NpmLock,
		"requirements.txt":         Requirements,
		"deps/requirements-ci.txt": Requirements,
		"go.sum":                   GoSum,
		"Cargo.lock":               CargoLock,
		"app/Gemfile.lock":         GemfileLock,
		"gems.locked":              GemfileLock,
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
