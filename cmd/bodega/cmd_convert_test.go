package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// jammyCapture is one row of the dpkg-query output bodega asks for.
const jammyCapture = "libexpat1\t2.4.7-1ubuntu0.2\tamd64\tinstall ok installed\texpat\n"

// runConvertApt converts an apt inventory to a file and returns the manifests
// and what reached stderr.
func runConvertApt(t *testing.T, input string, args ...string) ([]manifest.PackageManifest, string, error) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "catalog.json")
	var errbuf bytes.Buffer
	cmd := newConvertCmd(&globalFlags{})
	cmd.SetArgs(append([]string{"apt", input, "-o", out}, args...))
	cmd.SetErr(&errbuf)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	if err := cmd.Execute(); err != nil {
		return nil, errbuf.String(), err
	}
	blob, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read converted catalog: %v", err)
	}
	var pms []manifest.PackageManifest
	if err := json.Unmarshal(blob, &pms); err != nil {
		t.Fatalf("decode converted catalog: %v", err)
	}
	return pms, errbuf.String(), nil
}

// TestConvertAptRecordsTheSuite is the capture half of keying apt advisories on
// the release. Ubuntu and Debian backport a fix without moving the upstream
// version, so the records that settle a version are the ones published for its
// own release, and dpkg reports no codename in either of its formats. Without
// this flag every entry a capture produces is answered from one server-wide
// apt_codename, which is wrong for every host not running that release.
func TestConvertAptRecordsTheSuite(t *testing.T) {
	pms, errs, err := runConvertApt(t, writeTemp(t, "installed.txt", jammyCapture), "--suite", "jammy")
	if err != nil {
		t.Fatalf("pkg convert apt --suite: %v", err)
	}
	if len(pms) != 1 {
		t.Fatalf("converted %d packages, want 1", len(pms))
	}
	if got := pms[0].Versions[0].Suites; len(got) != 1 || got[0] != "jammy" {
		t.Errorf("suites = %v, want [jammy]", got)
	}
	// Silence would let an operator convert a capture from another release on
	// this machine and never learn which release got recorded.
	if !strings.Contains(errs, "jammy") {
		t.Errorf("the run has to say which release it recorded: %q", errs)
	}
}

// TestConvertAptResolvesTheSuiteFromOSRelease is the unflagged run on the host
// being cataloged, which is where convert is meant to run and the only reason
// the flag can be optional.
//
// Both branches are driven against a named os-release rather than the real
// one, because neither is reproducible on the host that has the other: the
// fallback exists only on Linux and the empty answer only off it, so a test
// reading /etc/os-release asserts whatever the machine running it happens to
// be and skips the rest.
func TestConvertAptResolvesTheSuiteFromOSRelease(t *testing.T) {
	local := writeTemp(t, "os-release", "ID=ubuntu\nVERSION_CODENAME=noble\n")
	res, err := convertInput(manifest.TypeApt, nil, jammyCapture, "", local, io.Discard)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if got := res.Packages[0].Versions[0].Suites; len(got) != 1 || got[0] != "noble" {
		t.Errorf("suites = %v, want [noble]", got)
	}
	// The flag outranks the host: a capture taken elsewhere is the whole
	// reason it exists.
	res, err = convertInput(manifest.TypeApt, nil, jammyCapture, "jammy", local, io.Discard)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if got := res.Packages[0].Versions[0].Suites; len(got) != 1 || got[0] != "jammy" {
		t.Errorf("suites = %v, want [jammy]", got)
	}

	// A host that names no codename records none: a capture converted on a
	// Mac, or on a distro that publishes no VERSION_CODENAME. The OSV gate
	// warns on that entry rather than guessing a release for it, and the run
	// names the flag that fixes it.
	absent := filepath.Join(t.TempDir(), "os-release")
	var errbuf bytes.Buffer
	res, err = convertInput(manifest.TypeApt, nil, jammyCapture, "", absent, &errbuf)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if got := res.Packages[0].Versions[0].Suites; len(got) != 0 {
		t.Errorf("suites = %v, want none recorded", got)
	}
	if !strings.Contains(errbuf.String(), "--suite") {
		t.Errorf("the warning has to name the flag that fixes it: %q", errbuf.String())
	}
}

// TestConvertSuiteIsRefusedForOtherTypes keeps the flag from being accepted and
// dropped. Only apt has a release, and a pypi run that took --suite silently
// would report success having recorded nothing.
func TestConvertSuiteIsRefusedForOtherTypes(t *testing.T) {
	cmd := newConvertCmd(&globalFlags{})
	cmd.SetArgs([]string{"pypi", writeTemp(t, "pip.json", pipList), "--suite", "jammy"})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	err := cmd.Execute()
	if err == nil {
		t.Fatal("pkg convert pypi --suite was accepted; nothing would have recorded it")
	}
	if !strings.Contains(err.Error(), "apt release") {
		t.Errorf("error = %v", err)
	}
}

// TestConvertAptSuiteIsTrimmed keeps the message honest. The parser reads a
// whitespace-only suite as none, so an untrimmed flag would announce a release
// on entries carrying no release at all.
func TestConvertAptSuiteIsTrimmed(t *testing.T) {
	pms, errs, err := runConvertApt(t, writeTemp(t, "installed.txt", jammyCapture), "--suite", "  jammy  ")
	if err != nil {
		t.Fatalf("pkg convert apt: %v", err)
	}
	if got := pms[0].Versions[0].Suites; len(got) != 1 || got[0] != "jammy" {
		t.Errorf("suites = %v, want [jammy]", got)
	}
	if strings.Contains(errs, `"  jammy  "`) {
		t.Errorf("the run reported the untrimmed flag: %q", errs)
	}

	if _, why := resolveAptSuite("   ", osReleasePath); why == "--suite" {
		t.Error("a whitespace-only --suite was taken as a release; the parser records none for it")
	}
}

// TestOSReleaseCodename reads the file the unflagged run reads. The quoting is
// the part worth pinning: os-release permits a bare, a double-quoted and a
// single-quoted value, and a codename carrying its quotes matches no entry in
// the suite table.
func TestOSReleaseCodename(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{"ID=ubuntu\nVERSION_CODENAME=jammy\n", "jammy"},
		{"VERSION_CODENAME=\"bookworm\"\n", "bookworm"},
		{"VERSION_CODENAME='noble'\n", "noble"},
		{"ID=ubuntu\nUBUNTU_CODENAME=jammy\n", ""},
		{"NAME=\"Alpine Linux\"\nVERSION_ID=3.20.0\n", ""},
	} {
		if got := osReleaseCodename(writeTemp(t, "os-release", tc.body)); got != tc.want {
			t.Errorf("osReleaseCodename(%q) = %q, want %q", tc.body, got, tc.want)
		}
	}
	if got := osReleaseCodename(filepath.Join(t.TempDir(), "absent")); got != "" {
		t.Errorf("a missing os-release read %q", got)
	}
}
