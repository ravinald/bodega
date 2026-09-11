package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// aptChecker returns a checker answering from the fixture database with the
// apt gate set to block, which is the configuration that makes a wrong verdict
// visible: a false clean passes an import nobody ever looks at again.
func aptChecker(t *testing.T) *OSVChecker {
	t.Helper()
	ck := NewOSVChecker(&fakeOSVStore{policies: map[string]audit.OSVPolicy{
		manifest.TypeApt: {Ecosystem: manifest.TypeApt, Action: ActionBlock},
	}})
	ck.LocalDB = syncedDB(t)
	return ck
}

func aptEntry(version, suite string) (*manifest.PackageManifest, *manifest.VersionEntry) {
	return &manifest.PackageManifest{Name: "libexpat1", Type: manifest.TypeApt},
		&manifest.VersionEntry{Version: version, SourceName: "expat", Suites: []string{suite}}
}

// TestOSVApt_BackportedRevisionReportsClean is the test this item exists for.
//
// USN-6694-1 and USN-7000-2 are real records: both fix expat in jammy at
// 2.4.7-1ubuntu0.3 and 2.4.7-1ubuntu0.4, and the upstream release never moves
// off 2.4.7. So the upstream version an operator reads off the package is
// inside a published vulnerable range (asserted here, not assumed), while the
// revision that carries the backported fix is outside it. An implementation
// that queried a generic ecosystem for "expat 2.4.7" reports both advisories
// against a host that has been patched for a year.
func TestOSVApt_BackportedRevisionReportsClean(t *testing.T) {
	ck := aptChecker(t)

	// The upstream release, with the revision dropped: what a naive query
	// asks, and what the published records answer.
	upstream, _, err := ck.LocalDB.Match("Ubuntu:22.04:LTS", "expat", "2.4.7")
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if got := vulnIDs(upstream); len(got) != 2 {
		t.Fatalf("the premise of this test is that upstream 2.4.7 is inside a published vulnerable range; got %v", got)
	}

	pm, ve := aptEntry("2.4.7-1ubuntu0.4", "jammy")
	r := ck.Check(context.Background(), pm, ve)
	if r.Action != ActionPass {
		t.Fatalf("2.4.7-1ubuntu0.4 carries the fix for both records; the gate reported %q: %s", r.Action, r.Reason)
	}
	if ve.Metadata[OSVMetaVulns] != "" {
		t.Errorf("a patched revision must stamp no findings, got %q", ve.Metadata[OSVMetaVulns])
	}
	if ve.Metadata[OSVMetaCheckedAt] == "" {
		t.Error("a clean answer from a current database has to carry its date")
	}
}

// TestOSVApt_BehindTheFixedRevisionReportsTheAdvisory is the other half: the
// same package one revision short of the fix, reported with the USN and DSA
// identifiers an operator searches for.
func TestOSVApt_BehindTheFixedRevisionReportsTheAdvisory(t *testing.T) {
	ck := aptChecker(t)

	for _, tc := range []struct {
		suite   string
		version string
		want    string
	}{
		{"jammy", "2.4.7-1ubuntu0.2", "USN-6694-1,USN-7000-2"},
		// 2.5.0-1 against a fix at 2.5.0-1+deb12u1. Semver reads the "+" as a
		// build tag and discards it, making the two versions equal and the
		// host clean; dpkg orders the revisions and does not.
		{"bookworm", "2.5.0-1", "DSA-5770-1"},
	} {
		t.Run(tc.suite, func(t *testing.T) {
			pm, ve := aptEntry(tc.version, tc.suite)
			r := ck.Check(context.Background(), pm, ve)
			if r.Action != ActionBlock {
				t.Fatalf("%s is behind the fixed revision; the gate reported %q: %s", tc.version, r.Action, r.Reason)
			}
			if got := ve.Metadata[OSVMetaVulns]; got != tc.want {
				t.Errorf("stamped %q, want %q", got, tc.want)
			}
			for _, id := range strings.Split(tc.want, ",") {
				if !strings.Contains(r.Reason, id) {
					t.Errorf("the reason must name %s: %q", id, r.Reason)
				}
			}
		})
	}
}

// TestOSVApt_EachSuiteAnswersFromItsOwnRelease pins requirement 1 against the
// failure it names: one catalog, two releases, and a codename that is right
// for one of them.
//
// The noble version is newer than every jammy record, so answering a noble
// entry from jammy's export reports a vulnerable host clean, asserted here so
// the test fails if the ecosystem ever stops being derived per entry.
func TestOSVApt_EachSuiteAnswersFromItsOwnRelease(t *testing.T) {
	ck := aptChecker(t)

	pm, jammy := aptEntry("2.4.7-1ubuntu0.4", "jammy")
	if r := ck.Check(context.Background(), pm, jammy); r.Action != ActionPass {
		t.Fatalf("jammy 2.4.7-1ubuntu0.4 is patched: %q %s", r.Action, r.Reason)
	}

	pm, noble := aptEntry("2.6.1-2build1", "noble")
	r := ck.Check(context.Background(), pm, noble)
	if r.Action != ActionBlock {
		t.Fatalf("noble 2.6.1-2build1 is behind USN-7000-1: %q %s", r.Action, r.Reason)
	}
	if got := noble.Metadata[OSVMetaVulns]; got != "USN-7000-1" {
		t.Errorf("stamped %q, want USN-7000-1", got)
	}

	wrong, _, err := ck.LocalDB.Match("Ubuntu:22.04:LTS", "expat", "2.6.1-2build1")
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if len(wrong) != 0 {
		t.Fatalf("the premise is that jammy's records say nothing about a noble version; got %v", vulnIDs(wrong))
	}
}

// TestOSVApt_QueriedNameIsStamped covers requirement 2 from both sides: an
// advisory is issued against the source package, and an operator reading a
// finding on libexpat1 has to be able to tell which name produced it.
func TestOSVApt_QueriedNameIsStamped(t *testing.T) {
	ck := aptChecker(t)

	pm, ve := aptEntry("2.4.7-1ubuntu0.2", "jammy")
	r := ck.Check(context.Background(), pm, ve)
	if r.Action != ActionBlock {
		t.Fatalf("libexpat1 is built from expat and inherits its advisories: %q %s", r.Action, r.Reason)
	}
	want := "source package expat in Ubuntu:22.04:LTS"
	if got := ve.Metadata[OSVMetaQueried]; got != want {
		t.Errorf("stamped %q, want %q", got, want)
	}
	if !strings.Contains(r.Reason, want) {
		t.Errorf("the admission reason must say what was queried: %q", r.Reason)
	}

	// No source name recorded: the binary name is what is left, and the stamp
	// says so rather than implying an advisory was matched against a source.
	pm = &manifest.PackageManifest{Name: "expat", Type: manifest.TypeApt}
	ve = &manifest.VersionEntry{Version: "2.4.7-1ubuntu0.2", Suites: []string{"jammy"}}
	if r := ck.Check(context.Background(), pm, ve); r.Action != ActionBlock {
		t.Fatalf("expat by its own name is still expat: %q %s", r.Action, r.Reason)
	}
	if got, want := ve.Metadata[OSVMetaQueried], "binary package expat in Ubuntu:22.04:LTS"; got != want {
		t.Errorf("stamped %q, want %q", got, want)
	}
}

// TestOSVApt_UnanswerableEntryWarns holds B34's line: a gate that cannot
// answer must not report clean. Every case here would pass silently if the
// resolution failure short-circuited the way an uncovered registry type does.
func TestOSVApt_UnanswerableEntryWarns(t *testing.T) {
	ck := aptChecker(t)

	for _, tc := range []struct {
		name string
		ve   manifest.VersionEntry
		want string
	}{
		{
			name: "suite with no OSV export",
			ve:   manifest.VersionEntry{Version: "2.6.3-2", SourceName: "expat", Suites: []string{"plucky"}},
			want: "plucky",
		},
		{
			name: "no suite at all",
			ve:   manifest.VersionEntry{Version: "2.6.3-2", SourceName: "expat"},
			want: "names no suite",
		},
		{
			name: "no version",
			ve:   manifest.VersionEntry{SourceName: "expat", Suites: []string{"jammy"}},
			want: "carries no version",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ve := tc.ve
			r := ck.Check(context.Background(),
				&manifest.PackageManifest{Name: "libexpat1", Type: manifest.TypeApt}, &ve)
			if r.Action != ActionWarn {
				t.Fatalf("an entry nothing can answer for must warn, got %q: %s", r.Action, r.Reason)
			}
			if !strings.Contains(r.Reason, tc.want) {
				t.Errorf("reason must name %q, got %q", tc.want, r.Reason)
			}
			if ve.Metadata[OSVMetaCheckedAt] != "" {
				t.Errorf("nothing was answered, so nothing may be dated: %q", ve.Metadata[OSVMetaCheckedAt])
			}
		})
	}
}

// TestOSVApt_PartiallyMappedSuitesDoNotReadAsWhole covers the entry published
// to a release OSV covers and one it does not. The covered release answers,
// and the answer is not dated: half a union is not a clean verdict.
func TestOSVApt_PartiallyMappedSuitesDoNotReadAsWhole(t *testing.T) {
	ck := aptChecker(t)

	ve := &manifest.VersionEntry{
		Version:    "2.4.7-1ubuntu0.4",
		SourceName: "expat",
		Suites:     []string{"jammy", "plucky"},
	}
	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "libexpat1", Type: manifest.TypeApt}, ve)
	if r.Action != ActionWarn {
		t.Fatalf("a suite nothing was queried for must warn, got %q: %s", r.Action, r.Reason)
	}
	if !strings.Contains(r.Reason, "plucky") {
		t.Errorf("reason must name the suite that was skipped: %q", r.Reason)
	}
	if ve.Metadata[OSVMetaCheckedAt] != "" {
		t.Error("a partial answer must not be dated")
	}
}

// TestOSVApt_MultipleSuitesUnionTheirRecords is the other half: the same .deb
// published to two covered releases is a finding if either one names it.
func TestOSVApt_MultipleSuitesUnionTheirRecords(t *testing.T) {
	ck := aptChecker(t)

	ve := &manifest.VersionEntry{
		Version:    "2.4.7-1ubuntu0.2",
		SourceName: "expat",
		Suites:     []string{"jammy", "noble"},
	}
	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "libexpat1", Type: manifest.TypeApt}, ve)
	if r.Action != ActionBlock {
		t.Fatalf("both releases name this version: %q %s", r.Action, r.Reason)
	}
	if got, want := ve.Metadata[OSVMetaVulns], "USN-6694-1,USN-7000-1,USN-7000-2"; got != want {
		t.Errorf("stamped %q, want the union %q", got, want)
	}
	if got, want := ve.Metadata[OSVMetaQueried], "source package expat in Ubuntu:22.04:LTS, Ubuntu:24.04:LTS"; got != want {
		t.Errorf("stamped %q, want %q", got, want)
	}
}

// TestAptOSVEcosystem covers the suite-to-release mapping, pockets included:
// bodega serves whatever name apt_suites holds, and "jammy-security" is the
// same Ubuntu release as "jammy".
func TestAptOSVEcosystem(t *testing.T) {
	for _, tc := range []struct{ suite, want string }{
		{"jammy", "Ubuntu:22.04:LTS"},
		{"jammy-security", "Ubuntu:22.04:LTS"},
		{"noble-updates", "Ubuntu:24.04:LTS"},
		{"bookworm", "Debian:12"},
		{"bookworm-backports", "Debian:12"},
		{"trixie", "Debian:13"},
		{"questing", "Ubuntu:25.10"},
		{"resolute", "Ubuntu:26.04:LTS"},
		{"resolute-security", "Ubuntu:26.04:LTS"},
		{"forky", "Debian:14"},
		// A superseded interim release carries a handful of records rather
		// than a release's worth, which distills to an index that passes
		// sync's no-packages check and then reports the rest of the release
		// clean. Absent, so the gate warns instead.
		{"mantic", ""},
		{"oracular", ""},
		{"plucky", ""},
		{"stable", ""},
		{"", ""},
	} {
		if got := AptOSVEcosystem(tc.suite); got != tc.want {
			t.Errorf("AptOSVEcosystem(%q) = %q, want %q", tc.suite, got, tc.want)
		}
	}
}

func TestOSVExportsFor(t *testing.T) {
	exports, unmapped := OSVExportsFor(manifest.TypeApt, []string{"noble", "jammy", "plucky", "jammy-security"})
	if got, want := strings.Join(exports, ","), "Ubuntu:22.04:LTS,Ubuntu:24.04:LTS"; got != want {
		t.Errorf("exports = %q, want %q deduped and sorted", got, want)
	}
	if got, want := strings.Join(unmapped, ","), "plucky"; got != want {
		t.Errorf("unmapped = %q, want %q", got, want)
	}
	if exports, _ := OSVExportsFor(manifest.TypeNpm, nil); strings.Join(exports, ",") != "npm" {
		t.Errorf("a language ecosystem is one export, got %v", exports)
	}
	if exports, _ := OSVExportsFor(manifest.TypeGit, nil); len(exports) != 0 {
		t.Errorf("git has no OSV export, got %v", exports)
	}
}

// TestCompareDebian pins dpkg's ordering on the pairs a wrong answer is most
// expensive on. The revision cases are the ones that decide whether a patched
// host reports clean.
func TestCompareDebian(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"3.0.2-0ubuntu1.15", "3.0.2-0ubuntu1.2", 1},
		{"3.0.2-0ubuntu1.2", "3.0.2-0ubuntu1.15", -1},
		{"2.4.7-1ubuntu0.4", "2.4.7-1ubuntu0.4", 0},
		{"2.5.0-1", "2.5.0-1+deb12u1", -1},
		{"2.6.1-2build1", "2.6.1-2ubuntu0.1", -1},
		// No revision at all is older than any revision: the upstream release
		// an operator reads off the package sorts below the distro build.
		{"2.4.7", "2.4.7-1ubuntu0.3", -1},
		// A tilde sorts below the end of the string, which is what makes a
		// release candidate older than its release.
		{"1.0~rc1", "1.0", -1},
		{"1.0~~", "1.0~", -1},
		// Leading zeros carry no weight.
		{"1.07", "1.7", 0},
		// An epoch outranks everything after it, which is what an epoch is
		// for: it is bumped when the upstream versioning scheme went
		// backwards.
		{"1:1.0", "2.0", 1},
		{"1.0", "1:0.9", -1},
	} {
		got, ok := compareDebian(tc.a, tc.b)
		if !ok {
			t.Errorf("compareDebian(%q, %q) could not order them", tc.a, tc.b)
			continue
		}
		if got != tc.want {
			t.Errorf("compareDebian(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}

	// A bound no ordering can place leaves the range unevaluated rather than
	// walked on a comparison that means nothing; see OSVDatabase.Match.
	for _, v := range []string{"", "NA", "unknown", "1.0 beta"} {
		if parseDebian(v).ok {
			t.Errorf("parseDebian(%q) claimed to order an unorderable version", v)
		}
	}
}

// TestOSVApt_ProRecordsAnswerTheSameRelease covers the half of a release OSV
// files under a second ecosystem string.
//
// Ubuntu:22.04:LTS carries main and Ubuntu:Pro:22.04:LTS carries universe, and
// the two sets are disjoint: measured 2026-09-11, a stock jammy imagemagick
// answers with 4 records under the first and 179 under the second. An index
// built from the first alone reports that host clean on everything outside
// main and dates the answer.
func TestOSVApt_ProRecordsAnswerTheSameRelease(t *testing.T) {
	ck := aptChecker(t)

	pm := &manifest.PackageManifest{Name: "imagemagick-6.q16", Type: manifest.TypeApt}
	ve := &manifest.VersionEntry{
		Version:    "8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3",
		SourceName: "imagemagick",
		Suites:     []string{"jammy"},
	}
	r := ck.Check(context.Background(), pm, ve)
	if r.Action != ActionBlock {
		t.Fatalf("USN-6621-1 fixes jammy imagemagick at +esm3 and this version is below it; the gate reported %q: %s", r.Action, r.Reason)
	}
	if got := ve.Metadata[OSVMetaVulns]; got != "USN-6621-1" {
		t.Errorf("stamped %q, want USN-6621-1", got)
	}
	if got, want := ve.Metadata[OSVMetaQueried], "source package imagemagick in Ubuntu:22.04:LTS"; got != want {
		t.Errorf("stamped %q, want %q: the Pro half is folded into the release's own index, not queried as a second ecosystem", got, want)
	}

	// A record whose Pro entry names a different source package than its main
	// entry lands under that package, and not under the one the main entry
	// names: the fold is per `affected` entry.
	node, _, err := ck.LocalDB.Match("Ubuntu:22.04:LTS", "nodejs", "12.22.9-1ubuntu3.6")
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if got := vulnIDs(node); len(got) != 1 || got[0] != "UBUNTU-CVE-2022-40735" {
		t.Errorf("the Pro entry of UBUNTU-CVE-2022-40735 names nodejs; jammy nodejs got %v", got)
	}
}

// TestOSVApt_FIPSRecordsAreNotFolded is the limit on the fold above.
//
// OSV also publishes Ubuntu:Pro:FIPS:<rel> and Ubuntu:Pro:FIPS-updates:<rel>,
// whose versions are FIPS builds. UBUNTU-CVE-2022-40735 fixes jammy openssl at
// 3.0.2-0ubuntu1.16 and the FIPS build at 3.0.2-0ubuntu1.16+Fips1, so a prefix
// match on "Ubuntu:Pro:" reports a patched stock host against a FIPS revision
// it never installed.
func TestOSVApt_FIPSRecordsAreNotFolded(t *testing.T) {
	ck := aptChecker(t)

	// The premise: the record is in the jammy index at all.
	behind, _, err := ck.LocalDB.Match("Ubuntu:22.04:LTS", "openssl", "3.0.2-0ubuntu1.15")
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if got := vulnIDs(behind); len(got) != 1 || got[0] != "UBUNTU-CVE-2022-40735" {
		t.Fatalf("3.0.2-0ubuntu1.15 is behind the stock fix at 3.0.2-0ubuntu1.16; got %v", got)
	}

	pm := &manifest.PackageManifest{Name: "libssl3", Type: manifest.TypeApt}
	ve := &manifest.VersionEntry{Version: "3.0.2-0ubuntu1.16", SourceName: "openssl", Suites: []string{"jammy"}}
	if r := ck.Check(context.Background(), pm, ve); r.Action != ActionPass {
		t.Fatalf("3.0.2-0ubuntu1.16 carries the stock fix; the FIPS revisions are about a build this host does not run: %q %s", r.Action, r.Reason)
	}
}

// TestOSVApt_NoSuitesFallsBackToDefault covers the shape every apt manifest
// written before the suites field existed has. The server publishes such an
// entry under apt_codename, so that is the release whose advisories cover it,
// and sync has already downloaded that index because ServedAptSuites always
// includes the codename.
func TestOSVApt_NoSuitesFallsBackToDefault(t *testing.T) {
	ck := aptChecker(t)
	ck.DefaultAptSuite = "jammy"

	pm := &manifest.PackageManifest{Name: "libexpat1", Type: manifest.TypeApt}
	ve := &manifest.VersionEntry{Version: "2.4.7-1ubuntu0.2", SourceName: "expat"}
	r := ck.Check(context.Background(), pm, ve)
	if r.Action != ActionBlock {
		t.Fatalf("an entry naming no suite is served under apt_codename and answered from it; got %q: %s", r.Action, r.Reason)
	}
	if got, want := ve.Metadata[OSVMetaQueried], "source package expat in Ubuntu:22.04:LTS"; got != want {
		t.Errorf("stamped %q, want %q", got, want)
	}

	// A default OSV publishes nothing for is still unanswerable, and names the
	// codename rather than leaving the operator to guess where it came from.
	ck.DefaultAptSuite = "plucky"
	ve = &manifest.VersionEntry{Version: "2.4.7-1ubuntu0.2", SourceName: "expat"}
	if r := ck.Check(context.Background(), pm, ve); r.Action != ActionWarn || !strings.Contains(r.Reason, "plucky") {
		t.Errorf("want a warn naming plucky, got %q: %s", r.Action, r.Reason)
	}
}
