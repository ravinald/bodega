package policy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ulikunitz/xz"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// vuxmlFixture is a VuXML document in the shape vuxml.freebsd.org publishes,
// one entry per range operator plus the cases a distill must drop: a
// cancelled entry and a base-system entry.
const vuxmlFixture = `<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE vuxml PUBLIC "-//vuxml.org//DTD VuXML 1.1//EN" "http://www.vuxml.org/dtd/vuxml-1/vuxml-11.dtd">
<vuxml xmlns="http://www.vuxml.org/apps/vuxml-1">
  <vuln vid="11111111-aaaa-11ef-8000-000000000001">
    <topic>OpenSSL -- multiple
      vulnerabilities</topic>
    <affects>
      <package>
        <name>openssl</name>
        <name>openssl-quictls</name>
        <range><lt>3.0.15_1,1</lt></range>
        <range><ge>3.1,1</ge><lt>3.1.7,1</lt></range>
      </package>
    </affects>
    <description><body xmlns="http://www.w3.org/1999/xhtml"><p>Fixed&nbsp;upstream.</p></body></description>
    <references><cvename>CVE-2024-0001</cvename></references>
    <dates><discovery>2024-09-03</discovery><entry>2024-09-04</entry></dates>
  </vuln>
  <vuln vid="22222222-bbbb-11ef-8000-000000000002">
    <topic>curl -- one release</topic>
    <affects><package><name>curl</name><range><eq>8.9.1</eq></range></package></affects>
    <description><body xmlns="http://www.w3.org/1999/xhtml"><p>x</p></body></description>
    <references/><dates><discovery>2024-09-11</discovery><entry>2024-09-11</entry></dates>
  </vuln>
  <vuln vid="33333333-cccc-11ef-8000-000000000003">
    <topic>nginx -- bounded</topic>
    <affects><package><name>nginx</name><range><gt>1.20</gt><le>1.26.2_1,3</le></range></package></affects>
    <description><body xmlns="http://www.w3.org/1999/xhtml"><p>x</p></body></description>
    <references/><dates><discovery>2024-10-01</discovery><entry>2024-10-01</entry></dates>
  </vuln>
  <vuln vid="44444444-dddd-11ef-8000-000000000004">
    <topic>tree -- withdrawn</topic>
    <affects><package><name>tree</name><range><lt>9.0</lt></range></package></affects>
    <description><body xmlns="http://www.w3.org/1999/xhtml"><p>x</p></body></description>
    <references/><dates><discovery>2024-10-02</discovery><entry>2024-10-02</entry></dates>
    <cancelled superseded="11111111-aaaa-11ef-8000-000000000001"/>
  </vuln>
  <vuln vid="55555555-eeee-11ef-8000-000000000005">
    <topic>FreeBSD -- base system</topic>
    <affects><system><name>FreeBSD-kernel</name><range><lt>14.1_5</lt></range></system></affects>
    <description><body xmlns="http://www.w3.org/1999/xhtml"><p>x</p></body></description>
    <references/><dates><discovery>2024-10-03</discovery><entry>2024-10-03</entry></dates>
  </vuln>
</vuxml>
`

func xzFixture(t *testing.T, doc string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := xz.NewWriter(&buf)
	if err != nil {
		t.Fatalf("xz writer: %v", err)
	}
	if _, err := w.Write([]byte(doc)); err != nil {
		t.Fatalf("xz write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("xz close: %v", err)
	}
	return buf.Bytes()
}

// vuxmlDB syncs body, served at a URL that is not OSV's bucket, into a fresh
// database. The export base points somewhere that fails every request, so a
// sync reaching for <base>/FreeBSD/all.zip instead of the VuXML URL fails.
func vuxmlDB(t *testing.T, body []byte) (*OSVDatabase, OSVDBMeta, error) {
	t.Helper()
	var paths []string
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path != "/mirror/vuln.xml.xz" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(feed.Close)
	db := NewOSVDatabase(t.TempDir())
	db.ExportBase = feed.URL + "/osv-bucket"
	db.VuXMLURL = feed.URL + "/mirror/vuln.xml.xz"
	meta, err := db.Sync(context.Background(), VuXMLEcosystem)
	if err == nil && (len(paths) != 1 || paths[0] != "/mirror/vuln.xml.xz") {
		t.Fatalf("sync fetched %v, want the configured VuXML URL alone", paths)
	}
	return db, meta, err
}

func TestVuXMLSync_FetchesTheConfiguredURLAndDistills(t *testing.T) {
	db, meta, err := vuxmlDB(t, xzFixture(t, vuxmlFixture))
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if meta.Ecosystem != VuXMLEcosystem || !strings.HasSuffix(meta.Source, "/mirror/vuln.xml.xz") {
		t.Errorf("meta = %+v, want the FreeBSD ecosystem sourced from the configured URL", meta)
	}
	// Three live entries naming four packages; the cancelled and the
	// base-system entries are not among them.
	if meta.Records != 3 || meta.Packages != 4 {
		t.Errorf("records/packages = %d/%d, want 3/4", meta.Records, meta.Packages)
	}
	if got, err := db.Meta(VuXMLEcosystem); err != nil || got.Records != 3 {
		t.Errorf("Meta after sync = %+v, %v", got, err)
	}
	for _, name := range []string{"tree", "freebsd-kernel"} {
		if vulns, _, err := db.Match(VuXMLEcosystem, name, "1.0"); err != nil || len(vulns) != 0 {
			t.Errorf("%s matched %v (%v); cancelled and base-system entries are not distilled", name, vulns, err)
		}
	}
}

func TestVuXMLSync_UncompressedDocumentIsRead(t *testing.T) {
	if _, meta, err := vuxmlDB(t, []byte(vuxmlFixture)); err != nil || meta.Records != 3 {
		t.Fatalf("sync of plain XML = %+v, %v", meta, err)
	}
}

// An export that distills to no packages fails the sync and writes nothing,
// so the gate warns on a missing database instead of passing on an empty one.
func TestVuXMLSync_NoPackagesRefusesToWrite(t *testing.T) {
	baseOnly := `<vuxml xmlns="http://www.vuxml.org/apps/vuxml-1">
  <vuln vid="55555555-eeee-11ef-8000-000000000005"><topic>base</topic>
    <affects><system><name>FreeBSD-kernel</name><range><lt>14.1_5</lt></range></system></affects></vuln>
</vuxml>`
	db, _, err := vuxmlDB(t, xzFixture(t, baseOnly))
	if err == nil || !strings.Contains(err.Error(), "no packages") {
		t.Fatalf("sync of a package-less document = %v, want the no-packages refusal", err)
	}
	if _, err := db.Meta(VuXMLEcosystem); !errors.Is(err, ErrOSVDBMissing) {
		t.Errorf("Meta = %v, want ErrOSVDBMissing: nothing may be written", err)
	}
	ck := freeBSDChecker(db, ActionBlock)
	r := ck.Check(context.Background(), freeBSDPkg("openssl"), freeBSDEntry("3.0.16,1"))
	if r.Action != ActionWarn || !strings.Contains(r.Reason, "policy osv sync") {
		t.Errorf("with no database the gate must warn, naming the sync: %+v", r)
	}

	if _, _, err := vuxmlDB(t, []byte("<html><body>not found</body></html>")); err == nil {
		t.Errorf("a document with no <vuln> must fail the sync")
	}
}

func freeBSDChecker(db *OSVDatabase, action string) *OSVChecker {
	ck := NewOSVChecker(&fakeOSVStore{policies: map[string]audit.OSVPolicy{
		manifest.TypeFreeBSD: {Ecosystem: manifest.TypeFreeBSD, Action: action},
	}})
	ck.LocalDB = db
	return ck
}

func freeBSDPkg(name string) *manifest.PackageManifest {
	return &manifest.PackageManifest{Type: manifest.TypeFreeBSD, Name: name}
}

func freeBSDEntry(version string) *manifest.VersionEntry {
	return &manifest.VersionEntry{Version: version, Metadata: map[string]string{FreeBSDABIKey: "FreeBSD:14:amd64"}}
}

func TestVuXMLChecker_StaleDatabaseWarns(t *testing.T) {
	db, _, err := vuxmlDB(t, xzFixture(t, vuxmlFixture))
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	ck := freeBSDChecker(db, ActionBlock)
	// osv_api_fallback must not reach api.osv.dev for FreeBSD: it knows no
	// such ecosystem and would answer clean.
	ck.AllowAPIFallback = true
	ck.Endpoint = "http://127.0.0.1:1/unreachable"
	ck.MaxAge = 7 * 24 * time.Hour
	ck.Now = func() time.Time { return time.Now().Add(30 * 24 * time.Hour) }

	r := ck.Check(context.Background(), freeBSDPkg("openssl"), freeBSDEntry("3.0.16,1"))
	if r.Action != ActionWarn || !strings.Contains(r.Reason, "30d") {
		t.Fatalf("a clean answer from a stale VuXML copy must warn with its age: %+v", r)
	}
	r = ck.Check(context.Background(), freeBSDPkg("openssl"), freeBSDEntry("3.0.15,1"))
	if r.Action != ActionBlock {
		t.Errorf("stale data still names a vulnerable version: %+v", r)
	}
}

func TestVuXMLChecker_BlockNamesVidAndTopic(t *testing.T) {
	db, _, err := vuxmlDB(t, xzFixture(t, vuxmlFixture))
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	ck := freeBSDChecker(db, ActionBlock)
	r := ck.Check(context.Background(), freeBSDPkg("openssl"), freeBSDEntry("3.0.15,1"))
	if r.Action != ActionBlock {
		t.Fatalf("openssl 3.0.15,1 = %+v, want block", r)
	}
	const vid, topic = "11111111-aaaa-11ef-8000-000000000001", "OpenSSL -- multiple vulnerabilities"
	if !strings.Contains(r.Reason, vid+" ("+topic+")") {
		t.Errorf("reason must name the vid and its topic: %q", r.Reason)
	}
	if topics, _ := r.Details["topics"].(map[string]string); topics[vid] != topic {
		t.Errorf("details topics = %#v", r.Details["topics"])
	}

	ck = freeBSDChecker(db, ActionWarn)
	if r := ck.Check(context.Background(), freeBSDPkg("openssl"), freeBSDEntry("3.0.15,1")); r.Action != ActionWarn {
		t.Errorf("under warn = %+v, want warn", r)
	}
	if r := ck.Check(context.Background(), freeBSDPkg("openssl"), freeBSDEntry("3.0.15_1,1")); r.Action != ActionPass {
		t.Errorf("the fixed revision = %+v, want pass", r)
	}
}

// A freebsd manifest entry is a repository whose version is an ABI. It passes
// as it always has, and is never looked up as if the ABI were a version.
func TestVuXMLChecker_RepositoryEntryIsNotLookedUp(t *testing.T) {
	ck := freeBSDChecker(nil, ActionBlock)
	r := ck.Check(context.Background(), &manifest.PackageManifest{Type: manifest.TypeFreeBSD, Name: "latest"},
		&manifest.VersionEntry{Version: "FreeBSD:14:amd64"})
	if r.Action != ActionPass {
		t.Errorf("repository entry = %+v, want pass", r)
	}
	if OSVCovers(manifest.TypeFreeBSD) {
		t.Errorf("OSVCovers(freebsd) answers for manifest entries, which no advisory covers")
	}
	found := false
	for _, eco := range OSVEcosystems() {
		found = found || eco == manifest.TypeFreeBSD
	}
	if !found {
		t.Errorf("OSVEcosystems() = %v, want freebsd among them so a policy row can be set", OSVEcosystems())
	}
}

func TestVuXMLMatch_RangeOperators(t *testing.T) {
	db, _, err := vuxmlDB(t, xzFixture(t, vuxmlFixture))
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	for _, tc := range []struct {
		name, version string
		hit           bool
	}{
		{"openssl", "3.0.15,1", true},    // lt: below the fixed revision
		{"openssl", "3.0.15_1,1", false}, // lt: the fix itself
		{"openssl", "3.0.14_3,1", true},  // lt: an older revision
		{"openssl", "3.0.16,1", false},   // between the two ranges
		{"openssl", "3.1.6,1", true},     // ge+lt: inside the second range
		{"openssl", "3.1.7,1", false},    // ge+lt: the second range's fix
		{"openssl", "3.9", true},         // epoch 0 sorts below every bound carrying epoch 1
		{"openssl-quictls", "3.0.1,1", true},
		{"OpenSSL", "3.0.1,1", false},  // pkg audit compares names case-sensitively
		{"curl", "8.9.1", true},        // eq
		{"curl", "8.9.1_1", false},     // eq: another revision
		{"nginx", "1.20", false},       // gt: the bound itself
		{"nginx", "1.20.1", true},      // gt
		{"nginx", "1.26.2_1,3", true},  // le: the bound itself
		{"nginx", "1.26.2_2,3", false}, // le: above it
		{"nginx", "1.26.3,3", false},   // le: above it
		{"py311-django", "4.2", false}, // in no entry
	} {
		vulns, skipped, err := db.Match(VuXMLEcosystem, tc.name, tc.version)
		if err != nil || len(skipped) != 0 {
			t.Fatalf("Match(%s, %s) = %v, skipped %v", tc.name, tc.version, err, skipped)
		}
		if (len(vulns) > 0) != tc.hit {
			t.Errorf("Match(%s, %s) = %v, want hit %v", tc.name, tc.version, vulns, tc.hit)
		}
	}
}

func TestComparePkgVersions(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		// The epoch decides first, then the version, then the revision.
		{"3.0.15_1,1", "3.0.15,1", 1},
		{"3.0.15_1,1", "3.0.16,1", -1},
		{"openssl-3.0.15_1,1", "3.0.15,1", 1},
		{"2.0", "1.0,1", -1},
		{"1.0,2", "1.0_9,1", 1},
		{"5.36.0.1", "5.36.0_1", 1},
		{"1.0_1", "1.0.0", 1},
		{"1.0_10", "1.0_9", 1},
		// Alpha, beta, pre and rc sort below the release and in that order.
		{"1.0alpha1", "1.0", -1},
		{"1.0alpha1", "1.0beta1", -1},
		{"1.0beta2", "1.0pre1", -1},
		{"1.0rc1", "1.0beta2", 1},
		{"1.0rc", "1.0", -1},
		{"1.0snap1", "1.0rc1", 1},
		{"1.0snap20240101", "1.0.1", -1},
		{"1.0.r", "1.0rc", 0},
		// A patch letter sorts above the release; pl below it.
		{"1.0a", "1.0", 1},
		{"1.1.1w", "1.1.1", 1},
		{"1.1.1w", "1.1.1v", 1},
		{"8.2p1", "8.2", 1},
		{"1.0pre1", "1.0p1", -1},
		{"1.0g", "1.0beta", 1},
		{"1.0pl1", "1.0", -1},
		{"1.0pl1", "1.0a", -1},
		{"1.0.b", "1.0b", -1},
		{"1.0.0b", "1.0.0.b", 1},
		{"1.0b2", "1.0b10", -1},
		// Trailing zeros and '+' are no difference.
		{"1.0", "1.0.0", 0},
		{"1.0+", "1.0", 0},
		{"3.0.15", "openssl-3.0.15", 0},
	} {
		if got, ok := comparePkgVersions(tc.a, tc.b); !ok || got != tc.want {
			t.Errorf("comparePkgVersions(%q, %q) = %d, %v; want %d", tc.a, tc.b, got, ok, tc.want)
		}
		if got, _ := comparePkgVersions(tc.b, tc.a); got != -tc.want {
			t.Errorf("comparePkgVersions(%q, %q) = %d; want %d (antisymmetry)", tc.b, tc.a, got, -tc.want)
		}
	}
}

// distillVuXML reads from disk, so a file that is not there is an error, not
// an empty index.
func TestDistillVuXML_MissingFile(t *testing.T) {
	if _, _, err := distillVuXML(t.TempDir() + "/absent.xml"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("distillVuXML(missing) = %v, want ErrNotExist", err)
	}
}

func TestReviewVuXMLNamePatterns(t *testing.T) {
	doc := strings.Replace(vuxmlFixture, "<name>openssl</name>", "<name>openssl*</name>", 1)
	db, _, err := vuxmlDB(t, []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	r := freeBSDChecker(db, ActionBlock).Check(context.Background(), freeBSDPkg("openssl"), freeBSDEntry("3.0.15,1"))
	if r.Action != ActionBlock {
		t.Fatalf("openssl* advisory against openssl@3.0.15,1: action=%s; want block", r.Action)
	}
}

func TestReviewVuXMLNamesAreCaseSensitive(t *testing.T) {
	db, _, err := vuxmlDB(t, []byte(vuxmlFixture))
	if err != nil {
		t.Fatal(err)
	}
	r := freeBSDChecker(db, ActionBlock).Check(context.Background(), freeBSDPkg("OpenSSL"), freeBSDEntry("3.0.15,1"))
	if r.Action != ActionPass {
		t.Fatalf("openssl advisory against distinct package OpenSSL: action=%s; want pass", r.Action)
	}
}

func TestReviewPkgSnapOrdering(t *testing.T) {
	if got, ok := comparePkgVersions("1.0snap1", "1.0"); !ok || got != -1 {
		t.Fatalf("comparePkgVersions(1.0snap1, 1.0) = %d, %v; pkg 2.8.4 returns -1", got, ok)
	}
}

// A vid naming a package both literally and through a pattern is one record,
// and fnmatch's "[!" negation and '?' read as pkg reads them.
func TestVuXMLMatch_PatternNames(t *testing.T) {
	const doc = `<vuxml>
<vuln vid="pat-1"><topic>both</topic><affects><package><name>libfoo</name><name>libfoo*</name><range><lt>2.0</lt></range></package></affects></vuln>
<vuln vid="pat-2"><topic>class</topic><affects><package><name>py3[!8]-bar</name><range><lt>1.0</lt></range></package></affects></vuln>
<vuln vid="pat-3"><topic>one char</topic><affects><package><name>php8?-baz</name></package></affects></vuln>
</vuxml>`
	db, _, err := vuxmlDB(t, []byte(doc))
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	for _, tc := range []struct {
		name, version string
		want          []string
	}{
		{"libfoo", "1.0", []string{"pat-1"}},
		{"libfoo-devel", "1.0", []string{"pat-1"}},
		{"libfoo", "2.0", nil},
		{"LibFoo", "1.0", nil},
		{"py39-bar", "0.5", []string{"pat-2"}},
		{"py38-bar", "0.5", nil},
		{"php83-baz", "8.3.1", []string{"pat-3"}},
		{"php8-baz", "8.3.1", nil},
	} {
		vulns, skipped, err := db.Match(VuXMLEcosystem, tc.name, tc.version)
		if err != nil || len(skipped) != 0 {
			t.Fatalf("Match(%s, %s) = %v, skipped %v", tc.name, tc.version, err, skipped)
		}
		var got []string
		for _, v := range vulns {
			got = append(got, v.ID)
		}
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("Match(%s, %s) = %v, want %v", tc.name, tc.version, got, tc.want)
		}
	}
}

func TestReviewVuXMLBracketLiterals(t *testing.T) {
	for _, tc := range []struct{ pattern, name string }{
		{"libfoo[-ab]*", "libfoo-devel"},
		{"libfoo[ab-]*", "libfoo-devel"},
		{"libfoo[]a]*", "libfooa"},
		{"libfoo[!]-]*", "libfooa"},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			doc := `<vuxml><vuln vid="bracket-vid"><topic>libfoo affected</topic><affects><package><name>` + tc.pattern + `</name><range><lt>2.0</lt></range></package></affects></vuln></vuxml>`
			db, _, err := vuxmlDB(t, []byte(doc))
			if err != nil {
				t.Fatal(err)
			}
			r := freeBSDChecker(db, ActionBlock).Check(context.Background(), freeBSDPkg(tc.name), freeBSDEntry("1.0"))
			if r.Action != ActionBlock {
				t.Fatalf("%s advisory against %s@1.0: action=%s; want block (FreeBSD fnmatch returns 0)", tc.pattern, tc.name, r.Action)
			}
			r = freeBSDChecker(db, ActionBlock).Check(context.Background(), freeBSDPkg(tc.name), freeBSDEntry("2.0"))
			if r.Action != ActionPass {
				t.Fatalf("fixed version: %+v; want pass", r)
			}
		})
	}
}

// Each want is FreeBSD 14.3 libc fnmatch(pattern, name, 0) == 0, run in the
// C locale.
func TestVuXMLNameMatches_FollowsFreeBSDFnmatch(t *testing.T) {
	for _, tc := range []struct {
		pattern, name string
		want          bool
	}{
		{"openssl", "openssl", true},
		{"openssl", "OpenSSL", false},
		{"openssl*", "openssl-devel", true},
		{"py3?-django", "py311-django", false},
		{"py3??-django", "py311-django", true},
		{"*", "", true},
		{"a*b*c", "aXbYbc", true},
		{"a*b*c", "aXbYbd", false},
		{"lib[a-c]x", "libbx", true},
		{"lib[a-c]x", "libdx", false},
		{"lib[!a-c]x", "libdx", true},
		{"lib[^a-c]x", "libbx", false},
		{"lib[-ab]", "lib-", true},
		{"lib[ab-]", "lib-", true},
		{"lib[]a]", "lib]", true},
		{"lib[!]a]", "lib]", false},
		{"lib[!]a]", "libz", true},
		{"lib[a-]", "lib-", true},
		{"lib[\\]]", "lib]", true},
		{"lib[a-\\z]", "liby", true},
		{"lib[", "lib[", true},
		{"lib[ab", "lib[ab", true},
		{"lib[ab", "liba", false},
		{"lib[]", "lib[]", true},
		{"lib[!]", "lib[!]", true},
		{"lib\\*", "lib*", true},
		{"lib\\*", "libx", false},
		{"lib\\", "lib\\", false},
		{"a/b*", "a/bc", true},
		{"*.x", ".x", true},
		{"[[:alpha:]]", "a", true},
		{"[[:alpha:]]", "a]", false},
		{"lib[[:digit:]-]", "lib-", true},
		{"[[:alpha:]a-z]", "b", true},
		{"[[:digit:]a-z]", "b", false},
		{"[[:digit:]a-z]", "[:a-z]", true},
		{"[[:bogus:]]", "[:]", true},
		{"[[:bogus:]]", "[:bogus:]]", false},
		{"[[.a.]-c]", "b", true},
		{"[[=a=]-c]", "b", false},
		{"lib[a\\]]", "liba", false},
		{"lib[a\\]]", "liba]", true},
		{"[\xe9]", "\xe9", true},
		{"[[:alpha:]]", "\xe9", false},
	} {
		if got := vuxmlNameMatches(tc.pattern, tc.name); got != tc.want {
			t.Errorf("vuxmlNameMatches(%q, %q) = %v; want %v", tc.pattern, tc.name, got, tc.want)
		}
	}
}

func TestVuXMLMatch_PatternKeyIsNotMatchedByEquality(t *testing.T) {
	doc := `<vuxml><vuln vid="eq-vid"><topic>bracket name</topic><affects><package><name>lib[x]</name><range><lt>2.0</lt></range></package></affects></vuln></vuxml>`
	db, _, err := vuxmlDB(t, []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"libx": ActionBlock, "lib[x]": ActionPass} {
		if r := freeBSDChecker(db, ActionBlock).Check(context.Background(), freeBSDPkg(name), freeBSDEntry("1.0")); r.Action != want {
			t.Errorf("lib[x] advisory against %s@1.0: action=%s; want %s", name, r.Action, want)
		}
	}
}

// TestVuXMLNameMatches_AgreesWithFreeBSD15Libc replays fnmatch results
// measured on FreeBSD 15.1 libc, so the port is held to the reference rather
// than to cases somebody thought to write down.
func TestVuXMLNameMatches_AgreesWithFreeBSD15Libc(t *testing.T) {
	f, err := os.Open("testdata/vuxml/fnmatch15.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	cases := 0
	for line := 1; sc.Scan(); line++ {
		if strings.HasPrefix(sc.Text(), "#") {
			continue
		}
		fields := strings.Split(sc.Text(), "\t")
		if len(fields) != 3 {
			t.Fatalf("fnmatch15.tsv:%d: %d fields; want 3", line, len(fields))
		}
		pattern, perr := strconv.Unquote(fields[0])
		name, nerr := strconv.Unquote(fields[1])
		if perr != nil || nerr != nil {
			t.Fatalf("fnmatch15.tsv:%d: unquote: %v %v", line, perr, nerr)
		}
		cases++
		if got, want := vuxmlNameMatches(pattern, name), fields[2] == "1"; got != want {
			t.Errorf("fnmatch15.tsv:%d: vuxmlNameMatches(%q, %q) = %v; FreeBSD 15 libc says %v", line, pattern, name, got, want)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if cases < 3000 {
		t.Fatalf("read %d cases; the reference holds over 3000", cases)
	}
}

func TestReviewVuXMLFreeBSD15CharacterClasses(t *testing.T) {
	for _, tc := range []struct{ pattern, name string }{
		{"lib[[:alpha:]]", "liba"},
		{"lib[[:digit:]]", "lib3"},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			doc := `<vuxml><vuln vid="class-vid"><topic>class package affected</topic><affects><package><name>` + tc.pattern + `</name><range><lt>2.0</lt></range></package></affects></vuln></vuxml>`
			db, _, err := vuxmlDB(t, []byte(doc))
			if err != nil {
				t.Fatal(err)
			}
			ve := freeBSDEntry("1.0")
			ve.Metadata[FreeBSDABIKey] = "FreeBSD:15:amd64"
			r := freeBSDChecker(db, ActionBlock).Check(context.Background(), freeBSDPkg(tc.name), ve)
			if r.Action != ActionBlock {
				t.Fatalf("%s advisory against %s@1.0 for %s: action=%s; want block (FreeBSD 15 fnmatch returns 0)", tc.pattern, tc.name, ve.Metadata[FreeBSDABIKey], r.Action)
			}
			ve.Version = "2.0"
			r = freeBSDChecker(db, ActionBlock).Check(context.Background(), freeBSDPkg(tc.name), ve)
			if r.Action != ActionPass {
				t.Fatalf("fixed version: %+v; want pass", r)
			}
		})
	}
}
