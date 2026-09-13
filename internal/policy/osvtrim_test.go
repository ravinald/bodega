package policy

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
	"unsafe"
)

// osvTrimPopulation is one export the trim is compared over: the records as
// OSV publishes them, and the ecosystems distilled out of them.
type osvTrimPopulation struct {
	name       string
	records    []byte
	ecosystems []string
}

// osvTrimAdversarial is the population the captured fixtures cannot supply.
// Every distro entry in testdata/osv is covered by its own ranges end to end,
// so a trim that dropped every enumerated string unconditionally agrees with
// the untrimmed index on all of them, and an assertion over those records
// alone reports a rule it never exercised. These entries reach outside their
// ranges under each of the three orderings, which is the case the per-string
// condition exists for.
const osvTrimAdversarial = `[
 {"id": "TRIM-SEMVER-1",
  "affected": [{"package": {"ecosystem": "npm", "name": "reaches-outside"},
   "versions": ["1.0.0", "2.0.0", "9.9.9"],
   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "3.0.0"}]}]}]},
 {"id": "TRIM-SEMVER-2",
  "affected": [{"package": {"ecosystem": "npm", "name": "enumerated-only"},
   "versions": ["1.2.3", "4.5.6"]}]},
 {"id": "TRIM-PEP440-1",
  "affected": [{"package": {"ecosystem": "PyPI", "name": "reaches-outside"},
   "versions": ["1.0", "1.5", "4.1.0-NA"],
   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}]},
 {"id": "TRIM-DEBIAN-1",
  "affected": [{"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "reaches-outside"},
   "versions": ["2.4.7-1ubuntu0.2", "2.4.7-1ubuntu0.3", "9:99-1"],
   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.4.7-1ubuntu0.4"}]}]}]}
]`

// TestOSVTrimChangesNoVerdict is what holds the line under trimCovered. The
// live oracles cover 5 distro pairs and 5 language cases between them; the trim
// touches every entry in every ecosystem, so the claim it needs is over a whole
// population rather than over a sample.
//
// Every version string the records name is queried against every package key,
// bounds included: a record's `fixed` boundary is where an off-by-one in the
// range walk would show, and no enumerated string ever sits on one.
func TestOSVTrimChangesNoVerdict(t *testing.T) {
	populations := []osvTrimPopulation{{
		name:       "adversarial",
		records:    []byte(osvTrimAdversarial),
		ecosystems: []string{"npm", "PyPI", "Ubuntu:22.04:LTS"},
	}}
	for _, source := range osvFixtureSources(t) {
		raw, err := os.ReadFile(filepath.Join("testdata", "osv", source+".json"))
		if err != nil {
			t.Fatal(err)
		}
		populations = append(populations, osvTrimPopulation{
			name: source, records: raw, ecosystems: osvFixtureEcosystems(source),
		})
	}

	for _, pop := range populations {
		zipPath := exportZip(t, pop.name, pop.records)
		trimmed := fixtureDB(t, zipPath, pop.ecosystems, trimEnumerated)
		kept := fixtureDB(t, zipPath, pop.ecosystems, keepEnumerated)
		versions := versionStrings(t, pop.records)

		for _, eco := range pop.ecosystems {
			before, after := countVersionStrings(t, kept, eco), countVersionStrings(t, trimmed, eco)
			t.Logf("%s/%s: %d enumerated version string(s) before the trim, %d after", pop.name, eco, before, after)
			// The adversarial population is the one that gives the comparison
			// below its teeth: a trim that kept everything or dropped
			// everything agrees with the untrimmed index on the captured
			// fixtures, whose lists never reach outside their ranges.
			if pop.name == "adversarial" && (after == 0 || after >= before) {
				t.Errorf("%s: %d string(s) of %d survived the trim; the comparison below proves nothing",
					eco, after, before)
			}

			idx, err := kept.index(eco)
			if err != nil {
				t.Fatalf("%s: %v", eco, err)
			}
			keys := make([]string, 0, len(idx.Packages))
			for key := range idx.Packages {
				keys = append(keys, key)
			}
			sort.Strings(keys)

			tidx, err := trimmed.index(eco)
			if err != nil {
				t.Fatalf("%s: %v", eco, err)
			}
			if len(tidx.Packages) != len(idx.Packages) {
				t.Errorf("%s: trim changed the package set: %d keys, want %d", eco, len(tidx.Packages), len(idx.Packages))
			}

			for _, key := range keys {
				for _, v := range versions {
					gotVulns, gotSkipped, err := trimmed.Match(eco, key, v)
					if err != nil {
						t.Fatalf("%s %s@%s: %v", eco, key, v, err)
					}
					wantVulns, wantSkipped, err := kept.Match(eco, key, v)
					if err != nil {
						t.Fatalf("%s %s@%s: %v", eco, key, v, err)
					}
					if !reflect.DeepEqual(gotVulns, wantVulns) {
						t.Errorf("%s %s@%s: trimmed index matched %v, untrimmed matched %v",
							eco, key, v, vulnIDs(gotVulns), vulnIDs(wantVulns))
					}
					if !reflect.DeepEqual(gotSkipped, wantSkipped) {
						t.Errorf("%s %s@%s: trimmed index skipped %v, untrimmed skipped %v",
							eco, key, v, gotSkipped, wantSkipped)
					}
				}
			}
		}
	}
}

// TestOSVTrimKeepsUnplaceableVersions defends the orderable guard, which no
// comparison of verdicts can: dropping a string the entry's ranges match never
// changes an answer, orderable or not, because the query of that same string
// walks those same ranges. What the guard buys is that the rule stands on its
// own rather than on osvRange.affects refusing a version it cannot place, and
// that an ecosystem ordering is never overruled by a SEMVER range carried in
// the same entry.
func TestOSVTrimKeepsUnplaceableVersions(t *testing.T) {
	// Real shapes: "4.1.0-NA" bounds pynetbox on PyPI and parses as semver
	// while PEP 440 refuses it.
	ranges := []osvRange{{Type: "SEMVER", Events: []osvEvent{{Introduced: "0"}}}}
	got := trimCovered(orderPEP440, []string{"1.0", "4.1.0-NA"}, ranges)
	if len(got) != 1 || got[0] != "4.1.0-NA" {
		t.Errorf("trimCovered kept %v, want only the version PEP 440 cannot place", got)
	}
	if kept := trimCovered(orderDebian, []string{"1:2.4.7-1ubuntu0.2"}, nil); len(kept) != 1 {
		t.Errorf("an entry with no range is the enumerated list or nothing; trim kept %v", kept)
	}
}

// TestOSVIndexRSS reports what one ecosystem costs a process that has checked
// a single version against it. The retained figure it prints is half the
// answer: the decode transient is larger and is what gets a host OOM-killed,
// and no test can print its own process peak, so this runs under a tool that
// reads it off the process.
//
//	go test -c -o /tmp/policy.test ./internal/policy
//	curl -sSLo /tmp/osv/Ubuntu.zip https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip
//	BODEGA_OSV_INDEX_RSS=1 BODEGA_OSV_LIVE_DIR=/tmp/osv \
//	  BODEGA_OSV_INDEX_ECOSYSTEM=Ubuntu:22.04:LTS \
//	  /usr/bin/time -l /tmp/policy.test -test.run TestOSVIndexRSS
//
// BODEGA_OSV_INDEX_UNTRIMMED=1 measures the pre-trim shape instead, out of a
// second database under <dir>/untrimmed, so both figures come off one host in
// one session rather than off two checkouts.
//
// It never syncs, because a harness that downloaded 650 MB would not be run
// twice: an archive it does not find it distills out of the export zip beside
// it (<dir>/Ubuntu.zip, which one curl serves for both shapes and for
// TestOSVLiveDistroAgreement), then stops. The run that measures decodes the
// archive and does nothing else.
func TestOSVIndexRSS(t *testing.T) {
	if os.Getenv("BODEGA_OSV_INDEX_RSS") == "" {
		t.Skip("set BODEGA_OSV_INDEX_RSS=1 to measure what one loaded ecosystem holds")
	}
	root := os.Getenv("BODEGA_OSV_LIVE_DIR")
	eco := os.Getenv("BODEGA_OSV_INDEX_ECOSYSTEM")
	if root == "" || eco == "" {
		t.Fatal("set BODEGA_OSV_LIVE_DIR to a synced directory and BODEGA_OSV_INDEX_ECOSYSTEM to one ecosystem in it")
	}
	trim := os.Getenv("BODEGA_OSV_INDEX_UNTRIMMED") == ""
	dir := root
	if !trim {
		dir = filepath.Join(root, "untrimmed")
	}

	db := NewOSVDatabase(dir)
	meta, err := db.Meta(eco)
	if err != nil {
		writeMeasuredIndex(t, root, dir, eco, trim)
		return
	}
	if meta.Trimmed != trim {
		t.Fatalf("%s in %s was written trimmed=%v, measurement wants trimmed=%v; delete it and re-run",
			eco, dir, meta.Trimmed, trim)
	}

	// One Match is what a server does on the first version it checks against
	// an ecosystem, and it is what decodes the archive.
	pkg, version := osvProbePackage(eco)
	vulns, skipped, err := db.Match(eco, pkg, version)
	if err != nil {
		t.Fatalf("%s match: %v", eco, err)
	}

	// Read the heap before counting anything: a walk that deduped ids would
	// allocate into the figure this exists to report.
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	retained := ms.HeapAlloc

	idx, err := db.index(eco)
	if err != nil {
		t.Fatalf("%s: %v", eco, err)
	}
	enumerated := 0
	for _, recs := range idx.Packages {
		for _, rec := range recs {
			for _, aff := range rec.Affected {
				enumerated += len(aff.Versions)
			}
		}
	}
	t.Logf("%s (trimmed=%v): retained %d MB, %d record(s), %d package(s), %d enumerated version string(s); %s@%s matched %v, skipped %v",
		eco, trim, retained>>20, meta.Records, len(idx.Packages), enumerated, pkg, version, vulnIDs(vulns), skipped)
	runtime.KeepAlive(idx)
}

// writeMeasuredIndex distills one ecosystem out of the export zip the operator
// already has and stops the run. Distilling and measuring in one process would
// report the export's peak rather than the archive's.
func writeMeasuredIndex(t *testing.T, root, dir, eco string, trim bool) {
	t.Helper()
	zipPath := filepath.Join(root, OSVExportSource(eco)+".zip")
	if _, err := os.Stat(zipPath); err != nil {
		t.Fatalf("no archive for %s in %s and no export to build one from:\n"+
			"  curl -sSLo %s %s/%s/all.zip",
			eco, dir, zipPath, DefaultOSVExportBase, OSVExportSource(eco))
	}
	indexes, records, err := distill([]string{eco}, zipPath, trim)
	if err != nil {
		t.Fatalf("distill %s: %v", eco, err)
	}
	idx := indexes[eco]
	if idx == nil || len(idx.Packages) == 0 {
		t.Fatalf("%s distilled to nothing out of %s", eco, zipPath)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	idx.FetchedAt = time.Now().UTC()
	db := NewOSVDatabase(dir)
	n, err := db.writeIndex(eco, idx)
	if err != nil {
		t.Fatalf("write %s: %v", eco, err)
	}
	if err := db.writeMeta(OSVDBMeta{
		Ecosystem: eco, Source: zipPath, FetchedAt: idx.FetchedAt,
		Records: records[eco], Packages: len(idx.Packages), Bytes: n, Trimmed: trim,
	}); err != nil {
		t.Fatalf("write %s meta: %v", eco, err)
	}
	t.Skipf("wrote %s (trimmed=%v, %d bytes); re-run to measure the decode alone", db.indexPath(eco), trim, n)
}

// osvProbePackage names a package the ecosystem carries, so the Match that
// decodes the archive returns a real answer rather than a miss indistinguishable
// from a broken harness. The agreement tables already name one per ecosystem.
func osvProbePackage(ecosystem string) (name, version string) {
	for _, tc := range osvLiveDistroCases {
		if tc.ecosystem == ecosystem {
			return tc.pkg, tc.versions[0]
		}
	}
	for _, tc := range osvAgreementCases {
		if tc.ecosystem == ecosystem {
			return tc.pkg, tc.vulnerable
		}
	}
	return "", "0"
}

// osvFixtureSources is every export under testdata/osv, checked against the
// ecosystems the tests distill out of it: a fixture nothing reads is a file
// that looks like coverage and is not.
func osvFixtureSources(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join("testdata", "osv"))
	if err != nil {
		t.Fatal(err)
	}
	var sources []string
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		source := strings.TrimSuffix(e.Name(), ".json")
		if len(osvFixtureEcosystems(source)) == 0 {
			t.Fatalf("fixture testdata/osv/%s distills into no ecosystem any test names", e.Name())
		}
		sources = append(sources, source)
	}
	return sources
}

// osvFixtureEcosystems is what one export distills into, drawn from the tables
// the agreement tests already read so the two populations cannot drift.
func osvFixtureEcosystems(source string) []string {
	var out []string
	for _, tc := range osvAgreementCases {
		if OSVExportSource(tc.ecosystem) == source {
			out = append(out, tc.ecosystem)
		}
	}
	for _, eco := range osvDistroFixtures {
		if OSVExportSource(eco) == source {
			out = append(out, eco)
		}
	}
	return out
}

// exportZip writes a set of OSV records out as OSV publishes them:
// <source>/all.zip, one JSON file per record.
func exportZip(t *testing.T, name string, records []byte) string {
	t.Helper()
	var recs []map[string]any
	if err := json.Unmarshal(records, &recs); err != nil {
		t.Fatalf("records %s: %v", name, err)
	}
	path := filepath.Join(t.TempDir(), name+".zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for i, rec := range recs {
		w, err := zw.Create(fmt.Sprintf("%d.json", i))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(w).Encode(rec); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// fixtureDB distills one export into a database of its own, in whichever of
// the two index shapes is named.
func fixtureDB(t *testing.T, zipPath string, ecosystems []string, trim bool) *OSVDatabase {
	t.Helper()
	indexes, _, err := distill(ecosystems, zipPath, trim)
	if err != nil {
		t.Fatal(err)
	}
	db := NewOSVDatabase(t.TempDir())
	for _, eco := range ecosystems {
		idx := indexes[eco]
		if idx == nil || len(idx.Packages) == 0 {
			t.Fatalf("%s distilled to nothing out of %s", eco, zipPath)
		}
		idx.FetchedAt = time.Now().UTC()
		if _, err := db.writeIndex(eco, idx); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// versionStrings is every version a set of records names: the enumerated
// lists and every range bound, deduped and sorted.
func versionStrings(t *testing.T, raw []byte) []string {
	t.Helper()
	var records []struct {
		Affected []struct {
			Versions []string   `json:"versions"`
			Ranges   []osvRange `json:"ranges"`
		} `json:"affected"`
	}
	if err := json.Unmarshal(raw, &records); err != nil {
		t.Fatalf("records: %v", err)
	}
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	for _, rec := range records {
		for _, aff := range rec.Affected {
			for _, v := range aff.Versions {
				add(v)
			}
			for _, r := range aff.Ranges {
				for _, e := range r.Events {
					add(e.Introduced)
					add(e.Fixed)
					add(e.LastAffected)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

func countVersionStrings(t *testing.T, db *OSVDatabase, ecosystem string) int {
	t.Helper()
	idx, err := db.index(ecosystem)
	if err != nil {
		t.Fatalf("%s: %v", ecosystem, err)
	}
	n := 0
	for _, recs := range idx.Packages {
		for _, rec := range recs {
			for _, aff := range rec.Affected {
				n += len(aff.Versions)
			}
		}
	}
	return n
}

// TestOSVIndexInternsSharedStrings asserts the invariant rather than a number:
// two equal strings reached through different records of one loaded index are
// one allocation. The figure it stands behind moves with the export and cannot
// be pinned in a test; what can be pinned is that the decode canonicalized at
// all, which is the whole of interning's contribution.
//
// A distro ecosystem, because that is where beginOSVDecode turns interning on
// and where a record repeats per package. The range bounds carry it there: the
// enumerated lists are empty after trimCovered, so a check on versions alone
// would pass on an index where nothing was interned.
func TestOSVIndexInternsSharedStrings(t *testing.T) {
	const records = `[
 {"id": "INTERN-1",
  "affected": [{"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "alpha"},
   "versions": ["9:99-1"],
   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0-1"}]}]}]},
 {"id": "INTERN-2",
  "affected": [{"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "beta"},
   "versions": ["9:99-1"],
   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0-1"}]}]}]}
]`
	eco := "Ubuntu:22.04:LTS"
	db := fixtureDB(t, exportZip(t, "intern", []byte(records)), []string{eco}, trimEnumerated)
	idx, err := db.index(eco)
	if err != nil {
		t.Fatal(err)
	}

	first := func(key, field string) string {
		recs := idx.Packages[key]
		if len(recs) != 1 || len(recs[0].Affected) != 1 {
			t.Fatalf("%s: want one record with one affected entry, got %+v", key, recs)
		}
		aff := recs[0].Affected[0]
		if field == "version" {
			if len(aff.Versions) != 1 {
				t.Fatalf("%s: the trim dropped a version its ranges do not cover: %v", key, aff.Versions)
			}
			return aff.Versions[0]
		}
		return aff.Ranges[0].Events[1].Fixed
	}

	for _, field := range []string{"version", "bound"} {
		a, b := first("alpha", field), first("beta", field)
		if a != b {
			t.Fatalf("%s: %q and %q are not the same string; the fixture is wrong", field, a, b)
		}
		//nolint:gosec // G103: comparing the two strings' data pointers is the
		// whole assertion. Nothing is dereferenced, written or converted.
		if unsafe.StringData(a) != unsafe.StringData(b) {
			t.Errorf("%s %q reached through two records is two allocations; the decode interned nothing", field, a)
		}
	}

	if osvCanon != nil {
		t.Error("the intern table outlived the load; the canonical strings are reachable through the index and the table is not")
	}
}
