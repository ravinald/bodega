package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"
	"unsafe"
)

// osvShareFanout is the shape the captured fixtures cannot supply: one
// advisory naming two binary packages of one source, which is how a distro
// export spends 772,549 record entries on 36,268 advisories. Every payload
// that repeats in testdata/osv repeats under a single package key instead
// (pyyaml under two advisory ids, gogo/protobuf under two, time under two), so
// the case sharing exists for has no captured example to assert on.
//
// SHARE-3 carries SHARE-1's payload under a different id, which is what keeps
// the payload assertion honest: SHARE-1's two packages read one shared record
// and would satisfy a payload comparison whatever the payload table did.
const osvShareFanout = `[
 {"id": "SHARE-1",
  "affected": [
   {"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "libfoo1"},
    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]},
   {"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "libfoo-dev"},
    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]},
 {"id": "SHARE-2",
  "affected": [
   {"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "libbar1"},
    "versions": ["9:99-1"],
    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0-1"}]}]}]},
 {"id": "SHARE-3",
  "affected": [
   {"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "libqux1"},
    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}
]`

// TestOSVShareChangesNoValue is the whole correctness claim of sharing the
// decoded payload: it changes identity and never value, so the two shapes of
// one archive are the same index. Nothing narrower would do, because a table
// that returned the wrong payload would hand one advisory's ranges to another
// package and the gate would answer clean for a version that is affected,
// with no error anywhere for anyone to see.
func TestOSVShareChangesNoValue(t *testing.T) {
	saved := 0
	for _, pop := range osvSharePopulations(t) {
		db := fixtureDB(t, exportZip(t, "share-"+pop.name, pop.records), pop.ecosystems, trimEnumerated)
		for _, eco := range pop.ecosystems {
			shared := loadOSVIndex(t, db.dir, eco, true)
			plain := loadOSVIndex(t, db.dir, eco, false)

			entries, records, payloads := countOSVPayloads(shared)
			saved += (entries - records) + (entries - payloads)
			t.Logf("%s/%s: %d record entr(ies) over %d record and %d payload allocation(s)",
				pop.name, eco, entries, records, payloads)
			if _, r, p := countOSVPayloads(plain); r != entries || p != entries {
				t.Errorf("%s/%s: the unshared decode produced %d record and %d payload allocation(s) for %d entr(ies); the lever does not reach both tables",
					pop.name, eco, r, p, entries)
			}

			if !reflect.DeepEqual(shared, plain) {
				t.Errorf("%s/%s: sharing changed the index at %s", pop.name, eco, firstOSVDiff(t, shared, plain))
			}
		}
	}
	// A population where nothing was shared would deep-equal itself and report
	// a table that never fired as a table that works.
	if saved == 0 {
		t.Fatal("nothing in the whole population was shared; the comparison above proves nothing")
	}
}

// TestOSVShareOneCopyPerAdvisory asserts the invariant behind the figure,
// which is what can be pinned: the figure moves with the export, and that the
// decode canonicalized at all does not. Two packages of one source reached
// through different keys read one record, two advisories carrying one payload
// read one backing array, and both tables are gone by the time the index is
// returned. Each claim is made against the lever both ways, so a decode that
// shared whatever it was told not to fails here rather than quietly making
// every comparison in this file a comparison of one shape with itself.
func TestOSVShareOneCopyPerAdvisory(t *testing.T) {
	eco := "Ubuntu:22.04:LTS"
	db := fixtureDB(t, exportZip(t, "share-identity", []byte(osvShareFanout)), []string{eco}, trimEnumerated)

	idx := loadOSVIndex(t, db.dir, eco, true)
	if osvSharedAffected != nil || osvSharedRecords != nil {
		t.Error("a sharing table outlived the load; what it canonicalized is reachable through the index and the table is not")
	}
	for _, shape := range []struct {
		name  string
		idx   *osvIndex
		share bool
	}{
		{"shared", idx, true},
		{"unshared", loadOSVIndex(t, db.dir, eco, false), false},
	} {
		foo, dev := onlyOSVRecord(t, shape.idx, "libfoo1"), onlyOSVRecord(t, shape.idx, "libfoo-dev")
		qux := onlyOSVRecord(t, shape.idx, "libqux1")
		if !reflect.DeepEqual(foo, dev) || !reflect.DeepEqual(foo.Affected, qux.Affected) {
			t.Fatalf("%s: the fixture no longer carries one advisory under two packages and one payload under two advisories: %+v, %+v, %+v",
				shape.name, foo, dev, qux)
		}
		//nolint:gosec // G103: comparing data pointers is the whole assertion.
		// Nothing is dereferenced, written or converted.
		gotRecord, gotPayload := foo == dev, unsafe.SliceData(foo.Affected) == unsafe.SliceData(qux.Affected)
		if gotRecord != shape.share {
			t.Errorf("%s: one advisory reached through two package keys is shared=%v, want %v",
				shape.name, gotRecord, shape.share)
		}
		if gotPayload != shape.share {
			t.Errorf("%s: one payload reached through two advisories is shared=%v, want %v",
				shape.name, gotPayload, shape.share)
		}
	}
}

// osvValueIndex and osvValueRecord are the archive's value shape: records held
// by value under each package key, and each record's `affected` entries a
// plain slice rather than the named type that canonicalizes them. Sharing
// needed pointers, and both distill and the load path moved to them together,
// so every index in the process is now pointer-shaped and a comparison between
// two of them cannot see a pointer encoding that drifted. These two types are
// the fixed point that comparison needs: they never change with the decode,
// so a *osvRecord that stopped encoding as the record it points at fails
// TestOSVShareWritesTheSameArchive rather than silently rewriting archives.
type osvValueIndex struct {
	Ecosystem string                      `json:"ecosystem"`
	FetchedAt time.Time                   `json:"fetched_at"`
	Packages  map[string][]osvValueRecord `json:"packages"`
}

type osvValueRecord struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary,omitempty"`
	Severity []OSVSeverity `json:"severity,omitempty"`
	Affected []osvAffected `json:"affected"`
}

func valueShapedOSV(idx *osvIndex) *osvValueIndex {
	out := &osvValueIndex{
		Ecosystem: idx.Ecosystem,
		FetchedAt: idx.FetchedAt,
		Packages:  make(map[string][]osvValueRecord, len(idx.Packages)),
	}
	for key, recs := range idx.Packages {
		values := make([]osvValueRecord, len(recs))
		for i, rec := range recs {
			values[i] = osvValueRecord{
				ID: rec.ID, Summary: rec.Summary, Severity: rec.Severity,
				Affected: []osvAffected(rec.Affected),
			}
		}
		out.Packages[key] = values
	}
	return out
}

// TestOSVShareWritesTheSameArchive holds the line writeIndex depends on:
// sharing changes identity, so a loaded index has to encode to the bytes the
// distilled one it was written from encodes to, and both have to encode to
// what the value shape does. distill feeds writeIndex today; a future caller
// handing it an index it loaded must not write a different archive, and
// nothing in the load path would report it if it did.
func TestOSVShareWritesTheSameArchive(t *testing.T) {
	for _, pop := range osvSharePopulations(t) {
		zipPath := exportZip(t, "archive-"+pop.name, pop.records)
		distilled, _, err := distill(pop.ecosystems, zipPath, trimEnumerated)
		if err != nil {
			t.Fatal(err)
		}
		db := fixtureDB(t, zipPath, pop.ecosystems, trimEnumerated)
		for _, eco := range pop.ecosystems {
			// The distilled index carries no fetch time until fixtureDB
			// stamps its own copy, which is the one on disk.
			distilled[eco].FetchedAt = mustOSVIndex(t, db, eco).FetchedAt
			want := marshalOSV(t, distilled[eco])
			for _, share := range []bool{true, false} {
				loaded := loadOSVIndex(t, db.dir, eco, share)
				if got := marshalOSV(t, loaded); got != want {
					t.Errorf("%s/%s (shared=%v): a loaded index encodes to different bytes than the distilled one:\n%s\nwant\n%s",
						pop.name, eco, share, got, want)
				}
				if got := marshalOSV(t, valueShapedOSV(loaded)); got != want {
					t.Errorf("%s/%s (shared=%v): the pointer shape encodes to different bytes than the value shape:\n%s\nwant\n%s",
						pop.name, eco, share, got, want)
				}
			}
		}
	}
}

// osvSharePopulations is every export under testdata/osv plus the fan-out the
// captures do not carry; see osvShareFanout.
func osvSharePopulations(t *testing.T) []osvTrimPopulation {
	t.Helper()
	populations := []osvTrimPopulation{{
		name: "fanout", records: []byte(osvShareFanout), ecosystems: []string{"Ubuntu:22.04:LTS"},
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
	return populations
}

func mustOSVIndex(t *testing.T, db *OSVDatabase, ecosystem string) *osvIndex {
	t.Helper()
	idx, err := db.index(ecosystem)
	if err != nil {
		t.Fatalf("%s: %v", ecosystem, err)
	}
	return idx
}

// loadOSVIndex decodes one ecosystem out of dir in whichever of the two shapes
// is named, through a database of its own so the decode is never served from
// what an earlier load cached.
func loadOSVIndex(t *testing.T, dir, ecosystem string, share bool) *osvIndex {
	t.Helper()
	defer withOSVSharing(share)()
	idx, err := NewOSVDatabase(dir).index(ecosystem)
	if err != nil {
		t.Fatalf("%s (shared=%v): %v", ecosystem, share, err)
	}
	return idx
}

func withOSVSharing(share bool) func() {
	prev := osvShareDecoded
	osvShareDecoded = share
	return func() { osvShareDecoded = prev }
}

// countOSVPayloads reports the record entries an index holds, the distinct
// records they read from and the distinct backing arrays their payloads read
// from. The two allocation counts are what sharing moves and the entry count
// is what it leaves alone.
func countOSVPayloads(idx *osvIndex) (entries, records, payloads int) {
	recSeen, affSeen := map[*osvRecord]bool{}, map[*osvAffected]bool{}
	for _, recs := range idx.Packages {
		entries += len(recs)
		for _, rec := range recs {
			recSeen[rec] = true
			//nolint:gosec // G103: the data pointer is an identity, never read.
			affSeen[unsafe.SliceData(rec.Affected)] = true
		}
	}
	return entries, len(recSeen), len(affSeen)
}

// firstOSVDiff names the first package key the two indexes disagree on, so a
// failure reports a key rather than two megabytes of records.
func firstOSVDiff(t *testing.T, a, b *osvIndex) string {
	t.Helper()
	keys := make([]string, 0, len(a.Packages))
	for key := range a.Packages {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !reflect.DeepEqual(a.Packages[key], b.Packages[key]) {
			return key + ": " + marshalOSV(t, a.Packages[key]) + " against " + marshalOSV(t, b.Packages[key])
		}
	}
	if len(a.Packages) != len(b.Packages) {
		return "the package set"
	}
	return "a field outside Packages"
}

func onlyOSVRecord(t *testing.T, idx *osvIndex, name string) *osvRecord {
	t.Helper()
	recs := idx.Packages[osvPackageKey(idx.Ecosystem, name)]
	if len(recs) != 1 {
		t.Fatalf("%s: want one record, got %d", name, len(recs))
	}
	return recs[0]
}
