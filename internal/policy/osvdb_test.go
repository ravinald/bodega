package policy

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// osvAgreementCases pins the local matcher to what api.osv.dev answered for
// the same triple. ids is the live API's verdict, captured with the fixtures
// in testdata/osv; the fixture files are those records as OSV publishes them,
// minus the prose fields sync drops anyway (details, references, credits).
//
// A new advisory against one of these packages changes what the live API
// returns and does not change the fixtures, which is why the comparison
// against the live service is its own opt-in test (TestOSVLiveAgreement).
var osvAgreementCases = []osvAgreementCase{
	{
		registryType: manifest.TypeNpm,
		ecosystem:    "npm",
		pkg:          "minimist",
		vulnerable:   "1.2.0",
		ids:          []string{"GHSA-vh95-rmgr-6w4m", "GHSA-xvch-5gv4-984h"},
		clean:        "1.2.8",
	},
	{
		registryType: manifest.TypePypi,
		ecosystem:    "PyPI",
		// Queried under the published spelling: the index is keyed per PEP
		// 503, so an import carrying "PyYAML" has to reach the pyyaml records.
		pkg:        "PyYAML",
		vulnerable: "5.3",
		ids:        []string{"GHSA-6757-jp84-gxfx", "GHSA-8q59-q68h-6hv4", "PYSEC-2020-96", "PYSEC-2021-142"},
		clean:      "6.0",
	},
	{
		registryType: manifest.TypeGomod,
		ecosystem:    "Go",
		pkg:          "github.com/gogo/protobuf",
		vulnerable:   "1.3.1",
		ids:          []string{"GHSA-c3h9-896r-86jm", "GO-2021-0053"},
		clean:        "1.3.2",
	},
	{
		registryType: manifest.TypeCargo,
		ecosystem:    "crates.io",
		pkg:          "time",
		vulnerable:   "0.1.44",
		ids:          []string{"GHSA-wcg3-cvx6-7396", "RUSTSEC-2020-0071"},
		clean:        "0.2.23",
	},
}

// osvAgreementCase is one (ecosystem, package, version) pair the local matcher
// has to answer exactly as api.osv.dev does.
//
// No Ubuntu or Debian release is a case here. Every distro package carries
// advisories nobody has fixed yet, so no version of one is ever clean, and the
// clean half of this table is a claim about api.osv.dev rather than about a
// frozen fixture. TestOSVLiveDistroAgreement makes the distro comparison
// against the live service directly.
type osvAgreementCase struct {
	registryType string
	ecosystem    string
	pkg          string
	vulnerable   string
	ids          []string
	clean        string
}

// osvDistroFixtures are the releases syncedDB writes beside the agreement
// cases, distilled out of the Ubuntu and Debian fixtures the same way a real
// sync distills them out of the aggregate archive.
var osvDistroFixtures = []string{"Ubuntu:22.04:LTS", "Ubuntu:24.04:LTS", "Debian:12"}

// exportServer serves the testdata records as OSV's per-ecosystem export:
// <base>/<ecosystem>/all.zip, one JSON file per record.
func exportServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		eco := filepath.Base(filepath.Dir(r.URL.Path))
		raw, err := os.ReadFile(filepath.Join("testdata", "osv", OSVEcosystemFile(eco)+".json"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		var records []map[string]any
		if err := json.Unmarshal(raw, &records); err != nil {
			t.Errorf("fixture %s: %v", eco, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for _, rec := range records {
			f, err := zw.Create(rec["id"].(string) + ".json")
			if err != nil {
				t.Errorf("zip create: %v", err)
				return
			}
			if err := json.NewEncoder(f).Encode(rec); err != nil {
				t.Errorf("zip write: %v", err)
				return
			}
		}
		if err := zw.Close(); err != nil {
			t.Errorf("zip close: %v", err)
			return
		}
		_, _ = w.Write(buf.Bytes())
	}))
}

// syncedDB returns a database in a temp directory holding every fixture
// ecosystem, synced from a local stand-in for OSV's export bucket.
func syncedDB(t *testing.T) *OSVDatabase {
	t.Helper()
	srv := exportServer(t)
	t.Cleanup(srv.Close)
	db := NewOSVDatabase(t.TempDir())
	db.ExportBase = srv.URL
	ecosystems := make([]string, 0, len(osvAgreementCases)+len(osvDistroFixtures))
	for _, tc := range osvAgreementCases {
		ecosystems = append(ecosystems, tc.ecosystem)
	}
	ecosystems = append(ecosystems, osvDistroFixtures...)
	for _, res := range db.SyncGroup(context.Background(), ecosystems) {
		if res.Err != nil {
			t.Fatalf("sync %s: %v", res.Ecosystem, res.Err)
		}
	}
	return db
}

func TestOSVDatabase_SyncWritesArchiveAndMeta(t *testing.T) {
	db := syncedDB(t)
	for _, tc := range osvAgreementCases {
		meta, err := db.Meta(tc.ecosystem)
		if err != nil {
			t.Fatalf("meta %s: %v", tc.ecosystem, err)
		}
		if meta.Records == 0 || meta.Packages == 0 || meta.Bytes == 0 {
			t.Errorf("%s: sync reported nothing written: %+v", tc.ecosystem, meta)
		}
		if time.Since(meta.FetchedAt) > time.Minute {
			t.Errorf("%s: fetch timestamp not recorded: %v", tc.ecosystem, meta.FetchedAt)
		}
		if _, err := os.Stat(filepath.Join(db.Dir(), OSVEcosystemFile(tc.ecosystem)+".json.gz")); err != nil {
			t.Errorf("%s: archive missing: %v", tc.ecosystem, err)
		}
	}
}

func TestOSVDatabase_MissingEcosystemIsNotEmpty(t *testing.T) {
	db := NewOSVDatabase(t.TempDir())
	if _, err := db.Meta("npm"); !errors.Is(err, ErrOSVDBMissing) {
		t.Errorf("unsynced ecosystem must report missing, got %v", err)
	}
	if _, _, err := db.Match("npm", "lodash", "4.17.4"); !errors.Is(err, ErrOSVDBMissing) {
		t.Errorf("unsynced ecosystem must not answer 'no vulns', got %v", err)
	}
}

// TestOSVMatcher_AgreesWithAPI is the reason the local matcher is allowed to
// replace the query: for a known-vulnerable version in every mapped ecosystem
// it returns the id set api.osv.dev returned, and nothing for a fixed one.
func TestOSVMatcher_AgreesWithAPI(t *testing.T) {
	db := syncedDB(t)
	for _, tc := range osvAgreementCases {
		vulns, _, err := db.Match(tc.ecosystem, tc.pkg, tc.vulnerable)
		if err != nil {
			t.Fatalf("%s match: %v", tc.ecosystem, err)
		}
		got := vulnIDs(vulns)
		if len(got) != len(tc.ids) {
			t.Errorf("%s %s@%s: got %v, api.osv.dev returned %v", tc.ecosystem, tc.pkg, tc.vulnerable, got, tc.ids)
			continue
		}
		for i := range got {
			if got[i] != tc.ids[i] {
				t.Errorf("%s %s@%s: got %v, api.osv.dev returned %v", tc.ecosystem, tc.pkg, tc.vulnerable, got, tc.ids)
				break
			}
		}
		clean, _, err := db.Match(tc.ecosystem, tc.pkg, tc.clean)
		if err != nil {
			t.Fatalf("%s match: %v", tc.ecosystem, err)
		}
		if len(clean) != 0 {
			t.Errorf("%s %s@%s is fixed upstream; matcher reported %v", tc.ecosystem, tc.pkg, tc.clean, vulnIDs(clean))
		}
	}
}

// TestOSVChecker_LocalAndAPIVerdictsMatch drives the same version through both
// paths and compares the verdict, not just the id list: a local matcher that
// stamps different metadata than the API path is a different gate.
func TestOSVChecker_LocalAndAPIVerdictsMatch(t *testing.T) {
	db := syncedDB(t)
	for _, tc := range osvAgreementCases {
		store := &fakeOSVStore{policies: map[string]audit.OSVPolicy{
			tc.registryType: {Ecosystem: tc.registryType, Action: ActionBlock},
		}}

		local := NewOSVChecker(store)
		local.LocalDB = db
		localVE := &manifest.VersionEntry{Version: tc.vulnerable}
		localRes := local.Check(context.Background(),
			&manifest.PackageManifest{Name: tc.pkg, Type: tc.registryType}, localVE)

		vulns := make([]map[string]any, 0, len(tc.ids))
		for _, id := range tc.ids {
			vulns = append(vulns, map[string]any{"id": id})
		}
		var gotEco string
		srv := stubOSVRecords(t, &gotEco, vulns...)
		defer srv.Close()
		api := NewOSVChecker(store)
		api.Endpoint = srv.URL
		api.AllowAPIFallback = true
		apiVE := &manifest.VersionEntry{Version: tc.vulnerable}
		apiRes := api.Check(context.Background(),
			&manifest.PackageManifest{Name: tc.pkg, Type: tc.registryType}, apiVE)

		if localRes.Action != apiRes.Action {
			t.Errorf("%s: local action %q, api action %q", tc.ecosystem, localRes.Action, apiRes.Action)
		}
		if localRes.Action != ActionBlock {
			t.Errorf("%s: a known-vulnerable version must not pass: %+v", tc.ecosystem, localRes)
		}
		if localVE.Metadata["vetting.osv.vulns"] != apiVE.Metadata["vetting.osv.vulns"] {
			t.Errorf("%s: local stamped %q, api stamped %q", tc.ecosystem,
				localVE.Metadata["vetting.osv.vulns"], apiVE.Metadata["vetting.osv.vulns"])
		}
	}
}

func TestOSVChecker_NoLocalDatabaseWarns(t *testing.T) {
	store := &fakeOSVStore{policies: map[string]audit.OSVPolicy{
		manifest.TypeNpm: {Ecosystem: manifest.TypeNpm, Action: ActionBlock},
	}}
	ck := NewOSVChecker(store)
	ck.LocalDB = NewOSVDatabase(t.TempDir())
	// A live endpoint that would fail the test if the checker reached it.
	ck.Endpoint = "http://127.0.0.1:0/never"

	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "lodash", Type: manifest.TypeNpm},
		&manifest.VersionEntry{Version: "4.17.4"})
	if r.Action != ActionWarn {
		t.Fatalf("an unsynced database must warn, not %q: %+v", r.Action, r)
	}
	if !contains(r.Reason, "policy osv sync") {
		t.Errorf("reason must name the next step: %q", r.Reason)
	}
	if !contains(r.Reason, "osv_api_fallback") {
		t.Errorf("reason must say nothing was queried: %q", r.Reason)
	}
}

func TestOSVChecker_UnconfiguredDatabaseWarns(t *testing.T) {
	store := &fakeOSVStore{policies: map[string]audit.OSVPolicy{
		manifest.TypeNpm: {Ecosystem: manifest.TypeNpm, Action: ActionBlock},
	}}
	ck := NewOSVChecker(store) // LocalDB nil: osv_db_dir unset

	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "lodash", Type: manifest.TypeNpm},
		&manifest.VersionEntry{Version: "4.17.4"})
	if r.Action != ActionWarn {
		t.Fatalf("no configured database must warn, not %q: %+v", r.Action, r)
	}
	if !contains(r.Reason, "osv_db_dir") {
		t.Errorf("reason must name the key to set: %q", r.Reason)
	}
}

func TestOSVChecker_StaleDatabaseWarnsWithAge(t *testing.T) {
	db := syncedDB(t)
	store := &fakeOSVStore{policies: map[string]audit.OSVPolicy{
		manifest.TypeNpm: {Ecosystem: manifest.TypeNpm, Action: ActionBlock},
	}}
	ck := NewOSVChecker(store)
	ck.LocalDB = db
	ck.MaxAge = 7 * 24 * time.Hour
	ck.Now = func() time.Time { return time.Now().Add(30 * 24 * time.Hour) }

	// Clean under the stale copy: the answer is "unknown", not "fine".
	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "minimist", Type: manifest.TypeNpm},
		&manifest.VersionEntry{Version: "1.2.8"})
	if r.Action != ActionWarn {
		t.Fatalf("a stale database must not pass: %+v", r)
	}
	if !contains(r.Reason, "30d") || !contains(r.Reason, "policy osv sync") {
		t.Errorf("reason must carry the age and the next step: %q", r.Reason)
	}

	// A record the stale copy does hold still blocks, with the age noted.
	ve := &manifest.VersionEntry{Version: "1.2.0"}
	r = ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "minimist", Type: manifest.TypeNpm}, ve)
	if r.Action != ActionBlock {
		t.Fatalf("stale data still names a vulnerable version: %+v", r)
	}
	if !contains(r.Reason, "30d") {
		t.Errorf("a block from stale data must say so: %q", r.Reason)
	}
}

func TestOSVChecker_StaleFallsBackToAPIWhenAllowed(t *testing.T) {
	db := syncedDB(t)
	store := &fakeOSVStore{policies: map[string]audit.OSVPolicy{
		manifest.TypeNpm: {Ecosystem: manifest.TypeNpm, Action: ActionBlock},
	}}
	var gotEco string
	srv := stubOSVRecords(t, &gotEco, map[string]any{"id": "GHSA-fresh"})
	defer srv.Close()

	ck := NewOSVChecker(store)
	ck.LocalDB = db
	ck.Endpoint = srv.URL
	ck.AllowAPIFallback = true
	ck.Now = func() time.Time { return time.Now().Add(30 * 24 * time.Hour) }

	ve := &manifest.VersionEntry{Version: "1.2.8"}
	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "minimist", Type: manifest.TypeNpm}, ve)
	if r.Action != ActionBlock {
		t.Fatalf("fallback answer must be used: %+v", r)
	}
	if ve.Metadata["vetting.osv.vulns"] != "GHSA-fresh" {
		t.Errorf("stamp should carry the API's answer, got %q", ve.Metadata["vetting.osv.vulns"])
	}
}

// TestOSVRange_IntroducedZeroCoversPrereleases pins the rule a live
// comparison against api.osv.dev turned up: `introduced: "0"` means "from the
// beginning", so it has to cover versions that sort below 0.0.0. Reading it as
// the version 0 missed every Go pseudo-version and every 0.0.0-0 prerelease,
// and, worse, sorted the event after a fixed pseudo-version and turned a
// patched module back into a hit.
func TestOSVRange_IntroducedZeroCoversPrereleases(t *testing.T) {
	all := osvRange{Type: "SEMVER", Events: []osvEvent{{Introduced: "0"}}}
	fixed := osvRange{Type: "SEMVER", Events: []osvEvent{
		{Introduced: "0"}, {Fixed: "0.0.0-20250616164159-0593516c4cfa"},
	}}
	cases := []struct {
		name    string
		r       osvRange
		version string
		want    bool
	}{
		{"pseudo-version under an open range", all, "0.0.0-20260116051925-c62ab83c589e", true},
		{"prerelease under an open range", all, "0.0.0-0", true},
		{"release under an open range", all, "1.2.3", true},
		{"pseudo-version before the fix", fixed, "0.0.0-20250101000000-aaaaaaaaaaaa", true},
		{"pseudo-version at the fix", fixed, "0.0.0-20250616164159-0593516c4cfa", false},
		{"release after the fix", fixed, "136.1", false},
	}
	for _, tc := range cases {
		got, unorderable := tc.r.affects(orderSemver, tc.version)
		if unorderable != "" {
			t.Errorf("%s: affects(%q) could not order %q", tc.name, tc.version, unorderable)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: affects(%q) = %v, want %v", tc.name, tc.version, got, tc.want)
		}
	}
}

func TestOSVPackageKey(t *testing.T) {
	cases := []struct{ eco, in, want string }{
		{"PyPI", "PyYAML", "pyyaml"},
		{"PyPI", "zope.interface", "zope-interface"},
		{"PyPI", "ruamel_.yaml", "ruamel-yaml"},
		{"npm", "Lodash", "lodash"},
		{"Go", "github.com/Masterminds/semver", "github.com/Masterminds/semver"},
	}
	for _, tc := range cases {
		if got := osvPackageKey(tc.eco, tc.in); got != tc.want {
			t.Errorf("osvPackageKey(%q, %q) = %q, want %q", tc.eco, tc.in, got, tc.want)
		}
	}
}

// recordServer serves an arbitrary record set as an ecosystem export, so a
// test can stand in for a second sync that found something new.
func recordServer(t *testing.T, records []map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for _, rec := range records {
			f, err := zw.Create(rec["id"].(string) + ".json")
			if err != nil {
				t.Errorf("zip create: %v", err)
				return
			}
			if err := json.NewEncoder(f).Encode(rec); err != nil {
				t.Errorf("zip write: %v", err)
				return
			}
		}
		if err := zw.Close(); err != nil {
			t.Errorf("zip close: %v", err)
			return
		}
		_, _ = w.Write(buf.Bytes())
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestOSVDatabase_ReloadsAfterOutOfProcessSync pins the case the cache gets
// wrong on its own: `policy osv sync` is a separate process from the server
// enforcing the gate, so a database that trusted its first load would report
// the fresh fetch time Meta reads off disk while matching against the copy it
// held before the sync. A gate that answers from data it has already been told
// is superseded is the silent-stale failure the warn path exists to prevent.
func TestOSVDatabase_ReloadsAfterOutOfProcessSync(t *testing.T) {
	dir := t.TempDir()
	serving := NewOSVDatabase(dir) // the long-running server
	syncing := NewOSVDatabase(dir) // `bodega policy osv sync`

	srv := recordServer(t, []map[string]any{{
		"id": "GHSA-old", "affected": []map[string]any{{
			"package":  map[string]any{"name": "lodash", "ecosystem": "npm"},
			"versions": []string{"4.17.4"},
		}},
	}})
	syncing.ExportBase = srv.URL
	if _, err := syncing.Sync(context.Background(), "npm"); err != nil {
		t.Fatalf("first sync: %v", err)
	}

	got, _, err := serving.Match("npm", "lodash", "4.17.4")
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if len(got) != 1 || got[0].ID != "GHSA-old" {
		t.Fatalf("first match: %v", vulnIDs(got))
	}

	// A second sync, in its own process, finds a newly disclosed advisory.
	srv2 := recordServer(t, []map[string]any{{
		"id": "GHSA-old", "affected": []map[string]any{{
			"package":  map[string]any{"name": "lodash", "ecosystem": "npm"},
			"versions": []string{"4.17.4"},
		}},
	}, {
		"id": "GHSA-new", "affected": []map[string]any{{
			"package":  map[string]any{"name": "lodash", "ecosystem": "npm"},
			"versions": []string{"4.17.4"},
		}},
	}})
	syncing.ExportBase = srv2.URL
	if _, err := syncing.Sync(context.Background(), "npm"); err != nil {
		t.Fatalf("second sync: %v", err)
	}

	got, _, err = serving.Match("npm", "lodash", "4.17.4")
	if err != nil {
		t.Fatalf("match after sync: %v", err)
	}
	if ids := vulnIDs(got); len(ids) != 2 {
		t.Errorf("a synced advisory must be visible to a process that already loaded the ecosystem; got %v", ids)
	}
}

func TestSharedOSVDatabase(t *testing.T) {
	dir := t.TempDir()
	if a, b := SharedOSVDatabase(dir), SharedOSVDatabase(dir); a != b {
		t.Error("one directory handed out two databases, so the index cache is per-caller")
	}
	if SharedOSVDatabase("  ") != nil {
		t.Error("an unconfigured directory must read as no local database, not an empty one")
	}
}

// TestOSVMatcher_UnorderableBoundIsSkippedNotMatched pins the two halves of
// the rule against records OSV publishes today. PYSEC-2024-325 bounds pynetbox
// with "4.1.0-NA", which no ordering can place; comparing it as a string put
// every 4.1.0 below the bound and blocked an import api.osv.dev answers with
// no records at all. GHSA-92cp-5422-2mw7 carries one such range beside two
// well-formed ones, so it also proves the bad range does not cost the good
// ones their match.
func TestOSVMatcher_UnorderableBoundIsSkippedNotMatched(t *testing.T) {
	db := syncedDB(t)
	cases := []struct {
		eco, pkg, version string
		wantIDs           []string
		wantSkip          string
	}{
		{"PyPI", "pynetbox", "4.1.0", nil, `PYSEC-2024-325 (bound "4.1.0-NA")`},
		{"PyPI", "pynetbox", "3.0.0", nil, `PYSEC-2024-325 (bound "4.1.0-NA")`},
		{"Go", "github.com/redis/go-redis/v9", "9.5.2", []string{"GHSA-92cp-5422-2mw7"}, ""},
		{"Go", "github.com/redis/go-redis/v9", "9.7.1", []string{"GHSA-92cp-5422-2mw7"}, ""},
		{"Go", "github.com/redis/go-redis/v9", "9.6.1", nil, `GHSA-92cp-5422-2mw7 (bound "9.6.0b1")`},
	}
	for _, tc := range cases {
		vulns, skipped, err := db.Match(tc.eco, tc.pkg, tc.version)
		if err != nil {
			t.Fatalf("%s %s@%s: %v", tc.eco, tc.pkg, tc.version, err)
		}
		if got := strings.Join(vulnIDs(vulns), ","); got != strings.Join(tc.wantIDs, ",") {
			t.Errorf("%s %s@%s matched %q, api.osv.dev returns %q", tc.eco, tc.pkg, tc.version, got, tc.wantIDs)
		}
		if got := strings.Join(skipped, ","); got != tc.wantSkip {
			t.Errorf("%s %s@%s skipped %q, want %q", tc.eco, tc.pkg, tc.version, got, tc.wantSkip)
		}
	}
}

// TestOSVChecker_UnevaluatedRecordWarnsInsteadOfPassing is the R4 shape for a
// record nothing could read: pynetbox has no matching advisory and one that
// went unevaluated, so the gate reports the id and the bound rather than a
// clean version.
func TestOSVChecker_UnevaluatedRecordWarnsInsteadOfPassing(t *testing.T) {
	store := &fakeOSVStore{policies: map[string]audit.OSVPolicy{
		manifest.TypePypi: {Ecosystem: manifest.TypePypi, Action: ActionBlock},
	}}
	ck := NewOSVChecker(store)
	ck.LocalDB = syncedDB(t)
	ck.Endpoint = "http://127.0.0.1:0/never"

	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "pynetbox", Type: manifest.TypePypi},
		&manifest.VersionEntry{Version: "4.1.0"})
	if r.Action != ActionWarn {
		t.Fatalf("an unevaluated record must warn, not %q: %+v", r.Action, r)
	}
	if !contains(r.Reason, "PYSEC-2024-325") || !contains(r.Reason, "4.1.0-NA") {
		t.Errorf("reason must name the record and the bound nobody could order: %q", r.Reason)
	}
}

// TestOSVDatabase_SyncRefusesEmptyExport covers the one way a sync can leave
// the gate blind while reporting itself current: an export that distills to
// nothing writes a fetch time the max-age window then accepts, and every
// version in the ecosystem reads clean until someone notices the record count.
func TestOSVDatabase_SyncRefusesEmptyExport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		f, err := zw.Create("README")
		if err != nil {
			t.Errorf("zip create: %v", err)
			return
		}
		_, _ = f.Write([]byte("no advisories here"))
		if err := zw.Close(); err != nil {
			t.Errorf("zip close: %v", err)
			return
		}
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	db := NewOSVDatabase(t.TempDir())
	db.ExportBase = srv.URL
	if _, err := db.Sync(context.Background(), "npm"); err == nil {
		t.Fatal("an export holding no advisories must fail the sync, not write an empty database")
	}
	if _, err := db.Meta("npm"); !errors.Is(err, ErrOSVDBMissing) {
		t.Errorf("a refused sync must leave the ecosystem unsynced, got %v", err)
	}

	store := &fakeOSVStore{policies: map[string]audit.OSVPolicy{
		manifest.TypeNpm: {Ecosystem: manifest.TypeNpm, Action: ActionBlock},
	}}
	ck := NewOSVChecker(store)
	ck.LocalDB = db
	ck.Endpoint = "http://127.0.0.1:0/never"
	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "minimist", Type: manifest.TypeNpm},
		&manifest.VersionEntry{Version: "1.2.0"})
	if r.Action != ActionWarn {
		t.Fatalf("a refused sync must leave the gate warning, not %q: %+v", r.Action, r)
	}
}
