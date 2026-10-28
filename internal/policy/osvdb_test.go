package policy

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
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
	{
		registryType: manifest.TypeRubygems,
		ecosystem:    "RubyGems",
		pkg:          "jmespath",
		vulnerable:   "1.6.0",
		ids:          []string{"GHSA-5c5f-7vfq-3732"},
		clean:        "1.6.1",
	},
	{
		registryType: manifest.TypeMaven,
		ecosystem:    "Maven",
		pkg:          "org.apache.logging.log4j:log4j-core",
		vulnerable:   "2.14.1",
		ids:          []string{"GHSA-jfh8-c2jp-5v3q"},
		clean:        "2.15.0",
	},
	{
		registryType: manifest.TypeComposer,
		ecosystem:    "Packagist",
		pkg:          "firebase/php-jwt",
		vulnerable:   "5.4.0",
		ids:          []string{"GHSA-2x45-7fc3-mxwq", "GHSA-8xf4-w7qw-pjjw"},
		clean:        "7.0.0",
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
// sync distills them out of the aggregate archive, and the Rocky Linux
// export, requested under its bare name as rpm requests it.
var osvDistroFixtures = []string{"Ubuntu:22.04:LTS", "Ubuntu:24.04:LTS", "Debian:12", "Rocky Linux"}

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
// the rule against records OSV publishes today. PYSEC-2024-325 bounds pywidget
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
		{"PyPI", "pywidget", "4.1.0", nil, `PYSEC-2024-325 (bound "4.1.0-NA")`},
		{"PyPI", "pywidget", "3.0.0", nil, `PYSEC-2024-325 (bound "4.1.0-NA")`},
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
// record nothing could read: pywidget has no matching advisory and one that
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
		&manifest.PackageManifest{Name: "pywidget", Type: manifest.TypePypi},
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

// A platform gem's version carries its platform, and RubyGems advisories are
// issued against the release: jmespath 1.6.0 built for java is jmespath 1.6.0.
func TestOSVChecker_RubygemsPlatformBuildMatchesItsRelease(t *testing.T) {
	db := syncedDB(t)
	store := &fakeOSVStore{policies: map[string]audit.OSVPolicy{
		manifest.TypeRubygems: {Ecosystem: manifest.TypeRubygems, Action: ActionBlock},
	}}
	ck := NewOSVChecker(store)
	ck.LocalDB = db
	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "jmespath", Type: manifest.TypeRubygems},
		&manifest.VersionEntry{Version: "1.6.0-java"})
	if r.Action != ActionBlock || !strings.Contains(r.Reason, "GHSA-5c5f-7vfq-3732") {
		t.Errorf("jmespath 1.6.0-java = %+v, want a block naming GHSA-5c5f-7vfq-3732", r)
	}
	r = ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "jmespath", Type: manifest.TypeRubygems},
		&manifest.VersionEntry{Version: "1.6.1-java"})
	if r.Action != ActionPass {
		t.Errorf("jmespath 1.6.1-java = %+v, want a pass", r)
	}
}

// A RubyGems range is walked in Gem::Version order, where a letter segment
// opens a prerelease: 1.6.1.rc1 is below a fix landing in 1.6.1, which semver
// cannot place at all.
func TestOSVRange_RubyGemsOrder(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.6.1.rc1", "1.6.1", -1},
		{"1.6.1.rc1", "1.6.0", 1},
		{"1.0", "1", 0},
		{"1.0.a", "1.a", 0},
		{"1.0.0.beta2", "1.0.0.beta10", -1},
		{"1.0.0-pre", "1.0.0.pre.pre", 0},
		{"2.10", "2.9", 1},
	} {
		if got, ok := compareGemVersions(tc.a, tc.b); !ok || got != tc.want {
			t.Errorf("compare(%q, %q) = %d, %v; want %d", tc.a, tc.b, got, ok, tc.want)
		}
	}
	if _, ok := compareGemVersions("1.0 junk", "1.0"); ok {
		t.Error("a version Gem::Version refuses was ordered")
	}
	fixed := osvRange{Type: "ECOSYSTEM", Events: []osvEvent{{Introduced: "0"}, {Fixed: "1.6.1"}}}
	if hit, bad := fixed.affects(osvVersionOrder("RubyGems"), "1.6.1.rc1"); !hit || bad != "" {
		t.Errorf("1.6.1.rc1 under fixed 1.6.1: hit=%v unorderable=%q, want a hit", hit, bad)
	}
}

// A Maven advisory is keyed <groupId>:<artifactId> and its ranges are walked
// in ComparableVersion order. Log4Shell's ranges start at 2.0-beta9, which
// sorts below 2.0, and a Spring-style 2.3.0.RELEASE is the release 2.3.0.
func TestOSVChecker_MavenLog4Shell(t *testing.T) {
	db := syncedDB(t)
	store := &fakeOSVStore{policies: map[string]audit.OSVPolicy{
		manifest.TypeMaven: {Ecosystem: manifest.TypeMaven, Action: ActionBlock},
	}}
	ck := NewOSVChecker(store)
	ck.LocalDB = db
	for _, tc := range []struct {
		name, version string
		action        string
	}{
		{"org.apache.logging.log4j:log4j-core", "2.14.1", ActionBlock},
		{"org.apache.logging.log4j:log4j-core", "2.0-beta9", ActionBlock},
		{"org.apache.logging.log4j:log4j-core", "2.3.0.RELEASE", ActionBlock},
		{"org.apache.logging.log4j:log4j-core", "2.0-beta8", ActionPass},
		{"org.apache.logging.log4j:log4j-core", "2.12.2", ActionPass},
		{"org.apache.logging.log4j:log4j-core", "2.17.1", ActionPass},
		{"org.apache.logging.log4j:log4j-api", "2.14.1", ActionPass},
	} {
		r := ck.Check(context.Background(),
			&manifest.PackageManifest{Name: tc.name, Type: manifest.TypeMaven},
			&manifest.VersionEntry{Version: tc.version})
		if r.Action != tc.action {
			t.Errorf("%s %s = %+v, want %s", tc.name, tc.version, r, tc.action)
		}
		if tc.action == ActionBlock && !strings.Contains(r.Reason, "GHSA-jfh8-c2jp-5v3q") {
			t.Errorf("%s %s: reason %q does not name the advisory", tc.name, tc.version, r.Reason)
		}
	}
}

// Maven's ComparableVersion: qualifiers order alpha < beta < milestone < rc <
// snapshot < release < sp, an unknown one sorts after a release, trailing
// zeros and release aliases vanish, and a letter-digit change opens a sublist
// as a '-' does.
func TestOSVRange_MavenOrder(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1", "1.0.0", 0},
		{"5.3.18.RELEASE", "5.3.18", 0},
		{"5.6.5.Final", "5.6.5", 0},
		{"1.0-ga", "1.0", 0},
		{"1.0-alpha1", "1.0-beta1", -1},
		{"1.0-beta1", "1.0-milestone1", -1},
		{"1.0-milestone1", "1.0-rc1", -1},
		{"1.0-rc1", "1.0-SNAPSHOT", -1},
		{"1.0-SNAPSHOT", "1.0", -1},
		{"1.0", "1.0-sp1", -1},
		{"1.0-a1", "1.0-alpha1", 0},
		{"1.0-cr1", "1.0-rc1", 0},
		{"2.0-beta9", "2.0", -1},
		{"2.0-beta9", "2.0-beta10", -1},
		{"31.1-jre", "31.1", 1},
		{"31.1-jre", "31.2", -1},
		{"1.10", "1.9", 1},
		{"1-1", "1.1", -1},
		{"1.0.0.1", "1.0.0", 1},
		{"007", "7", 0},
	} {
		if got, ok := compareMavenVersions(tc.a, tc.b); !ok || got != tc.want {
			t.Errorf("compare(%q, %q) = %d, %v; want %d", tc.a, tc.b, got, ok, tc.want)
		}
		if got, _ := compareMavenVersions(tc.b, tc.a); got != -tc.want {
			t.Errorf("compare(%q, %q) = %d; want %d", tc.b, tc.a, got, -tc.want)
		}
	}
	if _, ok := compareMavenVersions("1.0 junk", "1.0"); ok {
		t.Error("a version holding whitespace was ordered")
	}
	fixed := osvRange{Type: "ECOSYSTEM", Events: []osvEvent{{Introduced: "2.0-beta9"}, {Fixed: "2.3.1"}}}
	if hit, bad := fixed.affects(osvVersionOrder("Maven"), "2.3.0.RELEASE"); !hit || bad != "" {
		t.Errorf("2.3.0.RELEASE under [2.0-beta9, 2.3.1): hit=%v unorderable=%q, want a hit", hit, bad)
	}
}

// Packagist tags firebase/php-jwt as v5.4.0, and Composer reads that and
// 5.4.0 as one version. The gate strips the "v" before walking OSV's ranges,
// so either spelling is refused with both advisories named, and the fixed
// release passes under either.
func TestOSVChecker_ComposerVPrefixedVersion(t *testing.T) {
	db := syncedDB(t)
	store := &fakeOSVStore{policies: map[string]audit.OSVPolicy{
		manifest.TypeComposer: {Ecosystem: manifest.TypeComposer, Action: ActionBlock},
	}}
	ck := NewOSVChecker(store)
	ck.LocalDB = db
	for _, v := range []string{"v5.4.0", "5.4.0", "V5.4.0"} {
		r := ck.Check(context.Background(),
			&manifest.PackageManifest{Name: "firebase/php-jwt", Type: manifest.TypeComposer},
			&manifest.VersionEntry{Version: v})
		if r.Action != ActionBlock || !strings.Contains(r.Reason, "GHSA-2x45-7fc3-mxwq") || !strings.Contains(r.Reason, "GHSA-8xf4-w7qw-pjjw") {
			t.Errorf("firebase/php-jwt %s = %+v, want a block naming both advisories", v, r)
		}
	}
	for _, v := range []string{"v7.0.0", "7.0.0"} {
		r := ck.Check(context.Background(),
			&manifest.PackageManifest{Name: "firebase/php-jwt", Type: manifest.TypeComposer},
			&manifest.VersionEntry{Version: v})
		if r.Action != ActionPass {
			t.Errorf("firebase/php-jwt %s = %+v, want a pass", v, r)
		}
	}
	if got := osvQueryVersion("Packagist", "v5.4.0"); got != "5.4.0" {
		t.Errorf("osvQueryVersion(Packagist, v5.4.0) = %q, want 5.4.0", got)
	}
	for _, v := range []string{"dev-main", "v", "vendor-1.0"} {
		if got := osvQueryVersion("Packagist", v); got != v {
			t.Errorf("osvQueryVersion(Packagist, %q) = %q; only a v before a digit is a prefix", v, got)
		}
	}
	if got := OSVEcosystemFor(manifest.TypeComposer); got != "Packagist" {
		t.Errorf("OSVEcosystemFor(composer) = %q, want Packagist", got)
	}
}

// An rpm package is checked against the ecosystem its repository belongs to,
// read from the entry, and compared in rpm's order with the epoch. The fixture
// is OSV's own two Rocky Linux 9 openssl advisories, filed under
// "Rocky Linux:9" and requested under "Rocky Linux". 1:3.2.2-6.el9_5 sorts
// below the fix 1:3.2.2-6.el9_5.1, which a semver compare reads as equal at
// best. A repository with no ecosystem, EPEL's, is not run and says why.
func TestOSVChecker_RockyLinuxOpenssl(t *testing.T) {
	srv := exportServer(t)
	t.Cleanup(srv.Close)
	db := NewOSVDatabase(t.TempDir())
	db.ExportBase = srv.URL
	if _, err := db.Sync(t.Context(), "Rocky Linux"); err != nil {
		t.Fatalf("sync: %v", err)
	}
	store := &fakeOSVStore{policies: map[string]audit.OSVPolicy{
		manifest.TypeRpm: {Ecosystem: manifest.TypeRpm, Action: ActionBlock},
	}}
	ck := NewOSVChecker(store)
	ck.LocalDB = db
	rocky := func(v string) *manifest.VersionEntry {
		return &manifest.VersionEntry{Version: v, Metadata: map[string]string{RpmOSVEcosystemKey: "Rocky Linux", RpmRepositoryKey: "rocky-baseos", RpmReleaseKey: "9"}}
	}
	openssl := &manifest.PackageManifest{Name: "openssl", Type: manifest.TypeRpm}
	for _, tc := range []struct {
		version string
		ids     []string
	}{
		{"1:3.0.7-27.el9", []string{"RLSA-2024:6783", "RLSA-2024:9333"}},
		{"1:3.0.7-28.el9_4", []string{"RLSA-2024:9333"}},
		{"1:3.2.2-6.el9_5", []string{"RLSA-2024:9333"}},
	} {
		r := ck.Check(t.Context(), openssl, rocky(tc.version))
		got, _ := r.Details["vulns"].([]string)
		if r.Action != ActionBlock || !slices.Equal(got, tc.ids) || !strings.Contains(r.Reason, "queried as openssl in Rocky Linux:9") {
			t.Errorf("openssl %s = %+v, want a block naming %v", tc.version, r, tc.ids)
		}
	}
	for _, v := range []string{"1:3.2.2-6.el9_5.1", "1:3.5.1-7.el9_7"} {
		if r := ck.Check(t.Context(), openssl, rocky(v)); r.Action != ActionPass {
			t.Errorf("openssl %s = %+v, want a pass", v, r)
		}
	}
	// Without the epoch the version sorts below every fix: 3.2.2 is epoch 0.
	if r := ck.Check(t.Context(), openssl, rocky("3.5.1-7.el9_7")); r.Action != ActionBlock {
		t.Errorf("openssl 3.5.1-7.el9_7, epoch 0 = %+v, want a block", r)
	}

	epel := &manifest.VersionEntry{Version: "1.24.0-1.el9", Metadata: map[string]string{RpmRepositoryKey: "epel"}}
	r := ck.Check(t.Context(), &manifest.PackageManifest{Name: "htop", Type: manifest.TypeRpm}, epel)
	if r.Action != ActionNotEvaluated || !strings.Contains(r.Reason, "not run: rpm repository epel belongs to no OSV ecosystem") ||
		!strings.Contains(r.Reason, "osv_ecosystem") {
		t.Errorf("an EPEL package = %+v, want not evaluated naming the repository and the key that covers a mirror", r)
	}
	if got := osvVersionOrder("Rocky Linux:9"); got != orderRpm {
		t.Errorf("osvVersionOrder(Rocky Linux:9) = %s, want rpm", got)
	}
	if got := osvVersionOrder("Red Hat:enterprise_linux:9::appstream"); got != orderRpm {
		t.Errorf("osvVersionOrder(Red Hat:...) = %s, want rpm", got)
	}
}

// rpmMixedReleases is one vendor export carrying several releases, the way
// OSV publishes Rocky Linux, AlmaLinux and Red Hat: an EL9 advisory, an
// EL10-only one, one advisory naming both releases with a fix in each, and Red
// Hat's stock and EUS streams. The ids are synthetic; the ecosystem strings
// are OSV's.
const rpmMixedReleases = `[
 {"id":"EL9-ONLY","affected":[{"package":{"name":"openssl","ecosystem":"Rocky Linux:9"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:3.0.7-28.el9_4"}]}]}]},
 {"id":"EL10-ONLY","affected":[{"package":{"name":"openssl","ecosystem":"Rocky Linux:10"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:3.5.1-1.el10"}]}]}]},
 {"id":"BOTH","affected":[
  {"package":{"name":"openssl","ecosystem":"Rocky Linux:9"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:3.0.7-27.el9"}]}]},
  {"package":{"name":"openssl","ecosystem":"Rocky Linux:10"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:3.5.2-1.el10"}]}]}]},
 {"id":"RH-STOCK","affected":[{"package":{"name":"openssl","ecosystem":"Red Hat:enterprise_linux:9::baseos"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:3.0.7-28.el9_4"}]}]}]},
 {"id":"RH-EUS","affected":[{"package":{"name":"openssl","ecosystem":"Red Hat:rhel_eus:9.2::baseos"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:3.0.7-30.el9_2"}]}]}]}
]`

// rpmMixedDB syncs each vendor out of an export serving rpmMixedReleases at
// <vendor>/all.zip, through the same SyncGroup a real sync runs.
func rpmMixedDB(t *testing.T, vendors ...string) *OSVDatabase {
	t.Helper()
	body, err := os.ReadFile(exportZip(t, "rpm-mixed", []byte(rpmMixedReleases)))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	db := NewOSVDatabase(t.TempDir())
	db.ExportBase = srv.URL
	for _, res := range db.SyncGroup(t.Context(), vendors) {
		if res.Err != nil {
			t.Fatalf("sync %s: %v", res.Ecosystem, res.Err)
		}
	}
	return db
}

// A vendor's advisories are kept per release, so an EL9 build is judged by
// EL9's ranges alone and an EL10 build by EL10's, out of one archive, and a
// releasever of 9.4 is release 9. Red Hat's EUS stream answers no stock
// release.
func TestOSVRpmReleasesStayApart(t *testing.T) {
	db := rpmMixedDB(t, "Rocky Linux", "Red Hat")
	ck := NewOSVChecker(&fakeOSVStore{policies: map[string]audit.OSVPolicy{
		manifest.TypeRpm: {Ecosystem: manifest.TypeRpm, Action: ActionBlock},
	}})
	ck.LocalDB = db
	openssl := &manifest.PackageManifest{Name: "openssl", Type: manifest.TypeRpm}
	for _, tc := range []struct {
		vendor, release, version string
		ids                      []string
	}{
		{"Rocky Linux", "9", "1:3.0.7-27.el9", []string{"EL9-ONLY"}},
		{"Rocky Linux", "9.4", "1:3.0.7-27.el9", []string{"EL9-ONLY"}},
		{"Rocky Linux", "9", "1:3.0.7-28.el9_4", nil},
		{"Rocky Linux", "10", "1:3.5.0-1.el10", []string{"BOTH", "EL10-ONLY"}},
		{"Rocky Linux", "10", "1:3.5.1-1.el10", []string{"BOTH"}},
		{"Rocky Linux", "10", "1:3.5.2-1.el10", nil},
		{"Red Hat", "9", "1:3.0.7-28.el9_4", nil},
		{"Red Hat", "9", "1:3.0.7-27.el9", []string{"RH-STOCK"}},
	} {
		ve := &manifest.VersionEntry{Version: tc.version, Metadata: map[string]string{
			RpmOSVEcosystemKey: tc.vendor, RpmReleaseKey: tc.release, RpmRepositoryKey: "baseos"}}
		r := ck.Check(t.Context(), openssl, ve)
		got, _ := r.Details["vulns"].([]string)
		want := ActionBlock
		if tc.ids == nil {
			want = ActionPass
		}
		if r.Action != want || !slices.Equal(got, tc.ids) {
			t.Errorf("%s %s openssl %s = %+v, want %s naming %v", tc.vendor, tc.release, tc.version, r, want, tc.ids)
		}
	}

	ve := &manifest.VersionEntry{Version: "1:3.0.7-27.el9", Metadata: map[string]string{
		RpmOSVEcosystemKey: "Rocky Linux", RpmRepositoryKey: "baseos"}}
	if r := ck.Check(t.Context(), openssl, ve); r.Action != ActionWarn || !strings.Contains(r.Reason, "names no Enterprise Linux release") {
		t.Errorf("an entry naming no release = %+v, want a warn saying so", r)
	}
}

// An index synced before rpm advisories were kept per release cannot tell
// one release's records from another's, so it warns and names the sync that
// fixes it instead of answering.
func TestOSVRpmIndexWithoutReleasesRefused(t *testing.T) {
	db := rpmMixedDB(t, "Rocky Linux")
	idx := mustOSVIndex(t, db, "Rocky Linux")
	idx.ByRelease = false
	if _, err := db.writeIndex("Rocky Linux", idx); err != nil {
		t.Fatal(err)
	}
	ck := NewOSVChecker(&fakeOSVStore{policies: map[string]audit.OSVPolicy{
		manifest.TypeRpm: {Ecosystem: manifest.TypeRpm, Action: ActionBlock},
	}})
	ck.LocalDB = NewOSVDatabase(db.Dir())
	ve := &manifest.VersionEntry{Version: "1:3.0.7-28.el9_4", Metadata: map[string]string{
		RpmOSVEcosystemKey: "Rocky Linux", RpmReleaseKey: "9", RpmRepositoryKey: "baseos"}}
	r := ck.Check(t.Context(), &manifest.PackageManifest{Name: "openssl", Type: manifest.TypeRpm}, ve)
	if r.Action != ActionWarn || !strings.Contains(r.Reason, "bodega policy osv sync rpm") {
		t.Errorf("an index keyed by name alone = %+v, want a warn naming the sync", r)
	}
}

// api.osv.dev is asked under the vendor and answers with every release's
// hits, so the fallback keeps only the records whose own entries for the
// release asked about cover the version.
func TestOSVRpmAPIFallbackKeepsTheRelease(t *testing.T) {
	var asked string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Package struct{ Ecosystem string } `json:"package"`
		}
		_ = json.NewDecoder(r.Body).Decode(&q)
		asked = q.Package.Ecosystem
		var recs []json.RawMessage
		_ = json.Unmarshal([]byte(rpmMixedReleases), &recs)
		_, _ = fmt.Fprintf(w, `{"vulns":[%s,%s,%s]}`, recs[0], recs[1], recs[2])
	}))
	t.Cleanup(srv.Close)
	ck := NewOSVChecker(&fakeOSVStore{policies: map[string]audit.OSVPolicy{
		manifest.TypeRpm: {Ecosystem: manifest.TypeRpm, Action: ActionBlock},
	}})
	ck.Endpoint = srv.URL
	ck.AllowAPIFallback = true
	for _, tc := range []struct {
		release, version string
		ids              []string
	}{
		{"9", "1:3.0.7-28.el9_4", nil},
		{"9", "1:3.0.7-26.el9", []string{"BOTH", "EL9-ONLY"}},
		{"10", "1:3.5.1-1.el10", []string{"BOTH"}},
	} {
		ve := &manifest.VersionEntry{Version: tc.version, Metadata: map[string]string{
			RpmOSVEcosystemKey: "Rocky Linux", RpmReleaseKey: tc.release, RpmRepositoryKey: "baseos"}}
		r := ck.Check(t.Context(), &manifest.PackageManifest{Name: "openssl", Type: manifest.TypeRpm}, ve)
		got, _ := r.Details["vulns"].([]string)
		if !slices.Equal(got, tc.ids) {
			t.Errorf("release %s openssl %s = %+v, want %v", tc.release, tc.version, r, tc.ids)
		}
	}
	if asked != "Rocky Linux" {
		t.Errorf("api.osv.dev asked under %q, want the vendor", asked)
	}
}

// An rpm repository no OSV ecosystem covers is not run whatever else holds:
// ignored actions, the malware-only pass and an unresolved stub all say so
// rather than pass.
func TestOSVRpmUncoveredNotRunBeforeEveryPass(t *testing.T) {
	ignored := &fakeOSVStore{
		policies: map[string]audit.OSVPolicy{manifest.TypeRpm: {Ecosystem: manifest.TypeRpm, Action: ActionIgnore}},
		malware:  map[string]audit.OSVMalwarePolicy{manifest.TypeRpm: {Ecosystem: manifest.TypeRpm, Action: ActionIgnore}},
	}
	htop := &manifest.PackageManifest{Name: "htop", Type: manifest.TypeRpm}
	for _, tc := range []struct {
		name    string
		store   *fakeOSVStore
		version string
		malware bool
	}{
		{"actions ignored", ignored, "3.3.0-1.el9", false},
		{"malware only", &fakeOSVStore{}, "3.3.0-1.el9", true},
		{"no version", &fakeOSVStore{}, "", false},
		{"no version, actions ignored", ignored, "", false},
	} {
		ck := NewOSVChecker(tc.store)
		ve := &manifest.VersionEntry{Version: tc.version, Metadata: map[string]string{RpmRepositoryKey: "epel"}}
		var r Result
		if tc.malware {
			r = ck.CheckMalware(t.Context(), htop, ve)
		} else {
			r = ck.Check(t.Context(), htop, ve)
		}
		if r.Action != ActionNotEvaluated || !strings.Contains(r.Reason, "rpm repository epel belongs to no OSV ecosystem") {
			t.Errorf("%s: %+v, want not_evaluated naming epel", tc.name, r)
		}
	}
}
