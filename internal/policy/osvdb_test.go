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
var osvAgreementCases = []struct {
	registryType string
	ecosystem    string
	pkg          string
	vulnerable   string
	ids          []string
	clean        string
}{
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

// exportServer serves the testdata records as OSV's per-ecosystem export:
// <base>/<ecosystem>/all.zip, one JSON file per record.
func exportServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		eco := filepath.Base(filepath.Dir(r.URL.Path))
		raw, err := os.ReadFile(filepath.Join("testdata", "osv", eco+".json"))
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
	for _, tc := range osvAgreementCases {
		if _, err := db.Sync(context.Background(), tc.ecosystem); err != nil {
			t.Fatalf("sync %s: %v", tc.ecosystem, err)
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
		if _, err := os.Stat(filepath.Join(db.Dir(), tc.ecosystem+".json.gz")); err != nil {
			t.Errorf("%s: archive missing: %v", tc.ecosystem, err)
		}
	}
}

func TestOSVDatabase_MissingEcosystemIsNotEmpty(t *testing.T) {
	db := NewOSVDatabase(t.TempDir())
	if _, err := db.Meta("npm"); !errors.Is(err, ErrOSVDBMissing) {
		t.Errorf("unsynced ecosystem must report missing, got %v", err)
	}
	if _, err := db.Match("npm", "lodash", "4.17.4"); !errors.Is(err, ErrOSVDBMissing) {
		t.Errorf("unsynced ecosystem must not answer 'no vulns', got %v", err)
	}
}

// TestOSVMatcher_AgreesWithAPI is the reason the local matcher is allowed to
// replace the query: for a known-vulnerable version in every mapped ecosystem
// it returns the id set api.osv.dev returned, and nothing for a fixed one.
func TestOSVMatcher_AgreesWithAPI(t *testing.T) {
	db := syncedDB(t)
	for _, tc := range osvAgreementCases {
		vulns, err := db.Match(tc.ecosystem, tc.pkg, tc.vulnerable)
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
		clean, err := db.Match(tc.ecosystem, tc.pkg, tc.clean)
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
		if got := tc.r.affects(orderSemver, tc.version); got != tc.want {
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
