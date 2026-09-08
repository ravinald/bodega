package admit

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

func aptPkg(name, version string) *manifest.PackageManifest {
	return &manifest.PackageManifest{
		ConfigVersion: manifest.CurrentConfigVersion,
		Name:          name,
		Type:          manifest.TypeApt,
		Versions:      []manifest.VersionEntry{{Version: version, SourceName: name}},
	}
}

// TestAdmitRejectsAnUnreadableBackend is the check that used to run on only
// one of the two write paths. A storage name no backend answers to makes the
// artifact unreadable: resolution never falls back, so the entry 502s rather
// than serving from somewhere plausible.
func TestAdmitRejectsAnUnreadableBackend(t *testing.T) {
	cfg := &config.Config{StorageBackends: map[string]config.StorageSpec{"cold": {Driver: "local"}}}

	pm := aptPkg("hello", "2.10")
	pm.Versions[0].Storage = "does-not-exist"
	res := Admit(t.Context(), nil, nil, cfg, pm, "")
	if res.OK() {
		t.Fatal("admitted a version pinned to a backend nothing defines")
	}
	if !strings.Contains(res.Reason, "cold") {
		t.Errorf("the error does not name what is defined, so the operator cannot fix it: %q", res.Reason)
	}

	pm.Versions[0].Storage = "cold"
	if res := Admit(t.Context(), nil, nil, cfg, pm, ""); !res.OK() {
		t.Errorf("refused a configured backend: %s", res.Reason)
	}
	pm.Versions[0].Storage = ""
	if res := Admit(t.Context(), nil, nil, cfg, pm, ""); !res.OK() {
		t.Errorf("refused an entry with no backend recorded, which means the default: %s", res.Reason)
	}
}

// TestAdmitRefusesAVersionlessAptEntry keeps a package out of the store that
// no verb can address: remove, delete, hide and freeze all name a version, so
// its only exit would be a repair run.
func TestAdmitRefusesAVersionlessAptEntry(t *testing.T) {
	pm := aptPkg("blank", "")
	res := Admit(t.Context(), nil, nil, &config.Config{}, pm, "")
	if res.OK() {
		t.Fatal("admitted an apt entry with no version")
	}
	if !strings.Contains(res.Reason, `"*"`) {
		t.Errorf("the error does not offer the way out: %q", res.Reason)
	}
	if res := Admit(t.Context(), nil, nil, &config.Config{}, aptPkg("star", "*"), ""); !res.OK() {
		t.Errorf(`refused version "*", which resolves on the next build: %s`, res.Reason)
	}
}

// TestAdmitWarnsWithoutRefusing separates the two failure kinds. A
// storage_policy on a whole-directory type is inert rather than wrong, and
// manifests already in the field carry them; refusing would reject a file that
// was legal when it was written.
func TestAdmitWarnsWithoutRefusing(t *testing.T) {
	cfg := &config.Config{StorageBackends: map[string]config.StorageSpec{"bulk": {Driver: "local"}}}
	pm := &manifest.PackageManifest{
		Name: "requests", Type: manifest.TypePypi, StoragePolicy: "bulk",
		Versions: []manifest.VersionEntry{{Version: "2.32.3"}},
	}

	res := Admit(t.Context(), nil, nil, cfg, pm, "")
	if !res.OK() {
		t.Fatalf("an inert storage_policy was treated as an error: %s", res.Reason)
	}
	if len(res.Warnings) == 0 {
		t.Fatal("an ignored storage_policy passed with nothing said about it")
	}
	if !strings.Contains(res.Warnings[0], "storage_by_type") {
		t.Errorf("the warning does not name what would work: %q", res.Warnings[0])
	}

	// Every other type places per package, apt and git included since their
	// uploaders started walking manifest entries.
	for _, typ := range []string{manifest.TypeNpm, manifest.TypeApt, manifest.TypeGit} {
		per := &manifest.PackageManifest{
			Name: "lodash", Type: typ, StoragePolicy: "bulk",
			Versions: []manifest.VersionEntry{{Version: "4.17.21", Ref: "v4.17.21"}},
		}
		if res := Admit(t.Context(), nil, nil, cfg, per, ""); len(res.Warnings) != 0 {
			t.Errorf("%s places per package, so its storage_policy is honored and needs no warning: %v", typ, res.Warnings)
		}
	}
}

// TestAdmitRequiresTheBasics covers the fields with no sensible default.
func TestAdmitRequiresTheBasics(t *testing.T) {
	for _, tc := range []struct {
		name string
		pm   *manifest.PackageManifest
		want string
	}{
		{"no name", &manifest.PackageManifest{Type: manifest.TypeNpm}, "name is required"},
		// "." and ".." reach a manifest path outside their own type
		// directory, where two types collide on one file. Every admitting
		// surface refuses them, so a bulk import reports the entry beside
		// its siblings rather than failing the whole request at the write.
		{"dot name", &manifest.PackageManifest{Name: ".", Type: manifest.TypeNpm}, "path syntax"},
		{"dotdot name", &manifest.PackageManifest{Name: "..", Type: manifest.TypeNpm}, "path syntax"},
		{"no type", &manifest.PackageManifest{Name: "x"}, "type is required"},
		{"unknown type", &manifest.PackageManifest{Name: "x", Type: "rpm"}, "unknown type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := Admit(t.Context(), nil, nil, &config.Config{}, tc.pm, "")
			if res.OK() {
				t.Fatalf("admitted %s", tc.name)
			}
			if !strings.Contains(res.Reason, tc.want) {
				t.Errorf("reason = %q, want it to mention %q", res.Reason, tc.want)
			}
		})
	}
}

// TestDecisionStringsAreStable guards the values that reach an operator
// through the bulk import response.
func TestDecisionStringsAreStable(t *testing.T) {
	for d, want := range map[Decision]string{
		Admitted:      "admitted",
		Invalid:       "invalid",
		PolicyBlocked: "policy_blocked",
	} {
		if got := d.String(); got != want {
			t.Errorf("Decision(%d) = %q, want %q", int(d), got, want)
		}
	}
}

// TestAdmitRefusesAnUnservableSuite covers the entry that can never be served
// however apt_suites is edited later: config.Load refuses a suite name
// carrying "/", so nothing can put it in the served set. A legal suite that
// simply is not served yet is admitted — staging an entry before adding its
// suite is a normal order, and GET /api/v1/status is where that one shows up.
func TestAdmitRefusesAnUnservableSuite(t *testing.T) {
	pm := aptPkg("hello", "2.10")
	pm.Versions[0].Suites = []string{"a/b"}
	res := Admit(t.Context(), nil, nil, &config.Config{}, pm, "")
	if res.OK() {
		t.Fatal(`admitted an apt entry in suite "a/b", which no configuration can serve`)
	}
	if !strings.Contains(res.Reason, "a/b") {
		t.Errorf("the error does not name the suite it refused: %q", res.Reason)
	}

	pm.Versions[0].Suites = []string{"jammy"}
	if res := Admit(t.Context(), nil, nil, &config.Config{}, pm, ""); !res.OK() {
		t.Errorf("refused a legal suite this server does not serve yet: %s", res.Reason)
	}
}

// TestAdmitReportsADegradedOSVGate is the reason the version checks report on
// Result rather than only into the audit table. With no synced OSV database
// the gate answers "I could not tell", and an operator importing a package
// has to read that at the moment of the import: a clean line and a row filed
// under policy_warn is how a dark gate stays dark.
func TestAdmitReportsADegradedOSVGate(t *testing.T) {
	adb, err := audit.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	defer adb.Close()
	if err := adb.SetOSVPolicy(t.Context(), audit.OSVPolicy{
		Ecosystem: manifest.TypeNpm, Action: policy.ActionBlock,
	}); err != nil {
		t.Fatalf("set osv policy: %v", err)
	}

	// An empty directory: osv_db_dir is configured and `policy osv sync` has
	// never run, which is the state a fresh air-gapped install is in.
	cfg := &config.Config{StoragePath: t.TempDir(), OSVDBDir: t.TempDir()}
	pm := &manifest.PackageManifest{
		Name: "minimist", Type: manifest.TypeNpm,
		Versions: []manifest.VersionEntry{{Version: "1.2.0"}, {Version: "1.2.1"}},
	}

	res := Admit(t.Context(), nil, adb, cfg, pm, "")
	if !res.OK() {
		t.Fatalf("a degraded gate warns, it does not refuse: %s", res.Reason)
	}
	line := ""
	for _, w := range res.Warnings {
		if strings.Contains(w, "osv:") {
			line = w
		}
	}
	if line == "" {
		t.Fatalf("an unsynced OSV gate admitted with nothing said: %v", res.Warnings)
	}
	if !strings.Contains(line, "policy osv sync") {
		t.Errorf("the warning does not name the next step: %q", line)
	}
	if !strings.Contains(line, "osv_api_fallback") {
		t.Errorf("the warning does not say nothing was queried: %q", line)
	}
	// Both versions share one reason, so it is stated once and names them.
	if !strings.Contains(line, "2 versions") || !strings.Contains(line, "1.2.0") {
		t.Errorf("repeated reasons should collapse onto the versions they cover: %q", line)
	}
	if got := strings.Count(strings.Join(res.Warnings, "\n"), "policy osv sync"); got != 1 {
		t.Errorf("the same finding was reported %d times", got)
	}
}

// osvExport serves one ecosystem's records in the shape OSV publishes them,
// so a test can sync a real database without reaching the network.
func osvExport(t *testing.T, records ...map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

// TestAdmitKeepsWarningsBehindABlock covers the ordering the flush is deferred
// for. A block returns from the version loop early, and the warning that
// explains why the gate was degraded was collected before it: reporting only
// the block would tell the operator the import failed and not that the gate
// answering it was stale.
func TestAdmitKeepsWarningsBehindABlock(t *testing.T) {
	adb, err := audit.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	defer adb.Close()
	if err := adb.SetOSVPolicy(t.Context(), audit.OSVPolicy{
		Ecosystem: manifest.TypeNpm, Action: policy.ActionBlock,
	}); err != nil {
		t.Fatalf("set osv policy: %v", err)
	}

	dir := t.TempDir()
	db := policy.NewOSVDatabase(dir)
	db.ExportBase = osvExport(t, map[string]any{
		"id": "GHSA-test-0001",
		"affected": []map[string]any{{
			"package":  map[string]string{"name": "minimist", "ecosystem": "npm"},
			"versions": []string{"1.2.0"},
		}},
	}).URL
	if _, err := db.Sync(t.Context(), "npm"); err != nil {
		t.Fatalf("sync: %v", err)
	}

	// Stale the instant it is written, so a clean version warns while a
	// version the archive does name still blocks.
	cfg := &config.Config{StoragePath: t.TempDir(), OSVDBDir: dir, OSVDBMaxAge: "1ns"}
	pm := &manifest.PackageManifest{
		Name: "minimist", Type: manifest.TypeNpm,
		Versions: []manifest.VersionEntry{{Version: "1.2.8"}, {Version: "1.2.0"}},
	}

	res := Admit(t.Context(), nil, adb, cfg, pm, "")
	if res.OK() {
		t.Fatal("a version the archive names as vulnerable was admitted")
	}
	if !strings.Contains(res.Reason, "GHSA-test-0001") {
		t.Errorf("the block does not name the record: %q", res.Reason)
	}
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "1.2.8") && strings.Contains(w, "policy osv sync") {
			found = true
		}
	}
	if !found {
		t.Errorf("the stale-gate warning collected before the block was dropped: %v", res.Warnings)
	}
}
