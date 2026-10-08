package admit

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// admissionFixture is an audit store with an npm OSV gate set to block, and
// the two configs that drive it offline: one whose synced database names
// minimist 1.2.0, and one whose database directory was never synced, which
// makes the gate warn.
type admissionFixture struct {
	adb      *audit.DB
	synced   *config.Config
	unsynced *config.Config
}

func newAdmissionFixture(t *testing.T) admissionFixture {
	t.Helper()
	adb, err := audit.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	t.Cleanup(func() { _ = adb.Close() })
	// A fresh store seeds an npm age gate, which dates a version against the
	// public registry. These cases are about the OSV gate and must not reach
	// the network.
	if _, err := adb.DeleteAgePolicy(t.Context(), manifest.TypeNpm); err != nil {
		t.Fatalf("delete seeded age policy: %v", err)
	}
	if err := adb.SetOSVPolicy(t.Context(), audit.OSVPolicy{Ecosystem: manifest.TypeNpm, Action: policy.ActionBlock}); err != nil {
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
	return admissionFixture{
		adb:      adb,
		synced:   &config.Config{StoragePath: t.TempDir(), OSVDBDir: dir},
		unsynced: &config.Config{StoragePath: t.TempDir(), OSVDBDir: t.TempDir()},
	}
}

func (f admissionFixture) digest(t *testing.T) string {
	t.Helper()
	d, err := policy.Digest(t.Context(), f.adb)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	return d
}

func (f admissionFixture) rows(t *testing.T, name string) []audit.Admission {
	t.Helper()
	rows, err := f.adb.Admissions(t.Context(), audit.AdmissionFilter{PkgType: manifest.TypeNpm, PkgName: name})
	if err != nil {
		t.Fatalf("Admissions: %v", err)
	}
	return rows
}

func checkOf(t *testing.T, a audit.Admission, name string) audit.AdmissionCheck {
	t.Helper()
	for _, c := range a.Checks {
		if c.Check == name {
			return c
		}
	}
	t.Fatalf("row for %s@%s carries no %s check: %+v", a.PkgName, a.PkgVersion, name, a.Checks)
	return audit.AdmissionCheck{}
}

func minimist(versions ...string) *manifest.PackageManifest {
	pm := &manifest.PackageManifest{Name: "minimist", Type: manifest.TypeNpm}
	for _, v := range versions {
		pm.Versions = append(pm.Versions, manifest.VersionEntry{Version: v})
	}
	return pm
}

// TestAdmitRecordsEveryOutcome is requirement 3's core: every outcome writes
// one row per version, a clean pass included, each citing the policy digest
// in force.
func TestAdmitRecordsEveryOutcome(t *testing.T) {
	cases := []struct {
		name       string
		unsynced   bool
		versions   []string
		decision   string
		osv        []string // per version
		wantResult Decision
	}{
		{"clean_pass", false, []string{"1.2.8"}, audit.AdmissionAdmitted, []string{audit.CheckPass}, Admitted},
		{"warn", true, []string{"1.2.8"}, audit.AdmissionAdmitted, []string{audit.CheckWarn}, Admitted},
		{"block", false, []string{"1.2.8", "1.2.0", "1.2.5"}, audit.AdmissionPolicyBlocked,
			[]string{audit.CheckPass, audit.CheckBlock, audit.CheckNotEvaluated}, PolicyBlocked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAdmissionFixture(t)
			cfg := f.synced
			if tc.unsynced {
				cfg = f.unsynced
			}
			res := Admit(t.Context(), policy.NewChecker(f.adb), f.adb, cfg, minimist(tc.versions...), "ravi")
			if res.Decision != tc.wantResult {
				t.Fatalf("Decision = %v (%s), want %v", res.Decision, res.Reason, tc.wantResult)
			}
			rows := f.rows(t, "minimist")
			if len(rows) != len(tc.versions) || len(res.Admissions) != len(tc.versions) {
				t.Fatalf("%d rows stored, %d returned, want one per version (%d)", len(rows), len(res.Admissions), len(tc.versions))
			}
			want := f.digest(t)
			byVersion := map[string]audit.Admission{}
			for _, r := range rows {
				byVersion[r.PkgVersion] = r
			}
			for i, v := range tc.versions {
				r := byVersion[v]
				if r.Decision != tc.decision {
					t.Errorf("%s: decision = %q, want %q", v, r.Decision, tc.decision)
				}
				if r.PolicyDigest != want {
					t.Errorf("%s: policy_digest = %q, want %q", v, r.PolicyDigest, want)
				}
				if r.Actor != "ravi" || r.ObjectKey != "" {
					t.Errorf("%s: actor %q, object_key %q; want ravi and unpinned", v, r.Actor, r.ObjectKey)
				}
				osv := checkOf(t, r, audit.CheckOSV)
				if osv.Status != tc.osv[i] || osv.Action != policy.ActionBlock {
					t.Errorf("%s: osv = %+v, want status %s under action block", v, osv, tc.osv[i])
				}
				if al := checkOf(t, r, audit.CheckAllowList); i < 2 && al.Status != audit.CheckPass {
					t.Errorf("%s: allowlist = %+v, want pass with no rules", v, al)
				}
				if age := checkOf(t, r, audit.CheckAge); age.Action != audit.ActionNone {
					t.Errorf("%s: age action = %q with no age policy, want none", v, age.Action)
				}
			}
		})
	}
}

// TestAdmitRecordsAllowListAndInvalidRefusals covers the two refusals that
// stop before the per-version checks: their rows say what refused and that
// the rest did not run, never a pass.
func TestAdmitRecordsAllowListAndInvalidRefusals(t *testing.T) {
	f := newAdmissionFixture(t)
	if err := f.adb.InsertPolicy(t.Context(), audit.PolicyInfo{ID: "r1", RegistryType: manifest.TypeNpm, RuleKind: policy.KindPackage, Pattern: "lodash"}); err != nil {
		t.Fatalf("InsertPolicy: %v", err)
	}
	res := Admit(t.Context(), policy.NewChecker(f.adb), f.adb, f.synced, minimist("1.2.8"), "ravi")
	if res.Decision != PolicyBlocked {
		t.Fatalf("Decision = %v, want PolicyBlocked", res.Decision)
	}
	rows := f.rows(t, "minimist")
	if len(rows) != 1 {
		t.Fatalf("want one row, got %d", len(rows))
	}
	if al := checkOf(t, rows[0], audit.CheckAllowList); al.Status != audit.CheckBlock || al.Action != policy.ActionBlock {
		t.Errorf("allowlist = %+v, want block under action block", al)
	}
	for _, name := range []string{audit.CheckAge, audit.CheckOSV} {
		if c := checkOf(t, rows[0], name); c.Status != audit.CheckNotEvaluated {
			t.Errorf("%s = %+v after the allow-list refused, want not_evaluated", name, c)
		}
	}

	bad := minimist("1.0.0")
	bad.Type = "rubygems"
	res = Admit(t.Context(), nil, f.adb, f.synced, bad, "ravi")
	if res.Decision != Invalid || len(res.Admissions) != 1 {
		t.Fatalf("Decision = %v with %d rows, want Invalid with one", res.Decision, len(res.Admissions))
	}
	if res.Admissions[0].Decision != audit.AdmissionInvalid || res.Admissions[0].Evaluated() {
		t.Errorf("invalid row = %+v, want decision invalid and nothing evaluated", res.Admissions[0])
	}
}

// TestCreateRecordsTheOverride is the pkg create case: the allow-list's block
// stays on the row and the operator's answer is its own check, attributed.
func TestCreateRecordsTheOverride(t *testing.T) {
	for _, tc := range []struct {
		answer   bool
		err      error
		decision string
		override string
	}{
		{true, nil, audit.AdmissionAdmitted, audit.CheckPass},
		{false, nil, audit.AdmissionPolicyBlocked, audit.CheckBlock},
		{false, errors.New("EOF"), audit.AdmissionPolicyBlocked, audit.CheckNotEvaluated},
	} {
		f := newAdmissionFixture(t)
		if err := f.adb.InsertPolicy(t.Context(), audit.PolicyInfo{ID: "r1", RegistryType: manifest.TypeNpm, RuleKind: policy.KindPackage, Pattern: "lodash"}); err != nil {
			t.Fatalf("InsertPolicy: %v", err)
		}
		asked := 0
		confirm := func(version, candidate string) (bool, error) {
			asked++
			if version != "1.2.8" || candidate != "minimist" {
				t.Errorf("confirm asked about %s/%s", version, candidate)
			}
			return tc.answer, tc.err
		}
		res := Create(t.Context(), policy.NewChecker(f.adb), f.adb, f.synced, minimist("1.2.8"), Who{Actor: "ravi"}, confirm)
		if asked != 1 {
			t.Fatalf("confirm asked %d times, want 1", asked)
		}
		rows := f.rows(t, "minimist")
		if len(rows) != 1 {
			t.Fatalf("want one row, got %d", len(rows))
		}
		r := rows[0]
		if r.Decision != tc.decision || res.OK() != (tc.decision == audit.AdmissionAdmitted) {
			t.Errorf("answer %v: decision %q (OK=%v), want %q", tc.answer, r.Decision, res.OK(), tc.decision)
		}
		if al := checkOf(t, r, audit.CheckAllowList); al.Status != audit.CheckBlock {
			t.Errorf("answer %v: allowlist = %+v, want the block kept", tc.answer, al)
		}
		if ov := checkOf(t, r, audit.CheckOverride); ov.Status != tc.override {
			t.Errorf("answer %v: override = %+v, want %s", tc.answer, ov, tc.override)
		}
		if r.Actor != "ravi" || r.PolicyDigest != f.digest(t) {
			t.Errorf("answer %v: actor %q digest %q", tc.answer, r.Actor, r.PolicyDigest)
		}
		if tc.answer {
			if osv := checkOf(t, r, audit.CheckOSV); osv.Status != audit.CheckPass {
				t.Errorf("an override skipped the OSV check: %+v", osv)
			}
		}
	}
}

// TestFetchRecordsOneVersion is the builder's and the proxy's entry point.
func TestFetchRecordsOneVersion(t *testing.T) {
	f := newAdmissionFixture(t)
	ctx := context.Background()
	allow := AllowListCheck(false, "minimist", nil)
	checkers := VersionCheckers(f.synced, f.adb)

	ok := Fetch(ctx, f.adb, checkers, manifest.TypeNpm, "minimist", manifest.VersionEntry{Version: "1.2.8"}, allow, Who{Identity: "build-07"}, "")
	if ok.Block != nil || ok.Admission.Decision != audit.AdmissionAdmitted || ok.Admission.Identity != "build-07" {
		t.Errorf("clean fetch = %+v", ok)
	}
	blocked := Fetch(ctx, f.adb, checkers, manifest.TypeNpm, "minimist", manifest.VersionEntry{Version: "1.2.0"}, allow, Who{}, "")
	if blocked.Block == nil || blocked.Block.Check != "osv" || blocked.Admission.Decision != audit.AdmissionPolicyBlocked {
		t.Errorf("vulnerable fetch = %+v", blocked)
	}
	refused := Fetch(ctx, f.adb, checkers, manifest.TypeNpm, "minimist", manifest.VersionEntry{Version: "1.2.8"},
		AllowListCheck(true, "minimist", &policy.ViolationError{Candidate: "minimist"}), Who{}, "")
	if refused.Admission.Decision != audit.AdmissionPolicyBlocked || checkOf(t, refused.Admission, audit.CheckOSV).Status != audit.CheckNotEvaluated {
		t.Errorf("allow-list refusal = %+v", refused.Admission)
	}
	skipped := Fetch(ctx, f.adb, nil, manifest.TypeHelm, "chart", manifest.VersionEntry{Version: "1.0.0"}, allow, Who{}, "not run: no version")
	if c := checkOf(t, skipped.Admission, audit.CheckAge); c.Status != audit.CheckNotEvaluated || c.Detail != "not run: no version" {
		t.Errorf("nil checkers recorded %+v", c)
	}
	if got := len(f.rows(t, "minimist")); got != 3 {
		t.Errorf("stored %d minimist rows, want 3", got)
	}
}
