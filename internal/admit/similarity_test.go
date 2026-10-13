package admit

import (
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// cargo keeps these cases offline: no age gate is seeded for it, OSV reads
// the fixture's local database, and the provenance check reads nothing.
func crate(name string) *manifest.PackageManifest {
	return &manifest.PackageManifest{Type: manifest.TypeCargo, Name: name,
		Versions: []manifest.VersionEntry{{Version: "1.0.0"}}}
}

func cargoRow(t *testing.T, f admissionFixture, name string) audit.Admission {
	t.Helper()
	rows, err := f.adb.Admissions(t.Context(), audit.AdmissionFilter{PkgType: manifest.TypeCargo, PkgName: name})
	if err != nil || len(rows) == 0 {
		t.Fatalf("Admissions(%s) = %d rows, %v", name, len(rows), err)
	}
	return rows[0]
}

// The check's verdict lands in the admission row: a warn by default naming
// the popular crate and the distance, a refusal under block, and an exempt
// pass for an exact allow-list rule or a name in the baseline.
func TestAdmitRecordsNameSimilarity(t *testing.T) {
	f := newAdmissionFixture(t)
	ctx := t.Context()

	res := Admit(ctx, policy.NewChecker(f.adb), f.adb, f.unsynced, crate("serde_jsno"), "ravi")
	if res.Decision != Admitted {
		t.Fatalf("default: Decision = %v (%s), want admitted under warn", res.Decision, res.Reason)
	}
	c := checkOf(t, cargoRow(t, f, "serde_jsno"), audit.CheckNameSimilarity)
	if c.Action != policy.ActionWarn || c.Status != audit.CheckWarn ||
		!strings.Contains(c.Detail, "serde_json") || !strings.Contains(c.Detail, "distance 1") {
		t.Errorf("default check = %+v", c)
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "name_similarity") {
		t.Errorf("warnings %v do not report the near name", res.Warnings)
	}

	if err := f.adb.SetSimilarityPolicy(ctx, audit.SimilarityPolicy{Ecosystem: manifest.TypeCargo, Action: policy.ActionBlock}); err != nil {
		t.Fatal(err)
	}
	res = Admit(ctx, policy.NewChecker(f.adb), f.adb, f.unsynced, crate("tokioo"), "ravi")
	if res.Decision != PolicyBlocked || res.Check != audit.CheckNameSimilarity {
		t.Fatalf("block: Decision = %v, Check = %q (%s)", res.Decision, res.Check, res.Reason)
	}
	row := cargoRow(t, f, "tokioo")
	if row.Decision != audit.AdmissionPolicyBlocked {
		t.Errorf("block row decision = %s", row.Decision)
	}
	if c := checkOf(t, row, audit.CheckNameSimilarity); c.Status != audit.CheckBlock || c.Action != policy.ActionBlock {
		t.Errorf("block check = %+v", c)
	}

	if res := Admit(ctx, policy.NewChecker(f.adb), f.adb, f.unsynced, crate("bodega-widget"), "ravi"); res.Decision != Admitted {
		t.Errorf("a far name under block: %v (%s)", res.Decision, res.Reason)
	}
	if c := checkOf(t, cargoRow(t, f, "bodega-widget"), audit.CheckNameSimilarity); c.Status != audit.CheckPass {
		t.Errorf("far name check = %+v", c)
	}

	if took, err := policy.TakeNameBaseline(ctx, f.adb, map[string][]string{manifest.TypeCargo: {"randd"}}); err != nil || !took {
		t.Fatalf("TakeNameBaseline = %v, %v", took, err)
	}
	if res := Admit(ctx, policy.NewChecker(f.adb), f.adb, f.unsynced, crate("randd"), "ravi"); res.Decision != Admitted {
		t.Errorf("baseline name under block: %v (%s)", res.Decision, res.Reason)
	}
	if c := checkOf(t, cargoRow(t, f, "randd"), audit.CheckNameSimilarity); c.Status != audit.CheckPass || !strings.Contains(c.Detail, "exempt") {
		t.Errorf("baseline check = %+v", c)
	}

	if err := f.adb.InsertPolicy(ctx, audit.PolicyInfo{ID: "r1", RegistryType: manifest.TypeCargo,
		RuleKind: policy.KindPackage, Pattern: "tokioo"}); err != nil {
		t.Fatal(err)
	}
	if res := Admit(ctx, policy.NewChecker(f.adb), f.adb, f.unsynced, crate("tokioo"), "ravi"); res.Decision != Admitted {
		t.Errorf("exact rule under block: %v (%s)", res.Decision, res.Reason)
	}
}

// A fetch (the builder's and the proxy's admission) runs the same check.
func TestFetchRecordsNameSimilarity(t *testing.T) {
	f := newAdmissionFixture(t)
	allow := AllowListCheck(false, "serde_jsno", nil)
	res := Fetch(t.Context(), f.adb, VersionCheckers(f.unsynced, f.adb), manifest.TypeCargo, "serde_jsno",
		manifest.VersionEntry{Version: "1.0.0"}, allow, Who{Actor: "ravi"}, "")
	if res.Block != nil {
		t.Fatalf("Block = %+v under the default warn", res.Block)
	}
	if c := checkOf(t, res.Admission, audit.CheckNameSimilarity); c.Status != audit.CheckWarn || !strings.Contains(c.Detail, "serde_json") {
		t.Errorf("fetch check = %+v", c)
	}
	refused := Fetch(t.Context(), f.adb, nil, manifest.TypeCargo, "serde_jsno",
		manifest.VersionEntry{Version: "1.0.0"}, AllowListCheck(true, "serde_jsno", &policy.ViolationError{}), Who{}, "")
	if c := checkOf(t, refused.Admission, audit.CheckNameSimilarity); c.Status != audit.CheckNotEvaluated {
		t.Errorf("after an allow-list refusal = %+v, want not_evaluated", c)
	}
}
