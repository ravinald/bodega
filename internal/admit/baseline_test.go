package admit

import (
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// minimist 1.2.0 fails the fixture's OSV gate at block. Marked baseline it is
// admitted, and the row keeps the finding under status baseline rather than
// reading as a pass. The same version unmarked is still refused.
func TestBaselineAdmitsAFailingVersion(t *testing.T) {
	f := newAdmissionFixture(t)
	if res, row := admitMinimist(t, f, "1.2.0"); res.OK() || checkOf(t, row, audit.CheckOSV).Status != audit.CheckBlock {
		t.Fatalf("unmarked 1.2.0 = %s, want refused by osv", row.Decision)
	}

	pm := minimist("1.2.0")
	MarkBaseline(pm, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	res := Admit(t.Context(), policy.NewChecker(f.adb), f.adb, f.synced, pm, "ravi")
	if !res.OK() || len(res.Admissions) != 1 || res.Admissions[0].Decision != audit.AdmissionAdmitted {
		t.Fatalf("baseline 1.2.0 = %+v (%s), want admitted", res.Admissions, res.Reason)
	}
	c := checkOf(t, res.Admissions[0], audit.CheckOSV)
	if c.Status != audit.CheckBaseline || c.Action != policy.ActionBlock ||
		!strings.Contains(c.Detail, "GHSA-test-0001") || !strings.Contains(c.Detail, "2026-10-01T00:00:00Z") {
		t.Errorf("osv check = %+v, want baseline keeping the advisory and the mark time", c)
	}
}

// In listed mode a name no rule matches is refused by the allow-list; the
// baseline mark admits it past that gate too, since what hosts already run is
// what the list was written after.
func TestBaselineAdmitsPastTheAllowList(t *testing.T) {
	f := newAdmissionFixture(t)
	if err := f.adb.SetAdmissionMode(t.Context(), audit.AdmissionMode{Ecosystem: manifest.TypeNpm, Mode: audit.ModeListed}); err != nil {
		t.Fatal(err)
	}
	if res, _ := admitMinimist(t, f, "1.2.8"); res.OK() {
		t.Fatal("listed mode with no rules admitted an unlisted name")
	}
	pm := minimist("1.2.8")
	MarkBaseline(pm, time.Now())
	res := Admit(t.Context(), policy.NewChecker(f.adb), f.adb, f.synced, pm, "ravi")
	if !res.OK() {
		t.Fatalf("baseline 1.2.8 refused: %s", res.Reason)
	}
	if c := checkOf(t, res.Admissions[0], audit.CheckAllowList); c.Status != audit.CheckBaseline || c.Action != policy.ActionBlock {
		t.Errorf("allowlist check = %+v, want baseline at action block", c)
	}
}

// A mark a manifest arrives with is dropped unless the store already held it
// for that version, in which case the held time wins over the one supplied.
func TestCarryBaselineKeepsOnlyHeldMarks(t *testing.T) {
	existing := minimist("1.2.0", "1.2.5")
	existing.Versions[0].Baseline, existing.Versions[0].BaselineAt = true, "2026-09-01T00:00:00Z"

	incoming := minimist("1.2.0", "1.2.5", "1.2.8")
	for i := range incoming.Versions {
		incoming.Versions[i].Baseline, incoming.Versions[i].BaselineAt = true, "2026-10-13T00:00:00Z"
	}
	dropped := CarryBaseline(incoming, existing)
	if strings.Join(dropped, ",") != "1.2.5,1.2.8" {
		t.Errorf("dropped = %v, want 1.2.5 and 1.2.8", dropped)
	}
	got := incoming.Versions
	if !got[0].Baseline || got[0].BaselineAt != "2026-09-01T00:00:00Z" {
		t.Errorf("held 1.2.0 = %v %q, want the existing mark", got[0].Baseline, got[0].BaselineAt)
	}
	for _, ve := range got[1:] {
		if ve.Baseline || ve.BaselineAt != "" {
			t.Errorf("%s kept a mark the store never held: %v %q", ve.Version, ve.Baseline, ve.BaselineAt)
		}
	}
	if d := CarryBaseline(minimist("1.2.0"), nil); len(d) != 0 {
		t.Errorf("an unmarked manifest reported drops: %v", d)
	}
}

// A re-vet reads the version from the store, so a baseline version a new
// advisory now fails is admitted with the finding rather than refused.
func TestRevetHonorsBaseline(t *testing.T) {
	f := newRevetFixture(t, manifest.VersionEntry{Baseline: true, BaselineAt: "2026-09-01T00:00:00Z"})
	o := f.revetter(config.RevetHide).One(t.Context(), target(), "schedule")
	if o.Error != "" || o.Decision != audit.AdmissionAdmitted || o.Action != RevetNone {
		t.Fatalf("outcome = %+v, want admitted with no action", o)
	}
	if f.onDisk(t).Hidden {
		t.Error("re-vet hid a baseline version")
	}
	if c := checkOf(t, minimistRows(t, f.adb)[0], audit.CheckOSV); c.Status != audit.CheckBaseline {
		t.Errorf("re-vet osv check = %+v, want baseline", c)
	}
}

// clear removes the mark on the versions --older-than selects, saves them,
// and reports which of them now fail: 1.2.0 fails OSV, 1.2.8 is clean, and
// 1.2.5, marked yesterday, keeps its mark under a 7d cutoff.
func TestClearBaselineReportsWhatNowFails(t *testing.T) {
	f := newAdmissionFixture(t)
	dir := t.TempDir()
	store := manifest.NewLocalStore(dir)
	now := time.Now()
	old := now.Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	recent := now.Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	for _, ve := range []manifest.VersionEntry{
		{Version: "1.2.0", Baseline: true, BaselineAt: old},
		{Version: "1.2.5", Baseline: true, BaselineAt: recent},
		{Version: "1.2.8", Baseline: true, BaselineAt: old},
	} {
		if err := store.AddVersion(t.Context(), manifest.TypeNpm, "minimist", ve); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SaveIndex(t.Context()); err != nil {
		t.Fatal(err)
	}

	cleared, err := ClearBaseline(t.Context(), store, policy.NewChecker(f.adb), f.adb, f.synced, manifest.TypeNpm, 7*24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	failing := map[string]int{}
	for _, c := range cleared {
		failing[c.Version] = len(c.Failing)
	}
	if len(cleared) != 2 || failing["1.2.0"] != 1 || failing["1.2.8"] != 0 {
		t.Fatalf("cleared = %+v, want 1.2.0 failing one check and 1.2.8 clean", cleared)
	}
	if cleared[0].Failing[0].Check != audit.CheckOSV {
		t.Errorf("1.2.0 fails %s, want osv", cleared[0].Failing[0].Check)
	}

	pm, err := manifest.NewLocalStore(dir).GetPackage(t.Context(), manifest.TypeNpm, "minimist")
	if err != nil {
		t.Fatal(err)
	}
	for _, ve := range pm.Versions {
		if want := ve.Version == "1.2.5"; ve.Baseline != want {
			t.Errorf("%s baseline on disk = %v, want %v", ve.Version, ve.Baseline, want)
		}
	}
	if rows := f.rows(t, "minimist"); len(rows) != 0 {
		t.Errorf("clear recorded %d admission rows; its evaluation writes nothing", len(rows))
	}

	all, err := ClearBaseline(t.Context(), store, policy.NewChecker(f.adb), f.adb, f.synced, manifest.TypeNpm, 0, now)
	if err != nil || len(all) != 1 || all[0].Version != "1.2.5" {
		t.Fatalf("clear with no cutoff = %+v, %v; want the remaining 1.2.5", all, err)
	}
}
