package policy

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

func openAudit(t *testing.T) *audit.DB {
	t.Helper()
	db, err := audit.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// A type with no rules and no mode is open, as it always was. Setting it
// listed refuses every name until a rule matches one; setting it open with a
// rule in place admits names the rule does not match.
func TestAdmissionModeSwitching(t *testing.T) {
	db := openAudit(t)
	ctx := t.Context()
	c := NewChecker(db)
	mode := func() Mode {
		t.Helper()
		c.Invalidate()
		m, err := c.ModeFor(ctx, manifest.TypeCargo)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}

	if m := mode(); m.Mode != audit.ModeOpen || m.Set || m.Rules != 0 {
		t.Fatalf("fresh cargo = %+v, want open by default with no rules", m)
	}
	if err := c.Check(ctx, manifest.TypeCargo, "serde"); err != nil {
		t.Fatalf("open by default refused serde: %v", err)
	}

	if err := db.SetAdmissionMode(ctx, audit.AdmissionMode{Ecosystem: manifest.TypeCargo, Mode: audit.ModeListed, Actor: "ravi"}); err != nil {
		t.Fatal(err)
	}
	if m := mode(); m.Mode != audit.ModeListed || !m.Set {
		t.Fatalf("after set listed = %+v", m)
	}
	if err := c.Check(ctx, manifest.TypeCargo, "serde"); !IsViolation(err) {
		t.Fatalf("listed with no rules admitted serde: %v", err)
	}
	if listed, _ := c.Listed(ctx, manifest.TypeCargo); !listed {
		t.Error("Listed = false in listed mode")
	}

	if err := db.InsertPolicy(ctx, audit.PolicyInfo{ID: "r1", RegistryType: manifest.TypeCargo, RuleKind: KindPackage, Pattern: "serde"}); err != nil {
		t.Fatal(err)
	}
	c.Invalidate()
	if err := c.Check(ctx, manifest.TypeCargo, "serde"); err != nil {
		t.Errorf("listed refused the listed serde: %v", err)
	}
	if err := c.Check(ctx, manifest.TypeCargo, "tokio"); !IsViolation(err) {
		t.Errorf("listed admitted unlisted tokio: %v", err)
	}

	if err := db.SetAdmissionMode(ctx, audit.AdmissionMode{Ecosystem: manifest.TypeCargo, Mode: audit.ModeOpen, Actor: "ravi"}); err != nil {
		t.Fatal(err)
	}
	if m := mode(); m.Mode != audit.ModeOpen || !m.Set || m.Rules != 1 {
		t.Fatalf("after set open = %+v, want open, set, one rule", m)
	}
	if err := c.Check(ctx, manifest.TypeCargo, "tokio"); err != nil {
		t.Errorf("open mode refused tokio: %v", err)
	}
	if listed, _ := c.Listed(ctx, manifest.TypeCargo); listed {
		t.Error("Listed = true in open mode")
	}
	// Another type's rules and mode are its own.
	if m, _ := c.ModeFor(ctx, manifest.TypeNpm); m.Set {
		t.Errorf("npm picked up cargo's mode: %+v", m)
	}
}

// report sets every gate with a row to warn and enforce writes back exactly
// what each one had, ignore included; a gate with no row stays without one.
// Each switch is one audit event naming the actor and every gate's before and
// after.
func TestRolloutRoundTripRestoresEachAction(t *testing.T) {
	db := openAudit(t)
	ctx := t.Context()
	eco := manifest.TypeNpm
	if err := db.SetAgePolicy(ctx, audit.AgePolicy{Ecosystem: eco, MinAgeSeconds: 3 * 86400, Action: ActionBlock}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetOSVPolicy(ctx, audit.OSVPolicy{Ecosystem: eco, Action: ActionIgnore}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetProvenancePolicy(ctx, audit.ProvenancePolicy{Ecosystem: eco, Action: ActionBlock}); err != nil {
		t.Fatal(err)
	}
	before, err := gateActions(ctx, db, eco)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := before[audit.CheckNameSimilarity]; ok {
		t.Fatalf("fixture has a similarity row: %v", before)
	}

	switches, err := SwitchRollout(ctx, db, eco, RolloutReport, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(switches) != len(before) {
		t.Fatalf("switches = %+v, want one per gate with a row (%v)", switches, before)
	}
	during, _ := gateActions(ctx, db, eco)
	for gate := range before {
		if during[gate] != ActionWarn {
			t.Errorf("%s in report mode = %s, want warn", gate, during[gate])
		}
	}
	if _, ok := during[audit.CheckNameSimilarity]; ok {
		t.Error("report created a similarity row")
	}
	if age, _ := db.GetAgePolicy(ctx, eco); age.MinAgeSeconds != 3*86400 {
		t.Errorf("report changed the age threshold to %d", age.MinAgeSeconds)
	}
	if _, err := SwitchRollout(ctx, db, eco, RolloutReport, "alice"); err == nil {
		t.Fatal("a second report succeeded; it would save the warns over the real actions")
	}

	if _, err := SwitchRollout(ctx, db, eco, RolloutEnforce, "bob"); err != nil {
		t.Fatal(err)
	}
	after, _ := gateActions(ctx, db, eco)
	if len(after) != len(before) {
		t.Fatalf("after enforce = %v, want %v", after, before)
	}
	for gate, action := range before {
		if after[gate] != action {
			t.Errorf("%s after enforce = %s, want %s", gate, after[gate], action)
		}
	}
	if _, err := db.GetRollout(ctx, eco); !errors.Is(err, audit.ErrRolloutNotFound) {
		t.Errorf("rollout row after enforce: %v", err)
	}
	if _, err := SwitchRollout(ctx, db, eco, RolloutEnforce, "bob"); err == nil {
		t.Error("enforce outside report mode succeeded")
	}

	evs, err := db.Query(ctx, audit.Filter{EventType: audit.EventPolicy})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("events = %d, want one per switch", len(evs))
	}
	for _, ev := range evs {
		var d struct {
			Rollout string             `json:"rollout"`
			Gates   []audit.GateSwitch `json:"gates"`
		}
		if err := json.Unmarshal([]byte(ev.Details), &d); err != nil {
			t.Fatal(err)
		}
		if len(d.Gates) != len(before) || (d.Rollout == RolloutReport) != (ev.Actor == "alice") {
			t.Errorf("event %s by %s = %+v", d.Rollout, ev.Actor, d.Gates)
		}
		for _, g := range d.Gates {
			if d.Rollout == RolloutEnforce && (g.Before != ActionWarn || g.After != before[g.Gate]) {
				t.Errorf("enforce event %s: %s -> %s, want warn -> %s", g.Gate, g.Before, g.After, before[g.Gate])
			}
		}
	}
}

// The report groups by ecosystem, check and package, counts every request,
// collects the identities that asked, lets a block outrank a warn, keeps
// baseline findings under their own heading, and says what each check does
// once enforced.
func TestBuildReportGroups(t *testing.T) {
	row := func(typ, name, version, identity string, checks ...audit.AdmissionCheck) audit.Admission {
		return audit.Admission{PkgType: typ, PkgName: name, PkgVersion: version, Identity: identity, Checks: checks}
	}
	warn := func(check string) audit.AdmissionCheck {
		return audit.AdmissionCheck{Check: check, Status: audit.CheckWarn, Detail: check + " warned"}
	}
	flagged := []audit.Admission{
		row("npm", "left-pad", "1.3.0", "ci-1", warn(audit.CheckAge), warn(audit.CheckOSV)),
		row("npm", "left-pad", "1.3.0", "ci-2", warn(audit.CheckAge)),
		row("npm", "left-pad", "1.2.0", "", warn(audit.CheckAge)),
		row("npm", "left-pad", "1.1.0", "ci-1", audit.AdmissionCheck{Check: audit.CheckAge, Status: audit.CheckBlock}),
		row("pypi", "reqeusts", "2.0", "ci-1", warn(audit.CheckNameSimilarity),
			audit.AdmissionCheck{Check: audit.CheckOSV, Status: audit.CheckPass}),
	}
	debt := []audit.Admission{
		row("npm", "minimist", "1.2.0", "", audit.AdmissionCheck{Check: audit.CheckOSV, Status: audit.CheckBaseline, Detail: "GHSA"}),
	}
	onEnforce := map[string]map[string]string{"npm": {audit.CheckAge: ActionBlock}}
	rep := BuildReport(time.Time{}, flagged, debt, onEnforce)

	if len(rep.Flagged) != 3 {
		t.Fatalf("flagged groups = %+v, want npm age, npm osv, pypi similarity", rep.Flagged)
	}
	age := rep.Flagged[0]
	if age.Ecosystem != "npm" || age.Check != audit.CheckAge || age.Package != "left-pad" {
		t.Fatalf("first group = %+v", age)
	}
	if age.Requests != 4 || age.Status != audit.CheckBlock || age.OnEnforce != ActionBlock || age.Unidentified != 1 {
		t.Errorf("age group = %+v, want 4 requests, block, on enforce block, 1 unidentified", age)
	}
	if len(age.Hosts) != 2 || age.Hosts[0] != "ci-1" || age.Hosts[1] != "ci-2" {
		t.Errorf("age hosts = %v, want ci-1 and ci-2", age.Hosts)
	}
	if len(age.Versions) != 3 {
		t.Errorf("age versions = %v, want three", age.Versions)
	}
	if osv := rep.Flagged[1]; osv.Check != audit.CheckOSV || osv.Requests != 1 || osv.OnEnforce != "" {
		t.Errorf("osv group = %+v", osv)
	}
	if sim := rep.Flagged[2]; sim.Ecosystem != "pypi" || sim.Check != audit.CheckNameSimilarity {
		t.Errorf("third group = %+v, want pypi name_similarity (a pass is not flagged)", sim)
	}
	if len(rep.BaselineDebt) != 1 || rep.BaselineDebt[0].Package != "minimist" || rep.BaselineDebt[0].Status != audit.CheckBaseline {
		t.Errorf("baseline debt = %+v", rep.BaselineDebt)
	}
}

// The report's window is a SQL filter on decided_at, so a row outside it is
// never read rather than read and dropped.
func TestAdmissionsSince(t *testing.T) {
	db := openAudit(t)
	ctx := t.Context()
	now := time.Now()
	for _, at := range []time.Time{now.Add(-10 * 24 * time.Hour), now.Add(-time.Hour)} {
		if err := db.RecordAdmission(ctx, audit.Admission{PkgType: "npm", PkgName: "left-pad", PkgVersion: "1.3.0",
			Decision: audit.AdmissionAdmitted, DecidedAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.Admissions(ctx, audit.AdmissionFilter{Since: now.Add(-7 * 24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].DecidedAt.Before(now.Add(-2*time.Hour)) {
		t.Fatalf("rows since 7d = %+v, want only the recent one", rows)
	}
}
