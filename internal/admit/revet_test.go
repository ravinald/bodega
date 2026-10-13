package admit

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/attest"
	"github.com/ravinald/bodega/internal/attestsign"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
	"github.com/ravinald/bodega/internal/storage"
)

// verdict is a version checker whose answer a test sets.
type verdict struct{ action string }

func (v *verdict) Check(context.Context, *manifest.PackageManifest, *manifest.VersionEntry) policy.Result {
	if v.action == policy.ActionBlock {
		return policy.Result{Check: audit.CheckOSV, Action: policy.ActionBlock, Reason: "GHSA-late-0001 published after admission"}
	}
	return policy.Result{Check: audit.CheckOSV, Action: policy.ActionPass}
}

type revetFixture struct {
	adb     *audit.DB
	dir     string
	store   *manifest.Store
	osv     *verdict
	objects storage.ObjectStore
}

const revetKey = "npm/minimist/-/minimist-1.2.0.tgz"

// newRevetFixture catalogs minimist 1.2.0 and records the admission that
// passed it a month ago, pinned under revetKey with a sha256 on file.
func newRevetFixture(t *testing.T, ve manifest.VersionEntry) revetFixture {
	t.Helper()
	f := newAdmissionFixture(t)
	dir := t.TempDir()
	store := manifest.NewLocalStore(dir)
	ve.Version = "1.2.0"
	if err := store.AddVersion(t.Context(), manifest.TypeNpm, "minimist", ve); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveIndex(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := f.adb.RecordAdmission(t.Context(), audit.Admission{
		PkgType: manifest.TypeNpm, PkgName: "minimist", PkgVersion: "1.2.0", ObjectKey: revetKey,
		Decision: audit.AdmissionAdmitted, Actor: "ravi", DecidedAt: time.Now().Add(-30 * 24 * time.Hour),
		Checks: []audit.AdmissionCheck{
			{Check: audit.CheckAllowList, Action: audit.ActionNone, Status: audit.CheckPass},
			{Check: audit.CheckAge, Action: policy.ActionBlock, Status: audit.CheckPass, Detail: "published 40d ago"},
			{Check: audit.CheckOSV, Action: policy.ActionBlock, Status: audit.CheckPass},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.adb.StoreChecksum(t.Context(), revetKey, manifest.TypeNpm, "minimist", "1.2.0", "sha256",
		strings.Repeat("ab", 32), "computed"); err != nil {
		t.Fatal(err)
	}
	return revetFixture{adb: f.adb, dir: dir, store: store, osv: &verdict{action: policy.ActionBlock}, objects: storage.NewMemory()}
}

func (f revetFixture) revetter(onBlock string) *Revetter {
	return &Revetter{
		Cfg: &config.Config{}, DB: f.adb, Store: f.store, OnBlock: onBlock,
		Checkers: func() []policy.VersionChecker { return []policy.VersionChecker{f.osv} },
	}
}

// onDisk reads the version back through a store the revetter never held, so
// a hide that never reached SavePackage cannot pass.
func (f revetFixture) onDisk(t *testing.T) manifest.VersionEntry {
	t.Helper()
	pm, err := manifest.NewLocalStore(f.dir).GetPackage(t.Context(), manifest.TypeNpm, "minimist")
	if err != nil || pm == nil {
		t.Fatalf("read back: %v", err)
	}
	return pm.Versions[0]
}

func (f revetFixture) events(t *testing.T, et audit.EventType) []audit.StoredEvent {
	t.Helper()
	evs, err := f.adb.Query(t.Context(), audit.Filter{EventType: et, PkgName: "minimist"})
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

func target() RevetTarget {
	return RevetTarget{Type: manifest.TypeNpm, Name: "minimist", Version: "1.2.0"}
}

// A version admitted clean a month ago, re-vetted after an advisory landed,
// gets a policy_blocked row beside the admitted one, attributed to revet,
// pinned to the same object, with the age verdict carried rather than re-run.
// Under report it stays served.
func TestRevetFlipsPassToBlockUnderReport(t *testing.T) {
	f := newRevetFixture(t, manifest.VersionEntry{})
	o := f.revetter(config.RevetReport).One(t.Context(), target(), "schedule")
	if o.Error != "" {
		t.Fatalf("re-vet error: %s", o.Error)
	}
	if o.Previous != audit.AdmissionAdmitted || o.Decision != audit.AdmissionPolicyBlocked || o.Action != RevetReported {
		t.Fatalf("outcome = %+v, want admitted -> policy_blocked, reported", o)
	}

	rows := minimistRows(t, f.adb)
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want the admission kept and the re-vet beside it", len(rows))
	}
	newest, old := rows[0], rows[1]
	if old.Decision != audit.AdmissionAdmitted || old.Actor != "ravi" {
		t.Errorf("old row rewritten: %+v", old)
	}
	if newest.Decision != audit.AdmissionPolicyBlocked || newest.Actor != RevetActor || newest.Identity != "schedule" {
		t.Errorf("new row = %s by %s/%s", newest.Decision, newest.Actor, newest.Identity)
	}
	if newest.ObjectKey != revetKey {
		t.Errorf("new row object_key = %q, want %q", newest.ObjectKey, revetKey)
	}
	if newest.PolicyDigest == "" {
		t.Error("new row has no policy digest")
	}
	if c := checkOf(t, newest, audit.CheckOSV); c.Status != audit.CheckBlock {
		t.Errorf("osv = %+v, want block", c)
	}
	if c := checkOf(t, newest, audit.CheckAge); c.Status != audit.CheckPass || !strings.Contains(c.Detail, "not re-run") {
		t.Errorf("age = %+v, want the earlier pass carried and labeled", c)
	}

	if f.onDisk(t).Hidden {
		t.Error("report hid the version")
	}
	if evs := f.events(t, audit.EventRevet); len(evs) != 1 || evs[0].Actor != RevetActor || !strings.Contains(evs[0].Details, "GHSA-late-0001") {
		t.Errorf("revet events = %+v, want one naming the failing check", evs)
	}
	if evs := f.events(t, audit.EventHide); len(evs) != 0 {
		t.Errorf("report wrote a hide event: %+v", evs)
	}
}

// Under hide the refused version is hidden on disk, and the hide event names
// revet and the failing checks.
func TestRevetFlipsPassToBlockUnderHide(t *testing.T) {
	f := newRevetFixture(t, manifest.VersionEntry{})
	saved := ""
	rv := f.revetter(config.RevetHide)
	rv.Saved = func(_ context.Context, typ string) { saved = typ }
	o := rv.One(t.Context(), target(), "webhook")
	if o.Action != RevetHidden {
		t.Fatalf("action = %s (%v), want hidden", o.Action, o.Notes)
	}
	if !f.onDisk(t).Hidden {
		t.Error("version not hidden on disk")
	}
	if saved != manifest.TypeNpm {
		t.Errorf("Saved hook = %q, want npm", saved)
	}
	evs := f.events(t, audit.EventHide)
	if len(evs) != 1 || evs[0].Actor != RevetActor {
		t.Fatalf("hide events = %+v, want one by revet", evs)
	}
	var details struct {
		Failing []audit.AdmissionCheck `json:"failing"`
	}
	if err := json.Unmarshal([]byte(evs[0].Details), &details); err != nil || len(details.Failing) != 1 || details.Failing[0].Check != audit.CheckOSV {
		t.Errorf("hide details = %s, want the failing osv check", evs[0].Details)
	}
}

// A frozen version is reported and never hidden, whatever revet_on_block says.
func TestRevetNeverHidesAFrozenVersion(t *testing.T) {
	f := newRevetFixture(t, manifest.VersionEntry{Frozen: true})
	o := f.revetter(config.RevetHide).One(t.Context(), target(), "schedule")
	if o.Decision != audit.AdmissionPolicyBlocked || o.Action != RevetFrozen {
		t.Fatalf("outcome = %+v, want policy_blocked, frozen", o)
	}
	if f.onDisk(t).Hidden {
		t.Error("frozen version hidden")
	}
	if evs := f.events(t, audit.EventHide); len(evs) != 0 {
		t.Errorf("hide events = %+v, want none", evs)
	}
	if evs := f.events(t, audit.EventRevet); len(evs) != 1 {
		t.Errorf("revet events = %d, want the refusal reported", len(evs))
	}
}

// A refusal signs an envelope recording the block, and it is the newest one
// for the object; a later pass that overturns it signs one recording the pass.
func TestRevetSignsTheRevocation(t *testing.T) {
	f := newRevetFixture(t, manifest.VersionEntry{})
	ring, err := attestsign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	signer := ring.Signer()
	rv := f.revetter(config.RevetReport)
	rv.Stores = storage.NewSingle(f.objects)
	rv.Emitter = &attest.Emitter{Signer: func() attestsign.Signer { return signer }, Admissions: f.adb, PlatformID: "bodega://test"}

	o := rv.One(t.Context(), target(), "schedule")
	if len(o.Envelopes) != 1 {
		t.Fatalf("envelopes = %v (%v), want one", o.Envelopes, o.Notes)
	}
	st := newestStatement(t, f.objects)
	pe := st.Predicate.PolicyEvaluations
	if pe.Decision != audit.AdmissionPolicyBlocked {
		t.Errorf("newest envelope decision = %s, want policy_blocked", pe.Decision)
	}
	blocked := false
	for _, e := range pe.Evaluations {
		blocked = blocked || (e.Check == audit.CheckOSV && e.Status == audit.CheckBlock)
	}
	if !blocked {
		t.Errorf("evaluations do not record the osv block: %+v", pe.Evaluations)
	}

	// The advisory is withdrawn.
	f.osv.action = policy.ActionPass
	o = rv.One(t.Context(), target(), "schedule")
	if o.Decision != audit.AdmissionAdmitted || len(o.Envelopes) != 1 {
		t.Fatalf("outcome = %+v, want admitted with one envelope", o)
	}
	if d := newestStatement(t, f.objects).Predicate.PolicyEvaluations.Decision; d != audit.AdmissionAdmitted {
		t.Errorf("newest envelope after the withdrawal = %s, want admitted", d)
	}
}

// A clean re-vet of a clean version writes its row and signs nothing.
func TestRevetPassSignsNothing(t *testing.T) {
	f := newRevetFixture(t, manifest.VersionEntry{})
	f.osv.action = policy.ActionPass
	ring, _ := attestsign.Generate()
	signer := ring.Signer()
	rv := f.revetter(config.RevetHide)
	rv.Stores = storage.NewSingle(f.objects)
	rv.Emitter = &attest.Emitter{Signer: func() attestsign.Signer { return signer }, Admissions: f.adb}
	o := rv.One(t.Context(), target(), "schedule")
	if o.Decision != audit.AdmissionAdmitted || o.Action != RevetNone || len(o.Envelopes) != 0 {
		t.Fatalf("outcome = %+v, want admitted, none, unsigned", o)
	}
	if rows := minimistRows(t, f.adb); len(rows) != 2 || rows[0].Actor != RevetActor {
		t.Errorf("rows = %+v, want the re-vet recorded", rows)
	}
}

// --older-than skips a version decided inside the window.
func TestRevetTargetsOlderThan(t *testing.T) {
	f := newRevetFixture(t, manifest.VersionEntry{})
	rv := f.revetter(config.RevetReport)
	got, err := rv.Targets(t.Context(), RevetFilter{OlderThan: 7 * 24 * time.Hour})
	if err != nil || len(got) != 1 {
		t.Fatalf("targets = %v, %v; want the month-old admission", got, err)
	}
	if _, err := rv.Targets(t.Context(), RevetFilter{OlderThan: 60 * 24 * time.Hour}); err != nil {
		t.Fatalf("unfiltered-by-name walk with nothing old enough: %v", err)
	}
	if _, err := rv.Targets(t.Context(), RevetFilter{Name: "minimist", OlderThan: 60 * 24 * time.Hour}); err != ErrNoRevetTargets {
		t.Errorf("named walk with nothing old enough = %v, want ErrNoRevetTargets", err)
	}
}

func minimistRows(t *testing.T, adb *audit.DB) []audit.Admission {
	t.Helper()
	rows, err := adb.Admissions(t.Context(), audit.AdmissionFilter{PkgType: manifest.TypeNpm, PkgName: "minimist", PkgVersion: "1.2.0"})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func newestStatement(t *testing.T, objects storage.ObjectStore) attest.Statement {
	t.Helper()
	key, err := attest.Newest(t.Context(), objects, []string{revetKey})
	if err != nil || key == "" {
		t.Fatalf("newest envelope: %q, %v", key, err)
	}
	body, err := objects.Get(t.Context(), key)
	if err != nil {
		t.Fatal(err)
	}
	_, st, err := attest.ParseEnvelope(body)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(key)+"/" != manifest.AttestationDir(revetKey) {
		t.Errorf("envelope %s filed outside %s", key, manifest.AttestationDir(revetKey))
	}
	return *st
}
