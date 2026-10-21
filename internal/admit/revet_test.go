package admit

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
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
	st := newestStatement(t, f.objects, revetKey)
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
	if d := newestStatement(t, f.objects, revetKey).Predicate.PolicyEvaluations.Decision; d != audit.AdmissionAdmitted {
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

const proxyKey = "npm/left-pad/-/left-pad-1.3.0.tgz"

// admitProxyFill records what a proxy fill of left-pad 1.3.0 leaves behind:
// an admitted row pinned to the cached object and its sha256, and no catalog
// entry. is-odd 3.0.1 was refused at the fill, so it was never cached.
func (f revetFixture) admitProxyFill(t *testing.T) {
	t.Helper()
	for _, row := range []audit.Admission{
		{PkgType: manifest.TypeNpm, PkgName: "left-pad", PkgVersion: "1.3.0", ObjectKey: proxyKey,
			Decision: audit.AdmissionAdmitted, DecidedAt: time.Now().Add(-20 * 24 * time.Hour),
			Checks: []audit.AdmissionCheck{{Check: audit.CheckOSV, Action: policy.ActionBlock, Status: audit.CheckPass}}},
		{PkgType: manifest.TypeNpm, PkgName: "is-odd", PkgVersion: "3.0.1",
			Decision: audit.AdmissionPolicyBlocked, DecidedAt: time.Now().Add(-20 * 24 * time.Hour),
			Checks: []audit.AdmissionCheck{{Check: audit.CheckOSV, Action: policy.ActionBlock, Status: audit.CheckBlock}}},
	} {
		if err := f.adb.RecordAdmission(t.Context(), row); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.adb.StoreChecksum(t.Context(), proxyKey, manifest.TypeNpm, "left-pad", "1.3.0", "sha256",
		strings.Repeat("cd", 32), "computed"); err != nil {
		t.Fatal(err)
	}
}

func proxyTarget() RevetTarget {
	return RevetTarget{Type: manifest.TypeNpm, Name: "left-pad", Version: "1.3.0"}
}

// A version admitted by a proxy fill has no catalog entry and is still a
// target, under every filter that names it; a cataloged version is listed
// once, and a filter that drops it does not let the admissions table add it
// back; a version only ever refused is not a target.
func TestRevetTargetsIncludeProxyOnlyVersions(t *testing.T) {
	f := newRevetFixture(t, manifest.VersionEntry{})
	f.admitProxyFill(t)
	rv := f.revetter(config.RevetReport)
	cases := []struct {
		name string
		f    RevetFilter
		want []RevetTarget
	}{
		{"unfiltered", RevetFilter{}, []RevetTarget{target(), proxyTarget()}},
		{"type", RevetFilter{Type: manifest.TypeNpm}, []RevetTarget{target(), proxyTarget()}},
		{"name", RevetFilter{Name: "left-pad"}, []RevetTarget{proxyTarget()}},
		{"version", RevetFilter{Name: "left-pad", Version: "1.3.0"}, []RevetTarget{proxyTarget()}},
		{"version drops the cataloged one", RevetFilter{Version: "1.3.0"}, []RevetTarget{proxyTarget()}},
		{"older than both", RevetFilter{OlderThan: 7 * 24 * time.Hour}, []RevetTarget{target(), proxyTarget()}},
		{"older than the proxy fill", RevetFilter{OlderThan: 25 * 24 * time.Hour}, []RevetTarget{target()}},
		{"other type", RevetFilter{Type: manifest.TypePypi}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := rv.Targets(t.Context(), c.f)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("targets = %+v, want %+v", got, c.want)
			}
		})
	}
	if _, err := rv.Targets(t.Context(), RevetFilter{Name: "is-odd"}); err != ErrNoRevetTargets {
		t.Errorf("refused-only version = %v, want ErrNoRevetTargets", err)
	}
	if o := rv.One(t.Context(), RevetTarget{Type: manifest.TypeNpm, Name: "is-odd", Version: "3.0.1"}, "schedule"); o.Error == "" {
		t.Errorf("re-vet of a version never admitted = %+v, want an error", o)
	}
}

// A proxy-served version flipped to block gets a policy_blocked row beside
// the fill's, pinned to the cached object, and an envelope revoking it in
// the store the proxy caches into. There is no catalog entry to hide, so
// under either setting it is reported, the outcome says why, no hide event
// is written and no catalog entry appears.
func TestRevetProxyOnlyVersionIsReportedAndRevoked(t *testing.T) {
	for _, onBlock := range []string{config.RevetReport, config.RevetHide} {
		t.Run(onBlock, func(t *testing.T) {
			f := newRevetFixture(t, manifest.VersionEntry{})
			f.admitProxyFill(t)
			ring, err := attestsign.Generate()
			if err != nil {
				t.Fatal(err)
			}
			signer := ring.Signer()
			rv := f.revetter(onBlock)
			rv.Stores = storage.NewSingle(f.objects)
			rv.Emitter = &attest.Emitter{Signer: func() attestsign.Signer { return signer }, Admissions: f.adb, PlatformID: "bodega://test"}

			o := rv.One(t.Context(), proxyTarget(), "webhook")
			if o.Error != "" {
				t.Fatalf("re-vet error: %s", o.Error)
			}
			if o.Previous != audit.AdmissionAdmitted || o.Decision != audit.AdmissionPolicyBlocked || o.Action != RevetReported {
				t.Fatalf("outcome = %+v, want admitted -> policy_blocked, reported", o)
			}
			if !slices.ContainsFunc(o.Notes, func(n string) bool { return strings.Contains(n, "no catalog entry exists to hide") }) {
				t.Errorf("notes = %v, want the reason it was not hidden", o.Notes)
			}

			rows, err := f.adb.Admissions(t.Context(), audit.AdmissionFilter{PkgType: manifest.TypeNpm, PkgName: "left-pad", PkgVersion: "1.3.0"})
			if err != nil || len(rows) != 2 {
				t.Fatalf("rows = %+v (%v), want the fill's kept and the re-vet beside it", rows, err)
			}
			if r := rows[0]; r.Decision != audit.AdmissionPolicyBlocked || r.Actor != RevetActor || r.Identity != "webhook" || r.ObjectKey != proxyKey {
				t.Errorf("new row = %+v", r)
			}
			if rows[1].Decision != audit.AdmissionAdmitted || rows[1].Actor == RevetActor {
				t.Errorf("fill's row rewritten: %+v", rows[1])
			}

			if len(o.Envelopes) != 1 {
				t.Fatalf("envelopes = %v (%v), want one", o.Envelopes, o.Notes)
			}
			if d := newestStatement(t, f.objects, proxyKey).Predicate.PolicyEvaluations.Decision; d != audit.AdmissionPolicyBlocked {
				t.Errorf("newest envelope decision = %s, want policy_blocked", d)
			}

			for et, want := range map[audit.EventType]int{audit.EventHide: 0, audit.EventRevet: 1} {
				evs, err := f.adb.Query(t.Context(), audit.Filter{EventType: et, PkgName: "left-pad"})
				if err != nil || len(evs) != want {
					t.Errorf("%s events = %+v (%v), want %d", et, evs, err, want)
				}
			}
			if pm, err := f.store.GetPackage(t.Context(), manifest.TypeNpm, "left-pad"); err != nil || pm != nil {
				t.Errorf("re-vet wrote a catalog entry: %+v (%v)", pm, err)
			}
		})
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

func newestStatement(t *testing.T, objects storage.ObjectStore, object string) attest.Statement {
	t.Helper()
	key, err := attest.Newest(t.Context(), objects, []string{object})
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
	if filepath.Dir(key)+"/" != manifest.AttestationDir(object) {
		t.Errorf("envelope %s filed outside %s", key, manifest.AttestationDir(object))
	}
	return *st
}

const binaryKey = "binaries/tool/1.0.0/tool.tgz"

// cacheBinaryFill records what a binary proxy fill leaves behind: the object
// in the proxy store, its sha256, and an admitted row whose allow-list entry
// matched the upstream it was fetched from. With origin set, the cache origin
// is recorded under the identity of the stored object, as the fill does.
func (f revetFixture) cacheBinaryFill(t *testing.T, origin string) {
	t.Helper()
	ctx := t.Context()
	if err := f.objects.Put(ctx, binaryKey, []byte("tool bytes")); err != nil {
		t.Fatal(err)
	}
	if err := f.adb.RecordAdmission(ctx, audit.Admission{
		PkgType: manifest.TypeBinary, PkgName: "tool", PkgVersion: "1.0.0", ObjectKey: binaryKey,
		Decision: audit.AdmissionAdmitted, DecidedAt: time.Now().Add(-20 * 24 * time.Hour),
		Checks: []audit.AdmissionCheck{AllowListCheck(true, "https://evil.example.com/tool.tgz", nil)},
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.adb.StoreChecksum(ctx, binaryKey, manifest.TypeBinary, "tool", "1.0.0", "sha256",
		strings.Repeat("ef", 32), "computed"); err != nil {
		t.Fatal(err)
	}
	if origin == "" {
		return
	}
	res, err := f.objects.GetStream(ctx, binaryKey)
	if err != nil || res == nil {
		t.Fatalf("open cached object: %v", err)
	}
	_ = res.Body.Close()
	if err := f.adb.StoreCacheOrigin(ctx, binaryKey, origin, StreamIdentity(f.objects, res)); err != nil {
		t.Fatal(err)
	}
}

// A binary, helm or apt version the proxy cached has no catalog entry and so
// no URL to rule on; its allow-list is re-run against the upstream recorded
// for the cached object. Outside the list it is refused and revoked, inside
// it passes, and with no origin on record the allow-list is not_evaluated,
// the decision follows the other checks and the outcome says why.
func TestRevetProxyOnlyURLTypeRerunsAllowListOnCacheOrigin(t *testing.T) {
	cases := []struct {
		name, origin, decision, action, allow string
		envelopes                             int
		note                                  string
	}{
		{"outside the list", "https://evil.example.com/tool.tgz", audit.AdmissionPolicyBlocked, RevetReported, audit.CheckBlock, 1, "no catalog entry exists to hide"},
		{"inside the list", "https://good.example.com/tool.tgz", audit.AdmissionAdmitted, RevetNone, audit.CheckPass, 0, ""},
		{"no origin recorded", "", audit.AdmissionAdmitted, RevetNone, audit.CheckNotEvaluated, 0, "upstream of the cached object is unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newRevetFixture(t, manifest.VersionEntry{})
			f.osv.action = policy.ActionPass
			f.cacheBinaryFill(t, c.origin)
			if err := f.adb.InsertPolicy(t.Context(), audit.PolicyInfo{ID: "r1", RegistryType: manifest.TypeBinary,
				RuleKind: policy.RuleKindForType(manifest.TypeBinary), Pattern: "https://good.example.com/"}); err != nil {
				t.Fatal(err)
			}
			ring, err := attestsign.Generate()
			if err != nil {
				t.Fatal(err)
			}
			signer := ring.Signer()
			rv := f.revetter(config.RevetHide)
			rv.Allow = policy.NewChecker(f.adb)
			rv.Stores = storage.NewSingle(f.objects)
			rv.Emitter = &attest.Emitter{Signer: func() attestsign.Signer { return signer }, Admissions: f.adb, PlatformID: "bodega://test"}

			targets, err := rv.Targets(t.Context(), RevetFilter{Type: manifest.TypeBinary})
			want := []RevetTarget{{Type: manifest.TypeBinary, Name: "tool", Version: "1.0.0"}}
			if err != nil || !slices.Equal(targets, want) {
				t.Fatalf("targets = %+v (%v), want %+v", targets, err, want)
			}
			o := rv.One(t.Context(), targets[0], "schedule")
			if o.Error != "" || o.Decision != c.decision || o.Action != c.action {
				t.Fatalf("outcome = %+v, want %s, %s", o, c.decision, c.action)
			}
			if c.note != "" && !slices.ContainsFunc(o.Notes, func(n string) bool { return strings.Contains(n, c.note) }) {
				t.Errorf("notes = %v, want one containing %q", o.Notes, c.note)
			}
			if c.note == "" && len(o.Notes) != 0 {
				t.Errorf("notes = %v, want none", o.Notes)
			}
			if len(o.Envelopes) != c.envelopes {
				t.Errorf("envelopes = %v (%v), want %d", o.Envelopes, o.Notes, c.envelopes)
			}

			rows, err := f.adb.Admissions(t.Context(), audit.AdmissionFilter{PkgType: manifest.TypeBinary, PkgName: "tool", PkgVersion: "1.0.0"})
			if err != nil || len(rows) != 2 || rows[0].Actor != RevetActor || rows[0].ObjectKey != binaryKey {
				t.Fatalf("rows = %+v (%v), want the re-vet's beside the fill's", rows, err)
			}
			allow := rows[0].Checks[slices.IndexFunc(rows[0].Checks, func(ch audit.AdmissionCheck) bool { return ch.Check == audit.CheckAllowList })]
			if allow.Status != c.allow || (c.origin != "" && !strings.Contains(allow.Detail, c.origin)) {
				t.Errorf("allow-list entry = %+v, want %s naming %q", allow, c.allow, c.origin)
			}
		})
	}
}

// An origin is credited only to the object it was recorded for: bytes
// written over the key since, by a path that fetched nothing, leave the
// upstream unknown rather than inheriting the fill's.
func TestRevetIgnoresAnOriginRecordedForOtherBytes(t *testing.T) {
	f := newRevetFixture(t, manifest.VersionEntry{})
	f.osv.action = policy.ActionPass
	f.cacheBinaryFill(t, "https://good.example.com/tool.tgz")
	if err := f.objects.Put(t.Context(), binaryKey, []byte("uploaded over the fill")); err != nil {
		t.Fatal(err)
	}
	rv := f.revetter(config.RevetReport)
	rv.Allow = policy.NewChecker(f.adb)
	rv.Stores = storage.NewSingle(f.objects)
	o := rv.One(t.Context(), RevetTarget{Type: manifest.TypeBinary, Name: "tool", Version: "1.0.0"}, "schedule")
	if o.Error != "" || o.Decision != audit.AdmissionAdmitted {
		t.Fatalf("outcome = %+v", o)
	}
	if !slices.ContainsFunc(o.Notes, func(n string) bool { return strings.Contains(n, "upstream of the cached object is unknown") }) {
		t.Errorf("notes = %v, want the upstream reported unknown", o.Notes)
	}
}

// unversionedObject is a proxy-cached object whose key names no version, the
// upstream it was fetched from, and what a re-vet against a list naming only
// good.example.com decides about it.
type unversionedObject struct {
	key, origin, decision string
}

// cacheUnversionedFill records what a distfiles or binary fill of a key
// naming no version leaves behind: the object, its sha256, an admitted row of
// (type, name, "") pinned under the key, and the upstream it came from.
func (f revetFixture) cacheUnversionedFill(t *testing.T, typ, name string, o unversionedObject) {
	t.Helper()
	ctx := t.Context()
	if err := f.objects.Put(ctx, o.key, []byte("bytes of "+o.key)); err != nil {
		t.Fatal(err)
	}
	notRun := "not run: a " + typ + " proxy fill names no version the age and OSV checks can evaluate"
	if err := f.adb.RecordAdmission(ctx, audit.Admission{
		PkgType: typ, PkgName: name, ObjectKey: o.key,
		Decision: audit.AdmissionAdmitted, DecidedAt: time.Now().Add(-20 * 24 * time.Hour),
		Checks: []audit.AdmissionCheck{
			AllowListCheck(true, o.origin, nil),
			{Check: audit.CheckAge, Action: audit.ActionNone, Status: audit.CheckNotEvaluated, Detail: notRun},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.adb.StoreChecksum(ctx, o.key, typ, name, "", "sha256", strings.Repeat("cd", 32), "computed"); err != nil {
		t.Fatal(err)
	}
	res, err := f.objects.GetStream(ctx, o.key)
	if err != nil || res == nil {
		t.Fatalf("open cached object: %v", err)
	}
	_ = res.Body.Close()
	if err := f.adb.StoreCacheOrigin(ctx, o.key, o.origin, StreamIdentity(f.objects, res)); err != nil {
		t.Fatal(err)
	}
}

// A distfile or binary whose key names no version is a re-vet target of its
// own, identified by its key, since siblings under one name share (type,
// name, ""). It is ruled on by the allow-list against the upstream recorded
// for it and nothing else, and refusing one leaves its sibling admitted.
func TestRevetUnversionedObjectRerunsAllowListPerKey(t *testing.T) {
	cases := []struct {
		name, typ, pkg, pattern string
		objects                 []unversionedObject
	}{
		{"distfile", manifest.TypeDistfiles, "zsh-5.9.tar.xz", "good.example.com", []unversionedObject{
			{manifest.DistfilesKey("zsh-5.9.tar.xz"), "https://evil.example.com/zsh-5.9.tar.xz", audit.AdmissionPolicyBlocked},
		}},
		{"two binaries under one name", manifest.TypeBinary, "tool", "https://good.example.com/", []unversionedObject{
			{manifest.BinaryKey("tool", "", "tool-darwin.tgz"), "https://good.example.com/tool-darwin.tgz", audit.AdmissionAdmitted},
			{manifest.BinaryKey("tool", "", "tool-linux.tgz"), "https://evil.example.com/tool-linux.tgz", audit.AdmissionPolicyBlocked},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newRevetFixture(t, manifest.VersionEntry{})
			for _, o := range c.objects {
				f.cacheUnversionedFill(t, c.typ, c.pkg, o)
			}
			if err := f.adb.InsertPolicy(t.Context(), audit.PolicyInfo{ID: "r1", RegistryType: c.typ,
				RuleKind: policy.RuleKindForType(c.typ), Pattern: c.pattern}); err != nil {
				t.Fatal(err)
			}
			ring, err := attestsign.Generate()
			if err != nil {
				t.Fatal(err)
			}
			signer := ring.Signer()
			rv := f.revetter(config.RevetReport)
			rv.Allow = policy.NewChecker(f.adb)
			rv.Stores = storage.NewSingle(f.objects)
			rv.Emitter = &attest.Emitter{Signer: func() attestsign.Signer { return signer }, Admissions: f.adb, PlatformID: "bodega://test"}

			targets, err := rv.Targets(t.Context(), RevetFilter{Type: c.typ, Name: c.pkg})
			var want []RevetTarget
			for _, o := range c.objects {
				want = append(want, RevetTarget{Type: c.typ, Name: c.pkg, ObjectKey: o.key})
			}
			if err != nil || !slices.Equal(targets, want) {
				t.Fatalf("targets = %+v (%v), want %+v", targets, err, want)
			}
			if got, err := rv.Targets(t.Context(), RevetFilter{Type: c.typ, Name: c.pkg, Version: "5.9"}); len(got) != 0 {
				t.Errorf("a --version filter selected %+v (%v), want no unversioned object", got, err)
			}

			for i, o := range c.objects {
				out := rv.One(t.Context(), targets[i], "schedule")
				if out.Error != "" || out.Decision != o.decision || out.ObjectKey != o.key {
					t.Fatalf("%s: outcome = %+v, want %s", o.key, out, o.decision)
				}
				rows, err := f.adb.Admissions(t.Context(), audit.AdmissionFilter{PkgType: c.typ, PkgName: c.pkg, ObjectKey: o.key})
				if err != nil || len(rows) != 2 || rows[0].Actor != RevetActor || rows[0].ObjectKey != o.key ||
					rows[0].PkgVersion != "" || rows[0].Decision != o.decision {
					t.Fatalf("%s: rows = %+v (%v), want the re-vet's beside the fill's, pinned to its own key", o.key, rows, err)
				}
				for _, ch := range rows[0].Checks {
					if ch.Check == audit.CheckAllowList {
						continue
					}
					if ch.Status != audit.CheckNotEvaluated || ch.Detail != noVersionInKey {
						t.Errorf("%s: %s = %+v, want not_evaluated: %s", o.key, ch.Check, ch, noVersionInKey)
					}
				}
				if o.decision != audit.AdmissionPolicyBlocked {
					if len(out.Notes) != 0 || out.Action != RevetNone {
						t.Errorf("%s: outcome = %+v, want a clean pass", o.key, out)
					}
					continue
				}
				if out.Action != RevetReported || !slices.Contains(out.Notes, noCatalogEntry) {
					t.Errorf("%s: outcome = %+v, want reported with %q", o.key, out, noCatalogEntry)
				}
				if len(out.Failing) != 1 || out.Failing[0].Check != audit.CheckAllowList || !strings.Contains(out.Failing[0].Detail, o.origin) {
					t.Errorf("%s: failing = %+v, want the allow-list naming %s", o.key, out.Failing, o.origin)
				}
				if len(out.Envelopes) != 1 {
					t.Errorf("%s: envelopes = %v (%v), want the revocation", o.key, out.Envelopes, out.Notes)
				}
				evs, err := f.adb.Query(t.Context(), audit.Filter{EventType: audit.EventRevet, PkgName: c.pkg})
				if err != nil || !slices.ContainsFunc(evs, func(e audit.StoredEvent) bool { return strings.Contains(e.Details, o.key) }) {
					t.Errorf("%s: revet events = %+v (%v), want one naming the key", o.key, evs, err)
				}
			}
		})
	}
}

// A hosted entry was uploaded, so like its admission the re-vet finds no
// upstream to rule on and says only that, not that something went missing.
func TestRevetHostedEntryWithNoURLNamesNoUpstream(t *testing.T) {
	f := newRevetFixture(t, manifest.VersionEntry{})
	f.osv.action = policy.ActionPass
	ctx := t.Context()
	if err := f.store.AddVersion(ctx, manifest.TypeBinary, "tool", manifest.VersionEntry{Version: "1.0.0", Mode: manifest.ModeHosted}); err != nil {
		t.Fatal(err)
	}
	if err := f.objects.Put(ctx, binaryKey, []byte("uploaded bytes")); err != nil {
		t.Fatal(err)
	}
	if err := f.adb.RecordAdmission(ctx, audit.Admission{
		PkgType: manifest.TypeBinary, PkgName: "tool", PkgVersion: "1.0.0", ObjectKey: binaryKey,
		Decision: audit.AdmissionAdmitted, DecidedAt: time.Now().Add(-20 * 24 * time.Hour),
		Checks: []audit.AdmissionCheck{AllowListCheck(true, "", nil)},
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.adb.InsertPolicy(ctx, audit.PolicyInfo{ID: "r1", RegistryType: manifest.TypeBinary,
		RuleKind: policy.RuleKindForType(manifest.TypeBinary), Pattern: "https://good.example.com/"}); err != nil {
		t.Fatal(err)
	}
	rv := f.revetter(config.RevetReport)
	rv.Allow = policy.NewChecker(f.adb)
	rv.Stores = storage.NewSingle(f.objects)

	o := rv.One(ctx, RevetTarget{Type: manifest.TypeBinary, Name: "tool", Version: "1.0.0"}, "schedule")
	if o.Error != "" || o.Decision != audit.AdmissionAdmitted {
		t.Fatalf("outcome = %+v", o)
	}
	if len(o.Notes) != 0 {
		t.Errorf("notes = %v, want none", o.Notes)
	}
	rows, err := f.adb.Admissions(ctx, audit.AdmissionFilter{PkgType: manifest.TypeBinary, PkgName: "tool", PkgVersion: "1.0.0"})
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows = %+v (%v)", rows, err)
	}
	if c := checkOf(t, rows[0], audit.CheckAllowList); c.Status != audit.CheckNotEvaluated || !strings.Contains(c.Detail, "names no upstream") {
		t.Errorf("allow-list = %+v, want not_evaluated naming no upstream", c)
	}
}

// ageVerdict is an age checker whose answer a test sets.
type ageVerdict struct{ action string }

func (v *ageVerdict) Check(context.Context, *manifest.PackageManifest, *manifest.VersionEntry) policy.Result {
	if v.action == policy.ActionBlock {
		return policy.Result{Check: audit.CheckAge, Action: policy.ActionBlock, Reason: "published 2d ago, minimum 14d"}
	}
	return policy.Result{Check: audit.CheckAge, Action: policy.ActionPass, Reason: "published 20d ago"}
}

// A version admitted past age by an override has the gate re-run on every
// re-vet, so the override's expiry refuses it again, and a version that has
// since aged past the minimum passes on its own.
func TestRevetRerunsAgeAfterOverride(t *testing.T) {
	f := newRevetFixture(t, manifest.VersionEntry{})
	f.osv.action = policy.ActionPass
	now := time.Now()
	req := osvOverride("1.2.0")
	req.Check = audit.CheckAge
	o := request(t, f.adb, &config.Config{}, req, now)
	vote(t, f.adb, o.ID, "bob", true, now)
	if err := f.adb.RecordAdmission(t.Context(), audit.Admission{
		PkgType: manifest.TypeNpm, PkgName: "minimist", PkgVersion: "1.2.0", ObjectKey: revetKey,
		Decision: audit.AdmissionAdmitted, Actor: "ravi", DecidedAt: now.Add(-time.Hour),
		Checks: []audit.AdmissionCheck{
			{Check: audit.CheckAllowList, Action: audit.ActionNone, Status: audit.CheckPass},
			{Check: audit.CheckAge, Action: policy.ActionBlock, Status: audit.CheckOverridden, Override: o.ID},
			{Check: audit.CheckOSV, Action: policy.ActionBlock, Status: audit.CheckPass},
		},
	}); err != nil {
		t.Fatal(err)
	}
	age := &ageVerdict{action: policy.ActionBlock}
	r := f.revetter(config.RevetReport)
	r.Age = func() policy.VersionChecker { return age }
	revet := func(at time.Time) (RevetOutcome, audit.AdmissionCheck) {
		t.Helper()
		r.Now = func() time.Time { return at }
		out := r.One(t.Context(), target(), "schedule")
		if out.Error != "" {
			t.Fatalf("re-vet error: %s", out.Error)
		}
		return out, checkOf(t, minimistRows(t, f.adb)[0], audit.CheckAge)
	}

	if out, c := revet(now); out.Blocked() || c.Status != audit.CheckOverridden || c.Override != o.ID {
		t.Errorf("(a) under an active override: %s, age %+v; want admitted, overridden by %s", out.Decision, c, o.ID)
	}
	out, c := revet(now.Add(8 * 24 * time.Hour))
	if !out.Blocked() || out.Action != RevetReported || c.Status != audit.CheckBlock {
		t.Errorf("(b) past the override's expiry: %s/%s, age %+v; want policy_blocked, reported, age block", out.Decision, out.Action, c)
	}
	if len(out.Failing) != 1 || out.Failing[0].Check != audit.CheckAge {
		t.Errorf("(b) failing = %+v, want age", out.Failing)
	}
	if out, c := revet(now.Add(9 * 24 * time.Hour)); !out.Blocked() || c.Status != audit.CheckBlock {
		t.Errorf("(d) after a re-vet that blocked: %s, age %+v; want age re-run and blocking", out.Decision, c)
	}
	age.action = policy.ActionPass
	if out, c := revet(now.Add(10 * 24 * time.Hour)); out.Blocked() || c.Status != audit.CheckPass || strings.Contains(c.Detail, "not re-run") {
		t.Errorf("(c) once aged past the minimum: %s, age %+v; want admitted, age re-run and passing", out.Decision, c)
	}
}
