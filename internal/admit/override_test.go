package admit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// fixed is a version checker that always answers r.
type fixed struct{ r policy.Result }

func (f fixed) Check(context.Context, *manifest.PackageManifest, *manifest.VersionEntry) policy.Result {
	return f.r
}

func osvOverride(version string) OverrideRequest {
	return OverrideRequest{Type: manifest.TypeNpm, Name: "minimist", Version: version, Check: audit.CheckOSV,
		Reason: "patched in the vendored build, INC-1", Expires: "7d"}
}

// request records req as alice at at, failing the test on a refusal.
func request(t *testing.T, adb *audit.DB, cfg *config.Config, req OverrideRequest, at time.Time) audit.Override {
	t.Helper()
	o, err := RequestOverride(t.Context(), adb, cfg, req, "alice", at)
	if err != nil {
		t.Fatalf("RequestOverride: %v", err)
	}
	return o
}

func vote(t *testing.T, adb *audit.DB, id, who string, approve bool, at time.Time) audit.Override {
	t.Helper()
	o, err := VoteOverride(t.Context(), adb, id, who, approve, "", at)
	if err != nil {
		t.Fatalf("%s voting %v on %s: %v", who, approve, id, err)
	}
	return o
}

// admitMinimist runs the import path on one version and returns its row.
func admitMinimist(t *testing.T, f admissionFixture, version string) (Result, audit.Admission) {
	t.Helper()
	res := Admit(t.Context(), policy.NewChecker(f.adb), f.adb, f.synced, minimist(version), "ravi")
	if len(res.Admissions) != 1 {
		t.Fatalf("want one row, got %+v", res.Admissions)
	}
	return res, res.Admissions[0]
}

// Without an override, minimist 1.2.0 is refused by the fixture's OSV gate.
// The requester approving their own request leaves it pending and the version
// refused; a second identity's approval admits it, with the check recorded
// overridden and naming the override.
func TestOverrideNeedsASecondIdentity(t *testing.T) {
	f := newAdmissionFixture(t)
	now := time.Now()
	o := request(t, f.adb, f.synced, osvOverride("1.2.0"), now)
	if o.State != audit.OverridePending || o.Quorum != 2 {
		t.Fatalf("requested = %+v, want pending under the default quorum of 2", o)
	}

	if _, err := VoteOverride(t.Context(), f.adb, o.ID, "alice", true, "", now); !errors.Is(err, audit.ErrSelfApproval) {
		t.Fatalf("self-approval = %v, want ErrSelfApproval", err)
	}
	if res, row := admitMinimist(t, f, "1.2.0"); res.OK() || checkOf(t, row, audit.CheckOSV).Status != audit.CheckBlock {
		t.Fatalf("a self-approved override admitted the version: %+v", row)
	}

	o = vote(t, f.adb, o.ID, "bob", true, now)
	if o.State != audit.OverrideApproved {
		t.Fatalf("after bob = %+v, want approved", o)
	}
	res, row := admitMinimist(t, f, "1.2.0")
	if !res.OK() || row.Decision != audit.AdmissionAdmitted {
		t.Fatalf("approved override did not admit: %+v (%s)", row, res.Reason)
	}
	c := checkOf(t, row, audit.CheckOSV)
	if c.Status != audit.CheckOverridden || c.Override != o.ID || c.Action != policy.ActionBlock ||
		!strings.Contains(c.Detail, "GHSA-test-0001") || !strings.Contains(c.Detail, "alice, bob") {
		t.Errorf("osv check = %+v, want overridden naming %s, the advisory and both approvers", c, o.ID)
	}

	if res := Admit(t.Context(), policy.NewChecker(f.adb), f.adb, f.synced,
		&manifest.PackageManifest{Type: manifest.TypeNpm, Name: "minimist", Versions: []manifest.VersionEntry{{Version: "1.2.0"}, {Version: "1.2.8"}}}, "ravi"); !res.OK() {
		t.Errorf("1.2.0 overridden beside a clean 1.2.8 = %s", res.Reason)
	}
}

// override_quorum counts distinct identities with the requester among them:
// at 3, one other approval is not enough, the same approver twice is refused,
// and a third identity carries it.
func TestOverrideQuorum(t *testing.T) {
	f := newAdmissionFixture(t)
	cfg := *f.synced
	cfg.OverrideQuorum = 3
	now := time.Now()
	o := request(t, f.adb, &cfg, osvOverride("1.2.0"), now)

	o = vote(t, f.adb, o.ID, "bob", true, now)
	if o.State != audit.OverridePending {
		t.Fatalf("2 of 3 = %+v, want pending", o)
	}
	if _, err := VoteOverride(t.Context(), f.adb, o.ID, "bob", true, "", now); !errors.Is(err, audit.ErrAlreadyVoted) {
		t.Fatalf("bob again = %v, want ErrAlreadyVoted", err)
	}
	if res, _ := admitMinimist(t, f, "1.2.0"); res.OK() {
		t.Fatal("an override short of its quorum admitted the version")
	}
	if o = vote(t, f.adb, o.ID, "carol", true, now); o.State != audit.OverrideApproved {
		t.Fatalf("3 of 3 = %+v, want approved", o)
	}
	if res, _ := admitMinimist(t, f, "1.2.0"); !res.OK() {
		t.Fatalf("quorum met, still refused: %s", res.Reason)
	}
}

// A rejection by anyone cancels the request, before approval or after it,
// and nobody can approve it afterwards.
func TestOverrideRejection(t *testing.T) {
	f := newAdmissionFixture(t)
	now := time.Now()

	pending := request(t, f.adb, f.synced, osvOverride("1.2.0"), now)
	if o := vote(t, f.adb, pending.ID, "bob", false, now); o.State != audit.OverrideRejected {
		t.Fatalf("rejected = %+v", o)
	}
	if _, err := VoteOverride(t.Context(), f.adb, pending.ID, "carol", true, "", now); !errors.Is(err, audit.ErrOverrideClosed) {
		t.Fatalf("approve after reject = %v, want ErrOverrideClosed", err)
	}
	if res, _ := admitMinimist(t, f, "1.2.0"); res.OK() {
		t.Fatal("a rejected override admitted the version")
	}

	approved := request(t, f.adb, f.synced, osvOverride("1.2.0"), now)
	vote(t, f.adb, approved.ID, "bob", true, now)
	if res, _ := admitMinimist(t, f, "1.2.0"); !res.OK() {
		t.Fatalf("control: approved override refused: %s", res.Reason)
	}
	if o := vote(t, f.adb, approved.ID, "alice", false, now); o.State != audit.OverrideRejected {
		t.Fatalf("requester withdrawing = %+v, want rejected", o)
	}
	if res, _ := admitMinimist(t, f, "1.2.0"); res.OK() {
		t.Fatal("an override rejected after approval still applies")
	}
}

// An override past its expiry stops applying with nobody acting, can no
// longer be voted on, and the next re-vet refuses the version again.
func TestOverrideExpiry(t *testing.T) {
	f := newAdmissionFixture(t)
	past := time.Now().Add(-2 * time.Hour)
	req := osvOverride("1.2.0")
	req.Expires = "1h"
	o := request(t, f.adb, f.synced, req, past)
	vote(t, f.adb, o.ID, "bob", true, past.Add(time.Minute))
	if res, _ := admitMinimist(t, f, "1.2.0"); res.OK() {
		t.Fatal("an expired override admitted the version")
	}
	if _, err := VoteOverride(t.Context(), f.adb, o.ID, "carol", false, "", time.Now()); !errors.Is(err, audit.ErrOverrideClosed) {
		t.Errorf("vote after expiry = %v, want ErrOverrideClosed", err)
	}
	list, err := ListOverrides(t.Context(), f.adb, audit.OverrideStatusExpired, time.Now())
	if err != nil || len(list) != 1 || list[0].ID != o.ID {
		t.Errorf("--expired = %+v, %v", list, err)
	}

	rf := newRevetFixture(t, manifest.VersionEntry{})
	now := time.Now()
	live := request(t, rf.adb, &config.Config{}, osvOverride("1.2.0"), now)
	vote(t, rf.adb, live.ID, "bob", true, now)
	r := rf.revetter(config.RevetReport)
	if out := r.One(t.Context(), target(), "schedule"); out.Blocked() {
		t.Fatalf("re-vet under an active override = %+v, want admitted", out)
	}
	r.Now = func() time.Time { return now.Add(8 * 24 * time.Hour) }
	if out := r.One(t.Context(), target(), "schedule"); !out.Blocked() {
		t.Fatalf("re-vet after expiry = %+v, want policy_blocked", out)
	}
}

// Known malware and invalid upstream provenance are refused whatever an
// override says, and the row names the override it did not honor. An
// advisory block on the same path is overridden, so the exclusion is the
// verdict's and not the path's.
// unknown provenance says the evidence could not be read, not that the version
// is hostile, so an override admits it where it never admits invalid.
func TestOverrideNeverAppliesToMalwareOrInvalidProvenance(t *testing.T) {
	f := newAdmissionFixture(t)
	now := time.Now()
	for _, tc := range []struct {
		version string
		r       policy.Result
		applies bool
	}{
		{"1.0.0", policy.Result{Check: audit.CheckOSV, Action: policy.ActionBlock, Reason: "known malware: MAL-2026-1",
			Details: map[string]any{"malware": []string{"MAL-2026-1"}}}, false},
		{"1.0.1", policy.Result{Check: audit.CheckUpstreamProvenance, Action: policy.ActionBlock, Reason: "signature did not verify",
			Provenance: &audit.UpstreamProvenance{Outcome: audit.ProvenanceInvalid}}, false},
		{"1.0.2", policy.Result{Check: audit.CheckOSV, Action: policy.ActionBlock, Reason: "GHSA-test-0002",
			Details: map[string]any{"vulns": []string{"GHSA-test-0002"}}}, true},
		{"1.0.3", policy.Result{Check: audit.CheckUpstreamProvenance, Action: policy.ActionBlock, Reason: "the packument lists no version 1.0.3",
			Provenance: &audit.UpstreamProvenance{Outcome: audit.ProvenanceUnknown}}, true},
	} {
		req := osvOverride(tc.version)
		req.Check = tc.r.Check
		o := request(t, f.adb, f.synced, req, now)
		vote(t, f.adb, o.ID, "bob", true, now)

		got := Fetch(t.Context(), f.adb, []policy.VersionChecker{fixed{tc.r}}, manifest.TypeNpm, "minimist",
			manifest.VersionEntry{Version: tc.version}, AllowListCheck(false, "minimist", nil), Who{}, "")
		c := checkOf(t, got.Admission, tc.r.Check)
		if tc.applies {
			if got.Block != nil || c.Status != audit.CheckOverridden || c.Override != o.ID {
				t.Errorf("%s: control override did not apply: %+v", tc.version, c)
			}
			continue
		}
		if got.Block == nil || got.Admission.Decision != audit.AdmissionPolicyBlocked || c.Status != audit.CheckBlock {
			t.Errorf("%s: an override admitted past %q: %+v", tc.version, tc.r.Reason, got.Admission)
		}
		if !strings.Contains(c.Detail, "override "+o.ID+" does not apply") {
			t.Errorf("%s: detail %q does not name the override it refused", tc.version, c.Detail)
		}
	}
}

// An allow-list refusal on the import path takes an override like a version
// check does, and the version checks still run after it.
func TestOverrideAllowList(t *testing.T) {
	f := newAdmissionFixture(t)
	if err := f.adb.InsertPolicy(t.Context(), audit.PolicyInfo{ID: "r1", RegistryType: manifest.TypeNpm, RuleKind: policy.KindPackage, Pattern: "lodash"}); err != nil {
		t.Fatalf("InsertPolicy: %v", err)
	}
	now := time.Now()
	req := osvOverride("1.2.8")
	req.Check = audit.CheckAllowList
	o := request(t, f.adb, f.synced, req, now)
	vote(t, f.adb, o.ID, "bob", true, now)

	res, row := admitMinimist(t, f, "1.2.8")
	if !res.OK() {
		t.Fatalf("allow-list override refused: %s", res.Reason)
	}
	if c := checkOf(t, row, audit.CheckAllowList); c.Status != audit.CheckOverridden || c.Override != o.ID {
		t.Errorf("allowlist = %+v", c)
	}
	if c := checkOf(t, row, audit.CheckOSV); c.Status != audit.CheckPass {
		t.Errorf("osv after an allow-list override = %+v, want it run and passed", c)
	}
	if res, _ := admitMinimist(t, f, "1.2.0"); res.OK() || res.Check != "allow-list" {
		t.Errorf("1.2.0 has no override: %+v", res)
	}
	cr := Create(t.Context(), policy.NewChecker(f.adb), f.adb, f.synced, minimist("1.2.8"), Who{Actor: "ravi"})
	if !cr.OK() {
		t.Errorf("pkg create path ignored the override: %s", cr.Reason)
	}
}

func TestRequestOverrideRefusals(t *testing.T) {
	f := newAdmissionFixture(t)
	for name, tc := range map[string]struct {
		edit func(*OverrideRequest)
		want string
	}{
		"no expiry":     {func(r *OverrideRequest) { r.Expires = "" }, "an expiry is required, at most 30d"},
		"past the cap":  {func(r *OverrideRequest) { r.Expires = "31d" }, "beyond override_max_ttl (30d)"},
		"no reason":     {func(r *OverrideRequest) { r.Reason = "  " }, "a reason is required"},
		"unknown check": {func(r *OverrideRequest) { r.Check = "deny" }, `unknown check "deny"`},
		"no version":    {func(r *OverrideRequest) { r.Version = "" }, "version is required"},
	} {
		req := osvOverride("1.2.0")
		tc.edit(&req)
		_, err := RequestOverride(t.Context(), f.adb, f.synced, req, "alice", time.Now())
		if !errors.Is(err, ErrInvalidOverride) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want ErrInvalidOverride containing %q", name, err, tc.want)
		}
	}
	cfg := *f.synced
	cfg.OverrideMaxTTL = "90d"
	req := osvOverride("1.2.0")
	req.Expires = "60d"
	if _, err := RequestOverride(t.Context(), f.adb, &cfg, req, "alice", time.Now()); err != nil {
		t.Errorf("60d under a 90d cap: %v", err)
	}
}
