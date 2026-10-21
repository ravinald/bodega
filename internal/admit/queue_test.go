package admit

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

var queueT0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func openQueueStore(t *testing.T) *audit.DB {
	t.Helper()
	adb, err := audit.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	t.Cleanup(func() { _ = adb.Close() })
	return adb
}

// queued records f once and returns its row.
func queued(t *testing.T, adb *audit.DB, f audit.QueueRefusal) audit.QueueRow {
	t.Helper()
	if err := adb.RecordRefusal(t.Context(), f, queueT0); err != nil {
		t.Fatalf("RecordRefusal: %v", err)
	}
	rows, err := adb.ListQueue(t.Context(), audit.QueueFilter{PkgType: f.PkgType, Check: f.Check})
	if err != nil || len(rows) == 0 {
		t.Fatalf("ListQueue: %v %+v", err, rows)
	}
	for _, r := range rows {
		if r.PkgName == f.PkgName && r.PkgVersion == f.PkgVersion {
			return r
		}
	}
	t.Fatalf("no row for %+v in %+v", f, rows)
	return audit.QueueRow{}
}

// The queue check each blocking result lands under, and which of them no
// approval may waive.
func TestQueueCheckForAndUnwaivable(t *testing.T) {
	for _, tc := range []struct {
		name       string
		r          policy.Result
		check      string
		unwaivable bool
	}{
		{"allow-list", policy.Result{Check: audit.CheckAllowList}, QueueAllowList, false},
		{"age", policy.Result{Check: audit.CheckAge}, QueueAge, false},
		{"osv advisory", policy.Result{Check: audit.CheckOSV, Details: map[string]any{"vulns": []string{"GHSA-1"}}}, QueueOSV, false},
		{"osv malware", policy.Result{Check: audit.CheckOSV, Details: map[string]any{"malware": []string{"MAL-1"}}}, QueueMalware, true},
		{"provenance missing", policy.Result{Check: audit.CheckUpstreamProvenance,
			Provenance: &audit.UpstreamProvenance{Outcome: "missing"}}, QueueProvenance, false},
		{"provenance invalid", policy.Result{Check: audit.CheckUpstreamProvenance,
			Provenance: &audit.UpstreamProvenance{Outcome: audit.ProvenanceInvalid}}, QueueProvenance, true},
		{"name similarity", policy.Result{Check: audit.CheckNameSimilarity}, QueueSimilarity, false},
		{"integration risk", policy.Result{Check: "integration:socket", Details: map[string]any{"outcome": "flagged"}}, "integration:socket", false},
		{"integration malware", policy.Result{Check: "integration:aikido",
			Details: map[string]any{"outcome": "flagged", "malware": []string{"integration:aikido"}}}, "integration:aikido", true},
	} {
		if got := QueueCheckFor(tc.r); got != tc.check {
			t.Errorf("%s: check %q, want %q", tc.name, got, tc.check)
		}
		if got := Unwaivable(tc.r) != ""; got != tc.unwaivable {
			t.Errorf("%s: unwaivable %v, want %v", tc.name, got, tc.unwaivable)
		}
	}
}

// Approving an allow-list row adds the rule the row carries, attributed to
// the approver, and closes the row; approving it again is refused.
func TestApproveAllowListAddsTheRule(t *testing.T) {
	adb := openQueueStore(t)
	row := queued(t, adb, audit.QueueRefusal{PkgType: manifest.TypeNpm, PkgName: "leftpad", PkgVersion: "1.2.0",
		Check: QueueAllowList, Pattern: "leftpad"})
	res, err := ApproveQueued(t.Context(), adb, &config.Config{}, row.ID, "alice", QueueApproval{Reason: "INC-1"}, queueT0)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if res.Rule == nil || res.Rule.Pattern != "leftpad" || res.Rule.CreatedBy != "alice" || res.Row.State != audit.QueueApproved {
		t.Fatalf("resolution = %+v", res)
	}
	if err := policy.NewChecker(adb).Check(t.Context(), manifest.TypeNpm, "leftpad"); err != nil {
		t.Errorf("leftpad after approval: %v, want allowed", err)
	}
	if _, err := ApproveQueued(t.Context(), adb, &config.Config{}, row.ID, "bob", QueueApproval{Reason: "again"}, queueT0); !errors.Is(err, audit.ErrQueueRowClosed) {
		t.Errorf("approving an approved row: %v, want ErrQueueRowClosed", err)
	}
	events, _ := adb.Query(t.Context(), audit.Filter{EventType: audit.EventQueue})
	if len(events) != 1 || events[0].Actor != "alice" || events[0].Status != audit.QueueApproved {
		t.Errorf("queue events = %+v", events)
	}
}

// Every check other than allow-list and profile approves into a two-person
// override for that version and check, requested by the approver. A row that
// reopens while that override waits is approved into the same override.
func TestApproveVersionChecksRequestsAnOverride(t *testing.T) {
	for _, check := range []string{QueueAge, QueueOSV, QueueProvenance, QueueSimilarity, "integration:socket"} {
		t.Run(check, func(t *testing.T) {
			adb := openQueueStore(t)
			f := audit.QueueRefusal{PkgType: manifest.TypeNpm, PkgName: "minimist", PkgVersion: "1.2.0", Check: check}
			row := queued(t, adb, f)
			res, err := ApproveQueued(t.Context(), adb, &config.Config{}, row.ID, "alice", QueueApproval{Reason: "vendored fix", Expires: "3d"}, queueT0)
			if err != nil {
				t.Fatalf("approve: %v", err)
			}
			o := res.Override
			if o == nil || o.Check != check || o.PkgVersion != "1.2.0" || o.RequestedBy != "alice" ||
				o.Status != audit.OverrideStatusPending || !o.ExpiresAt.Equal(queueT0.Add(72*time.Hour)) {
				t.Fatalf("override = %+v", o)
			}
			if !strings.Contains(res.Row.Resolution, o.ID) {
				t.Errorf("resolution %q names no override", res.Row.Resolution)
			}

			if err := adb.RecordRefusal(t.Context(), f, queueT0.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			again, err := ApproveQueued(t.Context(), adb, &config.Config{}, row.ID, "alice", QueueApproval{Reason: "still"}, queueT0.Add(2*time.Minute))
			if err != nil || again.Override.ID != o.ID {
				t.Errorf("reapproving a reopened row: %+v %v, want override %s again", again.Override, err, o.ID)
			}
		})
	}
}

// An osv row approved from the queue admits the version once a second
// identity approves it: the queue goes through the override flow rather than
// around it.
func TestApprovedOSVRowAdmitsAfterTheQuorum(t *testing.T) {
	f := newAdmissionFixture(t)
	row := queued(t, f.adb, audit.QueueRefusal{PkgType: manifest.TypeNpm, PkgName: "minimist", PkgVersion: "1.2.0", Check: QueueOSV})
	if _, before := admitMinimist(t, f, "1.2.0"); before.Decision != audit.AdmissionPolicyBlocked {
		t.Fatalf("fixture does not refuse 1.2.0: %+v", before)
	}
	now := time.Now()
	res, err := ApproveQueued(t.Context(), f.adb, f.synced, row.ID, "alice", QueueApproval{Reason: "vendored fix"}, now)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, pending := admitMinimist(t, f, "1.2.0"); pending.Decision != audit.AdmissionPolicyBlocked {
		t.Errorf("admitted on the approver's word alone: %+v", pending)
	}
	vote(t, f.adb, res.Override.ID, "bob", true, now)
	if _, after := admitMinimist(t, f, "1.2.0"); after.Decision == audit.AdmissionPolicyBlocked {
		t.Errorf("still refused with the quorum met: %+v", after)
	}
}

// Known malware and provenance that failed to verify are refused with the
// check named, and the row stays open to be dismissed.
func TestApproveRefusesUnwaivableChecks(t *testing.T) {
	adb := openQueueStore(t)
	for _, f := range []audit.QueueRefusal{
		{PkgType: manifest.TypeNpm, PkgName: "evil", PkgVersion: "1.0.0", Check: QueueMalware,
			Unwaivable: "known malware is never overridden"},
		{PkgType: manifest.TypeNpm, PkgName: "evil2", PkgVersion: "1.0.0", Check: QueueMalware},
		{PkgType: manifest.TypeNpm, PkgName: "forged", PkgVersion: "2.0.0", Check: QueueProvenance,
			Unwaivable: "invalid upstream provenance is never overridden"},
		{PkgType: manifest.TypeNpm, PkgName: "openai-pr-reviewer", PkgVersion: "1.0.1", Check: "integration:aikido",
			Unwaivable: "known malware is never overridden"},
	} {
		row := queued(t, adb, f)
		_, err := ApproveQueued(t.Context(), adb, &config.Config{}, row.ID, "alice", QueueApproval{Reason: "please"}, queueT0)
		if !errors.Is(err, ErrQueueUnwaivable) || !strings.Contains(err.Error(), "refused by "+f.Check) {
			t.Errorf("%s/%s: %v, want a refusal naming %s", f.PkgName, f.Check, err, f.Check)
		}
		if got, _ := adb.GetQueueRow(t.Context(), row.ID); got.State != audit.QueueOpen {
			t.Errorf("%s left %s", f.PkgName, got.State)
		}
		if _, err := DismissQueued(t.Context(), adb, row.ID, "alice", "malicious", queueT0); err != nil {
			t.Errorf("dismissing %s: %v", f.PkgName, err)
		}
	}
	if list, _ := adb.ListOverrides(t.Context(), audit.OverrideFilter{}); len(list) != 0 {
		t.Errorf("a refused approval filed overrides: %+v", list)
	}
}

// A row whose check no approval is defined for says so, names the check and
// says how to close it, and stays open.
func TestApproveUnknownCheckNamesDismiss(t *testing.T) {
	adb := openQueueStore(t)
	row := queued(t, adb, audit.QueueRefusal{PkgType: manifest.TypeNpm, PkgName: "leftpad", PkgVersion: "1.0.0", Check: "tea_leaves"})
	_, err := ApproveQueued(t.Context(), adb, &config.Config{}, row.ID, "alice", QueueApproval{Reason: "please"}, queueT0)
	want := fmt.Sprintf("bodega queue dismiss %d", row.ID)
	if !errors.Is(err, ErrInvalidQueue) || !strings.Contains(err.Error(), `"tea_leaves"`) || !strings.Contains(err.Error(), want) {
		t.Errorf("approve of an unknown check: %v, want it to name the check and %q", err, want)
	}
	if got, _ := adb.GetQueueRow(t.Context(), row.ID); got.State != audit.QueueOpen {
		t.Errorf("row left %s", got.State)
	}
}

// A profile row pins the refused version in every profile that refused it,
// keeping the entry's spelling, with the reason and the approver on it.
func TestApproveProfilePinsInEachProfile(t *testing.T) {
	adb := openQueueStore(t)
	for _, p := range []string{"web", "batch"} {
		if err := adb.CreateProfileWith(t.Context(), audit.Profile{Name: p}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := adb.PutProfileEntry(t.Context(), audit.ProfileEntry{Profile: "batch", Type: manifest.TypePypi,
		Name: "Django", Constraint: manifest.ConstraintExact, Version: "4.2.0", Reason: "old"}); err != nil {
		t.Fatal(err)
	}
	f := audit.QueueRefusal{PkgType: manifest.TypePypi, PkgName: "django", PkgVersion: "5.0.0", Check: QueueProfile, Profile: "web"}
	queued(t, adb, f)
	f.Profile = "batch"
	row := queued(t, adb, f)

	res, err := ApproveQueued(t.Context(), adb, &config.Config{}, row.ID, "alice", QueueApproval{Reason: "needed"}, queueT0)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if len(res.Profiles) != 2 {
		t.Fatalf("profiles = %v", res.Profiles)
	}
	for _, p := range []string{"web", "batch"} {
		d, err := adb.GetProfile(t.Context(), p)
		if err != nil || len(d.Entries) != 1 {
			t.Fatalf("%s: %v %+v", p, err, d)
		}
		e := d.Entries[0]
		if e.Version != "5.0.0" || e.Constraint != manifest.ConstraintExact || e.PinnedBy != "alice" || !strings.Contains(e.Reason, "needed") {
			t.Errorf("%s entry = %+v", p, e)
		}
		if p == "batch" && e.Name != "Django" {
			t.Errorf("batch entry renamed to %q; the stored spelling is what keeps it one entry", e.Name)
		}
	}
}

// Dismissing closes the row without admitting anything, and both resolutions
// require a reason and an actor.
func TestDismissAndRequiredFields(t *testing.T) {
	adb := openQueueStore(t)
	row := queued(t, adb, audit.QueueRefusal{PkgType: manifest.TypeNpm, PkgName: "lodahs", PkgVersion: "1.0.0",
		Check: QueueAllowList, Pattern: "lodahs"})
	if _, err := ApproveQueued(t.Context(), adb, &config.Config{}, row.ID, "alice", QueueApproval{Reason: "  "}, queueT0); !errors.Is(err, ErrInvalidQueue) {
		t.Errorf("approve with no reason: %v", err)
	}
	if _, err := DismissQueued(t.Context(), adb, row.ID, "", "typo", queueT0); !errors.Is(err, ErrInvalidQueue) {
		t.Errorf("dismiss with no actor: %v", err)
	}
	got, err := DismissQueued(t.Context(), adb, row.ID, "alice", "typo of lodash", queueT0)
	if err != nil || got.State != audit.QueueDismissed || got.ResolvedBy != "alice" || got.ResolutionReason != "typo of lodash" {
		t.Fatalf("dismissed = %+v %v", got, err)
	}
	if rules, _ := adb.ListPolicies(t.Context()); len(rules) != 0 {
		t.Errorf("dismiss added rules: %+v", rules)
	}
	if _, err := ApproveQueued(t.Context(), adb, &config.Config{}, 999, "alice", QueueApproval{Reason: "x"}, queueT0); !errors.Is(err, audit.ErrQueueRowNotFound) {
		t.Errorf("unknown id: %v", err)
	}
}

// An allow-list row whose exact name sits near a popular one is refused
// before any rule is written, the row stays open, and an approval repeating
// the popular name writes the rule.
func TestApproveAllowListConfirmsANearPopularName(t *testing.T) {
	adb := openQueueStore(t)
	row := queued(t, adb, audit.QueueRefusal{PkgType: manifest.TypePypi, PkgName: "reqeusts", PkgVersion: "2.0.0",
		Check: QueueAllowList, Pattern: "reqeusts"})

	_, err := ApproveQueued(t.Context(), adb, &config.Config{}, row.ID, "alice", QueueApproval{Reason: "INC-1"}, queueT0)
	if !errors.Is(err, ErrInvalidQueue) || !strings.Contains(err.Error(), "requests") || !strings.Contains(err.Error(), "--confirm-near-popular") {
		t.Fatalf("unconfirmed approval: %v, want ErrInvalidQueue naming requests and the flag", err)
	}
	if rules, _ := adb.ListPolicies(t.Context()); len(rules) != 0 {
		t.Fatalf("rules after a refusal = %+v", rules)
	}
	if got, _ := adb.GetQueueRow(t.Context(), row.ID); got.State != audit.QueueOpen {
		t.Fatalf("row after a refusal = %+v, want open", got)
	}

	res, err := ApproveQueued(t.Context(), adb, &config.Config{}, row.ID, "alice",
		QueueApproval{Reason: "INC-1", ConfirmNearPopular: "requests"}, queueT0)
	if err != nil || res.Rule == nil || res.Rule.Pattern != "reqeusts" {
		t.Fatalf("confirmed approval = %+v, %v", res, err)
	}
	events, _ := adb.Query(t.Context(), audit.Filter{EventType: audit.EventCreate})
	if len(events) != 1 || !strings.Contains(events[0].Details, "near_popular=requests") || !strings.Contains(events[0].Details, "confirmed=yes") {
		t.Errorf("create events = %+v", events)
	}
}
