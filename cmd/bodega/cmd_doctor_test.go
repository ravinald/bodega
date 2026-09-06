package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/host"
)

// fakePosture is the audit read surface with nothing behind it, so a posture
// case is stated as the three lists it is.
type fakePosture struct {
	rules []audit.PolicyInfo
	ages  []audit.AgePolicy
	osvs  []audit.OSVPolicy
}

func (f fakePosture) ListPolicies(context.Context) ([]audit.PolicyInfo, error) {
	return f.rules, nil
}
func (f fakePosture) ListAgePolicies(context.Context) ([]audit.AgePolicy, error) { return f.ages, nil }
func (f fakePosture) ListOSVPolicies(context.Context) ([]audit.OSVPolicy, error) { return f.osvs, nil }

func findingFor(t *testing.T, findings []host.Finding, check string) host.Finding {
	t.Helper()
	for _, f := range findings {
		if f.Check == check {
			return f
		}
	}
	t.Fatalf("doctor printed no %q row; got %v", check, findings)
	return host.Finding{}
}

// The install this item exists for: a caching proxy with an audit trail and
// no control in front of it. doctor has to name it, and name the two commands
// that end it.
func TestDoctorReportsZeroPolicyInstall(t *testing.T) {
	f := findingFor(t, serverPosture(context.Background(), fakePosture{}), "policy-coverage")
	if !f.IsFinding() {
		t.Fatalf("an install with no allow-list and no age gate reported %s; it must count toward the exit-2 findings", f.Status)
	}
	for _, want := range []string{"bodega policy add", "bodega policy age set"} {
		if !strings.Contains(f.Remediation, want) {
			t.Errorf("remediation %q does not name %q", f.Remediation, want)
		}
	}
}

// One rule or one gate is a decision somebody made. doctor reports the install
// that never made one, not the one that made a small one.
func TestDoctorAcceptsAnyPolicyCoverage(t *testing.T) {
	store := fakePosture{ages: []audit.AgePolicy{{Ecosystem: "npm", MinAgeSeconds: 604800, Action: "warn"}}}
	if f := findingFor(t, serverPosture(context.Background(), store), "policy-coverage"); f.IsFinding() {
		t.Errorf("an install with a seeded age gate reported %s: %s", f.Status, f.Detail)
	}
}

// Silencing a gate during an incident and never restoring it leaves rows that
// read as configured policy. The state is indistinguishable from enforcement
// in `policy list`, which is why doctor has to separate them.
func TestDoctorReportsPolicySilencedEverywhere(t *testing.T) {
	store := fakePosture{
		ages: []audit.AgePolicy{{Ecosystem: "npm", Action: "ignore"}, {Ecosystem: "pypi", Action: "ignore"}},
		osvs: []audit.OSVPolicy{{Ecosystem: "npm", Action: "ignore"}},
	}
	f := findingFor(t, serverPosture(context.Background(), store), "policy-ignored")
	if !f.IsFinding() {
		t.Fatalf("every ecosystem on ignore reported %s: %s", f.Status, f.Detail)
	}
	for _, want := range []string{"age", "osv", "npm", "pypi"} {
		if !strings.Contains(f.Detail, want) {
			t.Errorf("detail %q does not name %q", f.Detail, want)
		}
	}
	if !strings.Contains(f.Remediation, "bodega policy age set") {
		t.Errorf("remediation %q does not say how to restore the gate", f.Remediation)
	}
}

// One ecosystem still enforcing is a live gate, not a silenced one.
func TestDoctorAcceptsAPartiallyIgnoredPolicy(t *testing.T) {
	store := fakePosture{ages: []audit.AgePolicy{
		{Ecosystem: "npm", Action: "ignore"},
		{Ecosystem: "pypi", MinAgeSeconds: 604800, Action: "warn"},
	}}
	if f := findingFor(t, serverPosture(context.Background(), store), "policy-ignored"); f.IsFinding() {
		t.Errorf("one ignored ecosystem out of two reported %s: %s", f.Status, f.Detail)
	}
}

// Risk #250: `set` refuses these now, and every row written before that
// refusal is still stored, still listed, and still read by nothing.
func TestDoctorReportsRowsNoGateCanEvaluate(t *testing.T) {
	store := fakePosture{
		ages: []audit.AgePolicy{{Ecosystem: "helm", MinAgeSeconds: 604800, Action: "block"}},
		osvs: []audit.OSVPolicy{{Ecosystem: "apt", Action: "block"}},
	}
	f := findingFor(t, serverPosture(context.Background(), store), "policy-ecosystem")
	if !f.IsFinding() {
		t.Fatalf("rows for helm and apt reported %s: %s", f.Status, f.Detail)
	}
	for _, want := range []string{"helm", "apt"} {
		if !strings.Contains(f.Detail, want) {
			t.Errorf("detail %q does not name %q", f.Detail, want)
		}
	}
	for _, want := range []string{"bodega policy age remove helm", "bodega policy osv remove apt"} {
		if !strings.Contains(f.Remediation, want) {
			t.Errorf("remediation %q does not name %q", f.Remediation, want)
		}
	}
}

// The posture checks run against the real store, not only the fake: an
// interface satisfied in the test and not in production reports on nothing.
// A fresh install passes all three, which is the point of shipping the seed.
func TestDoctorPassesOnAFreshInstall(t *testing.T) {
	db, err := audit.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	defer db.Close()
	for _, f := range serverPosture(context.Background(), db) {
		if f.IsFinding() {
			t.Errorf("fresh install reported %s on %s: %s", f.Status, f.Check, f.Detail)
		}
	}
}

// doctor is documented as read-only and runs on client hosts in CI. Opening
// the audit store would create it and seed a fresh install's policy, so the
// checks stat first and report that there is nothing here.
func TestDoctorDoesNotCreateAnAuditDatabase(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"audit_db":`+strconv.Quote(dbPath)+`}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("BODEGA_CONFIG_FILE", cfgPath)

	findings := serverPostureFindings(context.Background(), &globalFlags{})
	if len(findings) != len(postureChecks) {
		t.Fatalf("got %d posture rows, want one per check (%v)", len(findings), postureChecks)
	}
	for _, f := range findings {
		if f.Status != host.StatusNA {
			t.Errorf("%s on a host with no install reported %s, want N/A", f.Check, f.Status)
		}
	}
	if _, err := os.Stat(dbPath); err == nil {
		t.Fatal("doctor created the audit database it was asked to report on")
	}
}

// A row no gate reads is not enforcement. Measured against the shipped binary
// before it was: a stored helm row set to block reported policy-ignored as OK
// while every ecosystem the age gate can actually date sat on ignore.
func TestDoctorIgnoredIsNotMaskedByADeadRow(t *testing.T) {
	store := fakePosture{
		ages: []audit.AgePolicy{
			{Ecosystem: "helm", MinAgeSeconds: 604800, Action: "block"},
			{Ecosystem: "npm", MinAgeSeconds: 604800, Action: "ignore"},
		},
	}
	findings := serverPosture(context.Background(), store)
	f := findingFor(t, findings, "policy-ignored")
	if !f.IsFinding() {
		t.Fatalf("a helm row the gate cannot date masked the silenced npm gate: %s %s", f.Status, f.Detail)
	}
	if strings.Contains(f.Detail, "helm") {
		t.Errorf("detail %q names helm, which this check does not read", f.Detail)
	}
	if c := findingFor(t, findings, "policy-coverage"); strings.Contains(c.Detail, "2 ecosystem") {
		t.Errorf("coverage counted the dead helm row as a gate: %s", c.Detail)
	}
}
