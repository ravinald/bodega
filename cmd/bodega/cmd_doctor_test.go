package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/host"

	_ "modernc.org/sqlite" // the audit store's driver, for the raw handles below
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
		osvs: []audit.OSVPolicy{{Ecosystem: "git", Action: "block"}},
	}
	f := findingFor(t, serverPosture(context.Background(), store), "policy-ecosystem")
	if !f.IsFinding() {
		t.Fatalf("rows for helm and git reported %s: %s", f.Status, f.Detail)
	}
	for _, want := range []string{"helm", "git"} {
		if !strings.Contains(f.Detail, want) {
			t.Errorf("detail %q does not name %q", f.Detail, want)
		}
	}
	for _, want := range []string{"bodega policy age remove helm", "bodega policy osv remove git"} {
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

// Coverage asks whether a policy exists, so an all-ignore install keeps its
// OK; that is policy-ignored's finding to report and it does. What the line
// cannot do is claim two working gates on an install that refuses nothing.
func TestDoctorCoverageSaysHowManyGatesAreInForce(t *testing.T) {
	store := fakePosture{ages: []audit.AgePolicy{
		{Ecosystem: "npm", MinAgeSeconds: 604800, Action: "ignore"},
		{Ecosystem: "pypi", MinAgeSeconds: 604800, Action: "ignore"},
	}}
	f := findingFor(t, serverPosture(context.Background(), store), "policy-coverage")
	if !strings.Contains(f.Detail, "0 in force") {
		t.Errorf("coverage reported %q on an install whose every gate is ignored", f.Detail)
	}
}

// An OSV gate refuses fetches from the same admission path the age gate runs
// in, so an install carrying one is not wide open. Measured against the
// shipped binary before it was: 0 rules, 0 age rows and osv npm block read
// "every upstream fetch is admitted", which the operator's own
// policy_violation records disprove.
func TestDoctorCoverageCountsTheOSVGate(t *testing.T) {
	store := fakePosture{osvs: []audit.OSVPolicy{{Ecosystem: "npm", Action: "block"}}}
	f := findingFor(t, serverPosture(context.Background(), store), "policy-coverage")
	if f.IsFinding() {
		t.Fatalf("an install with a blocking OSV gate reported %s: %s", f.Status, f.Detail)
	}
	if !strings.Contains(f.Detail, "1 with an OSV gate") {
		t.Errorf("detail %q does not count the OSV gate", f.Detail)
	}
	if strings.Contains(f.Detail, "in force") {
		t.Errorf("coverage qualified an install whose only gate enforces: %q", f.Detail)
	}
}

// A silenced OSV gate is coverage without enforcement, the same as a silenced
// age gate, and the in-force count has to span both tables to say so.
func TestDoctorCoverageInForceSpansBothGates(t *testing.T) {
	store := fakePosture{
		ages: []audit.AgePolicy{{Ecosystem: "npm", MinAgeSeconds: 604800, Action: "warn"}},
		osvs: []audit.OSVPolicy{{Ecosystem: "npm", Action: "ignore"}},
	}
	f := findingFor(t, serverPosture(context.Background(), store), "policy-coverage")
	if !strings.Contains(f.Detail, "1 in force") {
		t.Errorf("coverage reported %q on an install with one live gate and one silenced", f.Detail)
	}
}

// A fresh install enforces everything it configured, so the line stays as
// short as it was before the silenced case needed spelling out.
func TestDoctorCoverageStaysQuietWhenEveryGateRuns(t *testing.T) {
	store := fakePosture{ages: []audit.AgePolicy{
		{Ecosystem: "npm", MinAgeSeconds: 604800, Action: "warn"},
		{Ecosystem: "pypi", MinAgeSeconds: 604800, Action: "warn"},
	}}
	f := findingFor(t, serverPosture(context.Background(), store), "policy-coverage")
	if strings.Contains(f.Detail, "in force") {
		t.Errorf("coverage qualified a fully enforcing install: %q", f.Detail)
	}
}

// doctor reports on the install; it does not upgrade it. Opening the store
// read-write runs pending migrations, so a doctor run against an install that
// predates migration 012 would claim the seed marker and decide the default
// posture for an operator who only asked what theirs was.
func TestDoctorDoesNotMigrateAnAuditDatabase(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")
	db, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close audit db: %v", err)
	}
	// Wind the store back to an install that predates the seed. Faster than
	// rebuilding it from the embedded migrations, which package main cannot
	// reach, and it reproduces what the read-write opener would act on: a
	// recorded version below 012 with no policy_seeds table behind it.
	rewindPastPolicySeed(t, dbPath)

	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"audit_db":`+strconv.Quote(dbPath)+`}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("BODEGA_CONFIG_FILE", cfgPath)

	serverPostureFindings(context.Background(), &globalFlags{})

	if v := schemaVersion(t, dbPath); v != policySeedSchema-1 {
		t.Fatalf("doctor migrated the install from schema %d to %d", policySeedSchema-1, v)
	}
	if tableExists(t, dbPath, "policy_seeds") {
		t.Fatal("doctor recreated policy_seeds, deciding the default posture for the operator")
	}
}

// policySeedSchema is migration 012, where the seed marker arrived. Spelled
// here rather than imported: internal/audit keeps its own copy unexported, and
// a test that reads the constant it is checking cannot catch it moving.
const policySeedSchema = 12

func rewindPastPolicySeed(t *testing.T, path string) {
	t.Helper()
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer raw.Close()
	for _, stmt := range []string{
		"DROP TABLE policy_seeds",
		"DELETE FROM age_policy",
		"UPDATE schema_migrations SET version = " + strconv.Itoa(policySeedSchema-1),
	} {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
}

func schemaVersion(t *testing.T, path string) int {
	t.Helper()
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer raw.Close()
	var v int
	if err := raw.QueryRow("SELECT version FROM schema_migrations").Scan(&v); err != nil {
		t.Fatalf("read schema version: %v", err)
	}
	return v
}

func tableExists(t *testing.T, path, name string) bool {
	t.Helper()
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer raw.Close()
	var n int
	if err := raw.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", name,
	).Scan(&n); err != nil {
		t.Fatalf("read sqlite_master: %v", err)
	}
	return n > 0
}
