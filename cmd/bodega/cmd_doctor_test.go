package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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

// The reproduction the review sent back. The shipped check compared the
// pepper's grants to config.json's and called them equal: both root:root, both
// granting owner and group. What it never asked is which triple the service
// account actually reads through — the config at 0644 hands it over on the
// other bit, and the pepper at 0640 has none.
func TestDoctorReportsAPepperTheServiceAccountCannotRead(t *testing.T) {
	dir := pepperTree(t, 0o644, 0o640)
	f := pepperFinding(audit.PepperState{Path: filepath.Join(dir, "pepper")}, serviceAccount, nil)

	if f.Status != host.StatusFail {
		t.Fatalf("a 0640 root:root pepper beside a 0644 root:root config reported %s: %s", f.Status, f.Detail)
	}
	for _, want := range []string{"pepper", serviceAccount.Name} {
		if !strings.Contains(f.Detail, want) {
			t.Errorf("detail %q does not name %q", f.Detail, want)
		}
	}
	if !strings.Contains(f.Remediation, "chown root:"+serviceAccount.Group) {
		t.Errorf("remediation %q does not carry the chown to run", f.Remediation)
	}
}

// The OK side has to be readability, not a matching pair of grants: a check
// that only ever fails is as useless as one that only ever passes.
func TestDoctorAcceptsAPepperTheServiceAccountReads(t *testing.T) {
	dir := pepperTree(t, 0o644, 0o640)
	path := filepath.Join(dir, "pepper")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	id := serviceAccount
	id.GID = int(fi.Sys().(*syscall.Stat_t).Gid)
	id.GIDs = []int{id.GID}

	if f := pepperFinding(audit.PepperState{Path: path}, id, nil); f.IsFinding() {
		t.Fatalf("a pepper whose group the service account is in reported %s: %s", f.Status, f.Detail)
	}
}

// A directory the service account cannot enter withholds a pepper whose own
// mode hands it over, and the chown goes on the directory. Naming the file
// there sends the operator to chown something already correct.
func TestDoctorNamesTheDirectoryThatWithholdsThePepper(t *testing.T) {
	dir := pepperTree(t, 0o644, 0o644)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	f := pepperFinding(audit.PepperState{Path: filepath.Join(dir, "pepper")}, serviceAccount, nil)

	if f.Status != host.StatusFail {
		t.Fatalf("a pepper inside a 0700 directory reported %s: %s", f.Status, f.Detail)
	}
	if !strings.Contains(f.Detail, dir) || !strings.Contains(f.Remediation, dir) {
		t.Errorf("detail %q / remediation %q do not name the directory %q", f.Detail, f.Remediation, dir)
	}
}

// A host running the server as whoever invoked it has no second account to
// check against, and a FAIL there would fire on every developer laptop.
func TestDoctorSkipsThePepperWithNoServiceAccount(t *testing.T) {
	f := pepperFinding(audit.PepperState{Path: "/etc/bodega/pepper"}, audit.ServiceIdentity{}, audit.ErrNoServiceAccount)
	if f.Status != host.StatusNA {
		t.Fatalf("status %s on a host with no service account, want N/A: %s", f.Status, f.Detail)
	}
}

// The unit names an account that does not exist. The service cannot start
// either, so reporting "nothing to check" would send the operator to the
// pepper instead of to useradd.
func TestDoctorReportsAnAccountTheHostDoesNotHave(t *testing.T) {
	f := pepperFinding(audit.PepperState{Path: "/etc/bodega/pepper"}, audit.ServiceIdentity{},
		errors.New("/etc/systemd/system/bodega.service runs the server as \"bodega\" and this host has no such account"))
	if f.Status != host.StatusFail {
		t.Fatalf("status %s, want FAIL: %s", f.Status, f.Detail)
	}
	if !strings.Contains(f.Detail, "bodega.service") {
		t.Errorf("detail %q does not name where the account was declared", f.Detail)
	}
}

// pepperPosture resolves the account itself, and that resolution is where the
// defect the review sent back lived: a vendor drop-in masked by an /etc file
// of the same name named a second account, doctor tested the pepper against
// that one and reported OK while the account systemd runs the server as could
// not open the file. Every case above hands pepperFinding an identity and so
// cannot see it.
func TestDoctorNamesTheAccountSystemdWouldRun(t *testing.T) {
	serving, masked := twoDoctorAccounts(t)
	units := t.TempDir()
	writeUnitFile(t, filepath.Join(units, "lib", "bodega.service"),
		"[Service]\nType=notify\nUser="+serving.Username+"\n")
	writeUnitFile(t, filepath.Join(units, "lib", "bodega.service.d", "10-account.conf"),
		"[Service]\nUser="+masked.Username+"\n")
	writeUnitFile(t, filepath.Join(units, "etc", "bodega.service.d", "10-account.conf"),
		"[Service]\nRestart=always\n")
	swapDoctorUnitDirs(t, filepath.Join(units, "etc"), filepath.Join(units, "lib"))

	path := filepath.Join(pepperTree(t, 0o644, 0o640), "pepper")
	if os.Geteuid() == 0 {
		// root:masked 0640 is the shape the wrong account's handoff leaves:
		// readable by the drop-in's account, closed to the one serving.
		gid, err := strconv.Atoi(masked.Gid)
		if err != nil {
			t.Fatalf("gid of %s: %v", masked.Username, err)
		}
		if err := os.Chown(path, 0, gid); err != nil {
			t.Fatalf("chown %s: %v", path, err)
		}
	} else if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
	prev := audit.DefaultPepperPaths
	audit.DefaultPepperPaths = []string{path}
	t.Cleanup(func() { audit.DefaultPepperPaths = prev })

	f := pepperPosture()
	if f.Status != host.StatusFail {
		t.Fatalf("status %s, want FAIL: %s serves and cannot read %s: %s",
			f.Status, serving.Username, path, f.Detail)
	}
	if !strings.Contains(f.Detail, strconv.Quote(serving.Username)) {
		t.Errorf("detail %q does not name %q, the account the unit runs the server as",
			f.Detail, serving.Username)
	}
	if strings.Contains(f.Detail, strconv.Quote(masked.Username)) {
		t.Errorf("detail %q names %q, which systemd never reads: its drop-in is masked by the /etc "+
			"file of the same name", f.Detail, masked.Username)
	}
	if !strings.Contains(f.Remediation, "chown root:") {
		t.Errorf("remediation %q carries no command to run", f.Remediation)
	}
}

// twoDoctorAccounts names two accounts this process is not, with distinct
// groups: one the unit runs the server as, one a masked drop-in names.
func twoDoctorAccounts(t *testing.T) (serving, masked *user.User) {
	t.Helper()
	var found []*user.User
	for _, name := range []string{"daemon", "bin", "www", "games", "sys", "nobody"} {
		u, err := user.Lookup(name)
		if err != nil {
			continue
		}
		uid, err := strconv.Atoi(u.Uid)
		if err != nil || uid == os.Getuid() {
			continue
		}
		if len(found) == 1 && u.Gid == found[0].Gid {
			continue
		}
		if found = append(found, u); len(found) == 2 {
			return found[0], found[1]
		}
	}
	t.Skip("this host has fewer than two accounts to model a masked drop-in with")
	return nil, nil
}

func writeUnitFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func swapDoctorUnitDirs(t *testing.T, dirs ...string) {
	t.Helper()
	prev := audit.UnitSearchDirs
	audit.UnitSearchDirs = dirs
	t.Cleanup(func() { audit.UnitSearchDirs = prev })
}

// serviceAccount is an identity this process is not: it owns nothing in a
// tree the test just built and belongs to none of its groups, which is the
// service account's position relative to a file root wrote.
var serviceAccount = audit.ServiceIdentity{
	Name: "bodega", Group: "bodega",
	UID: 4242, GID: 4242, GIDs: []int{4242},
	Source: "/etc/systemd/system/bodega.service",
}

// pepperTree builds /etc/bodega as the reproduction describes it, under a
// directory every uid can walk into: t.TempDir() sits at 0700 and would refuse
// the identity before the file under test got a say.
func pepperTree(t *testing.T, configMode, pepperMode os.FileMode) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "bodega-doctor")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod %s: %v", dir, err)
	}
	for name, mode := range map[string]os.FileMode{"config.json": configMode, "pepper": pepperMode} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x\n"), mode); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		if err := os.Chmod(filepath.Join(dir, name), mode); err != nil {
			t.Fatalf("chmod %s: %v", name, err)
		}
	}
	return dir
}
