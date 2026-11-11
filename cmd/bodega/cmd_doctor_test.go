package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/host"
	"github.com/ravinald/bodega/internal/manifest"

	_ "modernc.org/sqlite" // the audit store's driver, for the raw handles below
)

// fakePosture is the audit read surface with nothing behind it, so a posture
// case is stated as the three lists it is.
type fakePosture struct {
	rules []audit.PolicyInfo
	ages  []audit.AgePolicy
	osvs  []audit.OSVPolicy
	provs []audit.ProvenancePolicy
	modes []audit.AdmissionMode
	toks  []audit.TokenInfo
	binds []audit.IdentityBinding
}

func (f fakePosture) ListPolicies(context.Context) ([]audit.PolicyInfo, error) {
	return f.rules, nil
}
func (f fakePosture) ListAgePolicies(context.Context) ([]audit.AgePolicy, error) { return f.ages, nil }
func (f fakePosture) ListOSVPolicies(context.Context) ([]audit.OSVPolicy, error) { return f.osvs, nil }
func (f fakePosture) ListProvenancePolicies(context.Context) ([]audit.ProvenancePolicy, error) {
	return f.provs, nil
}
func (f fakePosture) ListAdmissionModes(context.Context) ([]audit.AdmissionMode, error) {
	return f.modes, nil
}
func (f fakePosture) ListTokens(context.Context) ([]audit.TokenInfo, error) { return f.toks, nil }
func (f fakePosture) ListIdentityBindings(context.Context) ([]audit.IdentityBinding, error) {
	return f.binds, nil
}

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
	f := findingFor(t, serverPosture(context.Background(), fakePosture{}, nil), "policy-coverage")
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
	if f := findingFor(t, serverPosture(context.Background(), store, nil), "policy-coverage"); f.IsFinding() {
		t.Errorf("an install with a seeded age gate reported %s: %s", f.Status, f.Detail)
	}
}

// An upstream provenance block refuses fetches on its own; a warn row refuses
// nothing, because warn is what the check runs at with no row.
func TestDoctorCountsAProvenanceBlockAsCoverage(t *testing.T) {
	store := fakePosture{provs: []audit.ProvenancePolicy{{Ecosystem: "npm", Action: "block"}}}
	if f := findingFor(t, serverPosture(context.Background(), store, nil), "policy-coverage"); f.IsFinding() {
		t.Errorf("an install with an npm provenance block reported %s: %s", f.Status, f.Detail)
	}
	store = fakePosture{provs: []audit.ProvenancePolicy{{Ecosystem: "npm", Action: "warn"}}}
	if f := findingFor(t, serverPosture(context.Background(), store, nil), "policy-coverage"); !f.IsFinding() {
		t.Errorf("an install whose only policy is a provenance warn reported %s: %s", f.Status, f.Detail)
	}
}

// Provenance runs at warn on an ecosystem with no row, so it is silenced only
// once every ecosystem it covers is on ignore.
func TestDoctorReportsProvenanceSilencedEverywhere(t *testing.T) {
	some := fakePosture{provs: []audit.ProvenancePolicy{{Ecosystem: "npm", Action: "ignore"}}}
	if f := findingFor(t, serverPosture(context.Background(), some, nil), "policy-ignored"); f.IsFinding() {
		t.Errorf("npm alone on ignore reported %s: %s", f.Status, f.Detail)
	}
	base := []audit.ProvenancePolicy{
		{Ecosystem: "npm", Action: "ignore"}, {Ecosystem: "git", Action: "ignore"}, {Ecosystem: "binary", Action: "ignore"}}
	noHelm := fakePosture{provs: append(append([]audit.ProvenancePolicy(nil), base...), audit.ProvenancePolicy{Ecosystem: "pypi", Action: "ignore"})}
	if f := findingFor(t, serverPosture(context.Background(), noHelm, nil), "policy-ignored"); f.IsFinding() {
		t.Errorf("helm still verifies .prov files at warn, but doctor reported %s: %s", f.Status, f.Detail)
	}
	noPypi := fakePosture{provs: append(append([]audit.ProvenancePolicy(nil), base...), audit.ProvenancePolicy{Ecosystem: "helm", Action: "ignore"})}
	if f := findingFor(t, serverPosture(context.Background(), noPypi, nil), "policy-ignored"); f.IsFinding() {
		t.Errorf("pypi still verifying reported provenance silenced: %s", f.Detail)
	}
	all := fakePosture{provs: append(noHelm.provs, audit.ProvenancePolicy{Ecosystem: "helm", Action: "ignore"})}
	f := findingFor(t, serverPosture(context.Background(), all, nil), "policy-ignored")
	if !f.IsFinding() || !strings.Contains(f.Detail, "upstream provenance") || !strings.Contains(f.Remediation, "bodega policy provenance set") {
		t.Errorf("every covered ecosystem on ignore reported %s: %s / %s", f.Status, f.Detail, f.Remediation)
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
	f := findingFor(t, serverPosture(context.Background(), store, nil), "policy-ignored")
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
	if f := findingFor(t, serverPosture(context.Background(), store, nil), "policy-ignored"); f.IsFinding() {
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
	f := findingFor(t, serverPosture(context.Background(), store, nil), "policy-ecosystem")
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
	for _, f := range serverPosture(context.Background(), db, nil) {
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
	findings := serverPosture(context.Background(), store, nil)
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
	f := findingFor(t, serverPosture(context.Background(), store, nil), "policy-coverage")
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
	f := findingFor(t, serverPosture(context.Background(), store, nil), "policy-coverage")
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
	f := findingFor(t, serverPosture(context.Background(), store, nil), "policy-coverage")
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
	f := findingFor(t, serverPosture(context.Background(), store, nil), "policy-coverage")
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
	f := pepperFinding(audit.PepperState{Path: filepath.Join(dir, "pepper")}, nil, serviceAccount, nil)

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

	if f := pepperFinding(audit.PepperState{Path: path}, nil, id, nil); f.IsFinding() {
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
	f := pepperFinding(audit.PepperState{Path: filepath.Join(dir, "pepper")}, nil, serviceAccount, nil)

	if f.Status != host.StatusFail {
		t.Fatalf("a pepper inside a 0700 directory reported %s: %s", f.Status, f.Detail)
	}
	if !strings.Contains(f.Detail, dir) || !strings.Contains(f.Remediation, dir) {
		t.Errorf("detail %q / remediation %q do not name the directory %q", f.Detail, f.Remediation, dir)
	}
}

// A symlinked config directory whose target sits under a directory the
// service account cannot enter. The pepper's own mode hands it over, so
// doctor reported OK and the operator's next move was to re-mint into the
// same 401 — which is the failure this check exists to end.
func TestDoctorNamesTheDirectoryBehindASymlinkedPepper(t *testing.T) {
	root := pepperTree(t, 0o644, 0o644)
	closed := filepath.Join(root, "private")
	if err := os.Mkdir(closed, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(closed, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	target := filepath.Join(closed, "pepper")
	if err := os.Rename(filepath.Join(root, "pepper"), target); err != nil {
		t.Fatalf("rename: %v", err)
	}
	link := filepath.Join(root, "pepper")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	f := pepperFinding(audit.PepperState{Path: link}, nil, serviceAccount, nil)
	if f.Status != host.StatusFail {
		t.Fatalf("a 0644 pepper behind a 0700 directory reported %s: %s", f.Status, f.Detail)
	}
	if !strings.Contains(f.Detail, closed) {
		t.Errorf("detail %q does not name %q, the directory that refuses the walk", f.Detail, closed)
	}
	if want := "chgrp " + serviceAccount.Group + " " + closed; !strings.Contains(f.Remediation, want) {
		t.Errorf("remediation %q carries no %q: a chown of the pepper leaves the directory refusing it", f.Remediation, want)
	}
}

// The OK side of the same shape. A check that refuses on sight of a symlink
// sends the operator to chmod a tree nothing is wrong with.
func TestDoctorAcceptsAPepperReachedThroughASymlink(t *testing.T) {
	root := pepperTree(t, 0o644, 0o644)
	link := filepath.Join(root, "pepper-link")
	if err := os.Symlink(filepath.Join(root, "pepper"), link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if f := pepperFinding(audit.PepperState{Path: link}, nil, serviceAccount, nil); f.IsFinding() {
		t.Fatalf("a pepper every uid can walk to and read reported %s: %s", f.Status, f.Detail)
	}
}

// A pepper the resolver could not open at all. The shipped check threw that
// error away, read the empty state as absence and printed "no pepper on this
// host" while the server refused every token minted against the file that is
// sitting right there.
func TestDoctorReportsAPepperThatWillNotOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pepper")
	if err := os.Symlink("pepper", path); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	st, resErr := audit.ResolvePepper([]string{path})
	f := pepperFinding(st, resErr, serviceAccount, nil)

	if f.Status != host.StatusFail {
		t.Fatalf("a pepper that will not open reported %s: %s", f.Status, f.Detail)
	}
	if strings.Contains(f.Detail, "no pepper on this host") {
		t.Fatalf("detail reports absence for a pepper that exists: %s", f.Detail)
	}
	if !strings.Contains(f.Detail, path) {
		t.Errorf("detail %q does not name the path", f.Detail)
	}
	if !strings.Contains(f.Detail, "symbolic links") {
		t.Errorf("detail %q does not carry why it would not open", f.Detail)
	}
	if f.Remediation == "" || strings.Contains(f.Remediation, "chown") || strings.Contains(f.Remediation, "chmod") {
		t.Errorf("remediation %q sends the operator to an ownership change for a path that will not open", f.Remediation)
	}
}

// A host running the server as whoever invoked it has no second account to
// check against, and a FAIL there would fire on every developer laptop.
func TestDoctorSkipsThePepperWithNoServiceAccount(t *testing.T) {
	f := pepperFinding(audit.PepperState{Path: "/etc/bodega/pepper"}, nil, audit.ServiceIdentity{}, audit.ErrNoServiceAccount)
	if f.Status != host.StatusNA {
		t.Fatalf("status %s on a host with no service account, want N/A: %s", f.Status, f.Detail)
	}
}

// The unit names an account that does not exist. The service cannot start
// either, so reporting "nothing to check" would send the operator to the
// pepper instead of to useradd.
func TestDoctorReportsAnAccountTheHostDoesNotHave(t *testing.T) {
	f := pepperFinding(audit.PepperState{Path: "/etc/bodega/pepper"}, nil, audit.ServiceIdentity{},
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

// TestDoctorFollowsAClearedGroup is the review's second reproduction on the
// doctor side. An operator who clears Group= with `systemctl edit` leaves a
// pepper already handed to the unit's original group, and the check that
// reports OK for it is the one command that exists to find this.
func TestDoctorFollowsAClearedGroup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to hand the pepper to a group this process is not in")
	}
	serving, stale := twoDoctorAccounts(t)
	units := t.TempDir()
	writeUnitFile(t, filepath.Join(units, "lib", "bodega.service"),
		"[Service]\nType=notify\nUser="+stale.Username+"\nGroup="+doctorGroupName(t, stale)+"\n")
	writeUnitFile(t, filepath.Join(units, "etc", "bodega.service.d", "10-account.conf"),
		"[Service]\nUser="+serving.Username+"\nGroup=\n")
	swapDoctorUnitDirs(t, filepath.Join(units, "etc"), filepath.Join(units, "lib"))

	// root:<the group the unit named before the edit>, 0640: what the mint
	// left on disk while the resolver still read the cleared key as absent.
	path := filepath.Join(pepperTree(t, 0o644, 0o640), "pepper")
	staleGID, err := strconv.Atoi(stale.Gid)
	if err != nil {
		t.Fatalf("gid of %s: %v", stale.Username, err)
	}
	if err := os.Chown(path, 0, staleGID); err != nil {
		t.Fatalf("chown %s: %v", path, err)
	}
	prev := audit.DefaultPepperPaths
	audit.DefaultPepperPaths = []string{path}
	t.Cleanup(func() { audit.DefaultPepperPaths = prev })

	f := pepperPosture()
	if f.Status != host.StatusFail {
		t.Fatalf("status %s, want FAIL: %s serves in its own primary group and cannot read a root:%s pepper: %s",
			f.Status, serving.Username, doctorGroupName(t, stale), f.Detail)
	}
	if !strings.Contains(f.Detail, strconv.Quote(serving.Username)) {
		t.Errorf("detail %q does not name %q, the account the unit runs the server as", f.Detail, serving.Username)
	}
	if want := "chown root:" + doctorGroupName(t, serving); !strings.Contains(f.Remediation, want) {
		t.Errorf("remediation %q does not carry %q, the chown that hands the pepper over", f.Remediation, want)
	}
}

func doctorGroupName(t *testing.T, u *user.User) string {
	t.Helper()
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Skipf("no group named for gid %s (%s): %v", u.Gid, u.Username, err)
	}
	return g.Name
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
	// The pepper check names the path the kernel lands on, and /tmp is a
	// symlink to /private/tmp on macOS, so a case comparing against the
	// unresolved root would measure that rather than what it built.
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("resolve %s: %v", dir, err)
	}
	return resolved
}

// The run the service unit prescribes: a root-owned config and an operator who
// did not type sudo. Before this, the three posture rows read N/A beside the
// checks that had genuinely passed, and the summary counted an unrelated snapd
// FAIL, so nothing in the output or the exit code said the posture was never
// measured.
func TestDoctorPostureIsSkippedWhenTheConfigWillNotOpen(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 file, so the unprivileged case cannot be staged here")
	}
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"audit_db":"/var/lib/bodega/audit.db"}`), 0o000); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("BODEGA_CONFIG_FILE", cfgPath)

	findings := append(serverPostureFindings(context.Background(), &globalFlags{}), retiredConfigKeys(&globalFlags{}))
	for _, f := range findings {
		if f.Status != host.StatusSkip {
			t.Errorf("%s reported %s on a config it could not read, want SKIPPED: %s", f.Check, f.Status, f.Detail)
		}
		if f.IsFinding() {
			t.Errorf("%s counts as a finding; a check that never ran has no verdict to report", f.Check)
		}
		if !strings.Contains(f.Remediation, "sudo bodega doctor") {
			t.Errorf("%s remediation %q does not name the privilege the check needs", f.Check, f.Remediation)
		}
	}
}

// N/A stays a measurement. A client host with no install has no posture, and
// telling its operator to re-run as root would send them after a file that
// does not exist.
func TestDoctorPostureStaysNAWithNoInstall(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	body := `{"audit_db":` + strconv.Quote(filepath.Join(dir, "audit.db")) + `}`
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("BODEGA_CONFIG_FILE", cfgPath)

	for _, f := range serverPostureFindings(context.Background(), &globalFlags{}) {
		if f.Status != host.StatusNA {
			t.Errorf("%s on a host with no install reported %s, want N/A", f.Check, f.Status)
		}
	}
}

// The summary is what a reader takes away, and a count of findings beside
// three checks that never ran is a count of the wrong thing.
func TestDoctorSummaryCountsWhatWasNotMeasured(t *testing.T) {
	cases := []struct {
		name                string
		actionable, skipped int
		wantCode            int
		wantContains        []string
	}{
		{"clean", 0, 0, 0, []string{"OK: host configuration aligns"}},
		{"findings only", 3, 0, 2, []string{"3 finding(s)"}},
		{"skips only", 0, 3, 3, []string{"3 check(s) that could not run", "No finding on what was measured"}},
		{"both", 1, 3, 3, []string{"1 finding(s)", "3 check(s) that could not run"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out strings.Builder
			code := doctorSummary(&out, tc.actionable, tc.skipped)
			if code != tc.wantCode {
				t.Errorf("exit code %d, want %d for %d finding(s) and %d skipped", code, tc.wantCode, tc.actionable, tc.skipped)
			}
			for _, want := range tc.wantContains {
				if !strings.Contains(out.String(), want) {
					t.Errorf("summary %q does not say %q", out.String(), want)
				}
			}
		})
	}
}

// Each unexpired token still holding read, write and admin unrestricted is
// warned about by id; a narrowed, expired or exchanged-and-narrow token is
// not. "full" is what an unmigrated store still says.
func TestDoctorWarnsOnUnscopedTokens(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	toks := []audit.TokenInfo{
		{ID: "legacy", Label: "ci", Scope: "read,write,admin"},
		{ID: "old-store", Label: "ops", Scope: "full"},
		{ID: "narrow", Label: "npm", Scope: "read,write:npm"},
		{ID: "gone", Label: "x", Scope: audit.ScopeFull, ExpiresAt: &past},
	}
	var warned []string
	for _, f := range tokenScope(toks, time.Now()) {
		if f.Status != host.StatusWarn {
			t.Errorf("token-scope row %+v, want WARN", f)
		}
		warned = append(warned, f.Detail)
	}
	if len(warned) != 2 || !strings.Contains(warned[0], "legacy") || !strings.Contains(warned[1], "old-store") {
		t.Errorf("warnings = %v, want one each for legacy and old-store", warned)
	}
	clean := findingFor(t, serverPosture(context.Background(), fakePosture{toks: toks[2:]}, nil), "token-scope")
	if clean.Status != host.StatusOK {
		t.Errorf("no broad tokens: %+v, want OK", clean)
	}
}

// Migration 037 gave every admin token superadmin and approve together. Each
// live one is named with the commands that split it; an exchanged one points
// at the OIDC rule instead, since that is what mints it again.
func TestDoctorWarnsOnSuperadminWithApprove(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	toks := []audit.TokenInfo{
		{ID: "migrated", Label: "ops", Scope: audit.ScopeFull},
		{ID: "pair", Label: "alice", Scope: "approve,superadmin"},
		{ID: "oidc", Label: "login", Scope: "approve,superadmin", Subject: "bob", Issuer: "https://idp.example"},
		{ID: "approver", Label: "oncall", Scope: "read,approve"},
		{ID: "minter", Label: "carol", Scope: "superadmin"},
		{ID: "gone", Label: "x", Scope: "approve,superadmin", ExpiresAt: &past},
	}
	rows := tokenScope(toks, time.Now())
	if len(rows) != 3 {
		t.Fatalf("rows = %+v, want one each for migrated, pair and oidc", rows)
	}
	for i, id := range []string{"migrated", "pair", "oidc"} {
		f := rows[i]
		if f.Status != host.StatusWarn || !strings.Contains(f.Detail, "token "+id+" ") || !strings.Contains(f.Detail, "superadmin with approve") {
			t.Errorf("row %d = %+v, want a WARN naming %s as superadmin with approve", i, f, id)
		}
	}
	if !strings.Contains(rows[0].Detail, "(ops)") || !strings.Contains(rows[0].Detail, "read, write and admin") {
		t.Errorf("migrated detail %q should name the label and both reasons", rows[0].Detail)
	}
	for _, want := range []string{"bodega token generate alice --scope", "bodega token revoke pair"} {
		if !strings.Contains(rows[1].Remediation, want) {
			t.Errorf("remediation %q does not name %q", rows[1].Remediation, want)
		}
	}
	if !strings.Contains(rows[2].Remediation, "oidc_providers rule for https://idp.example") {
		t.Errorf("exchanged token remediation %q should name the OIDC rule", rows[2].Remediation)
	}
}

// approveReach counts identities, not tokens: an unbound approve token cannot
// vote, two tokens bound to one identity are one voter, and one OIDC rule
// granting approve reaches a group doctor cannot count.
func TestDoctorWarnsWhenTooFewIdentitiesCanApprove(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	toks := []audit.TokenInfo{
		{ID: "a1", Label: "alice", Scope: "read,approve"},
		{ID: "a2", Label: "alice-laptop", Scope: "approve"},
		{ID: "loose", Label: "nobody", Scope: "approve"},
		{ID: "b-old", Label: "bob", Scope: "approve", ExpiresAt: &past},
		{ID: "ci", Label: "ci", Scope: "write:npm"},
	}
	binds := []audit.IdentityBinding{
		{Kind: audit.BindToken, Key: "a1", Identity: "alice"},
		{Kind: audit.BindToken, Key: "a2", Identity: "alice"},
		{Kind: audit.BindToken, Key: "b-old", Identity: "bob"},
		{Kind: audit.BindToken, Key: "ci", Identity: "ci"},
	}
	now := time.Now()

	f := approveReach(toks, binds, nil, now)
	if f.Status != host.StatusWarn {
		t.Fatalf("one approving identity against a quorum of 2: %+v, want WARN", f)
	}
	for _, want := range []string{"1 identities hold approve", "override_quorum is 2", "1 approve token(s) are bound to no identity"} {
		if !strings.Contains(f.Detail, want) {
			t.Errorf("detail %q does not say %q", f.Detail, want)
		}
	}
	for _, want := range []string{`"read,approve"`, "bodega identity bind token"} {
		if !strings.Contains(f.Remediation, want) {
			t.Errorf("remediation %q does not name %q", f.Remediation, want)
		}
	}

	exchanged := append(slices.Clone(toks), audit.TokenInfo{ID: "x", Label: "login", Scope: "read,approve", Subject: "dave", Issuer: "https://idp.example"})
	if f := approveReach(exchanged, binds, nil, now); f.Status != host.StatusOK {
		t.Errorf("alice plus an exchanged dave reach a quorum of 2: %+v, want OK", f)
	}
	if f := approveReach(exchanged, binds, &config.Config{OverrideQuorum: 3}, now); f.Status != host.StatusWarn {
		t.Errorf("two identities against override_quorum 3: %+v, want WARN", f)
	}

	oncall := &config.Config{OverrideQuorum: 3, OIDCProviders: []config.OIDCProvider{{
		Name: "corp", Issuer: "https://idp.example",
		Rules: []config.OIDCRule{{Claims: map[string]string{"groups": "oncall-primary"}, Scopes: "read,approve"}},
	}}}
	if f := approveReach(nil, nil, oncall, now); f.Status != host.StatusOK || !strings.Contains(f.Detail, "corp rule 0") {
		t.Errorf("an OIDC rule granting approve: %+v, want OK naming the rule", f)
	}

	// Nobody can request over the API, so nothing waits on the count.
	if f := approveReach([]audit.TokenInfo{{ID: "r", Label: "mirror", Scope: "read"}}, nil, nil, now); f.Status != host.StatusOK {
		t.Errorf("no write token anywhere: %+v, want OK", f)
	}

	// #135: a rule written as admin before migration 037 granted approve and
	// stopped granting it with no change to config.
	adminRule := &config.Config{OIDCProviders: []config.OIDCProvider{{
		Name: "corp", Issuer: "https://idp.example",
		Rules: []config.OIDCRule{{Claims: map[string]string{"groups": "platform"}, Scopes: "read,write,admin"}},
	}}}
	f = approveReach(nil, nil, adminRule, now)
	if f.Status != host.StatusWarn || !strings.Contains(f.Detail, "corp rule 0 (read,write,admin)") || !strings.Contains(f.Detail, "migration 037") {
		t.Errorf("an admin-only OIDC rule with nobody else approving: %+v, want WARN naming the rule", f)
	}

	// #135 after following "On-call approvers": the approve rule makes the
	// row OK, and the admin rule beside it is still named in either order.
	oncallRule := config.OIDCRule{Claims: map[string]string{"groups": "oncall-primary"}, Scopes: "read,approve"}
	adminsRule := config.OIDCRule{Claims: map[string]string{"groups": "bodega-admins"}, Scopes: "read,admin"}
	for _, tc := range []struct {
		rules []config.OIDCRule
		want  string
	}{
		{[]config.OIDCRule{oncallRule, adminsRule}, "okta rule 1 (read,admin)"},
		{[]config.OIDCRule{adminsRule, oncallRule}, "okta rule 0 (read,admin)"},
	} {
		cfg := &config.Config{OIDCProviders: []config.OIDCProvider{{Name: "okta", Issuer: "https://idp.example", Rules: tc.rules}}}
		f := approveReach(nil, nil, cfg, now)
		if f.Status != host.StatusOK || !strings.Contains(f.Detail, "grants approve to every identity") ||
			!strings.Contains(f.Detail, tc.want) || !strings.Contains(f.Detail, "migration 037") {
			t.Errorf("approve rule beside an admin rule: %+v, want OK naming %q and migration 037", f, tc.want)
		}
	}

	// The whole check through serverPosture, as doctor runs it.
	var reach host.Finding
	for _, r := range serverPosture(context.Background(), fakePosture{toks: toks, binds: binds}, nil) {
		if r.Check == "token-scope" {
			reach = r
		}
	}
	if reach.Status != host.StatusWarn || !strings.Contains(reach.Detail, "override_quorum") {
		t.Errorf("serverPosture's last token-scope row = %+v, want the approve-reach WARN", reach)
	}
}

// A skipped check whose producer set no remediation still has to appear in
// "Could not run:", or the block vanishes while the run exits 3.
func TestPrintRemediationListsSkipWithoutRemedy(t *testing.T) {
	findings := []host.Finding{
		{Check: "pip-conf", Status: host.StatusOK},
		{Check: "apt-sources", Status: host.StatusSkip, Detail: "could not inspect /etc/apt: not a directory"},
	}
	out := capture(t, func() { printRemediation("Could not run:", findings, host.Finding.IsSkipped) })
	for _, want := range []string{"Could not run:", "[apt-sources] could not inspect /etc/apt: not a directory"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "pip-conf") {
		t.Errorf("output lists a row the predicate drops:\n%s", out)
	}
}

// No test asks the node or pip that happens to be on the machine running it:
// what those trust is the machine's, and the rows would follow it.
func init() { doctorNode, doctorPip = nil, nil }

// caPlanServer is a bodega served over TLS under a certificate no store on
// this host trusts. It answers /client/plan with npm's, pip's and go's files
// and the oci set, each path rooted under the caller's home, and counts the
// requests it took. Maven's two files are in the plan too, for the tests that
// name maven. The returned PEM is the certificate it serves, which
// httptest mints as its own CA.
func caPlanServer(t *testing.T) (srv *httptest.Server, caPEM []byte, requests *int) {
	t.Helper()
	requests = new(int)
	type planFile struct{ system, path, key, content string }
	var files []planFile
	mux := http.NewServeMux()
	mux.HandleFunc("GET /client/plan", func(w http.ResponseWriter, _ *http.Request) {
		*requests++
		var plan clientconf.Plan
		for _, f := range files {
			sum := sha256.Sum256([]byte(f.content))
			plan.Records = append(plan.Records, clientconf.PlanRecord{
				Identity: "web-host", Match: "cidr:192.0.2.1/32", System: f.system, Action: clientconf.PlanInstall,
				Path: f.path, URL: srv.URL + "/client/" + f.system + "?file=" + f.key, SHA256: hex.EncodeToString(sum[:]),
			})
		}
		_ = json.NewEncoder(w).Encode(plan)
	})
	mux.HandleFunc("GET /client/{system}", func(w http.ResponseWriter, r *http.Request) {
		*requests++
		for _, f := range files {
			if f.system == r.PathValue("system") && f.key == r.URL.Query().Get("file") {
				_, _ = io.WriteString(w, f.content)
			}
		}
	})
	srv = httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	// The plan below writes each system path as Linux names it, under the
	// home directory, so the probe judging the install reads the host's
	// files from there and by Linux's layout too.
	prev := doctorTrustProbe
	doctorTrustProbe = func() host.TrustProbe {
		p := prev()
		p.Root, p.GOOS = p.Home, clientconf.OSLinux
		return p
	}
	t.Cleanup(func() { doctorTrustProbe = prev })
	files = []planFile{
		{manifest.TypeNpm, "~/.npmrc", "", clientconf.Npm(srv.URL, nil).Content},
		{manifest.TypePypi, "~/etc/pip.conf", "", clientconf.Pip(srv.URL).Content},
	}
	goEnv := clientconf.Gomod(srv.URL)
	files = append(files, planFile{manifest.TypeGomod, goEnv.Path(clientconf.OSLinux), "", goEnv.Content})
	for _, f := range clientconf.OCIClient(srv.URL, map[string]string{"docker.io": "https://registry-1.docker.io"}) {
		files = append(files, planFile{manifest.TypeOCI, "~" + f.Path(clientconf.OSLinux), f.Key + "x", f.Content})
	}
	for _, f := range clientconf.Maven(srv.URL, nil) {
		files = append(files, planFile{manifest.TypeMaven, f.Path(clientconf.OSLinux), filepath.Base(f.Path(clientconf.OSLinux)), f.Content})
	}
	return srv, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), requests
}

// F116 R1, R3: --configure npm,pip,oci --ca-file previews the CA beside the
// plan, writes it where each client reads it with every other setting kept,
// and changes nothing on a second --apply.
func TestDoctorConfigureInstallsACA(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	stubRuntimes(t, "dockerd", "containerd", "podman")
	srv, caPEM, _ := caPlanServer(t)
	host := strings.TrimPrefix(srv.URL, "https://")
	caFile := filepath.Join(t.TempDir(), "internal-ca.pem")
	npmrc, daemon := filepath.Join(home, ".npmrc"), filepath.Join(home, "etc/docker/daemon.json")
	token := "//" + host + "/npm/:_authToken=bodega_ak_kept"
	for path, content := range map[string]string{
		caFile: string(caPEM),
		npmrc:  "registry=https://registry.npmjs.org/\n" + token + "\n",
		daemon: `{"log-driver":"journald"}`,
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	userCA := filepath.Join(home, ".config/bodega/ca.pem")
	certs := []string{
		userCA,
		filepath.Join(home, "etc/docker/certs.d", host, "ca.crt"),
		filepath.Join(home, "etc/containers/certs.d", host, "ca.crt"),
	}
	args := []string{"--configure", "npm,pypi,oci", "--ca-file", caFile, "--url", srv.URL}

	out, err := runDoctor(t, args...)
	if err != nil {
		t.Fatalf("dry run = %v:\n%s", err, out)
	}
	for _, want := range []string{"+cafile=" + userCA, "+cert = " + userCA, `+  ca = "` + userCA + `"`, "+-----BEGIN CERTIFICATE-----", "Dry run: nothing was written"} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run does not show %q:\n%s", want, out)
		}
	}
	for _, p := range certs {
		if !strings.Contains(out, p) {
			t.Errorf("the dry run does not name %s:\n%s", p, out)
		}
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the dry run wrote %s: %v", p, err)
		}
	}

	if out, err = runDoctor(t, append(args, "--apply")...); err != nil {
		t.Fatalf("--apply = %v:\n%s", err, out)
	}
	for _, p := range certs {
		if got, _ := os.ReadFile(p); string(got) != string(caPEM) {
			t.Errorf("%s = %q, want the CA", p, got)
		}
	}
	if got, _ := os.ReadFile(npmrc); string(got) != "registry="+srv.URL+"/npm/\n"+token+"\ncafile="+userCA+"\n" {
		t.Errorf(".npmrc after --apply = %q, want the registry, the kept token and cafile", got)
	}
	if got, _ := os.ReadFile(filepath.Join(home, "etc/pip.conf")); string(got) != "[global]\ncert = "+userCA+"\nindex-url = "+srv.URL+"/pypi/simple/\n" {
		t.Errorf("pip.conf after --apply = %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(home, "etc/containerd/certs.d/docker.io/hosts.toml")); !strings.Contains(string(got), `  ca = "`+userCA+`"`) || !strings.Contains(string(got), "capabilities") {
		t.Errorf("hosts.toml after --apply = %q", got)
	}
	if got, _ := os.ReadFile(daemon); !strings.Contains(string(got), `"log-driver": "journald"`) || !strings.Contains(string(got), srv.URL) {
		t.Errorf("daemon.json after --apply = %s", got)
	}

	out, err = runDoctor(t, append(args, "--apply")...)
	if err != nil || !strings.Contains(out, "Nothing to change") {
		t.Errorf("second --apply = %v:\n%s", err, out)
	}
	if backups, _ := filepath.Glob(npmrc + ".bodega-*"); len(backups) != 1 {
		t.Errorf("backups of .npmrc = %v, want the one the first --apply made", backups)
	}
}

// F116 R1: a --ca-file that holds no CA is refused before the server is
// asked for anything, and --ca-file means nothing without --configure.
func TestDoctorConfigureRefusesAFileThatIsNoCA(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	stubRuntimes(t, "dockerd")
	srv, caPEM, requests := caPlanServer(t)
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "bodega.internal"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}, srv.Certificate(), &key.PublicKey, srv.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ content, want string }{
		"empty.pem": {"", "holds no PEM certificate"},
		"leaf.pem":  {string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})), "is not a CA"},
		"key.pem":   {string(caPEM) + "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", "certificates only"},
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := runDoctor(t, "--configure", "npm,pypi,oci", "--ca-file", path, "--url", srv.URL, "--apply")
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "nothing was written") {
			t.Errorf("%s: --ca-file = %v, want a refusal naming %q", name, err, tc.want)
		}
	}
	_, err = runDoctor(t, "--configure", "npm", "--ca-file", filepath.Join(dir, "absent.pem"), "--url", srv.URL)
	if err == nil || !strings.Contains(err.Error(), "--ca-file") {
		t.Errorf("an absent --ca-file = %v, want a refusal", err)
	}
	if *requests != 0 {
		t.Errorf("the server took %d request(s) for a refused --ca-file", *requests)
	}
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Errorf("a refused --ca-file left %d entries in the home directory", len(entries))
	}
	if _, err := runDoctor(t, "--ca-file", filepath.Join(dir, "leaf.pem")); err == nil || !strings.Contains(err.Error(), "--ca-file applies to --configure") {
		t.Errorf("--ca-file without --configure = %v, want the orphaned-flag refusal", err)
	}
}

// F116 R2: the report warns on a client configured for a bodega whose
// certificate no store it reads verifies, and stops once --ca-file has put
// the CA in that client's own.
func TestDoctorReportsAClientThatCannotVerifyBodega(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	stubRuntimes(t)
	srv, caPEM, _ := caPlanServer(t)
	prevExit := doctorExit
	doctorExit = func(int) {}
	t.Cleanup(func() { doctorExit = prevExit })
	caFile := filepath.Join(t.TempDir(), "internal-ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	npmrc := filepath.Join(home, ".npmrc")
	if err := os.WriteFile(npmrc, []byte("registry="+srv.URL+"/npm/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	npmRow := func(out string) string {
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "npm-config") {
				return line
			}
		}
		return ""
	}

	out, err := runDoctor(t, "--url", srv.URL)
	if err != nil {
		t.Fatalf("doctor = %v:\n%s", err, out)
	}
	if row := npmRow(out); !strings.Contains(row, "WARN") || !strings.Contains(row, "the system trust store, standing in for the roots Node bundles while no cafile setting names a file, does not verify") {
		t.Errorf("npm-config row = %q, want a warning naming the store npm reads:\n%s", row, out)
	}
	if want := "bodega doctor --configure npm --ca-file <CA certificate PEM> --apply --url " + srv.URL; !strings.Contains(out, want) {
		t.Errorf("the remediation does not read %q:\n%s", want, out)
	}

	if out, err := runDoctor(t, "--configure", "npm", "--ca-file", caFile, "--url", srv.URL, "--apply"); err != nil {
		t.Fatalf("--configure npm --ca-file = %v:\n%s", err, out)
	}
	out, err = runDoctor(t, "--url", srv.URL)
	if err != nil {
		t.Fatalf("doctor = %v:\n%s", err, out)
	}
	if row := npmRow(out); !strings.Contains(row, "OK") || strings.Contains(row, "WARN") {
		t.Errorf("npm-config row after --ca-file = %q, want OK:\n%s", row, out)
	}
}

// F116 R1: a system that verifies through the system trust store gets an
// anchor there and the command that rebuilds the store, previewed as a step,
// run once under --apply and not again once the store the clients read holds
// the CA.
func TestDoctorConfigureRebuildsTheSystemTrustStore(t *testing.T) {
	home, root := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	srv, caPEM, _ := caPlanServer(t)
	caFile := filepath.Join(t.TempDir(), "internal-ca.pem")
	osRelease := filepath.Join(t.TempDir(), "os-release")
	for path, content := range map[string]string{caFile: string(caPEM), osRelease: "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"26.04\"\n"} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var ran []string
	prevGOOS, prevRoot, prevRelease, prevRun := doctorCAGOOS, doctorOCIRoot, doctorOSRelease, doctorRun
	doctorCAGOOS, doctorOCIRoot, doctorOSRelease = clientconf.OSLinux, root, osRelease
	anchor := filepath.Join(root, "usr/local/share/ca-certificates/bodega-ca.crt")
	// update-ca-certificates, as far as doctor reads it: the anchors
	// concatenated into the bundle every client on the host opens.
	doctorRun = func(name string, args ...string) error {
		ran = append(ran, strings.Join(append([]string{name}, args...), " "))
		data, err := os.ReadFile(anchor)
		if err != nil {
			return err
		}
		bundle := filepath.Join(root, "etc/ssl/certs/ca-certificates.crt")
		if err := os.MkdirAll(filepath.Dir(bundle), 0o755); err != nil {
			return err
		}
		return os.WriteFile(bundle, data, 0o644)
	}
	t.Cleanup(func() {
		doctorCAGOOS, doctorOCIRoot, doctorOSRelease, doctorRun = prevGOOS, prevRoot, prevRelease, prevRun
	})
	args := []string{"--configure", "gomod", "--ca-file", caFile, "--url", srv.URL}

	out, err := runDoctor(t, args...)
	if err != nil || !strings.Contains(out, "update-ca-certificates") || !strings.Contains(out, "the trust store step") || !strings.Contains(out, anchor) {
		t.Fatalf("dry run = %v, want the anchor and the step previewed:\n%s", err, out)
	}
	if _, err := os.Stat(anchor); !errors.Is(err, os.ErrNotExist) || len(ran) != 0 {
		t.Fatalf("the dry run wrote the anchor (%v) or ran %v", err, ran)
	}

	if out, err = runDoctor(t, append(args, "--apply")...); err != nil {
		t.Fatalf("--apply = %v:\n%s", err, out)
	}
	if got, _ := os.ReadFile(anchor); string(got) != string(caPEM) {
		t.Errorf("%s = %q, want the CA", anchor, got)
	}
	if !slices.Equal(ran, []string{"update-ca-certificates"}) {
		t.Errorf("--apply ran %v, want update-ca-certificates once", ran)
	}

	out, err = runDoctor(t, append(args, "--apply")...)
	if err != nil || !strings.Contains(out, "Nothing to change") || len(ran) != 1 {
		t.Errorf("second --apply = %v, ran %v:\n%s", err, ran, out)
	}
}

// F116 R1, R2: --configure maven --ca-file imports the CA into the JVM trust
// store with keytool, reading the file the plan wrote. An import that fails
// is run again by the next --apply, the maven row warns naming that store
// until it holds the CA, and a run after that changes nothing.
func TestDoctorConfigureImportsIntoTheJVMTrustStore(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	stubRuntimes(t)
	srv, caPEM, _ := caPlanServer(t)
	caFile := filepath.Join(t.TempDir(), "internal-ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	// A distribution the wrapper downloaded is what makes Maven installed
	// for the report, on a host with no mvn on PATH.
	if err := os.MkdirAll(filepath.Join(home, ".m2/wrapper/dists/apache-maven"), 0o755); err != nil {
		t.Fatal(err)
	}
	var stored []*x509.Certificate
	var ran [][]string
	fail := true
	prevJVM, prevRun, prevExit, prevImport := doctorJVM, doctorRun, doctorExit, doctorRunJVM
	doctorExit = func(int) {}
	doctorRunJVM = func(cmd []string) error { return doctorRun(cmd[0], cmd[1:]...) }
	doctorJVM = func() (clientconf.JVMStore, []*x509.Certificate, error) {
		return clientconf.JVMStore{Keytool: "/jdk/bin/keytool"}, stored, nil
	}
	doctorRun = func(name string, args ...string) error {
		ran = append(ran, append([]string{name}, args...))
		if fail {
			return errors.New("keytool error: java.io.FileNotFoundException: cacerts (Permission denied)")
		}
		data, err := os.ReadFile(args[len(args)-1])
		if err != nil {
			return err
		}
		stored = append(stored, clientconf.ParseKeytoolList(data)...)
		return nil
	}
	t.Cleanup(func() { doctorJVM, doctorRun, doctorExit, doctorRunJVM = prevJVM, prevRun, prevExit, prevImport })
	mavenRow := func() string {
		out, err := runDoctor(t, "--url", srv.URL)
		if err != nil {
			t.Fatalf("doctor = %v:\n%s", err, out)
		}
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "maven ") {
				return line
			}
		}
		t.Fatalf("no maven row:\n%s", out)
		return ""
	}
	args := []string{"--configure", "maven", "--ca-file", caFile, "--url", srv.URL}

	out, err := runDoctor(t, args...)
	if err != nil || !strings.Contains(out, "/jdk/bin/keytool -importcert -noprompt -trustcacerts -cacerts -storepass changeit -alias bodega-ca-") ||
		!strings.Contains(out, "1 JVM trust store import(s)") || len(ran) != 0 {
		t.Fatalf("dry run = %v, ran %v; want the import previewed and not run:\n%s", err, ran, out)
	}

	if out, err = runDoctor(t, append(args, "--apply")...); err == nil || !strings.Contains(err.Error(), "runs the import again") || len(ran) != 1 {
		t.Fatalf("--apply with keytool failing = %v, ran %v:\n%s", err, ran, out)
	}
	if got, _ := os.ReadFile(ran[0][len(ran[0])-1]); string(got) != string(caPEM) {
		t.Errorf("the file keytool was handed = %q, want the CA", got)
	}
	if row := mavenRow(); !strings.Contains(row, "WARN") || !strings.Contains(row, "the cacerts keystore of the JDK /jdk/bin/keytool belongs to") {
		t.Errorf("maven row with the import failed = %q, want a warning naming the JVM store", row)
	}

	fail = false
	if out, err = runDoctor(t, append(args, "--apply")...); err != nil || len(ran) != 2 || len(stored) != 1 {
		t.Fatalf("retry = %v, ran %v, store holds %d:\n%s", err, ran, len(stored), out)
	}
	if row := mavenRow(); !strings.Contains(row, "OK") || strings.Contains(row, "WARN") {
		t.Errorf("maven row with the CA imported = %q, want OK", row)
	}
	out, err = runDoctor(t, append(args, "--apply")...)
	if err != nil || !strings.Contains(out, "Nothing to change") || len(ran) != 2 {
		t.Errorf("third --apply = %v, ran %v:\n%s", err, ran, out)
	}
}

func TestReviewDoctorConfigureNpmPipOCI(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	stubRuntimes(t, "dockerd", "containerd", "podman")
	srv, caPEM, _ := caPlanServer(t)
	host := strings.TrimPrefix(srv.URL, "https://")
	caFile := filepath.Join(t.TempDir(), "internal-ca.pem")
	npmrc, daemon := filepath.Join(home, ".npmrc"), filepath.Join(home, "etc/docker/daemon.json")
	token := "//" + host + "/npm/:_authToken=bodega_ak_kept"
	for path, content := range map[string]string{
		caFile: string(caPEM),
		npmrc:  "registry=https://registry.npmjs.org/\n" + token + "\n",
		daemon: `{"log-driver":"journald"}`,
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	userCA := filepath.Join(home, ".config/bodega/ca.pem")
	certs := []string{
		userCA,
		filepath.Join(home, "etc/docker/certs.d", host, "ca.crt"),
		filepath.Join(home, "etc/containers/certs.d", host, "ca.crt"),
	}
	args := []string{"--configure", "npm,pip,oci", "--ca-file", caFile, "--url", srv.URL}

	out, err := runDoctor(t, args...)
	if err != nil {
		t.Fatalf("dry run = %v:\n%s", err, out)
	}
	for _, want := range []string{"+cafile=" + userCA, "+cert = " + userCA, `+  ca = "` + userCA + `"`, "+-----BEGIN CERTIFICATE-----", "Dry run: nothing was written"} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run does not show %q:\n%s", want, out)
		}
	}
	for _, p := range certs {
		if !strings.Contains(out, p) {
			t.Errorf("the dry run does not name %s:\n%s", p, out)
		}
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the dry run wrote %s: %v", p, err)
		}
	}

	if out, err = runDoctor(t, append(args, "--apply")...); err != nil {
		t.Fatalf("--apply = %v:\n%s", err, out)
	}
	for _, p := range certs {
		if got, _ := os.ReadFile(p); string(got) != string(caPEM) {
			t.Errorf("%s = %q, want the CA", p, got)
		}
	}
	if got, _ := os.ReadFile(npmrc); string(got) != "registry="+srv.URL+"/npm/\n"+token+"\ncafile="+userCA+"\n" {
		t.Errorf(".npmrc after --apply = %q, want the registry, the kept token and cafile", got)
	}
	if got, _ := os.ReadFile(filepath.Join(home, "etc/pip.conf")); string(got) != "[global]\ncert = "+userCA+"\nindex-url = "+srv.URL+"/pypi/simple/\n" {
		t.Errorf("pip.conf after --apply = %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(home, "etc/containerd/certs.d/docker.io/hosts.toml")); !strings.Contains(string(got), `  ca = "`+userCA+`"`) || !strings.Contains(string(got), "capabilities") {
		t.Errorf("hosts.toml after --apply = %q", got)
	}
	if got, _ := os.ReadFile(daemon); !strings.Contains(string(got), `"log-driver": "journald"`) || !strings.Contains(string(got), srv.URL) {
		t.Errorf("daemon.json after --apply = %s", got)
	}

	out, err = runDoctor(t, append(args, "--apply")...)
	if err != nil || !strings.Contains(out, "Nothing to change") {
		t.Errorf("second --apply = %v:\n%s", err, out)
	}
	if backups, _ := filepath.Glob(npmrc + ".bodega-*"); len(backups) != 1 {
		t.Errorf("backups of .npmrc = %v, want the one the first --apply made", backups)
	}
}

func TestUsageDocDescribesPrivateCA(t *testing.T) {
	data, err := os.ReadFile("../../docs/usage.md")
	if err != nil {
		t.Fatal(err)
	}
	usage := string(data)
	_, doctor, ok := strings.Cut(usage, "### `bodega doctor ")
	if !ok {
		t.Fatal("no doctor section")
	}
	doctor, _, _ = strings.Cut(doctor, "\n### ")
	_, configure, ok := strings.Cut(doctor, "`--configure` applies")
	if !ok {
		t.Fatal("no --configure documentation")
	}
	for _, want := range []string{"--ca-file", "Store the client reads", "What doctor writes", "`npm`", "`pypi`", "`git`", "Docker", "containerd", "podman", "update-ca-certificates", "update-ca-trust", "certctl rehash"} {
		if !strings.Contains(configure, want) {
			t.Errorf("--configure documentation lacks %q", want)
		}
	}
	_, tls, ok := strings.Cut(usage, "\n### TLS\n")
	if !ok {
		t.Fatal("no TLS section")
	}
	tls, _, _ = strings.Cut(tls, "\n### ")
	if !strings.Contains(tls, "--ca-file") || !strings.Contains(tls, "](#bodega-doctor-") {
		t.Error("TLS documentation does not link to doctor's private-CA instructions")
	}
}

func TestReviewDoctorRetriesFailedTrustRebuild(t *testing.T) {
	home, root := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	srv, caPEM, _ := caPlanServer(t)
	caFile, release := filepath.Join(t.TempDir(), "ca.pem"), filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(release, []byte("ID=ubuntu\n"), 0600); err != nil {
		t.Fatal(err)
	}
	oldOS, oldRoot, oldRelease, oldRun := doctorCAGOOS, doctorOCIRoot, doctorOSRelease, doctorRun
	doctorCAGOOS, doctorOCIRoot, doctorOSRelease = clientconf.OSLinux, root, release
	attempts := 0
	// A rebuild that succeeds leaves the anchor in the bundle clients open,
	// which is what the verdict after it is reached against.
	doctorRun = func(string, ...string) error {
		attempts++
		if attempts == 1 {
			return errors.New("temporary trust rebuild failure")
		}
		data, err := os.ReadFile(filepath.Join(root, "usr/local/share/ca-certificates/bodega-ca.crt"))
		if err != nil {
			return err
		}
		bundle := filepath.Join(root, "etc/ssl/certs/ca-certificates.crt")
		if err := os.MkdirAll(filepath.Dir(bundle), 0o755); err != nil {
			return err
		}
		return os.WriteFile(bundle, data, 0o644)
	}
	t.Cleanup(func() { doctorCAGOOS, doctorOCIRoot, doctorOSRelease, doctorRun = oldOS, oldRoot, oldRelease, oldRun })
	args := []string{"--configure", "gomod", "--ca-file", caFile, "--url", srv.URL, "--apply"}
	if out, err := runDoctor(t, args...); err == nil {
		t.Fatalf("first rebuild should fail: %s", out)
	}
	out, err := runDoctor(t, args...)
	if err != nil || attempts != 2 {
		t.Fatalf("retry after failed trust rebuild: attempts=%d err=%v output=%s", attempts, err, out)
	}
}

func TestAuditPipInstallUsesTheInstalledCA(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	stubRuntimes(t)
	srv, pem, _ := caPlanServer(t)
	cafile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(cafile, pem, 0600); err != nil {
		t.Fatal(err)
	}
	pip := filepath.Join(home, "etc/pip.conf")
	if err := os.MkdirAll(filepath.Dir(pip), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pip, []byte("[global]\nindex-url=https://pypi.org/simple/\n[install]\ncert=/missing/old-ca.pem\nno-compile=true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	out, err := runDoctor(t, "--configure", "pip", "--ca-file", cafile, "--url", srv.URL, "--apply")
	if err != nil {
		t.Fatalf("apply: %v\n%s", err, out)
	}
	probe := host.TrustProbe{Root: home, GOOS: "linux", Getenv: func(string) string { return "" },
		Chain:  func(string) ([]*x509.Certificate, error) { return []*x509.Certificate{srv.Certificate()}, nil },
		System: func([]*x509.Certificate, string) error { return x509.UnknownAuthorityError{} },
	}
	f := probe.Apply([]host.Finding{{Check: "pip-config", Status: host.StatusOK}}, srv.URL)[0]
	if f.Status != host.StatusOK {
		t.Fatalf("successful --ca-file left pip install untrusted: %+v", f)
	}
}

// F116 R1: a CA written where a client no longer looks is not an install.
// A store the run cannot edit, one the environment names, fails the run and
// names the client and the variable. A configuration file the environment
// selects is edited instead, in the preview and the apply, keeping its own
// settings.
func TestDoctorConfigureFailsWhenAnotherStoreOutranksTheCA(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	stubRuntimes(t)
	// The plan's pip.conf is rooted under home, so that is the root the
	// report reads /etc from, as Linux: pip on macOS never opens /etc/pip.conf.
	prevRoot, prevGOOS := doctorOCIRoot, doctorCAGOOS
	doctorOCIRoot, doctorCAGOOS = home, clientconf.OSLinux
	t.Cleanup(func() { doctorOCIRoot, doctorCAGOOS = prevRoot, prevGOOS })
	srv, caPEM, _ := caPlanServer(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--configure", "pip,npm", "--ca-file", caFile, "--url", srv.URL}
	out, err := runDoctor(t, append(args, "--apply")...)
	if err != nil {
		t.Fatalf("--apply on a host with nothing outranking the plan = %v:\n%s", err, out)
	}
	t.Setenv("PIP_CERT", "/missing/site-ca.pem")
	out, err = runDoctor(t, append(args, "--apply")...)
	if err == nil || !strings.Contains(err.Error(), "pypi: ") || !strings.Contains(err.Error(), "the environment's PIP_CERT") {
		t.Fatalf("PIP_CERT outranks the cert setting the plan wrote; want the run to fail naming pypi and the variable, got %v:\n%s", err, out)
	}
	t.Setenv("PIP_CERT", "")

	selected := filepath.Join(home, "work.npmrc")
	if err := os.WriteFile(selected, []byte("; work\nregistry=https://registry.corp.example/\ncafile=/missing/corp.pem\nfund=false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NPM_CONFIG_USERCONFIG", selected)
	out, err = runDoctor(t, args...)
	if err != nil || !strings.Contains(out, selected) || !strings.Contains(out, "-cafile=/missing/corp.pem") {
		t.Fatalf("the preview leaves out the npmrc the environment selects (%v):\n%s", err, out)
	}
	if out, err = runDoctor(t, append(args, "--apply")...); err != nil {
		t.Fatalf("--apply with a selected npmrc = %v:\n%s", err, out)
	}
	got, err := os.ReadFile(selected)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"; work\n", "fund=false\n", "registry=" + srv.URL + "/npm/\n", "cafile=" + filepath.Join(home, ".config/bodega/ca.pem") + "\n"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("the selected npmrc lacks %q:\n%s", want, got)
		}
	}
	if out, err = runDoctor(t, append(args, "--apply")...); err != nil || !strings.Contains(out, "Nothing to change") {
		t.Fatalf("a second --apply with a selected npmrc = %v:\n%s", err, out)
	}
}

func TestIndependentPipInstallSelectedConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	stubRuntimes(t)
	srv, pem, _ := caPlanServer(t)
	cafile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(cafile, pem, 0600); err != nil {
		t.Fatal(err)
	}
	selected := filepath.Join(home, "selected-pip.conf")
	if err := os.WriteFile(selected, []byte("[global]\nindex-url="+srv.URL+"/pypi/simple/\ncert=/missing/old-ca.pem\n[install]\nno-compile=true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PIP_CONFIG_FILE", selected)
	out, err := runDoctor(t, "--configure", "pip", "--ca-file", cafile, "--url", srv.URL, "--apply")
	if err != nil {
		t.Fatalf("apply: %v\n%s", err, out)
	}
	probe := host.TrustProbe{Root: home, GOOS: "linux", Getenv: func(k string) string {
		if k == "PIP_CONFIG_FILE" {
			return selected
		}
		return ""
	},
		Chain:  func(string) ([]*x509.Certificate, error) { return []*x509.Certificate{srv.Certificate()}, nil },
		System: func([]*x509.Certificate, string) error { return x509.UnknownAuthorityError{} },
	}
	f := probe.Apply([]host.Finding{{Check: "pip-config", Status: host.StatusOK}}, srv.URL)[0]
	if f.Status != host.StatusOK {
		t.Fatalf("successful install left selected pip store untrusted: %+v", f)
	}
}

func TestStaffDoctorPodmanInstallsIntoSelectedCertDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	stubRuntimes(t, "podman")
	oldRoot := doctorOCIRoot
	doctorOCIRoot = home
	t.Cleanup(func() { doctorOCIRoot = oldRoot })
	srv, caPEM, _ := caPlanServer(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	selected := filepath.Join(home, ".config/containers/certs.d", strings.TrimPrefix(srv.URL, "https://"))
	if err := os.MkdirAll(selected, 0755); err != nil {
		t.Fatal(err)
	}
	out, err := runDoctor(t, "--configure", "oci", "--ca-file", caFile, "--url", srv.URL, "--apply")
	if err != nil {
		t.Fatalf("apply: %v\n%s", err, out)
	}
	pool := x509.NewCertPool()
	files, err := filepath.Glob(filepath.Join(selected, "*.crt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		pool.AppendCertsFromPEM(data)
	}
	if _, err := srv.Certificate().Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Fatalf("successful apply left podman's selected cert directory without the CA: %v\n%s", err, out)
	}
}

func TestFinalDoctorRejectsPipIgnoringEveryConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PIP_CONFIG_FILE", os.DevNull)
	t.Setenv("PIP_INDEX_URL", "")
	stubRuntimes(t)
	prevRoot, prevOS := doctorOCIRoot, doctorCAGOOS
	doctorOCIRoot, doctorCAGOOS = home, clientconf.OSLinux
	t.Cleanup(func() { doctorOCIRoot, doctorCAGOOS = prevRoot, prevOS })
	srv, caPEM, _ := caPlanServer(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		_, err := runDoctor(t, "--configure", "pip", "--ca-file", caFile, "--url", srv.URL, "--apply")
		if err == nil {
			t.Errorf("apply %d succeeded with PIP_CONFIG_FILE=/dev/null; pip consumes none of the installed settings or CA", i+1)
		}
	}
}

// F116 R1: after an install every owed check gets a verdict, and only a
// client shown to verify bodega's certificate passes. One that still reads a
// store without the CA fails the run, and so do one that could not be judged
// and one nothing points at bodega.
func TestUnreadCAOwesAVerdictPerSystem(t *testing.T) {
	srv, caPEM, _ := caPlanServer(t)
	root := t.TempDir()
	caFile := filepath.Join(root, "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	pipConf := filepath.Join(root, "etc/pip.conf")
	if err := os.MkdirAll(filepath.Dir(pipConf), 0o755); err != nil {
		t.Fatal(err)
	}
	prev := doctorTrustProbe
	t.Cleanup(func() { doctorTrustProbe = prev })
	doctorTrustProbe = func() host.TrustProbe {
		return host.TrustProbe{Root: root, Home: "/home/u", GOOS: "linux", Getenv: func(string) string { return "" },
			System: func([]*x509.Certificate, string) error { return nil }}
	}
	systems := []string{"pip-config"}
	for _, tc := range []struct {
		name, cert, want string
	}{
		{"pip cannot say which bundle it reads", "", "could not be checked"},
		{"pip reads a bundle without the CA", "cert = /missing/site.pem\n", "still read a store without it"},
		{"pip reads the installed CA", "cert = " + caFile + "\n", ""},
	} {
		if err := os.WriteFile(pipConf, []byte("[global]\nindex-url = "+srv.URL+"/pypi/simple/\n"+tc.cert), 0o644); err != nil {
			t.Fatal(err)
		}
		err := unreadCA(systems, nil, srv.URL)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v; want a pass", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "pypi: ") || strings.Contains(err.Error(), "cargo")):
			t.Errorf("%s: %v; want a failure naming pypi alone and %q", tc.name, err, tc.want)
		}
	}
	err := unreadCA([]string{"cargo-config", "pip-config"}, nil, srv.URL)
	if err == nil || !strings.Contains(err.Error(), "unverified") || !strings.Contains(err.Error(), "cargo: ") || strings.Contains(err.Error(), "pypi: ") {
		t.Errorf("a selected client nothing points at bodega = %v; want a failure naming cargo alone as unverified", err)
	}
	if got := owedTrustChecks([]clientconf.PlanRecord{{System: manifest.TypeOCI, Path: clientconf.DockerDaemonPath}, {System: manifest.TypeNpm, Path: "~/.npmrc"}}); !slices.Equal(got, []string{"npm-config", "oci-docker"}) {
		t.Errorf("owed checks = %v; want npm's and the one runtime the plan writes for", got)
	}
	srv.Close()
	if err := unreadCA(systems, nil, srv.URL); err == nil || !strings.Contains(err.Error(), "could not be checked") {
		t.Errorf("a bodega that stopped answering = %v; want the run to say nothing was checked", err)
	}
}

func TestAudit6DoctorCannotSucceedWithoutSelectedTrust(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, key := range []string{"npm_config_userconfig", "NPM_CONFIG_USERCONFIG", "npm_config_globalconfig", "NPM_CONFIG_GLOBALCONFIG", "npm_config_registry", "NPM_CONFIG_CA", "npm_config_ca", "npm_config_cafile"} {
		t.Setenv(key, "")
	}
	t.Setenv("NPM_CONFIG_REGISTRY", "https://registry.corp.example/")
	stubRuntimes(t)
	srv, caPEM, _ := caPlanServer(t)
	caFile, wrong := filepath.Join(home, "ca.pem"), filepath.Join(home, "unrelated-ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "unrelated CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wrong, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NPM_CONFIG_CAFILE", wrong)
	for i := 0; i < 2; i++ {
		out, err := runDoctor(t, "--configure", "npm", "--ca-file", caFile, "--url", srv.URL, "--apply")
		if err == nil {
			t.Errorf("apply %d returned success with selected npm unverified and NPM_CONFIG_CAFILE pointing at an unrelated CA (unverified line: %v)", i+1, strings.Contains(out, "unverified"))
		}
	}
}

// F116 R1: a selected client the install did not reach fails the run. With
// the environment naming another registry, npm reads nothing pointing it at
// bodega, and each apply says so and exits non-zero. A cafile the environment
// sets ahead of the installed one is refused before .npmrc is written.
func TestDoctorFailsASelectedClientLeftUnverified(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, key := range []string{"npm_config_userconfig", "NPM_CONFIG_USERCONFIG", "npm_config_globalconfig", "NPM_CONFIG_GLOBALCONFIG", "npm_config_registry", "NPM_CONFIG_CA", "npm_config_ca", "npm_config_cafile", "NPM_CONFIG_CAFILE"} {
		t.Setenv(key, "")
	}
	t.Setenv("NPM_CONFIG_REGISTRY", "https://registry.corp.example/")
	stubRuntimes(t)
	srv, caPEM, _ := caPlanServer(t)
	caFile := filepath.Join(home, "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--configure", "npm", "--ca-file", caFile, "--url", srv.URL, "--apply"}

	t.Setenv("NPM_CONFIG_CAFILE", filepath.Join(home, "elsewhere.pem"))
	if _, err := runDoctor(t, args...); err == nil || !strings.Contains(err.Error(), "NPM_CONFIG_CAFILE") {
		t.Errorf("apply under NPM_CONFIG_CAFILE = %v; want a refusal naming the variable", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".npmrc")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the refusal wrote .npmrc: %v", err)
	}

	t.Setenv("NPM_CONFIG_CAFILE", "")
	for i := 0; i < 2; i++ {
		_, err := runDoctor(t, args...)
		if err == nil || !strings.Contains(err.Error(), "unverified") || !strings.Contains(err.Error(), "npm: ") {
			t.Errorf("apply %d with npm's registry set elsewhere = %v; want a failure naming npm as unverified", i+1, err)
		}
	}
	t.Setenv("NPM_CONFIG_REGISTRY", "")
	if out, err := runDoctor(t, args...); err != nil {
		t.Errorf("apply once npm reads the registry written = %v:\n%s", err, out)
	}
}

func TestAudit7DoctorVerifiesTheAdvertisedEndpoint(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, key := range []string{"npm_config_userconfig", "NPM_CONFIG_USERCONFIG", "npm_config_globalconfig", "NPM_CONFIG_GLOBALCONFIG", "npm_config_registry", "NPM_CONFIG_REGISTRY", "npm_config_ca", "NPM_CONFIG_CA", "npm_config_cafile", "NPM_CONFIG_CAFILE"} {
		t.Setenv(key, "")
	}
	stubRuntimes(t)
	var content string
	public := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, content) }))
	t.Cleanup(public.Close)
	content = clientconf.Npm(public.URL, nil).Content
	sum := sha256.Sum256([]byte(content))
	plan := clientconf.Plan{Records: []clientconf.PlanRecord{{System: manifest.TypeNpm, Action: clientconf.PlanInstall, Path: "~/.npmrc", URL: public.URL + "/client/npm", SHA256: hex.EncodeToString(sum[:])}}}
	management := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(plan) }))
	t.Cleanup(management.Close)
	caFile := filepath.Join(home, "issuer.pem")
	bundle := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: public.Certificate().Raw}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: management.Certificate().Raw})...)
	if err := os.WriteFile(caFile, bundle, 0600); err != nil {
		t.Fatal(err)
	}
	prev := doctorTrustProbe
	t.Cleanup(func() { doctorTrustProbe = prev })
	doctorTrustProbe = func() host.TrustProbe {
		return host.TrustProbe{Root: home, Home: home, GOOS: clientconf.OSLinux, Getenv: os.Getenv}
	}
	for i := 0; i < 2; i++ {
		out, err := runDoctor(t, "--configure", "npm", "--ca-file", caFile, "--url", management.URL, "--apply")
		if err != nil {
			t.Errorf("apply %d: a client configured for public_url %s was judged against management URL %s: %v", i+1, public.URL, management.URL, err)
		}
		if i == 1 && !strings.Contains(out, "Nothing to change") {
			t.Errorf("second apply rewrote files: %s", out)
		}
	}
	verdicts, err := doctorTrustProbe().Judge([]string{"npm-config"}, public.URL)
	if err != nil || len(verdicts) != 1 || verdicts[0].State != host.TrustVerified {
		t.Fatalf("the installed configuration does not verify the advertised endpoint: %+v, %v", verdicts, err)
	}
}

func TestAudit7CAInputTableNamesMavenDiscovery(t *testing.T) {
	data, err := os.ReadFile("../../docs/usage.md")
	if err != nil {
		t.Fatal(err)
	}
	_, table, ok := strings.Cut(string(data), "Doctor installs and verifies through the inputs below")
	if !ok {
		t.Fatal("no CA input boundary")
	}
	table, _, _ = strings.Cut(table, "An input outside this table")
	var row string
	for _, line := range strings.Split(table, "\n") {
		if strings.HasPrefix(line, "| `maven`") {
			row = line
		}
	}
	for _, input := range []string{".m2/settings.xml", ".gradle/init.d/bodega.gradle", "GRADLE_USER_HOME"} {
		if !strings.Contains(row, input) {
			t.Errorf("CA input table omits Maven discovery input %s, which mavenStores reads", input)
		}
	}
}

func TestAudit8DoctorCannotCertifyQuotedNpmCA(t *testing.T) {
	nativeNpm(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, key := range []string{"npm_config_userconfig", "NPM_CONFIG_USERCONFIG", "npm_config_globalconfig", "NPM_CONFIG_GLOBALCONFIG", "npm_config_registry", "NPM_CONFIG_REGISTRY", "npm_config_ca", "NPM_CONFIG_CA", "npm_config_cafile", "NPM_CONFIG_CAFILE"} {
		t.Setenv(key, "")
	}
	stubRuntimes(t)
	srv, caPEM, _ := caPlanServer(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "unrelated CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	wrong := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	caFile, target := filepath.Join(home, "issuer.pem"), filepath.Join(home, ".npmrc")
	old := "registry=" + srv.URL + "/npm/\ncafile=/missing/previous.pem\n\"ca\"=\"" + strings.ReplaceAll(strings.TrimSpace(string(wrong)), "\n", `\n`) + "\"\n"
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = runDoctor(t, "--configure", "npm", "--ca-file", caFile, "--url", srv.URL, "--apply")
	if err != nil {
		if got, _ := os.ReadFile(target); string(got) != old {
			t.Fatal("refused quoted inline CA only after writing .npmrc")
		}
		if _, statErr := os.Stat(filepath.Join(home, ".config/bodega/ca.pem")); !os.IsNotExist(statErr) {
			t.Fatalf("refused only after writing the CA: %v", statErr)
		}
		return
	}
	cmd := exec.Command("npm", "config", "get", "ca", "--userconfig", target, "--globalconfig", filepath.Join(home, "global.npmrc"))
	cmd.Dir = home
	for _, e := range os.Environ() {
		key, _, _ := strings.Cut(e, "=")
		if !strings.HasPrefix(strings.ToLower(key), "npm_config_") && key != "NODE_OPTIONS" {
			cmd.Env = append(cmd.Env, e)
		}
	}
	out, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(out)) != strings.TrimSpace(string(wrong)) {
		t.Fatalf("native npm fixture: %q, %v", out, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(out) {
		t.Fatal("native npm returned no CA")
	}
	if _, err := srv.Certificate().Verify(x509.VerifyOptions{Roots: pool, DNSName: "127.0.0.1"}); err != nil {
		t.Fatalf("doctor returned success after writing cafile, but native npm's quoted ca replaces it and rejects bodega: %v", err)
	}
}

// nativeNpm gates a test that holds doctor's reading of an npmrc against
// npm's own. A developer's machine without npm skips it. CI does not: its
// test job installs a pinned Node, so a missing npm there is a broken job
// that would otherwise pass every oracle test unrun.
func nativeNpm(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("npm"); err != nil {
		if os.Getenv("CI") == "true" {
			t.Fatal("native npm is required in CI: the test job installs it with actions/setup-node")
		}
		t.Skip("native npm is not installed")
	}
}

func TestAudit9TrustDiscoveryNeverExecutesHostClients(t *testing.T) {
	for _, mode := range []string{"node-report", "pip-preview", "keytool-preview"} {
		t.Run(mode, func(t *testing.T) {
			home, bin := t.TempDir(), t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("VIRTUAL_ENV", "")
			t.Setenv("JAVA_HOME", "")
			t.Setenv("JAVA_TOOL_OPTIONS", "")
			t.Setenv("MAVEN_OPTS", "")
			for _, key := range []string{"npm_config_userconfig", "NPM_CONFIG_USERCONFIG", "npm_config_globalconfig", "NPM_CONFIG_GLOBALCONFIG", "npm_config_registry", "NPM_CONFIG_REGISTRY", "npm_config_ca", "NPM_CONFIG_CA", "npm_config_cafile", "NPM_CONFIG_CAFILE", "PIP_CONFIG_FILE"} {
				t.Setenv(key, "")
			}
			marker := filepath.Join(home, "host-client-ran")
			t.Setenv("F116_AUDIT_MARKER", marker)
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			for _, name := range []string{"node", "pip3", "pip", "keytool"} {
				if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\nprintf '%s\\n' \"$0 $*\" >> \"$F116_AUDIT_MARKER\"\nexit 1\n"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			oldNode, oldPip := doctorNode, doctorPip
			doctorNode, doctorPip = host.AskNode, host.AskPip
			t.Cleanup(func() { doctorNode, doctorPip = oldNode, oldPip })
			stubRuntimes(t)
			srv, caPEM, _ := caPlanServer(t)
			caFile := filepath.Join(home, "issuer.pem")
			if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
				t.Fatal(err)
			}
			if mode == "node-report" {
				if err := os.WriteFile(filepath.Join(home, ".npmrc"), []byte("registry="+srv.URL+"/npm/\n"), 0600); err != nil {
					t.Fatal(err)
				}
				doctorTrustProbe().Apply([]host.Finding{{Check: "npm-config", Status: host.StatusOK}}, srv.URL)
			} else {
				system := "pip"
				if mode == "keytool-preview" {
					system = "maven"
				}
				_, _ = runDoctor(t, "--configure", system, "--ca-file", caFile, "--url", srv.URL)
			}
			if ran, err := os.ReadFile(marker); err == nil {
				t.Fatalf("trust discovery executed host code before any apply:\n%s", ran)
			} else if !os.IsNotExist(err) {
				t.Fatal(err)
			}
		})
	}
}

func TestAudit9NpmEmptyCADoesNotRestoreDefaultRoots(t *testing.T) {
	if _, err := exec.LookPath("npm"); err != nil {
		if os.Getenv("CI") == "true" {
			t.Fatal("native npm is required in CI")
		}
		t.Skip("native npm is not installed")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	srv, caPEM, _ := caPlanServer(t)
	caFile := filepath.Join(home, "issuer.pem")
	configFile := filepath.Join(home, ".npmrc")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configFile, []byte("registry="+srv.URL+"/\nca=\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("npm", "config", "list", "--json", "--userconfig", configFile, "--globalconfig", filepath.Join(home, "global.npmrc"))
	cmd.Dir = t.TempDir()
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "NODE_EXTRA_CA_CERTS=" + caFile}
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var native struct {
		CA []string `json:"ca"`
	}
	if err := json.Unmarshal(out, &native); err != nil {
		t.Fatal(err)
	}
	if len(native.CA) != 1 || native.CA[0] != "" {
		t.Fatalf("native npm ca = %#v; want the explicitly empty CA string", native.CA)
	}
	ping := exec.Command("npm", "ping", "--userconfig", configFile, "--globalconfig", filepath.Join(home, "global.npmrc"), "--fetch-retries=0", "--fetch-timeout=3000")
	ping.Dir, ping.Env = cmd.Dir, cmd.Env
	controlFile := filepath.Join(home, "control.npmrc")
	if err := os.WriteFile(controlFile, []byte("registry="+srv.URL+"/\n"), 0600); err != nil {
		t.Fatal(err)
	}
	control := exec.Command("npm", "ping", "--userconfig", controlFile, "--globalconfig", filepath.Join(home, "global.npmrc"), "--fetch-retries=0", "--fetch-timeout=3000")
	control.Dir, control.Env = cmd.Dir, cmd.Env
	controlOut, controlErr := control.CombinedOutput()
	if controlErr == nil || !strings.Contains(string(controlOut), "E404") {
		t.Fatalf("without ca= npm did not complete TLS and reach the fixture's missing ping route: %v\n%s", controlErr, controlOut)
	}
	actual, err := ping.CombinedOutput()
	if err == nil || !strings.Contains(string(actual), "DEPTH_ZERO_SELF_SIGNED_CERT") {
		t.Fatalf("native npm did not reject the fixture certificate: %v\n%s", err, actual)
	}
	p := host.TrustProbe{Root: home, Home: home, GOOS: clientconf.OSLinux, Getenv: func(string) string { return "" }, Node: func() (host.NodeRoots, error) {
		return host.NodeRoots{PEM: []string{string(caPEM)}, Effective: true}, nil
	}}
	f := p.Apply([]host.Finding{{Check: "npm-config", Status: host.StatusOK}}, srv.URL)[0]
	if f.Status != host.StatusWarn || !strings.Contains(f.Remediation, "--ca-file") {
		t.Fatalf("native npm rejects the chain despite NODE_EXTRA_CA_CERTS, but doctor returned %+v", f)
	}
}

// F116 R2: a null ca resets npm's CA list to Node's defaults and an empty one
// replaces them, through each layer npm reads, and doctor's verdict follows
// what native npm does on the wire: with NODE_EXTRA_CA_CERTS naming the CA,
// npm completes TLS exactly where the effective ca is absent or null.
func TestNpmCALayersVerifyAsNpmDoes(t *testing.T) {
	nativeNpm(t)
	for name, tc := range map[string]struct {
		global, user string
		trusted      bool
	}{
		"no ca":                 {"", "", true},
		"null":                  {"", "ca=null\n", true},
		"null over empty":       {"ca=\n", "ca=null\n", true},
		"empty over null":       {"ca=null\n", "ca=\n", false},
		"empty list entry":      {"", "ca[]=\n", false},
		"empty in the global":   {"ca=\n", "", false},
		"null over a stray PEM": {"ca=not-a-certificate\n", `ca="null"` + "\n", true},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "home")
			t.Setenv("HOME", home)
			srv, caPEM, _ := caPlanServer(t)
			caFile := filepath.Join(root, "issuer.pem")
			global, user := filepath.Join(root, "etc/npmrc"), filepath.Join(home, ".npmrc")
			for path, content := range map[string]string{caFile: string(caPEM), global: tc.global, user: "registry=" + srv.URL + "/\n" + tc.user} {
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			ping := exec.Command("npm", "ping", "--userconfig", user, "--globalconfig", global, "--fetch-retries=0", "--fetch-timeout=3000")
			ping.Dir = t.TempDir()
			ping.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "NODE_EXTRA_CA_CERTS=" + caFile}
			out, _ := ping.CombinedOutput()
			// The fixture has no ping route, so a 404 is npm past the handshake.
			if reached := strings.Contains(string(out), "E404"); reached != tc.trusted {
				t.Fatalf("native npm completed TLS = %v, want %v:\n%s", reached, tc.trusted, out)
			}
			p := host.TrustProbe{Root: root, Home: home, GOOS: clientconf.OSLinux, Node: host.AskNode, Getenv: func(key string) string {
				if key == "NODE_EXTRA_CA_CERTS" {
					return caFile
				}
				return ""
			}}
			f := p.Apply([]host.Finding{{Check: "npm-config", Status: host.StatusOK}}, srv.URL)[0]
			if want := map[bool]host.Status{true: host.StatusOK, false: host.StatusWarn}[tc.trusted]; f.Status != want {
				t.Errorf("doctor = %s %q; native npm completed TLS = %v", f.Status, f.Detail, tc.trusted)
			}
			if !tc.trusted && (strings.Contains(f.Detail, "unchecked") || !strings.Contains(f.Remediation, "--ca-file")) {
				t.Errorf("an empty CA list is a refusal with the --ca-file remedy, not an unchecked row: %+v", f)
			}
		})
	}
}

func TestAudit10SystemInstallStillVerifiesServedChain(t *testing.T) {
	srv, _, _ := caPlanServer(t)
	prev := doctorTrustProbe
	t.Cleanup(func() { doctorTrustProbe = prev })
	for _, name := range []string{"wrong-host"} {
		t.Run(name, func(t *testing.T) {
			base := "https://wrong.example:443"
			doctorTrustProbe = func() host.TrustProbe {
				return host.TrustProbe{GOOS: clientconf.OSLinux,
					Getenv: func(k string) string {
						if k == "GOPROXY" {
							return base + "/go/"
						}
						return ""
					},
					Chain: func(string) ([]*x509.Certificate, error) { return []*x509.Certificate{srv.Certificate()}, nil },
					System: func(chain []*x509.Certificate, host string) error {
						pool := x509.NewCertPool()
						pool.AddCert(srv.Certificate())
						_, err := chain[0].Verify(x509.VerifyOptions{Roots: pool, DNSName: host})
						return err
					},
				}
			}
			control, err := doctorTrustProbe().Judge([]string{"goproxy-env"}, base)
			if err != nil || len(control) != 1 || control[0].State != host.TrustFailed {
				t.Fatalf("control = %+v, %v", control, err)
			}
			if err := unreadCA([]string{"goproxy-env"}, []string{manifest.TypeGomod}, base); err == nil {
				t.Fatalf("post-apply accepted %s after the same probe rejected it: %+v", name, control)
			}
		})
	}
}

func TestAudit11GomodApplyCannotPassOnShadowedEndpoint(t *testing.T) {
	home, root := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("GOENV", "")
	t.Setenv("GOPROXY", "https://proxy.golang.org,direct")
	srv, caPEM, _ := caPlanServer(t)
	caFile, release := filepath.Join(t.TempDir(), "ca.pem"), filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(release, []byte("ID=ubuntu\n"), 0600); err != nil {
		t.Fatal(err)
	}
	oldOS, oldRoot, oldRelease, oldRun := doctorCAGOOS, doctorOCIRoot, doctorOSRelease, doctorRun
	doctorCAGOOS, doctorOCIRoot, doctorOSRelease = clientconf.OSLinux, root, release
	doctorRun = func(string, ...string) error {
		data, err := os.ReadFile(filepath.Join(root, "usr/local/share/ca-certificates/bodega-ca.crt"))
		if err != nil {
			return err
		}
		bundle := filepath.Join(root, "etc/ssl/certs/ca-certificates.crt")
		if err := os.MkdirAll(filepath.Dir(bundle), 0755); err != nil {
			return err
		}
		return os.WriteFile(bundle, data, 0644)
	}
	t.Cleanup(func() { doctorCAGOOS, doctorOCIRoot, doctorOSRelease, doctorRun = oldOS, oldRoot, oldRelease, oldRun })
	for _, run := range []string{"first apply", "idle second apply"} {
		out, err := runDoctor(t, "--configure", "gomod", "--ca-file", caFile, "--url", srv.URL, "--apply")
		if err == nil {
			t.Errorf("%s succeeded although GOPROXY overrides the installed endpoint:\n%s", run, out)
		}
	}
}

func TestAudit12PipApplyCannotPassOnShadowedIndex(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	for _, k := range []string{"PIP_CONFIG_FILE", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_CERT", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "VIRTUAL_ENV"} {
		t.Setenv(k, "")
	}
	srv, caPEM, _ := caPlanServer(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(home, "etc", "pip.conf")
	if err := os.MkdirAll(filepath.Dir(conf), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(conf, []byte("[install]\nindex-url = https://pypi.org/simple\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"first apply", "idle second apply"} {
		out, err := runDoctor(t, "--configure", "pip", "--ca-file", caFile, "--url", srv.URL, "--apply")
		data, readErr := os.ReadFile(conf)
		if readErr != nil {
			t.Fatal(readErr)
		}
		vals := clientconf.PipOptions(data)
		effective, ok := vals["install.index-url"]
		if !ok {
			effective = vals["global.index-url"]
		}
		if err == nil && effective != srv.URL+"/pypi/simple/" {
			t.Errorf("%s certified pip although its install index is %s:\n%s", name, effective, out)
		}
	}
}

func TestAudit13PipOptionIdentityRefusesBeforeWritingOrInstalls(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	for _, key := range []string{"PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_CERT", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "VIRTUAL_ENV"} {
		t.Setenv(key, "")
	}
	srv, caPEM, _ := caPlanServer(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, "etc", "pip.conf")
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		t.Fatal(err)
	}
	old := "[global]\n--cert = /missing/company-ca.pem\nindex-url = https://pypi.org/simple/\n"
	if err := os.WriteFile(target, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PIP_CONFIG_FILE", target)
	out, err := runDoctor(t, "--configure", "pip", "--ca-file", caFile, "--url", srv.URL, "--apply")
	got, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if err != nil {
		if string(got) != old {
			t.Fatalf("apply changed pip.conf but left pip on its old --cert and failed: %v\n%s\nwritten file:\n%s", err, out, got)
		}
		if !strings.Contains(err.Error(), target) {
			t.Fatalf("refusal does not name %s: %v", target, err)
		}
		if _, statErr := os.Stat(filepath.Join(home, ".config", "bodega", "ca.pem")); !os.IsNotExist(statErr) {
			t.Fatalf("refusal wrote the CA: %v", statErr)
		}
		return
	}
	want := filepath.Join(home, ".config", "bodega", "ca.pem")
	if effective := clientconf.PipOptions(got)["global.cert"]; effective != want {
		t.Fatalf("apply succeeded with effective cert %s, want %s:\n%s", effective, want, got)
	}
}

func TestAudit14PipDuplicatesRefusedBeforeWrites(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	for _, location := range []string{"plan target", "selected extra file"} {
		t.Run(location, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
			for _, key := range []string{"PIP_CONFIG_FILE", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_CERT", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "VIRTUAL_ENV"} {
				t.Setenv(key, "")
			}
			srv, caPEM, _ := caPlanServer(t)
			caFile := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(home, "etc", "pip.conf")
			invalid := target
			if location == "selected extra file" {
				invalid = filepath.Join(home, "extra.conf")
			}
			if err := os.MkdirAll(filepath.Dir(invalid), 0700); err != nil {
				t.Fatal(err)
			}
			old := "[global]\ntimeout = 1\ntimeout = 2\n"
			if err := os.WriteFile(invalid, []byte(old), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PIP_CONFIG_FILE", invalid)
			cmd := exec.Command(python, "-m", "pip", "config", "list")
			cmd.Dir = t.TempDir()
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "PIP_CONFIG_FILE=" + invalid}
			native, nativeErr := cmd.CombinedOutput()
			if nativeErr == nil || !strings.Contains(string(native), "already exists") {
				t.Fatalf("oracle did not reject: %v: %s", nativeErr, native)
			}
			out, applyErr := runDoctor(t, "--configure", "pip", "--ca-file", caFile, "--url", srv.URL, "--apply")
			data, err := os.ReadFile(invalid)
			if err != nil {
				t.Fatal(err)
			}
			_, caErr := os.Stat(filepath.Join(home, ".config", "bodega", "ca.pem"))
			if applyErr == nil || !strings.Contains(applyErr.Error(), invalid) || string(data) != old || !os.IsNotExist(caErr) {
				t.Fatalf("native pip refuses:\n%s\napply error=%v, invalid file unchanged=%t, CA stat=%v\n%s", native, applyErr, string(data) == old, caErr, out)
			}
		})
	}
}

func TestAudit14PodmanApplyCannotPassOnHiddenSystemConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CONTAINERS_REGISTRIES_CONF", "")
	stubRuntimes(t, "podman")
	srv, caPEM, _ := caPlanServer(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	selected := filepath.Join(home, ".config", "containers", "registries.conf")
	if err := os.MkdirAll(filepath.Dir(selected), 0700); err != nil {
		t.Fatal(err)
	}
	old := "[[registry]]\nprefix = \"docker.io\"\nlocation = \"docker.io\"\n[[registry.mirror]]\nlocation = \"other.internal:5443\"\n"
	if err := os.WriteFile(selected, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	for _, run := range []string{"first apply", "idle second apply"} {
		out, err := runDoctor(t, "--configure", "oci", "--ca-file", caFile, "--url", srv.URL, "--apply")
		rows := (host.OCIHost{Root: home, Home: home, LookPath: doctorLookPath}).Check(srv.URL)
		if len(rows) != 1 {
			t.Fatalf("setup: %+v", rows)
		}
		if err == nil && rows[0].Status != host.StatusOK {
			t.Errorf("%s certified the install but podman's effective endpoint is still elsewhere: %+v\n%s", run, rows[0], out)
		}
	}
}

func TestAudit14CAInputTableNamesPodmanDiscovery(t *testing.T) {
	data, err := os.ReadFile("../../docs/usage.md")
	if err != nil {
		t.Fatal(err)
	}
	_, table, ok := strings.Cut(string(data), "Doctor installs and verifies through the inputs below")
	if !ok {
		t.Fatal("missing input boundary")
	}
	table, _, _ = strings.Cut(table, "An input outside this table")
	if !strings.Contains(table, "CONTAINERS_REGISTRIES_CONF") {
		t.Fatal("CA input boundary omits CONTAINERS_REGISTRIES_CONF, which the normal oci-podman row reads to discover its endpoint")
	}
}
