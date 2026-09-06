package audit

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

// migrateTo brings a fresh database file to one schema version and hands back
// its path, closing the handle so Open can take the file cleanly. It is how a
// test reproduces an install that predates a migration.
func migrateTo(t *testing.T, version uint) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := migrator(t, raw).Migrate(version); err != nil {
		t.Fatalf("migrate to %d: %v", version, err)
	}
	if _, err := raw.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw: %v", err)
	}
	return path
}

func agePolicyMap(t *testing.T, db *DB) map[string]AgePolicy {
	t.Helper()
	rows, err := db.ListAgePolicies(context.Background())
	if err != nil {
		t.Fatalf("list age policies: %v", err)
	}
	out := make(map[string]AgePolicy, len(rows))
	for _, p := range rows {
		out[p.Ecosystem] = p
	}
	return out
}

// TestFreshInstallGetsTheDefaultAgePolicy is the posture a new install ships
// with: a cooldown on the two ecosystems the campaigns ran in, reporting
// rather than refusing.
func TestFreshInstallGetsTheDefaultAgePolicy(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	got := agePolicyMap(t, db)
	if len(got) != len(DefaultAgeEcosystems()) {
		t.Fatalf("age policies = %v, want exactly %v", got, DefaultAgeEcosystems())
	}
	for _, eco := range DefaultAgeEcosystems() {
		p, ok := got[eco]
		if !ok {
			t.Fatalf("no age policy seeded for %s: %v", eco, got)
		}
		if p.MinAgeSeconds != DefaultAgeMinSeconds || p.Action != DefaultAgeAction {
			t.Errorf("%s seeded as %ds/%s, want %ds/%s",
				eco, p.MinAgeSeconds, p.Action, DefaultAgeMinSeconds, DefaultAgeAction)
		}
	}

	seeded, err := db.PolicySeeded(context.Background(), PolicySeedAge)
	if err != nil {
		t.Fatalf("policy seeded: %v", err)
	}
	if !seeded {
		t.Error("fresh install seeded rows without claiming the marker; the next open would seed again")
	}
}

// TestUpgradeWithExistingPolicyIsUntouched covers the fleet already running an
// age gate. Its rows are the operator's, including an ecosystem the default
// does not name and an action the default would not choose.
func TestUpgradeWithExistingPolicyIsUntouched(t *testing.T) {
	path := migrateTo(t, policySeedVersion-1)

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("reopen raw: %v", err)
	}
	if _, err := raw.Exec(
		`INSERT INTO age_policy (ecosystem, min_age_seconds, action) VALUES ('npm', 3600, 'block'), ('gomod', 86400, 'warn')`,
	); err != nil {
		t.Fatalf("seed pre-upgrade rows: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw: %v", err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	got := agePolicyMap(t, db)
	if len(got) != 2 {
		t.Fatalf("upgrade changed the policy set: got %v, want npm and gomod only", got)
	}
	if p := got["npm"]; p.MinAgeSeconds != 3600 || p.Action != "block" {
		t.Errorf("npm rewritten to %ds/%s, want the operator's 3600s/block", p.MinAgeSeconds, p.Action)
	}
	if _, ok := got["pypi"]; ok {
		t.Error("upgrade added a pypi gate the operator never configured")
	}
}

// TestUpgradeWithNoPolicyStaysEmpty is the failure the marker exists to
// prevent: an install with no age rows at all reads identically to a fresh
// one, and seeding it changes what a running fleet enforces.
func TestUpgradeWithNoPolicyStaysEmpty(t *testing.T) {
	db, err := Open(migrateTo(t, policySeedVersion-1))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	if got := agePolicyMap(t, db); len(got) != 0 {
		t.Fatalf("upgrade seeded %v onto an install that enforced nothing", got)
	}
	seeded, err := db.PolicySeeded(context.Background(), PolicySeedAge)
	if err != nil {
		t.Fatalf("policy seeded: %v", err)
	}
	if !seeded {
		t.Error("upgrade left the marker unclaimed; the next open would seed the fleet")
	}
}

// TestEmptyPolicySetSurvivesRestart is the acl_lists distinction applied here:
// an operator who removed every row said "no gate", and absent must keep
// meaning something different from empty across the restart that follows.
func TestEmptyPolicySetSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()
	for _, eco := range DefaultAgeEcosystems() {
		deleted, err := db.DeleteAgePolicy(ctx, eco)
		if err != nil {
			t.Fatalf("delete %s: %v", eco, err)
		}
		if !deleted {
			t.Fatalf("no seeded row to delete for %s", eco)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	again, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer again.Close()
	if got := agePolicyMap(t, again); len(got) != 0 {
		t.Fatalf("restart re-seeded %v over an operator who cleared the table", got)
	}
}
