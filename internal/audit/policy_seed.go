package audit

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ravinald/bodega/internal/manifest"
)

// policySeedVersion is migration 012, where policy_seeds started recording
// that a policy's default had been decided for this database.
const policySeedVersion = 12

// PolicySeedAge names the minimum-publish-age gate in policy_seeds.
const PolicySeedAge = "age"

// The posture a fresh install enforces: a one-week cooldown on npm and pypi,
// reporting rather than refusing.
//
// Seven days is the window the 2025-2026 npm and PyPI campaigns were caught
// in — the malicious versions were pulled within days of publication, so a
// fetch that waits a week gets the withdrawal instead of the payload.
// Checksum pinning does not reach this: it guarantees today's bytes match the
// first fetch, and a compromised first fetch is then served faithfully
// forever.
//
// The action is warn because a first install that refuses a build is an
// install that gets removed. Blocking is one command away and named in the
// startup banner.
const (
	DefaultAgeMinSeconds = 7 * 24 * 60 * 60
	DefaultAgeAction     = "warn"
)

// DefaultAgeEcosystems returns the ecosystems a fresh install gets an age gate
// on. Both have a reliable upstream publish timestamp and both are where the
// campaigns this default answers actually ran.
func DefaultAgeEcosystems() []string {
	return []string{manifest.TypeNpm, manifest.TypePypi}
}

// PolicySeeded reports whether this database has already been given (or
// deliberately denied) the shipped default for a policy. False means nobody
// has decided yet, which on the age gate is true only of an install that has
// never been opened by a binary carrying migration 012.
func (a *DB) PolicySeeded(ctx context.Context, policy string) (bool, error) {
	return policySeeded(ctx, a.db, policy)
}

func policySeeded(ctx context.Context, db *sql.DB, policy string) (bool, error) {
	var n int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM policy_seeds WHERE policy = ?`, policy).Scan(&n)
	return n > 0, err
}

// claimPolicySeed marks a policy decided without writing any rule behind it.
// The upgrade path calls it so an install that predates the default keeps
// enforcing exactly what it enforced yesterday.
func claimPolicySeed(ctx context.Context, db *sql.DB, policy string) error {
	_, err := db.ExecContext(ctx, `INSERT OR IGNORE INTO policy_seeds (policy) VALUES (?)`, policy)
	return err
}

// seedDefaultAgePolicy writes the shipped minimum publish age and returns the
// ecosystems it wrote, or nothing at all when the age gate has already been
// decided here. The marker and the rows land in one transaction: a marker with
// half a policy behind it is a posture nobody chose.
func seedDefaultAgePolicy(ctx context.Context, db *sql.DB) ([]string, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO policy_seeds (policy) VALUES (?)`, PolicySeedAge)
	if err != nil {
		return nil, err
	}
	claimed, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if claimed == 0 {
		return nil, nil // already decided; whatever age_policy holds is the operator's
	}

	seeded := DefaultAgeEcosystems()
	for _, eco := range seeded {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO age_policy (ecosystem, min_age_seconds, action) VALUES (?, ?, ?)`,
			eco, DefaultAgeMinSeconds, DefaultAgeAction,
		); err != nil {
			return nil, fmt.Errorf("seed age policy for %s: %w", eco, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return seeded, nil
}
