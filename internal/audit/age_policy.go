package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// AgePolicy: reject (or warn on) a version whose upstream publish time is
// newer than min_age_seconds ago. One row per ecosystem; absence means no
// gate for that ecosystem.
type AgePolicy struct {
	Ecosystem     string
	MinAgeSeconds int64
	Action        string // warn | block | ignore
	UpdatedAt     time.Time
}

// ErrAgePolicyNotFound is returned by GetAgePolicy when no row exists.
var ErrAgePolicyNotFound = errors.New("age policy not set for ecosystem")

func (a *DB) SetAgePolicy(ctx context.Context, p AgePolicy) error {
	_, err := a.db.ExecContext(ctx, `
		INSERT INTO age_policy (ecosystem, min_age_seconds, action, updated_at)
		VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
		ON CONFLICT(ecosystem) DO UPDATE SET
			min_age_seconds = excluded.min_age_seconds,
			action          = excluded.action,
			updated_at      = excluded.updated_at
	`, p.Ecosystem, p.MinAgeSeconds, p.Action)
	return err
}

func (a *DB) GetAgePolicy(ctx context.Context, ecosystem string) (AgePolicy, error) {
	var p AgePolicy
	var ts string
	err := a.db.QueryRowContext(ctx,
		`SELECT ecosystem, min_age_seconds, action, updated_at FROM age_policy WHERE ecosystem = ?`,
		ecosystem,
	).Scan(&p.Ecosystem, &p.MinAgeSeconds, &p.Action, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrAgePolicyNotFound
	}
	if err != nil {
		return p, err
	}
	p.UpdatedAt, _ = time.Parse(time.RFC3339Nano, ts)
	return p, nil
}

func (a *DB) ListAgePolicies(ctx context.Context) ([]AgePolicy, error) {
	rows, err := a.db.QueryContext(ctx,
		`SELECT ecosystem, min_age_seconds, action, updated_at FROM age_policy ORDER BY ecosystem`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgePolicy
	for rows.Next() {
		var p AgePolicy
		var ts string
		if err := rows.Scan(&p.Ecosystem, &p.MinAgeSeconds, &p.Action, &ts); err != nil {
			return nil, err
		}
		p.UpdatedAt, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, p)
	}
	return out, rows.Err()
}

func (a *DB) DeleteAgePolicy(ctx context.Context, ecosystem string) (bool, error) {
	res, err := a.db.ExecContext(ctx, `DELETE FROM age_policy WHERE ecosystem = ?`, ecosystem)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n > 1 {
		return false, fmt.Errorf("age_policy delete: unexpected row count %d", n)
	}
	return n == 1, nil
}
