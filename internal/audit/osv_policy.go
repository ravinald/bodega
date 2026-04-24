package audit

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type OSVPolicy struct {
	Ecosystem string
	Action    string
	UpdatedAt time.Time
}

var ErrOSVPolicyNotFound = errors.New("osv policy not set for ecosystem")

func (a *DB) SetOSVPolicy(ctx context.Context, p OSVPolicy) error {
	_, err := a.db.ExecContext(ctx, `
		INSERT INTO osv_policy (ecosystem, action, updated_at)
		VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
		ON CONFLICT(ecosystem) DO UPDATE SET
			action     = excluded.action,
			updated_at = excluded.updated_at
	`, p.Ecosystem, p.Action)
	return err
}

func (a *DB) GetOSVPolicy(ctx context.Context, ecosystem string) (OSVPolicy, error) {
	var p OSVPolicy
	var ts string
	err := a.db.QueryRowContext(ctx,
		`SELECT ecosystem, action, updated_at FROM osv_policy WHERE ecosystem = ?`,
		ecosystem,
	).Scan(&p.Ecosystem, &p.Action, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrOSVPolicyNotFound
	}
	if err != nil {
		return p, err
	}
	p.UpdatedAt, _ = time.Parse(time.RFC3339Nano, ts)
	return p, nil
}

func (a *DB) ListOSVPolicies(ctx context.Context) ([]OSVPolicy, error) {
	rows, err := a.db.QueryContext(ctx,
		`SELECT ecosystem, action, updated_at FROM osv_policy ORDER BY ecosystem`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OSVPolicy
	for rows.Next() {
		var p OSVPolicy
		var ts string
		if err := rows.Scan(&p.Ecosystem, &p.Action, &ts); err != nil {
			return nil, err
		}
		p.UpdatedAt, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, p)
	}
	return out, rows.Err()
}

func (a *DB) DeleteOSVPolicy(ctx context.Context, ecosystem string) (bool, error) {
	res, err := a.db.ExecContext(ctx, `DELETE FROM osv_policy WHERE ecosystem = ?`, ecosystem)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
