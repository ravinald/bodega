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
	_, err := a.writer().ExecContext(ctx, `
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
	res, err := a.writer().ExecContext(ctx, `DELETE FROM osv_policy WHERE ecosystem = ?`, ecosystem)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// OSVMalwarePolicy is the action for OSV records that mark a package as
// malicious rather than vulnerable. Absent means block; see
// ErrOSVMalwarePolicyNotFound.
type OSVMalwarePolicy struct {
	Ecosystem string
	Action    string
	Reason    string
	Actor     string
	UpdatedAt time.Time
}

// ErrOSVMalwarePolicyNotFound means nobody set an action for the ecosystem,
// which the gate reads as block. It is an error rather than a zero value so a
// caller cannot mistake "unset" for an empty action.
var ErrOSVMalwarePolicyNotFound = errors.New("osv malware policy not set for ecosystem")

func (a *DB) SetOSVMalwarePolicy(ctx context.Context, p OSVMalwarePolicy) error {
	_, err := a.writer().ExecContext(ctx, `
		INSERT INTO osv_malware_policy (ecosystem, action, reason, actor, updated_at)
		VALUES (?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
		ON CONFLICT(ecosystem) DO UPDATE SET
			action     = excluded.action,
			reason     = excluded.reason,
			actor      = excluded.actor,
			updated_at = excluded.updated_at
	`, p.Ecosystem, p.Action, p.Reason, p.Actor)
	return err
}

func (a *DB) GetOSVMalwarePolicy(ctx context.Context, ecosystem string) (OSVMalwarePolicy, error) {
	var p OSVMalwarePolicy
	var ts string
	err := a.db.QueryRowContext(ctx,
		`SELECT ecosystem, action, reason, actor, updated_at FROM osv_malware_policy WHERE ecosystem = ?`,
		ecosystem,
	).Scan(&p.Ecosystem, &p.Action, &p.Reason, &p.Actor, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrOSVMalwarePolicyNotFound
	}
	if err != nil {
		return p, err
	}
	p.UpdatedAt, _ = time.Parse(time.RFC3339Nano, ts)
	return p, nil
}

func (a *DB) ListOSVMalwarePolicies(ctx context.Context) ([]OSVMalwarePolicy, error) {
	rows, err := a.db.QueryContext(ctx,
		`SELECT ecosystem, action, reason, actor, updated_at FROM osv_malware_policy ORDER BY ecosystem`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OSVMalwarePolicy
	for rows.Next() {
		var p OSVMalwarePolicy
		var ts string
		if err := rows.Scan(&p.Ecosystem, &p.Action, &p.Reason, &p.Actor, &ts); err != nil {
			return nil, err
		}
		p.UpdatedAt, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, p)
	}
	return out, rows.Err()
}
