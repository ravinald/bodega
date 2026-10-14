package audit

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// IntegrationPolicy is one external check instance's action for one
// ecosystem. Absent means the integration type's default; see
// ErrIntegrationPolicyNotFound.
type IntegrationPolicy struct {
	Instance  string
	Ecosystem string
	Action    string
	Actor     string
	UpdatedAt time.Time
}

// ErrIntegrationPolicyNotFound means nobody set an action for the instance
// and ecosystem, which the check reads as its descriptor's default.
var ErrIntegrationPolicyNotFound = errors.New("integration policy not set for instance and ecosystem")

// IntegrationError is the last error an instance met.
type IntegrationError struct {
	Instance string
	Message  string
	At       time.Time
}

func (a *DB) SetIntegrationPolicy(ctx context.Context, p IntegrationPolicy) error {
	_, err := a.writer().ExecContext(ctx, `
		INSERT INTO integration_policy (instance, ecosystem, action, actor, updated_at)
		VALUES (?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
		ON CONFLICT(instance, ecosystem) DO UPDATE SET
			action     = excluded.action,
			actor      = excluded.actor,
			updated_at = excluded.updated_at
	`, p.Instance, p.Ecosystem, p.Action, p.Actor)
	return err
}

func (a *DB) GetIntegrationPolicy(ctx context.Context, instance, ecosystem string) (IntegrationPolicy, error) {
	var p IntegrationPolicy
	var ts string
	err := a.db.QueryRowContext(ctx,
		`SELECT instance, ecosystem, action, actor, updated_at FROM integration_policy WHERE instance = ? AND ecosystem = ?`,
		instance, ecosystem,
	).Scan(&p.Instance, &p.Ecosystem, &p.Action, &p.Actor, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrIntegrationPolicyNotFound
	}
	if err != nil {
		return p, err
	}
	p.UpdatedAt, _ = time.Parse(time.RFC3339Nano, ts)
	return p, nil
}

func (a *DB) ListIntegrationPolicies(ctx context.Context) ([]IntegrationPolicy, error) {
	rows, err := a.db.QueryContext(ctx,
		`SELECT instance, ecosystem, action, actor, updated_at FROM integration_policy ORDER BY instance, ecosystem`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IntegrationPolicy
	for rows.Next() {
		var p IntegrationPolicy
		var ts string
		if err := rows.Scan(&p.Instance, &p.Ecosystem, &p.Action, &p.Actor, &ts); err != nil {
			return nil, err
		}
		p.UpdatedAt, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, p)
	}
	return out, rows.Err()
}

// RecordIntegrationError replaces the instance's last error.
func (a *DB) RecordIntegrationError(ctx context.Context, instance, message string) error {
	_, err := a.writer().ExecContext(ctx, `
		INSERT INTO integration_errors (instance, message, at)
		VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
		ON CONFLICT(instance) DO UPDATE SET message = excluded.message, at = excluded.at
	`, instance, message)
	return err
}

// IntegrationErrors returns the last error of every instance that met one.
func (a *DB) IntegrationErrors(ctx context.Context) (map[string]IntegrationError, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT instance, message, at FROM integration_errors`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]IntegrationError{}
	for rows.Next() {
		var e IntegrationError
		var ts string
		if err := rows.Scan(&e.Instance, &e.Message, &ts); err != nil {
			return nil, err
		}
		e.At, _ = time.Parse(time.RFC3339Nano, ts)
		out[e.Instance] = e
	}
	return out, rows.Err()
}
