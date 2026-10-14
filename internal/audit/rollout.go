package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Admission modes: how an ecosystem decides which names it admits.
const (
	// ModeListed admits only a name an allow-list rule matches.
	ModeListed = "listed"
	// ModeOpen admits any name that passes every per-version gate.
	ModeOpen = "open"
)

// CheckBaseline is the status a check records when it failed on a version
// imported as baseline, which is admitted with the finding recorded rather
// than refused. It is never a pass: the finding is the debt the baseline
// carries until `bodega policy baseline clear` removes the mark.
const CheckBaseline = "baseline"

// AdmissionMode is the mode an operator set for one ecosystem.
type AdmissionMode struct {
	Ecosystem string
	Mode      string
	Actor     string
	UpdatedAt time.Time
}

// ErrAdmissionModeNotFound means nobody set a mode for the ecosystem, which
// the allow-list reads as listed when it has rules and open when it has none.
var ErrAdmissionModeNotFound = errors.New("admission mode not set for ecosystem")

func (a *DB) SetAdmissionMode(ctx context.Context, m AdmissionMode) error {
	_, err := a.writer().ExecContext(ctx, `
		INSERT INTO admission_mode (ecosystem, mode, actor, updated_at)
		VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
		ON CONFLICT(ecosystem) DO UPDATE SET
			mode       = excluded.mode,
			actor      = excluded.actor,
			updated_at = excluded.updated_at
	`, m.Ecosystem, m.Mode, m.Actor)
	return err
}

// GetAdmissionMode returns the mode set for ecosystem, or
// ErrAdmissionModeNotFound.
func (a *DB) GetAdmissionMode(ctx context.Context, ecosystem string) (AdmissionMode, error) {
	var m AdmissionMode
	var ts string
	err := a.db.QueryRowContext(ctx,
		`SELECT ecosystem, mode, actor, updated_at FROM admission_mode WHERE ecosystem = ?`, ecosystem,
	).Scan(&m.Ecosystem, &m.Mode, &m.Actor, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return m, ErrAdmissionModeNotFound
	}
	if err != nil {
		return m, err
	}
	m.UpdatedAt, _ = time.Parse(time.RFC3339Nano, ts)
	return m, nil
}

func (a *DB) ListAdmissionModes(ctx context.Context) ([]AdmissionMode, error) {
	rows, err := a.db.QueryContext(ctx,
		`SELECT ecosystem, mode, actor, updated_at FROM admission_mode ORDER BY ecosystem`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdmissionMode
	for rows.Next() {
		var m AdmissionMode
		var ts string
		if err := rows.Scan(&m.Ecosystem, &m.Mode, &m.Actor, &ts); err != nil {
			return nil, err
		}
		m.UpdatedAt, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, m)
	}
	return out, rows.Err()
}

// GateSwitch is one gate's action before and after a report or enforce
// switch. Before is what enforce writes back.
type GateSwitch struct {
	Gate   string `json:"gate"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// Rollout is an ecosystem in report mode, with the actions its gates had
// before the switch.
type Rollout struct {
	Ecosystem string
	Saved     []GateSwitch
	Actor     string
	UpdatedAt time.Time
}

// ErrRolloutNotFound means the ecosystem is not in report mode.
var ErrRolloutNotFound = errors.New("ecosystem is not in report mode")

func (a *DB) GetRollout(ctx context.Context, ecosystem string) (Rollout, error) {
	var r Rollout
	var saved, ts string
	err := a.db.QueryRowContext(ctx,
		`SELECT ecosystem, saved, actor, updated_at FROM policy_rollout WHERE ecosystem = ?`, ecosystem,
	).Scan(&r.Ecosystem, &saved, &r.Actor, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrRolloutNotFound
	}
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal([]byte(saved), &r.Saved); err != nil {
		return r, fmt.Errorf("decode saved gate actions for %s: %w", ecosystem, err)
	}
	r.UpdatedAt, _ = time.Parse(time.RFC3339Nano, ts)
	return r, nil
}

// SetRollout writes the ecosystem's gate switches and its age, OSV,
// provenance and similarity rows in one transaction, so a crash between them
// cannot leave gates on warn with no record of what they were. actions maps
// each gate to the action its row is set to; a gate absent from it is left
// alone. report true records r as the saved state; false deletes it.
func (a *DB) SetRollout(ctx context.Context, r Rollout, actions map[string]string, report bool) error {
	tx, err := a.writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	tables := map[string]string{
		CheckAge:                "age_policy",
		CheckOSV:                "osv_policy",
		CheckUpstreamProvenance: "upstream_provenance_policy",
		CheckNameSimilarity:     "name_similarity_policy",
	}
	for gate, action := range actions {
		table, ok := tables[gate]
		if !ok {
			return fmt.Errorf("no policy table for gate %q", gate)
		}
		//nolint:gosec // G202: the table name comes from the fixed map above; values are bound.
		if _, err := tx.ExecContext(ctx, `UPDATE `+table+` SET action = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE ecosystem = ?`,
			action, r.Ecosystem); err != nil {
			return fmt.Errorf("set %s action: %w", gate, err)
		}
	}
	if report {
		saved, err := json.Marshal(r.Saved)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO policy_rollout (ecosystem, saved, actor, updated_at)
			VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
			ON CONFLICT(ecosystem) DO UPDATE SET
				saved      = excluded.saved,
				actor      = excluded.actor,
				updated_at = excluded.updated_at
		`, r.Ecosystem, string(saved), r.Actor); err != nil {
			return err
		}
	} else if _, err := tx.ExecContext(ctx, `DELETE FROM policy_rollout WHERE ecosystem = ?`, r.Ecosystem); err != nil {
		return err
	}
	return tx.Commit()
}

// ListRollouts returns every ecosystem in report mode.
func (a *DB) ListRollouts(ctx context.Context) ([]Rollout, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT ecosystem, saved, actor, updated_at FROM policy_rollout ORDER BY ecosystem`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rollout
	for rows.Next() {
		var r Rollout
		var saved, ts string
		if err := rows.Scan(&r.Ecosystem, &saved, &r.Actor, &ts); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(saved), &r.Saved); err != nil {
			return nil, fmt.Errorf("decode saved gate actions for %s: %w", r.Ecosystem, err)
		}
		r.UpdatedAt, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, r)
	}
	return out, rows.Err()
}
