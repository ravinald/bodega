package audit

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// IndexFilter records whether one ecosystem's proxied indexes omit the
// versions its age and OSV gates would refuse.
type IndexFilter struct {
	Ecosystem string
	Enabled   bool
	UpdatedAt time.Time
}

func (a *DB) SetIndexFilter(ctx context.Context, f IndexFilter) error {
	_, err := a.writer().ExecContext(ctx, `
		INSERT INTO index_filter (ecosystem, enabled, updated_at)
		VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
		ON CONFLICT(ecosystem) DO UPDATE SET
			enabled    = excluded.enabled,
			updated_at = excluded.updated_at
	`, f.Ecosystem, f.Enabled)
	return err
}

// IndexFilterEnabled reports whether the filter is on for ecosystem. No row
// is off.
func (a *DB) IndexFilterEnabled(ctx context.Context, ecosystem string) (bool, error) {
	var enabled bool
	err := a.db.QueryRowContext(ctx,
		`SELECT enabled FROM index_filter WHERE ecosystem = ?`, ecosystem).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return enabled, err
}

func (a *DB) ListIndexFilters(ctx context.Context) ([]IndexFilter, error) {
	rows, err := a.db.QueryContext(ctx,
		`SELECT ecosystem, enabled, updated_at FROM index_filter ORDER BY ecosystem`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IndexFilter
	for rows.Next() {
		var f IndexFilter
		var ts string
		if err := rows.Scan(&f.Ecosystem, &f.Enabled, &ts); err != nil {
			return nil, err
		}
		f.UpdatedAt, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, f)
	}
	return out, rows.Err()
}
