package audit

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// PolicyInfo is an upstream allow-list rule. The policy package defines the
// matching semantics; this package just persists the rows.
type PolicyInfo struct {
	ID           string
	RegistryType string
	RuleKind     string
	Pattern      string
	Comment      string
	CreatedAt    time.Time
	CreatedBy    string // token label if added via API, else CLI actor
}

// InsertPolicy stores a new allow-list rule. Returns an error (including
// SQLite UNIQUE constraint violation) if a rule with the same type+kind+
// pattern already exists.
func (a *DB) InsertPolicy(ctx context.Context, p PolicyInfo) error {
	_, err := a.db.ExecContext(ctx,
		`INSERT INTO upstream_policies (id, registry_type, rule_kind, pattern, comment, created_by)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		p.ID, p.RegistryType, p.RuleKind, p.Pattern, p.Comment, p.CreatedBy,
	)
	return err
}

// ListPolicies returns every rule ordered by registry type, then pattern.
func (a *DB) ListPolicies(ctx context.Context) ([]PolicyInfo, error) {
	rows, err := a.db.QueryContext(ctx,
		`SELECT id, registry_type, rule_kind, pattern, comment, created_at, created_by
		 FROM upstream_policies
		 ORDER BY registry_type, pattern`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanPolicies(rows)
}

// GetPoliciesByType returns every rule for a single registry type. The policy
// Checker uses this to build per-type matcher lists.
func (a *DB) GetPoliciesByType(ctx context.Context, registryType string) ([]PolicyInfo, error) {
	rows, err := a.db.QueryContext(ctx,
		`SELECT id, registry_type, rule_kind, pattern, comment, created_at, created_by
		 FROM upstream_policies
		 WHERE registry_type = ?
		 ORDER BY pattern`,
		registryType,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanPolicies(rows)
}

// DeletePolicyByID removes a rule by its UUID. Returns (true, nil) when a row
// was actually deleted.
func (a *DB) DeletePolicyByID(ctx context.Context, id string) (bool, error) {
	res, err := a.db.ExecContext(ctx, `DELETE FROM upstream_policies WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// DeletePolicyByPattern removes rules matching (registryType, pattern). When
// registryType is empty, matches all types. Returns the number of rows
// deleted.
func (a *DB) DeletePolicyByPattern(ctx context.Context, registryType, pattern string) (int64, error) {
	var (
		res sql.Result
		err error
	)
	if registryType == "" {
		res, err = a.db.ExecContext(ctx, `DELETE FROM upstream_policies WHERE pattern = ?`, pattern)
	} else {
		res, err = a.db.ExecContext(ctx,
			`DELETE FROM upstream_policies WHERE registry_type = ? AND pattern = ?`,
			registryType, pattern,
		)
	}
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// PolicyCount returns the total rule count across all types. Useful for the
// "enforcement active?" summary in status output.
func (a *DB) PolicyCount(ctx context.Context) (int, error) {
	var n int
	err := a.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM upstream_policies`).Scan(&n)
	return n, err
}

func scanPolicies(rows *sql.Rows) ([]PolicyInfo, error) {
	var out []PolicyInfo
	for rows.Next() {
		var p PolicyInfo
		var created string
		var comment, createdBy sql.NullString
		if err := rows.Scan(&p.ID, &p.RegistryType, &p.RuleKind, &p.Pattern,
			&comment, &created, &createdBy); err != nil {
			return nil, err
		}
		if comment.Valid {
			p.Comment = comment.String
		}
		if createdBy.Valid {
			p.CreatedBy = createdBy.String
		}
		if parsed, err := time.Parse(time.RFC3339Nano, created); err == nil {
			p.CreatedAt = parsed
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan policies: %w", err)
	}
	return out, nil
}
