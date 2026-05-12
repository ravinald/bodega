package audit

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// DiscoveryRow is one upstream-fetch observation. Rows are deduplicated at
// insert time on (registry_type, pattern_hint, pkg_name, pkg_version, decision)
// — repeat requests bump request_count and update last_seen / last_client.
type DiscoveryRow struct {
	RegistryType string
	Host         string
	PatternHint  string // suggested promotion pattern (policy.SuggestPattern)
	PkgName      string
	PkgVersion   string
	Decision     string // allowed | denied | would_deny | no_policy
	UpstreamURL  string // full upstream URL bodega fetched (or would have); empty on rows recorded before migration 007
	FirstSeen    time.Time
	LastSeen     time.Time
	LastClient   string
	RequestCount int64
}

// DiscoveryFilter restricts which rows ListDiscovery / CountDiscovery return.
type DiscoveryFilter struct {
	RegistryType string    // empty = all
	PatternHint  string    // empty = all; exact match
	Decision     string    // empty = all
	Since        time.Time // zero = no lower bound on last_seen
	Limit        int       // 0 = default (1000)
}

// RecordDiscovery upserts an observation. Read-only handles are silently
// dropped (matches the existing Record behavior).
func (a *DB) RecordDiscovery(ctx context.Context, r DiscoveryRow) error {
	if a.readOnly {
		return nil
	}
	_, err := a.db.ExecContext(ctx,
		`INSERT INTO upstream_discovery
		   (registry_type, host, pattern_hint, pkg_name, pkg_version, decision, last_client, upstream_url)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(registry_type, pattern_hint, pkg_name, pkg_version, decision)
		 DO UPDATE SET
		   request_count = request_count + 1,
		   last_seen     = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
		   last_client   = excluded.last_client,
		   host          = excluded.host,
		   upstream_url  = CASE WHEN excluded.upstream_url = '' THEN upstream_discovery.upstream_url ELSE excluded.upstream_url END`,
		r.RegistryType, r.Host, r.PatternHint, r.PkgName, r.PkgVersion, r.Decision, r.LastClient, r.UpstreamURL,
	)
	return err
}

// ListDiscovery returns observations matching the filter, newest last_seen
// first. Default limit is 1000 when filter.Limit <= 0.
func (a *DB) ListDiscovery(ctx context.Context, f DiscoveryFilter) ([]DiscoveryRow, error) {
	var where []string
	var args []any

	if f.RegistryType != "" {
		where = append(where, "registry_type = ?")
		args = append(args, f.RegistryType)
	}
	if f.PatternHint != "" {
		where = append(where, "pattern_hint = ?")
		args = append(args, f.PatternHint)
	}
	if f.Decision != "" {
		where = append(where, "decision = ?")
		args = append(args, f.Decision)
	}
	if !f.Since.IsZero() {
		where = append(where, "last_seen >= ?")
		args = append(args, f.Since.UTC().Format(time.RFC3339Nano))
	}

	q := `SELECT registry_type, host, pattern_hint, pkg_name, pkg_version, decision,
	             upstream_url, first_seen, last_seen, last_client, request_count
	      FROM upstream_discovery`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY last_seen DESC"
	limit := f.Limit
	if limit <= 0 {
		limit = 1000
	}
	q += fmt.Sprintf(" LIMIT %d", limit)

	rows, err := a.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DiscoveryRow
	for rows.Next() {
		var r DiscoveryRow
		var firstSeen, lastSeen string
		if err := rows.Scan(&r.RegistryType, &r.Host, &r.PatternHint, &r.PkgName, &r.PkgVersion,
			&r.Decision, &r.UpstreamURL, &firstSeen, &lastSeen, &r.LastClient, &r.RequestCount); err != nil {
			return nil, err
		}
		r.FirstSeen, _ = time.Parse(time.RFC3339Nano, firstSeen)
		r.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeen)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan discovery: %w", err)
	}
	return out, nil
}

// DiscoveryAggregate is one (registry_type, pattern_hint) bucket, summed over
// every (pkg_name, pkg_version, decision) row that matched it. Used by
// `bodega discover list` — the bucket key is what `promote` will use.
type DiscoveryAggregate struct {
	RegistryType   string
	PatternHint    string
	Host           string
	RequestCount   int64
	FirstSeen      time.Time
	LastSeen       time.Time
	Decisions      string // comma-joined distinct decisions, e.g. "allowed,denied"
	SampleUpstream string // an example upstream URL from the bucket; empty if all rows pre-date migration 007
}

// AggregateDiscovery rolls observations into one row per (type, pattern_hint).
// Optional registryType filter ("" = all).
func (a *DB) AggregateDiscovery(ctx context.Context, registryType string) ([]DiscoveryAggregate, error) {
	var (
		rows *sql.Rows
		err  error
	)
	q := `SELECT registry_type, pattern_hint,
	             MAX(host)                       AS host,
	             SUM(request_count)              AS total,
	             MIN(first_seen)                 AS first_seen,
	             MAX(last_seen)                  AS last_seen,
	             GROUP_CONCAT(DISTINCT decision) AS decisions,
	             MAX(upstream_url)               AS sample_upstream
	      FROM upstream_discovery`
	if registryType != "" {
		q += " WHERE registry_type = ?"
		q += " GROUP BY registry_type, pattern_hint ORDER BY last_seen DESC"
		rows, err = a.db.QueryContext(ctx, q, registryType)
	} else {
		q += " GROUP BY registry_type, pattern_hint ORDER BY last_seen DESC"
		rows, err = a.db.QueryContext(ctx, q)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DiscoveryAggregate
	for rows.Next() {
		var a DiscoveryAggregate
		var firstSeen, lastSeen string
		var decisions, sampleUpstream sql.NullString
		if err := rows.Scan(&a.RegistryType, &a.PatternHint, &a.Host, &a.RequestCount,
			&firstSeen, &lastSeen, &decisions, &sampleUpstream); err != nil {
			return nil, err
		}
		a.FirstSeen, _ = time.Parse(time.RFC3339Nano, firstSeen)
		a.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeen)
		if decisions.Valid {
			a.Decisions = decisions.String
		}
		if sampleUpstream.Valid {
			a.SampleUpstream = sampleUpstream.String
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan discovery aggregate: %w", err)
	}
	return out, nil
}

// ClearDiscovery deletes rows for registryType. Empty = wipe table. Returns
// rows deleted.
func (a *DB) ClearDiscovery(ctx context.Context, registryType string) (int64, error) {
	var (
		res sql.Result
		err error
	)
	if registryType == "" {
		res, err = a.db.ExecContext(ctx, `DELETE FROM upstream_discovery`)
	} else {
		res, err = a.db.ExecContext(ctx,
			`DELETE FROM upstream_discovery WHERE registry_type = ?`, registryType)
	}
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// DiscoveryCount returns the row count for the given type ("" = all). Used by
// CLI guards ("no observations yet — is discover_mode set?").
func (a *DB) DiscoveryCount(ctx context.Context, registryType string) (int64, error) {
	var n int64
	var err error
	if registryType == "" {
		err = a.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM upstream_discovery`).Scan(&n)
	} else {
		err = a.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM upstream_discovery WHERE registry_type = ?`,
			registryType).Scan(&n)
	}
	return n, err
}
