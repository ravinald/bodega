package audit

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// sqliteSink writes the event stream into the same file the operational state
// lives in. It shares that handle rather than opening the database twice: two
// *sql.DB pools on one file are two sets of connections contending for the
// same write lock, which is the loss busyTimeout exists to stop.
type sqliteSink struct {
	db       *sql.DB
	readOnly bool
}

func (s *sqliteSink) Name() string { return SinkSQLite }

// Close is a no-op: the handle belongs to *DB, which closes it.
func (s *sqliteSink) Close() error { return nil }

func (s *sqliteSink) Record(ctx context.Context, ev Event) error {
	if s.readOnly {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO events (event_type, pkg_type, pkg_name, pkg_version, client_ip, user_agent, status, duration_ms, details, actor)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		string(ev.EventType), ev.PkgType, ev.PkgName, ev.PkgVersion,
		ev.ClientIP, ev.UserAgent, ev.Status, ev.DurationMs, ev.Details, ev.Actor,
	)
	return err
}

func (s *sqliteSink) RecordDiscovery(ctx context.Context, r DiscoveryRow) error {
	if s.readOnly {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO upstream_discovery
		   (registry_type, host, pattern_hint, pkg_name, pkg_version, decision, last_client, upstream_url)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(registry_type, pattern_hint, pkg_name, pkg_version, decision)
		 DO UPDATE SET
		   request_count = request_count + 1,
		   last_seen     = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
		   last_client   = excluded.last_client,
		   host          = CASE WHEN excluded.host = '' THEN upstream_discovery.host ELSE excluded.host END,
		   upstream_url  = CASE WHEN excluded.upstream_url = '' THEN upstream_discovery.upstream_url ELSE excluded.upstream_url END`,
		r.RegistryType, r.Host, r.PatternHint, r.PkgName, r.PkgVersion, r.Decision, r.LastClient, r.UpstreamURL,
	)
	return err
}

func (s *sqliteSink) QueryEvents(ctx context.Context, f Filter) ([]StoredEvent, error) {
	var where []string
	var args []interface{}

	if f.EventType != "" {
		where = append(where, "event_type = ?")
		args = append(args, string(f.EventType))
	}
	if f.PkgType != "" {
		where = append(where, "pkg_type = ?")
		args = append(args, f.PkgType)
	}
	if f.PkgName != "" {
		where = append(where, "pkg_name = ?")
		args = append(args, f.PkgName)
	}
	if f.ClientIP != "" {
		where = append(where, "client_ip = ?")
		args = append(args, f.ClientIP)
	}
	if f.Actor != "" {
		where = append(where, "actor = ?")
		args = append(args, f.Actor)
	}
	if !f.Since.IsZero() {
		where = append(where, "timestamp >= ?")
		args = append(args, f.Since.UTC().Format(time.RFC3339Nano))
	}
	if !f.Until.IsZero() {
		where = append(where, "timestamp <= ?")
		args = append(args, f.Until.UTC().Format(time.RFC3339Nano))
	}

	query := "SELECT id, timestamp, event_type, pkg_type, pkg_name, pkg_version, client_ip, user_agent, status, duration_ms, details, actor FROM events"
	if len(where) > 0 {
		//nolint:gosec // G202: WHERE clause assembled from a fixed slice of internal predicates; values are bound via ? parameters in `args`.
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY timestamp DESC"
	//nolint:gosec // G202: LIMIT clause built from a clamped int literal, no user-controlled string interpolation.
	query += fmt.Sprintf(" LIMIT %d", effectiveLimit(f.Limit))

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []StoredEvent
	for rows.Next() {
		var se StoredEvent
		var ts string
		var et string
		err := rows.Scan(&se.ID, &ts, &et,
			&se.PkgType, &se.PkgName, &se.PkgVersion,
			&se.ClientIP, &se.UserAgent, &se.Status,
			&se.DurationMs, &se.Details, &se.Actor)
		if err != nil {
			return nil, err
		}
		se.EventType = EventType(et)
		se.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		events = append(events, se)
	}
	return events, rows.Err()
}

func (s *sqliteSink) CountEvents(ctx context.Context, f Filter) (int64, error) {
	var where []string
	var args []interface{}

	if f.EventType != "" {
		where = append(where, "event_type = ?")
		args = append(args, string(f.EventType))
	}
	if f.PkgType != "" {
		where = append(where, "pkg_type = ?")
		args = append(args, f.PkgType)
	}

	query := "SELECT COUNT(*) FROM events"
	if len(where) > 0 {
		//nolint:gosec // G202: WHERE clause assembled from a fixed slice of internal predicates; values are bound via ? parameters in `args`.
		query += " WHERE " + strings.Join(where, " AND ")
	}

	var count int64
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&count)
	return count, err
}

func (s *sqliteSink) ListDiscovery(ctx context.Context, f DiscoveryFilter) ([]DiscoveryRow, error) {
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
		//nolint:gosec // G202: WHERE clause assembled from a fixed slice of internal predicates; values are bound via ? parameters in `args`.
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY last_seen DESC"
	//nolint:gosec // G202: LIMIT clause built from a clamped int literal, no user-controlled string interpolation.
	q += fmt.Sprintf(" LIMIT %d", effectiveLimit(f.Limit))

	rows, err := s.db.QueryContext(ctx, q, args...)
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

func (s *sqliteSink) AggregateDiscovery(ctx context.Context, registryType string) ([]DiscoveryAggregate, error) {
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
		rows, err = s.db.QueryContext(ctx, q, registryType)
	} else {
		q += " GROUP BY registry_type, pattern_hint ORDER BY last_seen DESC"
		rows, err = s.db.QueryContext(ctx, q)
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

func (s *sqliteSink) ClearDiscovery(ctx context.Context, registryType string) (int64, error) {
	var (
		res sql.Result
		err error
	)
	if registryType == "" {
		res, err = s.db.ExecContext(ctx, `DELETE FROM upstream_discovery`)
	} else {
		res, err = s.db.ExecContext(ctx,
			`DELETE FROM upstream_discovery WHERE registry_type = ?`, registryType)
	}
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func (s *sqliteSink) DiscoveryCount(ctx context.Context, registryType string) (int64, error) {
	var n int64
	var err error
	if registryType == "" {
		err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM upstream_discovery`).Scan(&n)
	} else {
		err = s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM upstream_discovery WHERE registry_type = ?`,
			registryType).Scan(&n)
	}
	return n, err
}

// effectiveLimit clamps a filter's row cap. Every queryable sink applies the
// same default, so a query answered by postgres returns the same page size as
// the one answered by SQLite.
func effectiveLimit(limit int) int {
	if limit <= 0 {
		return 1000
	}
	return limit
}
