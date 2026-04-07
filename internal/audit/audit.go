// Package audit provides a SQLite-backed audit trail for package operations.
// It records builds, client fetches, CRUD mutations, and proxy cache events.
package audit

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// EventType classifies an audit event.
type EventType string

const (
	EventFetch  EventType = "fetch"  // client downloaded a package
	EventBuild  EventType = "build"  // build pipeline completed
	EventCreate EventType = "create" // manifest entry created
	EventDelete EventType = "delete" // manifest entry deleted
	EventCache  EventType = "cache"  // proxy cache miss → upstream fetch
)

// Event is a single audit record.
type Event struct {
	EventType  EventType
	PkgType    string
	PkgName    string
	PkgVersion string
	ClientIP   string
	UserAgent  string
	Status     string // "success", "failure", "cache_hit", "cache_miss"
	DurationMs int64
	Details    string // JSON blob for extra context
}

// StoredEvent is an Event with its database ID and timestamp.
type StoredEvent struct {
	ID        int64
	Timestamp time.Time
	Event
}

// Filter controls which events are returned by Query.
type Filter struct {
	EventType  EventType // empty = all
	PkgType    string    // empty = all
	PkgName    string    // empty = all
	ClientIP   string    // empty = all
	Since      time.Time // zero = no lower bound
	Until      time.Time // zero = no upper bound
	Limit      int       // 0 = default (1000)
}

// DB is a SQLite audit database.
type DB struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    event_type  TEXT    NOT NULL,
    pkg_type    TEXT    NOT NULL,
    pkg_name    TEXT    NOT NULL,
    pkg_version TEXT    DEFAULT '',
    client_ip   TEXT    DEFAULT '',
    user_agent  TEXT    DEFAULT '',
    status      TEXT    DEFAULT '',
    duration_ms INTEGER DEFAULT 0,
    details     TEXT    DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_pkg ON events(pkg_type, pkg_name);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_client ON events(client_ip);

CREATE TABLE IF NOT EXISTS checksums (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    pkg_type    TEXT NOT NULL,
    pkg_name    TEXT NOT NULL,
    pkg_version TEXT NOT NULL DEFAULT '',
    s3_key      TEXT NOT NULL UNIQUE,
    algorithm   TEXT NOT NULL DEFAULT 'sha256',
    value       TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_checksums_pkg ON checksums(pkg_type, pkg_name);
`

// Open opens (or creates) the audit database at path and runs migrations.
func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open audit db %s: %w", path, err)
	}

	// Enable WAL mode for better concurrent read/write performance.
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate audit db: %w", err)
	}

	return &DB{db: db}, nil
}

// Close closes the database.
func (a *DB) Close() error {
	return a.db.Close()
}

// Record inserts an audit event.
func (a *DB) Record(ctx context.Context, ev Event) error {
	_, err := a.db.ExecContext(ctx,
		`INSERT INTO events (event_type, pkg_type, pkg_name, pkg_version, client_ip, user_agent, status, duration_ms, details)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		string(ev.EventType), ev.PkgType, ev.PkgName, ev.PkgVersion,
		ev.ClientIP, ev.UserAgent, ev.Status, ev.DurationMs, ev.Details,
	)
	return err
}

// Query returns events matching the filter, ordered by timestamp descending.
func (a *DB) Query(ctx context.Context, f Filter) ([]StoredEvent, error) {
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
	if !f.Since.IsZero() {
		where = append(where, "timestamp >= ?")
		args = append(args, f.Since.UTC().Format(time.RFC3339Nano))
	}
	if !f.Until.IsZero() {
		where = append(where, "timestamp <= ?")
		args = append(args, f.Until.UTC().Format(time.RFC3339Nano))
	}

	query := "SELECT id, timestamp, event_type, pkg_type, pkg_name, pkg_version, client_ip, user_agent, status, duration_ms, details FROM events"
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY timestamp DESC"

	limit := f.Limit
	if limit <= 0 {
		limit = 1000
	}
	query += fmt.Sprintf(" LIMIT %d", limit)

	rows, err := a.db.QueryContext(ctx, query, args...)
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
			&se.DurationMs, &se.Details)
		if err != nil {
			return nil, err
		}
		se.EventType = EventType(et)
		se.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		events = append(events, se)
	}
	return events, rows.Err()
}

// Count returns the total number of events matching the filter.
func (a *DB) Count(ctx context.Context, f Filter) (int64, error) {
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
		query += " WHERE " + strings.Join(where, " AND ")
	}

	var count int64
	err := a.db.QueryRowContext(ctx, query, args...).Scan(&count)
	return count, err
}

// StoredChecksum is a cached checksum record.
type StoredChecksum struct {
	ID         int64
	PkgType    string
	PkgName    string
	PkgVersion string
	S3Key      string
	Algorithm  string
	Value      string
	Source     string // "computed", "upstream", "manifest"
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// StoreChecksum inserts or updates a checksum record keyed by S3 key.
func (a *DB) StoreChecksum(ctx context.Context, s3Key, pkgType, pkgName, pkgVersion, algorithm, value, source string) error {
	_, err := a.db.ExecContext(ctx,
		`INSERT INTO checksums (s3_key, pkg_type, pkg_name, pkg_version, algorithm, value, source)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(s3_key) DO UPDATE SET
		   value = excluded.value,
		   algorithm = excluded.algorithm,
		   source = excluded.source,
		   updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`,
		s3Key, pkgType, pkgName, pkgVersion, algorithm, value, source,
	)
	return err
}

// GetChecksum returns the stored checksum for an S3 key, or nil if not found.
func (a *DB) GetChecksum(ctx context.Context, s3Key string) (*StoredChecksum, error) {
	var sc StoredChecksum
	var createdAt, updatedAt string
	err := a.db.QueryRowContext(ctx,
		`SELECT id, pkg_type, pkg_name, pkg_version, s3_key, algorithm, value, source, created_at, updated_at
		 FROM checksums WHERE s3_key = ?`, s3Key,
	).Scan(&sc.ID, &sc.PkgType, &sc.PkgName, &sc.PkgVersion, &sc.S3Key,
		&sc.Algorithm, &sc.Value, &sc.Source, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sc.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	sc.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	return &sc, nil
}

// ListChecksums returns all checksums matching the optional type and name filters.
func (a *DB) ListChecksums(ctx context.Context, pkgType, pkgName string) ([]StoredChecksum, error) {
	var where []string
	var args []interface{}

	if pkgType != "" {
		where = append(where, "pkg_type = ?")
		args = append(args, pkgType)
	}
	if pkgName != "" {
		where = append(where, "pkg_name = ?")
		args = append(args, pkgName)
	}

	query := "SELECT id, pkg_type, pkg_name, pkg_version, s3_key, algorithm, value, source, created_at, updated_at FROM checksums"
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY pkg_type, pkg_name, pkg_version"

	rows, err := a.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var checksums []StoredChecksum
	for rows.Next() {
		var sc StoredChecksum
		var createdAt, updatedAt string
		if err := rows.Scan(&sc.ID, &sc.PkgType, &sc.PkgName, &sc.PkgVersion, &sc.S3Key,
			&sc.Algorithm, &sc.Value, &sc.Source, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		sc.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		sc.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
		checksums = append(checksums, sc)
	}
	return checksums, rows.Err()
}

// ClearChecksum removes a stored checksum by S3 key.
func (a *DB) ClearChecksum(ctx context.Context, s3Key string) error {
	result, err := a.db.ExecContext(ctx, "DELETE FROM checksums WHERE s3_key = ?", s3Key)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("no checksum found for key %q", s3Key)
	}
	return nil
}

// ClearChecksumsByPackage removes all stored checksums for a package.
func (a *DB) ClearChecksumsByPackage(ctx context.Context, pkgType, pkgName string) error {
	_, err := a.db.ExecContext(ctx,
		"DELETE FROM checksums WHERE pkg_type = ? AND pkg_name = ?",
		pkgType, pkgName,
	)
	return err
}
