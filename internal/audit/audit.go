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
	// Admin/operator events (CLI commands).
	EventInit    EventType = "init"    // bodega init
	EventReset   EventType = "reset"   // bodega reset
	EventStatus  EventType = "status"  // bodega status
	EventFetch   EventType = "fetch"   // bodega build fetch (per entry)
	EventBuild   EventType = "build"   // bodega build run (per entry)
	EventPackage EventType = "package" // bodega build package (per entry)
	EventUpload  EventType = "upload"  // bodega build upload (per entry)
	EventSync    EventType = "sync"    // bodega build sync (per entry)
	EventCreate  EventType = "create"  // bodega create
	EventDelete  EventType = "delete"  // bodega delete
	EventRepair  EventType = "repair"  // bodega repair
	EventRefresh EventType = "refresh" // bodega refresh
	EventHide    EventType = "hide"    // bodega hide
	EventFreeze  EventType = "freeze"  // bodega freeze
	EventEdit    EventType = "edit"    // bodega pkg edit / TUI edit — free-form manifest change
	EventShow    EventType = "show"    // bodega show

	// Server lifecycle events.
	EventServeStart EventType = "serve_start" // bodega serve started
	EventServeStop  EventType = "serve_stop"  // bodega serve shut down

	// Client events (HTTP server).
	EventServeFetch EventType = "serve_fetch" // client downloaded a package via HTTP
	EventCache      EventType = "cache"       // proxy cache miss
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
	Actor      string // OS user for CLI/TUI events; empty for HTTP events (use ClientIP instead)
}

// StoredEvent is an Event with its database ID and timestamp.
type StoredEvent struct {
	ID        int64
	Timestamp time.Time
	Event
}

// Filter controls which events are returned by Query.
type Filter struct {
	EventType EventType // empty = all
	PkgType   string    // empty = all
	PkgName   string    // empty = all
	ClientIP  string    // empty = all
	Actor     string    // empty = all
	Since     time.Time // zero = no lower bound
	Until     time.Time // zero = no upper bound
	Limit     int       // 0 = default (1000)
}

// DB is a SQLite audit database.
type DB struct {
	db       *sql.DB
	filter   map[string]bool // nil = record all; otherwise only listed types
	location *time.Location  // display timezone (storage is always UTC)
}

// SetEventFilter restricts which event types are recorded. Pass nil or empty
// to record all events. Events not in the filter are silently dropped.
func (a *DB) SetEventFilter(allowed []string) {
	if len(allowed) == 0 {
		a.filter = nil
		return
	}
	a.filter = make(map[string]bool, len(allowed))
	for _, t := range allowed {
		a.filter[t] = true
	}
}

// ShouldRecord returns true if the given event type passes the filter.
func (a *DB) ShouldRecord(evType EventType) bool {
	if a.filter == nil {
		return true
	}
	return a.filter[string(evType)]
}

// SetTimezone sets the display timezone for query results. Stored timestamps
// are always UTC; this only affects how they're presented.
func (a *DB) SetTimezone(tz string) {
	if tz == "" {
		a.location = time.UTC
		return
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		a.location = time.UTC
		return
	}
	a.location = loc
}

// DisplayLocation returns the configured display timezone, defaulting to UTC.
func (a *DB) DisplayLocation() *time.Location {
	if a.location == nil {
		return time.UTC
	}
	return a.location
}

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

	if err := runMigrations(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate audit db: %w", err)
	}

	return &DB{db: db}, nil
}

// Close closes the database.
func (a *DB) Close() error {
	return a.db.Close()
}

// Record inserts an audit event. Events that don't pass the configured
// filter are silently dropped.
func (a *DB) Record(ctx context.Context, ev Event) error {
	if !a.ShouldRecord(ev.EventType) {
		return nil
	}
	_, err := a.db.ExecContext(ctx,
		`INSERT INTO events (event_type, pkg_type, pkg_name, pkg_version, client_ip, user_agent, status, duration_ms, details, actor)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		string(ev.EventType), ev.PkgType, ev.PkgName, ev.PkgVersion,
		ev.ClientIP, ev.UserAgent, ev.Status, ev.DurationMs, ev.Details, ev.Actor,
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
			&se.DurationMs, &se.Details, &se.Actor)
		if err != nil {
			return nil, err
		}
		se.EventType = EventType(et)
		se.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		if a.location != nil {
			se.Timestamp = se.Timestamp.In(a.location)
		}
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

// ---- API Token Management ---------------------------------------------------

// TokenInfo holds non-sensitive metadata about an API token.
type TokenInfo struct {
	ID        string
	Label     string
	Comment   string
	CreatedAt time.Time
	ExpiresAt *time.Time // nil = never expires
	LastUsed  *time.Time // nil = never used
}

// TokenHash holds the hash and expiry for auth verification.
type TokenHash struct {
	ID        string
	Hash      string
	ExpiresAt *time.Time
}

// InsertToken stores a new hashed API token.
func (a *DB) InsertToken(ctx context.Context, id, label, hash, comment string, expiresAt *time.Time) error {
	var exp sql.NullString
	if expiresAt != nil {
		exp = sql.NullString{String: expiresAt.UTC().Format(time.RFC3339), Valid: true}
	}
	_, err := a.db.ExecContext(ctx,
		"INSERT INTO api_tokens (id, label, hash, comment, expires_at) VALUES (?, ?, ?, ?, ?)",
		id, label, hash, comment, exp,
	)
	return err
}

// ListTokens returns metadata for all tokens (never the hash).
func (a *DB) ListTokens(ctx context.Context) ([]TokenInfo, error) {
	rows, err := a.db.QueryContext(ctx,
		"SELECT id, label, comment, created_at, expires_at, last_used FROM api_tokens ORDER BY created_at DESC",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []TokenInfo
	for rows.Next() {
		var t TokenInfo
		var created, expires, lastUsed sql.NullString
		if err := rows.Scan(&t.ID, &t.Label, &t.Comment, &created, &expires, &lastUsed); err != nil {
			return nil, err
		}
		if created.Valid {
			if parsed, err := time.Parse(time.RFC3339Nano, created.String); err == nil {
				t.CreatedAt = parsed
			}
		}
		if expires.Valid {
			if parsed, err := time.Parse(time.RFC3339, expires.String); err == nil {
				t.ExpiresAt = &parsed
			}
		}
		if lastUsed.Valid {
			if parsed, err := time.Parse(time.RFC3339, lastUsed.String); err == nil {
				t.LastUsed = &parsed
			}
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// GetTokenHashes returns all token hashes for auth verification.
func (a *DB) GetTokenHashes(ctx context.Context) ([]TokenHash, error) {
	rows, err := a.db.QueryContext(ctx,
		"SELECT id, hash, expires_at FROM api_tokens",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hashes []TokenHash
	for rows.Next() {
		var h TokenHash
		var expires sql.NullString
		if err := rows.Scan(&h.ID, &h.Hash, &expires); err != nil {
			return nil, err
		}
		if expires.Valid {
			if parsed, err := time.Parse(time.RFC3339, expires.String); err == nil {
				h.ExpiresAt = &parsed
			}
		}
		hashes = append(hashes, h)
	}
	return hashes, rows.Err()
}

// UpdateTokenLastUsed sets the last_used timestamp for a token.
func (a *DB) UpdateTokenLastUsed(ctx context.Context, id string) error {
	_, err := a.db.ExecContext(ctx,
		"UPDATE api_tokens SET last_used = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
		id,
	)
	return err
}

// DeleteToken removes a token by ID.
// DeleteToken removes a token by ID. Returns an error if the token does not exist.
func (a *DB) DeleteToken(ctx context.Context, id string) (bool, error) {
	result, err := a.db.ExecContext(ctx,
		"DELETE FROM api_tokens WHERE id = ?",
		id,
	)
	if err != nil {
		return false, err
	}
	n, _ := result.RowsAffected()
	return n > 0, nil
}

// DeleteTokenByLabel removes a token by label.
func (a *DB) DeleteTokenByLabel(ctx context.Context, label string) error {
	_, err := a.db.ExecContext(ctx,
		"DELETE FROM api_tokens WHERE label = ?",
		label,
	)
	return err
}

// TokenCount returns the number of active (non-expired) tokens.
func (a *DB) TokenCount(ctx context.Context) (int, error) {
	var count int
	err := a.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM api_tokens WHERE expires_at IS NULL OR expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
	).Scan(&count)
	return count, err
}
