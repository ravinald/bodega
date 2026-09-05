// Package audit provides the audit trail for package operations: builds,
// client fetches, CRUD mutations, proxy cache events, the server's own start
// and stop, and every request the server refused.
//
// The package holds two things that look alike and are not.
//
// The append-only event stream — Record and RecordDiscovery — is written on
// the hot path, read for reporting, and never read to make a decision. That is
// the pluggable half: EventSink, selected by audit_sink, with four
// implementations (sqlite, postgres, syslog, jsonl).
//
// Operational state — ACL lists, API tokens, cached checksums and the
// age/OSV/upstream policies — is not pluggable and is not a candidate for it.
// The request path reads it to decide: whether an address is permitted,
// whether a Bearer token is live, whether an upstream is allowed. Those reads
// need a transactional read-modify-write and a queryable store, so a sink that
// can only append (syslog, jsonl) cannot hold them, and moving them somewhere
// remote would put a network round trip inside every request bodega serves. It
// stays in the embedded SQLite database at audit_db, which every install has
// regardless of which sink the events go to.
//
// *DB is that embedded store. It also fronts the sink: Record and
// RecordDiscovery delegate, and the read surface (Query, ListDiscovery,
// AggregateDiscovery and their neighbours) either delegates to a sink that
// implements EventReader or refuses with an UnqueryableSinkError naming the
// configured sink. It never falls back to the local tables, because answering
// a query from a store the events are no longer going to is the lie this
// design is built to avoid.
package audit

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// CurrentActor returns the human invoking the process. $SUDO_USER wins so
// `sudo bodega ...` attributes to the human who escalated, not root. HTTP
// callers leave Actor empty and rely on ClientIP instead.
func CurrentActor() string {
	if v := os.Getenv("SUDO_USER"); v != "" {
		return v
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if v := os.Getenv("USER"); v != "" {
		return v
	}
	if v := os.Getenv("USERNAME"); v != "" {
		return v
	}
	return "unknown"
}

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

	// EventDenied is a request the server refused: a deny-listed IP, mutation
	// auth, an admin-only read endpoint, a frozen entry, or a version outside
	// its constraint. One type for the whole class because Filter has no OR
	// and no status predicate, so splitting it per gate would make "who was
	// turned away" five queries instead of one. Which gate refused is in
	// Status; see the Denial* constants.
	EventDenied EventType = "denied"
)

// Status values for EventDenied. They name the gate that refused, so an
// operator can tell an address that was never permitted from a token that
// simply aged out without reading the journal.
const (
	DenialDenyList       = "deny_list"            // client IP matched deny_list
	DenialUnparseableIP  = "client_ip_unparsable" // ClientIP did not parse as an address
	DenialIPNotPermitted = "ip_not_permitted"     // client IP outside admin_permit_cidr
	//nolint:gosec // G101: an event status naming a gate, not a credential.
	DenialNoTokens     = "no_tokens_configured" // remote mutation with no tokens in the DB
	DenialTokenMissing = "token_missing"        // no Bearer credential presented
	DenialTokenInvalid = "token_invalid"        // Bearer presented, matched no stored hash
	DenialTokenExpired = "token_expired"        // Bearer matched a token past expires_at
	DenialAdminOnly    = "admin_only"           // admin-gated read endpoint, IP not permitted

	// Refusals decided inside a handler rather than by the middleware chain.
	// They reach the same table because an operator asking "who was turned
	// away" is asking one question, and a refusal that answers it only from
	// the journal is a refusal that rotates away.
	DenialFrozenEntry       = "entry_frozen"       // DELETE on a package whose every version is frozen
	DenialVersionConstraint = "version_constraint" // requested version outside the entry's version_constraint
	DenialPushRefused       = "push_refused"       // git smart-HTTP push against a read-only mirror
)

// Event is a single audit record.
type Event struct {
	EventType  EventType
	PkgType    string
	PkgName    string
	PkgVersion string
	ClientIP   string
	UserAgent  string
	Status     string // "success", "failure", "cache_hit", "cache_miss"; a Denial* reason on EventDenied
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

// DB is the embedded SQLite store that holds operational state, and the front
// door to the configured event sink. See the package comment for why only one
// of those two halves is pluggable.
type DB struct {
	db       *sql.DB
	sink     EventSink       // where events go; sqliteSink shares db when audit_sink is "sqlite"
	filter   map[string]bool // nil = record all; otherwise only listed types
	location *time.Location  // display timezone (storage is always UTC)
	readOnly bool            // true when the backing file is not writable; Record becomes a no-op
}

// SinkName returns the configured sink kind, for error text and status output
// that has to name where events are going.
func (a *DB) SinkName() string { return a.sink.Name() }

// EventsQueryable reports whether the configured sink can answer a read. False
// for syslog and jsonl, which ship events out and keep no table.
func (a *DB) EventsQueryable() bool {
	_, ok := a.sink.(EventReader)
	return ok
}

// reader returns the sink's read surface, or the refusal a write-only sink
// owes the caller. op names what was being read so the message can say which
// query went unanswered.
func (a *DB) reader(op string) (EventReader, error) {
	r, ok := a.sink.(EventReader)
	if !ok {
		return nil, &UnqueryableSinkError{Sink: a.sink.Name(), Op: op}
	}
	return r, nil
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

// busyTimeout is how long a connection waits for the SQLite write lock before
// giving up. database/sql pools connections, so two goroutines writing through
// one *DB are two SQLite connections contending for that lock; with no timeout
// the loser is refused immediately and the row is gone. Eight goroutines
// writing fifty events each stored 30 of 400 without it.
//
// db.SetMaxOpenConns(1) would also stop the loss, by removing the contention:
// one connection cannot race itself. It removes the concurrent reads too,
// which is the thing WAL mode is turned on for — a dashboard query would then
// queue behind every write. Waiting for the lock keeps both.
const busyTimeout = 5 * time.Second

// dsn attaches the busy_timeout pragma to a database path. An empty path is
// left alone: the driver only strips a query string when it appears at index
// 1 or later, so "?..." on its own would be taken as a filename.
func dsn(path string) string {
	if path == "" {
		return path
	}
	return fmt.Sprintf("%s?_pragma=busy_timeout(%d)", path, busyTimeout.Milliseconds())
}

// Open opens (or creates) the audit database at path and runs migrations.
//
// If the backing file exists but isn't writable by this process (typical when
// bodega is installed as a system service and a non-root user is running a
// read-only command like `bodega audit events`), Open still returns a usable
// handle: migrations are skipped, and Record becomes a silent no-op. Query
// keeps working. This is the graceful path for "I'm logged in as ravi but
// /var/log/bodega/audit.db is root:root 644."
func Open(path string) (*DB, error) {
	return OpenWithSink(path, SinkConfig{})
}

// OpenWithSink opens the embedded store at path and attaches the configured
// event sink. The embedded store is opened either way: it holds the ACLs,
// tokens, checksums and policies the request path reads, which no sink
// replaces. A sink that cannot be reached is an error here rather than a
// warning, so `bodega serve` can refuse to start on it.
func OpenWithSink(path string, sc SinkConfig) (*DB, error) {
	readOnly := false
	if path != "" {
		// A first run has log_dir but not the directory under it. That is a
		// fixable condition, not a missing store, and since `bodega serve`
		// now refuses to start without the audit store, leaving it unfixed
		// would turn every fresh install into a startup failure. 0o750: the
		// trail names client addresses and package requests.
		if dir := filepath.Dir(path); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return nil, fmt.Errorf("create audit db directory %s: %w", dir, err)
			}
		}
		if _, statErr := os.Stat(path); statErr == nil {
			if f, err := os.OpenFile(path, os.O_WRONLY, 0); err != nil {
				readOnly = true
			} else {
				_ = f.Close()
			}
		}
	}

	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, fmt.Errorf("open audit db %s: %w", path, err)
	}

	// WAL mode needs write access; skip on read-only handles (journal_mode
	// returns the existing mode silently when write is denied, but we'd rather
	// not even attempt the PRAGMA).
	if !readOnly {
		if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("set WAL mode: %w", err)
		}
		from, err := runMigrations(db)
		if err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("migrate audit db: %w", err)
		}
		// Migration 011 corrects identity the request-path parser got wrong on
		// every cached artifact of seven of the eight ecosystems. It reads only
		// s3_key, so it runs here on the upgrade that crosses it rather than
		// costing every open a full scan of a table that grows with the cache.
		if from < checksumIdentityVersion {
			n, err := backfillChecksumIdentity(context.Background(), db)
			if err != nil {
				_ = db.Close()
				return nil, fmt.Errorf("backfill checksum package identity: %w", err)
			}
			if n > 0 {
				slog.Info("checksum rows re-derived from their object key", "rows", n, "migration", checksumIdentityVersion)
			}
		}
	}

	sink, err := newSink(sc, db, readOnly)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &DB{db: db, sink: sink, readOnly: readOnly}, nil
}

// ReadOnly returns true when the backing file is not writable. Record silently
// no-ops on a read-only handle; Query keeps working.
func (a *DB) ReadOnly() bool { return a.readOnly }

// Close closes the sink and then the embedded database. The sqlite sink shares
// the embedded handle and its Close is a no-op, so the file is closed once.
func (a *DB) Close() error {
	sinkErr := a.sink.Close()
	dbErr := a.db.Close()
	if sinkErr != nil {
		return sinkErr
	}
	return dbErr
}

// Record writes one event to the configured sink. It is silent on filtered
// events and on a read-only sqlite handle. Callers that need hard-fail
// semantics should check ReadOnly() themselves.
func (a *DB) Record(ctx context.Context, ev Event) error {
	if !a.ShouldRecord(ev.EventType) {
		return nil
	}
	return a.sink.Record(ctx, ev)
}

// Query returns events matching the filter, ordered by timestamp descending,
// with timestamps rendered in the display timezone. It refuses rather than
// returning an empty page when the configured sink keeps no table.
func (a *DB) Query(ctx context.Context, f Filter) ([]StoredEvent, error) {
	r, err := a.reader("audit events")
	if err != nil {
		return nil, err
	}
	events, err := r.QueryEvents(ctx, f)
	if err != nil {
		return nil, err
	}
	if a.location != nil {
		for i := range events {
			events[i].Timestamp = events[i].Timestamp.In(a.location)
		}
	}
	return events, nil
}

// Count returns the total number of events matching the filter.
func (a *DB) Count(ctx context.Context, f Filter) (int64, error) {
	r, err := a.reader("audit events")
	if err != nil {
		return 0, err
	}
	return r.CountEvents(ctx, f)
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
		//nolint:gosec // G202: WHERE clause assembled from a fixed slice of internal predicates; values are bound via ? parameters in `args`.
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

// ClearChecksumsByPackage removes all stored checksums for a package and
// returns how many rows it deleted. Zero is not an error here — the caller is
// an operator escaping a checksum mismatch, and they need to be told the
// filter matched nothing rather than read a success message over a table that
// still holds the stale digest.
func (a *DB) ClearChecksumsByPackage(ctx context.Context, pkgType, pkgName string) (int64, error) {
	result, err := a.db.ExecContext(ctx,
		"DELETE FROM checksums WHERE pkg_type = ? AND pkg_name = ?",
		pkgType, pkgName,
	)
	if err != nil {
		return 0, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return n, nil
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
