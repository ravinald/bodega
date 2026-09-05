package audit

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	migratepgx "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver for postgres
)

//go:embed migrations_postgres/*.sql
var postgresMigrationsFS embed.FS

// Pool shape for the postgres sink. A fleet's worth of `apt update` is many
// small inserts from many goroutines, so the pool is sized for concurrency
// rather than for a large working set; the lifetime bound is there so a
// connection surviving a failover on the server side gets replaced rather than
// returning errors until the process restarts.
const (
	pgMaxOpenConns    = 16
	pgMaxIdleConns    = 8
	pgConnMaxLifetime = 30 * time.Minute

	// pgConnectTimeout bounds the startup Ping. A sink that cannot connect is
	// fatal for `serve`, so this is how long bodega waits before saying so.
	pgConnectTimeout = 5 * time.Second
)

// postgresSink is the queryable sink for a fleet: many hosts writing at once,
// and one place to report across them. It holds only the two log-shaped tables;
// operational state stays in the embedded SQLite store on each host.
type postgresSink struct {
	db *sql.DB
}

func newPostgresSink(dsn string) (EventSink, error) {
	if dsn == "" {
		return nil, fmt.Errorf("audit_sink %q needs audit_sink_dsn: a libpq connection string, e.g. \"postgres://bodega:secret@db.internal:5432/bodega?sslmode=verify-full\"", SinkPostgres)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open audit sink %q: %w", SinkPostgres, err)
	}
	db.SetMaxOpenConns(pgMaxOpenConns)
	db.SetMaxIdleConns(pgMaxIdleConns)
	db.SetConnMaxLifetime(pgConnMaxLifetime)

	ctx, cancel := context.WithTimeout(context.Background(), pgConnectTimeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect audit sink %q: %w", SinkPostgres, err)
	}
	if err := runPostgresMigrations(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &postgresSink{db: db}, nil
}

func (s *postgresSink) Name() string { return SinkPostgres }

func (s *postgresSink) Close() error { return s.db.Close() }

// runPostgresMigrations applies the sink's own schema, with the same
// downgrade guardrail the embedded store has: a database migrated by a newer
// binary is refused rather than misread. The two sets are versioned separately
// because they describe different things, and a shared postgres holding an
// events table written by two bodega versions is the case this catches.
func runPostgresMigrations(db *sql.DB) error {
	src, err := iofs.New(postgresMigrationsFS, "migrations_postgres")
	if err != nil {
		return fmt.Errorf("iofs source (postgres): %w", err)
	}
	driver, err := migratepgx.WithInstance(db, &migratepgx.Config{
		MigrationsTable: "schema_migrations_audit_sink",
	})
	if err != nil {
		return fmt.Errorf("postgres migrate driver: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "pgx5", driver)
	if err != nil {
		return fmt.Errorf("migrate instance (postgres): %w", err)
	}
	codeMax, err := maxMigrationVersion(postgresMigrationsFS, "migrations_postgres")
	if err != nil {
		return err
	}
	version, dirty, err := m.Version()
	switch {
	case errors.Is(err, migrate.ErrNilVersion):
	case err != nil:
		return fmt.Errorf("read postgres schema version: %w", err)
	case dirty:
		return fmt.Errorf("audit sink schema is dirty at version %d; manual recovery required", version)
	case version > codeMax:
		return fmt.Errorf("audit sink schema version %d exceeds this binary's max (%d); upgrade bodega", version, codeMax)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("apply postgres migrations: %w", err)
	}
	return nil
}

func (s *postgresSink) Record(ctx context.Context, ev Event) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO events (event_type, pkg_type, pkg_name, pkg_version, client_ip, user_agent, status, duration_ms, details, actor)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		string(ev.EventType), ev.PkgType, ev.PkgName, ev.PkgVersion,
		ev.ClientIP, ev.UserAgent, ev.Status, ev.DurationMs, ev.Details, ev.Actor,
	)
	return err
}

func (s *postgresSink) RecordDiscovery(ctx context.Context, r DiscoveryRow) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO upstream_discovery
		   (registry_type, host, pattern_hint, pkg_name, pkg_version, decision, last_client, upstream_url)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT(registry_type, pattern_hint, pkg_name, pkg_version, decision)
		 DO UPDATE SET
		   request_count = upstream_discovery.request_count + 1,
		   last_seen     = now(),
		   last_client   = excluded.last_client,
		   host          = CASE WHEN excluded.host = '' THEN upstream_discovery.host ELSE excluded.host END,
		   upstream_url  = CASE WHEN excluded.upstream_url = '' THEN upstream_discovery.upstream_url ELSE excluded.upstream_url END`,
		r.RegistryType, r.Host, r.PatternHint, r.PkgName, r.PkgVersion, r.Decision, r.LastClient, r.UpstreamURL,
	)
	return err
}

// pgArgs accumulates bound values and hands out the $N placeholders postgres
// wants, so a WHERE clause can be assembled the same way the SQLite sink does
// without hand-counting positions.
type pgArgs struct {
	vals []any
}

func (p *pgArgs) next(v any) string {
	p.vals = append(p.vals, v)
	return fmt.Sprintf("$%d", len(p.vals))
}

func (s *postgresSink) QueryEvents(ctx context.Context, f Filter) ([]StoredEvent, error) {
	var where []string
	a := &pgArgs{}

	if f.EventType != "" {
		where = append(where, "event_type = "+a.next(string(f.EventType)))
	}
	if f.PkgType != "" {
		where = append(where, "pkg_type = "+a.next(f.PkgType))
	}
	if f.PkgName != "" {
		where = append(where, "pkg_name = "+a.next(f.PkgName))
	}
	if f.ClientIP != "" {
		where = append(where, "client_ip = "+a.next(f.ClientIP))
	}
	if f.Actor != "" {
		where = append(where, "actor = "+a.next(f.Actor))
	}
	if !f.Since.IsZero() {
		where = append(where, "timestamp >= "+a.next(f.Since.UTC()))
	}
	if !f.Until.IsZero() {
		where = append(where, "timestamp <= "+a.next(f.Until.UTC()))
	}

	q := "SELECT id, timestamp, event_type, pkg_type, pkg_name, pkg_version, client_ip, user_agent, status, duration_ms, details, actor FROM events"
	if len(where) > 0 {
		//nolint:gosec // G202: WHERE clause assembled from a fixed slice of internal predicates; values are bound via $N parameters.
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY timestamp DESC"
	//nolint:gosec // G202: LIMIT clause built from a clamped int literal, no user-controlled string interpolation.
	q += fmt.Sprintf(" LIMIT %d", effectiveLimit(f.Limit))

	rows, err := s.db.QueryContext(ctx, q, a.vals...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []StoredEvent
	for rows.Next() {
		var se StoredEvent
		var et string
		var ts time.Time
		if err := rows.Scan(&se.ID, &ts, &et,
			&se.PkgType, &se.PkgName, &se.PkgVersion,
			&se.ClientIP, &se.UserAgent, &se.Status,
			&se.DurationMs, &se.Details, &se.Actor); err != nil {
			return nil, err
		}
		se.EventType = EventType(et)
		se.Timestamp = ts.UTC()
		events = append(events, se)
	}
	return events, rows.Err()
}

func (s *postgresSink) CountEvents(ctx context.Context, f Filter) (int64, error) {
	var where []string
	a := &pgArgs{}

	if f.EventType != "" {
		where = append(where, "event_type = "+a.next(string(f.EventType)))
	}
	if f.PkgType != "" {
		where = append(where, "pkg_type = "+a.next(f.PkgType))
	}

	q := "SELECT COUNT(*) FROM events"
	if len(where) > 0 {
		//nolint:gosec // G202: WHERE clause assembled from a fixed slice of internal predicates; values are bound via $N parameters.
		q += " WHERE " + strings.Join(where, " AND ")
	}
	var count int64
	err := s.db.QueryRowContext(ctx, q, a.vals...).Scan(&count)
	return count, err
}

func (s *postgresSink) ListDiscovery(ctx context.Context, f DiscoveryFilter) ([]DiscoveryRow, error) {
	var where []string
	a := &pgArgs{}

	if f.RegistryType != "" {
		where = append(where, "registry_type = "+a.next(f.RegistryType))
	}
	if f.PatternHint != "" {
		where = append(where, "pattern_hint = "+a.next(f.PatternHint))
	}
	if f.Decision != "" {
		where = append(where, "decision = "+a.next(f.Decision))
	}
	if !f.Since.IsZero() {
		where = append(where, "last_seen >= "+a.next(f.Since.UTC()))
	}

	q := `SELECT registry_type, host, pattern_hint, pkg_name, pkg_version, decision,
	             upstream_url, first_seen, last_seen, last_client, request_count
	      FROM upstream_discovery`
	if len(where) > 0 {
		//nolint:gosec // G202: WHERE clause assembled from a fixed slice of internal predicates; values are bound via $N parameters.
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY last_seen DESC"
	//nolint:gosec // G202: LIMIT clause built from a clamped int literal, no user-controlled string interpolation.
	q += fmt.Sprintf(" LIMIT %d", effectiveLimit(f.Limit))

	rows, err := s.db.QueryContext(ctx, q, a.vals...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DiscoveryRow
	for rows.Next() {
		var r DiscoveryRow
		var firstSeen, lastSeen time.Time
		if err := rows.Scan(&r.RegistryType, &r.Host, &r.PatternHint, &r.PkgName, &r.PkgVersion,
			&r.Decision, &r.UpstreamURL, &firstSeen, &lastSeen, &r.LastClient, &r.RequestCount); err != nil {
			return nil, err
		}
		r.FirstSeen = firstSeen.UTC()
		r.LastSeen = lastSeen.UTC()
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan discovery: %w", err)
	}
	return out, nil
}

func (s *postgresSink) AggregateDiscovery(ctx context.Context, registryType string) ([]DiscoveryAggregate, error) {
	var (
		rows *sql.Rows
		err  error
	)
	// string_agg is postgres's GROUP_CONCAT. Change the separator or drop the
	// DISTINCT and `bodega discover list` prints a decision column that either
	// will not split or repeats one value per row in the bucket.
	q := `SELECT registry_type, pattern_hint,
	             MAX(host)                             AS host,
	             SUM(request_count)                    AS total,
	             MIN(first_seen)                       AS first_seen,
	             MAX(last_seen)                        AS last_seen,
	             string_agg(DISTINCT decision, ',')    AS decisions,
	             MAX(upstream_url)                     AS sample_upstream
	      FROM upstream_discovery`
	if registryType != "" {
		q += " WHERE registry_type = $1"
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
		var agg DiscoveryAggregate
		var firstSeen, lastSeen time.Time
		var decisions, sampleUpstream sql.NullString
		if err := rows.Scan(&agg.RegistryType, &agg.PatternHint, &agg.Host, &agg.RequestCount,
			&firstSeen, &lastSeen, &decisions, &sampleUpstream); err != nil {
			return nil, err
		}
		agg.FirstSeen = firstSeen.UTC()
		agg.LastSeen = lastSeen.UTC()
		if decisions.Valid {
			agg.Decisions = decisions.String
		}
		if sampleUpstream.Valid {
			agg.SampleUpstream = sampleUpstream.String
		}
		out = append(out, agg)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan discovery aggregate: %w", err)
	}
	return out, nil
}

func (s *postgresSink) ClearDiscovery(ctx context.Context, registryType string) (int64, error) {
	var (
		res sql.Result
		err error
	)
	if registryType == "" {
		res, err = s.db.ExecContext(ctx, `DELETE FROM upstream_discovery`)
	} else {
		res, err = s.db.ExecContext(ctx, `DELETE FROM upstream_discovery WHERE registry_type = $1`, registryType)
	}
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func (s *postgresSink) DiscoveryCount(ctx context.Context, registryType string) (int64, error) {
	var n int64
	var err error
	if registryType == "" {
		err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM upstream_discovery`).Scan(&n)
	} else {
		err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM upstream_discovery WHERE registry_type = $1`, registryType).Scan(&n)
	}
	return n, err
}
