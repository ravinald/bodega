package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// Sink kinds. The set is closed: each one answers a question the others
// cannot, and a fifth would need to justify itself the same way.
const (
	SinkSQLite   = "sqlite"   // one host, the default, no new dependency
	SinkPostgres = "postgres" // a fleet writing concurrently, reporting across instances
	SinkSyslog   = "syslog"   // shipping into a SIEM the operator already runs
	SinkJSONL    = "jsonl"    // a file another collector tails
)

// Sinks returns the four kinds in a stable order, for error text and docs.
func Sinks() []string { return []string{SinkSQLite, SinkPostgres, SinkSyslog, SinkJSONL} }

// ValidSink reports whether kind names a sink. The empty string is valid and
// means SinkSQLite, so an install that never set audit_sink keeps working.
func ValidSink(kind string) bool {
	switch kind {
	case "", SinkSQLite, SinkPostgres, SinkSyslog, SinkJSONL:
		return true
	}
	return false
}

// EventSink is the append-only half of the audit trail: written on the hot
// path, read for reporting, never read to make a decision. That is the whole
// pluggable surface, and it is two methods on purpose.
type EventSink interface {
	// Name returns the sink kind, for error text that has to say which store
	// refused or which one cannot answer.
	Name() string
	Record(ctx context.Context, ev Event) error

	// RecordDiscovery writes a batch of observations and returns how many of
	// them reached the destination. It is a batch on the interface rather than
	// an optional capability the transactional sinks add: an optional one
	// needs a fallback at the call site, and a fallback that loops is exactly
	// the serial drain the batch exists to remove.
	//
	// The returned count is what the caller lost track of when err is
	// non-nil — len(rows) - applied observations did not land. A sink that
	// writes the batch as one statement returns 0 or len(rows) and nothing
	// between; one that writes row by row returns where it stopped.
	RecordDiscovery(ctx context.Context, rows ...DiscoveryRow) (applied int, err error)

	Close() error
}

// EventReader is the read half, implemented only by sinks that keep a table.
// syslog and jsonl hand their events to something else and keep nothing to
// scan, so they implement EventSink and stop there; every read through *DB
// checks for this interface and refuses by name when it is absent.
type EventReader interface {
	QueryEvents(ctx context.Context, f Filter) ([]StoredEvent, error)
	CountEvents(ctx context.Context, f Filter) (int64, error)
	ListDiscovery(ctx context.Context, f DiscoveryFilter) ([]DiscoveryRow, error)
	AggregateDiscovery(ctx context.Context, registryType string) ([]DiscoveryAggregate, error)
	ClearDiscovery(ctx context.Context, registryType string) (int64, error)
	DiscoveryCount(ctx context.Context, registryType string) (int64, error)
}

// SinkConfig selects and addresses a sink.
type SinkConfig struct {
	// Kind is one of Sinks(); empty means SinkSQLite.
	Kind string

	// DSN addresses the destination and means something different per kind:
	// a libpq connection string for postgres, an address like
	// "tcp://logs.internal:514" (empty = the local daemon) for syslog, and a
	// file path for jsonl. It is unused by sqlite, which writes to the same
	// file the operational state lives in.
	DSN string
}

// UnqueryableSinkError is what every read surface returns when the configured
// sink is write-only. It carries the sink name because "no results" and "this
// store cannot answer" look identical to an operator otherwise, and the second
// one is not fixed by waiting.
type UnqueryableSinkError struct {
	Sink string // sink kind, one of Sinks()
	Op   string // what was being read, e.g. "audit events", "discovery rows"
}

func (e *UnqueryableSinkError) Error() string {
	op := e.Op
	if op == "" {
		op = "the audit trail"
	}
	return fmt.Sprintf("audit_sink %q is write-only: bodega ships %s to it and keeps no table to read back, "+
		"so this query cannot be answered here. Read them where %s delivers them, or set audit_sink to %q or %q "+
		"(both keep a queryable store) and restart bodega",
		e.Sink, op, e.Sink, SinkSQLite, SinkPostgres)
}

// IsUnqueryable reports whether err came from a write-only sink, so a caller
// can print the sink's own explanation instead of "internal error".
func IsUnqueryable(err error) bool {
	var e *UnqueryableSinkError
	return errors.As(err, &e)
}

// newSink builds the configured sink. embedded is the always-open SQLite
// handle that holds operational state; the sqlite sink shares it rather than
// opening the file twice, and the other three ignore it.
func newSink(sc SinkConfig, embedded *sql.DB, readOnly bool) (EventSink, error) {
	kind := sc.Kind
	if kind == "" {
		kind = SinkSQLite
	}
	switch kind {
	case SinkSQLite:
		if sc.DSN != "" {
			return nil, fmt.Errorf("audit_sink %q takes no audit_sink_dsn: it writes to audit_db (%s)", SinkSQLite, "the same file the ACLs and tokens live in")
		}
		return &sqliteSink{db: embedded, readOnly: readOnly}, nil
	case SinkPostgres:
		return newPostgresSink(sc.DSN)
	case SinkSyslog:
		return newSyslogSink(sc.DSN)
	case SinkJSONL:
		return newJSONLSink(sc.DSN)
	}
	return nil, fmt.Errorf("unknown audit_sink %q (want one of: %s)", sc.Kind, strings.Join(Sinks(), ", "))
}

// discoveryUpsertCols is the column count each batched row binds. It sets how
// many rows one statement can carry: discoveryBatchRows x this stays under
// SQLite's 32,766 variable ceiling and postgres's 65,535.
const discoveryUpsertCols = 10

// discoveryBatchRows caps the rows in one INSERT. The recorder batches well
// below this; the cap is here so a larger batch splits into legal statements
// instead of failing at the driver with "too many SQL variables".
const discoveryBatchRows = 500

// validateDiscovery refuses a batch carrying a decision outside the set before
// any of it is written. The queryable sinks have a CHECK that would refuse the
// statement anyway, but it would take every other row in the batch with it and
// report the loss as the store refusing; catching it here keeps one caller bug
// from reading as backpressure on the whole batch.
func validateDiscovery(rows []DiscoveryRow) error {
	for _, r := range rows {
		if !ValidDecision(r.Decision) {
			return fmt.Errorf("discovery decision %q is outside the set (%s)", r.Decision, strings.Join(Decisions(), ", "))
		}
	}
	return nil
}

// coalesceDiscovery merges observations sharing the upsert key and sets
// RequestCount to how many each merged row stands for. Postgres refuses an ON
// CONFLICT DO UPDATE that would touch one row twice in a single statement, and
// a batch drawn from a live request stream repeats keys constantly, so the
// merge is what makes a batched upsert legal rather than a way to shorten it.
//
// The merge reproduces what the same rows did arriving one at a time: counts
// add, the last observation wins last_client, and a non-empty host or
// upstream_url overwrites while an empty one leaves the earlier value alone.
// RequestCount on the input is ignored — callers record observations, not
// counts.
func coalesceDiscovery(rows []DiscoveryRow) []DiscoveryRow {
	type key struct{ regType, hint, pkg, version, decision string }
	at := make(map[key]int, len(rows))
	out := make([]DiscoveryRow, 0, len(rows))
	for _, r := range rows {
		k := key{r.RegistryType, r.PatternHint, r.PkgName, r.PkgVersion, r.Decision}
		i, seen := at[k]
		if !seen {
			r.RequestCount = 1
			at[k] = len(out)
			out = append(out, r)
			continue
		}
		m := &out[i]
		m.RequestCount++
		m.LastClient = r.LastClient
		m.LastIdentity = r.LastIdentity
		if r.Host != "" {
			m.Host = r.Host
		}
		if r.UpstreamURL != "" {
			m.UpstreamURL = r.UpstreamURL
		}
	}
	return out
}

// buildDiscoveryUpsert renders the multi-row upsert for rows, already
// coalesced. postgres wants $N placeholders and now(); SQLite wants ? and
// strftime. Nothing else about the statement differs, and one builder is what
// stops the two sinks drifting apart on the merge rules.
func buildDiscoveryUpsert(rows []DiscoveryRow, postgres bool) (string, []any) {
	var b strings.Builder
	b.WriteString(`INSERT INTO upstream_discovery
		   (registry_type, host, pattern_hint, pkg_name, pkg_version, decision, last_client, last_identity, upstream_url, request_count)
		 VALUES `)
	args := make([]any, 0, len(rows)*discoveryUpsertCols)
	for i, r := range rows {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteByte('(')
		for c := range discoveryUpsertCols {
			if c > 0 {
				b.WriteString(", ")
			}
			if postgres {
				fmt.Fprintf(&b, "$%d", i*discoveryUpsertCols+c+1)
			} else {
				b.WriteByte('?')
			}
		}
		b.WriteByte(')')
		args = append(args, r.RegistryType, r.Host, r.PatternHint, r.PkgName, r.PkgVersion,
			r.Decision, r.LastClient, r.LastIdentity, r.UpstreamURL, r.RequestCount)
	}
	lastSeen := `strftime('%Y-%m-%dT%H:%M:%fZ','now')`
	if postgres {
		lastSeen = "now()"
	}
	b.WriteString(`
		 ON CONFLICT(registry_type, pattern_hint, pkg_name, pkg_version, decision)
		 DO UPDATE SET
		   request_count = upstream_discovery.request_count + excluded.request_count,
		   last_seen     = ` + lastSeen + `,
		   last_client   = excluded.last_client,
		   last_identity = excluded.last_identity,
		   host          = CASE WHEN excluded.host = '' THEN upstream_discovery.host ELSE excluded.host END,
		   upstream_url  = CASE WHEN excluded.upstream_url = '' THEN upstream_discovery.upstream_url ELSE excluded.upstream_url END`)
	return b.String(), args
}

// chunkDiscovery splits rows into statement-sized pieces. Each piece is one
// statement, so a batch that outgrows the parameter ceiling lands in part
// rather than not at all, and the caller is told how much of it moved.
func chunkDiscovery(rows []DiscoveryRow) [][]DiscoveryRow {
	if len(rows) <= discoveryBatchRows {
		return [][]DiscoveryRow{rows}
	}
	var out [][]DiscoveryRow
	for start := 0; start < len(rows); start += discoveryBatchRows {
		end := min(start+discoveryBatchRows, len(rows))
		out = append(out, rows[start:end])
	}
	return out
}
