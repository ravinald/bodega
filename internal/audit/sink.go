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
	RecordDiscovery(ctx context.Context, r DiscoveryRow) error
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
