package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/syslog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// syslogTag is the program name every line carries, so a SIEM rule can select
// bodega's audit stream without matching on message content.
const syslogTag = "bodega"

// syslogFacility routes the stream. LOCAL0 rather than AUTHPRIV: the trail is
// mostly package fetches and cache decisions, and an operator who wants it in
// the auth log can route local0 there, while the reverse — pulling fetch noise
// back out of authpriv — needs a content filter.
const syslogFacility = syslog.LOG_INFO | syslog.LOG_LOCAL0

// wireRecord is what a write-only sink emits: one JSON object per event, with
// a kind discriminator so a collector can tell an event from a discovery
// observation without inspecting which fields are present.
//
// The field names are the SQL column names the queryable sinks use, not Go
// field names. A query written against the postgres sink and a SIEM rule
// written against the syslog stream then name the same things, which is the
// only sense in which "every sink writes the same event shape" is checkable.
type wireRecord struct {
	Kind      string         `json:"kind"` // "event" or "discovery"
	Timestamp string         `json:"timestamp"`
	Event     *wireEvent     `json:"event,omitempty"`
	Discovery *wireDiscovery `json:"discovery,omitempty"`
}

type wireEvent struct {
	EventType  string `json:"event_type"`
	PkgType    string `json:"pkg_type"`
	PkgName    string `json:"pkg_name"`
	PkgVersion string `json:"pkg_version"`
	ClientIP   string `json:"client_ip"`
	UserAgent  string `json:"user_agent"`
	Status     string `json:"status"`
	DurationMs int64  `json:"duration_ms"`
	Details    string `json:"details"`
	Actor      string `json:"actor"`
}

type wireDiscovery struct {
	RegistryType string `json:"registry_type"`
	Host         string `json:"host"`
	PatternHint  string `json:"pattern_hint"`
	PkgName      string `json:"pkg_name"`
	PkgVersion   string `json:"pkg_version"`
	Decision     string `json:"decision"`
	UpstreamURL  string `json:"upstream_url"`
	LastClient   string `json:"last_client"`
}

// encodeEvent renders one event as a single line with no interior newline.
// json.Marshal escapes control characters, so a user agent carrying a newline
// cannot forge a second record — the same property internal/logging pins for
// the log handler.
func encodeEvent(ev Event) ([]byte, error) {
	return json.Marshal(wireRecord{
		Kind:      "event",
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Event: &wireEvent{
			EventType:  string(ev.EventType),
			PkgType:    ev.PkgType,
			PkgName:    ev.PkgName,
			PkgVersion: ev.PkgVersion,
			ClientIP:   ev.ClientIP,
			UserAgent:  ev.UserAgent,
			Status:     ev.Status,
			DurationMs: ev.DurationMs,
			Details:    ev.Details,
			Actor:      ev.Actor,
		},
	})
}

// encodeDiscovery renders one observation. A write-only sink cannot
// deduplicate — that is what the upsert key does in a table — so it emits one
// record per request and leaves the rollup to whatever consumes the stream.
func encodeDiscovery(r DiscoveryRow) ([]byte, error) {
	// The queryable sinks refuse a decision outside the set with a CHECK. A
	// write-only sink has no constraint to lean on, so it checks here: a sink
	// swap that widened what the discovery stream can carry would put values
	// in a SIEM that `bodega discover promote` will never recognize.
	if !ValidDecision(r.Decision) {
		return nil, fmt.Errorf("discovery decision %q is outside the set (%s)", r.Decision, strings.Join(Decisions(), ", "))
	}
	return json.Marshal(wireRecord{
		Kind:      "discovery",
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Discovery: &wireDiscovery{
			RegistryType: r.RegistryType,
			Host:         r.Host,
			PatternHint:  r.PatternHint,
			PkgName:      r.PkgName,
			PkgVersion:   r.PkgVersion,
			Decision:     r.Decision,
			UpstreamURL:  r.UpstreamURL,
			LastClient:   r.LastClient,
		},
	})
}

// ---- syslog -----------------------------------------------------------------

// syslogSink hands each event to a syslog daemon and keeps nothing. It exists
// for the operator who already runs a SIEM and wants bodega's trail in it
// rather than in a second store they have to back up separately.
type syslogSink struct {
	w *syslog.Writer
}

// newSyslogSink dials the daemon. An empty dsn uses the local socket the
// platform's syslog library finds; otherwise dsn is scheme://address, e.g.
// "tcp://logs.internal:514", "udp://logs.internal:514" or
// "unix:///var/run/syslog".
//
// The dial happens here so an unreachable daemon is a startup failure rather
// than a per-request one: an audit sink that fails open silently is the defect
// this design exists to prevent.
func newSyslogSink(dsn string) (EventSink, error) {
	if dsn == "" {
		w, err := syslog.New(syslogFacility, syslogTag)
		if err != nil {
			return nil, fmt.Errorf("connect audit sink %q (local daemon): %w", SinkSyslog, err)
		}
		return &syslogSink{w: w}, nil
	}
	network, addr, err := parseSyslogDSN(dsn)
	if err != nil {
		return nil, err
	}
	w, err := syslog.Dial(network, addr, syslogFacility, syslogTag)
	if err != nil {
		return nil, fmt.Errorf("connect audit sink %q at %s://%s: %w", SinkSyslog, network, addr, err)
	}
	return &syslogSink{w: w}, nil
}

// parseSyslogDSN splits scheme://address. The scheme is the network name
// net.Dial takes, restricted to the three a syslog daemon actually listens on,
// so a typo is refused at startup rather than producing a dial to a network
// that will never answer.
func parseSyslogDSN(dsn string) (network, addr string, err error) {
	u, parseErr := url.Parse(dsn)
	if parseErr != nil || u.Scheme == "" {
		return "", "", fmt.Errorf("invalid audit_sink_dsn %q for %q: want scheme://address, e.g. \"tcp://logs.internal:514\" or \"unix:///var/run/syslog\" (empty means the local daemon)", dsn, SinkSyslog)
	}
	switch u.Scheme {
	case "tcp", "udp":
		if u.Host == "" {
			return "", "", fmt.Errorf("invalid audit_sink_dsn %q for %q: %s:// needs host:port", dsn, SinkSyslog, u.Scheme)
		}
		return u.Scheme, u.Host, nil
	case "unix", "unixgram":
		if u.Path == "" {
			return "", "", fmt.Errorf("invalid audit_sink_dsn %q for %q: %s:// needs a socket path", dsn, SinkSyslog, u.Scheme)
		}
		return u.Scheme, u.Path, nil
	}
	return "", "", fmt.Errorf("invalid audit_sink_dsn %q for %q: unknown network %q (want tcp, udp, unix or unixgram)", dsn, SinkSyslog, u.Scheme)
}

func (s *syslogSink) Name() string { return SinkSyslog }

func (s *syslogSink) Close() error { return s.w.Close() }

func (s *syslogSink) Record(_ context.Context, ev Event) error {
	line, err := encodeEvent(ev)
	if err != nil {
		return fmt.Errorf("encode audit event for %q: %w", SinkSyslog, err)
	}
	return s.w.Info(string(line))
}

func (s *syslogSink) RecordDiscovery(_ context.Context, r DiscoveryRow) error {
	line, err := encodeDiscovery(r)
	if err != nil {
		return fmt.Errorf("encode discovery row for %q: %w", SinkSyslog, err)
	}
	return s.w.Info(string(line))
}

// ---- jsonl ------------------------------------------------------------------

// jsonlSink appends one JSON object per line to a file another collector
// tails. No daemon, no schema migration, and the file is readable with the
// tools already on the host.
//
// Writes are not fsynced: an audit sink that waits for the disk on every
// `apt update` is slower than the SQLite store it replaced, which defeats the
// reason for choosing it. A crash can lose the tail of the file.
type jsonlSink struct {
	mu   sync.Mutex
	f    *os.File
	path string
}

func newJSONLSink(path string) (EventSink, error) {
	if path == "" {
		return nil, fmt.Errorf("audit_sink %q needs audit_sink_dsn: the file to append to, e.g. \"/var/log/bodega/audit.jsonl\"", SinkJSONL)
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("audit_sink_dsn %q for %q must be an absolute path: bodega serve runs from a working directory the unit file chooses, so a relative path names a different file per invocation", path, SinkJSONL)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create audit sink %q directory %s: %w", SinkJSONL, filepath.Dir(path), err)
	}
	// 0o640: the trail names client addresses and package requests, which is
	// enough to profile a fleet. Group-readable so a log shipper in the right
	// group can tail it without running as bodega.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open audit sink %q at %s: %w", SinkJSONL, path, err)
	}
	return &jsonlSink{f: f, path: path}, nil
}

func (s *jsonlSink) Name() string { return SinkJSONL }

func (s *jsonlSink) Close() error { return s.f.Close() }

func (s *jsonlSink) write(line []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("write audit sink %q at %s: %w", SinkJSONL, s.path, err)
	}
	return nil
}

func (s *jsonlSink) Record(_ context.Context, ev Event) error {
	line, err := encodeEvent(ev)
	if err != nil {
		return fmt.Errorf("encode audit event for %q: %w", SinkJSONL, err)
	}
	return s.write(line)
}

func (s *jsonlSink) RecordDiscovery(_ context.Context, r DiscoveryRow) error {
	line, err := encodeDiscovery(r)
	if err != nil {
		return fmt.Errorf("encode discovery row for %q: %w", SinkJSONL, err)
	}
	return s.write(line)
}

// ValidateSyslogDSN reports whether dsn is an address newSyslogSink can dial.
// internal/config calls it so a typo is refused at config load, where the
// operator is looking at the file, rather than at `serve` startup.
func ValidateSyslogDSN(dsn string) error {
	_, _, err := parseSyslogDSN(dsn)
	return err
}
