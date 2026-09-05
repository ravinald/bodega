package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The event-sink conformance suite. Every sink is held to the same contract
// here, and a new one joins by adding a line to conformanceSinks.
//
// Two things the storage suite got wrong are avoided on purpose (B8 R3): the
// fixtures are chosen so a broken sink can actually fail them — every field is
// distinct and non-empty, and two carry a newline and a quote — and the cases
// where the sinks genuinely differ are pinned as differences rather than
// dropped. A queryable sink deduplicates a repeated discovery observation; a
// write-only one cannot, and `bodega discover promote` depends on the first.
// Both are asserted below rather than left to a reader of the code.

// capturedEvent and capturedDiscovery are what a sink is read back as,
// whatever it stores. Normalizing on the wire shape is what lets one set of
// assertions drive a SQL table and a log line.
type capturedEvent = wireEvent

type capturedDiscovery = wireDiscovery

// sinkHarness is one sink plus the way to read back what it received.
type sinkHarness struct {
	sink EventSink

	// queryable is true when the sink implements EventReader. It gates the
	// query and dedup cases, not the write ones.
	queryable bool

	events      func(t *testing.T) []capturedEvent
	discoveries func(t *testing.T) []capturedDiscovery
}

// conformanceSinks builds a fresh harness per sink per case, so no assertion
// depends on the order the table happens to run in.
func conformanceSinks() map[string]func(t *testing.T) sinkHarness {
	return map[string]func(t *testing.T) sinkHarness{
		SinkSQLite:   newSQLiteHarness,
		SinkPostgres: newPostgresHarness,
		SinkSyslog:   newSyslogHarness,
		SinkJSONL:    newJSONLHarness,
	}
}

func TestEventSinkConformance(t *testing.T) {
	for name, mk := range conformanceSinks() {
		t.Run(name, func(t *testing.T) {
			testEventSink(t, mk)
		})
	}
}

func testEventSink(t *testing.T, mk func(t *testing.T) sinkHarness) {
	t.Helper()

	// A newline and a double quote in two fields: a sink that writes a line
	// format without escaping produces a second record from one event, which
	// is the log-forgery shape B16 R7 pinned for the log handler.
	fullEvent := Event{
		EventType:  EventDenied,
		PkgType:    "apt",
		PkgName:    "hello",
		PkgVersion: "2.10-3",
		ClientIP:   "10.4.5.6",
		UserAgent:  "curl/8.4.0\nDebian APT-HTTP/1.3",
		Status:     DenialTokenExpired,
		DurationMs: 4711,
		Details:    `{"note":"a \"quoted\" detail"}`,
		Actor:      "ravi",
	}

	fullRow := DiscoveryRow{
		RegistryType: "gomod",
		Host:         "proxy.golang.org",
		PatternHint:  "github.com/aws/",
		PkgName:      "github.com/aws/aws-sdk-go-v2",
		PkgVersion:   "v1.30.0",
		Decision:     DecisionDenied,
		UpstreamURL:  "https://proxy.golang.org/github.com/aws/aws-sdk-go-v2/@v/v1.30.0.zip",
		LastClient:   "10.4.5.6",
	}

	cases := []struct {
		name string
		run  func(t *testing.T, ctx context.Context, h sinkHarness)
	}{
		{"every_event_field_survives", func(t *testing.T, ctx context.Context, h sinkHarness) {
			if err := h.sink.Record(ctx, fullEvent); err != nil {
				t.Fatalf("Record: %v", err)
			}
			got := h.events(t)
			if len(got) != 1 {
				t.Fatalf("read back %d events, want 1", len(got))
			}
			want := capturedEvent{
				EventType: string(fullEvent.EventType), PkgType: fullEvent.PkgType,
				PkgName: fullEvent.PkgName, PkgVersion: fullEvent.PkgVersion,
				ClientIP: fullEvent.ClientIP, UserAgent: fullEvent.UserAgent,
				Status: fullEvent.Status, DurationMs: fullEvent.DurationMs,
				Details: fullEvent.Details, Actor: fullEvent.Actor,
			}
			if got[0] != want {
				t.Errorf("event round trip differs:\n got %+v\nwant %+v", got[0], want)
			}
		}},

		{"every_discovery_field_survives", func(t *testing.T, ctx context.Context, h sinkHarness) {
			if err := h.sink.RecordDiscovery(ctx, fullRow); err != nil {
				t.Fatalf("RecordDiscovery: %v", err)
			}
			got := h.discoveries(t)
			if len(got) != 1 {
				t.Fatalf("read back %d discovery rows, want 1", len(got))
			}
			want := capturedDiscovery{
				RegistryType: fullRow.RegistryType, Host: fullRow.Host,
				PatternHint: fullRow.PatternHint, PkgName: fullRow.PkgName,
				PkgVersion: fullRow.PkgVersion, Decision: fullRow.Decision,
				UpstreamURL: fullRow.UpstreamURL, LastClient: fullRow.LastClient,
			}
			if got[0] != want {
				t.Errorf("discovery round trip differs:\n got %+v\nwant %+v", got[0], want)
			}
		}},

		// The embedded store enforces the decision set with a CHECK. A sink
		// that accepted a value the store refuses would let a swap widen what
		// the discovery table can hold, and `discover promote` filters on it.
		{"decision_outside_the_set_is_refused", func(t *testing.T, ctx context.Context, h sinkHarness) {
			bad := fullRow
			bad.Decision = "would_deny" // retired by SQLite migration 010
			if err := h.sink.RecordDiscovery(ctx, bad); err == nil {
				t.Fatal("RecordDiscovery accepted a decision outside the set; every sink must refuse it")
			}
			if got := h.discoveries(t); len(got) != 0 {
				t.Errorf("refused write still left %d rows behind", len(got))
			}
		}},

		// One newline-carrying event must stay one record. A sink that wrote
		// the user agent raw would produce two, and the second would parse as
		// a truncated record rather than failing loudly.
		{"a_newline_cannot_forge_a_second_record", func(t *testing.T, ctx context.Context, h sinkHarness) {
			if err := h.sink.Record(ctx, fullEvent); err != nil {
				t.Fatalf("Record: %v", err)
			}
			if got := h.events(t); len(got) != 1 {
				t.Fatalf("one event with an embedded newline produced %d records, want 1", len(got))
			}
		}},

		// B9 requirement 2, held against every sink: eight goroutines, fifty
		// events each, through one handle. SQLite stored 30 of 400 before the
		// busy_timeout landed, and a new sink must not ship below that bar.
		{"concurrent_writers_keep_every_event", func(t *testing.T, ctx context.Context, h sinkHarness) {
			const writers, per = 8, 50
			var wg sync.WaitGroup
			errs := make(chan error, writers*per)
			for w := 0; w < writers; w++ {
				wg.Add(1)
				go func(w int) {
					defer wg.Done()
					for i := 0; i < per; i++ {
						ev := Event{
							EventType: EventServeFetch,
							PkgType:   "apt",
							PkgName:   fmt.Sprintf("pkg-%d-%d", w, i),
							Status:    "success",
						}
						if err := h.sink.Record(ctx, ev); err != nil {
							errs <- err
						}
					}
				}(w)
			}
			wg.Wait()
			close(errs)
			var failed int
			for err := range errs {
				if failed == 0 {
					t.Errorf("first write error: %v", err)
				}
				failed++
			}
			if failed > 0 {
				t.Errorf("%d of %d writes returned an error", failed, writers*per)
			}
			if got := h.events(t); len(got) != writers*per {
				t.Errorf("stored %d of %d events under %d concurrent writers", len(got), writers*per, writers)
			}
		}},

		// Capability-scoped from here down. These are the differences between
		// the two halves of the sink set, asserted rather than assumed.
		{"repeat_observations_collapse_only_on_a_queryable_sink", func(t *testing.T, ctx context.Context, h sinkHarness) {
			for i := 0; i < 3; i++ {
				if err := h.sink.RecordDiscovery(ctx, fullRow); err != nil {
					t.Fatalf("RecordDiscovery %d: %v", i, err)
				}
			}
			got := h.discoveries(t)
			if h.queryable {
				if len(got) != 1 {
					t.Fatalf("queryable sink kept %d rows for one upsert key, want 1", len(got))
				}
				r, ok := h.sink.(EventReader)
				if !ok {
					t.Fatal("harness says queryable but the sink is not an EventReader")
				}
				rows, err := r.ListDiscovery(ctx, DiscoveryFilter{})
				if err != nil {
					t.Fatalf("ListDiscovery: %v", err)
				}
				if rows[0].RequestCount != 3 {
					t.Errorf("request_count = %d after 3 observations, want 3", rows[0].RequestCount)
				}
				return
			}
			// A write-only sink has no upsert key to collapse on. Emitting
			// one record per request is the contract: the rollup belongs to
			// whatever consumes the stream, and `discover promote` is
			// unavailable for exactly this reason.
			if len(got) != 3 {
				t.Errorf("write-only sink emitted %d records for 3 observations, want 3", len(got))
			}
		}},

		{"a_write_only_sink_answers_no_query", func(t *testing.T, ctx context.Context, h sinkHarness) {
			if err := h.sink.Record(ctx, fullEvent); err != nil {
				t.Fatalf("Record: %v", err)
			}
			_, isReader := h.sink.(EventReader)
			if isReader != h.queryable {
				t.Fatalf("EventReader implemented = %v, harness queryable = %v", isReader, h.queryable)
			}
			if h.queryable {
				return
			}
			// The refusal is what the CLI and GET /api/v1/audit print, so the
			// text has to name the sink and a sink that can answer.
			err := (&UnqueryableSinkError{Sink: h.sink.Name(), Op: "audit events"}).Error()
			for _, want := range []string{h.sink.Name(), SinkPostgres, "write-only"} {
				if !strings.Contains(err, want) {
					t.Errorf("refusal text does not mention %q: %s", want, err)
				}
			}
		}},

		{"filters_select_by_event_type", func(t *testing.T, ctx context.Context, h sinkHarness) {
			if !h.queryable {
				t.Skip("write-only sink: no query surface to filter with")
			}
			r := h.sink.(EventReader)
			if err := h.sink.Record(ctx, fullEvent); err != nil {
				t.Fatalf("Record denied: %v", err)
			}
			if err := h.sink.Record(ctx, Event{EventType: EventServeFetch, PkgType: "apt", PkgName: "hello"}); err != nil {
				t.Fatalf("Record fetch: %v", err)
			}
			got, err := r.QueryEvents(ctx, Filter{EventType: EventDenied})
			if err != nil {
				t.Fatalf("QueryEvents: %v", err)
			}
			if len(got) != 1 || got[0].EventType != EventDenied {
				t.Fatalf("filter on %q returned %d rows, want 1 denied", EventDenied, len(got))
			}
			if got[0].Timestamp.IsZero() {
				t.Error("stored event carries a zero timestamp; the store must stamp it")
			}
			n, err := r.CountEvents(ctx, Filter{})
			if err != nil {
				t.Fatalf("CountEvents: %v", err)
			}
			if n != 2 {
				t.Errorf("CountEvents = %d, want 2", n)
			}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := mk(t)
			tc.run(t, context.Background(), h)
		})
	}
}

// ---- harnesses ---------------------------------------------------------------

func newSQLiteHarness(t *testing.T) sinkHarness {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return sqlHarness(t, db.sink)
}

// newPostgresHarness skips unless BODEGA_TEST_POSTGRES_DSN names a live
// server. It is a skip rather than an omission: the sink is held to this file
// by running it, and the DSN is one docker run away.
func newPostgresHarness(t *testing.T) sinkHarness {
	t.Helper()
	dsn := os.Getenv("BODEGA_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set BODEGA_TEST_POSTGRES_DSN to run the postgres sink against a live server")
	}
	sink, err := newPostgresSink(dsn)
	if err != nil {
		t.Fatalf("newPostgresSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	pg := sink.(*postgresSink)
	for _, stmt := range []string{"DELETE FROM events", "DELETE FROM upstream_discovery"} {
		if _, err := pg.db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	return sqlHarness(t, sink)
}

// sqlHarness reads a queryable sink back through its own EventReader, which is
// the surface the server and CLI use. Reading the tables directly would test a
// schema rather than the contract.
func sqlHarness(t *testing.T, sink EventSink) sinkHarness {
	t.Helper()
	r, ok := sink.(EventReader)
	if !ok {
		t.Fatalf("sink %q does not implement EventReader", sink.Name())
	}
	return sinkHarness{
		sink:      sink,
		queryable: true,
		events: func(t *testing.T) []capturedEvent {
			t.Helper()
			rows, err := r.QueryEvents(context.Background(), Filter{Limit: 10000})
			if err != nil {
				t.Fatalf("QueryEvents: %v", err)
			}
			out := make([]capturedEvent, 0, len(rows))
			for _, se := range rows {
				out = append(out, capturedEvent{
					EventType: string(se.EventType), PkgType: se.PkgType,
					PkgName: se.PkgName, PkgVersion: se.PkgVersion,
					ClientIP: se.ClientIP, UserAgent: se.UserAgent,
					Status: se.Status, DurationMs: se.DurationMs,
					Details: se.Details, Actor: se.Actor,
				})
			}
			return out
		},
		discoveries: func(t *testing.T) []capturedDiscovery {
			t.Helper()
			rows, err := r.ListDiscovery(context.Background(), DiscoveryFilter{Limit: 10000})
			if err != nil {
				t.Fatalf("ListDiscovery: %v", err)
			}
			out := make([]capturedDiscovery, 0, len(rows))
			for _, dr := range rows {
				out = append(out, capturedDiscovery{
					RegistryType: dr.RegistryType, Host: dr.Host,
					PatternHint: dr.PatternHint, PkgName: dr.PkgName,
					PkgVersion: dr.PkgVersion, Decision: dr.Decision,
					UpstreamURL: dr.UpstreamURL, LastClient: dr.LastClient,
				})
			}
			return out
		},
	}
}

func newJSONLHarness(t *testing.T) sinkHarness {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink, err := newJSONLSink(path)
	if err != nil {
		t.Fatalf("newJSONLSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	read := func(t *testing.T) []wireRecord {
		t.Helper()
		b, err := os.ReadFile(path) //nolint:gosec // G304: path is this test's own temp file.
		if err != nil {
			t.Fatalf("read jsonl: %v", err)
		}
		return parseWireLines(t, strings.Split(strings.TrimRight(string(b), "\n"), "\n"))
	}
	return writeOnlyHarness(sink, read)
}

// newSyslogHarness dials a TCP listener standing in for the daemon, which is
// what makes the syslog sink testable without a syslogd on the machine running
// the suite. The listener keeps every line it is handed.
func newSyslogHarness(t *testing.T) sinkHarness {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var mu sync.Mutex
	var lines []string
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				sc := bufio.NewScanner(conn)
				sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
				for sc.Scan() {
					mu.Lock()
					lines = append(lines, sc.Text())
					mu.Unlock()
				}
			}()
		}
	}()

	sink, err := newSyslogSink("tcp://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("newSyslogSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	read := func(t *testing.T) []wireRecord {
		t.Helper()
		// Record returns once the bytes are on the socket, so every write is
		// already in flight by the time a case reads; what is left is the
		// listener draining them. Wait for the count to stop moving rather
		// than sleeping a fixed interval, which is either slow or flaky, and
		// this suite counts 400 records in one case.
		const quiet = 10 // consecutive 20ms polls with no new line
		deadline := time.Now().Add(10 * time.Second)
		var snapshot []string
		still := 0
		for still < quiet && time.Now().Before(deadline) {
			mu.Lock()
			n := len(lines)
			if n != len(snapshot) {
				snapshot = append([]string(nil), lines...)
				still = 0
			} else {
				still++
			}
			mu.Unlock()
			time.Sleep(20 * time.Millisecond)
		}
		return parseWireLines(t, snapshot)
	}
	return writeOnlyHarness(sink, read)
}

func writeOnlyHarness(sink EventSink, read func(t *testing.T) []wireRecord) sinkHarness {
	return sinkHarness{
		sink:      sink,
		queryable: false,
		events: func(t *testing.T) []capturedEvent {
			t.Helper()
			var out []capturedEvent
			for _, rec := range read(t) {
				if rec.Kind == "event" && rec.Event != nil {
					out = append(out, *rec.Event)
				}
			}
			return out
		},
		discoveries: func(t *testing.T) []capturedDiscovery {
			t.Helper()
			var out []capturedDiscovery
			for _, rec := range read(t) {
				if rec.Kind == "discovery" && rec.Discovery != nil {
					out = append(out, *rec.Discovery)
				}
			}
			return out
		},
	}
}

// parseWireLines pulls the JSON object out of each line. A syslog line carries
// a priority, timestamp, host and tag first; the record starts at the first
// brace. A line with no brace, or one that will not parse, is a failure rather
// than a skip: that is what a forged second record would look like.
func parseWireLines(t *testing.T, lines []string) []wireRecord {
	t.Helper()
	var out []wireRecord
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		i := strings.IndexByte(line, '{')
		if i < 0 {
			t.Fatalf("line carries no JSON record: %q", line)
		}
		var rec wireRecord
		if err := json.Unmarshal([]byte(line[i:]), &rec); err != nil {
			t.Fatalf("parse record %q: %v", line[i:], err)
		}
		if rec.Timestamp == "" {
			t.Errorf("record carries no timestamp: %q", line[i:])
		}
		out = append(out, rec)
	}
	return out
}
