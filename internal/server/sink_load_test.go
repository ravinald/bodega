package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// TestSinkLoad drives every configured sink at the write rate B16 leaves
// behind and reports events per second, dropped events and p99 write latency.
//
// The shape is per request rather than per cache miss, which is what B16
// changed: one discovery observation through the recorder's queue, and one
// event row on the hot path (a denial or a serve_fetch). Both go through the
// same *audit.DB the server holds, so the number measured is the one an
// operator gets rather than one from a sink driven in isolation.
//
// Gated behind BODEGA_SINK_LOAD=1: it runs for loadDuration per sink and the
// postgres leg needs a live server, so it is not part of `make test`.
func TestSinkLoad(t *testing.T) {
	if os.Getenv("BODEGA_SINK_LOAD") != "1" {
		t.Skip("set BODEGA_SINK_LOAD=1 to run the sink load measurement")
	}

	const (
		writers      = 64 // concurrent clients, a fleet's worth of simultaneous apt update
		loadDuration = 10 * time.Second
	)

	// BODEGA_SINK_LOAD_RPS offers a fixed request rate instead of saturating.
	// Saturation finds each sink's ceiling; a fixed rate answers the question
	// an operator actually has, which is whether a fleet of a given size loses
	// rows. Left at 0 the generator runs open-loop, which is not fleet-shaped:
	// no real fleet offers 224,000 requests a second.
	targetRPS := 0
	if v := os.Getenv("BODEGA_SINK_LOAD_RPS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			t.Fatalf("BODEGA_SINK_LOAD_RPS=%q: want a non-negative integer", v)
		}
		targetRPS = n
	}
	// Each writer paces its own share. time.Sleep on a sub-millisecond
	// interval overshoots, so the interval is computed per writer rather than
	// globally: at 8,000 rps over 64 writers that is 8ms apiece.
	var perWriterInterval time.Duration
	if targetRPS > 0 {
		perWriterInterval = time.Duration(float64(writers) / float64(targetRPS) * float64(time.Second))
	}

	for _, kind := range audit.Sinks() {
		t.Run(kind, func(t *testing.T) {
			sc, ok := loadSinkConfig(t, kind)
			if !ok {
				return
			}
			db, err := audit.OpenWithSink(filepath.Join(t.TempDir(), "audit.db"), sc)
			if err != nil {
				t.Fatalf("open %s sink: %v", kind, err)
			}
			defer func() { _ = db.Close() }()

			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			rec := NewDiscoveryRecorder(db, logger)
			ctx, cancel := context.WithCancel(context.Background())
			workerDone := make(chan struct{})
			go func() { rec.Start(ctx); close(workerDone) }()

			var (
				requests  atomic.Uint64
				completed atomic.Uint64
				writeErrs atomic.Uint64
				latMu     sync.Mutex
				latencies []time.Duration
			)

			stop := time.Now().Add(loadDuration)
			var wg sync.WaitGroup
			for w := 0; w < writers; w++ {
				wg.Add(1)
				go func(w int) {
					defer wg.Done()
					var mine []time.Duration
					next := time.Now()
					for i := 0; time.Now().Before(stop); i++ {
						if perWriterInterval > 0 {
							next = next.Add(perWriterInterval)
							if d := time.Until(next); d > 0 {
								time.Sleep(d)
							}
						}
						requests.Add(1)
						rec.Record(audit.DiscoveryRow{
							RegistryType: "apt",
							Host:         "archive.ubuntu.com",
							PatternHint:  "archive.ubuntu.com",
							PkgName:      fmt.Sprintf("pkg-%d", i%512),
							PkgVersion:   "2.10-3",
							Decision:     audit.DecisionAllowed,
							LastClient:   fmt.Sprintf("10.0.%d.%d", w/256, w%256),
							UpstreamURL:  "https://archive.ubuntu.com/ubuntu/pool/main/h/hello/hello_2.10-3_amd64.deb",
						})
						start := time.Now()
						err := db.Record(context.Background(), audit.Event{
							EventType: audit.EventServeFetch,
							PkgType:   "apt",
							PkgName:   fmt.Sprintf("pkg-%d", i%512),
							ClientIP:  fmt.Sprintf("10.0.%d.%d", w/256, w%256),
							UserAgent: "Debian APT-HTTP/1.3 (2.7.14)",
							Status:    "success",
						})
						mine = append(mine, time.Since(start))
						if err != nil {
							writeErrs.Add(1)
							continue
						}
						completed.Add(1)
					}
					latMu.Lock()
					latencies = append(latencies, mine...)
					latMu.Unlock()
				}(w)
			}
			started := time.Now()
			wg.Wait()
			elapsed := time.Since(started)
			// Read the loss counters before cancelling: drain() calls
			// summarize(), which Swaps both to zero, so a read after shutdown
			// reports no loss on a run that lost thousands of rows. Up to
			// discoveryQueueSize observations are still in flight here and
			// land during the drain, which understates nothing that matters.
			dropped := rec.dropped.Load()
			failed := rec.failed.Load()
			cancel()
			<-workerDone

			sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
			p := func(q float64) time.Duration {
				if len(latencies) == 0 {
					return 0
				}
				i := int(float64(len(latencies))*q) - 1
				if i < 0 {
					i = 0
				}
				return latencies[i]
			}
			// Both loss counters, kept apart the way B9 R4 established:
			// backpressure and a rejected write are different problems.
			hotRows := completed.Load()
			reqs := requests.Load()
			// Two writes per simulated request. The discovery half can be lost
			// twice over, and the two losses stay apart the way B9 R4
			// established: a full queue is backpressure, a rejected write is
			// the store saying no.
			discoveryLanded := reqs - dropped - failed
			landed := hotRows + discoveryLanded

			offered := "saturated"
			if targetRPS > 0 {
				offered = fmt.Sprintf("%d rps offered", targetRPS)
			}
			t.Logf("sink=%s writers=%d elapsed=%s requests=%d (%s)", kind, writers, elapsed.Round(time.Millisecond), reqs, offered)
			t.Logf("  events/s landed (hot path + discovery): %.0f", float64(landed)/elapsed.Seconds())
			t.Logf("  hot-path rows: %d (%.0f/s), errors: %d", hotRows, float64(hotRows)/elapsed.Seconds(), writeErrs.Load())
			t.Logf("  discovery dropped (full queue): %d (%.1f%%), failed (rejected): %d",
				dropped, 100*float64(dropped)/float64(reqs), failed)
			t.Logf("  hot-path write latency p50=%s p99=%s max=%s", p(0.50), p(0.99), p(1.0))
		})
	}
}

// loadSinkConfig builds a sink config for the load run, or reports that this
// sink cannot be measured here and why.
func loadSinkConfig(t *testing.T, kind string) (audit.SinkConfig, bool) {
	t.Helper()
	switch kind {
	case audit.SinkSQLite:
		return audit.SinkConfig{Kind: kind}, true
	case audit.SinkPostgres:
		dsn := os.Getenv("BODEGA_TEST_POSTGRES_DSN")
		if dsn == "" {
			t.Skip("set BODEGA_TEST_POSTGRES_DSN to measure the postgres sink")
			return audit.SinkConfig{}, false
		}
		return audit.SinkConfig{Kind: kind, DSN: dsn}, true
	case audit.SinkJSONL:
		return audit.SinkConfig{Kind: kind, DSN: filepath.Join(t.TempDir(), "audit.jsonl")}, true
	case audit.SinkSyslog:
		// A collector that reads and discards. Measuring against the host's
		// own syslogd would measure that daemon's disk, which is not a
		// property of bodega and is not reproducible between machines.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func() { _, _ = io.Copy(io.Discard, conn); _ = conn.Close() }()
			}
		}()
		t.Cleanup(func() { _ = ln.Close() })
		return audit.SinkConfig{Kind: kind, DSN: "tcp://" + ln.Addr().String()}, true
	}
	t.Fatalf("no load config for sink %q — add one when a sink joins the set", kind)
	return audit.SinkConfig{}, false
}

// TestSinkLoadEndToEnd drives real HTTP requests at a running bodega, one sink
// at a time, so the numbers include the request chain rather than only the
// write. The route is the gomod no-manifest 404: it costs no upstream fetch
// and leaves one discovery observation per request, which is the per-request
// write shape B16 landed on.
//
// The latency reported here is request latency, not write latency — the
// discovery write happens on the recorder's goroutine. TestSinkLoad above is
// where the per-write p99 lives.
func TestSinkLoadEndToEnd(t *testing.T) {
	if os.Getenv("BODEGA_SINK_LOAD") != "1" {
		t.Skip("set BODEGA_SINK_LOAD=1 to run the sink load measurement")
	}
	const (
		clients      = 64
		loadDuration = 10 * time.Second
	)

	for _, kind := range audit.Sinks() {
		t.Run(kind, func(t *testing.T) {
			sc, ok := loadSinkConfig(t, kind)
			if !ok {
				return
			}
			s := newLoadServer(t, sc)
			ts := httptest.NewServer(s.Handler())
			t.Cleanup(ts.Close)

			// One pooled transport for every client. Without it each request
			// opens and closes a connection, and 64 goroutines exhaust the
			// ephemeral port range in seconds — which measures the host's
			// TIME_WAIT table, not bodega.
			tr := &http.Transport{
				MaxIdleConns:        clients * 2,
				MaxIdleConnsPerHost: clients * 2,
				MaxConnsPerHost:     clients * 2,
				IdleConnTimeout:     90 * time.Second,
			}
			t.Cleanup(tr.CloseIdleConnections)

			var (
				requests atomic.Uint64
				failures atomic.Uint64
				latMu    sync.Mutex
				lat      []time.Duration
			)
			stop := time.Now().Add(loadDuration)
			var wg sync.WaitGroup
			for c := 0; c < clients; c++ {
				wg.Add(1)
				go func(c int) {
					defer wg.Done()
					client := &http.Client{Timeout: 30 * time.Second, Transport: tr}
					var mine []time.Duration
					for i := 0; time.Now().Before(stop); i++ {
						url := fmt.Sprintf("%s/go/example.com/mod-%d/@v/v1.%d.0.info", ts.URL, i%512, i%64)
						start := time.Now()
						resp, err := client.Get(url) //nolint:noctx // a load generator, not a request path
						mine = append(mine, time.Since(start))
						requests.Add(1)
						if err != nil {
							failures.Add(1)
							continue
						}
						_, _ = io.Copy(io.Discard, resp.Body)
						_ = resp.Body.Close()
					}
					latMu.Lock()
					lat = append(lat, mine...)
					latMu.Unlock()
				}(c)
			}
			started := time.Now()
			wg.Wait()
			elapsed := time.Since(started)
			dropped := s.discovery.dropped.Load()
			failed := s.discovery.failed.Load()

			sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
			p := func(q float64) time.Duration {
				if len(lat) == 0 {
					return 0
				}
				i := int(float64(len(lat))*q) - 1
				if i < 0 {
					i = 0
				}
				return lat[i]
			}
			reqs := requests.Load()
			t.Logf("sink=%s clients=%d elapsed=%s requests=%d", kind, clients, elapsed.Round(time.Millisecond), reqs)
			t.Logf("  requests/s: %.0f, transport failures: %d", float64(reqs)/elapsed.Seconds(), failures.Load())
			t.Logf("  discovery events/s landed: %.0f", float64(reqs-dropped-failed)/elapsed.Seconds())
			t.Logf("  discovery dropped (full queue): %d (%.1f%%), failed (rejected): %d",
				dropped, 100*float64(dropped)/float64(reqs), failed)
			t.Logf("  request latency p50=%s p99=%s max=%s", p(0.50), p(0.99), p(1.0))
		})
	}
}

// newLoadServer is newDiscoveryServer with the sink under measurement. It
// keeps the same empty manifest store, so every request takes the
// no_manifest branch and no upstream is ever reached.
func newLoadServer(t *testing.T, sc audit.SinkConfig) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		AptCodename:    "noble",
		LogDir:         dir,
		AuditDB:        filepath.Join(dir, "audit.db"),
		StoragePath:    dir,
		DiscoverMode:   "observe",
		GomodUpstream:  "https://proxy.golang.org",
		AuditSink:      sc.Kind,
		AuditSinkDSN:   sc.DSN,
		AllowPlaintext: true,
	}
	s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), storage.NewSingle(storage.NewMemory()),
		"127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if s.auditErr != nil {
		t.Fatalf("audit sink %q: %v", sc.Kind, s.auditErr)
	}
	if s.discovery == nil {
		t.Fatal("discovery recorder not constructed; the run would measure nothing")
	}
	ctx, cancel := context.WithCancel(context.Background())
	go s.discovery.Start(ctx)
	t.Cleanup(func() {
		cancel()
		_ = s.auditDB.Close()
	})
	return s
}
