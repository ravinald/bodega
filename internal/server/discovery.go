package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// discoveryQueueSize is the buffered-channel depth between the request hot
// path and the writer goroutine. Sized so a sustained burst (~50 rps for ~20s)
// can land without dropping rows. Beyond that, drops are counted and surfaced
// in the periodic summary log.
const discoveryQueueSize = 1024

// discoveryDropLogPeriod is the cadence at which the recorder summarizes
// dropped observations. Hot enough to notice misconfiguration; cold enough not
// to spam.
const discoveryDropLogPeriod = time.Hour

// discoveryBatchSize is how many observations one write carries. Eight full
// batches empty the queue, and the queryable sinks pay one statement, one
// round trip and one commit per batch instead of per row — which is what
// capped the drain at one write latency however wide the pool underneath was.
// At nine bound parameters per row a full batch binds 1,152, far inside every
// driver's variable ceiling.
const discoveryBatchSize = 128

// discoveryBatchWait bounds how long an observation waits when the request
// rate is too low to fill a batch. A thousand hosts running `apt update` twice
// an hour is about 7 requests/s, so this rather than the batch size is what
// decides when their rows appear; 50ms is below what a reader of `bodega
// discover list` can perceive, and 20 wakeups a second on an idle server costs
// nothing.
const discoveryBatchWait = 50 * time.Millisecond

// discoverySink is the recorder's whole view of the audit store: one batched
// write reporting how many observations it moved. *audit.DB satisfies it. It
// is an interface so the loss accounting can be driven by a store that refuses
// or half-accepts a batch, which no real sink does on demand.
type discoverySink interface {
	RecordDiscovery(ctx context.Context, rows ...audit.DiscoveryRow) (int, error)
}

// DiscoveryRecorder writes upstream-fetch observations through a single worker
// goroutine, so the request path never blocks on a SQLite write. Callers send
// to Record(); the worker drains the channel until the context passed to
// Start() is cancelled.
//
// A nil *DiscoveryRecorder is safe to use — Record is a no-op. The server
// constructs one only when both the audit DB and a non-empty discover_mode
// are configured.
type DiscoveryRecorder struct {
	db     discoverySink
	logger *slog.Logger
	ch     chan audit.DiscoveryRow

	dropped atomic.Uint64 // rows lost to a full queue
	failed  atomic.Uint64 // rows dequeued but rejected by the database
}

// NewDiscoveryRecorder constructs a recorder backed by db. The returned value
// must have Start() called on it before any Record() calls drain; sends
// before Start are buffered up to discoveryQueueSize and then dropped.
func NewDiscoveryRecorder(db *audit.DB, logger *slog.Logger) *DiscoveryRecorder {
	return &DiscoveryRecorder{
		db:     db,
		logger: logger,
		ch:     make(chan audit.DiscoveryRow, discoveryQueueSize),
	}
}

// Record enqueues an observation. Drop-on-full keeps the request path lock-
// free; dropped rows are counted and summarized periodically by the worker.
func (r *DiscoveryRecorder) Record(row audit.DiscoveryRow) {
	if r == nil {
		return
	}
	select {
	case r.ch <- row:
	default:
		r.dropped.Add(1)
	}
}

// Start drains the queue until ctx is cancelled. Spawn it once from the server
// lifecycle (Server.Start). Rows accumulate until the batch is full or
// discoveryBatchWait elapses, whichever comes first; when ctx is done, the
// worker flushes the partial batch in hand and everything still in the
// buffered channel before returning.
func (r *DiscoveryRecorder) Start(ctx context.Context) {
	if r == nil {
		return
	}
	logTick := time.NewTicker(discoveryDropLogPeriod)
	defer logTick.Stop()
	// A ticker rather than a timer armed on the first row of each batch: the
	// timer is the tighter bound but has to be stopped, drained and reset on
	// every flush, and 20 wakeups a second buys the whole dance away for a
	// worst-case latency of one period instead of one period past the first row.
	flushTick := time.NewTicker(discoveryBatchWait)
	defer flushTick.Stop()

	batch := make([]audit.DiscoveryRow, 0, discoveryBatchSize)
	for {
		select {
		case <-ctx.Done():
			r.drain(batch)
			return
		case row := <-r.ch:
			batch = append(batch, row)
			if len(batch) >= discoveryBatchSize {
				batch = r.flush(ctx, batch)
			}
		case <-flushTick.C:
			batch = r.flush(ctx, batch)
		case <-logTick.C:
			r.summarize()
		}
	}
}

// summarize reports both loss counters and resets them. Called on the tick and
// once more at shutdown, so a server that stops inside one window still says
// what it lost rather than taking the counts down with it.
func (r *DiscoveryRecorder) summarize() {
	if n := r.dropped.Swap(0); n > 0 {
		r.logger.Warn("discovery rows dropped due to full queue — increase capacity or investigate request volume",
			"dropped", n, "window", discoveryDropLogPeriod.String())
	}
	if n := r.failed.Swap(0); n > 0 {
		r.logger.Error("discovery rows rejected by the database — this is not backpressure, check the audit db",
			"failed", n, "window", discoveryDropLogPeriod.String())
	}
}

// drain writes the partial batch Start was holding, then everything still in
// the buffered channel, then summarizes. Uses a fresh, time-bounded context —
// the parent ctx is already cancelled, and a batch handed a cancelled context
// is a batch the sink refuses on the way out the door.
func (r *DiscoveryRecorder) drain(batch []audit.DiscoveryRow) {
	drainCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		select {
		case row := <-r.ch:
			batch = append(batch, row)
			if len(batch) >= discoveryBatchSize {
				batch = r.flush(drainCtx, batch)
			}
		default:
			r.flush(drainCtx, batch)
			r.summarize()
			return
		}
	}
}

// flush writes the accumulated batch and hands back the emptied slice. A batch
// the sink refuses is counted as failed, never as dropped: backpressure means
// bodega is taking more traffic than the writer drains, a rejected write means
// the store itself is not accepting rows, and an operator sent to fix capacity
// for a store that is saying no is chasing the wrong thing. The sink reports
// how many observations it moved, so a batch that lands in part costs the
// counters only the part that did not, and the log line carries both numbers
// rather than leaving the reader to infer one from the other.
func (r *DiscoveryRecorder) flush(ctx context.Context, batch []audit.DiscoveryRow) []audit.DiscoveryRow {
	if len(batch) == 0 {
		return batch
	}
	applied, err := r.db.RecordDiscovery(ctx, batch...)
	if err != nil {
		lost := max(0, len(batch)-applied)
		r.failed.Add(uint64(lost))
		r.logger.Error("discovery batch write failed, observations lost — this is not backpressure, check the audit sink",
			"batch", len(batch), "applied", applied, "lost", lost, "error", err)
	}
	return batch[:0]
}

// classifyDecision maps the policy check result onto the discovery row's
// `decision` column. discover_mode is not an input: it decides whether a row
// is written, never what the row says. See proxy.go for the call site.
func classifyDecision(hasRules, violation bool) string {
	switch {
	case !hasRules:
		return audit.DecisionNoPolicy
	case !violation:
		return audit.DecisionAllowed
	default:
		return audit.DecisionDenied
	}
}

// recordDiscovery composes a DiscoveryRow from the proxy hook's locals and
// hands it to the recorder. No-op when discover_mode is off or the recorder
// is nil. Synchronous-but-cheap: the recorder is channel-based.
func (s *Server) recordDiscovery(ctx context.Context, r *http.Request, regType, upstreamURL, policyCandidate, discoveryPkgName, s3Key, decision string) {
	if s.discovery == nil || s.discoverMode == "" {
		return
	}

	host, fullPath := splitUpstreamURL(upstreamURL)

	// The version is the key's alone. Taking it from anywhere else is what let
	// one prerelease chart request record "cert-manager" at "rc.1" while the
	// handler served 1.14.0-rc.1.
	//
	// The name prefers the caller, which read it off the request path and so
	// knows a literal "--" from an encoded "/". ParseKey cannot: it restores
	// the slash for npm, git and binary because a scoped name genuinely
	// carries one, so letting it win recorded the npm package "foo--bar" as
	// "foo/bar". Falling back to the key covers a caller with no name of its
	// own, and helm's caller name is itself ParseKey-derived, so the chart
	// request still has one source. A key from outside every tree (the pypi
	// simple index, a cargo sparse path) yields neither, and the policy
	// candidate stands.
	_, keyName, pkgVersion := manifest.ParseKey(s3Key)
	pkgName := discoveryPkgName
	if pkgName == "" {
		pkgName = keyName
	}
	if pkgName == "" {
		// For URL-scoped types the candidate is the URL itself, which is a
		// poor aggregation key but better than an empty column.
		pkgName = policyCandidate
	}

	hint := policy.SuggestPattern(regType, host, fullPath, pkgName)
	if hint == "" {
		// Fall back to the candidate so the row is still aggregatable —
		// unknown types shouldn't silently drop observations.
		hint = policyCandidate
	}

	s.recordDiscoveryRaw(ctx, r, regType, host, hint, pkgName, pkgVersion, decision, upstreamURL)
}

// recordCacheHit writes the discovery row for a request the cache answered.
//
// Discovery records requests, not cache misses. Recording only misses made
// last_client name whoever caused the miss and nobody after it, and
// request_count count how badly the cache was working rather than how much the
// fleet asked for: three requests for one artifact produced one row with
// count 1. The promote-to-policy flow never noticed, needing each pattern
// once, but the shape the mode was built for — point a clean host at bodega,
// let it install, read back what it reached for — reported almost nothing on
// the second run.
//
// The decision column keeps meaning "what the allow-list says about this
// candidate", not "what happened to this request": a hit contacts no upstream,
// so there is no fetch to permit or refuse. Recording the current verdict is
// what keeps a hit on the same row as the miss that filled the cache, which is
// the whole point of counting requests. The check is a read-through cache with
// a 30s TTL (policy.DefaultCacheTTL), so the hot path pays a mutex and a slice
// scan, not a query.
func (s *Server) recordCacheHit(ctx context.Context, r *http.Request, regType, upstreamURL, policyCandidate, discoveryPkgName, s3Key string) {
	if s.discovery == nil || s.discoverMode == "" {
		return
	}
	if regType == "" || policyCandidate == "" {
		return
	}
	// Detached from the request: a client that hangs up mid-transfer still
	// asked, and a cancelled context would fail the verdict and drop the row
	// for the same callers recordDenial detaches for.
	verdictCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditWriteTimeout)
	defer cancel()
	decision, _, err := s.upstreamPolicyVerdict(verdictCtx, regType, policyCandidate)
	if err != nil {
		// The request is already being served from the cache; a policy store
		// that cannot answer is not a reason to fail it, only a reason to
		// leave the observation unrecorded rather than record it as something
		// it is not.
		s.logger.Debug("cache hit not recorded: policy verdict unavailable",
			"type", regType, "key", s3Key, "error", err)
		return
	}
	s.recordDiscovery(ctx, r, regType, upstreamURL, policyCandidate, discoveryPkgName, s3Key, decision)
}

// recordDiscoveryRaw enqueues an observation from a caller that already knows
// every column. Handlers that decide before proxyOrCache hold no s3Key and no
// policy candidate, so they cannot reach recordDiscovery; routing them through
// one constructor keeps the pre-cache and post-cache paths writing the same
// row shape.
//
// It applies the same nil-recorder and empty-mode guard recordDiscovery does,
// and hands off to the same channel: a synchronous SQLite write on the miss
// path would put the request hot path behind the database.
func (s *Server) recordDiscoveryRaw(_ context.Context, r *http.Request, regType, host, hint, pkgName, pkgVersion, decision, upstreamURL string) {
	if s.discovery == nil || s.discoverMode == "" {
		return
	}
	s.discovery.Record(audit.DiscoveryRow{
		RegistryType: regType,
		Host:         host,
		PatternHint:  hint,
		PkgName:      pkgName,
		PkgVersion:   pkgVersion,
		Decision:     decision,
		UpstreamURL:  upstreamURL,
		LastClient:   ClientIP(r),
	})
}

// recordNoManifest logs a request for a package with no manifest entry, from
// the handler branch that 404s it. host and pattern_hint are derived from the
// upstream URL the handler would have used, so the row a promote reads back
// carries a fetchable URL rather than the request path.
//
// It fires only where the manifest lookup returned nothing. A package that has
// an entry in some mode other than proxy reaches the same 404, but recording
// it here would tell an operator to create an entry that already exists; the
// fix for that package is to edit its mode, which is a different report and is
// already answerable from `bodega show pkg`.
func (s *Server) recordNoManifest(ctx context.Context, r *http.Request, regType, pkgName, pkgVersion, upstreamURL string) {
	if s.discovery == nil || s.discoverMode == "" {
		return
	}
	var host, fullPath string
	hint := pkgName
	if upstreamURL != "" {
		host, fullPath = splitUpstreamURL(upstreamURL)
		if suggested := policy.SuggestPattern(regType, host, fullPath, pkgName); suggested != "" {
			hint = suggested
		}
	}
	s.recordDiscoveryRaw(ctx, r, regType, host, hint, pkgName, pkgVersion, audit.DecisionNoManifest, upstreamURL)
}

// splitUpstreamURL returns (host, path) for an upstream URL, tolerating
// inputs that aren't well-formed. An unparseable URL surfaces as the raw
// string in host so it remains searchable in the discovery log.
func splitUpstreamURL(raw string) (string, string) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw, ""
	}
	return u.Hostname(), u.Path
}
