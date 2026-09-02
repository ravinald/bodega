package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"
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

// DiscoveryRecorder writes upstream-fetch observations through a single worker
// goroutine, so the request path never blocks on a SQLite write. Callers send
// to Record(); the worker drains the channel until the context passed to
// Start() is cancelled.
//
// A nil *DiscoveryRecorder is safe to use — Record is a no-op. The server
// constructs one only when both the audit DB and a non-empty discover_mode
// are configured.
type DiscoveryRecorder struct {
	db     *audit.DB
	logger *slog.Logger
	ch     chan audit.DiscoveryRow

	dropped atomic.Uint64 // rows lost to a full queue
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
// lifecycle (Server.Start). When ctx is done, the worker flushes any rows
// still in the buffered channel before returning.
func (r *DiscoveryRecorder) Start(ctx context.Context) {
	if r == nil {
		return
	}
	tick := time.NewTicker(discoveryDropLogPeriod)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			r.drain()
			return
		case row := <-r.ch:
			r.write(ctx, row)
		case <-tick.C:
			if n := r.dropped.Swap(0); n > 0 {
				r.logger.Warn("discovery rows dropped due to full queue — increase capacity or investigate request volume",
					"dropped", n, "window", discoveryDropLogPeriod.String())
			}
		}
	}
}

// drain pulls any remaining rows out of the buffered channel on shutdown.
// Uses a fresh, time-bounded context — the parent ctx is already cancelled.
func (r *DiscoveryRecorder) drain() {
	drainCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		select {
		case row := <-r.ch:
			r.write(drainCtx, row)
		default:
			return
		}
	}
}

func (r *DiscoveryRecorder) write(ctx context.Context, row audit.DiscoveryRow) {
	if err := r.db.RecordDiscovery(ctx, row); err != nil {
		r.logger.Warn("discovery write failed",
			"type", row.RegistryType, "hint", row.PatternHint, "error", err)
	}
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

	// Discovery-time package name preference: explicit > policy candidate. For
	// URL-scoped types the policy candidate is the URL itself, which is not
	// useful as an aggregation key — callers pass discoveryPkgName separately.
	pkgName := discoveryPkgName
	if pkgName == "" {
		pkgName = policyCandidate
	}

	hint := policy.SuggestPattern(regType, host, fullPath, pkgName)
	if hint == "" {
		// Fall back to the candidate so the row is still aggregatable —
		// unknown types shouldn't silently drop observations.
		hint = policyCandidate
	}

	s.recordDiscoveryRaw(ctx, r, regType, host, hint, pkgName, pkgVersionFromKey(s3Key), decision, upstreamURL)
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

// pkgVersionFromKey extracts a best-effort version string from an S3 key.
// Used only for discovery rows — wrong answers degrade aggregation quality
// but don't change behavior. Returns "" when no version segment is obvious.
func pkgVersionFromKey(key string) string {
	switch {
	case strings.HasPrefix(key, "gomod/"):
		// gomod/<module>/@v/<version>.<ext>
		if idx := strings.Index(key, "/@v/"); idx > 0 {
			ver := key[idx+len("/@v/"):]
			if dot := strings.LastIndex(ver, "."); dot > 0 {
				return ver[:dot]
			}
			return ver
		}
	case strings.HasPrefix(key, "charts/"):
		// charts/<chart>-<version>.tgz
		base := strings.TrimSuffix(path.Base(key), ".tgz")
		if idx := strings.LastIndex(base, "-"); idx > 0 {
			return base[idx+1:]
		}
	case strings.HasPrefix(key, "npm/"):
		// npm/<safe-name>/-/<version>.tgz or npm/<safe-name>/packument.json
		base := path.Base(key)
		if strings.HasSuffix(base, ".tgz") {
			return strings.TrimSuffix(base, ".tgz")
		}
	case strings.HasPrefix(key, manifest.AptPoolPrefix):
		// packages/apt/pool/<component>/<letter>/<source>/<pkg>_<version>_<arch>.deb
		// The version lives inside the filename, not in a path segment, and
		// these are the rows that record what a fleet's dependency closure
		// actually pulled — a blank version there costs the aggregation the
		// only thing that distinguishes one install from the next.
		_, version := aptDebIdentity(path.Base(key))
		return version
	case strings.HasPrefix(key, "pypi/wheels/"):
		// pypi/wheels/<version>/<dist>-<version>-<...>.whl
		segs := strings.Split(key, "/")
		if len(segs) >= 3 {
			return segs[2]
		}
	}
	return ""
}
