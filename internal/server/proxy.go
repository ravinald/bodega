package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
	"github.com/ravinald/bodega/internal/storage"
)

// CacheConfig holds proxy/cache settings.
type CacheConfig struct {
	// Enabled controls whether the server fetches from upstream on cache miss.
	// When false, only S3-backed artifacts are served.
	Enabled bool
	// MetadataTTL is how long mutable resources (e.g. @v/list, index.yaml,
	// packument) are considered fresh before re-checking upstream.
	MetadataTTL time.Duration
}

// proxyOrCache serves an S3 object, optionally fetching from upstream on miss.
// A miss is streamed: the upstream body goes to a spool file and out from
// there, so per-request memory is a copy buffer rather than the artifact.
//
// For immutable resources (versioned artifacts), once cached they are never
// re-fetched. For mutable resources (list files, indexes), the object is
// refreshed after the configured TTL based on S3 LastModified.
//
// regType is the manifest type (apt/git/pypi/npm/gomod/helm/binary) used for
// upstream allow-list enforcement; pass "" to skip the policy check. policyCandidate
// is the string checked against the allow-list for regType — callers pass the
// upstream URL for URL-scoped types (apt/git/helm/binary) and the package name
// or module path for name-scoped types (pypi/npm/gomod).
//
// discoveryPkgName is the human-meaningful package or module identifier used
// for the discovery log and for SuggestPattern. For name-scoped types this
// matches policyCandidate; for URL-scoped types (notably helm) callers pass
// the parsed package name separately because the candidate URL on its own
// isn't a useful aggregation key.
//
// store is the backend both the cache read and the cache write use. One
// parameter, not two lookups: that is what guarantees a miss written here is
// found by the next request's Head.
//
// If proxy/cache is disabled or upstreamURL is empty, falls back to direct
// S3 proxy.
func (s *Server) proxyOrCache(w http.ResponseWriter, r *http.Request, store storage.ObjectStore, s3Key, upstreamURL, regType, policyCandidate, discoveryPkgName string, immutable, forceProxy bool) {
	var resolve upstreamResolver
	if upstreamURL != "" {
		resolve = func(context.Context) (string, error) { return upstreamURL, nil }
	}
	s.proxyOrResolve(w, r, store, s3Key, resolve, upstreamURL, regType, policyCandidate, discoveryPkgName, immutable, forceProxy)
}

// upstreamResolver produces the URL a cache miss should fetch. It runs only
// after the cache read has missed, because pypi has to read the simple index
// to learn a wheel's content-hash path and a cache hit must not pay for a
// network round trip to a URL it will never use.
//
// A resolver that returns errUpstreamNotFound is refusing on the upstream's
// behalf: the object it was asked for is not published. Anything else is a
// failure to look.
type upstreamResolver func(ctx context.Context) (string, error)

// knownUpstream is the URL a miss would fetch when the caller already holds it,
// and "" when only the resolver can produce it. It exists for the cache-hit
// path, which records a discovery row and must not pay for a resolution it will
// never use: for pypi the row's pattern hint is the package name and the host
// column is preserved by the upsert, so "" costs the row nothing.
func (s *Server) proxyOrResolve(w http.ResponseWriter, r *http.Request, store storage.ObjectStore, s3Key string, resolve upstreamResolver, knownUpstream, regType, policyCandidate, discoveryPkgName string, immutable, forceProxy bool) {
	if !s.requireStorage(w, store) {
		return
	}

	ctx := r.Context()

	status, err := store.Head(ctx, s3Key)
	if err != nil {
		s.logger.Error("s3 head check failed", "key", s3Key, "error", err)
		// Fall through to upstream fetch if proxy enabled.
	}

	// Serve from cache if:
	// - object exists AND
	// - (immutable OR within TTL)
	if status != nil && status.Exists {
		if immutable || !s.isCacheStale(status) {
			s.logger.Debug("cache hit", "key", s3Key, "immutable", immutable)
			// Before the body, not after: a client that hangs up mid-transfer
			// still asked for the artifact, and the row is the record of the
			// request rather than of the delivery.
			s.serveCacheHit(w, r, store, s3Key, func(obj cachedObject) {
				s.recordCacheHit(ctx, r, regType, knownUpstream, policyCandidate, discoveryPkgName, s3Key, obj)
			})
			return
		}
		s.logger.Debug("cache stale", "key", s3Key)
	}

	// Cache miss or stale — fetch from upstream if proxy is enabled.
	if (!s.cacheEnabled() && !forceProxy) || resolve == nil {
		if status != nil && status.Exists {
			// Stale but no upstream — serve what we have. Recorded for the
			// same reason the fresh hit is: the row counts requests, and a
			// cache the request never left is still a request.
			s.serveCacheHit(w, r, store, s3Key, func(obj cachedObject) {
				s.recordCacheHit(ctx, r, regType, knownUpstream, policyCandidate, discoveryPkgName, s3Key, obj)
			})
			return
		}
		http.NotFound(w, r)
		return
	}

	// The allow-list decides before the resolver runs, not after. For pypi the
	// resolver is a read of <pypi_upstream>/simple/{dist}/, so a verdict that
	// waits for a URL only that read can produce has already let a denied
	// distribution's name reach the index host. Every other type composes its
	// URL offline, which is why the old ordering held until pypi grew a
	// resolver. The row is written below, once there is a resolved URL to put
	// in it.
	decision, ok := s.upstreamPolicyGate(w, r, regType, knownUpstream, policyCandidate, discoveryPkgName, s3Key, true)
	if !ok {
		return
	}

	// Before the resolve rather than after it: the resolve is itself an
	// upstream read for pypi, and a line printed after it describes the second
	// fetch while leaving the first with no trace in the log at all. The URL is
	// omitted rather than logged empty where only the resolver can produce it,
	// so an operator reading the line is not told the destination is blank; the
	// line below names it as soon as it exists.
	miss := []any{"key", s3Key}
	if knownUpstream != "" {
		miss = append(miss, "upstream", knownUpstream)
	}
	s.logger.Info("cache miss, fetching upstream", miss...)

	upstreamURL, err := resolve(ctx)
	if err != nil {
		if status != nil && status.Exists {
			s.logger.Error("upstream resolution failed, serving the stale cached copy", "key", s3Key, "error", err)
			// An outage is the window an operator reads these columns in.
			// Left unrecorded, request_count and last_client go quiet exactly
			// while the upstream is down and the cache is carrying the fleet.
			s.serveCacheHit(w, r, store, s3Key, func(obj cachedObject) {
				s.recordCacheHit(ctx, r, regType, knownUpstream, policyCandidate, discoveryPkgName, s3Key, obj)
			})
			return
		}
		// The resolution attempt is an upstream contact and gets its row. A
		// wheel the index does not list 404s here, and without this write the
		// request that named it would be absent from discovery entirely.
		s.recordUpstreamAttempt(r, regType, knownUpstream, policyCandidate, discoveryPkgName, s3Key, decision)
		if errors.Is(err, errUpstreamNotFound) {
			s.logger.Info("upstream publishes no such artifact", "key", s3Key, "error", err)
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		s.logger.Error("upstream resolution failed", "key", s3Key, "error", err)
		http.Error(w, "upstream resolution failed", http.StatusBadGateway)
		return
	}
	s.recordUpstreamAttempt(r, regType, upstreamURL, policyCandidate, discoveryPkgName, s3Key, decision)

	if upstreamURL != knownUpstream {
		s.logger.Info("resolved the upstream artifact URL", "key", s3Key, "upstream", upstreamURL)
	}

	// A stale copy beats both error paths here: the upstream said something
	// went wrong, and what bodega already holds is the better answer than
	// either status code. "The upstream does not publish this" is not a
	// gateway failure, and conflating the two makes every unpublished path
	// read as an outage.
	fail := func(err error) {
		if status != nil && status.Exists {
			s.logger.Error("upstream fetch failed, serving the stale cached copy", "url", upstreamURL, "error", err)
			// The audit row, not the discovery row. This branch is below the
			// allow-list gate, which already recorded the attempt for this
			// request, and a second discovery write would bump request_count
			// twice for one client fetch — the counting error B16 fixed in the
			// other direction. The cache row has no such double: the response
			// is cached bytes, and an outage is precisely the window an
			// operator asks which artifacts the cache is carrying.
			s.serveCacheHit(w, r, store, s3Key, func(obj cachedObject) {
				s.recordCacheServed(r, regType, policyCandidate, discoveryPkgName, s3Key, obj)
			})
			return
		}
		if errors.Is(err, errUpstreamNotFound) {
			s.logger.Debug("upstream has no such object", "url", upstreamURL)
			http.NotFound(w, r)
			return
		}
		s.logger.Error("upstream fetch failed", "url", upstreamURL, "error", err)
		http.Error(w, "upstream fetch failed", http.StatusBadGateway)
	}

	up, err := openUpstream(ctx, upstreamURL)
	if err != nil {
		fail(err)
		return
	}
	defer up.body.Close()

	spool, err := s.spoolUpstream(up)
	if err != nil {
		if reason := spoolDenialReason(err); reason != "" {
			s.recordSpoolRefusal(r, regType, discoveryPkgName, s3Key, reason, err)
			if status != nil && status.Exists {
				// A cached copy beats a 503 the client has to come back for,
				// and serving it costs no spool at all — which is the point
				// when the spool is what ran out.
				//
				// Two rows for one request, and they say different things: the
				// denial names the bound that fired, the cache row names the
				// bytes the client got. Either one alone leaves a 200 response
				// whose artifact came from the cache indistinguishable from a
				// request that was simply refused.
				s.serveCacheHit(w, r, store, s3Key, func(obj cachedObject) {
					s.recordCacheServed(r, regType, policyCandidate, discoveryPkgName, s3Key, obj)
				})
				return
			}
			// 503 and Retry-After rather than the 502 fail() would give: this
			// is a bound on this host, not a fault at the upstream, and an
			// operator sent to check the upstream is being sent to the wrong
			// place. See spoolLimiter for why the answer is a refusal and not
			// a queue.
			w.Header().Set("Retry-After", spoolRetryAfter)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		fail(err)
		return
	}
	defer spool.close()

	// Verification comes off the digest computed during the copy, and it comes
	// before a byte reaches the client. A tee straight to the response would
	// have already handed the client an artifact by the time the mismatch is
	// known, and a truncated response is not a refusal.
	if err := s.verifyProxyChecksum(ctx, s3Key, spool.sha256, immutable); err != nil {
		s.logger.Error("checksum verification failed", "key", s3Key, "error", err)
		http.Error(w, "checksum verification failed — upstream content may be tampered", http.StatusBadGateway)
		return
	}

	// Cache to storage (best-effort — don't fail the response if caching fails).
	// The read above and this write take the same store parameter: resolving
	// them separately is how a cache entry lands in a backend the next Head
	// never looks at.
	if store != nil {
		s.fillCache(ctx, store, s3Key, spool.path(), up.url, spool.sha256, spool.size)
	}

	// After the store write and before the body: by here the fetch has been
	// verified and cached, so the row names an upstream that actually answered
	// rather than one that was contacted. A client that hangs up during the
	// copy below still caused the fetch, and the row is the record of it.
	//
	// up.url, not upstreamURL: the row answers which host supplied these
	// bytes. The candidate bodega composed is what the allow-list ruled on and
	// what discovery aggregates, and recordUpstreamAttempt above has already
	// recorded it under both of those meanings.
	s.recordCacheEvent(r, audit.CacheMiss, regType, up.url, policyCandidate, discoveryPkgName, s3Key)

	ct := up.contentType
	if ct == "" {
		ct = contentTypeForKey(s3Key)
	}
	if ct == "" {
		ct = "application/octet-stream"
	}
	if _, err := spool.file.Seek(0, io.SeekStart); err != nil {
		s.logger.Error("could not rewind the spooled artifact", "key", s3Key, "error", err)
		http.Error(w, "upstream fetch failed", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", spool.size))
	w.WriteHeader(http.StatusOK)
	//nolint:gosec // G705: response body is the upstream artifact bytes; Content-Type is set above.
	if _, err := io.Copy(w, spool.file); err != nil {
		// The status line is already out, so there is nothing to tell the
		// client. The object is cached and the next request serves it.
		s.logger.Warn("client read of a proxied artifact was cut short", "key", s3Key, "error", err)
	}
}

// cacheEnabled returns true if the proxy/cache feature is active.
func (s *Server) cacheEnabled() bool {
	return s.cache.Enabled
}

// isCacheStale checks if a cached S3 object has exceeded the metadata TTL.
func (s *Server) isCacheStale(status *storage.ObjectInfo) bool {
	if s.cache.MetadataTTL <= 0 {
		return false
	}
	return time.Since(status.LastModified) > s.cache.MetadataTTL
}

// upstreamClient is a dedicated HTTP client for upstream fetches with an
// explicit timeout so that slow or unresponsive upstreams cannot hold
// goroutines open indefinitely.
//
// CheckRedirect re-runs the SSRF guard on every hop. The guard is applied to
// the URL bodega composed, and a registry that answers 302 chooses the next
// one: without this, an upstream could walk the fetch to the metadata service
// or onto the loopback interface and the validated first hop would be the only
// address anything checked.
//
// It restates the hop count too, because supplying CheckRedirect replaces
// net/http's own limit rather than adding a second check to it. An upstream
// redirecting to itself would otherwise spend a request per hop and hold the
// client's until Timeout fires.
var upstreamClient = &http.Client{
	Timeout: 90 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxUpstreamRedirects {
			return fmt.Errorf("stopped after %d redirects", len(via))
		}
		return upstreamGuard(req.URL.String())
	},
}

// maxUpstreamRedirects is net/http's own default, restated because
// upstreamClient's CheckRedirect displaces it.
const maxUpstreamRedirects = 10

// validateUpstreamURL rejects URLs that use non-HTTPS schemes or resolve to
// private/loopback addresses, mitigating SSRF attacks via upstream proxying.
func validateUpstreamURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid upstream URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("upstream URL must use https, got %q", u.Scheme)
	}
	host := u.Hostname()
	//nolint:gosec // G704: this lookup IS the SSRF defense — we resolve the host to inspect IPs and reject loopback / private / link-local before returning.
	ips, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("cannot resolve upstream host %q: %w", host, err)
	}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("upstream resolves to non-routable IP %s", ipStr)
		}
	}
	return nil
}

// errUpstreamNotFound reports that the upstream does not publish the object,
// which is a different thing from the upstream being unreachable and has to
// reach the client as a different status.
//
// Two things produce it: a 404 from the fetch, and a pypi simple index that
// answered 200 and listed no such file. The message states the shared fact
// rather than the mechanism, because each wrapper names its own.
//
// apt makes the distinction load-bearing: an archive publishes no Packages for
// an architecture or component it does not carry, and apt treats that 404 as
// the ordinary "not published here" and moves on. A 502 in its place is a
// server fault the operator has to chase, on every arch and component a mirror
// legitimately lacks.
var errUpstreamNotFound = errors.New("the upstream does not publish this")

// maxUpstreamBody caps an upstream body a caller reads into memory whole.
//
// It covers the two metadata fetches that have to parse what they get — the
// npm packument and the pypi simple index — and no longer covers artifacts:
// proxyOrResolve spools those to disk and streams them, so their size is
// bounded by the spool filesystem rather than by process memory.
//
// Exceeding it is an error, never a truncation. io.LimitReader reports EOF at
// its limit and io.ReadAll returns that as a complete body with a nil error,
// which is indistinguishable downstream from a whole body.
//
// A variable rather than a constant so a test can drive the over-limit path
// without moving a quarter of a gigabyte through it. Nothing in the shipped
// binary assigns to it.
var maxUpstreamBody int64 = 256 << 20

// upstreamGuard is the check every upstream fetch clears before a request
// leaves the process, held in a variable so a test can point a fixture archive
// at a loopback listener — the case the real guard exists to refuse.
//
// Nothing in the shipped binary rebinds it: no config value reaches it, it is
// unexported, and internal/server has no non-test caller that assigns to it.
var upstreamGuard = validateUpstreamURL

// upstreamStream is one upstream response whose body has not been read. The
// caller closes body.
type upstreamStream struct {
	// url is the address that answered, which is the last hop of any redirect
	// chain and not necessarily the one bodega composed. The two are the same
	// artifact only in the sense that one pointed at the other: a redirector
	// supplies no bytes, so crediting it in the trail names a host an incident
	// would then go and look at for content it never held.
	url           string
	body          io.ReadCloser
	contentType   string
	contentLength int64 // -1 when the upstream declared none
}

// openUpstream performs the fetch and maps its status, leaving the body for
// the caller to read or to stream. It is the one place the SSRF guard and the
// 404-versus-outage distinction live.
func openUpstream(ctx context.Context, rawURL string) (*upstreamStream, error) {
	if err := upstreamGuard(rawURL); err != nil {
		return nil, err
	}
	//nolint:gosec // G704: rawURL was just validated by validateUpstreamURL above (https-only, non-loopback, non-private).
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}

	//nolint:gosec // G704: see comment on NewRequestWithContext above; URL is validated.
	resp, err := upstreamClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, fmt.Errorf("%w: %s returned 404", errUpstreamNotFound, rawURL)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("upstream returned %d: %s", resp.StatusCode, rawURL)
	}

	// resp.Request is the last request in the chain, so its URL is the server
	// that produced this body. It is nil for no response net/http returns, but
	// the fallback keeps a future transport from leaving the field empty.
	answered := rawURL
	if resp.Request != nil && resp.Request.URL != nil {
		answered = resp.Request.URL.String()
	}

	return &upstreamStream{
		url:           answered,
		body:          resp.Body,
		contentType:   resp.Header.Get("Content-Type"),
		contentLength: resp.ContentLength,
	}, nil
}

// spooledUpstream is an upstream body written to a temp file, with the digest
// computed on the way through.
//
// Disk rather than memory is what removes the size ceiling: an artifact costs
// one copy buffer of process memory whatever its length, so a handful of
// concurrent large fetches no longer takes the process out. What it costs
// instead is disk under spool_dir, which spoolLimiter is the bound on.
type spooledUpstream struct {
	file   *os.File
	size   int64
	sha256 string
	res    *spoolReservation
}

func (sp *spooledUpstream) path() string { return sp.file.Name() }

// close removes the spool file and returns its bytes to the shared budget. The
// name is read before the descriptor is closed because that is the only handle
// on it: the file is not unlinked at creation, since PutFile takes a path.
func (sp *spooledUpstream) close() {
	name := sp.file.Name()
	_ = sp.file.Close()
	_ = os.Remove(name)
	sp.res.release()
}

// spoolUpstream copies an upstream body to a file under spool_dir, hashing as
// it goes, and returns it positioned at EOF. It is bounded on both axes by
// s.spool: one artifact against spool_max_artifact_bytes, every fetch in
// flight against the shared spool_max_total_bytes budget.
//
// A body shorter than the length the upstream declared is a cut transfer and
// fails here rather than being cached: chunked and transparently-decompressed
// responses report -1 and are exempt, so this only fires where the upstream
// stated a number. Caching short bytes was the failure that made every later
// fetch of the real artifact fail verification against the truncated digest.
func (s *Server) spoolUpstream(up *upstreamStream) (*spooledUpstream, error) {
	res, err := s.spool.begin(up.contentLength)
	if err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(s.spool.dir, "bodega-upstream-*")
	if err != nil {
		res.release()
		return nil, fmt.Errorf("create spool file in %s: %w", s.spool.dir, err)
	}
	sp := &spooledUpstream{file: f, res: res}

	h := sha256.New()
	sw := &spoolWriter{w: io.MultiWriter(f, h), res: res, max: s.spool.maxArtifact}
	n, err := io.Copy(sw, up.body)
	sp.size = n
	if err != nil {
		// A spool refusal is not a cut transfer and must not be reported as
		// one: the message below tells an operator to go and check the
		// upstream, which is the wrong place to look when the bound that
		// fired is this host's.
		if spoolDenialReason(err) != "" {
			sp.close()
			return nil, err
		}
		// net/http reports a cut transfer as ErrUnexpectedEOF here, before the
		// declared-length check below ever runs, so this message has to carry
		// the same fact: the spool is removed and nothing was cached.
		sp.close()
		return nil, fmt.Errorf("read upstream body from %s after %d bytes: %w — nothing was cached; retry, and check the upstream if it repeats", up.url, n, err)
	}
	if up.contentLength >= 0 && n != up.contentLength {
		sp.close()
		return nil, fmt.Errorf("upstream sent %d bytes against a declared Content-Length of %d: %s — the transfer was cut and nothing was cached; retry, and check the upstream if it repeats",
			n, up.contentLength, up.url)
	}
	sp.sha256 = hex.EncodeToString(h.Sum(nil))
	return sp, nil
}

// fetchUpstream downloads a URL into memory and returns the body bytes and
// content type. For a caller that has to parse what it gets; an artifact goes
// through openUpstream and spoolUpstream instead.
func fetchUpstream(ctx context.Context, rawURL string) ([]byte, string, error) {
	up, err := openUpstream(ctx, rawURL)
	if err != nil {
		return nil, "", err
	}
	defer up.body.Close()

	// A declared length over the cap is refusable before a byte is read.
	if up.contentLength > maxUpstreamBody {
		return nil, "", fmt.Errorf("upstream declares %d bytes, over bodega's %d-byte buffer: %s — nothing was cached; this response has to be parsed in memory and cannot carry that much",
			up.contentLength, maxUpstreamBody, rawURL)
	}

	// One byte past the cap. Anything read there means the body was longer
	// than the buffer, which has to fail rather than return short bytes the
	// checksum would then bless.
	data, err := io.ReadAll(io.LimitReader(up.body, maxUpstreamBody+1))
	if err != nil {
		return nil, "", fmt.Errorf("read upstream body: %w", err)
	}
	if int64(len(data)) > maxUpstreamBody {
		return nil, "", fmt.Errorf("upstream body exceeds bodega's %d-byte buffer: %s — nothing was cached; fetch this artifact out of band or serve it from storage",
			maxUpstreamBody, rawURL)
	}
	// A body shorter than the length the upstream declared is a cut transfer.
	// Chunked and transparently-decompressed responses report -1 and are
	// exempt, so this only fires where the upstream stated a number.
	if up.contentLength >= 0 && int64(len(data)) != up.contentLength {
		return nil, "", fmt.Errorf("upstream sent %d bytes against a declared Content-Length of %d: %s — the transfer was cut and nothing was cached; retry, and check the upstream if it repeats",
			len(data), up.contentLength, rawURL)
	}

	return data, up.contentType, nil
}

// verifyProxyChecksum verifies a fetched artifact's SHA-256 against the stored
// checksum in the audit DB. On first fetch (no stored checksum), it stores the
// computed digest. On mismatch, returns an error — the caller must NOT cache
// or serve the artifact.
//
// It takes the digest rather than the bytes: the artifact is streamed to a
// spool file and hashed on the way, so nothing here ever holds it.
//
// Only runs for immutable resources (versioned artifacts). Mutable resources
// (list files, indexes) change by design and are not checksummed.
func (s *Server) verifyProxyChecksum(ctx context.Context, s3Key, computed string, immutable bool) error {
	if !immutable {
		return nil // mutable resources are not checksummed
	}
	if s.auditDB == nil {
		return nil // no audit DB, skip verification
	}

	// Look up stored checksum.
	stored, err := s.auditDB.GetChecksum(ctx, s3Key)
	if err != nil {
		s.logger.Error("checksum DB unavailable, refusing to serve immutable resource", "key", s3Key, "error", err)
		return fmt.Errorf("checksum lookup unavailable: %w", err)
	}

	// A row with no value is a digest an operator cleared to escape an upstream
	// that republished different bytes. The row itself is kept because the apt
	// index reads it to tell a mirrored .deb from a built one, so "no digest"
	// arrives as a blank value rather than a missing row and takes the
	// first-fetch path (#225).
	if stored == nil || stored.Value == "" {
		// First fetch — store the computed checksum.
		pkgType, pkgName, pkgVersion := manifest.ParseKey(s3Key)
		if err := s.auditDB.StoreChecksum(ctx, s3Key, pkgType, pkgName, pkgVersion, "sha256", computed, "computed"); err != nil {
			s.logger.Warn("failed to store checksum", "key", s3Key, "error", err)
		} else {
			s.logger.Info("checksum stored", "key", s3Key, "sha256", computed[:12]+"...")
		}
		return nil
	}

	// Verify against stored checksum.
	if stored.Value != computed {
		// Record the mismatch in the audit trail.
		if s.auditDB != nil {
			details, _ := json.Marshal(map[string]string{
				"expected": stored.Value,
				"computed": computed,
				"s3_key":   s3Key,
			})
			_ = s.auditDB.Record(ctx, audit.Event{
				EventType:  audit.EventCache,
				PkgType:    stored.PkgType,
				PkgName:    stored.PkgName,
				PkgVersion: stored.PkgVersion,
				Status:     audit.CacheChecksumMismatch,
				Details:    string(details),
			})
		}
		return fmt.Errorf("sha256 mismatch for %s: stored=%s computed=%s", s3Key, shortDigest(stored.Value), shortDigest(computed))
	}

	s.logger.Debug("checksum verified", "key", s3Key)
	return nil
}

// shortDigest is the leading hex of a digest, enough to name which two
// disagreed without printing two 64-character strings.
//
// It takes the whole value when it is shorter. A stored value is whatever the
// table holds, and a panic on the slice would turn the refusal into a dropped
// connection, which a client reports as a network fault rather than as the
// checksum gate saying no.
func shortDigest(v string) string {
	if len(v) <= 12 {
		return v
	}
	return v[:12] + "..."
}

// upstreamPolicyVerdict is the allow-list decision for one candidate, with no
// response written and no discovery row. Decisions are:
//
//	no_policy : no rules configured for this type, so nothing was checked
//	allowed   : a rule matched
//	denied    : a rule exists and none matched; the caller must refuse
//
// A non-nil error means the check itself could not run, which is a 500 rather
// than a refusal — the caller decides. It is separate from
// enforceUpstreamPolicyRecording because the apt pool probe checks several candidates
// to answer one request: recording a row per candidate would count one client
// fetch as many, and the row is written once by the fetch that follows.
func (s *Server) upstreamPolicyVerdict(ctx context.Context, regType, policyCandidate string) (string, bool, error) {
	hasRules, hasRulesErr := s.policy.HasRules(ctx, regType)
	if hasRulesErr != nil {
		s.logger.Error("policy rules lookup failed", "error", hasRulesErr)
	}
	err := s.policy.Check(ctx, regType, policyCandidate)
	violation := err != nil && policy.IsViolation(err)
	if err != nil && !violation {
		return "", false, err
	}
	return classifyDecision(hasRules, violation), violation, nil
}

// enforceUpstreamPolicyRecording runs the allow-list check and writes the
// discovery row for one upstream attempt, returning false when it has already
// written the response and the caller must stop.
//
// A nil checker or an empty regType means policy is disabled (opt-in feature).
// discover_mode decides whether the attempt is recorded and nothing else: a
// violation is refused at every mode.
//
// It is a method rather than inline in proxyOrCache because the git smart-HTTP
// handler never reaches proxyOrCache: it execs git-http-backend against a local
// mirror instead of fetching an object. Two copies of an allow-list gate is one
// copy that stops matching the other.
//
// record exists for a protocol whose single client operation reaches the gate
// more than once. One `git clone` is two requests, an info/refs GET and a
// git-upload-pack POST, and both have to pass the allow-list. Recording both
// would make the discovery table count protocol legs for git and requests for
// every other type, so an operator comparing counts across types reads git as
// twice as busy as it is. The refusal is unconditional; only the row is not.
//
// proxyOrResolve does not call this. It cannot name its upstream URL until
// after the gate has run, so it drives upstreamPolicyGate and
// recordUpstreamAttempt directly.
func (s *Server) enforceUpstreamPolicyRecording(w http.ResponseWriter, r *http.Request, regType, upstreamURL, policyCandidate, discoveryPkgName, s3Key string, record bool) bool {
	decision, ok := s.upstreamPolicyGate(w, r, regType, upstreamURL, policyCandidate, discoveryPkgName, s3Key, record)
	if !ok {
		return false
	}
	if record {
		s.recordUpstreamAttempt(r, regType, upstreamURL, policyCandidate, discoveryPkgName, s3Key, decision)
	}
	return true
}

// upstreamPolicyGate is the refusal half of enforceUpstreamPolicyRecording: the verdict,
// the 403 and the denial row, with the allowed case's discovery row left to the
// caller. It returns the decision the caller should record and false once it
// has written the response.
//
// The split exists so a caller that cannot name its upstream URL yet can still
// be refused before it goes looking for one. proxyOrResolve is that caller: for
// pypi the URL comes back from a fetch of the simple index, so a gate that
// needed the URL first would let the denied name reach the index host.
// A refusal records what it knows, which on that path is no URL at all; the
// allowed case records once the resolver has produced one.
func (s *Server) upstreamPolicyGate(w http.ResponseWriter, r *http.Request, regType, upstreamURL, policyCandidate, discoveryPkgName, s3Key string, record bool) (string, bool) {
	if s.policy == nil || regType == "" || policyCandidate == "" {
		return "", true
	}
	// Detached, for the reason recordCacheHit detaches: net/http cancels
	// r.Context() the moment the client hangs up, and on a cold rule cache the
	// verdict is a database read. Run on the request context it fails, the
	// handler answers 500 and returns above the deny branch, so the 403 and
	// its row are both lost for the scanner-shaped callers the row exists to
	// name.
	ctx, cancel := auditContext(r)
	defer cancel()
	decision, violation, err := s.upstreamPolicyVerdict(ctx, regType, policyCandidate)
	if err != nil {
		s.logger.Error("policy check failed", "error", err)
		http.Error(w, "policy check failed", http.StatusInternalServerError)
		return "", false
	}
	if violation {
		if record {
			s.recordDiscovery(ctx, r, regType, upstreamURL, policyCandidate, discoveryPkgName, s3Key, decision)
		}
		// The URL is omitted rather than logged empty, for the reason the
		// cache-miss line above omits it: on the pypi path only the resolver
		// can produce one, and it is the refusal that stops it from running.
		// url="" reads as a bug in the refusal to whoever is holding the log.
		blocked := []any{"type", regType, "candidate", policyCandidate}
		if upstreamURL != "" {
			blocked = append(blocked, "url", upstreamURL)
		}
		s.logger.Warn("upstream blocked by policy", blocked...)
		s.recordPolicyViolation(r, regType, policyCandidate, upstreamURL)
		http.Error(w, "upstream blocked by allow-list", http.StatusForbidden)
		return decision, false
	}
	return decision, true
}

// recordUpstreamAttempt writes the discovery row for one permitted upstream
// attempt, so operators can review what the fleet reached for and later promote
// a captured host or package to an allow-list rule.
//
// An empty decision means upstreamPolicyGate found policy disabled for this
// caller and checked nothing; there is no verdict to put in the column, and a
// row claiming one would be a fabrication.
func (s *Server) recordUpstreamAttempt(r *http.Request, regType, upstreamURL, policyCandidate, discoveryPkgName, s3Key, decision string) {
	if decision == "" {
		return
	}
	ctx, cancel := auditContext(r)
	defer cancel()
	s.recordDiscovery(ctx, r, regType, upstreamURL, policyCandidate, discoveryPkgName, s3Key, decision)
}

// recordPolicyViolation writes the audit row for one candidate the allow-list
// refused. Separate from the discovery row: discovery answers "what did the
// fleet reach for", the audit table answers "who was turned away", and an
// operator asking the second question queries GET /api/v1/audit.
//
// The refusal stands whether or not the row lands: an audit database that
// cannot be written is not a reason to let a blocked upstream through. It is a
// reason to say so loudly, naming the event, so a reconstruction from the log
// is possible when the table is missing the row.
func (s *Server) recordPolicyViolation(r *http.Request, regType, policyCandidate, upstreamURL string) {
	if s.auditDB == nil {
		return
	}
	ctx, cancel := auditContext(r)
	defer cancel()
	if err := s.auditDB.Record(ctx, audit.Event{
		EventType: audit.EventCache,
		PkgType:   regType,
		PkgName:   policyCandidate,
		Status:    audit.CachePolicyViolation,
		Details:   fmt.Sprintf("url=%s", upstreamURL),
	}); err != nil {
		s.logger.Error("audit write failed, denial not recorded — still refusing",
			"event_type", audit.EventCache, "status", audit.CachePolicyViolation,
			"type", regType, "candidate", policyCandidate, "url", upstreamURL,
			"error", err)
	}
}

// recordCacheEvent writes the audit row for one proxy outcome: an artifact the
// cache answered, or one this request fetched from upstream and stored.
//
// It is separate from the discovery row recordCacheHit also writes. Discovery
// answers "what did the fleet reach for" and is off unless discover_mode is
// set; the audit trail answers "which artifacts came from upstream", which is
// the first question an incident asks and has no other source. Sharing one
// guard is how the cache row went unwritten on every install that left
// discover_mode at its default.
//
// The upstream goes in details rather than a column because no column names a
// host, and an operator reading a cache_miss row needs to know which registry
// answered before anything else in the row is actionable.
func (s *Server) recordCacheEvent(r *http.Request, status, regType, upstreamURL, policyCandidate, discoveryPkgName, s3Key string) {
	if s.auditDB == nil || !s.auditDB.ShouldRecord(audit.EventCache) {
		return
	}
	// The key names all three, and it is the only source that agrees with what
	// was served: the version in particular exists nowhere else on this path.
	keyType, keyName, pkgVersion := manifest.ParseKey(s3Key)
	pkgType := regType
	if pkgType == "" {
		pkgType = keyType
	}
	// Same precedence recordDiscovery uses, for the same reason: the caller
	// read the name off the request path and can tell a literal "--" from an
	// encoded "/", and ParseKey cannot.
	pkgName := discoveryPkgName
	if pkgName == "" {
		pkgName = keyName
	}
	if pkgName == "" {
		pkgName = policyCandidate
	}
	fields := map[string]string{
		"upstream": truncateField(upstreamURL, maxDetailField),
		"key":      truncateField(s3Key, maxDetailField),
	}
	if status == audit.CacheHit && upstreamURL == "" {
		fields["upstream_origin"] = cacheOriginUnrecorded
	}
	details, err := json.Marshal(fields)
	if err != nil {
		details = []byte("{}")
	}
	ctx, cancel := auditContext(r)
	defer cancel()
	if err := s.auditDB.Record(ctx, audit.Event{
		EventType:  audit.EventCache,
		PkgType:    pkgType,
		PkgName:    pkgName,
		PkgVersion: pkgVersion,
		ClientIP:   ClientIP(r),
		Identity:   Identity(r),
		UserAgent:  truncateField(r.UserAgent(), maxDetailField),
		Status:     status,
		Details:    string(details),
	}); err != nil {
		s.logger.Error("audit write failed, proxy outcome not recorded — still serving",
			"event_type", audit.EventCache, "status", status,
			"key", s3Key, "upstream", upstreamURL, "error", err)
	}
}

// cacheOriginUnrecorded marks a cache_hit whose object's origin nothing
// recorded: cached before bodega kept origins, or filled by a path that
// fetches nothing. Named in the row rather than left silent, because an empty
// upstream field on its own reads as a write that dropped it.
const cacheOriginUnrecorded = "unrecorded"

// recordCacheServed writes the audit row for a response the cache answered,
// naming the upstream that supplied those bytes rather than the one the caller
// would fetch from today.
//
// The two differ more often than the old code assumed. The pypi wheel route
// holds no URL at all on a hit, because composing one costs a read of the
// simple index that a hit exists to avoid; an operator who edits
// gomod_upstream makes every later hit credit a host that answered nothing;
// and a restart leaves the resolved URL nowhere in memory. Reading the origin
// back is a primary-key lookup in the embedded store, so the hit still
// contacts no network.
func (s *Server) recordCacheServed(r *http.Request, regType, policyCandidate, discoveryPkgName, s3Key string, obj cachedObject) {
	if s.auditDB == nil || !s.auditDB.ShouldRecord(audit.EventCache) {
		return
	}
	s.recordCacheEvent(r, audit.CacheHit, regType, s.cachedOrigin(r, s3Key, obj), policyCandidate, discoveryPkgName, s3Key)
}

// cachedOrigin is the upstream recorded for the object obj identifies at
// s3Key, or "" when none is.
//
// The fallback to an in-flight fill covers the window between a fetch's bytes
// becoming readable and its origin row landing. A request arriving inside it
// reads an object that exists and finds no row for it, and recording the fetch
// it is reading the result of as unrecorded would be wrong about a fetch this
// process is in the middle of making. Reading the pending attribution is a map
// lookup, so no request waits for another's store write.
func (s *Server) cachedOrigin(r *http.Request, s3Key string, obj cachedObject) string {
	ctx, cancel := auditContext(r)
	defer cancel()
	origin, err := s.auditDB.CacheOrigin(ctx, s3Key, obj.id)
	if err != nil {
		// Unknown, not guessed. The row says the origin is unrecorded, which
		// is the honest answer to a lookup that could not run.
		s.logger.Warn("cache origin lookup failed, the hit row cannot name its upstream",
			"key", s3Key, "error", err)
		return ""
	}
	if origin == "" {
		origin = s.pendingOrigin(ctx, s3Key, obj)
	}
	return origin
}

// pendingOrigin is the upstream of an in-flight fill of s3Key, when the bytes
// that fill is publishing are the ones obj was opened on.
//
// Confirmed by digest, not by length: a fill is exactly the window another
// writer's artifact can arrive in, and two objects of one length at one key
// are not one object. The hash runs only where a fill of that key is open,
// which is the rare case this fallback exists for, and it is compared against
// the identity the serving handle reported so that the bytes verified are the
// bytes leaving.
func (s *Server) pendingOrigin(ctx context.Context, s3Key string, obj cachedObject) string {
	if obj.store == nil || !obj.id.Known() || !s.fills.inFlight(s3Key) {
		return ""
	}
	id, digest, err := identifyObject(ctx, obj.store, s3Key)
	if err != nil {
		s.logger.Warn("the cached object could not be read back, a fill in flight cannot be credited with it",
			"key", s3Key, "error", err)
		return ""
	}
	if id != obj.id {
		return ""
	}
	return s.fills.pending(s3Key, digest)
}

// fillCache writes the fetched artifact to the store and records which
// upstream supplied it, holding s3Key against readers for the whole of it.
//
// The order is forced from both ends. Recording first would attribute bytes
// that may never land, and a hit on whatever is already at the key would read
// that attribution back. Recording after without the hold leaves the window
// this gate exists for: the object is readable the instant PutFile returns,
// and a request arriving before the row lands sees a fill it cannot name.
// Caching is best effort and a failed write is not the client's problem, which
// is why nothing here is returned.
func (s *Server) fillCache(ctx context.Context, store storage.ObjectStore, s3Key, localPath, upstreamURL, digest string, size int64) {
	release := s.fills.hold(s3Key, upstreamURL, digest)
	defer release()

	if err := store.PutFile(ctx, localPath, s3Key); err != nil {
		s.logger.Warn("failed to cache object", "key", s3Key, "error", err)
		return
	}
	s.logger.Debug("cached object", "key", s3Key, "bytes", size)
	s.recordCacheOrigin(ctx, store, s3Key, upstreamURL, digest)
}

// recordCacheOrigin remembers which upstream supplied the bytes just written
// to s3Key. It runs only after the store write succeeded: an origin for bytes
// that never landed would be read back by a hit on somebody else's object.
//
// The read back is what binds the row to this fetch's bytes rather than to
// their key, and digest is what this fetch wrote. A Head in its place answers
// what is at the key now, so an upload that landed while the fetch was in
// flight is identified instead, and its identity is then persisted against an
// upstream that supplied none of it — after which every later comparison
// succeeds on the wrong association. Nothing in bodega can order that upload
// against this write: `pkg upload` goes through the placer, a second process
// goes through neither, and a lock held here covers neither of them.
//
// The identity comes off the same read as the digest for the same reason, and
// the store's account of the object is what a hit compares against; a backend
// that rewrites length or timestamp on ingest would make its own fills fail to
// match if this measured the spool instead.
//
// The cost is one read of the object per fill. It sits on the caching path
// rather than the serving one, where the alternative is an origin trail that
// is wrong rather than incomplete.
func (s *Server) recordCacheOrigin(ctx context.Context, store storage.ObjectStore, s3Key, upstreamURL, digest string) {
	if s.auditDB == nil || s3Key == "" || upstreamURL == "" || digest == "" {
		return
	}
	// Detached for the reason every other write on this path is: the copy to
	// the client has not started yet, and a client that hangs up here would
	// otherwise leave a cached object nothing can attribute.
	octx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditWriteTimeout)
	defer cancel()

	id, stored, err := identifyObject(octx, store, s3Key)
	if err != nil {
		s.logger.Warn("cached object could not be identified, a later hit cannot name its upstream",
			"key", s3Key, "error", err)
		return
	}
	if stored != digest {
		s.logger.Warn("the cached object is not the one this fetch wrote, origin left unrecorded",
			"key", s3Key, "upstream", upstreamURL,
			"fetched", shortDigest(digest), "stored", shortDigest(stored))
		return
	}
	if err := s.auditDB.StoreCacheOrigin(octx, s3Key, upstreamURL, id); err != nil {
		s.logger.Warn("cache origin not recorded, a later hit on this key cannot name its upstream",
			"key", s3Key, "upstream", upstreamURL, "error", err)
	}
}

// cachedObject is the object a served response came out of: the identity the
// store reported when the handle supplying the bytes was opened, and the store
// that opened it.
//
// The two travel together because a recorded origin is a claim about bytes.
// Confirming it against an in-flight fill means reading those bytes back, and
// the store that answered the open is the only one that can be asked.
type cachedObject struct {
	store storage.ObjectStore
	id    audit.ObjectIdentity
}

// streamIdentity is what the store said about the object an open handle is on,
// in the form the audit store compares. The zero value is what a caller with
// no metadata in hand produces, and it matches no recorded origin.
func streamIdentity(store storage.ObjectStore, res *storage.StreamResult) audit.ObjectIdentity {
	if store == nil || res == nil {
		return audit.ObjectIdentity{}
	}
	obj := audit.ObjectIdentity{
		Backend: store.Label(),
		Size:    res.ContentLength,
		ETag:    res.ETag,
	}
	if !res.LastModified.IsZero() {
		obj.Modified = res.LastModified.UTC().Format(time.RFC3339Nano)
	}
	return obj
}

// identifyObject reads the object at s3Key and reports both what the store
// said about that open and the digest of what it read.
//
// Both halves come off one operation on purpose. A Head answers what sits at a
// key at the moment it is asked, which is somebody else's artifact whenever a
// writer landed since, and the digest is the only field a second writer cannot
// reproduce by landing bytes of the same length in the same clock tick. It
// costs a read of the object, so the callers are the ones binding provenance:
// a fill recording where its bytes came from, and a hit arriving while that
// fill is still publishing.
func identifyObject(ctx context.Context, store storage.ObjectStore, s3Key string) (audit.ObjectIdentity, string, error) {
	res, err := store.GetStream(ctx, s3Key)
	if err != nil {
		return audit.ObjectIdentity{}, "", err
	}
	if res == nil {
		return audit.ObjectIdentity{}, "", fs.ErrNotExist
	}
	defer func() { _ = res.Body.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, res.Body); err != nil {
		return audit.ObjectIdentity{}, "", err
	}
	return streamIdentity(store, res), hex.EncodeToString(h.Sum(nil)), nil
}

// serveCacheHit records what the cache answered and then answers it, taking
// the object's identity from the handle that supplies the bytes.
//
// One open, used for both. Recording off the Head that decided the request was
// a hit names whatever sat at the key at decision time, and an upload landing
// between that Head and this open is then served under the previous tenant's
// attribution.
func (s *Server) serveCacheHit(w http.ResponseWriter, r *http.Request, store storage.ObjectStore, s3Key string, record func(cachedObject)) {
	res, ok := s.openStored(w, r, store, s3Key)
	if !ok {
		return
	}
	defer func() { _ = res.Body.Close() }()
	record(cachedObject{store: store, id: streamIdentity(store, res)})
	s.serveStored(w, s3Key, res)
}

// cacheFills is the attribution for keys whose proxied bytes have reached the
// store and whose origin row has not. A hit landing in that window reads the
// pending entry, so a fill this process is making is never recorded as a fetch
// nobody can account for.
//
// Registered before the store write rather than after it, because an object
// becomes readable partway through PutFile and not when it returns; cleared
// only once the row is durable in the audit store, so the two never both miss.
// Nothing here blocks: a reader takes a map lookup, and two requests that miss
// the same key still fetch concurrently as they did before.
//
// In-process by construction, which is the scope of the window it covers. A
// second bodega's fill is invisible here, and a hit racing it finds no row and
// says unrecorded, which is a missing answer rather than a wrong one.
type cacheFills struct {
	mu   sync.Mutex
	held map[string][]*cacheFill
}

// cacheFill is one fetch being published to a key: where the bytes came from,
// and what they hash to.
type cacheFill struct {
	upstream string
	digest   string
}

// hold registers a fetch being published to key and returns the release, which
// the caller runs once the origin row is written. Every hold must be released:
// a leaked one goes on attributing that key to a fetch that has finished.
func (c *cacheFills) hold(key, upstream, digest string) func() {
	f := &cacheFill{upstream: upstream, digest: digest}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.held == nil {
		c.held = make(map[string][]*cacheFill)
	}
	c.held[key] = append(c.held[key], f)
	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		rest := c.held[key][:0]
		for _, other := range c.held[key] {
			if other != f {
				rest = append(rest, other)
			}
		}
		if len(rest) == 0 {
			delete(c.held, key)
			return
		}
		c.held[key] = rest
	}
}

// inFlight reports whether any fetch is publishing to key. It is the cheap
// half of the fallback: pending's answer needs the digest of what the store
// holds, and reading that back is worth doing only where a fill is open.
func (c *cacheFills) inFlight(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.held[key]) > 0
}

// pending is the upstream of an in-flight fill of key that fetched the bytes
// digest names, or "" when none did.
//
// The digest is what keeps the fallback from crediting the wrong bytes. A
// reader can arrive after the hold and find the previous tenant of the key, or
// an artifact some other writer has just put there; neither came from this
// fetch, and length does not tell them apart from what did.
//
// Most recent first, because a key filled twice at once ends up holding the
// bytes of whichever finished last.
func (c *cacheFills) pending(key, digest string) string {
	if digest == "" {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	fills := c.held[key]
	for i := len(fills) - 1; i >= 0; i-- {
		if fills[i].digest == digest {
			return fills[i].upstream
		}
	}
	return ""
}
