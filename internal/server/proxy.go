package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/ravinald/bodega/internal/audit"
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
			s.recordCacheHit(ctx, r, regType, knownUpstream, policyCandidate, discoveryPkgName, s3Key)
			s.proxyS3(w, r, store, s3Key)
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
			s.recordCacheHit(ctx, r, regType, knownUpstream, policyCandidate, discoveryPkgName, s3Key)
			s.proxyS3(w, r, store, s3Key)
			return
		}
		http.NotFound(w, r)
		return
	}

	upstreamURL, err := resolve(ctx)
	if err != nil {
		if status != nil && status.Exists {
			s.logger.Error("upstream resolution failed, serving the stale cached copy", "key", s3Key, "error", err)
			// An outage is the window an operator reads these columns in.
			// Left unrecorded, request_count and last_client go quiet exactly
			// while the upstream is down and the cache is carrying the fleet.
			s.recordCacheHit(ctx, r, regType, knownUpstream, policyCandidate, discoveryPkgName, s3Key)
			s.proxyS3(w, r, store, s3Key)
			return
		}
		if errors.Is(err, errUpstreamNotFound) {
			s.logger.Info("upstream publishes no such artifact", "key", s3Key, "error", err)
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		s.logger.Error("upstream resolution failed", "key", s3Key, "error", err)
		http.Error(w, "upstream resolution failed", http.StatusBadGateway)
		return
	}

	// Upstream allow-list enforcement. Runs before fetchUpstream so a blocked
	// candidate never hits the network.
	if !s.enforceUpstreamPolicy(w, r, regType, upstreamURL, policyCandidate, discoveryPkgName, s3Key) {
		return
	}

	s.logger.Info("cache miss, fetching upstream", "key", s3Key, "upstream", upstreamURL)

	// A stale copy beats both error paths here: the upstream said something
	// went wrong, and what bodega already holds is the better answer than
	// either status code. "The upstream does not publish this" is not a
	// gateway failure, and conflating the two makes every unpublished path
	// read as an outage.
	fail := func(err error) {
		if status != nil && status.Exists {
			s.logger.Error("upstream fetch failed, serving the stale cached copy", "url", upstreamURL, "error", err)
			// No row here. This branch is below the allow-list gate, which
			// already recorded the attempt for this request; a second write
			// would bump request_count twice for one client fetch, which is
			// the counting error B16 fixed in the other direction.
			s.proxyS3(w, r, store, s3Key)
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

	spool, err := spoolUpstream(up)
	if err != nil {
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
		if err := store.PutFile(ctx, spool.path(), s3Key); err != nil {
			s.logger.Warn("failed to cache object", "key", s3Key, "error", err)
		} else {
			s.logger.Debug("cached object", "key", s3Key, "bytes", spool.size)
		}
	}

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
var upstreamClient = &http.Client{
	Timeout: 90 * time.Second,
}

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

	return &upstreamStream{
		url:           rawURL,
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
// concurrent large fetches no longer takes the process out. The spool lives in
// os.TempDir(), so TMPDIR is what has to hold the largest artifact bodega
// proxies — a small tmpfs there is the one place the old limit reappears.
type spooledUpstream struct {
	file   *os.File
	size   int64
	sha256 string
}

func (sp *spooledUpstream) path() string { return sp.file.Name() }

// close removes the spool file. The name is read before the descriptor is
// closed because that is the only handle on it: the file is not unlinked at
// creation, since PutFile takes a path.
func (sp *spooledUpstream) close() {
	name := sp.file.Name()
	_ = sp.file.Close()
	_ = os.Remove(name)
}

// spoolUpstream copies an upstream body to a temp file, hashing as it goes,
// and returns it positioned at EOF.
//
// A body shorter than the length the upstream declared is a cut transfer and
// fails here rather than being cached: chunked and transparently-decompressed
// responses report -1 and are exempt, so this only fires where the upstream
// stated a number. Caching short bytes was the failure that made every later
// fetch of the real artifact fail verification against the truncated digest.
func spoolUpstream(up *upstreamStream) (*spooledUpstream, error) {
	f, err := os.CreateTemp("", "bodega-upstream-*")
	if err != nil {
		return nil, fmt.Errorf("create spool file: %w", err)
	}
	sp := &spooledUpstream{file: f}

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), up.body)
	sp.size = n
	if err != nil {
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

	if stored == nil {
		// First fetch — store the computed checksum.
		pkgType, pkgName, pkgVersion := parsePackagePath("/" + s3Key)
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
				Status:     "checksum_mismatch",
				Details:    string(details),
			})
		}
		return fmt.Errorf("sha256 mismatch for %s: stored=%s computed=%s", s3Key, stored.Value[:12]+"...", computed[:12]+"...")
	}

	s.logger.Debug("checksum verified", "key", s3Key)
	return nil
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
// enforceUpstreamPolicy because the apt pool probe checks several candidates
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

// enforceUpstreamPolicy runs the allow-list check and writes the discovery row
// for one upstream attempt, returning false when it has already written the
// response and the caller must stop.
//
// A nil checker or an empty regType means policy is disabled (opt-in feature).
// discover_mode decides whether the attempt is recorded and nothing else: a
// violation is refused at every mode.
//
// It is a method rather than inline in proxyOrCache because the git smart-HTTP
// handler never reaches proxyOrCache: it execs git-http-backend against a local
// mirror instead of fetching an object. Two copies of an allow-list gate is one
// copy that stops matching the other.
func (s *Server) enforceUpstreamPolicy(w http.ResponseWriter, r *http.Request, regType, upstreamURL, policyCandidate, discoveryPkgName, s3Key string) bool {
	return s.enforceUpstreamPolicyRecording(w, r, regType, upstreamURL, policyCandidate, discoveryPkgName, s3Key, true)
}

// enforceUpstreamPolicyRecording is enforceUpstreamPolicy with the discovery
// write made optional, for a protocol whose single client operation reaches
// the gate more than once.
//
// One `git clone` is two requests, an info/refs GET and a git-upload-pack
// POST, and both have to pass the allow-list. Recording both would make the
// discovery table count protocol legs for git and requests for every other
// type, so an operator comparing counts across types reads git as twice as
// busy as it is. The refusal is unconditional; only the row is not.
func (s *Server) enforceUpstreamPolicyRecording(w http.ResponseWriter, r *http.Request, regType, upstreamURL, policyCandidate, discoveryPkgName, s3Key string, record bool) bool {
	if s.policy == nil || regType == "" || policyCandidate == "" {
		return true
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
		return false
	}

	// Discovery log: record every upstream attempt with its decision so
	// operators can review/forensically audit and later promote captured
	// hosts/packages to allow-list rules.
	if record {
		s.recordDiscovery(ctx, r, regType, upstreamURL, policyCandidate, discoveryPkgName, s3Key, decision)
	}

	if violation {
		s.logger.Warn("upstream blocked by policy",
			"type", regType, "candidate", policyCandidate, "url", upstreamURL)
		s.recordPolicyViolation(r, regType, policyCandidate, upstreamURL)
		http.Error(w, "upstream blocked by allow-list", http.StatusForbidden)
		return false
	}
	return true
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
		Status:    "policy_violation",
		Details:   fmt.Sprintf("url=%s", upstreamURL),
	}); err != nil {
		s.logger.Error("audit write failed, denial not recorded — still refusing",
			"event_type", audit.EventCache, "status", "policy_violation",
			"type", regType, "candidate", policyCandidate, "url", upstreamURL,
			"error", err)
	}
}
