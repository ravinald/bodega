package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/logging"
)

// contextKey is an unexported type for context keys in this package.
type contextKey int

const (
	clientIPKey contextKey = iota
	trustedNetsKey
)

// ClientIP returns the resolved client IP from the request context, falling
// back to r.RemoteAddr if not set by RealIPMiddleware.
func ClientIP(r *http.Request) string {
	if ip, ok := r.Context().Value(clientIPKey).(string); ok {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// NetsFunc supplies a CIDR set. It is called once per request rather than once
// per chain build, so a list changed on a running server takes effect without
// the handler chain being rebuilt. A nil NetsFunc yields no set at all.
type NetsFunc func() []*net.IPNet

// StaticNets wraps a fixed set for a caller with nothing to reload.
func StaticNets(nets []*net.IPNet) NetsFunc {
	return func() []*net.IPNet { return nets }
}

// nets calls f, tolerating a nil f.
func (f NetsFunc) nets() []*net.IPNet {
	if f == nil {
		return nil
	}
	return f()
}

// RealIPMiddleware extracts the real client IP from reverse proxy headers
// (X-Real-IP, X-Forwarded-For) and stores it in the request context.
// Only trusts forwarded headers when the direct peer is in the trusted set.
// A nil set, from a nil NetsFunc or one returning nil, means RFC 1918 +
// loopback. A non-nil empty set means trust nobody, and the two must not be
// collapsed: the second is an operator's answer, the first is the absence of
// one.
func RealIPMiddleware(trusted NetsFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			trustedNets := trusted.nets()
			if trustedNets == nil {
				trustedNets = defaultTrustedNets()
			}
			ip := resolveClientIP(r, trustedNets)
			ctx := context.WithValue(r.Context(), clientIPKey, ip)
			// Carried so every later reader of a forwarded header answers to
			// the same trusted set this middleware resolved against. Without
			// it requestScheme falls back to the built-in default and an
			// operator who narrowed trusted_proxies still has X-Forwarded-Proto
			// believed from a peer they excluded.
			ctx = context.WithValue(ctx, trustedNetsKey, trustedNets)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// trustedNetsFor returns the trusted set RealIPMiddleware resolved for this
// request. It falls back to the built-in default only when the middleware
// never ran, which is the case in tests that exercise a handler directly.
func trustedNetsFor(r *http.Request) []*net.IPNet {
	if nets, ok := r.Context().Value(trustedNetsKey).([]*net.IPNet); ok {
		return nets
	}
	return defaultTrustedNets()
}

func resolveClientIP(r *http.Request, trusted []*net.IPNet) string {
	peerHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	peerIP := net.ParseIP(peerHost)
	if peerIP == nil || !isTrusted(peerIP, trusted) {
		return peerHost
	}

	// Trust X-Real-IP first (set by nginx).
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	// Fall back to X-Forwarded-For (last entry before our trusted proxy).
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		// Walk from right to find the first non-trusted IP.
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			parsed := net.ParseIP(ip)
			if parsed == nil || !isTrusted(parsed, trusted) {
				return ip
			}
		}
		// All IPs are trusted; return the leftmost.
		return strings.TrimSpace(parts[0])
	}

	return peerHost
}

func isTrusted(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func defaultTrustedNets() []*net.IPNet {
	cidrs := []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"::1/128",
		"fc00::/7",
	}
	var nets []*net.IPNet
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}

// ParseDenyList parses a list of CIDR strings into []*net.IPNet.
// Bare addresses without a prefix length are treated as /32 (IPv4) or /128 (IPv6).
func ParseDenyList(entries []string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// If there's no slash, append the appropriate prefix length.
		if !strings.Contains(entry, "/") {
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, fmt.Errorf("invalid deny list entry: %q", entry)
			}
			if ip.To4() != nil {
				entry += "/32"
			} else {
				entry += "/128"
			}
		}
		_, cidr, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid deny list entry: %q: %w", entry, err)
		}
		nets = append(nets, cidr)
	}
	return nets, nil
}

// DenyListMiddleware rejects requests from clients whose IP falls within any
// of the provided CIDR ranges, returning 403 Forbidden. It relies on
// RealIPMiddleware having already resolved the client IP into the request
// context. An empty set makes the middleware a pass-through, re-evaluated per
// request rather than at chain build time so a first entry added to an empty
// list is honored.
//
// auditDB may be nil; refusals are then logged nowhere but the journal.
func DenyListMiddleware(denyNets NetsFunc, auditDB *audit.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nets := denyNets.nets()
			if len(nets) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			clientIP := ClientIP(r)
			ip := net.ParseIP(clientIP)
			if ip != nil {
				for _, cidr := range nets {
					if cidr.Contains(ip) {
						recordDenial(auditDB, r, audit.DenialDenyList, nil)
						http.Error(w, "Forbidden", http.StatusForbidden)
						return
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// recordDenial writes one audit row for a request the server refused, so the
// only queryable record of who was turned away does not live in a journal that
// rotates. reason is one of the audit.Denial* constants and lands in the
// status column; extra carries gate-specific context.
//
// It records no credential. A caller identifies a token by its id or by a
// prefix of its peppered hash, never by the token itself, and no header is
// copied into the row.
//
// A nil db is a no-op: the server keeps serving when the audit DB could not be
// opened, and a denial must not become the thing that panics it.
func recordDenial(db *audit.DB, r *http.Request, reason string, extra map[string]string) {
	if db == nil {
		return
	}
	pkgType, pkgName := parseAPIPackagePath(r.URL.Path)
	details := map[string]string{
		"method": r.Method,
		"path":   truncateField(r.URL.Path, maxDetailField),
	}
	for k, v := range extra {
		details[k] = truncateField(v, maxDetailField)
	}
	blob, err := json.Marshal(details)
	if err != nil {
		blob = []byte("{}")
	}
	_ = db.Record(r.Context(), audit.Event{
		EventType: audit.EventDenied,
		PkgType:   pkgType,
		PkgName:   pkgName,
		ClientIP:  ClientIP(r),
		UserAgent: truncateField(r.UserAgent(), maxDetailField),
		Status:    reason,
		Details:   string(blob),
	})
}

// hashPrefix is the leading bytes of a peppered token hash, enough to tell two
// rejected credentials apart in the audit trail and far too little to attack
// the hash with.
func hashPrefix(hash string) string {
	const n = 12
	if len(hash) <= n {
		return hash
	}
	return hash[:n]
}

// maxDetailField caps every client-controlled string copied into an audit row.
// A denial is written before any handler has validated the request, so path,
// User-Agent and package name here are whatever the caller sent: unbounded,
// they let an unauthenticated stranger choose how much disk each 403 costs.
const maxDetailField = 256

func truncateField(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// parseAPIPackagePath pulls the type and name out of /api/v1/packages/{type}
// and /api/v1/packages/{type}/{name}. The mutation gate runs before the mux,
// so r.PathValue is empty there and a denial would otherwise carry no subject.
func parseAPIPackagePath(path string) (pkgType, pkgName string) {
	rest, ok := strings.CutPrefix(path, "/api/v1/packages/")
	if !ok {
		return "", ""
	}
	parts := strings.Split(rest, "/")
	pkgType = truncateField(parts[0], maxDetailField)
	if len(parts) > 1 {
		pkgName = truncateField(parts[1], maxDetailField)
	}
	return pkgType, pkgName
}

// maxBodyCapture is the maximum number of bytes captured from request/response
// bodies at Trace level.
const maxBodyCapture = 64 * 1024

// RequestLogger returns middleware that logs HTTP requests using the provided
// slog.Logger. The amount of detail depends on the logger's configured level:
//
//   - Info:  method, path, status, duration, bytes, client IP
//   - Debug: + request headers, response headers
//   - Trace: + request body, response body (capped at 64KB, skips binary)
func RequestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip health checks.
			if r.URL.Path == "/healthz" {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()

			// Capture request body at Trace level.
			var reqBody []byte
			if logger.Enabled(r.Context(), logging.LevelTrace) && r.Body != nil && !isBinaryContentType(r.Header.Get("Content-Type")) {
				reqBody, _ = io.ReadAll(io.LimitReader(r.Body, maxBodyCapture))
				r.Body = io.NopCloser(io.MultiReader(
					strings.NewReader(string(reqBody)),
					r.Body,
				))
			}

			rec := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}

			// Capture response body at Trace level.
			if logger.Enabled(r.Context(), logging.LevelTrace) {
				rec.captureBody = true
			}

			next.ServeHTTP(rec, r)

			duration := time.Since(start)
			clientIP := ClientIP(r)

			// Info level: basic request details.
			if !logger.Enabled(r.Context(), slog.LevelInfo) {
				return
			}
			attrs := []slog.Attr{
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", rec.statusCode),
				slog.String("duration", formatDuration(duration)),
				slog.Int("bytes", rec.size),
				slog.String("client", clientIP),
			}

			// Debug level: add headers.
			if logger.Enabled(r.Context(), slog.LevelDebug) {
				attrs = append(attrs,
					slog.String("req_headers", formatHeaders(r.Header)),
					slog.String("resp_headers", formatHeaders(rec.Header())),
				)
			}

			// Trace level: add bodies.
			if logger.Enabled(r.Context(), logging.LevelTrace) {
				if len(reqBody) > 0 {
					attrs = append(attrs, slog.String("req_body", string(reqBody)))
				}
				if rec.captureBody && len(rec.body) > 0 && !isBinaryContentType(rec.Header().Get("Content-Type")) {
					attrs = append(attrs, slog.String("resp_body", string(rec.body)))
				}
			}

			logger.LogAttrs(r.Context(), slog.LevelInfo, "http request", attrs...)
		})
	}
}

// responseRecorder wraps http.ResponseWriter to capture the status code,
// response size, and optionally the response body.
type responseRecorder struct {
	http.ResponseWriter
	statusCode  int
	size        int
	captureBody bool
	body        []byte
}

func (r *responseRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.size += n
	if r.captureBody && len(r.body) < maxBodyCapture {
		remaining := maxBodyCapture - len(r.body)
		if n < remaining {
			remaining = n
		}
		r.body = append(r.body, b[:remaining]...)
	}
	return n, err
}

// Flush implements http.Flusher for streaming responses.
func (r *responseRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func formatHeaders(h http.Header) string {
	var sb strings.Builder
	for k, vs := range h {
		for _, v := range vs {
			if sb.Len() > 0 {
				sb.WriteString("; ")
			}
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(v)
		}
	}
	return sb.String()
}

func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%.0fµs", float64(d.Microseconds()))
	}
	if d < time.Second {
		return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000)
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

// AuditMiddleware records package fetch events to the audit database.
// It only records events for package-serving routes (not /healthz or /api/v1/*).
// The audit DB may be nil, in which case the middleware is a no-op.
func AuditMiddleware(db *audit.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if db == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path

			// Skip non-package routes.
			if path == "/healthz" || strings.HasPrefix(path, "/api/") {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()
			rec := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(rec, r)
			duration := time.Since(start)

			// Only audit successful package fetches.
			if rec.statusCode < 200 || rec.statusCode >= 400 {
				return
			}

			pkgType, pkgName, pkgVersion := parsePackagePath(path)
			if pkgType == "" {
				return
			}

			// 404s on package routes are deliberately not recorded: the
			// guard above has already discarded them, and apt probes several
			// optional index paths on every update, so recording them would
			// bury the fetches under noise no operator asked about.
			_ = db.Record(r.Context(), audit.Event{
				EventType:  audit.EventServeFetch,
				PkgType:    pkgType,
				PkgName:    pkgName,
				PkgVersion: pkgVersion,
				ClientIP:   ClientIP(r),
				UserAgent:  r.UserAgent(),
				Status:     "success",
				DurationMs: duration.Milliseconds(),
			})
		})
	}
}

// parsePackagePath extracts package type, name, and version from a request path.
func parsePackagePath(path string) (pkgType, pkgName, pkgVersion string) {
	switch {
	case strings.HasPrefix(path, "/apt/"):
		return "apt", strings.TrimPrefix(path, "/apt/"), ""
	case strings.HasPrefix(path, "/pypi/wheels/"):
		filename := strings.TrimPrefix(path, "/pypi/wheels/")
		parts := strings.SplitN(filename, "-", 3)
		if len(parts) >= 2 {
			return "pypi", parts[0], parts[1]
		}
		return "pypi", filename, ""
	case strings.HasPrefix(path, "/pypi/simple/"):
		name := strings.Trim(strings.TrimPrefix(path, "/pypi/simple/"), "/")
		return "pypi", name, ""
	case strings.HasPrefix(path, "/git/"):
		parts := strings.SplitN(strings.TrimPrefix(path, "/git/"), "/", 2)
		return "git", parts[0], ""
	case strings.HasPrefix(path, "/binaries/"):
		parts := strings.SplitN(strings.TrimPrefix(path, "/binaries/"), "/", 3)
		if len(parts) >= 2 {
			return "binary", parts[0], parts[1]
		}
		return "binary", strings.TrimPrefix(path, "/binaries/"), ""
	case strings.HasPrefix(path, "/go/"):
		full := strings.TrimPrefix(path, "/go/")
		if idx := strings.Index(full, "/@v/"); idx >= 0 {
			module := full[:idx]
			file := full[idx+4:]
			// Extract version from filename (e.g., "v1.30.0.zip" → "v1.30.0")
			if dot := strings.LastIndex(file, "."); dot > 0 && file != "list" {
				return "gomod", module, file[:dot]
			}
			return "gomod", module, ""
		}
		return "gomod", full, ""
	case strings.HasPrefix(path, "/helm/charts/"):
		filename := strings.TrimPrefix(path, "/helm/charts/")
		// chart-name-version.tgz → name, version
		filename = strings.TrimSuffix(filename, ".tgz")
		if idx := strings.LastIndex(filename, "-"); idx > 0 {
			return "helm", filename[:idx], filename[idx+1:]
		}
		return "helm", filename, ""
	case strings.HasPrefix(path, "/helm/"):
		return "helm", "index", ""
	case strings.HasPrefix(path, "/npm/"):
		full := strings.TrimPrefix(path, "/npm/")
		if idx := strings.Index(full, "/-/"); idx >= 0 {
			pkgName := full[:idx]
			tarball := full[idx+3:]
			// Extract version from tarball name
			tarball = strings.TrimSuffix(tarball, ".tgz")
			if vIdx := strings.LastIndex(tarball, "-"); vIdx > 0 {
				return "npm", pkgName, tarball[vIdx+1:]
			}
			return "npm", pkgName, ""
		}
		return "npm", full, ""
	case strings.HasPrefix(path, "/cargo/"):
		full := strings.TrimPrefix(path, "/cargo/")
		// Crate download: <crate>/<version>/download
		if strings.HasSuffix(full, "/download") {
			parts := strings.SplitN(strings.TrimSuffix(full, "/download"), "/", 2)
			if len(parts) == 2 {
				return "cargo", parts[0], parts[1]
			}
		}
		// Sparse index lookup: trailing path segment is the crate name.
		parts := strings.Split(full, "/")
		return "cargo", parts[len(parts)-1], ""
	}
	return "", "", ""
}

// LocalhostOnly returns true if every entry in nets is a loopback range. It is
// the test that decides whether the mutation API requires a Bearer token, so
// `bodega acl` answers it the same way the middleware does rather than
// re-deriving it.
func LocalhostOnly(nets []*net.IPNet) bool {
	for _, n := range nets {
		if !n.IP.IsLoopback() {
			return false
		}
	}
	return true
}

// MutationAuthMiddleware restricts POST and DELETE requests to clients in the
// admin allow-list. When that list extends beyond localhost, a valid Bearer
// token is required, verified via SHA-256(token + pepper) against the
// hashes stored in the audit DB.
//
// Both the allow-list and the localhost-only test are evaluated per request:
// widening the list is exactly what turns the token requirement on, so a set
// captured at chain build time would leave a widened server still admitting
// unauthenticated mutations until it restarted.
//
// GET/HEAD/OPTIONS requests pass through unconditionally — package manager
// clients (apt, pip, go, npm) cannot send auth headers over standard protocols.
func MutationAuthMiddleware(admin NetsFunc, auditDB *audit.DB, pepper string, logger *slog.Logger) func(http.Handler) http.Handler {
	// Cache token hashes to avoid per-request DB queries.
	var cachedHashes []audit.TokenHash
	var cacheTime time.Time
	const cacheTTL = 30 * time.Second

	loadHashes := func() []audit.TokenHash {
		if time.Since(cacheTime) < cacheTTL && cachedHashes != nil {
			return cachedHashes
		}
		if auditDB == nil {
			return nil
		}
		hashes, err := auditDB.GetTokenHashes(context.Background())
		if err != nil {
			logger.Error("failed to load token hashes", "error", err)
			return cachedHashes // return stale cache on error
		}
		cachedHashes = hashes
		cacheTime = time.Now()
		return hashes
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost && r.Method != http.MethodDelete && r.Method != http.MethodPatch {
				next.ServeHTTP(w, r)
				return
			}

			// Check IP against admin_permit_cidr.
			clientIP := net.ParseIP(ClientIP(r))
			if clientIP == nil {
				logger.Warn("mutation blocked: unparseable client IP", "remote", r.RemoteAddr)
				recordDenial(auditDB, r, audit.DenialUnparseableIP, nil)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			adminNets := admin.nets()
			allowed := false
			for _, n := range adminNets {
				if n.Contains(clientIP) {
					allowed = true
					break
				}
			}
			if !allowed {
				logger.Warn("mutation blocked: IP not in admin_permit_cidr",
					"client_ip", clientIP.String(), "method", r.Method, "path", r.URL.Path)
				recordDenial(auditDB, r, audit.DenialIPNotPermitted, nil)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			// If the allow-list goes beyond localhost, require a valid Bearer token.
			if !LocalhostOnly(adminNets) {
				hashes := loadHashes()
				if len(hashes) == 0 {
					logger.Warn("mutation blocked: no tokens configured for remote access",
						"client_ip", clientIP.String())
					recordDenial(auditDB, r, audit.DenialNoTokens, nil)
					http.Error(w, "Unauthorized — no tokens configured", http.StatusUnauthorized)
					return
				}

				auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
				if auth == "" || auth == r.Header.Get("Authorization") {
					// No Bearer prefix or empty token.
					logger.Warn("mutation blocked: no bearer credential",
						"client_ip", clientIP.String(), "method", r.Method, "path", r.URL.Path)
					recordDenial(auditDB, r, audit.DenialTokenMissing, nil)
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}

				// Hash the incoming token with pepper and compare.
				incoming := audit.HashToken(auth, pepper)

				var matched *audit.TokenHash
				for i := range hashes {
					if subtle.ConstantTimeCompare([]byte(incoming), []byte(hashes[i].Hash)) == 1 {
						matched = &hashes[i]
						break
					}
				}

				if matched == nil {
					logger.Warn("mutation blocked: invalid token",
						"client_ip", clientIP.String(), "method", r.Method, "path", r.URL.Path)
					// A prefix of the peppered hash, never the credential: it
					// correlates a repeat caller across rows and is not
					// replayable without the pepper.
					recordDenial(auditDB, r, audit.DenialTokenInvalid,
						map[string]string{"hash_prefix": hashPrefix(incoming)})
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}

				// Check expiry.
				if matched.ExpiresAt != nil && matched.ExpiresAt.Before(time.Now()) {
					logger.Warn("mutation blocked: token expired",
						"token_id", matched.ID, "client_ip", clientIP.String())
					recordDenial(auditDB, r, audit.DenialTokenExpired,
						map[string]string{
							"token_id":   matched.ID,
							"expired_at": matched.ExpiresAt.UTC().Format(time.RFC3339),
						})
					http.Error(w, "Unauthorized — token expired", http.StatusUnauthorized)
					return
				}

				// Update last_used asynchronously.
				if auditDB != nil {
					go func(id string) {
						_ = auditDB.UpdateTokenLastUsed(context.Background(), id)
					}(matched.ID)
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeadersMiddleware adds standard security headers to every response.
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func isBinaryContentType(ct string) bool {
	if ct == "" {
		return false
	}
	ct = strings.ToLower(ct)
	return strings.HasPrefix(ct, "application/octet-stream") ||
		strings.HasPrefix(ct, "application/zip") ||
		strings.HasPrefix(ct, "application/gzip") ||
		strings.HasPrefix(ct, "application/x-") ||
		strings.HasPrefix(ct, "image/") ||
		strings.HasPrefix(ct, "audio/") ||
		strings.HasPrefix(ct, "video/") ||
		strings.Contains(ct, "debian")
}

// requestScheme reports the scheme the client used, which is not always the
// one this listener answered on. Behind a TLS-terminating proxy r.TLS is nil
// on every request, so reading it alone prints http:// for a deployment that
// is https everywhere a client can see.
//
// X-Forwarded-Proto is honored only from a trusted peer, on the same rule
// resolveClientIP applies to X-Real-IP: a header any client can set decides
// nothing by itself. An untrusted peer gets the listener's own answer.
func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" || !peerIsTrusted(r, trustedNetsFor(r)) {
		return "http"
	}
	if i := strings.Index(proto, ","); i >= 0 {
		proto = proto[:i]
	}
	switch p := strings.ToLower(strings.TrimSpace(proto)); p {
	case "http", "https":
		return p
	}
	return "http"
}

// peerIsTrusted reports whether the direct peer is one of nets, ignoring every
// forwarded header. It answers "may this connection speak for another".
func peerIsTrusted(r *http.Request, nets []*net.IPNet) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && isTrusted(ip, nets)
}
