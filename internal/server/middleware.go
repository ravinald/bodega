package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/scaleapi/bodega/internal/audit"
	"github.com/scaleapi/bodega/internal/logging"
)

// contextKey is an unexported type for context keys in this package.
type contextKey int

const clientIPKey contextKey = iota

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

// RealIPMiddleware extracts the real client IP from reverse proxy headers
// (X-Real-IP, X-Forwarded-For) and stores it in the request context.
// Only trusts forwarded headers when the direct peer is in trustedNets.
// If trustedNets is nil, RFC 1918 + loopback ranges are used.
func RealIPMiddleware(trustedNets []*net.IPNet) func(http.Handler) http.Handler {
	if trustedNets == nil {
		trustedNets = defaultTrustedNets()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := resolveClientIP(r, trustedNets)
			ctx := context.WithValue(r.Context(), clientIPKey, ip)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
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
// context. If denyNets is nil or empty the middleware is a no-op.
func DenyListMiddleware(denyNets []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if len(denyNets) == 0 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := ClientIP(r)
			ip := net.ParseIP(clientIP)
			if ip != nil {
				for _, cidr := range denyNets {
					if cidr.Contains(ip) {
						http.Error(w, "Forbidden", http.StatusForbidden)
						return
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
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

			status := "success"
			if rec.statusCode == http.StatusNotFound {
				status = "not_found"
			}

			_ = db.Record(r.Context(), audit.Event{
				EventType:  audit.EventFetch,
				PkgType:    pkgType,
				PkgName:    pkgName,
				PkgVersion: pkgVersion,
				ClientIP:   ClientIP(r),
				UserAgent:  r.UserAgent(),
				Status:     status,
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
	}
	return "", "", ""
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
