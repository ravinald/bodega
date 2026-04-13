package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/ravinald/bodega/internal/audit"
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
//
// For immutable resources (versioned artifacts), once cached they are never
// re-fetched. For mutable resources (list files, indexes), the object is
// refreshed after the configured TTL based on S3 LastModified.
//
// If proxy/cache is disabled or upstreamURL is empty, falls back to direct
// S3 proxy.
func (s *Server) proxyOrCache(w http.ResponseWriter, r *http.Request, s3Key, upstreamURL string, immutable, forceProxy bool) {
	if !s.requireS3(w) {
		return
	}

	ctx := r.Context()

	// Check if object exists in S3.
	status, err := s.objects.Head(ctx, s3Key)
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
			s.proxyS3(w, r, s3Key)
			return
		}
		s.logger.Debug("cache stale", "key", s3Key)
	}

	// Cache miss or stale — fetch from upstream if proxy is enabled.
	if (!s.cacheEnabled() && !forceProxy) || upstreamURL == "" {
		if status != nil && status.Exists {
			// Stale but no upstream — serve what we have.
			s.proxyS3(w, r, s3Key)
			return
		}
		http.NotFound(w, r)
		return
	}

	s.logger.Info("cache miss, fetching upstream", "key", s3Key, "upstream", upstreamURL)

	data, ct, err := fetchUpstream(ctx, upstreamURL)
	if err != nil {
		s.logger.Error("upstream fetch failed", "url", upstreamURL, "error", err)
		// If we have a stale copy, serve it.
		if status != nil && status.Exists {
			s.proxyS3(w, r, s3Key)
			return
		}
		http.Error(w, "upstream fetch failed", http.StatusBadGateway)
		return
	}

	// Checksum verification.
	if err := s.verifyProxyChecksum(ctx, s3Key, data, immutable); err != nil {
		s.logger.Error("checksum verification failed", "key", s3Key, "error", err)
		http.Error(w, "checksum verification failed — upstream content may be tampered", http.StatusBadGateway)
		return
	}

	// Cache to storage (best-effort — don't fail the response if caching fails).
	if s.objects != nil {
		if err := s.objects.Put(ctx, s3Key, data); err != nil {
			s.logger.Warn("failed to cache object", "key", s3Key, "error", err)
		} else {
			s.logger.Debug("cached object", "key", s3Key, "bytes", len(data))
		}
	}

	// Serve the fetched data directly.
	if ct == "" {
		ct = contentTypeForKey(s3Key)
	}
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
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

// fetchUpstream downloads a URL and returns the body bytes and content type.
func fetchUpstream(ctx context.Context, rawURL string) ([]byte, string, error) {
	if err := validateUpstreamURL(rawURL); err != nil {
		return nil, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", err
	}

	resp, err := upstreamClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, "", fmt.Errorf("upstream 404: %s", rawURL)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("upstream returned %d: %s", resp.StatusCode, rawURL)
	}

	// Cap at 256MB to prevent unbounded memory use.
	const maxSize = 256 << 20
	limited := io.LimitReader(resp.Body, maxSize)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, "", fmt.Errorf("read upstream body: %w", err)
	}

	return data, resp.Header.Get("Content-Type"), nil
}

// verifyProxyChecksum verifies the SHA-256 of fetched data against the stored
// checksum in the audit DB. On first fetch (no stored checksum), it stores the
// computed digest. On mismatch, returns an error — the caller should NOT cache
// or serve the data.
//
// Only runs for immutable resources (versioned artifacts). Mutable resources
// (list files, indexes) change by design and are not checksummed.
func (s *Server) verifyProxyChecksum(ctx context.Context, s3Key string, data []byte, immutable bool) error {
	if !immutable {
		return nil // mutable resources are not checksummed
	}
	if s.auditDB == nil {
		return nil // no audit DB, skip verification
	}

	// Compute SHA-256 of the fetched data.
	h := sha256.Sum256(data)
	computed := hex.EncodeToString(h[:])

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

// logCacheEvent records an audit event for a proxy/cache operation.
func (s *Server) logCacheEvent(r *http.Request, pkgType, pkgName, pkgVersion, status string, logger *slog.Logger) {
	logger.Info("proxy cache event",
		"pkg_type", pkgType,
		"pkg_name", pkgName,
		"pkg_version", pkgVersion,
		"status", status,
		"client", ClientIP(r),
	)
}
