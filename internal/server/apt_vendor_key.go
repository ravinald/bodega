package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ravinald/bodega/internal/aptsign"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// aptVendorKeyRoute is where a mirrored codename's vendor key is served.
const aptVendorKeyRoute = "/apt/keys/"

// maxAptVendorKey bounds a vendor key download. A public key with a few
// subkeys and signatures is tens of kilobytes; anything near this is not one.
const maxAptVendorKey = 1 << 20

// aptVendorKeyTimeout bounds the upstream fetch on a first request, shorter
// than upstreamClient's own because an apt client is waiting on it.
const aptVendorKeyTimeout = 30 * time.Second

// aptVendorKeys holds every vendor key that has passed its fingerprint check,
// armored, keyed by URL and fingerprint together: a reload that changes either
// one must fetch and check again rather than serve the key the old pair
// admitted.
//
// Memory only. A restart refetches on the first request, which costs one
// upstream round trip and keeps a key the vendor has since rotated from
// outliving the process that verified it.
type aptVendorKeys struct {
	mu   sync.Mutex
	keys map[config.AptSigningKey][]byte
}

func (c *aptVendorKeys) get(k config.AptSigningKey) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.keys[k]
}

func (c *aptVendorKeys) put(k config.AptSigningKey, armored []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.keys == nil {
		c.keys = map[config.AptSigningKey][]byte{}
	}
	c.keys[k] = armored
}

// handleAptVendorKey serves GET /apt/keys/{file}, the vendor key a mirrored
// codename's InRelease is signed with, as <codename>.asc.
//
// The fingerprint in the config is the trust decision; the URL only says
// where to look. A key whose primary fingerprint differs is refused with 502
// rather than served, because serving it would have apt trust whatever the
// vendor's host, or anything between it and bodega, chose to hand over.
func (s *Server) handleAptVendorKey(w http.ResponseWriter, r *http.Request) {
	codename, ok := strings.CutSuffix(r.PathValue("file"), ".asc")
	if _, configured := s.cfg.AptSigningKeyFor(codename); !ok || !configured {
		http.Error(w, fmt.Sprintf("no vendor key is configured for %q. Codenames with one: %s",
			r.PathValue("file"), aptKeyedList(s.cfg)), http.StatusNotFound)
		return
	}
	armored, status := s.aptVendorKey(r, codename)
	if armored == nil {
		http.Error(w, http.StatusText(status)+": the vendor key for "+codename+" could not be served; the server log names why", status)
		return
	}
	w.Header().Set("Content-Type", "application/pgp-keys")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	//nolint:gosec // G705: armor bodega re-encoded from a parsed key, not upstream bytes; Content-Type is set above.
	_, _ = w.Write(armored)
}

// aptVendorKey returns a configured codename's verified key from the cache,
// fetching and checking it on a miss, or nil and the status to answer with.
func (s *Server) aptVendorKey(r *http.Request, codename string) ([]byte, int) {
	key, _ := s.cfg.AptSigningKeyFor(codename)
	if armored := s.aptVendorKeys.get(key); armored != nil {
		return armored, http.StatusOK
	}
	armored, status := s.fetchAptVendorKey(r, codename, key)
	if armored != nil {
		s.aptVendorKeys.put(key, armored)
	}
	return armored, status
}

// fetchAptVendorKey downloads and checks one vendor key, returning it armored,
// or nil and the status to answer with.
func (s *Server) fetchAptVendorKey(r *http.Request, codename string, key config.AptSigningKey) ([]byte, int) {
	if s.policy != nil {
		verdictCtx, cancel := auditContext(r)
		_, violation, err := s.upstreamPolicyVerdict(verdictCtx, manifest.TypeApt, key.URL)
		cancel()
		if err != nil {
			s.logger.Error("policy check failed for an apt vendor key", "codename", codename, "url", key.URL, "error", err)
			return nil, http.StatusInternalServerError
		}
		if violation {
			host := key.URL
			if u, err := url.Parse(key.URL); err == nil {
				host = u.Hostname()
			}
			s.logger.Warn("apt vendor key host is off the allow-list, not fetched",
				"codename", codename, "url", key.URL, "next", "bodega policy add apt "+host)
			return nil, http.StatusForbidden
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), aptVendorKeyTimeout)
	defer cancel()
	up, err := openUpstream(ctx, key.URL, false)
	if err != nil {
		s.logger.Error("apt vendor key fetch failed", "codename", codename, "url", key.URL, "error", err)
		return nil, http.StatusBadGateway
	}
	defer up.body.Close()
	raw, err := io.ReadAll(io.LimitReader(up.body, maxAptVendorKey+1))
	switch {
	case err != nil:
		s.logger.Error("apt vendor key read failed", "codename", codename, "url", up.url, "error", err)
		return nil, http.StatusBadGateway
	case len(raw) > maxAptVendorKey:
		s.logger.Error("apt vendor key is larger than any public key, not served",
			"codename", codename, "url", up.url, "limit_bytes", maxAptVendorKey)
		return nil, http.StatusBadGateway
	}
	armored, found, err := aptsign.VendorKey(raw, key.Fingerprint)
	if err != nil {
		s.logger.Error("apt vendor key does not carry the configured fingerprint, not served",
			"codename", codename, "url", up.url, "want_fingerprint", key.Fingerprint,
			"got_fingerprints", strings.Join(found, " "), "error", err,
			"next", "compare the key at the URL against the vendor's published fingerprint before changing signing_key_fingerprint")
		return nil, http.StatusBadGateway
	}
	s.logger.Info("apt vendor key verified and cached", "codename", codename, "url", up.url, "fingerprint", key.Fingerprint)
	return armored, http.StatusOK
}

// aptKeyedList names the codenames whose vendor key this server serves, for a
// refusal to offer instead.
func aptKeyedList(cfg *config.Config) string {
	if names := cfg.AptKeyedCodenames(); len(names) > 0 {
		return strings.Join(names, ", ")
	}
	return "none (set signing_key_url and signing_key_fingerprint on an apt_upstreams entry)"
}
