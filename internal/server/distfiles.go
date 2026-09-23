package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/distinfo"
	"github.com/ravinald/bodega/internal/manifest"
)

// ---- Ports distfiles --------------------------------------------------------

// distinfoRefresh is how old the distinfo index may get before a request
// starts a background re-read, so a ports tree updated under a running server
// is picked up without a restart. A warm re-read of a full tree is about a
// second.
const distinfoRefresh = 10 * time.Minute

// distfilesGuard is upstreamGuard with plain http admitted, and it is the only
// upstream check in bodega that admits it.
//
// Every other type trusts the transport for the bytes it caches, because the
// digest it later checks is one bodega recorded from that same transport. A
// distfile's digest is pinned in the ports tree before bodega fetches anything,
// so TLS adds nothing to what gets admitted: an attacker on the path can make
// a fetch fail the check and nothing else. And the default upstream needs it.
// distcache.FreeBSD.org answers https with a certificate naming only
// pkg.freebsd.org and pkgmir.geo.freebsd.org, which is why bsd.port.mk's own
// MASTER_SITE_BACKUP spells it http://. The address check still applies, so a
// distfiles_upstream cannot be pointed at this host's own network.
//
// A variable, like upstreamGuard, so a test can serve a fixture from loopback.
var distfilesGuard = func(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid upstream URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("distfiles upstream URL must use http or https, got %q", u.Scheme)
	}
	return checkUpstreamHost(u.Hostname())
}

// distfilesUpstreamClient is upstreamClient with distfilesGuard on every
// redirect hop, and no overall timeout: a distfile can run to gigabytes, and
// the server's own write timeout bounds the request that caused the fetch.
var distfilesUpstreamClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxUpstreamRedirects {
			return fmt.Errorf("stopped after %d redirects", len(via))
		}
		return distfilesGuard(req.URL.String())
	},
}

// handleDistfiles serves GET /distfiles/{name...}: one distfile by its distinfo name, which is
// "[${DIST_SUBDIR}/]<file>". This is the HTTP deployment: a client sets
//
//	MASTER_SITE_OVERRIDE?=	https://<bodega>/distfiles/${DIST_SUBDIR}/
//
// in /etc/make.conf and do-fetch.sh requests <override><file>, which is this
// route with the distinfo name as its path.
//
// The HTTP deployment preempts the port's own sites; it does not enforce
// anything. do-fetch.sh tries the override, then the port's MASTER_SITES,
// then MASTER_SITE_BACKUP, so any answer here other than the bytes (a 404, a
// 451, a 502, an unreachable host) sends the client straight to the internet.
// Only the DISTDIR deployment, where 'bodega build fetch distfiles' writes
// into a directory the client already reads, stops a build reaching the
// network: do-fetch.sh skips every site list for a file already present.
//
// Pull-through is the default rather than a full copy. The complete set runs
// to roughly two terabytes, distcache.FreeBSD.org answers 403 to a directory
// listing, and there is no manifest of the universe short of walking every
// */*/distinfo in a ports tree. A miss is fetched from distfiles_upstream,
// held against the distinfo line, and only then cached and served.
//
// The digest check is the reason this is not a binary namespace. See
// internal/distinfo for why the two must stay apart.
func (s *Server) handleDistfiles(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := manifest.DistfilesValidName(name); err != nil || !isSafePath(name) {
		http.Error(w, "invalid distfile path: expected /distfiles/[<DIST_SUBDIR>/]<file>, the name as a distinfo line spells it", http.StatusBadRequest)
		return
	}
	if s.distinfo == nil {
		// 404 rather than 503: this is configuration, not an outage, and a
		// client configured against this host falls through to the port's
		// own sites on a 404 at once.
		http.Error(w, "this server has no distfiles_ports_tree configured, so it has no distinfo to admit a distfile against", http.StatusNotFound)
		return
	}
	// A distfile whose manifest entry records a backend lives there, which is
	// what 'bodega pkg move' changes. Anything else, pulled through or not yet
	// uploaded, lives where storage_by_type sends new writes. pm.Name is
	// compared because GetPackage folds "/" to "--", so "a/b" and "a--b"
	// reach one manifest.
	ctx := r.Context()
	store := s.typeStore(manifest.TypeDistfiles)
	if pm, _ := s.store.GetPackage(ctx, manifest.TypeDistfiles, name); pm != nil && pm.Name == name {
		if isPackageHidden(pm) {
			http.NotFound(w, r)
			return
		}
		if s.stores != nil && len(pm.Versions) > 0 && pm.Versions[0].Storage != "" {
			recorded, err := s.stores.ByName(pm.Versions[0].Storage)
			if err != nil {
				s.logger.Error("storage backend recorded for distfile is not configured", "name", name, "error", err)
				http.Error(w, "storage backend error", http.StatusBadGateway)
				return
			}
			store = recorded
		}
	}
	if !s.requireStorage(w, store) {
		return
	}
	w = cachePrivateOn200(w, name)
	if !s.entitleGate(w, r, manifest.TypeDistfiles, name, "") {
		return
	}

	// The distinfo decides before the cache does. A file cached before its
	// port was marked RESTRICTED, or before a tree update repinned its name,
	// must not keep being served on the strength of having been admitted once.
	entry, err := s.distinfo.Lookup(name)
	switch {
	case errors.Is(err, distinfo.ErrRestricted):
		s.logger.Info("distfiles: refusing a distfile its port forbids redistributing", "name", name, "reason", err)
		recordDenialFor(s.auditDB, r, manifest.TypeDistfiles, name, "", audit.DenialDistfileLicense, map[string]string{"reason": entry.Restricted})
		// 451 names the reason a 404 would hide. The client moves on to the
		// port's own sites either way, which is where a restricted file has
		// to come from.
		http.Error(w, err.Error()+"; fetch it from the port's own MASTER_SITES", http.StatusUnavailableForLegalReasons)
		return
	case errors.Is(err, distinfo.ErrNotReady):
		s.logger.Warn("distfiles: request arrived before the ports tree was indexed", "name", name, "error", err)
		w.Header().Set("Retry-After", "30")
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	case err != nil:
		// Not listed, or listed ambiguously: either way there is no digest to
		// hold the bytes to, and pinning the first fetch is what binary does
		// and what this type exists not to do.
		s.logger.Info("distfiles: no distinfo digest to admit against", "name", name, "error", err)
		http.Error(w, err.Error()+" under "+s.distinfo.Root()+"; update the server's ports tree to the client's revision", http.StatusNotFound)
		return
	}

	key := manifest.DistfilesKey(name)
	if info, _ := store.Head(ctx, key); info != nil && info.Exists && info.Size == entry.Size {
		s.serveCacheHit(w, r, store, key, func(obj cachedObject) {
			s.recordCacheServed(r, manifest.TypeDistfiles, name, name, key, obj)
		})
		return
	}

	upstream := s.cfg.DistfilesUpstream + manifest.DistfilesURLPath(name)
	s.logger.Info("distfiles: cache miss, fetching upstream", "name", name, "upstream", upstream)
	// Identity encoding, because the digest is over the file as distinfo
	// describes it and a transport that decoded a gzip-encoded response would
	// hand the check different bytes than the client's `make checksum` reads.
	up, err := openUpstreamVia(ctx, distfilesUpstreamClient, distfilesGuard, upstream, true)
	if err != nil {
		if errors.Is(err, errUpstreamNotFound) {
			http.Error(w, "distfiles_upstream does not carry "+name, http.StatusNotFound)
			return
		}
		s.logger.Error("distfiles: upstream fetch failed", "name", name, "upstream", upstream, "error", err)
		http.Error(w, "upstream fetch failed", http.StatusBadGateway)
		return
	}
	defer up.body.Close()

	// A declared length that disagrees with distinfo is refused before the
	// body is read, so a wrong file costs no spool.
	if up.contentLength >= 0 && up.contentLength != entry.Size {
		s.refuseDistfile(w, r, name, key, entry, "", up.contentLength, up.url)
		return
	}
	spool, err := s.spoolUpstream(up)
	if err != nil {
		if reason := spoolDenialReason(err); reason != "" {
			s.recordSpoolRefusal(r, manifest.TypeDistfiles, name, key, reason, err)
			w.Header().Set("Retry-After", spoolRetryAfter)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		s.logger.Error("distfiles: upstream read failed", "name", name, "error", err)
		http.Error(w, "upstream fetch failed", http.StatusBadGateway)
		return
	}
	defer spool.close()

	if spool.size != entry.Size || spool.sha256 != entry.SHA256 {
		s.refuseDistfile(w, r, name, key, entry, spool.sha256, spool.size, up.url)
		return
	}

	s.fillCache(ctx, store, key, spool.path(), up.url, spool.sha256, spool.size)
	s.recordCacheEvent(r, audit.CacheMiss, manifest.TypeDistfiles, up.url, name, name, key)

	if _, err := spool.file.Seek(0, io.SeekStart); err != nil {
		s.logger.Error("distfiles: could not rewind the spooled distfile", "name", name, "error", err)
		http.Error(w, "upstream fetch failed", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", spool.size))
	w.WriteHeader(http.StatusOK)
	//nolint:gosec // G705: the body is a distfile whose digest matched distinfo; Content-Type is set above.
	if _, err := io.Copy(w, spool.file); err != nil {
		s.logger.Warn("distfiles: client read was cut short", "name", name, "error", err)
	}
}

// refuseDistfile answers a fetch whose bytes disagree with distinfo. Nothing
// is cached. computed is empty when the refusal came off the declared length
// alone.
func (s *Server) refuseDistfile(w http.ResponseWriter, r *http.Request, name, key string, entry distinfo.Entry, computed string, size int64, from string) {
	s.logger.Error("distfiles: upstream bytes disagree with distinfo, refusing them",
		"name", name, "upstream", from, "want_sha256", entry.SHA256, "want_size", entry.Size,
		"got_sha256", computed, "got_size", size, "ports", strings.Join(entry.Ports, ","))
	if s.auditDB != nil {
		ctx, cancel := auditContext(r)
		defer cancel()
		details, _ := json.Marshal(map[string]string{
			"expected":      entry.SHA256,
			"computed":      computed,
			"expected_size": fmt.Sprintf("%d", entry.Size),
			"size":          fmt.Sprintf("%d", size),
			"object_key":    key,
			"upstream_url":  from,
			"ports":         strings.Join(entry.Ports, ","),
		})
		_ = s.auditDB.Record(ctx, audit.Event{
			EventType: audit.EventCache,
			PkgType:   manifest.TypeDistfiles,
			PkgName:   name,
			Status:    audit.CacheChecksumMismatch,
			Details:   string(details),
		})
	}
	http.Error(w, "upstream bytes for "+name+" do not match the ports tree's distinfo, so they were not cached or served", http.StatusBadGateway)
}
