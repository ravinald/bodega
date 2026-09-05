package server

import (
	"context"
	"fmt"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// ---- apt transparent mirror ------------------------------------------------
//
// A codename in apt_upstreams is served entirely from upstream: the dists/
// tree is proxied byte-for-byte, InRelease and Release.gpg included, so the
// archive's own signature reaches the client intact and verifies against the
// distro keyring the client already has. bodega neither generates nor signs
// anything for such a codename.
//
// That is why config.Load refuses a codename in both apt_suites and
// apt_upstreams. bodega's signature covers the digests of bodega's Packages;
// upstream's covers the digests of upstream's. One URL can serve one Packages
// file per (component, arch), so a shared codename would necessarily hand a
// client an InRelease whose digests do not describe the index it gets next.
// The alternatives and why they lost are in
// docs-internal/DESIGN_apt-suites-and-signing_2026_08_25.md.
//
// Dependency awareness arrives free with the index: apt parses the proxied
// Packages locally and then asks bodega for each .deb by its Filename, so the
// pool rows in the discovery log are the closure of what the fleet installs.

const (
	// aptRouteTTL is how long a pool path's resolved archive is remembered.
	// Positive and negative results share it: without a negative entry a path
	// no archive has would re-probe every configured host on every retry, and
	// apt retries.
	aptRouteTTL = time.Hour

	// aptRouteCacheMax bounds the route cache. Its keys are pool paths from
	// the request, so a client can invent them; past the cap the whole map is
	// dropped rather than evicted one entry at a time. Re-probing a few hot
	// paths costs a HEAD each, and an LRU here would be machinery guarding a
	// few megabytes.
	aptRouteCacheMax = 8192

	// aptProbeTimeout bounds one candidate probe. The probe is a HEAD against
	// an archive that may be slow or down, and a client waits behind every
	// candidate in the list, so this is the per-candidate share of that wait
	// rather than the 90s a full fetch is allowed.
	aptProbeTimeout = 10 * time.Second
)

// aptRoute is one pool path's resolved archive and the moment it resolved. An
// empty URL is a negative result and is deliberately cacheable: "no configured
// archive has this path" is the answer that costs the most to recompute.
type aptRoute struct {
	url string
	at  time.Time
}

// aptRouteCache maps a pool path to the archive that answered for it.
//
// It exists because a pool request carries no codename. apt decided which
// archive to trust when it read a Packages file during `apt update`, and that
// decision is not recoverable from `GET /apt/pool/main/n/nginx/nginx_...deb`:
// the request looks identical whichever suite produced it. So bodega probes
// and remembers, and an operator serving two archives that publish different
// bytes at one pool path is served whichever probe answered first. Real
// Debian and Ubuntu archives do not do that — a pool path names one version of
// one package — but a private mirror rebuilt from source can.
type aptRouteCache struct {
	mu     sync.Mutex
	routes map[string]aptRoute
}

// get returns the remembered archive for a pool path, and whether the answer
// is still fresh. A fresh answer with an empty URL means "no archive has it".
func (c *aptRouteCache) get(poolPath string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rt, ok := c.routes[poolPath]
	if !ok || time.Since(rt.at) > aptRouteTTL {
		return "", false
	}
	return rt.url, true
}

func (c *aptRouteCache) put(poolPath, upstreamURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.routes == nil || len(c.routes) >= aptRouteCacheMax {
		c.routes = make(map[string]aptRoute, aptRouteCacheMax/8)
	}
	c.routes[poolPath] = aptRoute{url: upstreamURL, at: time.Now()}
}

// handleAptMirrorDists proxies one path under a mirrored codename's dists/
// tree.
//
// Nothing about the bytes is interpreted. The upstream Release names the
// components, architectures and by-hash digests, apt reads them, and the next
// request arrives with the path already composed — so an index bodega does not
// parse is an index bodega cannot get wrong.
func (s *Server) handleAptMirrorDists(w http.ResponseWriter, r *http.Request, codename, rest string) {
	if rest == "" {
		http.NotFound(w, r)
		return
	}
	upstreams := s.cfg.AptUpstreams[codename]
	if len(upstreams) == 0 {
		http.NotFound(w, r)
		return
	}

	// Several archives can serve one codename (archive + security + updates),
	// and each publishes its own dists/<codename>/ tree with its own Release.
	// The first is the one whose index this codename means; the rest are
	// reachable under codenames of their own. Mixing them under one name would
	// serve a Release from one host and a Packages from another, which is the
	// hash mismatch the whole disjoint-namespace rule exists to prevent.
	upstream := upstreams[0].URL + "/dists/" + codename + "/" + rest
	key := manifest.AptKey("dists/" + codename + "/" + rest)
	immutable := aptDistsImmutable(rest)

	s.serveAptMirror(w, r, s.typeStore(manifest.TypeApt), key, upstream, aptMirrorPkgName(codename, rest), immutable)
}

// aptMirrorPkgName is the discovery row's package name for a path under a
// mirrored dists/ tree.
//
// A by-hash path names its own digest and no package, so the raw path is ~100
// characters of hex that `bodega discover show apt <host>` sizes the PACKAGE
// column to — six by-hash rows from one `apt install` push UPSTREAM URL off the
// terminal and make the pool rows beside them unreadable. The digest is already
// in the upstream URL on the same row, so collapsing every by-hash entry under
// one name loses nothing and keeps the column the width of a package name.
func aptMirrorPkgName(codename, rest string) string {
	if aptByHash(rest) {
		return codename + "/by-hash"
	}
	return codename + "/" + rest
}

// handleAptMirrorPool proxies one pool artifact, resolving which archive has
// it first.
func (s *Server) handleAptMirrorPool(w http.ResponseWriter, r *http.Request, poolPath string, store storage.ObjectStore) {
	key := manifest.AptKey(poolPath)

	// A cached .deb needs no archive resolved for it, which is the common case
	// once a fleet is warm: the probe below is per pool path and the cache
	// read is not.
	if s.aptCached(r.Context(), store, key, true) {
		s.recordAptPoolHit(r, poolPath, key)
		s.proxyS3(w, r, store, key)
		return
	}

	base, ok := s.aptResolvePoolUpstream(w, r, poolPath)
	if !ok {
		return
	}
	if base == "" {
		http.NotFound(w, r)
		return
	}

	// The resolver answers with the archive root, which is what the route
	// cache keys on: the pool path is already in hand and re-deriving it from
	// a stored full URL would be a second parse of the same string.
	name, _ := aptDebIdentity(path.Base(poolPath))
	s.serveAptMirror(w, r, store, key, base+"/"+poolPath, name, true)
}

// recordAptPoolHit writes the discovery row for a .deb served out of the cache.
//
// The pool path names no archive — that is why aptRouteCache exists — and a
// cached object is served without resolving one, so the archive has to be
// recovered rather than probed: a HEAD per served .deb would undo the
// short-circuit this sits inside. A fresh route entry answers first; failing
// that, a single configured archive is unambiguous.
//
// With several archives configured and no fresh route, the row is skipped. The
// alternative is a row whose pattern hint is not the host, which would split
// one archive's traffic across two buckets in `bodega discover list` — a wrong
// answer where this is a missing one. It resolves itself on the next miss,
// which repopulates the route.
func (s *Server) recordAptPoolHit(r *http.Request, poolPath, key string) {
	if s.discovery == nil || s.discoverMode == "" {
		return
	}
	upstream := s.aptPoolHitUpstream(poolPath)
	if upstream == "" {
		s.logger.Debug("apt pool cache hit not recorded: no archive resolved for this path",
			"pool_path", poolPath)
		return
	}
	name, _ := aptDebIdentity(path.Base(poolPath))
	s.recordCacheHit(r.Context(), r, manifest.TypeApt, upstream, upstream, name, key)
}

// aptPoolHitUpstream names the archive a cached pool object came from, or ""
// when nothing in memory can say without a network probe.
func (s *Server) aptPoolHitUpstream(poolPath string) string {
	if base, fresh := s.aptRoutes.get(poolPath); fresh && base != "" {
		return base + "/" + poolPath
	}
	if candidates := s.cfg.AptPoolUpstreams(); len(candidates) == 1 {
		return candidates[0] + "/" + poolPath
	}
	return ""
}

// serveAptMirror runs one mirrored fetch through proxyOrCache, coalescing
// concurrent misses for the same object.
//
// Coalescing is skipped on a hit. A fleet installing the same package at the
// same minute should make one upstream fetch, but concurrent clients pulling
// one already-cached 80 MB .deb out of storage must not serialize behind each
// other — that would turn the cache into the bottleneck it exists to remove.
// The waiters re-enter proxyOrCache after the leader returns and find the
// object in storage.
func (s *Server) serveAptMirror(w http.ResponseWriter, r *http.Request, store storage.ObjectStore, key, upstream, pkgName string, immutable bool) {
	if !s.aptCached(r.Context(), store, key, immutable) {
		release := s.aptMirror.lock(key)
		defer release()
	}
	// policyCandidate is the upstream URL: apt is a host-scoped type, so the
	// allow-list matches its hostname. proxyOrCache runs that check before
	// fetchUpstream, which is what keeps a refused archive from being
	// contacted at all. The discovery row's version is read back off the key
	// by pkgVersionFromKey, which parses the same filename this handler did.
	s.proxyOrCache(w, r, store, key, upstream, manifest.TypeApt, upstream, pkgName, immutable, true)
}

// aptResolvePoolUpstream returns the archive that has poolPath, an empty
// string when none does, and ok=false when it has already written the response.
//
// Candidates are probed in sorted order and the winner is remembered, so a
// second request for the same .deb goes straight to it. Each candidate clears
// the allow-list before it is contacted: "bodega policy add apt <host>" means
// bodega does not talk to anything else, and a probe that asks first and
// checks the answer later has already made the request the rule forbids.
//
// A refused candidate is skipped rather than fatal. An operator allowing one
// of two configured archives means "use that one", and aborting on whichever
// sorts first would refuse every pool path including the ones the allowed
// archive serves. Only a request where every candidate was refused is a 403,
// and that distinction is what keeps a policy refusal from reading as a
// package that does not exist.
//
// The probe writes no discovery row. proxyOrCache writes one for the fetch
// that follows, and recording here as well would count one client download as
// one row per configured archive.
func (s *Server) aptResolvePoolUpstream(w http.ResponseWriter, r *http.Request, poolPath string) (string, bool) {
	if cached, fresh := s.aptRoutes.get(poolPath); fresh {
		return cached, true
	}

	ctx := r.Context()
	// The verdict alone runs detached, for the reason
	// enforceUpstreamPolicyRecording detaches: a cold rule cache makes it a
	// database read, and a client that hung up would turn the refusal into a
	// 500 with no row. The probe below keeps the request context, so a
	// canceled client still stops the network work it was waiting on.
	verdictCtx, cancel := auditContext(r)
	defer cancel()
	name, version := aptDebIdentity(path.Base(poolPath))
	candidates := s.cfg.AptPoolUpstreams()
	var refused []string
	for _, base := range candidates {
		candidate := base + "/" + poolPath
		if s.policy != nil {
			decision, violation, err := s.upstreamPolicyVerdict(verdictCtx, manifest.TypeApt, candidate)
			if err != nil {
				s.logger.Error("policy check failed", "error", err)
				http.Error(w, "policy check failed", http.StatusInternalServerError)
				return "", false
			}
			if violation {
				// Recorded here rather than left to the fetch, because for
				// this candidate there is no fetch: this is the only place the
				// refusal can be observed. Both rows, because the discovery
				// table answers what the fleet reached for and the audit table
				// answers who was turned away — the same pair
				// enforceUpstreamPolicyRecording writes on the proxy path.
				s.recordDiscovery(ctx, r, manifest.TypeApt, candidate, candidate, name, manifest.AptKey(poolPath), decision)
				s.recordPolicyViolation(r, manifest.TypeApt, candidate, candidate)
				refused = append(refused, base)
				continue
			}
		}
		found, err := s.aptProbe(ctx, candidate)
		if err != nil {
			s.logger.Warn("apt pool probe failed; trying the next archive",
				"pool_path", poolPath, "upstream", candidate, "error", err)
			continue
		}
		if found {
			s.aptRoutes.put(poolPath, base)
			s.logger.Debug("apt pool path resolved", "pool_path", poolPath, "upstream", base)
			return base, true
		}
	}

	// Every configured archive was refused, so the client is being told "no"
	// by policy, not by the archives. Not cached either way: a rule can be
	// widened while the server runs, and a remembered refusal would outlive
	// the change that lifted it.
	if len(refused) == len(candidates) && len(candidates) > 0 {
		s.logger.Warn("apt pool path blocked: every configured archive is off the allow-list",
			"pool_path", poolPath, "archives", strings.Join(refused, " "))
		http.Error(w, "upstream blocked by allow-list", http.StatusForbidden)
		return "", false
	}

	// Negative result, remembered. apt retries a failed download, and without
	// this every retry would fan back out across every configured archive.
	s.aptRoutes.put(poolPath, "")
	s.logger.Info("apt pool path is in no configured archive",
		"pool_path", poolPath, "package", name, "version", version,
		"archives", strings.Join(candidates, " "))
	return "", true
}

// aptProbe reports whether an archive has a path, using HEAD so resolving one
// .deb does not download it twice.
//
// An archive that refuses the method answers "yes": 405 and 501 say nothing
// about whether the path exists, and treating them as absent would make
// bodega work against Debian and silently fail against a mirror with a
// stricter front end. The GET that follows settles it.
func (s *Server) aptProbe(ctx context.Context, rawURL string) (bool, error) {
	if err := upstreamGuard(rawURL); err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(ctx, aptProbeTimeout)
	defer cancel()

	//nolint:gosec // G704: rawURL cleared upstreamGuard immediately above.
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	if err != nil {
		return false, err
	}
	//nolint:gosec // G704: see the guard above; the URL is validated.
	resp, err := upstreamClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusMethodNotAllowed, resp.StatusCode == http.StatusNotImplemented:
		return true, nil
	case resp.StatusCode == http.StatusNotFound, resp.StatusCode == http.StatusGone:
		return false, nil
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return true, nil
	}
	return false, fmt.Errorf("probe returned %d", resp.StatusCode)
}

// aptCached reports whether the object is in storage and still good to serve.
// It mirrors the hit condition inside proxyOrCache rather than replacing it —
// this is the cheap precondition that decides whether to take the coalescing
// lock, and proxyOrCache still makes the real decision.
func (s *Server) aptCached(ctx context.Context, store storage.ObjectStore, key string, immutable bool) bool {
	if store == nil {
		return false
	}
	status, err := store.Head(ctx, key)
	if err != nil || status == nil || !status.Exists {
		return false
	}
	return immutable || !s.isCacheStale(status)
}

// aptPoolIsLocal reports whether a manifest entry owns this pool path, which
// makes the bytes bodega's own build rather than anything to fetch.
//
// The guard matters most in the window where the entry exists and its .deb has
// not been uploaded: without it a storage miss on bodega's own pool path would
// fall through to the mirror, cache some archive's artifact under it, and then
// serve those bytes against the SHA256 the manifest recorded at package time.
// The client's own hash check would reject them, and the operator would be
// looking at a package they built.
func (s *Server) aptPoolIsLocal(poolPath string) bool {
	snap := s.aptSnap.Load()
	if snap == nil {
		return false
	}
	_, ok := snap.poolStorage[poolPath]
	return ok
}

// aptDistsImmutable reports whether a path under dists/ names content-
// addressed bytes.
//
// by-hash entries are keyed by their own digest, so they never change and are
// cached forever. Everything else under dists/ — InRelease, Release,
// Release.gpg, Packages, Sources, Translation-*, Contents-* — is republished in
// place and is refetched after metadata_ttl. Getting this backwards in either
// direction is expensive: an immutable index is a suite frozen at whatever it
// said the first time, and a mutable by-hash entry is every .deb re-downloaded
// on every install.
func aptDistsImmutable(rest string) bool {
	return aptByHash(rest)
}

// aptByHash reports whether a path under dists/ is a by-hash entry. Two callers
// want the same test for different reasons — caching policy and the discovery
// row's package name — and one predicate keeps them from drifting apart.
func aptByHash(rest string) bool {
	return rest == "by-hash" ||
		strings.HasPrefix(rest, "by-hash/") ||
		strings.Contains(rest, "/by-hash/")
}

// aptDebIdentity splits a pool filename into its package name and version.
//
// Debian names a binary package file <package>_<version>_<arch>.<ext>, with an
// epoch's ":" percent-encoded as "%3a" because ":" is not portable in a
// filename. Source artifacts drop the architecture field. Anything that fits
// neither shape yields two empty strings rather than a guess: this feeds the
// discovery rows an operator promotes from, and a wrong package name there
// produces a manifest entry for a package that does not exist.
func aptDebIdentity(filename string) (name, version string) {
	for _, ext := range []string{".deb", ".udeb", ".ddeb", ".dsc"} {
		if strings.HasSuffix(filename, ext) {
			filename = strings.TrimSuffix(filename, ext)
			parts := strings.Split(filename, "_")
			if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
				return "", ""
			}
			return parts[0], strings.ReplaceAll(strings.ReplaceAll(parts[1], "%3a", ":"), "%3A", ":")
		}
	}
	return "", ""
}
