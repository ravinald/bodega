package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/clearsign"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/deb822"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
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
// docs/usage.md carries the operator-facing half under "Mirroring an upstream
// archive".
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

// aptRouteCache maps a pool object's key to the upstream root that answered
// for it.
//
// It exists because a pool request carries no codename. apt decided which
// suite to trust when it read a Packages file during `apt update`, and that
// decision is not recoverable from `GET /apt/pool/main/n/nginx/nginx_...deb`:
// the request looks identical whichever suite produced it. So bodega probes
// the roots of the request's archive and remembers.
//
// Keyed by object key, which carries the archive, because one pool path is
// not one package across distributions: Ubuntu rebuilds what it syncs from
// Debian under the same version and filename, so the two publish different
// bytes at one path. Inside one archive the roots (archive, updates,
// security) are one pool, and whichever answers first has the same file.
type aptRouteCache struct {
	mu     sync.Mutex
	routes map[string]aptRoute
}

// get returns the remembered archive for a pool path, and whether the answer
// is still fresh. A fresh answer with an empty URL means "no archive has it".
func (c *aptRouteCache) get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rt, ok := c.routes[key]
	if !ok || time.Since(rt.at) > aptRouteTTL {
		return "", false
	}
	return rt.url, true
}

func (c *aptRouteCache) put(key, upstreamURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.routes == nil || len(c.routes) >= aptRouteCacheMax {
		c.routes = make(map[string]aptRoute, aptRouteCacheMax/8)
	}
	c.routes[key] = aptRoute{url: upstreamURL, at: time.Now()}
}

// handleAptMirrorDists proxies one path under a mirrored codename's dists/
// tree.
//
// Nothing about the bytes is interpreted for the client. The upstream Release
// names the components, architectures and by-hash digests, apt reads them, and
// the next request arrives with the path already composed — so an index bodega
// does not parse is an index bodega cannot get wrong. The age gate records
// every Release or Packages object bodega reads in full for the request, from
// the cache or the archive, including a stale_grace refresh that completes
// after the client was answered from the older copy. It records the read, not
// the delivery: a client that hangs up, reads slowly or sent HEAD still made
// bodega read the whole object, and a prefix that reached a client is never
// evidence. The record takes the earliest date any observation gives, so the
// order the observations arrive in does not matter and none waits for another.
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
	key := manifest.AptArchiveKey(s.cfg.AptArchiveOf(codename), "dists/"+codename+"/"+rest)
	immutable := aptDistsImmutable(rest)
	markIndexResponse(r)

	if s.auditDB == nil || !aptDistsObserved(rest) {
		s.serveAptMirror(w, r, s.typeStore(manifest.TypeApt), key, upstream, aptMirrorPkgName(codename, rest), immutable)
		return
	}
	observe := func(ctx context.Context, raw []byte, acquired time.Time) {
		s.observeAptMirrorDists(ctx, codename, rest, raw)
		s.retainAptServedIndex(ctx, codename, rest, raw, acquired)
	}
	r = withInputObserver(r, &inputObserver{observe: observe})
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

// handleAptMirrorPool proxies one pool artifact of an archive.
//
// The archive's Packages paragraphs are the authority for a path they name:
// the .deb is fetched from the roots of the codename that listed it and held
// to the size and SHA256 that paragraph gives, and a cached copy whose pin
// disagrees is dropped and fetched again. A path no paragraph names is probed
// across the archive's roots and pinned on first fetch, which is all a pool
// path carrying no codename allows.
func (s *Server) handleAptMirrorPool(w http.ResponseWriter, r *http.Request, archive, poolPath string, store storage.ObjectStore) {
	key := manifest.AptArchiveKey(archive, poolPath)
	name, _ := manifest.AptDebIdentity(path.Base(poolPath))
	p := s.profileFor(r)
	refused := s.aptRefusedArchiveRoots(p)
	refuse := func(base string) bool {
		codenames := refused[base]
		if len(codenames) == 0 {
			return false
		}
		s.refuseAptArchive(w, r, p, codenames[0], base+"/"+poolPath, name)
		return true
	}

	// Ahead of the cache read, so a build cached before the index could tell
	// the two apart is not served out of the cache either.
	want, conflict := s.aptPoolParagraph(r.Context(), key)
	if conflict != nil {
		f := aptPoolConflictRefusal(archive, poolPath, name, *conflict)
		s.logger.Warn("apt pool path refused: two codenames of one archive list different builds of it",
			"pool_path", poolPath, "archive", aptArchiveLabel(archive), "codenames", conflict.codenames[0]+" "+conflict.codenames[1],
			"incident", f.incident)
		f.write(w, r)
		return
	}

	// The audit row is unconditional. This is the only path a cached .deb is
	// served by, and it used to write through recordAptPoolHit, whose first
	// line returns on discovery being off — so on a default install every
	// mirrored .deb after the first was served with nothing in the trail
	// saying the cache answered it.
	//
	// The profile judges the cached object only once admit has said it is
	// the build this request would be served. A copy admit rejects is
	// repaired, and the origin of bytes about to be removed says nothing
	// about the build that replaces them; serveAptPoolListed authorizes that
	// one against its paragraph's codename before anything is removed.
	serveHit := func(admit func(cachedObject) bool) {
		s.serveCacheHitIf(w, r, store, key, true, func(obj cachedObject) bool {
			if !admit(obj) {
				return false
			}
			if len(refused) > 0 && !s.aptAdmitCachedDeb(w, r, p, refused, poolPath, key, obj) {
				return false
			}
			return s.aptMirrorHitGate(w, r, poolPath)
		}, func(obj cachedObject) {
			s.recordCacheServed(r, manifest.TypeApt, "", name, key, obj)
			s.recordAptPoolHit(r, poolPath, key, obj)
		})
	}

	if want != nil {
		s.serveAptPoolListed(w, r, store, key, poolPath, name, *want, serveHit, refused, refuse)
		return
	}

	// A cached .deb needs no archive resolved for it, which is the common case
	// once a fleet is warm: the probe is per pool path and the cache read is
	// not. The exception is a host whose profile refuses a vendor archive,
	// where the archive the object came from is the whole question and
	// aptAdmitCachedDeb answers it. No paragraph names this path, so a hit has
	// nothing to be judged against and takes no lock.
	serveAny := func(cachedObject) bool { return true }
	if s.aptCached(r.Context(), store, key, true) != nil {
		serveHit(serveAny)
		return
	}

	// A fill runs under the lock a listed request repairs this key under,
	// because a paragraph naming the path can be published while this request
	// is in flight, and the cache is read again under it: the miss above is a
	// verdict on whatever sat at the key then, and a fill that trusted it would
	// land beside, or after, that repair. The lock is released once the fill
	// has stored its bytes and pin, never held for the transfer to the client.
	var once sync.Once
	locked := s.aptMirror.lock(key)
	release := func() { once.Do(locked) }
	defer release()
	base, ok := s.aptResolvePoolUpstreamAmong(w, r, key, s.cfg.AptPoolUpstreamsIn(archive))
	if !ok {
		return
	}
	if base == "" {
		http.NotFound(w, r)
		return
	}
	if refuse(base) {
		return
	}
	if s.aptCached(r.Context(), store, key, true) != nil {
		release()
		serveHit(serveAny)
		return
	}
	// The resolver answers with the archive root, which is what the route
	// cache keys on: the pool path is already in hand and re-deriving it from
	// a stored full URL would be a second parse of the same string.
	upstream := base + "/" + poolPath
	r = withFillHooks(r, fillHooks{fetchOnly: true, published: release})
	s.proxyOrCache(w, r, store, key, upstream, manifest.TypeApt, upstream, name, true, true)
}

// serveAptPoolListed serves a pool object a Packages paragraph names, and
// only ever the build that paragraph lists.
//
// The object is opened and judged under the lock every repair and fill of this
// key takes, and the lock is released only once the handle is admitted, before
// any byte is streamed. The handle is admitted on the SHA256 of the object it
// is open on (aptOpenedDigest), its length and this process's pin all equaling
// the paragraph's. The pin alone is not evidence: it belongs to the key, and a
// bodega sharing the store with its own checksum database can replace the
// object without touching it. Holding the lock for the open alone keeps
// concurrent hits on one cached .deb from queueing behind each other's
// transfers. Anything else (no copy, no pin, another digest, another length)
// is settled under the same lock, so a request that waited behind a fill
// judges what that fill left against its own paragraph.
//
// A copy that is not the listed build is repaired, and the profile is asked
// about the build the repair would fetch: when every root of the paragraph's
// codename is one the host's profile refuses, the request is refused before
// anything is removed.
func (s *Server) serveAptPoolListed(w http.ResponseWriter, r *http.Request, store storage.ObjectStore, key, poolPath, name string, want aptPoolStanza, serveHit func(admit func(cachedObject) bool), refused map[string][]string, refuse func(base string) bool) {
	var once sync.Once
	locked := s.aptMirror.lock(key)
	release := func() { once.Do(locked) }
	defer release()
	listed := func(obj cachedObject) bool {
		return want.sizeMatches(obj.id.Size) && s.aptPinned(r.Context(), key) == want.sha256 &&
			s.aptOpenedDigest(r.Context(), key, obj) == want.sha256
	}

	if s.aptCached(r.Context(), store, key, true) != nil {
		unlisted := false
		serveHit(func(obj cachedObject) bool {
			if listed(obj) {
				release()
				return true
			}
			unlisted = true
			return false
		})
		if !unlisted {
			return
		}
	}

	roots := s.aptCodenameRoots(want.codename)
	if len(refused) > 0 && len(roots) > 0 && !slices.ContainsFunc(roots, func(root string) bool { return len(refused[root]) == 0 }) {
		refuse(roots[0])
		return
	}
	cached, f := s.aptSettleListedCache(r.Context(), store, key, poolPath, name, want)
	if f != nil {
		f.write(w, r)
		return
	}
	if cached {
		// Under the lock, so this opens what the settle judged; a store some
		// other process writes can still change it, and that is refused rather
		// than served unjudged.
		serveHit(func(obj cachedObject) bool {
			if listed(obj) {
				release()
				return true
			}
			s.aptRepairRefusal(r.Context(), key, poolPath, name, want, "open the cached build it had just verified",
				fmt.Errorf("the object changed while it was opened (%d bytes)", obj.id.Size)).write(w, r)
			return false
		})
		return
	}
	base, ok := s.aptResolvePoolUpstreamAmong(w, r, key, roots)
	if !ok {
		return
	}
	if base == "" {
		http.NotFound(w, r)
		return
	}
	if refuse(base) {
		return
	}
	s.serveAptMirrorIndexed(w, r, store, key, base, poolPath, name, want, release)
}

// aptPinned is the SHA256 pinned for key, or "" when none is pinned or the
// pin cannot be read; either sends the caller to aptSettleListedCache, which
// reads it again and refuses on an error.
func (s *Server) aptPinned(ctx context.Context, key string) string {
	if s.auditDB == nil {
		return ""
	}
	pin, err := s.auditDB.GetChecksum(ctx, key)
	if err != nil || pin == nil {
		return ""
	}
	return pin.Value
}

// aptSettleListedCache brings a listed pool object's cache entry into line
// with the paragraph naming it, under the key's fill lock. It reports true
// when the cached copy is the paragraph's build and pinned as such, and false
// when there is no copy and no disagreeing pin, so a fetch may run.
//
// A copy is kept only on the digest of its own bytes, read here, whether its
// pin is blank or already the listed one: a blank pin is what an operator's
// checksum clear leaves, and a matching pin is this process's record for the
// key, which another bodega sharing the store does not update when it
// replaces the object. A copy whose pin names another build is dropped
// unread. A copy that disagrees is deleted before its pin is cleared, and a
// failed delete refuses the request and keeps the pin, because the pin is
// what makes the next request try the repair again.
func (s *Server) aptSettleListedCache(ctx context.Context, store storage.ObjectStore, key, poolPath, name string, want aptPoolStanza) (bool, *refusal) {
	if s.auditDB == nil || store == nil {
		return s.aptCached(ctx, store, key, true) != nil, nil
	}
	ctx = context.WithoutCancel(ctx)
	fail := func(what string, err error) *refusal {
		return s.aptRepairRefusal(ctx, key, poolPath, name, want, what, err)
	}
	pin, err := s.auditDB.GetChecksum(ctx, key)
	if err != nil {
		return false, fail("read the pinned checksum", err)
	}
	pinned := ""
	if pin != nil {
		pinned = pin.Value
	}
	info, err := store.Head(ctx, key)
	if err != nil {
		return false, fail("read the cached object", err)
	}
	dropped := false
	if info != nil && info.Exists {
		stored, storedSize := pinned, info.Size
		if pinned == "" || pinned == want.sha256 {
			id, sum, err := identifyObject(ctx, store, key)
			if err != nil {
				return false, fail("hash the cached object", err)
			}
			if sum == want.sha256 && want.sizeMatches(id.Size) {
				if pinned == "" {
					pkgType, pkgName, pkgVersion := manifest.ParseKey(key)
					if err := s.auditDB.StoreChecksum(ctx, key, pkgType, pkgName, pkgVersion, "sha256", sum, "computed"); err != nil {
						return false, fail("pin the unpinned cached object", err)
					}
				}
				s.aptMeasured.put(key, id, sum)
				return true, nil
			}
			stored, storedSize = sum, id.Size
		}
		s.logger.Warn("a cached .deb is not the build the Packages paragraph naming its path lists, so bodega drops the object and its pin and fetches it again",
			"key", key, "cached", stored, "cached_size", storedSize, "pinned", pinned,
			"listed", want.sha256, "listed_size", want.size, "codename", want.codename)
		if err := store.Delete(ctx, key); err != nil {
			return false, fail("remove the cached build the paragraph disagrees with", err)
		}
		dropped = true
	}
	if pinned != "" && (pinned != want.sha256 || dropped) {
		if err := s.auditDB.ClearChecksum(ctx, key); err != nil {
			return false, fail("clear the pin the paragraph disagrees with", err)
		}
	}
	return false, nil
}

// aptRepairRefusal answers a listed pool object bodega could not bring into
// line with its paragraph, naming the step that failed.
func (s *Server) aptRepairRefusal(ctx context.Context, key, poolPath, name string, want aptPoolStanza, what string, err error) *refusal {
	_, version := manifest.AptDebIdentity(path.Base(poolPath))
	f := newRefusal(checkChecksum, manifest.TypeApt, name, version, http.StatusBadGateway)
	f.reason = fmt.Sprintf("bodega could not %s for %s, whose Packages paragraph in %s lists sha256 %s, so it serves nothing for it: %v.",
		what, poolPath, want.codename, want.sha256, err)
	f.next = fmt.Sprintf("retry; if it persists, give an operator incident %s, whose ERROR line in the server log names the step that failed.", f.incident)
	s.logFor(ctx).Error("bodega could not repair a cached .deb its Packages paragraph disagrees with, so it refused the request",
		"key", key, "step", what, "listed", want.sha256, "error", err, "incident", f.incident)
	return f
}

// aptMeasuredMax bounds aptMeasuredDigests. Past it the map is dropped whole,
// as aptRouteCache is, and each cached .deb costs one more read on its next
// hit.
const aptMeasuredMax = 65536

// aptMeasuredDigest is the SHA256 bodega read off one stored object, and the
// identity the store gave that object on the read.
type aptMeasuredDigest struct {
	id     audit.ObjectIdentity
	sha256 string
}

// aptMeasuredDigests remembers what each cached pool object hashed to, so a
// hit on an object bodega has already read costs no second read. An entry
// answers only for the identity it was measured under: a replacement, by this
// process or another sharing the store, is a different identity and is read
// again.
type aptMeasuredDigests struct {
	mu   sync.Mutex
	byID map[string]aptMeasuredDigest
}

func (m *aptMeasuredDigests) get(key string, id audit.ObjectIdentity) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.byID[key]
	if !ok || e.id != id {
		return "", false
	}
	return e.sha256, true
}

func (m *aptMeasuredDigests) put(key string, id audit.ObjectIdentity, sum string) {
	if !id.Known() {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.byID == nil || len(m.byID) >= aptMeasuredMax {
		m.byID = make(map[string]aptMeasuredDigest, aptMeasuredMax/8)
	}
	m.byID[key] = aptMeasuredDigest{id: id, sha256: sum}
}

// aptOpenedDigest is the SHA256 of the object obj was opened on, or "" when
// bodega cannot establish it.
//
// A digest measured earlier answers when the store reports the same identity
// for this open. Otherwise the object is read through a second handle, and
// that read counts only when the store reports the same identity for it as
// for obj: a second handle onto a replacement would certify bytes this
// request is not about to send. An object the store reports no identity for
// cannot be tied to a read and is never admitted on one.
func (s *Server) aptOpenedDigest(ctx context.Context, key string, obj cachedObject) string {
	if obj.store == nil || !obj.id.Known() {
		return ""
	}
	if sum, ok := s.aptMeasured.get(key, obj.id); ok {
		return sum
	}
	id, sum, err := identifyObject(context.WithoutCancel(ctx), obj.store, key)
	if err != nil {
		s.logFor(ctx).Warn("a cached .deb could not be read back to check it against its Packages paragraph, so it is repaired rather than served",
			"key", key, "error", err)
		return ""
	}
	if id != obj.id {
		return ""
	}
	s.aptMeasured.put(key, id, sum)
	return sum
}

// aptCodenameRoots is the roots one mirrored codename is configured with, in
// the order apt_upstreams lists them, each once.
func (s *Server) aptCodenameRoots(codename string) []string {
	var out []string
	for _, up := range s.cfg.AptUpstreams[codename] {
		if up.URL != "" && !slices.Contains(out, up.URL) {
			out = append(out, up.URL)
		}
	}
	return out
}

// serveAptMirrorIndexed is serveAptMirror for a .deb a Packages paragraph
// names: the fetched bytes are held to the paragraph's size and SHA256 before
// anything is pinned, cached or served. The caller holds the key's fill lock
// and has settled the cache, so the proxy is told to fetch rather than serve a
// copy it would not hold to the paragraph, and released runs once the fill has
// stored its bytes and pin.
func (s *Server) serveAptMirrorIndexed(w http.ResponseWriter, r *http.Request, store storage.ObjectStore, key, root, poolPath, name string, want aptPoolStanza, released func()) {
	upstream := root + "/" + poolPath
	resolve := func(context.Context) (resolvedUpstream, error) {
		return resolvedUpstream{url: upstream, check: func(ctx context.Context, sum string, size int64) *refusal {
			if sum == want.sha256 && want.sizeMatches(size) {
				return nil
			}
			return s.aptParagraphMismatch(ctx, key, root, poolPath, name, want, sum, size)
		}}, nil
	}
	r = withFillHooks(r, fillHooks{fetchOnly: true, published: released})
	s.proxyOrResolveIndexed(w, r, store, key, resolve, upstream, nil, manifest.TypeApt, upstream, name, true, true)
}

// aptParagraphMismatch records and answers a .deb whose bytes are not the
// build the paragraph naming its path lists, as a checksum refusal is: an
// audit row holding both digests under the incident the body names.
func (s *Server) aptParagraphMismatch(ctx context.Context, key, root, poolPath, name string, want aptPoolStanza, sum string, size int64) *refusal {
	_, _, version := manifest.ParseKey(key)
	f := newRefusal(checkChecksum, manifest.TypeApt, name, version, http.StatusBadGateway)
	f.reason = fmt.Sprintf("%s from %s is %d bytes with sha256 %s, but the Packages paragraph of %s that names it lists %d bytes with sha256 %s; nothing was cached or pinned.",
		poolPath, manifest.PublicURL(root), size, sum, want.codename, want.size, want.sha256)
	f.next = fmt.Sprintf("retry once the archive's pool and index agree again, since the next request asks upstream again; if it persists, give an operator incident %s, whose audit row holds both digests.", f.incident)
	details, _ := json.Marshal(map[string]any{
		"expected":      want.sha256,
		"computed":      sum,
		"expected_size": want.size,
		"computed_size": size,
		"object_key":    key,
		"upstream":      manifest.PublicURL(root),
		"codename":      want.codename,
		"incident":      f.incident,
	})
	if s.auditDB != nil {
		_ = s.auditDB.Record(context.WithoutCancel(ctx), audit.Event{
			EventType:  audit.EventCache,
			PkgType:    manifest.TypeApt,
			PkgName:    name,
			PkgVersion: version,
			Status:     audit.CacheChecksumMismatch,
			Details:    string(details),
		})
	}
	s.logFor(ctx).Error("mirrored .deb differs from the Packages paragraph that names it", "key", key,
		"upstream", manifest.PublicURL(root), "listed", want.sha256, "listed_size", want.size,
		"served", sum, "served_size", size, "incident", f.incident)
	return f
}

// aptPoolConflictRefusal answers a pool path two codenames of one archive list
// with different SHA256 values. Neither build is fetched: whichever answered
// would be pinned, and the client whose index lists the other refuses it.
func aptPoolConflictRefusal(archive, poolPath, name string, c aptPoolConflict) *refusal {
	_, version := manifest.AptDebIdentity(path.Base(poolPath))
	f := newRefusal(checkChecksum, manifest.TypeApt, name, version, http.StatusBadGateway)
	f.reason = fmt.Sprintf("%s is listed by mirrored codename %s with sha256 %s and by %s with sha256 %s, and both are in %s, which shares one pool between them, so bodega cannot tell which build this client expects and fetches neither.",
		poolPath, c.codenames[0], c.digests[0], c.codenames[1], c.digests[1], aptArchiveLabel(archive))
	f.next = fmt.Sprintf("an operator separates the two distributions with apt_archives, which gives each its own /apt/{archive}/ root, and points each host's sources at its own; incident %s.", f.incident)
	return f
}

// aptMirrorOSV is the OSV gate's verdict on one .deb a mirrored codename
// serves, and false when the apt advisory action is unset or ignore, which
// leaves the fetch exactly as ungated as it was before the gate covered apt.
//
// The question is the one a manifest entry is asked: the source package and
// version, read from the mirrored Packages paragraph whose Filename is the
// pool path, in the release the mirrored codename belongs to. Not from the
// filename: the archive pool drops the epoch, OSV's Ubuntu and Debian ranges
// carry it, and openssh's 9.6p1-3ubuntu13.20 compared as epoch 0 sorts below
// a fix at 1:9.6p1-3ubuntu13.3, so every patched build of a package with an
// epoch would read as vulnerable. A pool
// path names no codename, so the release comes from apt_upstreams, and it is
// only placeable while the mirrored codenames are one release (resolute with
// its pockets). Two releases share a pool, and a noble revision checked
// against resolute's ranges sits below every resolute fix and reads
// vulnerable; that is aptAmbiguousSuiteReason's rule, reached from the pool.
//
// Whatever cannot be answered comes back not evaluated, never warn: the
// fetch is served, the admission row says why it went unchecked, and the log
// says so once per release. A warn per artifact would bury the advisory warns
// beside it, and a refusal would stop every install on a host whose release
// nobody has synced yet.
func (s *Server) aptMirrorOSV(ctx context.Context, poolPath string) (policy.Result, bool) {
	if s.auditDB == nil {
		return policy.Result{}, false
	}
	switch p, err := s.auditDB.GetOSVPolicy(ctx, manifest.TypeApt); {
	case errors.Is(err, audit.ErrOSVPolicyNotFound):
		return policy.Result{}, false
	case err == nil && p.Action != policy.ActionWarn && p.Action != policy.ActionBlock:
		return policy.Result{}, false
	}
	name, _ := manifest.AptDebIdentity(path.Base(poolPath))
	if name == "" {
		return policy.Result{}, false
	}
	codename, release, why := s.aptMirrorRelease()
	if why != "" {
		return s.aptMirrorUnchecked(release, why), true
	}
	if _, err := policy.SharedOSVDatabase(s.cfg.ResolveOSVDBDir()).Meta(release); err != nil && !s.cfg.OSVAPIFallback {
		return s.aptMirrorUnchecked(release, fmt.Sprintf(
			"no synced OSV export for %s, the release mirrored codename %s belongs to (%v); run 'bodega policy osv sync apt'",
			release, codename, err)), true
	}
	stanza, why := s.aptMirrorStanza(ctx, poolPath)
	if why != "" {
		return policy.Result{Check: audit.CheckOSV, Action: policy.ActionNotEvaluated, Reason: "not run: " + why}, true
	}
	ve := manifest.VersionEntry{Version: stanza.version, SourcePackage: stanza.source,
		CaptureSuite: codename, Mode: manifest.ModeProxy}
	res := admit.OSVChecker(s.cfg, s.auditDB).Check(ctx, &manifest.PackageManifest{Type: manifest.TypeApt, Name: name}, &ve)
	if res.Action == policy.ActionWarn && res.Details["vulns"] == nil && res.Details["malware"] == nil {
		return s.aptMirrorUnchecked(release, res.Reason), true
	}
	return res, true
}

// aptMirrorAge is the age gate's verdict on one .deb a mirrored codename
// serves, and false when no apt age policy is set or it is ignore.
//
// The date is the one the audit database derives for the source version the
// mirrored paragraph names, for the epoch reason aptMirrorOSV gives. A path the
// current index no longer lists is looked up by the source version an earlier
// index listed it under, so an upgrade rotating it out keeps it gated. A path
// no index bodega read has named, a version nothing recorded, or one an index
// listed that no recorded Release publishes yet, comes back not evaluated
// with the reason, the way aptMirrorOSV treats an index it
// cannot read.
func (s *Server) aptMirrorAge(ctx context.Context, poolPath string) (policy.Result, bool) {
	if s.auditDB == nil {
		return policy.Result{}, false
	}
	switch p, err := s.auditDB.GetAgePolicy(ctx, manifest.TypeApt); {
	case errors.Is(err, audit.ErrAgePolicyNotFound):
		return policy.Result{}, false
	case err == nil && p.Action == policy.ActionIgnore:
		return policy.Result{}, false
	}
	name, version := manifest.AptDebIdentity(path.Base(poolPath))
	if name == "" {
		return policy.Result{}, false
	}
	ve := manifest.VersionEntry{Version: version, Mode: manifest.ModeProxy, Metadata: map[string]string{}}
	stanza, why := s.aptMirrorStanza(ctx, poolPath)
	if why != "" {
		if e, ok, err := s.auditDB.GetAptPoolPath(ctx, poolPath); err != nil {
			why += "; " + err.Error()
		} else if ok {
			stanza, why = aptPoolStanza{source: e.Source, version: e.Version}, ""
		}
	}
	if why != "" {
		ve.Metadata[policy.AptDateErrorKey] = why
	} else if d, ok, err := s.auditDB.GetAptVersionDate(ctx, stanza.source, stanza.version); err != nil {
		ve.Metadata[policy.AptDateErrorKey] = err.Error()
	} else if !ok {
		ve.Metadata[policy.AptDateErrorKey] = fmt.Sprintf(
			"bodega holds no record of a mirrored index listing source %s %s; it records one each time it reads the mirrored Packages, so this one has failed to read or to record since it was listed",
			stanza.source, stanza.version)
	} else if d.DatedBy == audit.AptDatedByNothing {
		ve.Metadata[policy.AptDateErrorKey] = fmt.Sprintf(
			"bodega read an index of %s listing source %s %s, and has recorded no Release publishing that index; the version is dated when bodega next reads a Release that does",
			d.Codename, stanza.source, stanza.version)
	} else {
		ve.Metadata[policy.AptDatedByKey] = d.DatedBy
		ve.Metadata[policy.AptCodenameKey] = d.Codename
		if !d.PublishedAt.IsZero() {
			ve.PublishedAt = d.PublishedAt.UTC().Format(time.RFC3339)
		}
	}
	return policy.NewAgeChecker(s.auditDB).Check(ctx, &manifest.PackageManifest{Type: manifest.TypeApt, Name: name}, &ve), true
}

// aptPoolIndexRetry is how soon a pool index that could not read every
// mirrored codename is rebuilt. Short, because each path the failure hides is
// judged by an older read, or by none, until then; not zero, because the build refetches every
// Packages behind it and apt fetches .debs in bursts.
const aptPoolIndexRetry = time.Minute

// aptPoolStanza is what a mirrored Packages paragraph says about one pool
// path: the source package OSV keys on, the version it is compared at, the
// size and SHA256 the .deb must have, and the codename whose index listed it.
// sha256 is "" and size -1 when the paragraph lists none.
type aptPoolStanza struct {
	source   string
	version  string
	sha256   string
	size     int64
	codename string
}

// sizeMatches reports whether n bytes is the length the paragraph lists. A
// paragraph with no Size field, read as -1, constrains nothing.
func (st aptPoolStanza) sizeMatches(n int64) bool {
	return st.size < 0 || n == st.size
}

// aptPoolConflict is a pool path two codenames of one archive list with
// different SHA256 values. One pool namespace holds one file per path, so the
// index cannot say which build a client asking for it expects.
type aptPoolConflict struct {
	codenames [2]string
	digests   [2]string
}

// aptPoolIndex maps every Filename the mirrored codenames' Packages publish,
// as the object key of the archive the codename belongs to, to its paragraph,
// as read at one moment.
//
// Keyed by object key rather than pool path because two archives publish
// different builds at one path (issue #336), and each archive's paragraph is
// the authority for its own.
//
// shadow holds the paragraphs of later codenames at a key byKey already
// holds, and archives the archive each codename was indexed under, so a
// rebuild that cannot read a codename carries forward every paragraph it last
// read for it rather than only those that came first.
type aptPoolIndex struct {
	ident     string
	byKey     map[string]aptPoolStanza
	shadow    map[string][]aptPoolStanza
	conflicts map[string]aptPoolConflict
	archives  map[string]string
	// indexed holds each codename/component/arch whose Packages this index,
	// or one it carried from, read a body for. A 404 for one of them is a
	// failed read rather than an architecture the root does not serve.
	indexed map[string]bool
	// acquired is, per triple in indexed, when bodega read from upstream the
	// Packages this index or one it carried from parsed for it. at is when
	// the build ran, which says nothing about how old its documents were.
	acquired map[string]time.Time
	failed   []string
	at       time.Time
	ttl      time.Duration
}

// acquire records that the Packages of triple read from upstream at at went
// into idx.
func (idx *aptPoolIndex) acquire(triple string, at time.Time) {
	idx.indexed[triple] = true
	if at.After(idx.acquired[triple]) {
		idx.acquired[triple] = at
	}
}

// acquiredFor is when the newest Packages idx parsed for codename was read
// from upstream, zero when it parsed none.
func (idx *aptPoolIndex) acquiredFor(codename string) time.Time {
	var newest time.Time
	for triple, at := range idx.acquired {
		if strings.HasPrefix(triple, codename+"/") && at.After(newest) {
			newest = at
		}
	}
	return newest
}

// add records one codename's paragraph for key. A path two codenames of one
// archive both publish keeps the first in byKey: the pool is one namespace, so
// agreeing paragraphs describe one file, and disagreeing ones are recorded as
// a conflict.
func (idx *aptPoolIndex) add(key string, st aptPoolStanza) {
	prev, seen := idx.byKey[key]
	if !seen {
		idx.byKey[key] = st
		return
	}
	if prev.codename == st.codename || slices.ContainsFunc(idx.shadow[key], func(o aptPoolStanza) bool { return o.codename == st.codename }) {
		return
	}
	idx.shadow[key] = append(idx.shadow[key], st)
	if _, already := idx.conflicts[key]; !already && prev.sha256 != "" && st.sha256 != "" && prev.sha256 != st.sha256 {
		idx.conflicts[key] = aptPoolConflict{codenames: [2]string{prev.codename, st.codename}, digests: [2]string{prev.sha256, st.sha256}}
	}
}

// carry adds every paragraph prev read for codename, when prev indexed it
// under the archive it belongs to now.
func (idx *aptPoolIndex) carry(prev *aptPoolIndex, codename string) {
	if prev == nil || prev.archives[codename] != idx.archives[codename] {
		return
	}
	for k := range prev.indexed {
		if strings.HasPrefix(k, codename+"/") {
			idx.acquire(k, prev.acquired[k])
		}
	}
	for k, first := range prev.byKey {
		for _, st := range append([]aptPoolStanza{first}, prev.shadow[k]...) {
			if st.codename == codename {
				idx.add(k, st)
			}
		}
	}
}

// aptPoolIndexCache holds the one pool index. Its builder runs under the lock
// so a burst of cold fetches reads the archive's indexes once, not per .deb.
type aptPoolIndexCache struct {
	mu  sync.Mutex
	idx *aptPoolIndex
}

// aptPoolIndexIdent names the configuration an index was built for: which
// codenames are mirrored and the archive each belongs to. An index built
// under another one is rebuilt rather than read.
func (s *Server) aptPoolIndexIdent(codenames []string) string {
	parts := make([]string, len(codenames))
	for i, c := range codenames {
		parts[i] = c + "=" + s.cfg.AptArchiveOf(c)
	}
	return strings.Join(parts, " ")
}

// aptPoolIndexNow is the current pool index, rebuilt first when it is stale or
// was built for another configuration.
func (s *Server) aptPoolIndexNow(ctx context.Context) *aptPoolIndex {
	codenames := s.cfg.MirroredAptCodenames()
	ident := s.aptPoolIndexIdent(codenames)
	s.aptPoolIdx.mu.Lock()
	defer s.aptPoolIdx.mu.Unlock()
	idx := s.aptPoolIdx.idx
	if idx == nil || idx.ident != ident || time.Since(idx.at) >= idx.ttl {
		// Detached from the request: a client hanging up mid-build would
		// otherwise leave a failed index every other fetch is answered from.
		idx = s.buildAptPoolIndexFrom(context.WithoutCancel(ctx), codenames, idx)
		s.aptPoolIdx.idx = idx
	}
	return idx
}

// aptMirrorStanza is the mirrored paragraph for one pool path, or why there is
// none. A path no paragraph names is not answered from its filename instead,
// for the epoch reason aptMirrorOSV gives: the caller records it unchecked.
//
// A pool path names no archive, so this is the paragraph of the first
// mirrored codename, in sorted order, that lists the path in any archive.
func (s *Server) aptMirrorStanza(ctx context.Context, poolPath string) (aptPoolStanza, string) {
	idx := s.aptPoolIndexNow(ctx)
	codenames := s.cfg.MirroredAptCodenames()
	var found *aptPoolStanza
	seen := map[string]bool{}
	for _, c := range codenames {
		archive := s.cfg.AptArchiveOf(c)
		if seen[archive] {
			continue
		}
		seen[archive] = true
		if st, ok := idx.byKey[manifest.AptArchiveKey(archive, poolPath)]; ok && (found == nil || st.codename < found.codename) {
			found = &st
		}
	}
	if found != nil {
		return *found, ""
	}
	why := fmt.Sprintf("no Packages paragraph of mirrored %s, as read at %s, has Filename %s, and the filename's version carries no epoch to compare",
		strings.Join(codenames, " "), idx.at.UTC().Format(time.RFC3339), poolPath)
	if len(idx.failed) > 0 {
		why += "; unreadable: " + strings.Join(idx.failed, "; ")
	}
	return aptPoolStanza{}, why
}

// aptPoolParagraph is what the index says about one pool object: the
// paragraph naming it, the conflict that keeps any paragraph from answering
// for it, or neither when no paragraph of its archive names it.
func (s *Server) aptPoolParagraph(ctx context.Context, key string) (*aptPoolStanza, *aptPoolConflict) {
	idx := s.aptPoolIndexNow(ctx)
	if c, ok := idx.conflicts[key]; ok {
		return nil, &c
	}
	if st, ok := idx.byKey[key]; ok && st.sha256 != "" {
		return &st, nil
	}
	return nil, nil
}

// buildAptPoolIndex reads every mirrored codename's Packages through the same
// cached fetch the filtered codenames use, so it shares their metadata_ttl and
// their allow-list check.
func (s *Server) buildAptPoolIndex(ctx context.Context, codenames []string) *aptPoolIndex {
	return s.buildAptPoolIndexFrom(ctx, codenames, nil)
}

// buildAptPoolIndexFrom is buildAptPoolIndex with the index it replaces. A
// codename this build cannot read keeps the paragraphs prev read for it, and
// those of the Packages files clients were served for it: a failed read does
// not make a path unnamed, and treating it as unnamed would pin whatever build
// the probe reached first.
func (s *Server) buildAptPoolIndexFrom(ctx context.Context, codenames []string, prev *aptPoolIndex) *aptPoolIndex {
	idx := &aptPoolIndex{ident: s.aptPoolIndexIdent(codenames), byKey: map[string]aptPoolStanza{},
		shadow: map[string][]aptPoolStanza{}, conflicts: map[string]aptPoolConflict{}, archives: map[string]string{},
		indexed: map[string]bool{}, acquired: map[string]time.Time{}, at: time.Now(), ttl: s.cache.MetadataTTL}
	if idx.ttl <= 0 {
		idx.ttl = aptRouteTTL
	}
	reads := map[string]aptIndexRead{}
	for _, c := range codenames {
		idx.archives[c] = s.cfg.AptArchiveOf(c)
		if err := s.indexAptPool(ctx, c, idx, prev, reads); err != nil {
			idx.failed = append(idx.failed, err.Error())
			s.aptServed.carryInto(idx, prev, c)
		} else {
			s.aptServed.forget(c, idx)
		}
	}
	if len(idx.failed) > 0 {
		idx.ttl = min(idx.ttl, aptPoolIndexRetry)
		s.logger.Warn("bodega could not read every mirrored apt index, so the .debs those indexes name are judged by the last read of them that succeeded, or probed and pinned on first fetch where none has, until it reads them",
			"failed", strings.Join(idx.failed, "; "), "retry", idx.ttl)
	}
	s.logAptPoolConflicts(idx)
	return idx
}

// logAptPoolConflicts writes one ERROR per pair of codenames whose paragraphs
// disagree about paths in one pool, with how many paths, once per build.
func (s *Server) logAptPoolConflicts(idx *aptPoolIndex) {
	if len(idx.conflicts) == 0 {
		return
	}
	pairs := map[[2]string]int{}
	for _, c := range idx.conflicts {
		pairs[c.codenames]++
	}
	keys := make([][2]string, 0, len(pairs))
	for p := range pairs {
		keys = append(keys, p)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i][0]+" "+keys[i][1] < keys[j][0]+" "+keys[j][1] })
	for _, p := range keys {
		s.logger.Error("two mirrored codenames in one apt archive publish different .debs at the same pool paths, so bodega refuses those paths with 502; declare apt_archives to give each distribution its own pool",
			"codenames", p[0]+" "+p[1], "archive", aptArchiveLabel(s.cfg.AptArchiveOf(p[0])), "paths", pairs[p])
	}
}

// aptArchiveLabel names an archive in a log line or a refusal body.
func aptArchiveLabel(archive string) string {
	if archive == "" {
		return "the default archive"
	}
	return "archive " + archive
}

// indexAptPool adds one codename's paragraphs to idx. A parse break keeps what came before it, since each entry is a
// paragraph that did parse and a path missing past the break goes unchecked
// rather than misjudged.
//
// A 404 for a Packages prev read a body for is returned as an error once the
// rest are read, so the caller carries prev's paragraphs: the Release still
// lists that document, and a mirror mid-sync answering 404 for it says
// nothing about whether the paths it named are still published.
func (s *Server) indexAptPool(ctx context.Context, codename string, idx, prev *aptPoolIndex, reads map[string]aptIndexRead) error {
	release, err := s.aptUpstreamRelease(ctx, codename)
	if err != nil {
		return fmt.Errorf("read the Release for %s: %w", codename, err)
	}
	layout, err := s.aptUpstreamComponents(codename, release)
	if err != nil {
		return err
	}
	archive := s.cfg.AptArchiveOf(codename)
	var vanished []string
	for _, comp := range layout {
		for _, arch := range comp.arches {
			read, err := s.aptUpstreamRead(ctx, codename, comp, arch, release, reads)
			if err != nil {
				return err
			}
			triple := codename + "/" + comp.name + "/" + arch
			if read.notPublished {
				if (prev != nil && prev.indexed[triple]) || s.aptServed.indexed(codename, archive, triple) {
					vanished = append(vanished, triple)
				}
				continue
			}
			idx.acquire(triple, read.at)
			if err := aptPoolStanzas(read.body, archive, codename, idx.add); err != nil {
				return fmt.Errorf("parse the Packages for %s/%s/%s: %w", codename, comp.name, arch, err)
			}
		}
	}
	if len(vanished) > 0 {
		return fmt.Errorf("the Release lists the Packages for %s, which bodega read before, but upstream answered 404 for it", strings.Join(vanished, " "))
	}
	return nil
}

// aptPoolStanzas hands add each paragraph of one decompressed Packages file of
// codename that names a Filename, keyed as an object of archive. A parse break
// returns the error after the paragraphs before it.
func aptPoolStanzas(body []byte, archive, codename string, add func(key string, st aptPoolStanza)) error {
	return deb822.ParseStreamRaw(bytes.NewReader(body), func(_ []byte, fields map[string]string) error {
		filename := strings.TrimSpace(fields["Filename"])
		if filename == "" {
			return nil
		}
		size, err := strconv.ParseInt(strings.TrimSpace(fields["Size"]), 10, 64)
		if err != nil {
			size = -1
		}
		add(manifest.AptArchiveKey(archive, filename), aptPoolStanza{source: deb822.SourceName(fields), version: aptSourceVersion(fields),
			sha256: strings.ToLower(strings.TrimSpace(fields["SHA256"])), size: size, codename: codename})
		return nil
	})
}

// aptServedIndexes is what each listed Packages file a client was served
// said, per codename and component/arch, for the pool index to fall back on.
//
// apt reads Release and Packages before it asks for a single .deb, and from
// then on it expects the builds those paragraphs list. The pool index reads
// the archive on its own schedule, so the first pool request after
// `apt update` can be the first build, and that build can fail; without this
// the paths apt was just told about would be judged as named by nothing.
//
// It has its own lock because the client read that fills it can run while the
// pool index builds, and the builder's lock is held across that build.
type aptServedIndexes struct {
	mu         sync.Mutex
	byCodename map[string]*aptServedCodename
}

// aptServedReleases is how many served Releases of one codename a Packages
// file is checked against: the newest, and the one before it, which a client
// that read its Release just ahead of an archive update still fetches against.
const aptServedReleases = 2

// aptServedCodename is one codename's served paragraphs: the archive they
// were keyed under, per triple (codename/component/arch) the paragraphs of the
// newest file served for it, and the Packages paths the newest served
// Releases list, by SHA256.
type aptServedCodename struct {
	archive  string
	triples  map[string]aptServedTriple
	releases []map[string]string
}

// aptServedTriple is the paragraphs of one served Packages file and when
// bodega read that file from upstream. A file a client was served from the
// cache has a zero time: bodega learned nothing new about upstream by
// delivering it, so it ranks below every read that did.
type aptServedTriple struct {
	stanzas map[string]aptPoolStanza
	at      time.Time
}

// newest is when the newest Packages served for c was read from upstream.
func (c *aptServedCodename) newest() time.Time {
	var newest time.Time
	for _, t := range c.triples {
		if t.at.After(newest) {
			newest = t.at
		}
	}
	return newest
}

// entry is codename's record under archive, created or reset as needed. The
// caller holds mu.
func (sv *aptServedIndexes) entry(codename, archive string) *aptServedCodename {
	if sv.byCodename == nil {
		sv.byCodename = map[string]*aptServedCodename{}
	}
	c := sv.byCodename[codename]
	if c == nil || c.archive != archive {
		c = &aptServedCodename{archive: archive, triples: map[string]aptServedTriple{}}
		sv.byCodename[codename] = c
	}
	return c
}

// recordRelease keeps the Packages paths a Release served for codename lists,
// by SHA256.
func (sv *aptServedIndexes) recordRelease(codename, archive string, byDigest map[string]string) {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	c := sv.entry(codename, archive)
	c.releases = append(c.releases, byDigest)
	if len(c.releases) > aptServedReleases {
		c.releases = slices.Clone(c.releases[len(c.releases)-aptServedReleases:])
	}
}

// releasePath is the Packages path a served Release of codename lists with
// SHA256 sum, newest first, or "" when none does.
func (sv *aptServedIndexes) releasePath(codename, archive, sum string) string {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	c := sv.byCodename[codename]
	if c == nil || c.archive != archive {
		return ""
	}
	for i := len(c.releases) - 1; i >= 0; i-- {
		if rel := c.releases[i][sum]; rel != "" {
			return rel
		}
	}
	return ""
}

// record keeps stanzas as what triple of codename says, unless a file read
// from upstream after at already does.
func (sv *aptServedIndexes) record(codename, archive, triple string, stanzas map[string]aptPoolStanza, at time.Time) {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	c := sv.entry(codename, archive)
	if held, ok := c.triples[triple]; ok && at.Before(held.at) {
		return
	}
	c.triples[triple] = aptServedTriple{stanzas: stanzas, at: at}
}

// indexed reports whether a file served for triple of codename, under
// archive, named its paragraphs.
func (sv *aptServedIndexes) indexed(codename, archive, triple string) bool {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	c := sv.byCodename[codename]
	if c == nil || c.archive != archive {
		return false
	}
	_, ok := c.triples[triple]
	return ok
}

// forget drops the paragraphs served for codename that idx, a build that read
// every index of codename, superseded: a triple read from upstream before idx
// read it, or before the newest file idx read for codename where idx read no
// file for that triple. The served Releases stay, since a client may still
// fetch a Packages file one of them lists.
func (sv *aptServedIndexes) forget(codename string, idx *aptPoolIndex) {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	c := sv.byCodename[codename]
	if c == nil {
		return
	}
	newest := idx.acquiredFor(codename)
	for triple, t := range c.triples {
		read, ok := idx.acquired[triple]
		if !ok {
			read = newest
		}
		if t.at.Before(read) {
			delete(c.triples, triple)
		}
	}
}

// carryInto adds to idx the paragraphs of codename that prev and the served
// files hold, for a build that could not read codename. Whichever of the two
// holds the Packages read from upstream more recently answers for a path both
// name, prev on a tie; each adds the triples only it read. Both are ordered by
// when bodega read upstream, never by when a cached copy was delivered, so a
// replay of an older file cannot displace what the last pool read found.
func (sv *aptServedIndexes) carryInto(idx, prev *aptPoolIndex, codename string) {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	c := sv.byCodename[codename]
	if c == nil || c.archive != idx.archives[codename] {
		idx.carry(prev, codename)
		return
	}
	servedFirst := prev == nil || prev.archives[codename] != idx.archives[codename] || c.newest().After(prev.acquiredFor(codename))
	if !servedFirst {
		idx.carry(prev, codename)
	}
	for triple, t := range c.triples {
		if !servedFirst && prev.indexed[triple] {
			continue
		}
		idx.acquire(triple, t.at)
		for k, st := range t.stanzas {
			idx.add(k, st)
		}
	}
	if servedFirst {
		idx.carry(prev, codename)
	}
}

// retainAptServedIndex keeps what a client was served from a mirrored
// codename's dists/ tree for the pool index to fall back on: the Packages
// digests a Release or InRelease lists, and the paragraphs of a Packages file
// one of those Releases lists, read whole. A Packages file no served Release
// lists, nor a Release the age gate recorded, is not authority and is skipped,
// as is one that does not parse whole.
func (s *Server) retainAptServedIndex(ctx context.Context, codename, rest string, raw []byte, acquired time.Time) {
	archive := s.cfg.AptArchiveOf(codename)
	if rest == "Release" || rest == "InRelease" {
		release, err := deb822.ParseSingle(aptClearsignedBody(raw))
		if err != nil {
			return
		}
		byDigest := map[string]string{}
		for rel, sum := range aptReleaseDigests(release) {
			if _, _, ok := aptPackagesIndexPath(rel); ok && !aptByHash(rel) {
				byDigest[strings.ToLower(sum)] = rel
			}
		}
		s.aptServed.recordRelease(codename, archive, byDigest)
		return
	}
	if _, _, ok := aptPackagesIndexPath(rest); !ok {
		return
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	rel := s.aptServed.releasePath(codename, archive, digest)
	if rel == "" && s.auditDB != nil {
		if snap, listed, err := s.auditDB.LookupAptIndex(context.WithoutCancel(ctx), codename, digest); err == nil && listed {
			rel = snap.Path
		}
	}
	component, arch, ok := aptPackagesIndexPath(rel)
	if !ok {
		return
	}
	body, err := aptDecompressSniffed(codename, rest, raw)
	if err != nil {
		return
	}
	stanzas := map[string]aptPoolStanza{}
	if err := aptPoolStanzas(body, archive, codename, func(key string, st aptPoolStanza) {
		if _, seen := stanzas[key]; !seen {
			stanzas[key] = st
		}
	}); err != nil {
		s.logger.Warn("a mirrored Packages file served to a client does not parse, so its paragraphs are not kept for the pool index to fall back on",
			"codename", codename, "index", rest, "error", err)
		return
	}
	s.aptServed.record(codename, archive, codename+"/"+component+"/"+arch, stanzas, acquired)
}

// The age gate's record of a mirrored codename is built from observations: a
// dated Release bodega read, and a Packages file bodega read or served, kept
// with the versions it lists under its SHA256, which ties it to the recorded
// Releases that published those exact bytes whichever was recorded first. A
// version's date is the earliest Date: among the recorded Releases whose
// Packages listed it, and the codename's baseline is the earliest Release
// recorded for it, whose versions predate bodega. Every value is a minimum,
// so which reader records first, how fast its client reads, and whether the
// bytes came from cache or by-hash cannot change the result.

// errAptReleaseUndated is a Release with no usable Date:, which dates nothing.
var errAptReleaseUndated = errors.New("the mirrored Release carries no usable Date field")

// recordAptRelease records the Packages files a Release of codename digests,
// once per distinct Release, then reads any index the record left the gate
// needing.
func (s *Server) recordAptRelease(ctx context.Context, codename string, release map[string]string) error {
	ctx = context.WithoutCancel(ctx)
	date, dateErr := aptReleaseDate(release)
	ident := sha256.Sum256([]byte(release["Date"] + "\n" + release["SHA256"]))
	if last, ok := s.aptReleaseRecorded.Load(codename); ok && last.([sha256.Size]byte) == ident {
		if dateErr != nil {
			return errAptReleaseUndated
		}
		return nil
	}
	if dateErr != nil {
		s.logger.Warn("a mirrored Release carries no usable Date:, so the age gate dates nothing from it and the versions only it lists are not evaluated",
			"codename", codename, "error", dateErr)
		s.aptReleaseRecorded.Store(codename, ident)
		return errAptReleaseUndated
	}
	if err := s.auditDB.RecordAptRelease(ctx, codename, date, aptReleaseIndexes(release)); err != nil {
		return err
	}
	s.aptReleaseRecorded.Store(codename, ident)
	s.readPendingAptIndexes(ctx, codename)
	return nil
}

// aptReleaseIndexes is every binary Packages file a Release digests.
func aptReleaseIndexes(release map[string]string) []audit.AptReleaseIndex {
	var out []audit.AptReleaseIndex
	for rel, sum := range aptReleaseDigests(release) {
		component, arch, ok := aptPackagesIndexPath(rel)
		if !ok || aptByHash(rel) {
			continue
		}
		out = append(out, audit.AptReleaseIndex{Path: rel, Index: component + "/binary-" + arch, SHA256: sum})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// observeAptMirrorDists is the one place a completely read object from a
// mirrored codename's dists/ tree becomes age gate evidence. Both ways bodega
// reads such an object end here: a client's dists request, through the input
// observer, and aptUpstreamFetch, which the pool index, the profile rebuild
// and the hide filter read through. It runs on the raw bytes before any
// caller checks them, so a caller failing a digest match or a parse has
// already left its evidence.
//
// A Release or InRelease is recorded as a Release, and a Packages file, named
// or by hash, is recorded under the SHA256 of the exact bytes with the
// versions it lists. A digest no recorded Release publishes sends bodega to
// the archive's current Release once; when that does not publish it either,
// the versions are kept undated under the digest until a Release publishing
// it is recorded.
func (s *Server) observeAptMirrorDists(ctx context.Context, codename, rest string, raw []byte) {
	if s.auditDB == nil {
		return
	}
	ctx = context.WithoutCancel(ctx)
	if rest == "Release" || rest == "InRelease" {
		release, err := deb822.ParseSingle(aptClearsignedBody(raw))
		if err == nil {
			err = s.recordAptRelease(ctx, codename, release)
		}
		if err != nil && !errors.Is(err, errAptReleaseUndated) {
			s.logger.Warn("could not record a mirrored Release bodega read, so the age gate dates its indexes when it next reads one",
				"codename", codename, "path", rest, "error", err)
		}
		return
	}
	if _, _, ok := aptPackagesIndexPath(rest); !ok {
		return
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	if seen, err := s.auditDB.AptIndexObserved(ctx, codename, digest); err == nil && seen {
		return
	}
	_, listed, err := s.auditDB.LookupAptIndex(ctx, codename, digest)
	if err == nil && !listed {
		var release map[string]string
		if release, err = s.aptUpstreamRelease(ctx, codename); err == nil {
			err = s.recordAptRelease(ctx, codename, release)
		}
		if err == nil {
			_, listed, err = s.auditDB.LookupAptIndex(ctx, codename, digest)
		}
	}
	if err != nil && !errors.Is(err, errAptReleaseUndated) {
		s.logger.Warn("could not tie a mirrored apt index bodega read to a Release, so the age gate dates the versions it lists when a Release publishing it is recorded",
			"codename", codename, "path", rest, "error", err)
	}
	body, err := aptDecompressSniffed(codename, rest, raw)
	var entries []audit.AptIndexEntry
	if err == nil {
		entries, err = aptIndexEntries(body)
	}
	if !listed && (err != nil || !aptEntriesNameAVersion(entries)) {
		// apt's pdiffs and a binary-<arch>/Release reach here by hash: no
		// Release lists them as a Packages file and they list no version.
		s.logger.Debug("an object read from a mirrored index directory is no Packages file a Release bodega recorded publishes, so the age gate records nothing from it",
			"codename", codename, "path", rest, "sha256", digest, "error", err)
		return
	}
	if err != nil {
		s.logger.Warn("a mirrored apt index does not parse, so the age gate records nothing from it until a read that does",
			"codename", codename, "index", rest, "error", err)
		return
	}
	_ = s.recordAptIndexEntries(ctx, codename, rest, digest, entries)
}

func aptEntriesNameAVersion(entries []audit.AptIndexEntry) bool {
	for _, e := range entries {
		if e.Source != "" && e.Version != "" {
			return true
		}
	}
	return false
}

// aptDecompressSniffed decompresses one Packages file by its leading bytes,
// because a by-hash path carries no suffix and the Release that would name
// the compression may not be recorded yet.
func aptDecompressSniffed(codename, rest string, raw []byte) ([]byte, error) {
	as := "Packages"
	switch {
	case bytes.HasPrefix(raw, []byte{0x1f, 0x8b}):
		as = "Packages.gz"
	case bytes.HasPrefix(raw, []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}):
		as = "Packages.xz"
	}
	body, err := aptDecompressIndex(codename, as, raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", rest, err)
	}
	return body, nil
}

// recordAptIndexEntries records the versions one Packages file lists and a
// source version for each pool path, then reads any index the record left the
// gate needing. A failure is logged and costs only those versions' coverage:
// the gate finds no record and leaves them unchecked, and the next read of
// the file tries again, as does the next mirror rewrite that reuses an index
// built from it.
func (s *Server) recordAptIndexEntries(ctx context.Context, codename, label, sum string, entries []audit.AptIndexEntry) error {
	ctx = context.WithoutCancel(ctx)
	if err := s.auditDB.RecordAptIndexMembers(ctx, codename, sum, entries); err != nil {
		s.logger.Warn("could not record which versions a mirrored apt index listed, so the age gate leaves the new ones unchecked until the next read or index rebuild retries",
			"codename", codename, "index", label, "error", err)
		return err
	}
	s.readPendingAptIndexes(ctx, codename)
	return nil
}

// readPendingAptIndexes reads, by hash from the archive, each Packages file
// the audit database says the gate still needs: the baseline's copy of an
// index bodega has read only a later copy of, so a version the archive listed
// when bodega found it is not dated by the later copy. These are bytes bodega
// never read, and the fetch records them as it does any other read. When the
// archive no longer has them, the versions keep the later date bodega gave
// them, which errs toward holding them.
//
// One pass per record: the reads it makes record indexes of their own, and
// those records do not start another pass, which would refetch what this one
// is already walking.
func (s *Server) readPendingAptIndexes(ctx context.Context, codename string) {
	if ctx.Value(aptPendingReadKey{}) != nil {
		return
	}
	pending, err := s.auditDB.PendingAptIndexes(ctx, codename, aptPackagesCompressions)
	if err != nil {
		s.logger.Warn("could not check which mirrored apt indexes the age gate still needs", "codename", codename, "error", err)
		return
	}
	ctx = context.WithValue(ctx, aptPendingReadKey{}, true)
	for _, ix := range pending {
		if _, err := s.aptUpstreamFetch(ctx, codename, path.Dir(ix.Path)+"/by-hash/SHA256/"+ix.SHA256); err != nil {
			s.logger.Info("an older mirrored apt index the age gate needs cannot be read, so the versions it listed keep the later date bodega gave them",
				"codename", codename, "index", ix.Path, "error", err)
		}
	}
}

// aptPendingReadKey marks a context readPendingAptIndexes is reading under.
type aptPendingReadKey struct{}

// aptIndexEntries is the pool Filename and source version of every paragraph
// of one decompressed Packages file.
func aptIndexEntries(body []byte) ([]audit.AptIndexEntry, error) {
	var entries []audit.AptIndexEntry
	err := deb822.ParseStreamRaw(bytes.NewReader(body), func(_ []byte, fields map[string]string) error {
		entries = append(entries, audit.AptIndexEntry{Filename: strings.TrimSpace(fields["Filename"]),
			Source: deb822.SourceName(fields), Version: aptSourceVersion(fields)})
		return nil
	})
	return entries, err
}

// aptClearsignedBody is the signed text of an InRelease, or raw unchanged when
// it is not clearsigned. bodega checks no signature here: the Release is read
// only for the digests and Date: it publishes. The OpenPGP decoder reads the
// armor, because an archive may sign with CRLF line endings and a split on a
// blank LF line returns the armored document instead of the Release.
func aptClearsignedBody(raw []byte) []byte {
	block, _ := clearsign.Decode(raw)
	if block == nil {
		return raw
	}
	return block.Plaintext
}

// aptDistsObserved reports whether the age gate records what a client read of
// dists/<codename>/rest served.
func aptDistsObserved(rest string) bool {
	if rest == "Release" || rest == "InRelease" {
		return true
	}
	_, _, ok := aptPackagesIndexPath(rest)
	return ok
}

// aptPackagesIndexPath is the component and architecture of a dists/ path
// naming a binary Packages index, compressed or by hash.
func aptPackagesIndexPath(rest string) (component, arch string, ok bool) {
	component, tail, ok := strings.Cut(rest, "/binary-")
	if !ok || component == "" {
		return "", "", false
	}
	arch, file, ok := strings.Cut(tail, "/")
	if !ok || arch == "" {
		return "", "", false
	}
	switch {
	case file == "Packages", file == "Packages.gz", file == "Packages.xz", strings.HasPrefix(file, "by-hash/"):
		return strings.TrimPrefix(component, "updates/"), arch, true
	}
	return "", "", false
}

// aptReleaseDate parses a Release's Date:, which Debian and Ubuntu write in
// RFC 1123 form with the zone as UTC or a numeric offset.
func aptReleaseDate(release map[string]string) (time.Time, error) {
	raw := strings.TrimSpace(release["Date"])
	if raw == "" {
		return time.Time{}, errors.New("the Release has no Date: field")
	}
	for _, layout := range []string{time.RFC1123Z, time.RFC1123} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("the Release Date: %q is not an RFC 1123 time", raw)
}

// aptSourceVersion is the version of the source a paragraph was built from.
// A binNMU's Source: field names it in parentheses because the binary was
// rebuilt under a version of its own, and OSV's ranges are source versions.
func aptSourceVersion(fields map[string]string) string {
	src := fields["Source"]
	if i := strings.IndexByte(src, '('); i > 0 {
		if v, _, ok := strings.Cut(src[i+1:], ")"); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return strings.TrimSpace(fields["Version"])
}

// aptMirrorRelease is the one release every mirrored codename belongs to, a
// codename of it for the lookup to name, and why there is none when there is
// not. release is also the key the unchecked log is deduplicated on.
func (s *Server) aptMirrorRelease() (codename, release, why string) {
	byRelease := map[string]string{}
	var releases []string
	for _, c := range s.cfg.MirroredAptCodenames() {
		rel := policy.AptOSVEcosystem(c)
		if rel == "" {
			rel = c
		}
		if _, ok := byRelease[rel]; !ok {
			byRelease[rel] = c
			releases = append(releases, rel)
		}
	}
	switch {
	case len(releases) > 1:
		return "", "mirrored releases " + strings.Join(releases, ", "), fmt.Sprintf(
			"this bodega mirrors %d releases (%s) from one pool, and a pool path names none of them, so nothing places this .deb in one release's advisories",
			len(releases), strings.Join(releases, ", "))
	case len(releases) == 0:
		return "", "no mirrored release", "no codename is mirrored"
	}
	rel := releases[0]
	if policy.AptOSVEcosystem(byRelease[rel]) == "" {
		return "", rel, fmt.Sprintf("mirrored codename %s names no release OSV publishes an Ubuntu or Debian export for", rel)
	}
	return byRelease[rel], rel, ""
}

// aptMirrorUnchecked is the not-evaluated verdict for a mirrored .deb the gate
// cannot answer for, logged the first time each release produces one.
func (s *Server) aptMirrorUnchecked(release, reason string) policy.Result {
	if _, seen := s.aptOSVUnchecked.LoadOrStore(release, true); !seen {
		s.logger.Warn("mirrored apt is served unchecked by the OSV gate",
			"release", release, "reason", reason)
	}
	return policy.Result{Check: audit.CheckOSV, Action: policy.ActionNotEvaluated, Reason: "not run: " + reason}
}

// aptMirrorHitGate runs the OSV gate on a mirrored .deb served out of the
// cache, and returns false once it has written a refusal.
//
// The miss is gated in versionPolicyGate like every other fill. The hit is
// gated here as well because a mirrored .deb has no manifest entry for
// 'bodega policy osv rescan' to revisit, so a version cached before its
// advisory was published would otherwise be served for as long as the cache
// holds it. A row is written only for a finding: one per cached install would
// bury the decisions the rows exist for.
//
// The age gate is not run here. A version's age only grows, so the fill's
// verdict stands for the bytes it admitted, as an oci blob takes its tag's,
// and a hit costs no index read for it.
func (s *Server) aptMirrorHitGate(w http.ResponseWriter, r *http.Request, poolPath string) bool {
	res, on := s.aptMirrorOSV(r.Context(), poolPath)
	if !on || (res.Action != policy.ActionWarn && res.Action != policy.ActionBlock) {
		return true
	}
	name, version := manifest.AptDebIdentity(path.Base(poolPath))
	fill := fillAdmission{typ: manifest.TypeApt, name: name, version: version}
	allow := audit.AdmissionCheck{Check: audit.CheckAllowList, Action: audit.ActionNone, Status: audit.CheckNotEvaluated,
		Detail: "not run: served from the cache, which the allow-list ruled on when it was filled"}
	ctx, cancel := auditContext(r)
	fr := admit.Fetch(ctx, s.auditDB, []policy.VersionChecker{verdict{res}}, fill.typ, fill.name,
		manifest.VersionEntry{Version: version, Mode: manifest.ModeProxy}, allow, admit.Who{Identity: Identity(r)}, "")
	cancel()
	s.recordFillPolicyEvent(r, fill, fr)
	if fr.Block == nil {
		for _, warn := range fr.Warns {
			s.logger.Warn("cached apt fetch served with a policy warning", "package", name,
				"version", version, "check", warn.Check, "reason", warn.Reason)
		}
		return true
	}
	f := admitRefusal(fill.typ, name, admitBlock{check: fr.Block.Check, version: version,
		incident: fr.Incident, details: fr.Block.Details})
	s.logger.Warn("cached apt fetch blocked by policy", "package", name, "version", version,
		"check", fr.Block.Check, "reason", fr.Block.Reason, "incident", f.incident)
	s.queueResult(r, fill.typ, name, version, *fr.Block, f)
	f.write(w, r)
	return false
}

// recordAptPoolHit writes the discovery row alone for a .deb served out of the
// cache; the audit row is its caller's, which owes one whatever discovery is
// set to.
//
// The pool path names no archive — that is why aptRouteCache exists — and a
// cached object is served without resolving one, so the archive has to be
// recovered rather than probed: a HEAD per served .deb would undo the
// short-circuit this sits inside. A fresh route entry answers first; failing
// that, a single configured archive is unambiguous, and failing that, the
// origin recorded when the bytes were fetched names the archive. That last one
// is what a restarted server has for every .deb it cached under several
// archives, Debian's two among them.
//
// With none of the three, the row is skipped. The alternative is a row whose
// pattern hint is not the host, which would split one archive's traffic across
// two buckets in `bodega discover list` — a wrong answer where this is a
// missing one. It resolves itself on the next miss, which repopulates the
// route.
func (s *Server) recordAptPoolHit(r *http.Request, poolPath, key string, obj cachedObject) {
	if s.discovery == nil || s.discoverMode == "" {
		return
	}
	upstream := s.aptPoolHitUpstream(r, poolPath, key, obj)
	if upstream == "" {
		s.logger.Debug("apt pool cache hit not recorded: no archive resolved for this path",
			"pool_path", poolPath)
		return
	}
	name, _ := manifest.AptDebIdentity(path.Base(poolPath))
	s.recordCacheHitDiscovery(r.Context(), r, manifest.TypeApt, upstream, upstream, name, key)
}

// aptPoolHitUpstream names the archive a cached pool object came from, or ""
// when nothing short of a network probe can say. A recorded origin under no
// configured root says nothing about today's archives and is not used.
func (s *Server) aptPoolHitUpstream(r *http.Request, poolPath, key string, obj cachedObject) string {
	if base, fresh := s.aptRoutes.get(key); fresh && base != "" {
		return base + "/" + poolPath
	}
	archive, _, _ := manifest.SplitAptKey(key)
	candidates := s.cfg.AptPoolUpstreamsIn(archive)
	if len(candidates) == 1 {
		return candidates[0] + "/" + poolPath
	}
	if s.auditDB == nil {
		return ""
	}
	if origin := s.cachedOrigin(r, key, obj); origin != "" {
		for _, root := range candidates {
			if strings.HasPrefix(origin, root+"/") {
				return root + "/" + poolPath
			}
		}
	}
	return ""
}

// serveAptMirror runs one mirrored fetch through proxyOrCache, coalescing
// concurrent misses for the same object.
//
// It serves the dists/ tree; pool objects take handleAptMirrorPool's lock,
// which a listed repair shares. Coalescing is skipped on a hit. A fleet
// running apt update at the same minute should make one upstream fetch, but
// concurrent clients reading one cached index must not serialize behind each
// other, which would turn the cache into the bottleneck it exists to remove.
// The waiters re-enter proxyOrCache after the leader returns and find the
// object in storage.
func (s *Server) serveAptMirror(w http.ResponseWriter, r *http.Request, store storage.ObjectStore, key, upstream, pkgName string, immutable bool) {
	if s.aptCached(r.Context(), store, key, immutable) == nil {
		release := s.aptMirror.lock(key)
		defer release()
	}
	// policyCandidate is the upstream URL: apt is a host-scoped type, so the
	// allow-list matches its hostname. proxyOrCache runs that check before
	// fetchUpstream, which is what keeps a refused archive from being
	// contacted at all. The discovery row's name and version are read back off
	// the key by manifest.ParseKey, which parses the same filename this
	// handler did.
	s.proxyOrCache(w, r, store, key, upstream, manifest.TypeApt, upstream, pkgName, immutable, true)
}

// aptResolvePoolUpstream returns the upstream root that has the pool object
// key names, an empty string when none does, and ok=false when it has already
// written the response.
//
// The candidates are the roots of the key's own archive, so a path one
// distribution publishes is never answered by another's build of it. They are
// probed in sorted order and the winner is remembered, so a
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
func (s *Server) aptResolvePoolUpstream(w http.ResponseWriter, r *http.Request, key string) (string, bool) {
	archive, _, _ := manifest.SplitAptKey(key)
	return s.aptResolvePoolUpstreamAmong(w, r, key, s.cfg.AptPoolUpstreamsIn(archive))
}

// aptResolvePoolUpstreamAmong is aptResolvePoolUpstream over the candidates
// given, in the order given. A remembered route outside them is not used: it
// was resolved over a wider list before the index narrowed it, and may be the
// other distribution's root.
func (s *Server) aptResolvePoolUpstreamAmong(w http.ResponseWriter, r *http.Request, key string, candidates []string) (string, bool) {
	if cached, fresh := s.aptRoutes.get(key); fresh && (cached == "" || slices.Contains(candidates, cached)) {
		return cached, true
	}
	_, poolPath, _ := manifest.SplitAptKey(key)

	ctx := r.Context()
	// The verdict alone runs detached, for the reason
	// enforceUpstreamPolicyRecording detaches: a cold rule cache makes it a
	// database read, and a client that hung up would turn the refusal into a
	// 500 with no row. The probe below keeps the request context, so a
	// canceled client still stops the network work it was waiting on.
	verdictCtx, cancel := auditContext(r)
	defer cancel()
	name, version := manifest.AptDebIdentity(path.Base(poolPath))
	var refused []string
	// One refusal, and so one incident, across every candidate row: the
	// client made one request and gets one answer.
	f := allowListRefusal(manifest.TypeApt, "", name, version)
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
				s.recordDiscovery(ctx, r, manifest.TypeApt, candidate, candidate, name, key, decision)
				s.recordPolicyViolation(r, manifest.TypeApt, candidate, candidate, f.incident)
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
			s.aptRoutes.put(key, base)
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
			"pool_path", poolPath, "archives", strings.Join(refused, " "), "incident", f.incident)
		first := candidates[0] + "/" + poolPath
		s.queueRefusal(r, audit.QueueRefusal{PkgType: manifest.TypeApt, PkgName: name, PkgVersion: version,
			Check: admit.QueueAllowList, Pattern: queuePattern(manifest.TypeApt, first, first, name),
			Detail: f.reason, Incident: f.incident})
		f.write(w, r)
		return "", false
	}

	// Negative result, remembered. apt retries a failed download, and without
	// this every retry would fan back out across every configured archive.
	s.aptRoutes.put(key, "")
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
	req.Header.Set("User-Agent", policy.UserAgent)
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
// aptCached returns what the store reports about a cached object fit to serve,
// or nil when there is none. The metadata comes back rather than a bool because
// the audit row for the served bytes has to name the object it is describing,
// and a second Head to recover it would be a second answer to a question this
// one already asked.
func (s *Server) aptCached(ctx context.Context, store storage.ObjectStore, key string, immutable bool) *storage.ObjectInfo {
	if store == nil {
		return nil
	}
	status, err := store.Head(ctx, key)
	if err != nil || status == nil || !status.Exists {
		return nil
	}
	if !immutable && s.isCacheStale(status) {
		return nil
	}
	return status
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
