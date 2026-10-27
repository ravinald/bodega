package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

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
	markIndexResponse(r)

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
	p := s.profileFor(r)
	refused := s.aptRefusedArchiveRoots(p)
	refuse := func(base string) bool {
		codenames := refused[base]
		if len(codenames) == 0 {
			return false
		}
		name, _ := manifest.AptDebIdentity(path.Base(poolPath))
		s.refuseAptArchive(w, r, p, codenames[0], base+"/"+poolPath, name)
		return true
	}

	// A cached .deb needs no archive resolved for it, which is the common case
	// once a fleet is warm: the probe is per pool path and the cache read is
	// not. The exception is a host whose profile refuses a vendor archive,
	// where the archive the object came from is the whole question and
	// aptAdmitCachedDeb answers it.
	if cached := s.aptCached(r.Context(), store, key, true); cached != nil {
		// The audit row is unconditional. This shortcut is the only path a
		// cached .deb is served by, and it used to write through
		// recordAptPoolHit, whose first line returns on discovery being off —
		// so on a default install every mirrored .deb after the first was
		// served with nothing in the trail saying the cache answered it.
		name, _ := manifest.AptDebIdentity(path.Base(poolPath))
		s.serveCacheHitIf(w, r, store, key, true, func(obj cachedObject) bool {
			if len(refused) > 0 && !s.aptAdmitCachedDeb(w, r, p, refused, poolPath, key, obj) {
				return false
			}
			return s.aptMirrorHitGate(w, r, poolPath)
		}, func(obj cachedObject) {
			s.recordCacheServed(r, manifest.TypeApt, "", name, key, obj)
			s.recordAptPoolHit(r, poolPath, key, obj)
		})
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
	if refuse(base) {
		return
	}

	// The resolver answers with the archive root, which is what the route
	// cache keys on: the pool path is already in hand and re-deriving it from
	// a stored full URL would be a second parse of the same string.
	name, _ := manifest.AptDebIdentity(path.Base(poolPath))
	s.serveAptMirror(w, r, store, key, base+"/"+poolPath, name, true)
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

// aptPoolIndexRetry is how soon a pool index that could not read every
// mirrored codename is rebuilt. Short, because each path the failure hides is
// served unchecked until then; not zero, because the build refetches every
// Packages behind it and apt fetches .debs in bursts.
const aptPoolIndexRetry = time.Minute

// aptPoolStanza is what a mirrored Packages paragraph says about one pool
// path: the source package OSV keys on, and the version it is compared at.
type aptPoolStanza struct {
	source  string
	version string
}

// aptPoolIndex maps every Filename the mirrored codenames' Packages publish to
// its paragraph, as read at one moment.
type aptPoolIndex struct {
	codenames string
	byPath    map[string]aptPoolStanza
	failed    []string
	at        time.Time
	ttl       time.Duration
}

// aptPoolIndexCache holds the one pool index. Its builder runs under the lock
// so a burst of cold fetches reads the archive's indexes once, not per .deb.
type aptPoolIndexCache struct {
	mu  sync.Mutex
	idx *aptPoolIndex
}

// aptMirrorStanza is the mirrored paragraph for one pool path, or why there is
// none. A path no paragraph names is not answered from its filename instead,
// for the epoch reason aptMirrorOSV gives: the caller records it unchecked.
func (s *Server) aptMirrorStanza(ctx context.Context, poolPath string) (aptPoolStanza, string) {
	codenames := s.cfg.MirroredAptCodenames()
	key := strings.Join(codenames, " ")
	s.aptPoolIdx.mu.Lock()
	idx := s.aptPoolIdx.idx
	if idx == nil || idx.codenames != key || time.Since(idx.at) >= idx.ttl {
		// Detached from the request: a client hanging up mid-build would
		// otherwise leave a failed index every other fetch is answered from.
		idx = s.buildAptPoolIndex(context.WithoutCancel(ctx), codenames)
		s.aptPoolIdx.idx = idx
	}
	s.aptPoolIdx.mu.Unlock()
	if st, ok := idx.byPath[poolPath]; ok {
		return st, ""
	}
	why := fmt.Sprintf("no Packages paragraph of mirrored %s, as read at %s, has Filename %s, and the filename's version carries no epoch to compare",
		key, idx.at.UTC().Format(time.RFC3339), poolPath)
	if len(idx.failed) > 0 {
		why += "; unreadable: " + strings.Join(idx.failed, "; ")
	}
	return aptPoolStanza{}, why
}

// buildAptPoolIndex reads every mirrored codename's Packages through the same
// cached fetch the filtered codenames use, so it shares their metadata_ttl and
// their allow-list check.
func (s *Server) buildAptPoolIndex(ctx context.Context, codenames []string) *aptPoolIndex {
	idx := &aptPoolIndex{codenames: strings.Join(codenames, " "), byPath: map[string]aptPoolStanza{},
		at: time.Now(), ttl: s.cache.MetadataTTL}
	if idx.ttl <= 0 {
		idx.ttl = aptRouteTTL
	}
	reads := map[string]aptIndexRead{}
	for _, c := range codenames {
		if err := s.indexAptPool(ctx, c, idx.byPath, reads); err != nil {
			idx.failed = append(idx.failed, err.Error())
		}
	}
	if len(idx.failed) > 0 {
		idx.ttl = min(idx.ttl, aptPoolIndexRetry)
		s.logger.Warn("the OSV gate could not read every mirrored apt index, so the .debs only those indexes name are served unchecked until it reads them",
			"failed", strings.Join(idx.failed, "; "), "retry", idx.ttl)
	}
	return idx
}

// indexAptPool adds one codename's paragraphs to byPath. A path two codenames
// both publish keeps the first: one pool path is one build, so the paragraphs
// agree. A parse break keeps what came before it, since each entry is a
// paragraph that did parse and a path missing past the break goes unchecked
// rather than misjudged.
func (s *Server) indexAptPool(ctx context.Context, codename string, byPath map[string]aptPoolStanza, reads map[string]aptIndexRead) error {
	release, err := s.aptUpstreamRelease(ctx, codename)
	if err != nil {
		return fmt.Errorf("read the Release for %s: %w", codename, err)
	}
	layout, err := s.aptUpstreamComponents(codename, release)
	if err != nil {
		return err
	}
	for _, comp := range layout {
		for _, arch := range comp.arches {
			read, err := s.aptUpstreamRead(ctx, codename, comp, arch, release, reads)
			if err != nil {
				return err
			}
			if read.notPublished {
				continue
			}
			err = deb822.ParseStreamRaw(bytes.NewReader(read.body), func(_ []byte, fields map[string]string) error {
				filename := strings.TrimSpace(fields["Filename"])
				if _, seen := byPath[filename]; filename != "" && !seen {
					byPath[filename] = aptPoolStanza{source: deb822.SourceName(fields), version: aptSourceVersion(fields)}
				}
				return nil
			})
			if err != nil {
				return fmt.Errorf("parse the Packages for %s/%s/%s: %w", codename, comp.name, arch, err)
			}
		}
	}
	return nil
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
	if base, fresh := s.aptRoutes.get(poolPath); fresh && base != "" {
		return base + "/" + poolPath
	}
	candidates := s.cfg.AptPoolUpstreams()
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
// Coalescing is skipped on a hit. A fleet installing the same package at the
// same minute should make one upstream fetch, but concurrent clients pulling
// one already-cached 80 MB .deb out of storage must not serialize behind each
// other — that would turn the cache into the bottleneck it exists to remove.
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
	name, version := manifest.AptDebIdentity(path.Base(poolPath))
	candidates := s.cfg.AptPoolUpstreams()
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
				s.recordDiscovery(ctx, r, manifest.TypeApt, candidate, candidate, name, manifest.AptKey(poolPath), decision)
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
