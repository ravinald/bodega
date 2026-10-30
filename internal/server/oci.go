package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
	"github.com/ravinald/bodega/internal/storage"
)

// ---- OCI registry ----------------------------------------------------------
//
// Bodega serves the pull half of the OCI distribution spec under /v2/, the
// prefix every container client hardcodes, for each registry oci_upstreams
// names:
//
//   GET /v2/                                     — the ping
//   GET|HEAD /v2/<name>/manifests/<tag|digest>   — tag mutable, digest immutable
//   GET|HEAD /v2/<name>/blobs/<digest>           — one key per digest, shared
//   GET /v2/<name>/tags/list                     — mutable
//   GET /v2/<name>/referrers/<digest>            — mutable, never a 404
//
// One route serves every registry, so the request has to say which one it
// means, and the three client families say it three ways; ociTargetFor reads
// all three. Every other method answers 405, and every error carries the
// spec's JSON body, because docker and containerd print its message and
// nothing else.

// The route segment a request names after the repository.
const (
	ociManifests = "manifests"
	ociBlobs     = "blobs"
	ociTags      = "tags"
	ociReferrers = "referrers"
)

const (
	ociAPIVersionHeader = "Docker-Distribution-API-Version"
	ociDigestHeader     = "Docker-Content-Digest"
	ociFiltersHeader    = "OCI-Filters-Applied"
	ociErrorContentType = "application/json"

	ociDockerHub = "docker.io"

	mediaOCIIndex        = "application/vnd.oci.image.index.v1+json"
	mediaOCIManifest     = "application/vnd.oci.image.manifest.v1+json"
	mediaDockerList      = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaDockerManifest  = "application/vnd.docker.distribution.manifest.v2+json"
	mediaDockerSchema1   = "application/vnd.docker.distribution.manifest.v1+json"
	mediaDockerSchema1JW = "application/vnd.docker.distribution.manifest.v1+prettyjws"
)

// ociManifestAccept is every manifest form bodega serves. Schema 1 is left
// out, so a registry holding both answers with the one bodega can serve.
var ociManifestAccept = strings.Join([]string{mediaOCIIndex, mediaOCIManifest, mediaDockerList, mediaDockerManifest}, ", ")

// ociMaxManifest bounds a manifest read into memory to resolve a tag. The
// distribution spec has registries refuse a manifest over 4 MiB on push.
const ociMaxManifest = 4 << 20

// ociDefaultTokenLifetime is the lifetime the token spec gives a token whose
// response names no expires_in.
const ociDefaultTokenLifetime = 60 * time.Second

// ociTarget is what one /v2/ request names, resolved against oci_upstreams.
type ociTarget struct {
	registry string // a key of oci_upstreams
	repo     string // the repository at that registry
	upstream string // oci_upstreams[registry], userinfo and all
	kind     string // ociManifests, ociBlobs, ociTags or ociReferrers
	ref      string // a tag or digest; "list" for the tag list
}

// name is the package identity: what the allow-list, discovery, hiding and
// constraints are written against.
func (t ociTarget) name() string { return t.registry + "/" + t.repo }

// url is the upstream URL for a path under the repository, with the
// credential left out: it is logged and recorded, and the registry host never
// sees the credential anyway.
func (t ociTarget) url(tail string) string {
	u, err := url.Parse(t.upstream)
	if err != nil {
		return ""
	}
	u.User = nil
	return strings.TrimRight(u.String(), "/") + "/v2/" + t.repo + "/" + tail
}

func (t ociTarget) isDigest() bool { return manifest.OCIValidDigest(t.ref) }

// ociErrorMiddleware gives a refusal written before the request reaches
// handleOCI the same JSON body handleOCI's own carry: the deny list and a
// token's scopes refuse in middleware, as text, and docker prints the
// message of a JSON error and nothing at all of a text one. It wraps
// everything that can refuse, and an error handleOCI already formatted
// passes through it untouched.
func ociErrorMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isOCIRoute(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		ow := &ociResponseWriter{ResponseWriter: w, r: r, kind: ociKindOf(strings.TrimPrefix(r.URL.Path, "/v2/"))}
		defer ow.finish()
		ow.Header().Set(ociAPIVersionHeader, "registry/2.0")
		next.ServeHTTP(ow, r.WithContext(context.WithValue(r.Context(), ociOuterKey{}, ow)))
	})
}

type ociOuterKey struct{}

func (s *Server) handleOCI(w http.ResponseWriter, r *http.Request) {
	p := r.PathValue("path")
	outer, _ := r.Context().Value(ociOuterKey{}).(*ociResponseWriter)
	ow := &ociResponseWriter{ResponseWriter: w, r: r, kind: ociKindOf(p), outer: outer}
	defer ow.finish()
	ow.Header().Set(ociAPIVersionHeader, "registry/2.0")

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		ow.Header().Set("Allow", "GET, HEAD")
		ow.writeError(http.StatusMethodNotAllowed, "UNSUPPORTED",
			fmt.Sprintf("bodega is a pull-only mirror: %s is not served under /v2/. Push to the registry itself.", r.Method))
		return
	}
	if p == "" {
		ow.Header().Set("Content-Type", "application/json")
		ow.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = io.WriteString(ow, "{}")
		}
		return
	}
	t, status, code, msg := s.ociTargetFor(p, r.URL.Query().Get("ns"))
	if status != 0 {
		ow.writeError(status, code, msg)
		return
	}
	switch t.kind {
	case ociManifests:
		if t.isDigest() {
			s.handleOCIManifestDigest(ow, r, t)
		} else {
			s.handleOCIManifestTag(ow, r, t)
		}
	case ociBlobs:
		s.handleOCIBlob(ow, r, t)
	case ociTags:
		s.handleOCITagList(ow, r, t)
	case ociReferrers:
		s.handleOCIReferrers(ow, r, t)
	}
}

// ociKindOf is the route segment a path names, for the error code a 404 on it
// carries, read before the path is validated.
func ociKindOf(p string) string {
	if strings.HasSuffix(p, "/tags/list") {
		return ociTags
	}
	if i := strings.LastIndex(p, "/"); i > 0 {
		rest := p[:i]
		return rest[strings.LastIndex(rest, "/")+1:]
	}
	return ""
}

// splitOCIPath splits <name>/<kind>/<ref>. A repository may hold a segment
// named "manifests", so the split is taken from the right.
func splitOCIPath(p string) (name, kind, ref string, ok bool) {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "", "", "", false
	}
	ref, rest := p[i+1:], p[:i]
	j := strings.LastIndex(rest, "/")
	if j <= 0 {
		return "", "", "", false
	}
	return rest[:j], rest[j+1:], ref, true
}

// ociRegistryOf resolves which registry a request means: containerd's ns
// parameter; else a first path segment holding a dot, which is podman's
// mirror location prefix and which no Docker Hub namespace can be; else
// Docker Hub, the only registry Docker Engine mirrors, with library/
// prepended to an official image's one-segment name as Docker does.
//
// A registry named either way that oci_upstreams lacks is not quietly taken
// as Docker Hub: the same path at another registry is another image.
func ociRegistryOf(name, ns string) (registry, repo string) {
	registry, repo = strings.ToLower(ns), name
	if registry == "" {
		if first, rest, ok := strings.Cut(name, "/"); ok && strings.Contains(first, ".") {
			registry, repo = strings.ToLower(first), rest
		} else {
			registry = ociDockerHub
		}
	}
	if registry == ociDockerHub && !strings.Contains(repo, "/") {
		repo = "library/" + repo
	}
	return registry, repo
}

// parseOCIPackagePath is the package a /v2/ path names, for the audit row,
// with ns the query parameter when the caller has one. It does not consult
// oci_upstreams: a path naming an unknown registry is a 404 and leaves no
// serve row to name.
func parseOCIPackagePath(path, ns string) (name, version string) {
	n, kind, ref, ok := splitOCIPath(strings.TrimPrefix(path, "/v2/"))
	if !ok {
		return "", ""
	}
	registry, repo := ociRegistryOf(n, ns)
	if kind == ociTags {
		ref = ""
	}
	return registry + "/" + repo, ref
}

// ociTargetFor resolves a /v2/ path below the prefix. A non-zero status is the
// error to answer with, and no upstream has been contacted.
func (s *Server) ociTargetFor(p, ns string) (ociTarget, int, string, string) {
	n, kind, ref, ok := splitOCIPath(p)
	if !ok || (kind != ociManifests && kind != ociBlobs && kind != ociReferrers && !(kind == ociTags && ref == "list")) {
		return ociTarget{}, http.StatusNotFound, "NAME_UNKNOWN",
			fmt.Sprintf("bodega serves /v2/<name>/manifests/<reference>, /v2/<name>/blobs/<digest>, /v2/<name>/tags/list and /v2/<name>/referrers/<digest>, and %q is none of them.", "/v2/"+p)
	}
	registry, repo := ociRegistryOf(n, ns)
	upstream, configured := s.cfg.OCIUpstreams[registry]
	if !configured {
		return ociTarget{}, http.StatusNotFound, "NAME_UNKNOWN",
			fmt.Sprintf("registry %q is not one this bodega pulls from. An operator adds it to oci_upstreams to serve it.", registry)
	}
	if !manifest.OCIValidRepository(repo) {
		return ociTarget{}, http.StatusBadRequest, "NAME_INVALID",
			fmt.Sprintf("%q is not a repository name: lowercase components joined by '/'.", repo)
	}
	t := ociTarget{registry: registry, repo: repo, upstream: upstream, kind: kind, ref: ref}
	switch {
	case kind == ociBlobs && !manifest.OCIValidDigest(ref):
		return ociTarget{}, http.StatusBadRequest, "DIGEST_INVALID",
			fmt.Sprintf("%q is not a sha256 digest; bodega serves blobs by sha256:<64 hex> only.", ref)
	case kind == ociReferrers && !manifest.OCIValidDigest(ref):
		return ociTarget{}, http.StatusBadRequest, "DIGEST_INVALID",
			fmt.Sprintf("%q is not a sha256 digest; referrers are listed for a manifest by sha256:<64 hex> only.", ref)
	case kind == ociManifests && !manifest.OCIValidDigest(ref) && !manifest.OCIValidTag(ref):
		return ociTarget{}, http.StatusNotFound, "MANIFEST_UNKNOWN",
			fmt.Sprintf("%q is neither a tag nor a sha256 digest.", ref)
	}
	return t, 0, "", ""
}

// ociForceProxy is composer's rule: a package with no entry, or a proxy
// entry, is fetched on a miss whatever cache_enabled says.
func ociForceProxy(pm *manifest.PackageManifest) bool {
	return pm == nil || packageMode(pm) == manifest.ModeProxy
}

// ociAllowListGate judges the request under its package identity before the
// cache is read. proxyOrResolve judges only a miss, and a blob is shared by
// every repository that carries it, so without this a repository the
// allow-list refuses would be served any layer an admitted one had cached.
// A refusal leaves its discovery row; an admitted request leaves its row
// where the fetch or the hit is recorded.
func (s *Server) ociAllowListGate(w http.ResponseWriter, r *http.Request, typ string, t ociTarget, key string, immutable bool) bool {
	baseline := s.baselineLookup(r.Context(), typ, t.name(), key, immutable)
	override := s.allowListOverrideLookup(r.Context(), typ, t.name(), key, immutable)
	_, ok := s.ociAllowListVerdict(w, r, typ, t, key, immutable, baseline, override)
	return ok
}

// ociAllowListVerdict is ociAllowListGate with the lookups supplied, for the
// tag, whose admission row has to read the same baseline and override answer
// the allow-list did.
func (s *Server) ociAllowListVerdict(w http.ResponseWriter, r *http.Request, typ string, t ociTarget, key string, immutable bool, baseline baselineLookup, override overrideLookup) (string, bool) {
	decision, ok := s.upstreamPolicyGate(w, r, typ, "", t.name(), t.name(), key, true, baseline, override)
	if !ok && decision == audit.DecisionDenied && immutable {
		s.recordFillRefusal(r, typ, t.name(), t.name(), key)
	}
	return decision, ok
}

// ociJudgeVersion is handleComposerDist's gate order for one tag: hidden,
// then the entry's version constraint, under typ.
func (s *Server) ociJudgeVersion(w http.ResponseWriter, r *http.Request, typ string, pm *manifest.PackageManifest, name, tag string) bool {
	if isVersionHidden(pm, tag) {
		s.refuseHidden(w, r, typ, name, tag)
		return false
	}
	if !ociVersionPermits(pm, typ, tag) {
		vc, baseVer := packageVersionConstraint(pm)
		_, ordered := versionAllowed(typ, baseVer, tag, vc)
		s.refuseVersionConstraint(w, r, typ, name, baseVer, tag, vc, ordered)
		return false
	}
	return true
}

// ociVersionPermits reports whether the entry's version constraint admits a
// tag. An exact pin compares as a string, since "latest" or "17-alpine"
// orders against nothing.
func ociVersionPermits(pm *manifest.PackageManifest, typ, tag string) bool {
	if !ociConstrained(pm) {
		return true
	}
	vc, baseVer := packageVersionConstraint(pm)
	if vc == manifest.ConstraintExact && tag == baseVer {
		return true
	}
	ok, _ := versionAllowed(typ, baseVer, tag, vc)
	return ok
}

// ociConstrained reports whether the entry holds its package to a version.
func ociConstrained(pm *manifest.PackageManifest) bool {
	vc, baseVer := packageVersionConstraint(pm)
	return vc != "" && vc != manifest.ConstraintAny && baseVer != ""
}

// handleOCIManifestTag serves a manifest by tag. The tag's key holds the
// digest and media type it resolved to, mutable under metadata_ttl, and the
// manifest itself is stored once under its digest. Resolving through
// proxyOrCache gives the tag every gate, discovery row and stale-grace
// answer a mutable document gets; the bytes then come from the digest key.
func (s *Server) handleOCIManifestTag(w *ociResponseWriter, r *http.Request, t ociTarget) {
	r, typ, fetched, err := s.ociManifestType(r, t)
	ctx := r.Context()
	name := t.name()
	store := s.typeStore(manifest.TypeOCI)
	key := manifest.OCITagKey(t.registry, t.repo, t.ref)
	if err != nil {
		s.refuseChartUnrecorded(w, t, err)
		return
	}
	g, ok := s.ociGateFull(w, r, typ, t, []string{t.ref}, true, key, false)
	if !ok {
		return
	}

	pm := g.pm
	req := r.Clone(withUpstreamOpener(ctx, s.ociTagOpener(t, store, ociPlatformOf(r), fetched)))
	req.Method = http.MethodGet
	for _, h := range []string{"Range", "If-Range", "If-None-Match", "If-Modified-Since"} {
		req.Header.Del(h)
	}
	cw := &capturedResponse{header: http.Header{}}
	s.proxyOrCache(cw, req, store, key, t.url(ociManifests+"/"+t.ref), typ, name, name, false, ociForceProxy(pm))
	if cw.status != http.StatusOK {
		relayCaptured(w, cw)
		return
	}
	var doc ociTagDoc
	if err := json.Unmarshal(cw.body.Bytes(), &doc); err != nil || !manifest.OCIValidDigest(doc.Digest) {
		s.logger.Error("oci tag record does not parse", "key", key, "error", err)
		w.writeError(http.StatusBadGateway, "UNKNOWN",
			fmt.Sprintf("bodega's record of tag %s in %s does not parse, so it cannot say which manifest the tag names. Retry once metadata_ttl has passed.", t.ref, name))
		return
	}
	// The tag record can outlive its manifest, which only a reset or a failed
	// write leaves behind; the manifest is then fetched again by digest.
	body, err := s.ociManifestBytes(ctx, t, doc.Digest, true)
	if err != nil {
		s.logger.Error("oci manifest for a cached tag not read", "key", key, "digest", doc.Digest, "error", err)
		w.writeError(http.StatusBadGateway, "UNKNOWN",
			fmt.Sprintf("tag %s of %s names manifest %s, which bodega does not hold and could not fetch: %v. Retry once the registry answers.", t.ref, name, doc.Digest, err))
		return
	}
	// A refresh can move the tag to a manifest of the other type after the
	// gates ran. A chart's blobs are recorded as its own before anything is
	// refused or served, and what is served is judged again as what it is,
	// with its discovery row under that type.
	served := ociArtifactType(body)
	if served == manifest.TypeHelm {
		if err := s.ociRecordChart(ctx, t, doc.Digest, body); err != nil {
			s.refuseChartUnrecorded(w, t, err)
			return
		}
	}
	if served != typ {
		if g, ok = s.ociGateFull(w, r, served, t, []string{t.ref}, true, key, false); !ok {
			return
		}
		typ = served
		s.recordCacheHitDiscovery(ctx, r, typ, t.url(ociManifests+"/"+t.ref), name, name, key)
	}
	if !s.ociTagPolicyGate(w, r, typ, t, store, doc, body, g.decision, g.baseline, g.override) {
		return
	}
	s.recordOCIResolvedBy(ctx, store, t, doc.Digest, body)
	w.Header().Set("Cache-Control", cachePrivate)
	writeOCIManifest(w, r, doc.MediaType, doc.Digest, body)
}

// ociTagDoc is what a tag's key holds. FirstSeen is when bodega first
// resolved the tag to Digest, which dates an image whose config carries no
// created time.
type ociTagDoc struct {
	Digest    string `json:"digest"`
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
	FirstSeen string `json:"firstSeen,omitempty"`
}

func writeOCIManifest(w http.ResponseWriter, r *http.Request, mediaType, digest string, body []byte) {
	h := w.Header()
	h.Set("Content-Type", mediaType)
	h.Set(ociDigestHeader, digest)
	h.Set("ETag", `"`+digest+`"`)
	h.Set("Content-Length", fmt.Sprint(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		//nolint:gosec // G705: a manifest verified against its digest, under the registry's manifest media type.
		_, _ = w.Write(body)
	}
}

// relayCaptured answers with a response proxyOrCache wrote to a capture.
func relayCaptured(w http.ResponseWriter, cw *capturedResponse) {
	for _, h := range []string{"Content-Type", refusalHeader, "Retry-After", "X-Content-Type-Options"} {
		if v := cw.header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	status := cw.status
	if status == 0 {
		status = http.StatusBadGateway
	}
	w.WriteHeader(status)
	_, _ = w.Write(cw.body.Bytes())
}

// handleOCIManifestDigest serves a manifest by digest. A digest names no
// tag, so it is judged by the tags bodega resolved to it: the allow-list's
// constraint by the one the registry last answered, and under a version
// constraint a digest bodega never resolved is refused, since the constraint
// has nothing to compare. The profile admits it when any tag resolved to it
// is one the profile permits.
func (s *Server) handleOCIManifestDigest(w *ociResponseWriter, r *http.Request, t ociTarget) {
	r, typ, fetched, err := s.ociManifestType(r, t)
	ctx := r.Context()
	store := s.typeStore(manifest.TypeOCI)
	if err != nil {
		s.refuseChartUnrecorded(w, t, err)
		return
	}
	last := s.ociResolvedTag(ctx, store, t, t.ref)
	tags := s.ociResolvedByTags(ctx, store, t, last)
	pm, ok := s.ociGate(w, r, typ, t, tags, last != "", manifest.OCIManifestKey(t.registry, t.repo, t.ref), true)
	if !ok {
		return
	}
	if !s.ociMemberGate(w, r, t, store) {
		return
	}
	s.serveOCIManifestDigest(w, r, typ, t, pm, "", fetched)
}

// ociResolvedByTags is every tag bodega resolved to t.ref, last first. last
// is the allow-list's record, which is all a digest resolved before the
// per-tag markers existed carries. A listing that fails leaves the markers
// out, so a pinned profile refuses rather than guesses.
func (s *Server) ociResolvedByTags(ctx context.Context, store storage.ObjectStore, t ociTarget, last string) []string {
	var tags []string
	if last != "" {
		tags = append(tags, last)
	}
	if store == nil {
		return tags
	}
	prefix := manifest.OCIResolvedByPrefix(t.registry, t.repo, t.ref)
	keys, err := store.List(ctx, prefix)
	if err != nil {
		s.logger.Warn("oci tag resolutions not listed; the digest is judged by the last tag alone",
			"name", t.name(), "digest", t.ref, "error", err)
		return tags
	}
	for _, k := range keys {
		if tag, ok := manifest.OCIResolvedByTag(prefix, k); ok && tag != last {
			tags = append(tags, tag)
		}
	}
	return tags
}

// recordOCIResolvedBy marks t.ref as resolving to digest and, for an index,
// to each platform manifest it lists, which a client pulling the tag asks
// for next by digest. It runs on every tag response bodega serves, cache
// hits and stale answers included, so a digest is judged by the tag a host
// just pulled whatever another host's pulls did to the cache in between.
// One key per tag, so no write loses another's and nothing is evicted; a
// marker already there is not written again.
func (s *Server) recordOCIResolvedBy(ctx context.Context, store storage.ObjectStore, t ociTarget, digest string, body []byte) {
	if store == nil {
		return
	}
	// The client may hang up as soon as it has the bytes, and the next
	// request it makes by digest depends on these writes.
	ctx = context.WithoutCancel(ctx)
	for _, d := range append([]string{digest}, ociIndexChildren(body)...) {
		key := manifest.OCIResolvedByKey(t.registry, t.repo, d, t.ref)
		if info, err := store.Head(ctx, key); err == nil && info != nil && info.Exists {
			continue
		}
		if err := store.Put(ctx, key, []byte(t.ref)); err != nil {
			s.logger.Warn("oci tag resolution not recorded; a profile with a version rule refuses this digest until it is",
				"name", t.name(), "tag", t.ref, "digest", d, "error", err)
		}
	}
}

// refuseUnresolvedDigest answers a digest request a version constraint
// cannot judge.
func (s *Server) refuseUnresolvedDigest(w http.ResponseWriter, r *http.Request, typ, name, digest, baseVer, vc string) {
	f := newRefusal(checkConstraint, typ, name, digest, http.StatusForbidden)
	f.reason = fmt.Sprintf("this server holds %s to version %s (%s), and no tag it resolved names this digest, so the constraint cannot judge it.", name, baseVer, vc)
	f.next = fmt.Sprintf("pull %s by a tag the constraint admits, which records the digest it names, or ask an operator to widen the entry's constraint.", name)
	recordDenialFor(s.auditDB, r, typ, name, digest, audit.DenialVersionConstraint, map[string]string{
		"constraint": vc, "entry_version": baseVer, "incident": f.incident, "reason": f.reason,
	})
	f.write(w, r)
}

// serveOCIManifestDigest fetches or serves the manifest t.ref names, verified
// against the digest before anything is stored. mediaType, when known, is the
// type the response carries on a cache hit; otherwise the type recorded when
// the manifest was fetched does, and only a manifest stored with no record is
// typed by its bytes.
func (s *Server) serveOCIManifestDigest(w *ociResponseWriter, r *http.Request, typ string, t ociTarget, pm *manifest.PackageManifest, mediaType string, fetched *ociFetched) {
	ctx := r.Context()
	store, err := s.versionStore(ctx, manifest.TypeOCI, t.name(), t.ref)
	if err != nil {
		s.logger.Error("storage backend recorded for artifact is not configured",
			"type", manifest.TypeOCI, "package", t.name(), "version", t.ref, "error", err)
		http.Error(w, "storage backend error", http.StatusBadGateway)
		return
	}
	key := manifest.OCIManifestKey(t.registry, t.repo, t.ref)
	if store != nil && mediaType == "" {
		mediaType = s.ociStoredMediaType(ctx, store, t, key)
	}
	w.contentType = mediaType
	w.Header().Set(ociDigestHeader, t.ref)
	w.Header().Set("ETag", `"`+t.ref+`"`)
	req := r.WithContext(withUpstreamOpener(ctx, s.ociManifestOpener(t, store, typ, fetched)))
	upstream := t.url(ociManifests + "/" + t.ref)
	resolve := func(context.Context) (string, error) { return upstream, nil }
	s.proxyOrResolve(&cacheDirectiveWriter{ResponseWriter: w, directive: cachePrivateImmutable}, req, store, key,
		resolve, upstream, nil, typ, t.name(), t.name(), true, ociForceProxy(pm))
}

// ociStoredMediaType is the type a cached manifest is served under, "" when
// none is cached.
func (s *Server) ociStoredMediaType(ctx context.Context, store storage.ObjectStore, t ociTarget, key string) string {
	if b, err := store.Get(ctx, manifest.OCIManifestTypeKey(t.registry, t.repo, t.ref)); err == nil && len(b) > 0 {
		return string(b)
	}
	b, err := store.Get(ctx, key)
	if err != nil || b == nil {
		return ""
	}
	s.logger.Warn("oci manifest cached with no media type record, typing it by its bytes", "key", key)
	return ociMediaType("", b)
}

// handleOCIBlob serves a layer or config blob from the one key its digest
// has, whichever repository and registry it was first fetched under. It is
// judged under the repository it is requested under.
func (s *Server) handleOCIBlob(w *ociResponseWriter, r *http.Request, t ociTarget) {
	ctx := r.Context()
	name := t.name()
	store := s.typeStore(manifest.TypeOCI)
	key := manifest.OCIBlobKey(t.ref)
	typ, pm, ok := s.ociBlobGate(w, r, t, key)
	if !ok {
		return
	}
	if !s.ociMemberGate(w, r, t, store) {
		return
	}
	upstream := t.url(ociBlobs + "/" + t.ref)
	w.Header().Set(ociDigestHeader, t.ref)
	dw := &cacheDirectiveWriter{ResponseWriter: w, directive: cachePrivateImmutable}
	if store != nil {
		if info, err := store.Head(ctx, key); err == nil && info != nil && info.Exists {
			s.serveOCIBlobHit(dw, r, store, key, typ, t, upstream)
			return
		}
	}
	w.contentType = "application/octet-stream"
	req := r.WithContext(withUpstreamOpener(ctx, s.ociDigestOpener(t)))
	resolve := func(context.Context) (string, error) { return upstream, nil }
	s.proxyOrResolve(dw, req, store, key, resolve, upstream, nil, typ, name, name, true, ociForceProxy(pm))
}

// serveOCIBlobHit is serveCacheHit with Range honored: containerd resumes an
// interrupted layer with one, and a layer runs to gigabytes. The row is
// recorded off the handle that supplies the bytes, as serveCacheHit does.
func (s *Server) serveOCIBlobHit(w http.ResponseWriter, r *http.Request, store storage.ObjectStore, key, typ string, t ociTarget, upstream string) {
	res, ok := s.openStored(w, r, store, key)
	if !ok {
		return
	}
	defer func() { _ = res.Body.Close() }()
	obj := cachedObject{store: store, id: streamIdentity(store, res)}
	s.recordCacheHit(r.Context(), r, typ, upstream, t.name(), t.name(), key, obj)
	noteServed(r, key, "")
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Accept-Ranges", "bytes")
	h.Set("ETag", `"`+t.ref+`"`)
	h.Del("Content-Length")
	body := seekableBody(res)
	if _, forward := body.(*forwardSeeker); forward && namesSeveralRanges(r.Header.Get("Range")) {
		r = r.Clone(r.Context())
		r.Header.Del("Range")
	}
	http.ServeContent(w, r, "", time.Time{}, body)
}

// namesSeveralRanges reports whether a Range header asks for more than one
// part. ServeContent writes the 206 and the multipart length before it seeks
// to each part in the order the client named them, so a descending or
// overlapping set needs a backward seek after the headers are gone. A body
// that reads forward only serves such a request in full instead, as HTTP
// permits a server to ignore Range.
func namesSeveralRanges(header string) bool {
	spec, ok := strings.CutPrefix(header, "bytes=")
	if !ok {
		return false
	}
	parts := 0
	for _, ra := range strings.Split(spec, ",") {
		if strings.TrimSpace(ra) != "" {
			parts++
		}
	}
	return parts > 1
}

// seekableBody is the stored object as the io.ReadSeeker ServeContent asks
// for. A backend whose body seeks is used as it is. Any other is read forward
// only: ServeContent learns the size from a seek to the end, which the stored
// length answers without moving, and then seeks once to the start of a range,
// which skips forward. That holds only with Content-Type already set, since
// ServeContent otherwise reads the head to sniff one and seeks back, and only
// for one range, which is why serveOCIBlobHit drops a request for several.
func seekableBody(res *storage.StreamResult) io.ReadSeeker {
	if rs, ok := res.Body.(io.ReadSeeker); ok {
		return rs
	}
	return &forwardSeeker{r: res.Body, size: res.ContentLength}
}

type forwardSeeker struct {
	r    io.Reader
	pos  int64
	size int64
}

func (f *forwardSeeker) Read(p []byte) (int, error) {
	n, err := f.r.Read(p)
	f.pos += int64(n)
	return n, err
}

func (f *forwardSeeker) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekEnd:
		if offset != 0 || f.size < 0 {
			return 0, errors.New("forwardSeeker: only the end itself can be named, and only when the length is known")
		}
		// Reports the length without moving; ServeContent seeks back to
		// where it was next.
		return f.size, nil
	case io.SeekCurrent:
		offset += f.pos
	}
	if offset < f.pos {
		return 0, fmt.Errorf("forwardSeeker: cannot seek back from %d to %d", f.pos, offset)
	}
	if _, err := io.CopyN(io.Discard, f.r, offset-f.pos); err != nil {
		return 0, err
	}
	f.pos = offset
	return f.pos, nil
}

// handleOCITagList serves the upstream's tag list, every page of it cached
// as one mutable document, and pages it for a client that sends n or last.
// Paging here rather than upstream keeps one cache key per repository, so an
// outage serves the whole list and not whichever pages happened to be asked
// for, and a next link that names bodega rather than the registry.
func (s *Server) handleOCITagList(w *ociResponseWriter, r *http.Request, t ociTarget) {
	ctx := r.Context()
	name := t.name()
	noSharedCache(w)
	page, ok := ociPageOf(r.URL.Query())
	if !ok {
		w.writeError(http.StatusBadRequest, "PAGINATION_NUMBER_INVALID",
			fmt.Sprintf("n=%q is not a count of tags; send a whole number, or leave n out for every tag.", r.URL.Query().Get("n")))
		return
	}
	// A repository can hold images and charts at once, and a list names
	// both, so it is judged as oci, and as helm only where oci refuses it and
	// helm admits it: a chart bodega read never takes away a list a host was
	// served before it.
	typ := manifest.TypeOCI
	listKey := manifest.OCITagListKey(t.registry, t.repo)
	if s.ociRepoHoldsCharts(ctx, t) && !s.ociListAdmits(r, manifest.TypeOCI, t, listKey) &&
		s.ociListAdmits(r, manifest.TypeHelm, t, listKey) {
		typ = manifest.TypeHelm
	}
	pm, _ := s.store.GetPackage(ctx, typ, name)
	if pm != nil && isPackageHidden(pm) {
		s.refuseHidden(w, r, typ, name, "")
		return
	}
	// 404 rather than 403 for a repository the profile excludes: to that
	// host it does not exist, which is what a client listing tags is told.
	if !s.entitleGateAnswering(w, r, typ, name, "", http.StatusNotFound) {
		return
	}
	key := manifest.OCITagListKey(t.registry, t.repo)
	if !s.ociAllowListGate(w, r, typ, t, key, false) {
		return
	}
	req := r.Clone(withUpstreamOpener(ctx, s.ociTagListOpener(t)))
	req.Method = http.MethodGet
	cw := &capturedResponse{header: http.Header{}}
	s.proxyOrCache(cw, req, s.typeStore(manifest.TypeOCI), key, t.url("tags/list"), typ, name, name, false, ociForceProxy(pm))
	if cw.status != http.StatusOK {
		relayCaptured(w, cw)
		return
	}
	var list ociTagList
	if err := json.Unmarshal(cw.body.Bytes(), &list); err != nil {
		s.logger.Error("oci tag list does not parse", "key", key, "error", err)
		w.writeError(http.StatusBadGateway, "UNKNOWN",
			fmt.Sprintf("bodega's copy of the tag list for %s does not parse. Retry once metadata_ttl has passed.", name))
		return
	}
	// Filtered here, on the way out, and never stored: the cache holds the
	// registry's list, which every other host is served from.
	if permit := profileVersionFilter(s.profileFor(r), manifest.TypeOCI, name); permit != nil {
		kept := []string{}
		for _, tag := range list.Tags {
			if permit(tag) {
				kept = append(kept, tag)
			}
		}
		list.Tags = kept
	}
	tags, more := page.slice(list.Tags)
	if more {
		q := url.Values{"n": {fmt.Sprint(page.n)}, "last": {tags[len(tags)-1]}}
		if ns := r.URL.Query().Get("ns"); ns != "" {
			q.Set("ns", ns)
		}
		w.Header().Set("Link", fmt.Sprintf(`<%s?%s>; rel="next"`, r.URL.EscapedPath(), q.Encode()))
	}
	body, _ := json.Marshal(ociTagList{Name: list.Name, Tags: tags})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

// ociTagList is the tags/list document.
type ociTagList struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

// ociPage is a client's n and last. n < 0 is no limit.
type ociPage struct {
	n    int
	last string
}

func ociPageOf(q url.Values) (ociPage, bool) {
	p := ociPage{n: -1, last: q.Get("last")}
	if v := q.Get("n"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return p, false
		}
		p.n = n
	}
	return p, true
}

// slice is the page of a lexically sorted list after last, at most n long,
// and whether tags remain past it.
func (p ociPage) slice(tags []string) ([]string, bool) {
	if p.last != "" {
		tags = tags[sort.SearchStrings(tags, p.last):]
		if len(tags) > 0 && tags[0] == p.last {
			tags = tags[1:]
		}
	}
	if p.n >= 0 && len(tags) > p.n {
		return tags[:p.n], p.n > 0
	}
	return tags, false
}

// handleOCIReferrers serves the referrers index of a manifest, cached as a
// mutable document under one key per artifactType filter. Docker Engine asks
// a mirror for it on every pull and takes anything but a 200 as the cue to
// ask the registry itself, around bodega, so a registry with no referrers
// API, an outage with nothing cached and a stored copy that will not parse
// all answer an empty index rather than an error: referrers add signatures
// and attestations to a pull and never take the image away. A refusal is
// still a refusal, judged as a manifest by the same digest is.
func (s *Server) handleOCIReferrers(w *ociResponseWriter, r *http.Request, t ociTarget) {
	ctx := r.Context()
	name := t.name()
	noSharedCache(w)
	artifactType := r.URL.Query().Get("artifactType")
	if artifactType != "" && !ociValidMediaType(artifactType) {
		w.writeError(http.StatusBadRequest, "UNSUPPORTED",
			fmt.Sprintf("artifactType=%q is not a media type such as application/vnd.example.sbom.v1+json; send one, or leave artifactType out for every referrer.", artifactType))
		return
	}
	store := s.typeStore(manifest.TypeOCI)
	key := manifest.OCIReferrersKey(t.registry, t.repo, t.ref, artifactType)
	// Judged as the tag list judges a repository holding charts: as helm only
	// where oci refuses it and helm admits it.
	typ := manifest.TypeOCI
	if s.ociRepoHoldsCharts(ctx, t) && !s.ociListAdmits(r, manifest.TypeOCI, t, key) &&
		s.ociListAdmits(r, manifest.TypeHelm, t, key) {
		typ = manifest.TypeHelm
	}
	last := s.ociResolvedTag(ctx, store, t, t.ref)
	pm, ok := s.ociGate(w, r, typ, t, s.ociResolvedByTags(ctx, store, t, last), last != "", key, false)
	if !ok {
		return
	}
	if !s.ociMemberGate(w, r, t, store) {
		return
	}
	upstream := t.url(ociReferrers + "/" + t.ref)
	if artifactType != "" {
		upstream += "?" + url.Values{"artifactType": {artifactType}}.Encode()
	}
	req := r.Clone(withUpstreamOpener(ctx, s.ociReferrersOpener(t)))
	req.Method = http.MethodGet
	for _, h := range []string{"Range", "If-Range", "If-None-Match", "If-Modified-Since"} {
		req.Header.Del(h)
	}
	cw := &capturedResponse{header: http.Header{}}
	s.proxyOrCache(cw, req, store, key, upstream, typ, name, name, false, ociForceProxy(pm))
	var idx ociReferrersIndex
	switch {
	case cw.status == http.StatusOK && json.Unmarshal(cw.body.Bytes(), &idx) == nil:
	case cw.header.Get(refusalHeader) != "":
		relayCaptured(w, cw)
		return
	default:
		idx = s.ociReferrersFallback(ctx, store, t, artifactType, cw)
	}
	if artifactType != "" {
		idx = idx.filtered(artifactType)
		w.Header().Set(ociFiltersHeader, "artifactType")
	}
	body, _ := json.Marshal(idx)
	w.Header().Set("Content-Type", mediaOCIIndex)
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		//nolint:gosec // G705: an index bodega marshaled itself, under the index media type.
		_, _ = w.Write(body)
	}
}

// ociReferrersFallback is the index served when neither the registry nor
// the copy cached under the request's own key answered one: a filtered
// request reads the unfiltered copy, which it filters on the way out, and
// anything else is the empty index.
func (s *Server) ociReferrersFallback(ctx context.Context, store storage.ObjectStore, t ociTarget, artifactType string, cw *capturedResponse) ociReferrersIndex {
	s.logger.Warn("oci referrers not answered, serving what bodega holds",
		"name", t.name(), "digest", t.ref, "artifact_type", artifactType, "status", cw.status)
	if artifactType != "" && store != nil {
		if b, err := store.Get(ctx, manifest.OCIReferrersKey(t.registry, t.repo, t.ref, "")); err == nil && b != nil {
			var idx ociReferrersIndex
			if json.Unmarshal(b, &idx) == nil {
				return idx
			}
		}
	}
	return emptyOCIReferrers()
}

// ociReferrersIndex is the referrers response: an image index whose
// manifests are the descriptors of the artifacts that name the subject.
type ociReferrersIndex struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	Manifests     []json.RawMessage `json:"manifests"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

func emptyOCIReferrers() ociReferrersIndex {
	return ociReferrersIndex{SchemaVersion: 2, MediaType: mediaOCIIndex, Manifests: []json.RawMessage{}}
}

// filtered keeps the descriptors whose artifactType is the one asked for.
// Applying it to an index the registry already filtered changes nothing.
func (idx ociReferrersIndex) filtered(artifactType string) ociReferrersIndex {
	kept := []json.RawMessage{}
	for _, d := range idx.Manifests {
		var desc struct {
			ArtifactType string `json:"artifactType"`
		}
		if json.Unmarshal(d, &desc) == nil && desc.ArtifactType == artifactType {
			kept = append(kept, d)
		}
	}
	idx.Manifests = kept
	return idx
}

// ociMediaTypeRE is RFC 6838's type/subtype, narrowed to the characters
// registries use, so a filter is safe as one segment of a storage key.
var ociMediaTypeRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,126}/[A-Za-z0-9][A-Za-z0-9.+_-]{0,126}$`)

func ociValidMediaType(v string) bool { return ociMediaTypeRE.MatchString(v) }

// ---- upstream --------------------------------------------------------------

// ociDigestOpener opens a blob through the registry's token handshake. The
// body is verified against t.ref as it is read, and a mismatch fails the read
// before the spool is cached, so no byte that does not hash to the digest is
// stored or served.
func (s *Server) ociDigestOpener(t ociTarget) upstreamOpener {
	return func(ctx context.Context, rawURL string) (*upstreamStream, error) {
		resp, err := s.ociGet(ctx, t, rawURL, "")
		if err != nil {
			return nil, err
		}
		return &upstreamStream{url: answeredURL(resp, rawURL), contentType: resp.Header.Get("Content-Type"), contentLength: resp.ContentLength,
			body: &ociDigestReader{r: resp.Body, h: sha256.New(), want: t.ref, refuse: func(got string) error { return ociMismatch(t, got) }}}, nil
	}
}

// ociManifestOpener fetches a manifest by digest. It reads the manifest whole,
// as the tag opener does, because a schema 1 manifest is told by its body as
// often as by its Content-Type, and the refusal has to come before a byte is
// stored or served. The type it is served under is recorded before
// proxyOrResolve stores the bytes, so a stored manifest always has one.
func (s *Server) ociManifestOpener(t ociTarget, store storage.ObjectStore, typ string, fetched *ociFetched) upstreamOpener {
	return func(ctx context.Context, rawURL string) (*upstreamStream, error) {
		f, err := s.ociFetchOnce(ctx, t, rawURL, &fetched)
		if err != nil {
			return nil, err
		}
		body, ct, answered := f.body, f.contentType, f.answered
		if got := ociDigest(body); got != t.ref {
			return nil, afterAnswer(ociMismatch(t, got))
		}
		if got := ociArtifactType(body); got != typ {
			return nil, afterAnswer(ociTypeChanged(t, typ, got))
		}
		mediaType := ociMediaType(ct, body)
		if typ == manifest.TypeHelm {
			if err := s.ociRecordChart(ctx, t, t.ref, body); err != nil {
				return nil, afterAnswer(err)
			}
		}
		if store != nil {
			if err := store.Put(ctx, manifest.OCIManifestTypeKey(t.registry, t.repo, t.ref), []byte(mediaType)); err != nil {
				return nil, afterAnswer(fmt.Errorf("record the media type of manifest %s for %s: %w", t.ref, t.name(), err))
			}
			s.ociInheritVerdicts(ctx, store, t, body)
		}
		return &upstreamStream{url: answered, body: io.NopCloser(bytes.NewReader(body)),
			contentType: mediaType, contentLength: int64(len(body))}, nil
	}
}

// ociFetchManifest reads one manifest whole, bounded, and refuses schema 1.
func (s *Server) ociFetchManifest(ctx context.Context, t ociTarget, rawURL string) (*ociFetched, error) {
	resp, err := s.ociGet(ctx, t, rawURL, ociManifestAccept)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	answered := answeredURL(resp, rawURL)
	body, err := io.ReadAll(io.LimitReader(resp.Body, ociMaxManifest+1))
	if err != nil {
		return nil, afterAnswer(fmt.Errorf("read the manifest for %s:%s from %s: %w", t.name(), t.ref, answered, err))
	}
	if len(body) > ociMaxManifest {
		return nil, afterAnswer(fmt.Errorf("the manifest for %s:%s is over %d bytes, which no registry accepts on push", t.name(), t.ref, ociMaxManifest))
	}
	contentType := resp.Header.Get("Content-Type")
	if ociIsSchema1(contentType, body) {
		return nil, afterAnswer(s.ociSchema1Refusal(t))
	}
	return &ociFetched{body: body, contentType: contentType, sentDigest: resp.Header.Get(ociDigestHeader), answered: answered}, nil
}

// ociFetchOnce is the manifest fetched to classify the request, the first
// time an opener asks, and a fresh fetch after that.
func (s *Server) ociFetchOnce(ctx context.Context, t ociTarget, rawURL string, fetched **ociFetched) (*ociFetched, error) {
	if f := *fetched; f != nil {
		*fetched = nil
		return f, nil
	}
	return s.ociFetchManifest(ctx, t, rawURL)
}

func ociDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return manifest.OCIDigestPrefix + hex.EncodeToString(sum[:])
}

// The tag list is read whole into memory, so its pages and its total are
// bounded. Docker Hub's largest repositories list a few thousand tags.
const (
	ociMaxTagPages = 1000
	ociMaxTagList  = 16 << 20
)

// ociTagListOpener reads every page of a registry's tag list, following its
// next links, and answers with one sorted list. A next link is followed only
// on the registry's own scheme and host: the registry's token rides on every
// request, and a link elsewhere would carry it there.
func (s *Server) ociTagListOpener(t ociTarget) upstreamOpener {
	return func(ctx context.Context, rawURL string) (_ *upstreamStream, err error) {
		var list ociTagList
		list.Tags = []string{}
		seen := map[string]bool{}
		budget := ociMaxTagList
		answered := ""
		defer func() {
			if answered != "" {
				err = afterAnswer(err)
			}
		}()
		for next := rawURL; next != ""; {
			if len(seen) == ociMaxTagPages {
				return nil, fmt.Errorf("the tag list for %s at %s runs past %d pages; bodega serves none of it rather than part", t.name(), rawURL, ociMaxTagPages)
			}
			seen[next] = true
			resp, err := s.ociGet(ctx, t, next, "application/json")
			if err != nil {
				return nil, err
			}
			if answered == "" {
				answered = answeredURL(resp, next)
			}
			b, err := io.ReadAll(io.LimitReader(resp.Body, int64(budget)+1))
			link := resp.Header.Get("Link")
			drainClose(resp)
			if err != nil {
				return nil, fmt.Errorf("read the tag list for %s from %s: %w", t.name(), next, err)
			}
			if budget -= len(b); budget < 0 {
				return nil, fmt.Errorf("the tag list for %s at %s is over %d bytes; bodega serves none of it rather than part", t.name(), rawURL, ociMaxTagList)
			}
			var page ociTagList
			if err := json.Unmarshal(b, &page); err != nil {
				return nil, fmt.Errorf("the tag list page %s for %s does not parse: %w", next, t.name(), err)
			}
			if list.Name == "" {
				list.Name = page.Name
			}
			list.Tags = append(list.Tags, page.Tags...)
			if next, err = ociNextPage(next, link); err != nil {
				return nil, fmt.Errorf("the tag list for %s: %w", t.name(), err)
			}
			if seen[next] {
				return nil, fmt.Errorf("the tag list for %s names %s as its next page twice, so it never ends; bodega serves none of it rather than part", t.name(), next)
			}
		}
		if list.Name == "" {
			list.Name = t.repo
		}
		sort.Strings(list.Tags)
		list.Tags = slices.Compact(list.Tags)
		doc, _ := json.Marshal(list)
		return &upstreamStream{url: answered, body: io.NopCloser(bytes.NewReader(doc)),
			contentType: "application/json", contentLength: int64(len(doc))}, nil
	}
}

// ociReferrersOpener reads a registry's referrers index and answers with it
// normalized, or with the empty index when the registry answers 404: a
// registry with no referrers API answers that for every digest, and storing
// the empty index keeps each pull from asking it again until metadata_ttl.
// A body that is not an index is an error, so nothing unparseable is cached.
func (s *Server) ociReferrersOpener(t ociTarget) upstreamOpener {
	return func(ctx context.Context, rawURL string) (*upstreamStream, error) {
		idx := emptyOCIReferrers()
		answered := rawURL
		resp, err := s.ociGet(ctx, t, rawURL, mediaOCIIndex)
		switch {
		case errors.Is(err, errUpstreamNotFound):
		case err != nil:
			return nil, err
		default:
			answered = answeredURL(resp, rawURL)
			b, err := io.ReadAll(io.LimitReader(resp.Body, ociMaxManifest+1))
			drainClose(resp)
			if err != nil {
				return nil, afterAnswer(fmt.Errorf("read the referrers of %s@%s from %s: %w", t.name(), t.ref, rawURL, err))
			}
			if len(b) > ociMaxManifest {
				return nil, afterAnswer(fmt.Errorf("the referrers of %s@%s at %s are over %d bytes; bodega serves none of them rather than part", t.name(), t.ref, rawURL, ociMaxManifest))
			}
			if err := json.Unmarshal(b, &idx); err != nil || idx.SchemaVersion != 2 {
				return nil, afterAnswer(fmt.Errorf("the referrers of %s@%s at %s are not an image index (%v)", t.name(), t.ref, rawURL, err))
			}
			idx.MediaType = mediaOCIIndex
			if idx.Manifests == nil {
				idx.Manifests = []json.RawMessage{}
			}
		}
		doc, _ := json.Marshal(idx)
		return &upstreamStream{url: answered, body: io.NopCloser(bytes.NewReader(doc)),
			contentType: mediaOCIIndex, contentLength: int64(len(doc))}, nil
	}
}

// ociNextPage is the URL a Link header's rel="next" names, resolved against
// the page that carried it, or "" when there is none.
func ociNextPage(current, link string) (string, error) {
	for part := range strings.SplitSeq(link, ",") {
		target, params, ok := strings.Cut(part, ";")
		target = strings.TrimSpace(target)
		if !ok || !strings.HasPrefix(target, "<") || !strings.HasSuffix(target, ">") {
			continue
		}
		isNext := false
		for p := range strings.SplitSeq(params, ";") {
			k, v, _ := strings.Cut(strings.TrimSpace(p), "=")
			if strings.EqualFold(k, "rel") && strings.EqualFold(strings.Trim(v, `"`), "next") {
				isNext = true
			}
		}
		if !isNext {
			continue
		}
		base, err := url.Parse(current)
		if err != nil {
			return "", err
		}
		ref, err := url.Parse(target[1 : len(target)-1])
		if err != nil {
			return "", fmt.Errorf("next page link %q does not parse: %w", target, err)
		}
		u := base.ResolveReference(ref)
		if u.Scheme != base.Scheme || !strings.EqualFold(u.Host, base.Host) {
			return "", fmt.Errorf("next page link %q leaves %s, and bodega sends the registry's token nowhere else", target, base.Host)
		}
		return u.String(), nil
	}
	return "", nil
}

// ociTagOpener resolves a tag. It reads the manifest whole, refuses schema 1,
// checks the bytes against the Docker-Content-Digest the registry sent, and
// stores them under their digest before the tag's record names it, so a
// record never points at a manifest bodega does not hold. The record, not the
// manifest, is what proxyOrResolve caches under the tag.
func (s *Server) ociTagOpener(t ociTarget, store storage.ObjectStore, platform ociPlatform, fetched *ociFetched) upstreamOpener {
	return func(ctx context.Context, rawURL string) (*upstreamStream, error) {
		f, err := s.ociFetchOnce(ctx, t, rawURL, &fetched)
		if err != nil {
			return nil, err
		}
		body, ct := f.body, f.contentType
		digest := ociDigest(body)
		if sent := f.sentDigest; sent != "" && sent != digest {
			return nil, afterAnswer(ociMismatchSent(t, sent, digest))
		}
		mediaType := ociMediaType(ct, body)
		// From here on bodega knows the image the tag names, and storing its
		// manifest and recording its children are what let a digest request
		// reach it, so the image is marked unsettled before either.
		if s.auditDB != nil {
			child := digest
			if c := ociPickChild(body, platform); c != "" {
				child = c
			}
			if !s.ociImageSettled(ctx, store, t, digest, child) {
				if err := s.ociMarkJudging(ctx, store, t, digest, child, t.ref); err != nil {
					return nil, afterAnswer(fmt.Errorf("record that bodega is checking tag %s of %s before serving any of it: %w", t.ref, t.name(), err))
				}
			}
		}
		// A chart's blobs are recorded as its own before its manifest is
		// stored, so no request finds the chart cached with its blobs still
		// judged as an image's.
		if ociArtifactType(body) == manifest.TypeHelm {
			if err := s.ociRecordChart(ctx, t, digest, body); err != nil {
				return nil, afterAnswer(err)
			}
		}
		if err := s.ociStoreManifest(ctx, t, digest, mediaType, body); err != nil {
			return nil, afterAnswer(err)
		}
		// An index's platform manifests are fetched by digest and never by
		// tag, so they are recorded as resolved by the tag that named their
		// index; otherwise a version constraint would refuse every
		// multi-arch pull at its second request.
		s.ociRecordResolved(ctx, store, t, t.ref, append(append([]string{digest}, ociIndexChildren(body)...), ociImageBlobs(body)...))
		tagDoc := ociTagDoc{Digest: digest, MediaType: mediaType, Size: int64(len(body)), FirstSeen: time.Now().UTC().Format(time.RFC3339)}
		if prev := s.ociCachedTagDoc(ctx, store, t); prev.Digest == digest && prev.FirstSeen != "" {
			tagDoc.FirstSeen = prev.FirstSeen
		}
		doc, _ := json.Marshal(tagDoc)
		return &upstreamStream{url: f.answered, body: io.NopCloser(bytes.NewReader(doc)),
			contentType: "application/json", contentLength: int64(len(doc))}, nil
	}
}

// ociStoreManifest stores a manifest verified against digest, its media type
// first, so a stored manifest always has one.
func (s *Server) ociStoreManifest(ctx context.Context, t ociTarget, digest, mediaType string, body []byte) error {
	mstore, err := s.versionStore(ctx, manifest.TypeOCI, t.name(), digest)
	if err != nil {
		return fmt.Errorf("the backend recorded for %s@%s is not configured: %w", t.name(), digest, err)
	}
	if err := mstore.Put(ctx, manifest.OCIManifestTypeKey(t.registry, t.repo, digest), []byte(mediaType)); err != nil {
		return fmt.Errorf("record the media type of manifest %s for %s:%s: %w", digest, t.name(), t.ref, err)
	}
	if err := mstore.Put(ctx, manifest.OCIManifestKey(t.registry, t.repo, digest), body); err != nil {
		return fmt.Errorf("store the manifest %s for %s:%s: %w", digest, t.name(), t.ref, err)
	}
	return nil
}

// ociCachedTagDoc is the tag's record as the cache holds it, zero when there
// is none.
func (s *Server) ociCachedTagDoc(ctx context.Context, store storage.ObjectStore, t ociTarget) ociTagDoc {
	var doc ociTagDoc
	if store == nil {
		return doc
	}
	if b, err := store.Get(ctx, manifest.OCITagKey(t.registry, t.repo, t.ref)); err == nil {
		_ = json.Unmarshal(b, &doc)
	}
	return doc
}

// ociPlatform is the platform a client pulls for.
type ociPlatform struct{ os, arch string }

// ociPlatformOf reads the platform Docker Engine names in its User-Agent
// ("... os/linux arch/arm64 ..."). No other client names one on a manifest
// request, and those get linux/amd64.
func ociPlatformOf(r *http.Request) ociPlatform {
	p := ociPlatform{os: "linux", arch: "amd64"}
	for f := range strings.FieldsSeq(r.Header.Get("User-Agent")) {
		if v, ok := strings.CutPrefix(f, "os/"); ok && v != "" {
			p.os = v
		} else if v, ok := strings.CutPrefix(f, "arch/"); ok && v != "" {
			p.arch = v
		}
	}
	return p
}

// ociConfigCreated is an image config's created time in RFC 3339, "" when it
// has none, does not parse, or is at or before the Unix epoch, which
// reproducible builds write in place of a build time.
func ociConfigCreated(cfg []byte) string {
	var c struct {
		Created string `json:"created"`
	}
	if json.Unmarshal(cfg, &c) != nil || c.Created == "" {
		return ""
	}
	at, err := time.Parse(time.RFC3339Nano, c.Created)
	if err != nil || !at.After(time.Unix(0, 0)) {
		return ""
	}
	return at.UTC().Format(time.RFC3339)
}

// ociPickChild is the child manifest of an index whose config dates the
// image, "" for a body that is not an index.
func ociPickChild(body []byte, platform ociPlatform) string {
	var idx struct {
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform *struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if json.Unmarshal(body, &idx) != nil {
		return ""
	}
	first, amd64 := "", ""
	for _, m := range idx.Manifests {
		if !manifest.OCIValidDigest(m.Digest) {
			continue
		}
		if first == "" {
			first = m.Digest
		}
		if m.Platform == nil {
			continue
		}
		if m.Platform.OS == platform.os && m.Platform.Architecture == platform.arch {
			return m.Digest
		}
		if amd64 == "" && m.Platform.OS == "linux" && m.Platform.Architecture == "amd64" {
			amd64 = m.Digest
		}
	}
	if amd64 != "" {
		return amd64
	}
	return first
}

// ociImageBlobs lists the config and layer digests an image manifest names,
// and nothing for an index.
func ociImageBlobs(body []byte) []string {
	var m struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if json.Unmarshal(body, &m) != nil {
		return nil
	}
	var out []string
	if manifest.OCIValidDigest(m.Config.Digest) {
		out = append(out, m.Config.Digest)
	}
	for _, l := range m.Layers {
		if manifest.OCIValidDigest(l.Digest) {
			out = append(out, l.Digest)
		}
	}
	return out
}

func answeredURL(resp *http.Response, rawURL string) string {
	if resp.Request != nil && resp.Request.URL != nil {
		return resp.Request.URL.String()
	}
	return rawURL
}

// ociGet sends one GET to a registry, answering its Bearer challenge once.
// A 200 is returned with its body open; anything else is the error
// openUpstream would give, so proxyOrResolve tells a 404 from an outage.
func (s *Server) ociGet(ctx context.Context, t ociTarget, rawURL, accept string) (*http.Response, error) {
	if err := upstreamGuard(rawURL); err != nil {
		return nil, err
	}
	pullScope := "repository:" + t.repo + ":pull"
	resp, err := ociDo(ctx, rawURL, accept, s.ociTokens.get(t.registry, pullScope))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		challenge := resp.Header.Get("WWW-Authenticate")
		drainClose(resp)
		params, ok := parseBearerChallenge(challenge)
		if !ok {
			return nil, fmt.Errorf("upstream %s answered 401 with no Bearer challenge bodega can follow (WWW-Authenticate %q)", rawURL, challenge)
		}
		scope := params["scope"]
		if scope == "" {
			scope = pullScope
		}
		token, err := s.ociToken(ctx, t, params["realm"], params["service"], scope)
		if err != nil {
			return nil, err
		}
		if scope != pullScope {
			s.ociTokens.put(t.registry, pullScope, token)
		}
		if resp, err = ociDo(ctx, rawURL, accept, token.value); err != nil {
			return nil, err
		}
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return resp, nil
	case http.StatusNotFound:
		drainClose(resp)
		return nil, fmt.Errorf("%w: %s returned 404", errUpstreamNotFound, rawURL)
	default:
		drainClose(resp)
		return nil, &upstreamStatusError{url: rawURL, status: resp.StatusCode}
	}
}

func ociDo(ctx context.Context, rawURL, accept, token string) (*http.Response, error) {
	//nolint:gosec // G704: rawURL passed upstreamGuard in ociGet.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", policy.UserAgent)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	//nolint:gosec // G704: see above; the redirect hops are guarded by upstreamClient.
	return upstreamClient.Do(req)
}

func drainClose(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
}

// ociTokenClient is the upstream client with redirects refused. A token
// request carries the credential, and a realm that redirects would choose
// where it goes next.
var ociTokenClient = &http.Client{
	Timeout:       30 * time.Second,
	Transport:     upstreamTransport,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// ociToken fetches a token from the realm a challenge named: as Basic auth
// when the registry's oci_upstreams URL carries userinfo, anonymously
// otherwise. The realm's host has to be the registry's own or on
// oci_token_hosts, or nothing is sent to it.
func (s *Server) ociToken(ctx context.Context, t ociTarget, realm, service, scope string) (ociTokenEntry, error) {
	ru, err := url.Parse(realm)
	if err != nil || ru.Host == "" {
		return ociTokenEntry{}, fmt.Errorf("registry %s named a token realm %q that is not an absolute URL", t.registry, realm)
	}
	up, _ := url.Parse(t.upstream)
	if !strings.EqualFold(ru.Host, up.Host) && !s.ociTokenHostListed(ru.Hostname()) {
		f := newRefusal(checkTokenHost, manifest.TypeOCI, t.name(), t.ref, http.StatusBadGateway)
		f.reason = fmt.Sprintf("registry %s sends its token requests to %s, which oci_token_hosts does not list, so bodega asked it for nothing.", t.registry, ru.Hostname())
		f.next = fmt.Sprintf("ask an operator to add %s to oci_token_hosts if %s issues its tokens there.", ru.Hostname(), t.registry)
		return ociTokenEntry{}, &resolveRefusal{f: f}
	}
	q := ru.Query()
	if service != "" {
		q.Set("service", service)
	}
	q.Set("scope", scope)
	ru.RawQuery = q.Encode()
	if err := upstreamGuard(ru.String()); err != nil {
		return ociTokenEntry{}, err
	}
	//nolint:gosec // G704: the realm passed the host list and upstreamGuard above.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ru.String(), nil)
	if err != nil {
		return ociTokenEntry{}, err
	}
	req.Header.Set("User-Agent", policy.UserAgent)
	if up.User != nil {
		pw, _ := up.User.Password()
		req.SetBasicAuth(up.User.Username(), pw)
	}
	//nolint:gosec // G704: see above.
	resp, err := ociTokenClient.Do(req)
	if err != nil {
		return ociTokenEntry{}, fmt.Errorf("token request to %s for %s: %w", ru.Hostname(), t.registry, err)
	}
	defer drainClose(resp)
	if resp.StatusCode != http.StatusOK {
		next := "check the credential in its oci_upstreams URL"
		if up.User == nil {
			next = "the registry may need a credential in its oci_upstreams URL"
		}
		return ociTokenEntry{}, fmt.Errorf("token service %s answered %d for %s scope %q; %s", ru.Hostname(), resp.StatusCode, t.registry, scope, next)
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return ociTokenEntry{}, fmt.Errorf("token service %s answered with a body that does not parse: %w", ru.Hostname(), err)
	}
	tok := ociTokenEntry{value: body.Token}
	if tok.value == "" {
		tok.value = body.AccessToken
	}
	if tok.value == "" {
		return ociTokenEntry{}, fmt.Errorf("token service %s answered with no token", ru.Hostname())
	}
	life := ociDefaultTokenLifetime
	if body.ExpiresIn > 0 {
		life = time.Duration(body.ExpiresIn) * time.Second
	}
	tok.expires = time.Now().Add(life)
	s.ociTokens.put(t.registry, scope, tok)
	return tok, nil
}

func (s *Server) ociTokenHostListed(host string) bool {
	host = config.CanonicalHost(host)
	for _, h := range s.cfg.OCITokenHosts {
		if config.CanonicalHost(h) == host {
			return true
		}
	}
	return false
}

// parseBearerChallenge reads a WWW-Authenticate Bearer challenge's
// parameters. A scope holds commas inside its quotes, so the split follows
// the quoting.
func parseBearerChallenge(h string) (map[string]string, bool) {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(h), " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return nil, false
	}
	params := map[string]string{}
	for rest = strings.TrimSpace(rest); rest != ""; {
		key, after, ok := strings.Cut(rest, "=")
		if !ok {
			break
		}
		key = strings.ToLower(strings.TrimSpace(key))
		after = strings.TrimSpace(after)
		var val string
		if strings.HasPrefix(after, `"`) {
			end := strings.Index(after[1:], `"`)
			if end < 0 {
				return nil, false
			}
			val, rest = after[1:1+end], after[2+end:]
		} else {
			val, rest, _ = strings.Cut(after, ",")
			rest = "," + rest
		}
		params[key] = val
		rest = strings.TrimLeft(strings.TrimSpace(rest), ",")
		rest = strings.TrimSpace(rest)
	}
	return params, params["realm"] != ""
}

// ociTokenCache holds issued tokens per registry and scope until each
// expires. The zero value is ready to use.
type ociTokenCache struct {
	mu     sync.Mutex
	tokens map[string]ociTokenEntry
}

type ociTokenEntry struct {
	value   string
	expires time.Time
}

func (c *ociTokenCache) get(registry, scope string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.tokens[registry+" "+scope]; ok && time.Now().Before(e.expires) {
		return e.value
	}
	return ""
}

func (c *ociTokenCache) put(registry, scope string, e ociTokenEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tokens == nil {
		c.tokens = map[string]ociTokenEntry{}
	}
	c.tokens[registry+" "+scope] = e
}

// ociDigestReader hashes a body as it is read and fails the read at EOF when
// the bytes do not hash to want. Failing the read, not checking afterwards,
// is what keeps the spool from being cached.
type ociDigestReader struct {
	r      io.ReadCloser
	h      hash.Hash
	want   string
	refuse func(got string) error
}

func (d *ociDigestReader) Read(p []byte) (int, error) {
	n, err := d.r.Read(p)
	d.h.Write(p[:n])
	if errors.Is(err, io.EOF) {
		if got := manifest.OCIDigestPrefix + hex.EncodeToString(d.h.Sum(nil)); got != d.want {
			return n, d.refuse(got)
		}
	}
	return n, err
}

func (d *ociDigestReader) Close() error { return d.r.Close() }

func ociMismatch(t ociTarget, got string) error {
	f := newRefusal(checkChecksum, manifest.TypeOCI, t.name(), t.ref, http.StatusBadGateway)
	f.reason = fmt.Sprintf("registry %s sent bytes whose digest is %s for %s, so bodega stored nothing.", t.registry, got, t.ref)
	f.next = "retry; if it repeats, something between bodega and the registry is altering the content, and an operator should look before trusting that registry."
	return &resolveRefusal{f: f}
}

func ociMismatchSent(t ociTarget, sent, got string) error {
	f := newRefusal(checkChecksum, manifest.TypeOCI, t.name(), t.ref, http.StatusBadGateway)
	f.reason = fmt.Sprintf("registry %s named the manifest for this tag %s and sent bytes whose digest is %s, so bodega stored nothing.", t.registry, sent, got)
	f.next = "retry; if it repeats, something between bodega and the registry is altering the content, and an operator should look before trusting that registry."
	return &resolveRefusal{f: f}
}

func (s *Server) ociSchema1Refusal(t ociTarget) error {
	f := newRefusal(checkSchema, manifest.TypeOCI, t.name(), t.ref, http.StatusNotFound)
	f.reason = fmt.Sprintf("registry %s serves this as a Docker schema 1 manifest, which bodega does not serve; no current client pulls one.", t.registry)
	f.next = "pull a tag the image's publisher has rebuilt since 2017, or ask them to republish this one."
	return &resolveRefusal{f: f}
}

// ociIsSchema1 reports a schema 1 manifest by its media type, or by its body
// when the registry sent a generic one.
func ociIsSchema1(contentType string, body []byte) bool {
	ct := strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0])
	if ct == mediaDockerSchema1 || ct == mediaDockerSchema1JW {
		return true
	}
	if body == nil {
		return false
	}
	var m struct {
		SchemaVersion int `json:"schemaVersion"`
	}
	return json.Unmarshal(body, &m) == nil && m.SchemaVersion == 1
}

// ociIndexChildren lists the manifest digests an image index or manifest
// list names, and nothing for an image manifest.
func ociIndexChildren(body []byte) []string {
	var idx struct {
		Manifests []struct {
			Digest string `json:"digest"`
		} `json:"manifests"`
	}
	if json.Unmarshal(body, &idx) != nil {
		return nil
	}
	var out []string
	for _, m := range idx.Manifests {
		if manifest.OCIValidDigest(m.Digest) {
			out = append(out, m.Digest)
		}
	}
	return out
}

// ociMediaType is the type a manifest is served under: the registry's own
// Content-Type when it names a manifest form, else the manifest's mediaType
// field, else what its shape says. A stored manifest has no header with it.
func ociMediaType(contentType string, body []byte) string {
	switch ct := strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]); ct {
	case mediaOCIIndex, mediaOCIManifest, mediaDockerList, mediaDockerManifest:
		return ct
	}
	var m struct {
		MediaType string          `json:"mediaType"`
		Manifests json.RawMessage `json:"manifests"`
	}
	_ = json.Unmarshal(body, &m)
	switch {
	case m.MediaType != "":
		return m.MediaType
	case m.Manifests != nil:
		return mediaOCIIndex
	}
	return mediaOCIManifest
}

// ---- responses -------------------------------------------------------------

// ociResponseWriter gives every error under /v2/ the spec's JSON body. The
// gates the other types share write their refusals as text, which docker and
// containerd would show as a bare status; the text becomes the message
// instead, so bodega's reason is what the operator at the client reads.
type ociResponseWriter struct {
	http.ResponseWriter
	r    *http.Request
	kind string
	// contentType is set on a 2xx when not empty: the stored copy of a
	// manifest carries no type of its own.
	contentType string
	wrote       bool
	status      int
	errBody     bytes.Buffer
	// outer is ociErrorMiddleware's writer, which an error this one emits
	// reaches already formatted; passthrough is that writer told so.
	outer       *ociResponseWriter
	passthrough bool
}

// ociMaxErrorBody bounds the text a refusal's body is read from.
const ociMaxErrorBody = 16 << 10

func (o *ociResponseWriter) Unwrap() http.ResponseWriter { return o.ResponseWriter }

func (o *ociResponseWriter) WriteHeader(code int) {
	if o.wrote {
		return
	}
	o.wrote, o.status = true, code
	if code >= http.StatusBadRequest && !o.passthrough {
		return
	}
	if o.contentType != "" && code < http.StatusMultipleChoices {
		o.Header().Set("Content-Type", o.contentType)
	}
	o.ResponseWriter.WriteHeader(code)
}

func (o *ociResponseWriter) Write(b []byte) (int, error) {
	if !o.wrote {
		o.WriteHeader(http.StatusOK)
	}
	if o.status >= http.StatusBadRequest && !o.passthrough {
		if room := ociMaxErrorBody - o.errBody.Len(); room > 0 {
			o.errBody.Write(b[:min(len(b), room)])
		}
		return len(b), nil
	}
	return o.ResponseWriter.Write(b)
}

// finish writes a buffered error. A refusal's text runs to two lines, its
// summary and its next step, and the message is one. A 401 goes out as 403:
// a client answers a 401 from a registry by asking it for a token, and
// bodega issues none, so the 401 would hide the reason behind a failed
// handshake.
func (o *ociResponseWriter) finish() {
	if o.status < http.StatusBadRequest || o.passthrough {
		return
	}
	msg := strings.Join(strings.Fields(o.errBody.String()), " ")
	if msg == "" {
		msg = http.StatusText(o.status)
	}
	status := o.status
	if status == http.StatusUnauthorized {
		status = http.StatusForbidden
	}
	o.emit(status, ociErrorCode(status, o.kind), msg)
}

// writeError answers with an error bodega composed itself.
func (o *ociResponseWriter) writeError(status int, code, message string) {
	o.wrote, o.status = true, 0
	o.emit(status, code, message)
}

func (o *ociResponseWriter) emit(status int, code, message string) {
	if o.outer != nil {
		o.outer.passthrough = true
	}
	h := o.Header()
	h.Del("Content-Length")
	h.Del(ociDigestHeader)
	h.Del("ETag")
	h.Del("Accept-Ranges")
	h.Set("Content-Type", ociErrorContentType)
	h.Set("X-Content-Type-Options", "nosniff")
	o.ResponseWriter.WriteHeader(status)
	if o.r.Method != http.MethodHead {
		_, _ = o.ResponseWriter.Write(jsonBody(ociErrors{Errors: []ociError{{Code: code, Message: message}}}))
	}
}

type ociErrors struct {
	Errors []ociError `json:"errors"`
}

type ociError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ociErrorCode is the spec's code for a status on a route. The spec defines
// none for a server-side failure, so those carry UNKNOWN as the reference
// registry's do.
func ociErrorCode(status int, kind string) string {
	switch status {
	case http.StatusForbidden:
		return "DENIED"
	case http.StatusNotFound:
		switch kind {
		case ociManifests, ociReferrers:
			return "MANIFEST_UNKNOWN"
		case ociBlobs:
			return "BLOB_UNKNOWN"
		}
		return "NAME_UNKNOWN"
	case http.StatusMethodNotAllowed:
		return "UNSUPPORTED"
	case http.StatusTooManyRequests:
		return "TOOMANYREQUESTS"
	case http.StatusRequestedRangeNotSatisfiable:
		return "BLOB_UNKNOWN"
	}
	return "UNKNOWN"
}

// isOCIRoute reports a path under /v2/. The route writes nothing for any
// method, so a POST there is answered by its own 405 rather than refused as a
// mutation by the admin gate.
func isOCIRoute(p string) bool { return p == "/v2/" || strings.HasPrefix(p, "/v2/") }
