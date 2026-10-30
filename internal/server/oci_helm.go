package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// ---- Helm charts under /v2/ -------------------------------------------------

// A chart pushed to an OCI registry is served by the same /v2/ routes as an
// image and differs only in its manifest's config media type. It is judged as
// helm, under its <registry>/<repository> identity, so one helm profile, hide
// or pin covers a chart whichever way a client pulls it. Its storage stays
// under the oci keys: the bytes are the registry's, and only the judgment
// changes.
//
// Three rules keep a verdict attached to the bytes it judged:
//   - a manifest is typed by the bytes served, so a tag that moved between an
//     image and a chart since bodega cached it is judged again as what it
//     now names, and a manifest fetched by digest that turns out to be the
//     other type is refused rather than served under the wrong verdict;
//   - a chart's config and layers are judged under the chart that names
//     them, from records in the shared store (manifest.OCIChartBlobKey), so a
//     blob of a refused chart is refused after a restart and on every host;
//   - a blob no chart names is judged as oci, as F70 judges every blob, so a
//     helm entry never reaches an image's layers.

// ociFetched is one manifest read whole from a registry. A manifest fetched to
// learn its type is handed to the opener that would otherwise fetch it again,
// so classifying an admitted chart costs no second request.
type ociFetched struct {
	body        []byte
	contentType string
	sentDigest  string // the registry's Docker-Content-Digest, "" when it sent none
	answered    string
}

// ociManifestDoc is the part of a manifest the helm judgment reads.
type ociManifestDoc struct {
	Config struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
	} `json:"config"`
	Layers []struct {
		Digest string `json:"digest"`
	} `json:"layers"`
}

// ociArtifactType is the type a manifest is judged under: helm when its
// config names the chart config media type, oci for anything else, an image
// index included.
func ociArtifactType(body []byte) string {
	var m ociManifestDoc
	if json.Unmarshal(body, &m) == nil && m.Config.MediaType == manifest.HelmOCIConfigMediaType {
		return manifest.TypeHelm
	}
	return manifest.TypeOCI
}

// ociChartBlobs is the config and layer digests a chart manifest names.
func ociChartBlobs(body []byte) []string {
	var m ociManifestDoc
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

// ociManifestType is the type a manifest request is judged under, and the
// manifest when it had to be fetched to say. A manifest bodega holds answers
// from the store. One it does not is fetched when ociWorthClassifying says
// so, and otherwise judged as oci without a request leaving bodega.
//
// A fetch that fails is judged as oci. The serve path that follows meets the
// same failure and answers it as F70 does, and a later fetch that succeeds
// with a chart is checked against that judgment where it is served. err is
// a chart whose blobs could not be recorded as its own, which the caller
// refuses: those blobs would otherwise be judged as an image's.
//
// The returned request carries the observation when the classifying fetch saw
// the path answer 2xx, whatever bodega then made of the body, and the path's
// not-found record is already gone: every exit after this, the gates and the
// proxy alike, reads that observation instead of an earlier 404.
func (s *Server) ociManifestType(r *http.Request, t ociTarget) (*http.Request, string, *ociFetched, error) {
	ctx := r.Context()
	if digest, body, ok := s.ociCachedManifest(ctx, t); ok {
		typ := ociArtifactType(body)
		if typ == manifest.TypeHelm {
			if err := s.ociRecordChart(ctx, t, digest, body); err != nil {
				return r, typ, nil, err
			}
		}
		return r, typ, nil, nil
	}
	tags, resolved := s.ociVersionsFor(ctx, t)
	key := ociManifestRequestKey(t)
	if !s.ociWorthClassifying(r, t, tags, resolved, key) {
		return r, manifest.TypeOCI, nil, nil
	}
	f, err := s.ociFetchManifest(ctx, t, t.url(ociManifests+"/"+t.ref))
	if err == nil || upstreamAnsweredIn(err) {
		s.ociClearNotFound(ctx, t, key)
		r = r.WithContext(withPathAnswered(ctx))
		ctx = r.Context()
	}
	if err != nil {
		s.logger.Debug("oci manifest not classified; judging it as oci", "name", t.name(), "ref", t.ref, "error", err)
		return r, manifest.TypeOCI, nil, nil
	}
	typ := ociArtifactType(f.body)
	if digest := ociDigest(f.body); typ == manifest.TypeHelm && ociFetchMatches(t, f, digest) {
		if err := s.ociRecordChart(ctx, t, digest, f.body); err != nil {
			return r, typ, nil, err
		}
	}
	return r, typ, f, nil
}

// ociClearNotFound removes the not-found record a manifest request's proxy
// keeps, in the store that proxy reads: the type's for a tag, the version's
// for a digest.
func (s *Server) ociClearNotFound(ctx context.Context, t ociTarget, key string) {
	store := s.typeStore(manifest.TypeOCI)
	if t.isDigest() {
		var err error
		if store, err = s.versionStore(ctx, manifest.TypeOCI, t.name(), t.ref); err != nil {
			s.logger.Warn("could not resolve the store holding an earlier upstream 404", "key", key, "error", err)
			return
		}
	}
	if store != nil {
		s.clearNotFound(ctx, store, key)
	}
}

// refuseChartUnrecorded answers a chart whose blobs bodega could not record
// as the chart's, which it refuses rather than let them be judged as an
// image's.
func (s *Server) refuseChartUnrecorded(w *ociResponseWriter, t ociTarget, err error) {
	s.logger.Error("oci chart blobs not recorded; refusing the chart", "name", t.name(), "ref", t.ref, "error", err)
	w.writeError(http.StatusServiceUnavailable, "UNAVAILABLE",
		fmt.Sprintf("bodega could not record which blobs chart %s@%s names, so it cannot hold them to the chart's verdict: %v. Retry; if it persists, the storage backend is refusing writes.", t.name(), t.ref, err))
}

// ociFetchMatches reports whether a fetched manifest is the one the request
// names: its digest for a digest request, the digest the registry sent for a
// tag. Only a manifest that matches is recorded as naming its blobs; one that
// does not is refused where it would be served.
func ociFetchMatches(t ociTarget, f *ociFetched, digest string) bool {
	if t.isDigest() {
		return digest == t.ref
	}
	return f.sentDigest == "" || f.sentDigest == digest
}

func ociManifestRequestKey(t ociTarget) string {
	if t.isDigest() {
		return manifest.OCIManifestKey(t.registry, t.repo, t.ref)
	}
	return manifest.OCITagKey(t.registry, t.repo, t.ref)
}

// ociCachedManifest is the manifest bodega holds for the request, and its
// digest: the one a cached tag record names, or the one under the digest.
func (s *Server) ociCachedManifest(ctx context.Context, t ociTarget) (string, []byte, bool) {
	store := s.typeStore(manifest.TypeOCI)
	if store == nil {
		return "", nil, false
	}
	digest := t.ref
	if !t.isDigest() {
		b, err := store.Get(ctx, manifest.OCITagKey(t.registry, t.repo, t.ref))
		var doc ociTagDoc
		if err != nil || b == nil || json.Unmarshal(b, &doc) != nil || !manifest.OCIValidDigest(doc.Digest) {
			return "", nil, false
		}
		digest = doc.Digest
	}
	body := s.ociStoredManifest(ctx, t, digest)
	return digest, body, body != nil
}

// ociStoredManifest is the manifest stored under digest, nil when bodega
// holds none.
func (s *Server) ociStoredManifest(ctx context.Context, t ociTarget, digest string) []byte {
	mstore, err := s.versionStore(ctx, manifest.TypeOCI, t.name(), digest)
	if err != nil || mstore == nil {
		return nil
	}
	body, err := mstore.Get(ctx, manifest.OCIManifestKey(t.registry, t.repo, digest))
	if err != nil {
		return nil
	}
	return body
}

// ociVersionsFor is the versions a manifest request is judged under: the tag
// it names, or every tag bodega resolved to the digest it names, the last
// one first. resolved is false for a digest no tag ever named, which a
// version constraint cannot judge.
func (s *Server) ociVersionsFor(ctx context.Context, t ociTarget) (tags []string, resolved bool) {
	if !t.isDigest() {
		return []string{t.ref}, true
	}
	store := s.typeStore(manifest.TypeOCI)
	last := s.ociResolvedTag(ctx, store, t, t.ref)
	return s.ociResolvedByTags(ctx, store, t, last), last != ""
}

// ociGatesAdmit answers, writing nothing, whether ociGate would admit the
// request under typ. tags are the versions it may be judged under; the
// version constraint reads the first, the profile admits any of them.
func (s *Server) ociGatesAdmit(r *http.Request, typ string, t ociTarget, tags []string, resolved bool, key string, immutable bool) bool {
	return s.ociEntryAdmits(r, typ, t, tags, resolved) && s.ociAccessAdmits(r, typ, t, tags, key, immutable)
}

// ociEntryAdmits is the half of ociGatesAdmit that reads the type's own
// package entry: its hide and its version constraint.
func (s *Server) ociEntryAdmits(r *http.Request, typ string, t ociTarget, tags []string, resolved bool) bool {
	version := t.ref
	if len(tags) > 0 {
		version = tags[0]
	}
	pm, _ := s.store.GetPackage(r.Context(), typ, t.name())
	if pm == nil {
		return true
	}
	switch {
	case isPackageHidden(pm):
		return false
	case !resolved && ociConstrained(pm):
		return false
	case resolved && (isVersionHidden(pm, version) || !ociVersionPermits(pm, typ, version)):
		return false
	}
	return true
}

// ociAccessAdmits is the other half: the profile and the allow-list, which
// say whether this host may reach the repository at all.
func (s *Server) ociAccessAdmits(r *http.Request, typ string, t ociTarget, tags []string, key string, immutable bool) bool {
	ctx := r.Context()
	name := t.name()
	if p := s.profileFor(r); p != nil {
		if len(tags) == 0 && !t.isDigest() {
			tags = []string{t.ref}
		}
		if d, _ := p.PermitsOneOf(typ, name, tags); !d.Permitted {
			return false
		}
	}
	if s.policy == nil {
		return true
	}
	_, violation, err := s.upstreamPolicyVerdict(ctx, typ, name)
	if err != nil || !violation {
		return err == nil
	}
	if o := s.allowListOverrideLookup(ctx, typ, name, key, immutable); o != nil {
		if _, ok := o(); ok {
			return true
		}
	}
	if b := s.baselineLookup(ctx, typ, name, key, immutable); b != nil {
		if _, ok := b(); ok {
			return true
		}
	}
	return false
}

// ociWorthClassifying reports whether a manifest bodega does not hold is
// fetched to learn its type. It is when oci admits it, when helm's own
// configuration names the repository, or when the only thing refusing it is
// oci's package entry (a hide or a constraint on images) and helm admits it:
// an entry about images says nothing about a chart. A profile or allow-list
// that keeps this host from the repository under oci keeps the request off
// the registry unless helm names it, so refused content stays off the
// registry's logs.
func (s *Server) ociWorthClassifying(r *http.Request, t ociTarget, tags []string, resolved bool, key string) bool {
	immutable := t.isDigest()
	ociAccess := s.ociAccessAdmits(r, manifest.TypeOCI, t, tags, key, immutable)
	switch {
	case ociAccess && s.ociEntryAdmits(r, manifest.TypeOCI, t, tags, resolved):
		return true
	case s.ociHelmNames(r.Context(), r, t.name()):
		return true
	case ociAccess:
		return s.ociGatesAdmit(r, manifest.TypeHelm, t, tags, resolved, key, immutable)
	}
	return false
}

// ociGate runs the gates F70 runs on a manifest under typ, in its order:
// hiding, the version constraint, the profile, then the allow-list. A digest
// no tag resolved is refused under a version constraint, which has nothing
// to compare it with. It answers every refusal itself.
func (s *Server) ociGate(w http.ResponseWriter, r *http.Request, typ string, t ociTarget, tags []string, resolved bool, key string, immutable bool) (*manifest.PackageManifest, bool) {
	g, ok := s.ociGateFull(w, r, typ, t, tags, resolved, key, immutable)
	return g.pm, ok
}

// ociGated is what ociGateFull read on the way through, which a tag's
// per-version checks record their admission row against.
type ociGated struct {
	pm       *manifest.PackageManifest
	decision string
	baseline baselineLookup
	override overrideLookup
}

// ociGateFull is ociGate. tags are the versions the request may be judged
// under, the last one bodega resolved first: the version constraint reads
// that one, and the profile admits any of them, so a second tag resolving to
// a digest never displaces the one a profile permits.
func (s *Server) ociGateFull(w http.ResponseWriter, r *http.Request, typ string, t ociTarget, tags []string, resolved bool, key string, immutable bool) (ociGated, bool) {
	ctx := r.Context()
	name := t.name()
	version := t.ref
	if len(tags) > 0 {
		version = tags[0]
	}
	var g ociGated
	g.pm, _ = s.store.GetPackage(ctx, typ, name)
	if pm := g.pm; pm != nil {
		if isPackageHidden(pm) {
			s.refuseHidden(w, r, typ, name, "")
			return g, false
		}
		if resolved {
			if !s.ociJudgeVersion(w, r, typ, pm, name, version) {
				return g, false
			}
		} else if ociConstrained(pm) {
			vc, baseVer := packageVersionConstraint(pm)
			s.refuseUnresolvedDigest(w, r, typ, name, t.ref, baseVer, vc)
			return g, false
		}
	}
	// A digest is never compared with a pin itself: only the tags resolved
	// to it are.
	if p := s.profileFor(r); p != nil && t.isDigest() {
		d, tag := p.PermitsOneOf(typ, name, tags)
		if tag == "" {
			tag = t.ref
		}
		if !s.entitleGateDecided(w, r, p, typ, name, tag, d, http.StatusForbidden) {
			return g, false
		}
	} else if !s.entitleGate(w, r, typ, name, version) {
		return g, false
	}
	g.baseline = s.baselineLookup(ctx, typ, name, key, immutable)
	g.override = s.allowListOverrideLookup(ctx, typ, name, key, immutable)
	var ok bool
	g.decision, ok = s.ociAllowListVerdict(w, r, typ, t, key, immutable, g.baseline, g.override)
	return g, ok
}

// ociHelmNames reports whether helm's configuration names the identity
// itself: a helm package entry, a closed helm profile rule listing it, or a
// listed helm allow-list with a rule admitting it. An open helm type admits
// everything and so names nothing. It decides only whether a manifest oci
// would refuse is worth fetching to learn its type, never what a blob is.
func (s *Server) ociHelmNames(ctx context.Context, r *http.Request, name string) bool {
	if pm, _ := s.store.GetPackage(ctx, manifest.TypeHelm, name); pm != nil {
		return true
	}
	if p := s.profileFor(r); p != nil {
		d := p.Covers(manifest.TypeHelm, name)
		if d.Rule != nil && d.Rule.Membership == audit.MembershipClosed && !d.Outside {
			return true
		}
	}
	if s.policy == nil {
		return false
	}
	listed, err := s.policy.Listed(ctx, manifest.TypeHelm)
	return err == nil && listed && s.policy.Check(ctx, manifest.TypeHelm, name) == nil
}

// ociRecordChart records each blob a chart manifest names, under the tag the
// request reached it by. A request by digest records the tag bodega resolved
// to it, and an unresolved digest records none, never erasing a tag an
// earlier request wrote. Every write is attempted and any failure is
// returned: an unrecorded blob is judged as an image's, so the caller refuses
// the chart rather than let its blobs pass under the wrong type.
func (s *Server) ociRecordChart(ctx context.Context, t ociTarget, digest string, body []byte) error {
	store := s.typeStore(manifest.TypeOCI)
	if store == nil {
		return nil
	}
	tag := ""
	if !t.isDigest() {
		tag = t.ref
	} else {
		tag = s.ociResolvedTag(ctx, store, t, digest)
	}
	var errs []error
	for _, blob := range ociChartBlobs(body) {
		key := manifest.OCIChartBlobKey(t.registry, t.repo, blob, digest)
		old, err := store.Get(ctx, key)
		if err != nil {
			errs = append(errs, fmt.Errorf("read the chart record of blob %s: %w", blob, err))
			continue
		}
		if old != nil && (tag == "" || string(old) == tag) {
			continue
		}
		if err := store.Put(ctx, key, []byte(tag)); err != nil {
			errs = append(errs, fmt.Errorf("record blob %s as chart %s's: %w", blob, digest, err))
		}
	}
	return errors.Join(errs...)
}

// ociChartOwner is one chart manifest that names a blob.
type ociChartOwner struct {
	digest string
	tag    string
}

// ociChartOwners lists the chart manifests of the repository that name the
// blob t requests, sorted by digest so a refusal names the same chart on
// every request.
func (s *Server) ociChartOwners(ctx context.Context, t ociTarget) ([]ociChartOwner, error) {
	store := s.typeStore(manifest.TypeOCI)
	if store == nil {
		return nil, nil
	}
	prefix := manifest.OCIChartBlobPrefix(t.registry, t.repo, t.ref)
	keys, err := store.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	var out []ociChartOwner
	for _, k := range keys {
		digest := manifest.OCIDigestPrefix + strings.TrimPrefix(k, prefix)
		if !manifest.OCIValidDigest(digest) {
			continue
		}
		tag, err := store.Get(ctx, k)
		if err != nil {
			return nil, err
		}
		if tag == nil {
			continue
		}
		out = append(out, ociChartOwner{digest: digest, tag: string(tag)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].digest < out[j].digest })
	return out, nil
}

// ociBlobGate judges a blob request. A blob a chart of the repository names
// is helm, admitted when one of those charts is: its version is the tag the
// chart was reached by, or the tag bodega last resolved to its digest.
// Otherwise every chart refuses it, and the first one's refusal answers.
// A blob no chart names is judged as F70 judges it.
func (s *Server) ociBlobGate(w http.ResponseWriter, r *http.Request, t ociTarget, key string) (string, *manifest.PackageManifest, bool) {
	ctx := r.Context()
	name := t.name()
	owners, err := s.ociChartOwners(ctx, t)
	if err != nil {
		s.logger.Error("oci chart records unreadable", "name", name, "blob", t.ref, "error", err)
		f := newRefusal(checkSchema, manifest.TypeOCI, name, t.ref, http.StatusServiceUnavailable)
		f.reason = fmt.Sprintf("bodega could not read which charts in %s name blob %s, so it cannot say which verdict the blob follows.", name, t.ref)
		f.next = "retry; if it repeats, an operator should check that bodega's object store is reachable."
		f.write(w, r)
		return "", nil, false
	}
	if len(owners) == 0 {
		pm, _ := s.store.GetPackage(ctx, manifest.TypeOCI, name)
		if pm != nil && isPackageHidden(pm) {
			s.refuseHidden(w, r, manifest.TypeOCI, name, "")
			return "", pm, false
		}
		if !s.entitleGate(w, r, manifest.TypeOCI, name, "") {
			return "", pm, false
		}
		return manifest.TypeOCI, pm, s.ociAllowListGate(w, r, manifest.TypeOCI, t, key, true)
	}
	chosen := owners[0]
	for _, o := range owners {
		if tags, resolved := s.ociOwnerVersions(ctx, t, o); s.ociGatesAdmit(r, manifest.TypeHelm, ociByChart(t, o), tags, resolved, key, true) {
			chosen = o
			break
		}
	}
	tags, resolved := s.ociOwnerVersions(ctx, t, chosen)
	pm, ok := s.ociGate(w, r, manifest.TypeHelm, ociByChart(t, chosen), tags, resolved, key, true)
	return manifest.TypeHelm, pm, ok
}

// ociByChart is the request t judged as one by the digest of chart o.
func ociByChart(t ociTarget, o ociChartOwner) ociTarget {
	byChart := t
	byChart.ref = o.digest
	return byChart
}

// ociOwnerVersions is every tag a chart was reached by: the one its blob
// record names and every tag bodega resolved to its digest.
func (s *Server) ociOwnerVersions(ctx context.Context, t ociTarget, o ociChartOwner) ([]string, bool) {
	store := s.typeStore(manifest.TypeOCI)
	byChart := ociByChart(t, o)
	last := s.ociResolvedTag(ctx, store, byChart, o.digest)
	tags := s.ociResolvedByTags(ctx, store, byChart, last)
	if o.tag != "" && !slices.Contains(tags, o.tag) {
		tags = append(tags, o.tag)
	}
	return tags, len(tags) > 0
}

// ociListAdmits answers, writing nothing, whether a tag list's gates (the
// package hide, the profile's membership and the allow-list) admit the
// repository under typ. A list names no version, so no constraint applies.
func (s *Server) ociListAdmits(r *http.Request, typ string, t ociTarget, key string) bool {
	ctx := r.Context()
	name := t.name()
	if pm, _ := s.store.GetPackage(ctx, typ, name); pm != nil && isPackageHidden(pm) {
		return false
	}
	if p := s.profileFor(r); p != nil && !p.Covers(typ, name).Permitted {
		return false
	}
	if s.policy == nil {
		return true
	}
	_, violation, err := s.upstreamPolicyVerdict(ctx, typ, name)
	return err == nil && !violation
}

// ociRepoHoldsCharts reports whether bodega recorded a chart in the
// repository, which is what judges its tag list as helm.
func (s *Server) ociRepoHoldsCharts(ctx context.Context, t ociTarget) bool {
	store := s.typeStore(manifest.TypeOCI)
	if store == nil {
		return false
	}
	keys, err := store.List(ctx, manifest.OCIChartsPrefix(t.registry, t.repo))
	return err == nil && len(keys) > 0
}

// ociTypeChanged refuses a manifest whose bytes are not the type its request
// was judged under: the registry answered a classification fetch with one
// and the serving fetch with the other, or the classification fetch failed.
func ociTypeChanged(t ociTarget, judged, got string) error {
	f := newRefusal(checkSchema, judged, t.name(), t.ref, http.StatusBadGateway)
	f.reason = fmt.Sprintf("bodega judged %s@%s as %s and registry %s then served it as %s, so bodega served nothing under a verdict it did not reach.", t.name(), t.ref, judged, t.registry, got)
	f.next = "retry; the next request judges the manifest as what the registry now serves."
	return &resolveRefusal{f: f}
}
