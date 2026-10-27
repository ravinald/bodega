package server

import (
	"context"
	"encoding/json"
	"net/http"

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

// ociFetched is one manifest read whole from a registry. A manifest fetched to
// learn its type is handed to the opener that would otherwise fetch it again,
// so classifying an admitted chart costs no second request.
type ociFetched struct {
	body        []byte
	contentType string
	sentDigest  string // the registry's Docker-Content-Digest, "" when it sent none
	answered    string
}

// ociArtifactType is the type a manifest is judged under: helm when its
// config names the chart config media type, oci for anything else, an image
// index included.
func ociArtifactType(body []byte) string {
	var m struct {
		Config struct {
			MediaType string `json:"mediaType"`
		} `json:"config"`
	}
	if json.Unmarshal(body, &m) == nil && m.Config.MediaType == manifest.HelmOCIConfigMediaType {
		return manifest.TypeHelm
	}
	return manifest.TypeOCI
}

// ociManifestType is the type a manifest request is judged under, and the
// manifest when it had to be fetched to say. A manifest bodega holds answers
// from the store. One it does not is fetched only when the request could be
// served under either type: oci's own gates admit it, or helm's name it. A
// repository oci refuses and helm never mentions is judged as oci without a
// request leaving bodega, which is what keeps refused content off the
// registry's logs.
//
// A fetch that fails is judged as oci, and the serve path that follows meets
// the same failure and answers it as F70 does: a stale copy, a 404, a 502.
func (s *Server) ociManifestType(r *http.Request, t ociTarget) (string, *ociFetched) {
	ctx := r.Context()
	if typ, ok := s.ociCachedType(ctx, t); ok {
		s.noteOCIRepoType(t, typ)
		return typ, nil
	}
	if !s.ociOCIGatesAdmit(r, t) && !s.ociHelmNames(ctx, r, t.name()) {
		return manifest.TypeOCI, nil
	}
	f, err := s.ociFetchManifest(ctx, t, t.url(ociManifests+"/"+t.ref))
	if err != nil {
		s.logger.Debug("oci manifest not classified; judging it as oci", "name", t.name(), "ref", t.ref, "error", err)
		return manifest.TypeOCI, nil
	}
	typ := ociArtifactType(f.body)
	s.noteOCIRepoType(t, typ)
	return typ, f
}

// ociCachedType reads the type from the manifest bodega holds for the
// request: the one a cached tag record names, or the one under the digest.
func (s *Server) ociCachedType(ctx context.Context, t ociTarget) (string, bool) {
	store := s.typeStore(manifest.TypeOCI)
	if store == nil {
		return "", false
	}
	digest := t.ref
	if !t.isDigest() {
		b, err := store.Get(ctx, manifest.OCITagKey(t.registry, t.repo, t.ref))
		var doc ociTagDoc
		if err != nil || b == nil || json.Unmarshal(b, &doc) != nil || !manifest.OCIValidDigest(doc.Digest) {
			return "", false
		}
		digest = doc.Digest
	}
	mstore, err := s.versionStore(ctx, manifest.TypeOCI, t.name(), digest)
	if err != nil || mstore == nil {
		return "", false
	}
	body, err := mstore.Get(ctx, manifest.OCIManifestKey(t.registry, t.repo, digest))
	if err != nil || body == nil {
		return "", false
	}
	return ociArtifactType(body), true
}

// ociOCIGatesAdmit answers, writing nothing, whether the gates F70 runs on a
// manifest request would admit it as oci: hiding, the version constraint, the
// profile and the allow-list.
func (s *Server) ociOCIGatesAdmit(r *http.Request, t ociTarget) bool {
	ctx := r.Context()
	name := t.name()
	version := t.ref
	if pm, _ := s.store.GetPackage(ctx, manifest.TypeOCI, name); pm != nil {
		if isPackageHidden(pm) {
			return false
		}
		tag := t.ref
		if t.isDigest() {
			tag = s.ociResolvedTag(ctx, t)
		}
		switch {
		case tag == "" && ociConstrained(pm):
			return false
		case tag != "":
			if isVersionHidden(pm, tag) || !ociVersionPermits(pm, manifest.TypeOCI, tag) {
				return false
			}
			version = tag
		}
	}
	if p := s.profileFor(r); p != nil && !p.Permits(manifest.TypeOCI, name, version).Permitted {
		return false
	}
	if s.policy == nil {
		return true
	}
	_, violation, err := s.upstreamPolicyVerdict(ctx, manifest.TypeOCI, name)
	if err != nil || !violation {
		return err == nil
	}
	key := manifest.OCIManifestKey(t.registry, t.repo, t.ref)
	if !t.isDigest() {
		key = manifest.OCITagKey(t.registry, t.repo, t.ref)
	}
	if o := s.allowListOverrideLookup(ctx, manifest.TypeOCI, name, key, t.isDigest()); o != nil {
		if _, ok := o(); ok {
			return true
		}
	}
	if b := s.baselineLookup(ctx, manifest.TypeOCI, name, key, t.isDigest()); b != nil {
		if _, ok := b(); ok {
			return true
		}
	}
	return false
}

// ociHelmNames reports whether helm's configuration names the identity
// itself: a helm package entry, a closed helm profile rule listing it, or a
// listed helm allow-list with a rule admitting it. An open helm type admits
// everything and so names nothing.
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

// ociRepoType is the type a blob or tag list request is judged under. Neither
// names a manifest, so each follows the repository's charts: helm once a
// manifest of the repository was judged as a chart, or when a helm entry
// names it, and oci otherwise.
func (s *Server) ociRepoType(ctx context.Context, t ociTarget) string {
	if _, chart := s.ociCharts.Load(t.name()); chart {
		return manifest.TypeHelm
	}
	if pm, _ := s.store.GetPackage(ctx, manifest.TypeHelm, t.name()); pm != nil {
		return manifest.TypeHelm
	}
	return manifest.TypeOCI
}

func (s *Server) noteOCIRepoType(t ociTarget, typ string) {
	if typ == manifest.TypeHelm {
		s.ociCharts.Store(t.name(), struct{}{})
	} else {
		s.ociCharts.Delete(t.name())
	}
}

// ociResolvedTag is the tag bodega last resolved to the digest t names, ""
// when it never resolved one.
func (s *Server) ociResolvedTag(ctx context.Context, t ociTarget) string {
	store := s.typeStore(manifest.TypeOCI)
	if store == nil {
		return ""
	}
	if b, err := store.Get(ctx, manifest.OCIResolvedKey(t.registry, t.repo, t.ref)); err == nil {
		return string(b)
	}
	return ""
}
