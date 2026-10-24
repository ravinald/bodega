package server

import (
	"net/http"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

// handleMaven serves a Maven repository: Maven Central's layout, proxied byte
// for byte from maven_upstream, so one URL (<base>/maven/) answers Maven,
// Gradle, sbt and every other JVM resolver.
//
// The identity is <groupId>:<artifactId> at the path's version directory.
// Every file of one version (jar, pom, module, classifiers and their
// checksums and signatures) is judged and recorded under that one identity,
// which is what keeps a resolver's ten requests per dependency on one
// discovery row.
func (s *Server) handleMaven(w http.ResponseWriter, r *http.Request) {
	p := r.PathValue("path")
	mp, ok := manifest.ParseMavenPath(p)
	if !ok {
		// Answered here rather than upstream: a path outside the layout names
		// no identity the allow-list could judge, so forwarding it would let
		// any request reach the upstream unvetted.
		http.NotFound(w, r)
		return
	}
	name := mp.Name()
	ctx := r.Context()

	pm, _ := s.store.GetPackage(ctx, manifest.TypeMaven, name)
	if pm != nil {
		if isPackageHidden(pm) {
			s.refuseHidden(w, r, manifest.TypeMaven, name, "")
			return
		}
		if mp.Version != "" {
			if isVersionHidden(pm, mp.Version) {
				s.refuseHidden(w, r, manifest.TypeMaven, name, mp.Version)
				return
			}
			vc, baseVer := packageVersionConstraint(pm)
			if vc != "" && vc != manifest.ConstraintAny && baseVer != "" && !versionAllowed(baseVer, mp.Version, vc) {
				s.refuseVersionConstraint(w, r, manifest.TypeMaven, name, baseVer, mp.Version, vc)
				return
			}
		}
	}

	immutable := mp.Immutable()
	directive := cachePrivate
	if immutable {
		directive = cachePrivateImmutable
	}
	w = &cacheDirectiveWriter{ResponseWriter: w, directive: directive}

	upstream := strings.TrimRight(s.cfg.MavenUpstream, "/") + "/" + p
	s3Key := manifest.MavenKey(p)
	forceProxy := pm == nil || packageMode(pm) == manifest.ModeProxy
	store := s.typeStore(manifest.TypeMaven)
	if mp.Version != "" && !mp.Metadata {
		var err error
		if store, err = s.versionStore(ctx, manifest.TypeMaven, name, mp.Version); err != nil {
			s.logger.Error("storage backend recorded for artifact is not configured",
				"type", manifest.TypeMaven, "package", name, "version", mp.Version, "error", err)
			http.Error(w, "storage backend error", http.StatusBadGateway)
			return
		}
	}
	s.proxyOrCache(w, r, store, s3Key, upstream, manifest.TypeMaven, name, name, immutable, forceProxy)
}
