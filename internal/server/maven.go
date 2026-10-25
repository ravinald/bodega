package server

import (
	"crypto/md5"  //nolint:gosec // G501: the repository layout's own checksum, which Maven compares; it guards nothing here.
	"crypto/sha1" //nolint:gosec // G505: as above.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strconv"
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
			if vc != "" && vc != manifest.ConstraintAny && baseVer != "" {
				if ok, ordered := versionAllowed(manifest.TypeMaven, baseVer, mp.Version, vc); !ok {
					s.refuseVersionConstraint(w, r, manifest.TypeMaven, name, baseVer, mp.Version, vc, ordered)
					return
				}
			}
		}
	}

	forceProxy := pm == nil || packageMode(pm) == manifest.ModeProxy
	// The index filter rewrites only metadata answered from upstream, and the
	// artifact route refuses only what such metadata would have withheld, as
	// the gomod route does.
	proxied := (pm == nil && s.cacheEnabled()) || (pm != nil && packageMode(pm) == manifest.ModeProxy)
	if mp.Metadata && mp.Version == "" {
		// Artifact-level metadata names no version, so membership decides it
		// here and the version rule decides each version listed in it. 404
		// rather than 403: Maven and Gradle read a 404 on metadata as an
		// artifact with no versions and say so, and read a 403 as a broken
		// repository.
		if !s.entitleGateAnswering(w, r, manifest.TypeMaven, name, "", http.StatusNotFound) {
			return
		}
		permit := profileVersionFilter(s.profileFor(r), manifest.TypeMaven, name)
		var withhold *indexWithhold
		if proxied {
			withhold = s.indexWithholdFor(r, manifest.TypeMaven, name)
		}
		if permit != nil || withhold != nil {
			s.serveFilteredMavenMetadata(w, r, mp, p, permit, withhold, forceProxy)
			return
		}
	} else {
		if !s.entitleGate(w, r, manifest.TypeMaven, name, mp.Version) {
			return
		}
		if proxied && s.refuseWithheld(w, r, manifest.TypeMaven, name, mp.Version) {
			return
		}
	}

	immutable := mp.Immutable()
	directive := cachePrivate
	if immutable {
		directive = cachePrivateImmutable
	}
	w = &cacheDirectiveWriter{ResponseWriter: w, directive: directive}

	upstream := s.mavenUpstreamURL(p)
	s3Key := manifest.MavenKey(p)
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

func (s *Server) mavenUpstreamURL(p string) string {
	return strings.TrimRight(s.cfg.MavenUpstream, "/") + "/" + p
}

// serveFilteredMavenMetadata answers an artifact-level maven-metadata.xml, or
// one of its companions, filtered for a profile that rules on the artifact's
// versions, by the index filter, or both; either may be nil. The cache keeps
// the upstream's document and every host class filters its own copy on the
// way out, so one profile's reading is never stored where another's request
// can be answered from it.
//
// The checksum companions are computed from the filtered bytes. The upstream's
// describe a document this host is not handed, and Maven and Gradle both
// refuse metadata whose checksum disagrees. The .asc signature cannot be
// recomputed, so it is answered 404: Maven does not ask for one on metadata,
// and a signature over other bytes would be a false claim.
func (s *Server) serveFilteredMavenMetadata(w http.ResponseWriter, r *http.Request, mp manifest.MavenPath, p string, permit func(string) bool, withhold *indexWithhold, forceProxy bool) {
	noSharedCache(w)
	name := mp.Name()
	metaPath := strings.TrimSuffix(p, "."+mp.Companion)
	store := s.typeStore(manifest.TypeMaven)
	filter := func(b []byte) []byte {
		b = filterMavenMetadata(b, permit)
		if withhold != nil {
			b = withhold.mavenMetadata(b)
		}
		return b
	}

	if mp.Companion == "" {
		rw := &indexFilterWriter{
			ResponseWriter: w,
			subject:        "the maven-metadata.xml for " + name,
			filter: func(b []byte) []byte {
				b = filter(b)
				if withhold != nil {
					withhold.finish(w.Header())
				}
				return b
			},
		}
		s.proxyOrCache(rw, r, store, manifest.MavenKey(p), s.mavenUpstreamURL(p), manifest.TypeMaven, name, name, false, forceProxy)
		if err := rw.flush(); err != nil {
			s.logger.Error("maven metadata response failed", "artifact", name, "error", err)
		}
		return
	}

	newHash, ok := mavenChecksums[mp.Companion]
	if !ok {
		http.Error(w, fmt.Sprintf("%s: this host is served a filtered list of the versions of %s, so the upstream's %s signature covers a different document and is not served",
			p, name, mp.Companion), http.StatusNotFound)
		return
	}
	body, status, err := s.mavenMetadataRead(r, metaPath, name, forceProxy)
	if err != nil {
		s.logger.Warn("maven metadata checksum: the metadata it describes could not be read",
			"artifact", name, "companion", mp.Companion, "error", err)
		if status < 400 || status >= 500 {
			status = http.StatusBadGateway
		}
		http.Error(w, fmt.Sprintf("%s: %v", p, err), status)
		return
	}
	h := newHash()
	h.Write(filter(body))
	sum := hex.EncodeToString(h.Sum(nil))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(sum)))
	_, _ = io.WriteString(w, sum)
}

// mavenChecksums are the companions a filtered metadata file's checksum can be
// recomputed for.
var mavenChecksums = map[string]func() hash.Hash{
	"md5":    md5.New,  //nolint:gosec // G401: the repository layout's own checksum, which Maven compares; it guards nothing here.
	"sha1":   sha1.New, //nolint:gosec // G401: as above.
	"sha256": sha256.New,
	"sha512": sha512.New,
}

// mavenMetadataRead reads a maven-metadata.xml as the metadata route would
// serve it to this request, through the same cache, so the checksum computed
// from it describes the document the client was handed. The read is bodega's
// own (withOwnRead): the client's metadata request already wrote its rows.
func (s *Server) mavenMetadataRead(r *http.Request, metaPath, name string, forceProxy bool) ([]byte, int, error) {
	req := r.Clone(withOwnRead(r.Context()))
	req.URL.Path = "/maven/" + metaPath
	req.URL.RawQuery = ""
	for _, h := range []string{"Range", "If-Range", "If-None-Match", "If-Modified-Since"} {
		req.Header.Del(h)
	}
	cw := &capturedResponse{header: http.Header{}}
	s.proxyOrCache(cw, req, s.typeStore(manifest.TypeMaven), manifest.MavenKey(metaPath), s.mavenUpstreamURL(metaPath),
		manifest.TypeMaven, name, name, false, forceProxy)
	switch {
	case cw.tooBig:
		return nil, http.StatusBadGateway, fmt.Errorf("%s exceeds bodega's %d-byte buffer", metaPath, maxUpstreamBody)
	case cw.status != 0 && cw.status != http.StatusOK:
		return nil, cw.status, fmt.Errorf("%s answered HTTP %d, so there is no document to checksum", metaPath, cw.status)
	}
	return cw.body.Bytes(), http.StatusOK, nil
}
