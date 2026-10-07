package server

import (
	"encoding/json"
	"strings"
	"time"

	"net/http"

	"github.com/ravinald/bodega/internal/manifest"
)

// ---- Go module proxy -------------------------------------------------------

func (s *Server) handleGomod(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	fullPath := r.PathValue("path")
	idx := strings.Index(fullPath, "/@v/")
	if idx < 0 {
		http.NotFound(w, r)
		return
	}
	module := fullPath[:idx]
	file := fullPath[idx+4:] // "list", "v1.30.0.info", etc.

	s3Key := manifest.GomodFileKey(module, file)
	upstream := s.cfg.GomodUpstream + "/" + module + "/@v/" + file
	immutable := file != "list" && !strings.HasSuffix(file, "latest")

	pm, _ := s.store.GetPackage(ctx, manifest.TypeGomod, module)
	if pm != nil && isPackageHidden(pm) {
		s.refuseHidden(w, r, manifest.TypeGomod, module, "")
		return
	}

	// list and @latest are the mutable documents a profile decides the content
	// of; everything else under @v/ is an artifact whose bytes a profile
	// decides the reachability of. Neither may be stored by a cache shared
	// across host classes.
	if immutable {
		w = cachePrivateOn200(w, file)
	} else {
		noSharedCache(w)
	}

	// The listing names no version, so it is decided at the membership level
	// and filtered below; every other file under @v/ names one.
	if !s.entitleGate(w, r, manifest.TypeGomod, module, gomodVersionFromFile(file)) {
		return
	}
	// The index filter rewrites only a list answered from upstream, and the
	// artifact gate refuses only what such a list would have withheld: a
	// hosted module's list names versions admitted on import, and refusing
	// their files would be the mid-install 403 the filter exists to prevent.
	proxied := (pm == nil && s.cacheEnabled()) || (pm != nil && packageMode(pm) == manifest.ModeProxy)
	if proxied && s.refuseWithheld(w, r, manifest.TypeGomod, module, gomodVersionFromFile(file)) {
		return
	}
	if file == "list" {
		permit := profileVersionFilter(s.profileFor(r), manifest.TypeGomod, module)
		var withhold *indexWithhold
		if proxied {
			withhold = s.indexWithholdFor(r, manifest.TypeGomod, module)
		}
		if permit != nil || withhold != nil {
			rw := &indexFilterWriter{
				ResponseWriter: w,
				subject:        module + "/@v/list",
				filter: func(b []byte) []byte {
					b = filterGomodList(b, permit)
					if withhold != nil {
						b = withhold.gomodList(b)
						withhold.finish(w.Header())
					}
					return b
				},
			}
			s.serveGomodFile(rw, r, pm, module, file, s3Key, upstream, immutable)
			if err := rw.flush(); err != nil {
				s.logger.Error("gomod list response failed", "module", module, "error", err)
			}
			return
		}
	}

	s.serveGomodFile(w, r, pm, module, file, s3Key, upstream, immutable)
}

// serveGomodFile is the body of handleGomod once the profile has decided
// whether the response passes through a filter. Split so the filtered and
// unfiltered paths cannot answer a request differently for any reason other
// than the filter.
func (s *Server) serveGomodFile(w http.ResponseWriter, r *http.Request, pm *manifest.PackageManifest, module, file, s3Key, upstream string, immutable bool) {
	ctx := r.Context()
	if pm != nil && packageMode(pm) == manifest.ModeProxy {
		// Version constraint enforcement: check if the requested version is allowed.
		if immutable {
			vc, ver := packageVersionConstraint(pm)
			if vc != "" && vc != manifest.ConstraintAny {
				reqVersion := file
				if dot := strings.LastIndex(file, "."); dot > 0 {
					reqVersion = file[:dot] // "v1.30.0.info" → "v1.30.0"
				}
				if !versionAllowed(ver, reqVersion, vc) {
					s.refuseVersionConstraint(w, r, manifest.TypeGomod, module, ver, reqVersion, vc)
					return
				}
			}
		}
		s.proxyOrCache(w, r, s.typeStore(manifest.TypeGomod), s3Key, upstream, manifest.TypeGomod, module, module, immutable, true)
		return
	}

	// A module no manifest names is answered upstream when the proxy is on, as
	// the npm packument and the cargo sparse index already are. Left to
	// proxyVersion it 404s, which is a `go get` for anything not catalogued
	// here failing against a feature README.md advertises for this type.
	//
	// Every file under @v/ takes this path, not just the mutable ones. The
	// listing alone answers nothing a client can act on: `go get` reads list,
	// then .info, .mod and .zip, and proxying the first while 404ing the rest
	// is a module resolution that fails one step later.
	if pm == nil && s.cacheEnabled() {
		s.proxyOrCache(w, r, s.typeStore(manifest.TypeGomod), s3Key, upstream, manifest.TypeGomod, module, module, immutable, false)
		return
	}

	if pm == nil {
		s.recordNoManifest(ctx, r, manifest.TypeGomod, module, gomodVersionFromFile(file), upstream)
	}
	if published, ok := gomodRecordedTime(pm, file); ok {
		rw := &indexFilterWriter{
			ResponseWriter: w,
			subject:        module + "/@v/" + file,
			filter:         func(b []byte) []byte { return gomodInfoWithTime(b, published) },
		}
		s.proxyVersion(rw, r, manifest.TypeGomod, module, gomodVersionFromFile(file), s3Key)
		if err := rw.flush(); err != nil {
			s.logger.Error("gomod info response failed", "module", module, "error", err)
		}
		return
	}
	s.proxyVersion(w, r, manifest.TypeGomod, module, gomodVersionFromFile(file), s3Key)
}

// gomodRecordedTime returns the publish time recorded for the version a .info
// request names. Any other file, or a version with none recorded, is served
// as stored.
func gomodRecordedTime(pm *manifest.PackageManifest, file string) (time.Time, bool) {
	if pm == nil || !strings.HasSuffix(file, ".info") {
		return time.Time{}, false
	}
	version := strings.TrimSuffix(file, ".info")
	for _, ve := range pm.Versions {
		if ve.Version == version {
			return publishedTime(ve)
		}
	}
	return time.Time{}, false
}

// gomodInfoWithTime sets Time in a stored .info document to the recorded
// publish time, keeping every other field. The stored document is upstream's
// own, so the two normally agree; the manifest is what every hosted index
// answers from, and a .info disagreeing with the packument and the simple page
// would give one module two ages. A document that does not parse is passed
// through as it is, since the go command reports that better than this can.
func gomodInfoWithTime(body []byte, published time.Time) []byte {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil || doc == nil {
		return body
	}
	ts, err := json.Marshal(published.Format(time.RFC3339))
	if err != nil {
		return body
	}
	doc["Time"] = ts
	out, err := json.Marshal(doc)
	if err != nil {
		return body
	}
	return out
}

// gomodVersionFromFile recovers the manifest version from a proxy filename.
// "list" and "@latest" name no version and return "", which routes them by
// type — correct, because both are regenerable listings rather than artifacts.
func gomodVersionFromFile(file string) string {
	for _, ext := range []string{".zip", ".info", ".mod"} {
		if strings.HasSuffix(file, ext) {
			return strings.TrimSuffix(file, ext)
		}
	}
	return ""
}

// versionAllowed checks whether reqVersion satisfies the constraint relative to entryVersion.
func versionAllowed(entryVersion, reqVersion, constraint string) bool {
	switch constraint {
	case manifest.ConstraintExact, "":
		return reqVersion == entryVersion
	case manifest.ConstraintAny:
		return true
	case manifest.ConstraintCompatible:
		// Same major version, any minor/patch.
		return reqVersion >= entryVersion
	case manifest.ConstraintPatch:
		// Same major.minor, any patch.
		return reqVersion >= entryVersion
	}
	return false
}
