package server

import (
	"strings"

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
		http.NotFound(w, r)
		return
	}

	// The listing names no version, so it is decided at the membership level
	// and filtered below; every other file under @v/ names one.
	if !s.entitleGate(w, r, manifest.TypeGomod, module, gomodVersionFromFile(file)) {
		return
	}
	if file == "list" {
		if permit := profileVersionFilter(s.profileFor(r), manifest.TypeGomod, module); permit != nil {
			rw := &indexFilterWriter{
				ResponseWriter: w,
				subject:        module + "/@v/list",
				filter:         func(b []byte) []byte { return filterGomodList(b, permit) },
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
					s.recordVersionRefusal(r, manifest.TypeGomod, module, ver, reqVersion, vc)
					http.Error(w, "version not allowed by constraint", http.StatusForbidden)
					return
				}
			}
		}
		s.proxyOrCache(w, r, s.typeStore(manifest.TypeGomod), s3Key, upstream, manifest.TypeGomod, module, module, immutable, true)
		return
	}

	if pm == nil {
		s.recordNoManifest(ctx, r, manifest.TypeGomod, module, gomodVersionFromFile(file), upstream)
	}
	s.proxyVersion(w, r, manifest.TypeGomod, module, gomodVersionFromFile(file), s3Key)
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
