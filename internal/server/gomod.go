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

	s3Key := "gomod/" + module + "/@v/" + file
	upstream := s.cfg.GomodUpstream + "/" + module + "/@v/" + file
	immutable := file != "list" && !strings.HasSuffix(file, "latest")

	pm, _ := s.store.GetPackage(ctx, manifest.TypeGomod, module)
	if pm != nil && isPackageHidden(pm) {
		http.NotFound(w, r)
		return
	}

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
					http.Error(w, "version not allowed by constraint", http.StatusForbidden)
					return
				}
			}
		}
		s.proxyOrCache(w, r, s3Key, upstream, manifest.TypeGomod, module, immutable, true)
		return
	}
	s.proxyS3(w, r, s3Key)
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
