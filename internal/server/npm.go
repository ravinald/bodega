package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

func (s *Server) handleNpm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	fullPath := r.PathValue("path")

	// Tarball request: path contains "/-/"
	if idx := strings.Index(fullPath, "/-/"); idx >= 0 {
		pkgName := fullPath[:idx]   // canonical, e.g. "@bitwarden/cli"
		tarball := fullPath[idx+3:] // URL form, e.g. "cli-2026.3.0.tgz"
		w = cacheImmutableOn200(w, tarball)

		// Storage uses the safe-encoded form everywhere; the URL does not, so
		// the version has to come back out of the wire filename before a key
		// can be derived. An unparseable filename names no artifact.
		reqVersion := npmVersionFromTarball(pkgName, tarball)
		if reqVersion == "" {
			http.NotFound(w, r)
			return
		}
		storageKey := manifest.NpmTarballKey(pkgName, reqVersion)

		pm, _ := s.store.GetPackage(ctx, manifest.TypeNpm, pkgName)
		if pm != nil {
			if isPackageHidden(pm) {
				http.NotFound(w, r)
				return
			}
			if isVersionHidden(pm, reqVersion) {
				http.NotFound(w, r)
				return
			}
			// 403 (not 404) below — the version exists upstream, we're
			// refusing by policy. Mirrors the gomod path in versionAllowed.
			vc, baseVer := packageVersionConstraint(pm)
			if vc != "" && vc != manifest.ConstraintAny && baseVer != "" {
				if !versionAllowed(baseVer, reqVersion, vc) {
					s.recordVersionRefusal(r, manifest.TypeNpm, pkgName, baseVer, reqVersion, vc)
					http.Error(w, "version not allowed by constraint", http.StatusForbidden)
					return
				}
			}
		}

		upstream := s.cfg.NpmUpstream + "/" + pkgName + "/-/" + tarball
		if pm != nil && packageMode(pm) == manifest.ModeProxy {
			s.proxyOrCache(w, r, s.typeStore(manifest.TypeNpm), storageKey, upstream, manifest.TypeNpm, pkgName, pkgName, true, true)
			return
		}
		if pm == nil {
			s.recordNoManifest(ctx, r, manifest.TypeNpm, pkgName, reqVersion, upstream)
		}
		s.proxyVersion(w, r, manifest.TypeNpm, pkgName, reqVersion, storageKey)
		return
	}

	// Packument request: path is just the package name (possibly scoped).
	pkgName := fullPath
	pm, _ := s.store.GetPackage(ctx, manifest.TypeNpm, pkgName)

	if pm != nil && isPackageHidden(pm) {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Filtered packument is not cached — its S3 key would collide with the
	// unfiltered copy.
	if pm != nil && (hasHiddenVersion(pm) || hasVersionConstraint(pm)) {
		s.serveFilteredPackument(w, r, pkgName, pm)
		return
	}

	upstream := s.cfg.NpmUpstream + "/" + pkgName
	s3Key := manifest.NpmPackumentKey(pkgName)
	forceProxy := pm != nil && packageMode(pm) == manifest.ModeProxy
	s.proxyOrCache(w, r, s.typeStore(manifest.TypeNpm), s3Key, upstream, manifest.TypeNpm, pkgName, pkgName, false, forceProxy)
}

// @bitwarden/cli + cli-2026.4.0.tgz → 2026.4.0. "" on unexpected shape.
func npmVersionFromTarball(pkgName, tarball string) string {
	basename := pkgName
	if idx := strings.LastIndex(basename, "/"); idx >= 0 {
		basename = basename[idx+1:]
	}
	prefix := basename + "-"
	if !strings.HasPrefix(tarball, prefix) {
		return ""
	}
	v := strings.TrimPrefix(tarball, prefix)
	v = strings.TrimSuffix(v, ".tgz")
	return v
}

// Silent on unknown versions; the manifest's silence is not a hide.
func isVersionHidden(pm *manifest.PackageManifest, version string) bool {
	for _, ve := range pm.Versions {
		if ve.Version == version || ve.Ref == version {
			return ve.Hidden
		}
	}
	return false
}

func hasHiddenVersion(pm *manifest.PackageManifest) bool {
	for _, ve := range pm.Versions {
		if ve.Hidden {
			return true
		}
	}
	return false
}

func hasVersionConstraint(pm *manifest.PackageManifest) bool {
	vc, baseVer := packageVersionConstraint(pm)
	return vc != "" && vc != manifest.ConstraintAny && baseVer != ""
}

func (s *Server) serveFilteredPackument(w http.ResponseWriter, r *http.Request, pkgName string, pm *manifest.PackageManifest) {
	upstream := s.cfg.NpmUpstream + "/" + pkgName
	data, ct, err := fetchUpstream(r.Context(), upstream)
	if err != nil {
		s.logger.Error("packument fetch failed", "url", upstream, "error", err)
		http.Error(w, "upstream fetch failed", http.StatusBadGateway)
		return
	}

	filtered, err := filterPackumentByManifest(data, pm)
	if err != nil {
		s.logger.Error("packument filter failed", "pkg", pkgName, "error", err)
		http.Error(w, "packument filter failed", http.StatusInternalServerError)
		return
	}

	if ct == "" {
		ct = "application/json"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(filtered)))
	w.WriteHeader(http.StatusOK)
	//nolint:gosec // G705: filtered is the JSON packument body; Content-Type set to application/json above.
	_, _ = w.Write(filtered)
}

// Strip hidden + out-of-constraint versions (and any dist-tags pointing at
// them) from a raw npm packument, so clients never see a version we'd
// refuse to serve.
func filterPackumentByManifest(body []byte, pm *manifest.PackageManifest) ([]byte, error) {
	hidden := make(map[string]bool)
	for _, ve := range pm.Versions {
		if ve.Hidden && ve.Version != "" {
			hidden[ve.Version] = true
		}
	}

	vc, baseVer := packageVersionConstraint(pm)
	hasConstraint := vc != "" && vc != manifest.ConstraintAny && baseVer != ""

	if len(hidden) == 0 && !hasConstraint {
		return body, nil
	}

	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}

	rejected := func(v string) bool {
		if hidden[v] {
			return true
		}
		if hasConstraint && !versionAllowed(baseVer, v, vc) {
			return true
		}
		return false
	}

	if versions, ok := doc["versions"].(map[string]any); ok {
		for v := range versions {
			if rejected(v) {
				delete(versions, v)
			}
		}
	}
	if times, ok := doc["time"].(map[string]any); ok {
		for v := range times {
			if v == "created" || v == "modified" {
				continue
			}
			if rejected(v) {
				delete(times, v)
			}
		}
	}
	if tags, ok := doc["dist-tags"].(map[string]any); ok {
		for tag, v := range tags {
			s, ok := v.(string)
			if !ok {
				continue
			}
			if rejected(s) {
				delete(tags, tag)
			}
		}
	}

	return json.Marshal(doc)
}
