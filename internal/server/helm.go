package server

import (
	"strings"

	"net/http"

	"github.com/ravinald/bodega/internal/manifest"
)

// ---- Helm chart repository -------------------------------------------------

func (s *Server) handleHelmIndex(w http.ResponseWriter, r *http.Request) {
	s.proxyS3(w, r, s.typeStore(manifest.TypeHelm), manifest.HelmIndexKey)
}

func (s *Server) handleHelmChart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	file := r.PathValue("file")
	// The route serves chart archives only, and the key is rebuilt from the
	// parsed identity rather than pasted from the request. Anything that is not
	// a .tgz would produce a key the uploader never writes.
	if !strings.HasSuffix(file, ".tgz") {
		http.NotFound(w, r)
		return
	}
	setCacheImmutable(w, file)

	// Parse chart name from filename: "ingress-nginx-4.0.0.tgz" → "ingress-nginx".
	// Splitting on the last "-" and rejoining is lossless, so a prerelease
	// version ("4.0.0-rc1") lands on the same key it was uploaded under even
	// though the split lands in the wrong place.
	chartName := strings.TrimSuffix(file, ".tgz")
	chartVersion := ""
	if idx := strings.LastIndex(chartName, "-"); idx > 0 {
		chartVersion = chartName[idx+1:]
		chartName = chartName[:idx]
	}
	key := manifest.HelmChartKey(chartName, chartVersion)
	pm, _ := s.store.GetPackage(ctx, manifest.TypeHelm, chartName)
	if pm != nil && packageMode(pm) == manifest.ModeProxy {
		// Use the URL from the first version that has one.
		for _, ve := range pm.Versions {
			if ve.URL != "" {
				upstream := strings.TrimSuffix(ve.URL, "/") + "/" + file
				s.proxyOrCache(w, r, s.typeStore(manifest.TypeHelm), key, upstream, manifest.TypeHelm, upstream, chartName, true, true)
				return
			}
		}
	}
	s.proxyVersion(w, r, manifest.TypeHelm, chartName, chartVersion, key)
}
