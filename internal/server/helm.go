package server

import (
	"strings"

	"net/http"

	"github.com/ravinald/bodega/internal/manifest"
)

// ---- Helm chart repository -------------------------------------------------

func (s *Server) handleHelmIndex(w http.ResponseWriter, r *http.Request) {
	s.proxyS3(w, r, "charts/index.yaml")
}

func (s *Server) handleHelmChart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	file := r.PathValue("file")
	key := "charts/" + file
	setCacheImmutable(w, file)

	// Check if any helm entry is in proxy mode with a URL we can use.
	// Parse chart name from filename: "ingress-nginx-4.0.0.tgz" → "ingress-nginx"
	chartName := strings.TrimSuffix(file, ".tgz")
	if idx := strings.LastIndex(chartName, "-"); idx > 0 {
		chartName = chartName[:idx]
	}
	pm, _ := s.store.GetPackage(ctx, manifest.TypeHelm, chartName)
	if pm != nil && packageMode(pm) == manifest.ModeProxy {
		// Use the URL from the first version that has one.
		for _, ve := range pm.Versions {
			if ve.URL != "" {
				upstream := strings.TrimSuffix(ve.URL, "/") + "/" + file
				s.proxyOrCache(w, r, key, upstream, manifest.TypeHelm, upstream, chartName, true, true)
				return
			}
		}
	}
	s.proxyS3(w, r, key)
}
