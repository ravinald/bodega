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
	w = cacheImmutableOn200(w, file)

	// The whole basename as an unversioned chart yields the key the request
	// names, which ParseKey then splits the way HelmChartKey built it. Reading
	// the identity back out of the key rather than off the filename is what
	// keeps a prerelease whole: "cert-manager-1.14.0-rc.1" is the chart
	// cert-manager at 1.14.0-rc.1, not cert-manager-1.14.0 at rc.1.
	key := manifest.HelmChartKey(strings.TrimSuffix(file, ".tgz"), "")
	_, chartName, chartVersion := manifest.ParseKey(key)
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
	if pm == nil {
		// No manifest entry means no chart repo URL either — helm upstreams are
		// recorded per version entry, not in config. The row is written with an
		// empty upstream_url, which `discover promote --as manifest` reports as
		// needing an operator-supplied URL.
		s.recordNoManifest(ctx, r, manifest.TypeHelm, chartName, chartVersion, "")
	}
	s.proxyVersion(w, r, manifest.TypeHelm, chartName, chartVersion, key)
}
