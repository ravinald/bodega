package server

import (
	"strings"

	"net/http"

	"github.com/ravinald/bodega/internal/manifest"
)

// ---- Helm chart repository -------------------------------------------------

// handleHelmIndex serves the generated chart index, with the charts and
// releases this host's profile does not permit removed.
//
// The filter runs on the way out against the live profile, as it does on the
// four indexes bodega caches from an upstream, so an operator's edit lands
// within the binding cache TTL rather than at the next build. Here the
// document is generated into storage by `bodega build` rather than cached,
// which means a filtered copy has nowhere to land even by accident.
//
// The route is not gated. A profile that permits no chart answers 200 with an
// empty `entries:` map, because a 403 on this path fails `helm repo add`
// itself and helm names neither the profile nor a chart in what it prints. An
// empty repository sends the operator to `helm search repo`, which is the
// question they can answer; the refusal with a reason attached is on the chart
// pull. See TestHelmIndexIsNotRefusedByAProfile and docs/USAGE.md.
func (s *Server) handleHelmIndex(w http.ResponseWriter, r *http.Request) {
	prof := s.profileFor(r)
	if prof == nil {
		s.proxyS3(w, r, s.typeStore(manifest.TypeHelm), manifest.HelmIndexKey)
		return
	}
	covers := func(chart string) bool { return prof.Covers(manifest.TypeHelm, chart).Permitted }
	permit := func(chart, version string) bool {
		if f := profileVersionFilter(prof, manifest.TypeHelm, chart); f != nil {
			return f(version)
		}
		return true
	}
	rw := &indexFilterWriter{
		ResponseWriter: w,
		subject:        "the helm chart index",
		filter:         func(b []byte) []byte { return filterHelmIndex(b, covers, permit) },
	}
	s.proxyS3(rw, r, s.typeStore(manifest.TypeHelm), manifest.HelmIndexKey)
	if err := rw.flush(); err != nil {
		s.logger.Error("helm index response failed", "error", err)
	}
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
	if !s.entitleGate(w, r, manifest.TypeHelm, chartName, chartVersion) {
		return
	}
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
