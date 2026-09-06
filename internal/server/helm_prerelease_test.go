package server

import (
	"net/http"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// A prerelease chart is the shape the request path used to split at the wrong
// "-": "cert-manager-1.14.0-rc.1" read as the chart "cert-manager-1.14.0" at
// version "rc.1". The object key came out right either way, so only the three
// call sites that read the identity — the proxy lookup, the discovery row and
// the per-version backend — can tell the difference.
const (
	prereleaseChart = "cert-manager-1.14.0-rc.1.tgz"
	stableChart     = "cert-manager-1.14.0.tgz"
)

// seedProxyHelm puts one proxy-mode chart in the store. A helm upstream is
// recorded on the version entry rather than in config, so the URL travels
// there.
func seedProxyHelm(t *testing.T, s *Server, chart, version, url string) {
	t.Helper()
	pm := &manifest.PackageManifest{
		ConfigVersion: manifest.CurrentConfigVersion,
		Name:          chart,
		Type:          manifest.TypeHelm,
		Versions:      []manifest.VersionEntry{{Version: version, URL: url, Mode: manifest.ModeProxy}},
	}
	if err := s.store.SavePackage(t.Context(), pm); err != nil {
		t.Fatalf("seed helm/%s: %v", chart, err)
	}
}

// TestHelmPrereleaseChartReachesProxyUpstream pins the ModeProxy branch for a
// chart whose version carries a "-". The manifest names the chart
// "cert-manager"; a lookup on "cert-manager-1.14.0" returns nil and the branch
// never fires, so the fixture never sees a request.
func TestHelmPrereleaseChartReachesProxyUpstream(t *testing.T) {
	s := proxyingServer(t)
	up := newRecordingUpstream(t)
	up.route("/charts/"+prereleaseChart, "chart bytes")
	seedProxyHelm(t, s, "cert-manager", "1.14.0-rc.1", up.ts.URL+"/charts")

	status, body := getStatusAndBody(t, s, "/helm/charts/"+prereleaseChart)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q); upstream saw %v", status, body, up.paths())
	}
	if body != "chart bytes" {
		t.Errorf("body = %q, want the fixture's chart bytes", body)
	}
	if !up.sawPath("/charts/" + prereleaseChart) {
		t.Errorf("upstream saw %v, want a fetch of /charts/%s: the proxy-mode entry was looked up under the wrong chart name",
			up.paths(), prereleaseChart)
	}
}

// TestHelmChartNoManifestRowNamesTheChart asserts the identity on the
// discovery row itself, not the fact that a row exists. `discover promote --as
// manifest` hands an operator whatever the row says, and a prerelease used to
// name a chart no repository serves.
func TestHelmChartNoManifestRowNamesTheChart(t *testing.T) {
	s := newDiscoveryServer(t)

	for _, file := range []string{prereleaseChart, stableChart} {
		if status, body := getStatusAndBody(t, s, "/helm/charts/"+file); status != http.StatusNotFound {
			t.Fatalf("GET %s = %d (%q), want 404 — this branch records the miss, it does not serve it", file, status, body)
		}
	}

	rows := waitForDiscovery(t, s, 2)
	for _, want := range [][2]string{
		{"cert-manager", "1.14.0-rc.1"},
		{"cert-manager", "1.14.0"},
	} {
		found := false
		for _, row := range rows {
			if row.PkgName == want[0] && row.PkgVersion == want[1] {
				found = true
			}
		}
		if !found {
			t.Errorf("no discovery row for %s at %s; rows carry %v", want[0], want[1], identities(rows))
		}
	}
}

func identities(rows []audit.DiscoveryRow) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.PkgName+"/"+row.PkgVersion)
	}
	return out
}
