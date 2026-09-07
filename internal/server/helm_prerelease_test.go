package server

import (
	"net/http"
	"testing"
	"time"

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
	// A "v" prefix is the other shape the old split read correctly, so the
	// splitting rule has to open on one to keep it.
	prefixedChart = "mychart-v1.2.3.tgz"
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

	for _, file := range []string{prereleaseChart, stableChart, prefixedChart} {
		if status, body := getStatusAndBody(t, s, "/helm/charts/"+file); status != http.StatusNotFound {
			t.Fatalf("GET %s = %d (%q), want 404 — this branch records the miss, it does not serve it", file, status, body)
		}
	}

	rows := waitForDiscovery(t, s, 3)
	for _, want := range [][2]string{
		{"cert-manager", "1.14.0-rc.1"},
		{"cert-manager", "1.14.0"},
		{"mychart", "v1.2.3"},
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

// TestHelmPrereleaseAgreesAcrossEveryDerivation drives one proxy-mode request
// and reads back every place its identity is written down. Three derivations
// ran over the same request and only the handler's had moved: the discovery
// row split at the last "-" and recorded cert-manager at "rc.1", the
// serve_fetch event split the same way and recorded "cert-manager-1.14.0" at
// "rc.1", and an operator reading `discover list` or `audit events` got a name
// and version no repository serves. A test that checks one of the three is
// what let this survive two items, so this checks all three off one request.
func TestHelmPrereleaseAgreesAcrossEveryDerivation(t *testing.T) {
	const (
		wantChart   = "cert-manager"
		wantVersion = "1.14.0-rc.1"
	)
	s := proxyingServer(t)
	up := newRecordingUpstream(t)
	up.route("/charts/"+prereleaseChart, "chart bytes")
	seedProxyHelm(t, s, wantChart, wantVersion, up.ts.URL+"/charts")

	if status, body := getStatusAndBody(t, s, "/helm/charts/"+prereleaseChart); status != http.StatusOK {
		t.Fatalf("status = %d (%q), want 200; upstream saw %v", status, body, up.paths())
	}

	// The request path itself: the proxy-mode branch only fires on a manifest
	// lookup for the chart the seed names.
	if !up.sawPath("/charts/" + prereleaseChart) {
		t.Errorf("upstream saw %v, want /charts/%s", up.paths(), prereleaseChart)
	}

	rows := waitForAnyDiscovery(t, s, 1)
	var gotRow bool
	for _, row := range rows {
		if row.PkgName == wantChart && row.PkgVersion == wantVersion {
			gotRow = true
		}
	}
	if !gotRow {
		t.Errorf("no discovery row for %s at %s; rows carry %v", wantChart, wantVersion, identities(rows))
	}

	fetches := waitForServeFetch(t, s, 1)
	var gotEvent bool
	for _, ev := range fetches {
		if ev.PkgType == manifest.TypeHelm && ev.PkgName == wantChart && ev.PkgVersion == wantVersion {
			gotEvent = true
		}
	}
	if !gotEvent {
		t.Errorf("no serve_fetch event for helm %s at %s; events carry %v",
			wantChart, wantVersion, eventIdentities(fetches))
	}
}

// waitForAnyDiscovery is waitForDiscovery with no decision filter: a fetch the
// allow-list permitted lands under no_policy, not no_manifest.
func waitForAnyDiscovery(t *testing.T, s *Server, want int) []audit.DiscoveryRow {
	t.Helper()
	var rows []audit.DiscoveryRow
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		var err error
		rows, err = s.auditDB.ListDiscovery(t.Context(), audit.DiscoveryFilter{})
		if err != nil {
			t.Fatalf("list discovery: %v", err)
		}
		if len(rows) >= want {
			return rows
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("discovery rows = %d after 3s, want %d (%+v)", len(rows), want, rows)
	return nil
}

// waitForServeFetch polls the audit table: AuditMiddleware writes the event
// after the handler returns, which can be after the client has read the body.
func waitForServeFetch(t *testing.T, s *Server, want int) []audit.StoredEvent {
	t.Helper()
	var events []audit.StoredEvent
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		var err error
		events, err = s.auditDB.Query(t.Context(), audit.Filter{EventType: audit.EventServeFetch})
		if err != nil {
			t.Fatalf("query audit db: %v", err)
		}
		if len(events) >= want {
			return events
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("serve_fetch events = %d after 3s, want %d (%+v)", len(events), want, events)
	return nil
}

func eventIdentities(events []audit.StoredEvent) []string {
	out := make([]string, 0, len(events))
	for _, ev := range events {
		out = append(out, ev.PkgType+"/"+ev.PkgName+"/"+ev.PkgVersion)
	}
	return out
}
