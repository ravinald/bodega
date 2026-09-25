package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// The three artifact routes that answered an uncatalogued name with a bare 404
// while cargo and gomod proxied one. npm was a contradiction rather than an
// asymmetry: bodega published the tarball URL and then refused it. pypi and
// helm keep refusing, and the tests here hold them to saying why.

const (
	uncatNpmPkg     = "is-number"
	uncatNpmVersion = "7.0.0"
	uncatNpmBytes   = "\x1f\x8b tarball bytes"
)

// npmUpstreamFixture publishes one package: a packument naming its own tarball
// by absolute URL, the way registry.npmjs.org does, and the tarball itself.
func npmUpstreamFixture(t *testing.T) *httptest.Server {
	t.Helper()
	var base string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tarball := "/" + uncatNpmPkg + "/-/" + uncatNpmPkg + "-" + uncatNpmVersion + ".tgz"
		switch r.URL.Path {
		case "/" + uncatNpmPkg:
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"name":%q,"dist-tags":{"latest":%q},"versions":{%q:{"name":%q,"version":%q,"dist":{"tarball":%q}}}}`,
				uncatNpmPkg, uncatNpmVersion, uncatNpmVersion, uncatNpmPkg, uncatNpmVersion, base+tarball)
		case tarball:
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(uncatNpmBytes)))
			_, _ = w.Write([]byte(uncatNpmBytes))
		default:
			http.NotFound(w, r)
		}
	}))
	base = ts.URL
	t.Cleanup(ts.Close)
	return ts
}

// TestNpmTarballProxiesAPackageNoManifestNames is the contradiction itself: the
// packument route proxies an uncatalogued package and rewrites every
// dist.tarball onto bodega, so the URL asserted here is the one bodega handed
// the client. Fetching it is what `npm install` does next.
func TestNpmTarballProxiesAPackageNoManifestNames(t *testing.T) {
	up := npmUpstreamFixture(t)
	s := proxyingServer(t)
	s.cfg.NpmUpstream = up.URL

	code, body := getStatusAndBody(t, s, "/npm/"+uncatNpmPkg)
	if code != http.StatusOK {
		t.Fatalf("GET /npm/%s = %d, want 200 (%s)", uncatNpmPkg, code, body)
	}
	tarballPath := packumentTarballPath(t, body)
	if want := "/npm/" + uncatNpmPkg + "/-/"; !strings.HasPrefix(tarballPath, want) {
		t.Fatalf("packument names %q, want a path under %q", tarballPath, want)
	}

	code, body = getStatusAndBody(t, s, tarballPath)
	if code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200 — bodega published this URL in the packument above (%s)", tarballPath, code, body)
	}
	if body != uncatNpmBytes {
		t.Errorf("tarball body = %q, want the upstream bytes %q", body, uncatNpmBytes)
	}

	// Served is not cached, and a server that proxied every request and stored
	// nothing answers 200 just as well.
	key := manifest.NpmTarballKey(uncatNpmPkg, uncatNpmVersion)
	info, err := s.typeStore(manifest.TypeNpm).Head(t.Context(), key)
	if err != nil {
		t.Fatalf("head %s: %v", key, err)
	}
	if info == nil || !info.Exists {
		t.Errorf("GET %s served 200 but cached nothing at %s", tarballPath, key)
	}

	rows, err := s.auditDB.Query(context.Background(), audit.Filter{EventType: audit.EventCache})
	if err != nil {
		t.Fatalf("query cache events: %v", err)
	}
	var misses int
	for _, row := range rows {
		if row.Status == audit.CacheMiss && strings.Contains(row.Details, key) {
			misses++
		}
	}
	if misses == 0 {
		t.Errorf("no cache_miss row names %s; the fetch is unattributable (%+v)", key, rows)
	}
}

// packumentTarballPath pulls the one dist.tarball out of a packument and
// returns its path. The rewrite is npmPackumentWriter's, asserted here only far
// enough to have a URL to fetch.
func packumentTarballPath(t *testing.T, body string) string {
	t.Helper()
	var doc struct {
		Versions map[string]struct {
			Dist struct {
				Tarball string `json:"tarball"`
			} `json:"dist"`
		} `json:"versions"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("parse packument: %v (%s)", err, body)
	}
	ver, ok := doc.Versions[uncatNpmVersion]
	if !ok {
		t.Fatalf("packument has no version %s: %s", uncatNpmVersion, body)
	}
	idx := strings.Index(ver.Dist.Tarball, "/npm/")
	if idx < 0 {
		t.Fatalf("dist.tarball = %q, want a URL on bodega's own /npm root", ver.Dist.Tarball)
	}
	return ver.Dist.Tarball[idx:]
}

// TestPypiWheelRefusalNamesTheIndexItWouldHaveRead holds the decision that pypi
// artifacts stay catalog-only. The refusal is the whole of what ships, so it
// has to carry the index read that is the reason and the command that ends it.
func TestPypiWheelRefusalNamesTheIndexItWouldHaveRead(t *testing.T) {
	s := proxyingServer(t)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	code, body := getStatusAndBody(t, s, "/pypi/wheels/six-1.16.0-py2.py3-none-any.whl")
	if code != http.StatusNotFound {
		t.Fatalf("GET an uncatalogued wheel = %d, want 404 (%s)", code, body)
	}
	for _, want := range []string{"six", "https://pypi.org/simple/six/", "bodega pkg create pypi six"} {
		if !strings.Contains(body, want) {
			t.Errorf("wheel refusal does not name %q: %q", want, body)
		}
	}

	// The refusal and the discovery row are two halves of one answer: the body
	// tells the operator reading the response, the row tells the one reading
	// `bodega discover list`.
	rows := waitForDiscovery(t, s, 1)
	if rows[0].UpstreamURL != "https://pypi.org/simple/six/" {
		t.Errorf("no_manifest upstream_url = %q, want the simple index", rows[0].UpstreamURL)
	}
}

// TestPypiWheelRefusalCutsTheConfiguredCredential holds the refusal to the rule
// a published manifest url follows. The GET takes no token, so a private index
// configured with userinfo would otherwise hand its credential to any caller.
// The username is asserted apart from the password because url.Redacted keeps
// it as user:xxxxx@, which a match on user@ misses. The body is held to
// absence rather than to replacement wording.
func TestPypiWheelRefusalCutsTheConfiguredCredential(t *testing.T) {
	s := proxyingServer(t)
	s.cfg.PypiUpstream = "https://user:secret@pypi.internal"
	var logged bytes.Buffer
	s.logger = slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelInfo}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/pypi/wheels/six-1.16.0-py2.py3-none-any.whl", nil)
	s.Handler().ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET an uncatalogued wheel = %d, want 404 (%s)", rec.Code, body)
	}
	if strings.Contains(body, "secret") {
		t.Errorf("anonymous refusal body carries the password from pypi_upstream: %q", body)
	}
	if strings.Contains(body, "user") {
		t.Errorf("anonymous refusal body carries the username from pypi_upstream: %q", body)
	}
	if strings.Contains(body, "@") {
		t.Errorf("anonymous refusal body carries a userinfo component: %q", body)
	}
	if !strings.Contains(body, "pypi.internal") {
		t.Errorf("refusal no longer names the index host: %q", body)
	}

	// The operator still learns which index, and which account on it.
	log := logged.String()
	if !strings.Contains(log, "https://user:xxxxx@pypi.internal/simple/six/") {
		t.Errorf("refusal log line does not name the configured index: %q", log)
	}
	if strings.Contains(log, "secret") {
		t.Errorf("refusal log line carries the password: %q", log)
	}
}

// TestHelmChartRefusalNamesTheMissingRepositoryURL is the route that cannot be
// opened at all. A chart repository is recorded per version entry, so an
// uncatalogued chart has no host to proxy to, and the bare 404 it used to
// answer sends an operator looking upstream for a chart that is published and
// reachable.
func TestHelmChartRefusalNamesTheMissingRepositoryURL(t *testing.T) {
	s := proxyingServer(t)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	code, body := getStatusAndBody(t, s, "/helm/charts/ingress-nginx-4.0.0.tgz")
	if code != http.StatusNotFound {
		t.Fatalf("GET an uncatalogued chart = %d, want 404 (%s)", code, body)
	}
	for _, want := range []string{"ingress-nginx", "chart repository URL", "bodega pkg create helm ingress-nginx"} {
		if !strings.Contains(body, want) {
			t.Errorf("chart refusal does not name %q: %q", want, body)
		}
	}
}

// A cached object with no manifest entry still serves. The refusals above are
// for an empty backend, and a Head that finds bytes must not turn into one.
func TestUncataloguedRefusalYieldsToACachedObject(t *testing.T) {
	s := proxyingServer(t)
	key := manifest.HelmChartKey("ingress-nginx-4.0.0", "")
	if err := s.typeStore(manifest.TypeHelm).Put(t.Context(), key, []byte("chart bytes")); err != nil {
		t.Fatalf("seed %s: %v", key, err)
	}

	code, body := getStatusAndBody(t, s, "/helm/charts/ingress-nginx-4.0.0.tgz")
	if code != http.StatusOK {
		t.Fatalf("GET a cached chart with no entry = %d, want 200 (%s)", code, body)
	}
	if body != "chart bytes" {
		t.Errorf("body = %q, want the stored bytes", body)
	}
}
