package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// ociChart is a chart as `helm push` stores it: a manifest whose config is
// the chart's metadata and whose one layer is the packaged chart.
type ociChart struct {
	manifest, config, layer []byte
	digest, configD, layerD string
}

// publishChart serves a chart at repo under tag. The config and layer carry
// the repository, so two charts never share a blob.
func (g *ociRegistry) publishChart(repo, tag string) ociChart {
	c := ociChart{
		config: []byte(`{"name":"` + repo + `","version":"` + tag + `","apiVersion":"v2"}`),
		layer:  []byte("chart archive for " + repo + " " + tag),
	}
	c.configD, c.layerD = ociDigest(c.config), ociDigest(c.layer)
	c.manifest, _ = json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": mediaOCIManifest,
		"config": map[string]any{"mediaType": manifest.HelmOCIConfigMediaType, "digest": c.configD, "size": len(c.config)},
		"layers": []any{map[string]any{"mediaType": "application/vnd.cncf.helm.chart.content.v1.tar+gzip", "digest": c.layerD, "size": len(c.layer)}},
	})
	c.digest = ociDigest(c.manifest)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.manifests[repo+"@"+tag] = ociObject{mediaOCIManifest, c.manifest}
	g.manifests[repo+"@"+c.digest] = ociObject{mediaOCIManifest, c.manifest}
	g.blobs[c.configD], g.blobs[c.layerD] = c.config, c.layer
	g.tagLists[repo] = `{"name":"` + repo + `","tags":["` + tag + `"]}`
	return c
}

func (g *ociRegistry) blobHits(c ociChart, repo string) int {
	return g.hitsFor("/v2/"+repo+"/blobs/"+c.configD) + g.hitsFor("/v2/"+repo+"/blobs/"+c.layerD)
}

// waitForDiscoveryRow waits for the row naming name at version under typ, and
// returns every row of typ once it is there.
func waitForDiscoveryRow(t *testing.T, s *Server, typ, name, version string) []audit.DiscoveryRow {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		rows, err := s.auditDB.ListDiscovery(t.Context(), audit.DiscoveryFilter{RegistryType: typ})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if r.PkgName == name && r.PkgVersion == version {
				return rows
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s discovery row for %s at %s: %+v", typ, name, version, rows)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func discoveryNames(t *testing.T, s *Server, typ string) []string {
	t.Helper()
	rows, err := s.auditDB.ListDiscovery(t.Context(), audit.DiscoveryFilter{RegistryType: typ})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range rows {
		names = append(names, r.PkgName)
	}
	return names
}

// A chart manifest under /v2/ is served, its blobs with it, and recorded
// under helm at its <registry>/<repository> identity and tag. The manifest is
// fetched once: the copy read to classify it is the copy served.
func TestOCIHelmChartServedAndRecordedAsHelm(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	c := f.hub.publishChart("bitnamicharts/redis", "20.0.0")

	rec := doRequest(s, http.MethodGet, "/v2/bitnamicharts/redis/manifests/20.0.0", nil)
	if rec.Code != http.StatusOK || rec.Body.String() != string(c.manifest) {
		t.Fatalf("chart manifest: %d %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get(ociDigestHeader); got != c.digest {
		t.Errorf("%s %q, want %q", ociDigestHeader, got, c.digest)
	}
	for _, d := range []string{c.configD, c.layerD} {
		if rec := doRequest(s, http.MethodGet, "/v2/bitnamicharts/redis/blobs/"+d, nil); rec.Code != http.StatusOK {
			t.Errorf("chart blob %s: %d %s", d, rec.Code, rec.Body.String())
		}
	}
	if n := f.hub.hitsFor("/v2/bitnamicharts/redis/manifests/20.0.0"); n != 1 {
		t.Errorf("chart manifest fetched upstream %d times, want 1", n)
	}

	waitForDiscoveryRow(t, s, manifest.TypeHelm, "docker.io/bitnamicharts/redis", "20.0.0")
	waitForDiscoveryRow(t, s, manifest.TypeHelm, "docker.io/bitnamicharts/redis", c.layerD)
	for _, n := range discoveryNames(t, s, manifest.TypeOCI) {
		if n == "docker.io/bitnamicharts/redis" {
			t.Errorf("the chart left a discovery row under oci")
		}
	}

	// A digest request for the chart is judged as helm from the stored copy,
	// which reaches the registry not at all.
	before := f.hub.total()
	if rec := doRequest(s, http.MethodGet, "/v2/bitnamicharts/redis/manifests/"+c.digest, nil); rec.Code != http.StatusOK {
		t.Fatalf("chart by digest: %d %s", rec.Code, rec.Body.String())
	}
	if n := f.hub.total() - before; n != 0 {
		t.Errorf("chart by digest reached the registry %d times", n)
	}
}

// A helm hide on the chart's identity refuses it under /v2/ with the spec's
// error body, and its blobs with it, and no blob is fetched.
func TestOCIHelmHideRefusesTheChart(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	c := f.hub.publishChart("bitnamicharts/redis", "20.0.0")
	addVersion(t, s, manifest.TypeHelm, "docker.io/bitnamicharts/redis", manifest.VersionEntry{Version: "20.0.0", Mode: manifest.ModeProxy, Hidden: true})

	rec := doRequest(s, http.MethodGet, "/v2/bitnamicharts/redis/manifests/20.0.0", nil)
	assertOCIError(t, rec, http.StatusNotFound, "MANIFEST_UNKNOWN", "docker.io/bitnamicharts/redis")
	refusalIncident(t, rec.Header(), checkHidden)
	// Over a real connection too: helm's own refusals answer in the status
	// line, and a chart under /v2/ must not.
	status, body := getWithToken(t, s, "", "/v2/bitnamicharts/redis/manifests/20.0.0")
	if status != http.StatusNotFound || !strings.Contains(body, `"MANIFEST_UNKNOWN"`) {
		t.Errorf("hidden chart over the wire = %d %s, want the spec's error JSON", status, body)
	}

	rec = doRequest(s, http.MethodGet, "/v2/bitnamicharts/redis/blobs/"+c.layerD, nil)
	assertOCIError(t, rec, http.StatusNotFound, "BLOB_UNKNOWN", "docker.io/bitnamicharts/redis")
	if n := f.hub.blobHits(c, "bitnamicharts/redis"); n != 0 {
		t.Errorf("a hidden chart's blobs were fetched %d times", n)
	}
}

// A helm profile listing one chart repository admits it under /v2/ and
// refuses another chart from the same registry, naming helm and the
// membership rule, before any of the refused chart's blobs is fetched.
func TestOCIHelmProfileAdmitsOneChartAndRefusesAnother(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	redis := f.hub.publishChart("bitnamicharts/redis", "20.0.0")
	pg := f.hub.publishChart("bitnamicharts/postgresql", "16.0.0")
	pf := bindProfile(t, s, "charts", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeHelm, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{Type: manifest.TypeHelm, Name: "docker.io/bitnamicharts/redis"}})

	for _, p := range []string{"/v2/bitnamicharts/redis/manifests/20.0.0", "/v2/bitnamicharts/redis/blobs/" + redis.layerD} {
		if status, body := pf.get(t, p); status != http.StatusOK {
			t.Errorf("%s: %d %s, want the listed chart served", p, status, body)
		}
	}

	status, body := pf.get(t, "/v2/bitnamicharts/postgresql/manifests/16.0.0")
	if status != http.StatusForbidden || !strings.Contains(body, `"DENIED"`) ||
		!strings.Contains(body, "membership") || !strings.Contains(body, "helm/docker.io/bitnamicharts/postgresql") {
		t.Errorf("unlisted chart = %d %s, want a 403 DENIED naming helm membership", status, body)
	}
	if n := f.hub.blobHits(pg, "bitnamicharts/postgresql"); n != 0 {
		t.Errorf("the refused chart's blobs were fetched %d times", n)
	}
}

// An image from the registry a chart is served from is still judged as oci:
// an oci entry hides it, a helm entry on the same name does not reach it, and
// its discovery row is recorded under oci.
func TestOCIImageBesideAChartStaysOCI(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	f.hub.publishChart("bitnamicharts/redis", "20.0.0")
	if rec := doRequest(s, http.MethodGet, "/v2/bitnamicharts/redis/manifests/20.0.0", nil); rec.Code != http.StatusOK {
		t.Fatalf("chart: %d %s", rec.Code, rec.Body.String())
	}

	addVersion(t, s, manifest.TypeHelm, "docker.io/library/nginx", manifest.VersionEntry{Version: "1.27", Mode: manifest.ModeProxy, Hidden: true})
	if rec := doRequest(s, http.MethodGet, "/v2/library/nginx/manifests/1.27", nil); rec.Code != http.StatusOK {
		t.Fatalf("image under a helm hide on its name: %d %s, want it served as oci", rec.Code, rec.Body.String())
	}
	waitForDiscoveryRow(t, s, manifest.TypeOCI, "docker.io/library/nginx", "1.27")
	for _, n := range discoveryNames(t, s, manifest.TypeHelm) {
		if n == "docker.io/library/nginx" {
			t.Errorf("the image left a discovery row under helm")
		}
	}

	addVersion(t, s, manifest.TypeOCI, "docker.io/example-corp/web", manifest.VersionEntry{Version: "2.0", Mode: manifest.ModeProxy, Hidden: true})
	rec := doRequest(s, http.MethodGet, "/v2/example-corp/web/manifests/2.0", nil)
	assertOCIError(t, rec, http.StatusNotFound, "MANIFEST_UNKNOWN", "docker.io/example-corp/web")
	refusalIncident(t, rec.Header(), checkHidden)
}

// A tag that moved between an image and a chart since bodega cached it is
// judged again as what the refresh served, in both directions.
func TestOCIHelmMovedTagJudgedAsWhatItNowNames(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	const toChart = "/v2/library/nginx/manifests/1.27"
	if rec := doRequest(s, http.MethodGet, toChart, nil); rec.Code != http.StatusOK {
		t.Fatalf("image: %d %s", rec.Code, rec.Body.String())
	}
	f.hub.publishChart("charts/app", "1.0")
	if rec := doRequest(s, http.MethodGet, "/v2/charts/app/manifests/1.0", nil); rec.Code != http.StatusOK {
		t.Fatalf("chart: %d %s", rec.Code, rec.Body.String())
	}

	c := f.hub.publishChart("library/nginx", "1.27")
	addVersion(t, s, manifest.TypeHelm, "docker.io/library/nginx", manifest.VersionEntry{Version: "1.27", Mode: manifest.ModeProxy, Hidden: true})
	f.hub.publish("charts/app", "1.0", f.image)
	addVersion(t, s, manifest.TypeOCI, "docker.io/charts/app", manifest.VersionEntry{Version: "1.0", Mode: manifest.ModeProxy, Hidden: true})
	s.cache.MetadataTTL = time.Nanosecond

	rec := doRequest(s, http.MethodGet, toChart, nil)
	assertOCIError(t, rec, http.StatusNotFound, "MANIFEST_UNKNOWN", "docker.io/library/nginx")
	if strings.Contains(rec.Body.String(), string(c.manifest)) {
		t.Errorf("the hidden chart's manifest was served")
	}
	rec = doRequest(s, http.MethodGet, "/v2/charts/app/manifests/1.0", nil)
	assertOCIError(t, rec, http.StatusNotFound, "MANIFEST_UNKNOWN", "docker.io/charts/app")
}

// A classification fetch that fails judges the request as oci, and a
// serving fetch that then gets a chart does not serve it under that verdict.
func TestOCIHelmFailedClassificationNeverServesAChartAsOCI(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	c := f.hub.publishChart("charts/app", "2.0.0")
	addVersion(t, s, manifest.TypeHelm, "docker.io/charts/app", manifest.VersionEntry{Version: "2.0.0", Mode: manifest.ModeProxy, Hidden: true})

	byDigest := "/v2/charts/app/manifests/" + c.digest
	f.hub.mu.Lock()
	f.hub.failOnce[byDigest] = true
	f.hub.failOnce["/v2/charts/app/manifests/2.0.0"] = true
	f.hub.mu.Unlock()

	rec := doRequest(s, http.MethodGet, byDigest, nil)
	if rec.Code == http.StatusOK {
		t.Fatalf("a chart fetched after a failed classification was served as oci: %s", rec.Body.String())
	}
	if rec := doRequest(s, http.MethodGet, byDigest, nil); rec.Code != http.StatusNotFound {
		t.Errorf("retry by digest = %d %s, want the helm hide's 404", rec.Code, rec.Body.String())
	}
	rec = doRequest(s, http.MethodGet, "/v2/charts/app/manifests/2.0.0", nil)
	assertOCIError(t, rec, http.StatusNotFound, "MANIFEST_UNKNOWN", "docker.io/charts/app")
	if n := f.hub.blobHits(c, "charts/app"); n != 0 {
		t.Errorf("the hidden chart's blobs were fetched %d times", n)
	}
}

// A chart's config and layer follow the verdict of the chart that names
// them: a hidden version refuses both before either is fetched, and a
// constraint added after a blob was cached refuses the cached copy too.
func TestOCIHelmBlobsFollowTheirChartsVerdict(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	cur := f.hub.publishChart("charts/app", "2.0.0")
	addVersion(t, s, manifest.TypeHelm, "docker.io/charts/app", manifest.VersionEntry{Version: "2.0.0", Mode: manifest.ModeProxy, Hidden: true})

	rec := doRequest(s, http.MethodGet, "/v2/charts/app/manifests/2.0.0", nil)
	assertOCIError(t, rec, http.StatusNotFound, "MANIFEST_UNKNOWN", "docker.io/charts/app")
	for _, d := range []string{cur.configD, cur.layerD} {
		rec := doRequest(s, http.MethodGet, "/v2/charts/app/blobs/"+d, nil)
		assertOCIError(t, rec, http.StatusNotFound, "BLOB_UNKNOWN", "docker.io/charts/app")
	}
	if n := f.hub.blobHits(cur, "charts/app"); n != 0 {
		t.Errorf("the hidden version's blobs were fetched %d times", n)
	}

	old := f.hub.publishChart("charts/other", "1.0.0")
	if rec := doRequest(s, http.MethodGet, "/v2/charts/other/manifests/1.0.0", nil); rec.Code != http.StatusOK {
		t.Fatalf("chart 1.0.0: %d %s", rec.Code, rec.Body.String())
	}
	for _, d := range []string{old.configD, old.layerD} {
		if rec := doRequest(s, http.MethodGet, "/v2/charts/other/blobs/"+d, nil); rec.Code != http.StatusOK {
			t.Fatalf("chart 1.0.0 blob %s: %d %s", d, rec.Code, rec.Body.String())
		}
	}
	addVersion(t, s, manifest.TypeHelm, "docker.io/charts/other", manifest.VersionEntry{Version: "3.0.0", Mode: manifest.ModeProxy, VersionConstraint: manifest.ConstraintExact})
	for _, d := range []string{old.configD, old.layerD} {
		rec := doRequest(s, http.MethodGet, "/v2/charts/other/blobs/"+d, nil)
		if rec.Code != http.StatusForbidden {
			t.Errorf("cached blob of a chart the pin now refuses = %d %s, want 403", rec.Code, rec.Body.String())
		}
		refusalIncident(t, rec.Header(), checkConstraint)
	}
	// Once each to serve them, and the config once more when the tag's
	// checks read it to date the chart.
	if n := f.hub.blobHits(old, "charts/other"); n != 3 {
		t.Errorf("the cached blobs were fetched %d times, want 3", n)
	}
}

// An image in a repository that also holds a chart keeps F70's verdict
// through its blobs: hiding the chart's version does not reach them.
func TestOCIHelmImageBlobsInAChartRepositoryStayOCI(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	c := f.hub.publishChart("library/nginx", "chart-1.0.0")
	addVersion(t, s, manifest.TypeHelm, "docker.io/library/nginx", manifest.VersionEntry{Version: "chart-1.0.0", Mode: manifest.ModeProxy, Hidden: true})
	rec := doRequest(s, http.MethodGet, "/v2/library/nginx/manifests/chart-1.0.0", nil)
	assertOCIError(t, rec, http.StatusNotFound, "MANIFEST_UNKNOWN", "docker.io/library/nginx")
	assertOCIError(t, doRequest(s, http.MethodGet, "/v2/library/nginx/blobs/"+c.layerD, nil), http.StatusNotFound, "BLOB_UNKNOWN")

	for _, p := range []string{"/v2/library/nginx/manifests/1.27", "/v2/library/nginx/manifests/" + f.image.amd64Digest,
		"/v2/library/nginx/blobs/" + f.image.amd64ConfigD, "/v2/library/nginx/blobs/" + f.image.amd64LayerD} {
		if rec := doRequest(s, http.MethodGet, p, nil); rec.Code != http.StatusOK {
			t.Errorf("%s: %d %s, want the image served as oci", p, rec.Code, rec.Body.String())
		}
	}
	waitForDiscoveryRow(t, s, manifest.TypeOCI, "docker.io/library/nginx", f.image.amd64LayerD)
}

// A profile entry pinning a chart, with no package entry behind it, admits
// the chart's digest once a tag it admits resolved to it, and still refuses
// a digest no tag resolved.
func TestOCIHelmProfilePinAdmitsTheResolvedDigest(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	c := f.hub.publishChart("charts/app", "1.0.0")
	pf := bindProfile(t, s, "charts", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeHelm, audit.VersionPinned, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{Type: manifest.TypeHelm, Name: "docker.io/charts/app", Constraint: manifest.ConstraintExact, Version: "1.0.0"}})

	if status, body := pf.get(t, "/v2/charts/app/manifests/"+c.digest); status != http.StatusForbidden {
		t.Errorf("unresolved digest = %d %s, want 403", status, body)
	}
	for _, p := range []string{"/v2/charts/app/manifests/1.0.0", "/v2/charts/app/manifests/" + c.digest, "/v2/charts/app/blobs/" + c.layerD} {
		if status, body := pf.get(t, p); status != http.StatusOK {
			t.Errorf("%s: %d %s, want the pinned chart served", p, status, body)
		}
	}
}

// A tag cached as an image that the registry moved to a chart is judged as
// the chart on refresh, and the chart's blobs take its refusal: a hidden
// chart's config and layer are refused, on this process and a fresh one, and
// never fetched.
func TestOCIHelmRefreshedHiddenChartRefusesItsBlobs(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	path := "/v2/library/nginx/manifests/1.27"
	if rec := doRequest(s, http.MethodGet, path, nil); rec.Code != http.StatusOK {
		t.Fatalf("the image: %d %s", rec.Code, rec.Body.String())
	}
	c := f.hub.publishChart("library/nginx", "1.27")
	addVersion(t, s, manifest.TypeHelm, "docker.io/library/nginx", manifest.VersionEntry{Version: "1.27", Mode: manifest.ModeProxy, Hidden: true})
	s.cache.MetadataTTL = time.Nanosecond
	assertOCIError(t, doRequest(s, http.MethodGet, path, nil), http.StatusNotFound, "MANIFEST_UNKNOWN", "docker.io/library/nginx")
	for _, srv := range []*Server{s, ociPeer(t, f, s)} {
		for _, d := range []string{c.configD, c.layerD} {
			assertOCIError(t, doRequest(srv, http.MethodGet, "/v2/library/nginx/blobs/"+d, nil), http.StatusNotFound, "BLOB_UNKNOWN", "docker.io/library/nginx")
		}
	}
	if n := f.hub.blobHits(c, "library/nginx"); n != 0 {
		t.Errorf("the hidden chart's blobs were fetched %d times", n)
	}
}

// A tag that moved from an image to an admitted chart leaves a helm
// discovery row when the refresh serves the chart.
func TestOCIHelmRefreshedChartRecordsHelmDiscovery(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	path := "/v2/library/nginx/manifests/1.27"
	if rec := doRequest(s, http.MethodGet, path, nil); rec.Code != http.StatusOK {
		t.Fatalf("the image: %d %s", rec.Code, rec.Body.String())
	}
	waitForDiscoveryRow(t, s, manifest.TypeOCI, "docker.io/library/nginx", "1.27")
	c := f.hub.publishChart("library/nginx", "1.27")
	s.cache.MetadataTTL = time.Nanosecond
	if rec := doRequest(s, http.MethodGet, path, nil); rec.Code != http.StatusOK || rec.Body.String() != string(c.manifest) {
		t.Fatalf("the refreshed chart: %d %s", rec.Code, rec.Body.String())
	}
	waitForDiscoveryRow(t, s, manifest.TypeHelm, "docker.io/library/nginx", "1.27")
}

// An oci hide is a statement about images: a chart helm admits under the same
// identity is served.
func TestOCIHelmChartServedUnderAnOCIHide(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	c := f.hub.publishChart("charts/app", "1.0.0")
	addVersion(t, s, manifest.TypeOCI, "docker.io/charts/app", manifest.VersionEntry{Version: "1.0.0", Mode: manifest.ModeProxy, Hidden: true})
	rec := doRequest(s, http.MethodGet, "/v2/charts/app/manifests/1.0.0", nil)
	if rec.Code != http.StatusOK || rec.Body.String() != string(c.manifest) {
		t.Fatalf("a chart under an oci hide: %d %s", rec.Code, rec.Body.String())
	}
	waitForDiscoveryRow(t, s, manifest.TypeHelm, "docker.io/charts/app", "1.0.0")
}

// A refused chart in a repository of images takes nothing away from the
// images: the tag list is the same before and after bodega read the chart.
func TestOCIHelmRefusedChartLeavesTheImageTagList(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	list := "/v2/library/nginx/tags/list"
	if rec := doRequest(s, http.MethodGet, list, nil); rec.Code != http.StatusOK {
		t.Fatalf("tag list before any chart: %d %s", rec.Code, rec.Body.String())
	}
	f.hub.publishChart("library/nginx", "chart-1.0")
	addVersion(t, s, manifest.TypeHelm, "docker.io/library/nginx", manifest.VersionEntry{Version: "chart-1.0", Mode: manifest.ModeProxy, Hidden: true})
	assertOCIError(t, doRequest(s, http.MethodGet, "/v2/library/nginx/manifests/chart-1.0", nil), http.StatusNotFound, "MANIFEST_UNKNOWN")
	if rec := doRequest(s, http.MethodGet, list, nil); rec.Code != http.StatusOK {
		t.Errorf("tag list after a refused chart: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doRequest(s, http.MethodGet, "/v2/library/nginx/manifests/1.27", nil); rec.Code != http.StatusOK {
		t.Errorf("the image beside the refused chart: %d %s", rec.Code, rec.Body.String())
	}
}

// Two tags resolving to one chart digest each admit it: a second tag the
// profile does not permit never displaces the one it does.
func TestOCIHelmProfileDigestFollowsAnyPermittedTag(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	c := f.hub.publishChart("charts/app", "1.0.0")
	f.hub.mu.Lock()
	f.hub.manifests["charts/app@stable"] = ociObject{mediaOCIManifest, c.manifest}
	f.hub.mu.Unlock()
	pf := bindProfile(t, s, "charts", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeHelm, audit.VersionPinned, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{Type: manifest.TypeHelm, Name: "docker.io/charts/app", Constraint: manifest.ConstraintExact, Version: "1.0.0"}})
	if status, body := pf.get(t, "/v2/charts/app/manifests/1.0.0"); status != http.StatusOK {
		t.Fatalf("the pinned tag: %d %s", status, body)
	}
	if rec := doRequest(s, http.MethodGet, "/v2/charts/app/manifests/stable", nil); rec.Code != http.StatusOK {
		t.Fatalf("an unprofiled host's stable: %d %s", rec.Code, rec.Body.String())
	}
	for _, p := range []string{"/v2/charts/app/manifests/" + c.digest, "/v2/charts/app/blobs/" + c.layerD} {
		if status, body := pf.get(t, p); status != http.StatusOK {
			t.Errorf("%s after another tag resolved to the chart: %d %s", p, status, body)
		}
	}
}
