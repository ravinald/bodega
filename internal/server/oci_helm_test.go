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
