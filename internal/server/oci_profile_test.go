package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// ociSingleManifest is an image manifest with a config no other test image
// shares, so its digest is its own.
func ociSingleManifest(label string) []byte {
	cfg := []byte(`{"architecture":"amd64","os":"linux","label":"` + label + `"}`)
	m, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": mediaOCIManifest,
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": ociDigest(cfg), "size": len(cfg)},
		"layers": []any{},
	})
	return m
}

// publishTag serves a single manifest at repo under tag and by its digest.
func (g *ociRegistry) publishTag(repo, tag string, body []byte) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	d := ociDigest(body)
	g.manifests[repo+"@"+tag] = ociObject{mediaOCIManifest, body}
	g.manifests[repo+"@"+d] = ociObject{mediaOCIManifest, body}
	return d
}

func (g *ociRegistry) setTags(repo, list string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.tagLists[repo] = list
}

func (pf *profileFixture) oci(path string) *httptest.ResponseRecorder {
	return doRequest(pf.s, http.MethodGet, path, map[string]string{"Authorization": "Bearer " + pf.token})
}

func ociTagsOf(t *testing.T, rec *httptest.ResponseRecorder) []string {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("tags/list: %d %s", rec.Code, rec.Body.String())
	}
	var l ociTagList
	if err := json.Unmarshal(rec.Body.Bytes(), &l); err != nil {
		t.Fatalf("tags/list does not parse: %v\n%s", err, rec.Body.String())
	}
	return l.Tags
}

// A namespace-wide entry admits every repository of its namespace and none of
// another, and an entry naming one repository of it sets that repository's
// own tag rule.
func TestOCIProfileNamespaceWideEntry(t *testing.T) {
	f := newOCIFixture(t)
	f.ghcr.publish("acme-labs/widget", "v4.1", f.image)
	f.ghcr.publishTag("acme-labs/widget", "v4.2", ociSingleManifest("widget 4.2"))
	f.ghcr.publish("acme-labs/widget-worker", "3.0", f.image)
	s := ociServer(t, f)
	pf := bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeOCI, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{
			{Type: manifest.TypeOCI, Name: "ghcr.io/acme-labs/*"},
			{Type: manifest.TypeOCI, Name: "ghcr.io/acme-labs/widget", Constraint: manifest.ConstraintExact, Version: "v4.1"},
		})

	for _, p := range []string{
		"/v2/ghcr.io/acme-labs/widget-worker/manifests/3.0",
		"/v2/acme-labs/widget/manifests/v4.1?ns=ghcr.io",
	} {
		if rec := pf.oci(p); rec.Code != http.StatusOK || rec.Body.String() != string(f.image.index) {
			t.Errorf("%s under the namespace-wide entry: %d %s", p, rec.Code, rec.Body.String())
		}
	}

	before := f.ghcr.total()
	assertOCIError(t, pf.oci("/v2/ghcr.io/example-corp/api/manifests/v1"), http.StatusForbidden, "DENIED",
		`profile "web"`, "bodega profile add web oci ghcr.io/example-corp/api")
	assertOCIError(t, pf.oci("/v2/ghcr.io/acme-labs/widget/manifests/v4.2"), http.StatusForbidden, "DENIED",
		`profile "web"`, "pinned to v4.1")
	if n := f.ghcr.total() - before; n != 0 {
		t.Errorf("the refused requests reached the registry %d times", n)
	}
}

// A tag pin admits its own tag and no other, and a digest is judged by the
// tags bodega resolved to it: refused before any permitted tag named it,
// served after, and still served once another host pulls the same digest
// under a tag this profile refuses.
func TestOCIProfileTagPinAndDigests(t *testing.T) {
	f := newOCIFixture(t)
	f.hub.publish("library/postgres", "17", f.image)
	f.hub.publish("library/postgres", "latest", f.image)
	newer := f.hub.publishTag("library/postgres", "17.2", ociSingleManifest("postgres 17.2"))
	s := ociServer(t, f)
	pf := bindProfile(t, s, "db", "db01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeOCI, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{
			{Type: manifest.TypeOCI, Name: "docker.io/library/postgres", Constraint: manifest.ConstraintExact, Version: "17"},
		})
	im := f.image

	assertOCIError(t, pf.oci("/v2/library/postgres/manifests/"+im.indexDigest), http.StatusForbidden, "DENIED",
		`profile "db"`, "pinned to 17", "by a tag the profile permits first")

	if rec := pf.oci("/v2/library/postgres/manifests/17"); rec.Code != http.StatusOK || rec.Body.String() != string(im.index) {
		t.Fatalf("the pinned tag: %d %s", rec.Code, rec.Body.String())
	}
	assertOCIError(t, pf.oci("/v2/library/postgres/manifests/17.2"), http.StatusForbidden, "DENIED", `profile "db"`, "pinned to 17")

	for _, d := range []string{im.indexDigest, im.amd64Digest} {
		if rec := pf.oci("/v2/library/postgres/manifests/" + d); rec.Code != http.StatusOK {
			t.Errorf("digest %s, resolved by the pinned tag: %d %s", d, rec.Code, rec.Body.String())
		}
	}
	assertOCIError(t, pf.oci("/v2/library/postgres/manifests/"+newer), http.StatusForbidden, "DENIED", `profile "db"`)

	// An unprofiled host resolving latest to the same index puts latest first
	// in the digest's record; the pinned host is still judged by 17.
	if rec := doRequest(s, http.MethodGet, "/v2/library/postgres/manifests/latest", nil); rec.Code != http.StatusOK {
		t.Fatalf("unprofiled latest: %d %s", rec.Code, rec.Body.String())
	}
	key := manifest.OCIResolvedKey("docker.io", "library/postgres", im.indexDigest)
	if got := storedObject(t, s, manifest.TypeOCI, key); got != "latest\n17" {
		t.Errorf("the digest's record = %q, want latest then 17", got)
	}
	if rec := pf.oci("/v2/library/postgres/manifests/" + im.indexDigest); rec.Code != http.StatusOK {
		t.Errorf("the pinned host was refused its digest after another host pulled it as latest: %d %s", rec.Code, rec.Body.String())
	}
}

// A blob is judged by the repository it is requested under alone, so a layer
// an admitted repository cached is refused under one the profile excludes.
func TestOCIProfileRefusesABlobOutsideIt(t *testing.T) {
	f := newOCIFixture(t)
	f.hub.publish("library/redis", "7", f.image)
	s := ociServer(t, f)
	pf := bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeOCI, audit.VersionPinned, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{Type: manifest.TypeOCI, Name: "docker.io/library/nginx", Version: "1.27"}})

	if rec := pf.oci("/v2/library/nginx/blobs/" + f.image.amd64LayerD); rec.Code != http.StatusOK {
		t.Fatalf("a blob of the listed repository: %d %s", rec.Code, rec.Body.String())
	}
	assertOCIError(t, pf.oci("/v2/library/redis/blobs/"+f.image.amd64LayerD), http.StatusForbidden, "DENIED",
		`profile "web"`, "bodega profile add web oci docker.io/library/redis")
}

// tags/list carries only the tags the profile permits, filtered per request
// from the registry's list as it is cached, and a repository the profile
// excludes does not exist to the host.
func TestOCIProfileFiltersTheTagList(t *testing.T) {
	f := newOCIFixture(t)
	f.hub.publish("library/postgres", "17", f.image)
	f.hub.setTags("library/postgres", `{"name":"library/postgres","tags":["17","17.2","latest"]}`)
	s := ociServer(t, f)
	pf := bindProfile(t, s, "db", "db01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeOCI, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{
			{Type: manifest.TypeOCI, Name: "docker.io/library/postgres", Constraint: manifest.ConstraintExact, Version: "17"},
		})

	rec := pf.oci("/v2/library/postgres/tags/list")
	if got := ociTagsOf(t, rec); !reflect.DeepEqual(got, []string{"17"}) {
		t.Errorf("filtered tags = %v, want [17]", got)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != cacheNoStore {
		t.Errorf("filtered tags/list Cache-Control = %q, want %q", cc, cacheNoStore)
	}
	var stored ociTagList
	if err := json.Unmarshal([]byte(storedObject(t, s, manifest.TypeOCI, manifest.OCITagListKey("docker.io", "library/postgres"))), &stored); err != nil {
		t.Fatalf("the cached tag list does not parse: %v", err)
	}
	if want := []string{"17", "17.2", "latest"}; !reflect.DeepEqual(stored.Tags, want) {
		t.Errorf("the cache holds %v, want the registry's %v", stored.Tags, want)
	}
	if got := ociTagsOf(t, doRequest(s, http.MethodGet, "/v2/library/postgres/tags/list", nil)); len(got) != 3 {
		t.Errorf("an unprofiled host was served the filtered list %v", got)
	}

	assertOCIError(t, pf.oci("/v2/library/nginx/tags/list"), http.StatusNotFound, "NAME_UNKNOWN", `profile "db"`)
}
