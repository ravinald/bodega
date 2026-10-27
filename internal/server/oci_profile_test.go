package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

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

	// An unprofiled host resolving latest to the same index makes latest the
	// allow-list's record of the digest; the pinned host is still judged by 17.
	if rec := doRequest(s, http.MethodGet, "/v2/library/postgres/manifests/latest", nil); rec.Code != http.StatusOK {
		t.Fatalf("unprofiled latest: %d %s", rec.Code, rec.Body.String())
	}
	key := manifest.OCIResolvedKey("docker.io", "library/postgres", im.indexDigest)
	if got := storedObject(t, s, manifest.TypeOCI, key); got != "latest" {
		t.Errorf("the allow-list's record of the digest = %q, want latest", got)
	}
	if got := resolvedByTags(t, s, "library/postgres", im.indexDigest); !reflect.DeepEqual(got, []string{"17", "latest"}) {
		t.Errorf("the digest's tag markers = %v, want [17 latest]", got)
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

// resolvedByTags lists the tags marked as resolving to digest in
// docker.io/<repo>.
func resolvedByTags(t *testing.T, s *Server, repo, digest string) []string {
	t.Helper()
	prefix := manifest.OCIResolvedByPrefix("docker.io", repo, digest)
	keys, err := s.typeStore(manifest.TypeOCI).List(context.Background(), prefix)
	if err != nil {
		t.Fatalf("list %s: %v", prefix, err)
	}
	var tags []string
	for _, k := range keys {
		if tag, ok := manifest.OCIResolvedByTag(prefix, k); ok {
			tags = append(tags, tag)
		}
	}
	return tags
}

// forgetResolvedBy deletes tag's markers on digests, which is the state a
// marker write that failed leaves behind.
func forgetResolvedBy(t *testing.T, s *Server, repo, tag string, digests ...string) {
	t.Helper()
	for _, d := range digests {
		if err := s.typeStore(manifest.TypeOCI).Delete(context.Background(), manifest.OCIResolvedByKey("docker.io", repo, d, tag)); err != nil {
			t.Fatal(err)
		}
	}
}

// A pinned host's digest pulls follow the tag it pulled, whatever else
// happened to the digest: other hosts resolving more aliases of it than any
// bounded record would hold, and a pull of the tag answered from the cache or
// as a stale copy during an outage, each of which records what it served.
func TestOCIProfileDigestFollowsTheTagServed(t *testing.T) {
	f := newOCIFixture(t)
	f.hub.publish("library/postgres", "17", f.image)
	s := ociServer(t, f)
	pf := bindProfile(t, s, "db", "db01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeOCI, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{
			{Type: manifest.TypeOCI, Name: "docker.io/library/postgres", Constraint: manifest.ConstraintExact, Version: "17"},
		})
	im := f.image
	digests := []string{im.indexDigest, im.amd64Digest, im.arm64Digest}
	assertDigestsServed := func(when string) {
		t.Helper()
		for _, d := range digests[:2] {
			if rec := pf.oci("/v2/library/postgres/manifests/" + d); rec.Code != http.StatusOK {
				t.Errorf("digest %s %s: %d %s", d, when, rec.Code, rec.Body.String())
			}
		}
	}

	if rec := pf.oci("/v2/library/postgres/manifests/17"); rec.Code != http.StatusOK {
		t.Fatalf("the pinned tag: %d %s", rec.Code, rec.Body.String())
	}
	for i := range 40 {
		alias := fmt.Sprintf("alias%02d", i)
		f.hub.publish("library/postgres", alias, im)
		if rec := doRequest(s, http.MethodGet, "/v2/library/postgres/manifests/"+alias, nil); rec.Code != http.StatusOK {
			t.Fatalf("unprofiled %s: %d %s", alias, rec.Code, rec.Body.String())
		}
	}
	assertDigestsServed("after 40 other aliases resolved to it")

	const tagPath = "/v2/library/postgres/manifests/17"
	forgetResolvedBy(t, s, "library/postgres", "17", digests...)
	before := f.hub.hitsFor(tagPath)
	if rec := pf.oci(tagPath); rec.Code != http.StatusOK {
		t.Fatalf("the pinned tag from the cache: %d %s", rec.Code, rec.Body.String())
	}
	if n := f.hub.hitsFor(tagPath) - before; n != 0 {
		t.Fatalf("the tag was fetched %d times; this case is a cache hit", n)
	}
	assertDigestsServed("after a cache hit on the pinned tag")

	forgetResolvedBy(t, s, "library/postgres", "17", digests...)
	s.cache.MetadataTTL = time.Nanosecond
	s.cache.StaleGrace = staleGraceForTest
	f.hub.stopAnswering()
	if rec := pf.oci(tagPath); rec.Code != http.StatusOK || rec.Header().Get(ociDigestHeader) != im.indexDigest {
		t.Fatalf("the pinned tag during an outage: %d %s", rec.Code, rec.Body.String())
	}
	f.hub.endOutage()
	waitFor(t, refreshIdle(s, manifest.OCITagKey("docker.io", "library/postgres", "17")))
	s.cache.MetadataTTL = time.Hour
	assertDigestsServed("after a stale answer for the pinned tag")
}

// Tags resolving to one digest at once each keep their own marker: no write
// replaces another, so none of them is lost to a race.
func TestOCIProfileConcurrentResolutionsKeepEveryTag(t *testing.T) {
	f := newOCIFixture(t)
	want := []string{"17"}
	f.hub.publish("library/postgres", "17", f.image)
	for i := range 16 {
		alias := fmt.Sprintf("alias%02d", i)
		f.hub.publish("library/postgres", alias, f.image)
		want = append(want, alias)
	}
	s := ociServer(t, f)
	var wg sync.WaitGroup
	for _, tag := range want {
		wg.Go(func() {
			if rec := doRequest(s, http.MethodGet, "/v2/library/postgres/manifests/"+tag, nil); rec.Code != http.StatusOK {
				t.Errorf("%s: %d %s", tag, rec.Code, rec.Body.String())
			}
		})
	}
	wg.Wait()
	for _, d := range []string{f.image.indexDigest, f.image.amd64Digest} {
		got := resolvedByTags(t, s, "library/postgres", d)
		if len(got) != len(want) {
			t.Errorf("digest %s carries %d tag markers after %d concurrent resolutions: %v", d, len(got), len(want), got)
		}
	}
	pf := bindProfile(t, s, "db", "db01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeOCI, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{
			{Type: manifest.TypeOCI, Name: "docker.io/library/postgres", Constraint: manifest.ConstraintExact, Version: "17"},
		})
	if rec := pf.oci("/v2/library/postgres/manifests/" + f.image.amd64Digest); rec.Code != http.StatusOK {
		t.Errorf("the pinned host's platform digest: %d %s", rec.Code, rec.Body.String())
	}
}

// An exact pin whose value is a digest admits no request by that digest
// before a permitted tag resolved to it, however the entry was stored: the
// digest is never compared against the pin.
func TestOCIProfileDigestPinAdmitsNoUnresolvedDigest(t *testing.T) {
	f := newOCIFixture(t)
	f.hub.publish("library/postgres", "17", f.image)
	s := ociServer(t, f)
	pf := bindProfile(t, s, "db", "db01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeOCI, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{
			{Type: manifest.TypeOCI, Name: "docker.io/library/postgres", Constraint: manifest.ConstraintExact, Version: f.image.indexDigest},
		})
	before := f.hub.total()
	assertOCIError(t, pf.oci("/v2/library/postgres/manifests/"+f.image.indexDigest), http.StatusForbidden, "DENIED",
		`profile "db"`, "without a version to compare", "by a tag the profile permits first")
	if n := f.hub.total() - before; n != 0 {
		t.Errorf("the refused digest reached the registry %d times", n)
	}

	floating := bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeOCI, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{Type: manifest.TypeOCI, Name: "docker.io/library/postgres"}})
	if rec := floating.oci("/v2/library/postgres/manifests/" + f.image.indexDigest); rec.Code != http.StatusOK {
		t.Errorf("a floating entry refused an unresolved digest: %d %s", rec.Code, rec.Body.String())
	}
}
