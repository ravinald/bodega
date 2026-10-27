package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// ociTokenHost is a token service: it issues a fresh token per request and
// records the Basic credential each request carried.
type ociTokenHost struct {
	ts        *httptest.Server
	mu        sync.Mutex
	hits      int
	basic     []string
	issued    map[string]bool
	expiresIn int
}

func newOCITokenHost(t *testing.T) *ociTokenHost {
	t.Helper()
	h := &ociTokenHost{issued: map[string]bool{}, expiresIn: 300}
	h.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.hits++
		if u, p, ok := r.BasicAuth(); ok {
			h.basic = append(h.basic, u+":"+p)
		}
		tok := fmt.Sprintf("tok-%d-%s", h.hits, r.URL.Query().Get("scope"))
		h.issued[tok] = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"token": tok, "expires_in": h.expiresIn})
	}))
	t.Cleanup(h.ts.Close)
	return h
}

func (h *ociTokenHost) valid(tok string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.issued[tok]
}

func (h *ociTokenHost) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hits
}

type ociObject struct {
	mediaType string
	body      []byte
}

// ociRegistry answers every request without a token it issued with a Bearer
// challenge naming the token host, and serves manifests by tag or digest,
// blobs by digest and a tag list per repository.
type ociRegistry struct {
	ts        *httptest.Server
	tokens    *ociTokenHost
	mu        sync.Mutex
	hits      map[string]int
	manifests map[string]ociObject // <repo>@<tag or digest>
	blobs     map[string][]byte
	tagLists  map[string]string
	tamper    map[string][]byte // path > body served in place of the real one
	sawBasic  bool
	hang      chan struct{}
	resume    chan struct{}
}

func newOCIRegistry(t *testing.T, tokens *ociTokenHost) *ociRegistry {
	t.Helper()
	g := &ociRegistry{tokens: tokens, hits: map[string]int{}, manifests: map[string]ociObject{},
		blobs: map[string][]byte{}, tagLists: map[string]string{}, tamper: map[string][]byte{},
		hang: make(chan struct{}), resume: make(chan struct{})}
	g.ts = httptest.NewServer(http.HandlerFunc(g.serve))
	t.Cleanup(func() {
		g.stopAnswering()
		g.endOutage()
		g.ts.Close()
	})
	return g
}

func (g *ociRegistry) serve(w http.ResponseWriter, r *http.Request) {
	select {
	case <-g.hang:
		select {
		case <-g.resume:
			http.Error(w, "outage", http.StatusServiceUnavailable)
		case <-r.Context().Done():
		}
		return
	default:
	}
	name, kind, ref, _ := splitOCIPath(strings.TrimPrefix(r.URL.Path, "/v2/"))
	auth := r.Header.Get("Authorization")
	g.mu.Lock()
	if strings.HasPrefix(auth, "Basic ") {
		g.sawBasic = true
	}
	g.mu.Unlock()
	if !g.tokens.valid(strings.TrimPrefix(auth, "Bearer ")) {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="registry.test",scope="repository:%s:pull"`, g.tokens.ts.URL, name))
		http.Error(w, `{"errors":[{"code":"UNAUTHORIZED"}]}`, http.StatusUnauthorized)
		return
	}
	g.mu.Lock()
	g.hits[r.URL.Path]++
	tampered, isTampered := g.tamper[r.URL.Path]
	var obj ociObject
	var ok bool
	switch kind {
	case ociManifests:
		obj, ok = g.manifests[name+"@"+ref]
	case ociBlobs:
		var b []byte
		b, ok = g.blobs[ref]
		obj = ociObject{mediaType: "application/octet-stream", body: b}
	case ociTags:
		var l string
		l, ok = g.tagLists[name]
		obj = ociObject{mediaType: "application/json", body: []byte(l)}
	}
	g.mu.Unlock()
	if !ok {
		http.Error(w, `{"errors":[{"code":"MANIFEST_UNKNOWN"}]}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", obj.mediaType)
	if kind == ociManifests {
		w.Header().Set(ociDigestHeader, ociDigest(obj.body))
	}
	if isTampered {
		obj.body = tampered
	}
	_, _ = w.Write(obj.body)
}

func (g *ociRegistry) hitsFor(path string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.hits[path]
}

func (g *ociRegistry) total() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for _, v := range g.hits {
		n += v
	}
	return n
}

func (g *ociRegistry) stopAnswering() {
	select {
	case <-g.hang:
	default:
		close(g.hang)
	}
}

func (g *ociRegistry) endOutage() {
	select {
	case <-g.resume:
	default:
		close(g.resume)
	}
}

// ociImage is a multi-arch image: an index naming an amd64 and an arm64
// manifest, each with a config blob and one layer.
type ociImage struct {
	index, amd64, arm64          []byte
	indexDigest, amd64Digest     string
	arm64Digest                  string
	amd64Config, amd64Layer      []byte
	amd64ConfigD, amd64LayerD    string
	stray                        []byte // a manifest no tag names
	strayDigest                  string
	arm64LayerD, arm64ConfigD    string
	arm64Layer, arm64ConfigBytes []byte
}

func newOCIImage() ociImage {
	var im ociImage
	platformManifest := func(arch string) (m, cfg, layer []byte) {
		cfg = []byte(`{"architecture":"` + arch + `","os":"linux"}`)
		layer = []byte("layer bytes for " + arch + " 0123456789")
		m, _ = json.Marshal(map[string]any{
			"schemaVersion": 2, "mediaType": mediaOCIManifest,
			"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": ociDigest(cfg), "size": len(cfg)},
			"layers": []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": ociDigest(layer), "size": len(layer)}},
		})
		return m, cfg, layer
	}
	im.amd64, im.amd64Config, im.amd64Layer = platformManifest("amd64")
	im.arm64, im.arm64ConfigBytes, im.arm64Layer = platformManifest("arm64")
	im.amd64Digest, im.arm64Digest = ociDigest(im.amd64), ociDigest(im.arm64)
	im.amd64ConfigD, im.amd64LayerD = ociDigest(im.amd64Config), ociDigest(im.amd64Layer)
	im.arm64ConfigD, im.arm64LayerD = ociDigest(im.arm64ConfigBytes), ociDigest(im.arm64Layer)
	im.index, _ = json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": mediaOCIIndex,
		"manifests": []any{
			map[string]any{"mediaType": mediaOCIManifest, "digest": im.amd64Digest, "size": len(im.amd64), "platform": map[string]string{"architecture": "amd64", "os": "linux"}},
			map[string]any{"mediaType": mediaOCIManifest, "digest": im.arm64Digest, "size": len(im.arm64), "platform": map[string]string{"architecture": "arm64", "os": "linux"}},
		},
	})
	im.indexDigest = ociDigest(im.index)
	im.stray, _ = json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": mediaDockerManifest, "config": map[string]any{}, "layers": []any{}})
	im.strayDigest = ociDigest(im.stray)
	return im
}

// publish serves the image at repo under tag.
func (g *ociRegistry) publish(repo, tag string, im ociImage) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.manifests[repo+"@"+tag] = ociObject{mediaOCIIndex, im.index}
	g.manifests[repo+"@"+im.indexDigest] = ociObject{mediaOCIIndex, im.index}
	g.manifests[repo+"@"+im.amd64Digest] = ociObject{mediaOCIManifest, im.amd64}
	g.manifests[repo+"@"+im.arm64Digest] = ociObject{mediaOCIManifest, im.arm64}
	g.manifests[repo+"@"+im.strayDigest] = ociObject{mediaDockerManifest, im.stray}
	for _, b := range [][]byte{im.amd64Config, im.amd64Layer, im.arm64ConfigBytes, im.arm64Layer} {
		g.blobs[ociDigest(b)] = b
	}
	g.tagLists[repo] = `{"name":"` + repo + `","tags":["` + tag + `"]}`
}

type ociFixture struct {
	tokens          *ociTokenHost
	hub, ghcr, quay *ociRegistry
	image           ociImage
}

// newOCIFixture stands up one token host and a registry each for docker.io,
// ghcr.io and quay.io, so a test can tell which registry a request reached.
func newOCIFixture(t *testing.T) *ociFixture {
	t.Helper()
	f := &ociFixture{tokens: newOCITokenHost(t), image: newOCIImage()}
	f.hub, f.ghcr, f.quay = newOCIRegistry(t, f.tokens), newOCIRegistry(t, f.tokens), newOCIRegistry(t, f.tokens)
	f.hub.publish("library/nginx", "1.27", f.image)
	f.hub.publish("example-corp/web", "2.0", f.image)
	f.ghcr.publish("example-corp/api", "v1", f.image)
	f.quay.publish("example-corp/tool", "v3", f.image)
	return f
}

// ociServer proxies the three registries. The token host shares the
// registries' address and differs in port, so it is on oci_token_hosts as
// auth.docker.io is by default.
func ociServer(t *testing.T, f *ociFixture) *Server {
	t.Helper()
	s := proxyingServer(t)
	s.cfg.OCIUpstreams = map[string]string{"docker.io": f.hub.ts.URL, "ghcr.io": f.ghcr.ts.URL, "quay.io": f.quay.ts.URL}
	s.cfg.OCITokenHosts = []string{"127.0.0.1"}
	return s
}

// assertOCIError holds a response to the spec's error body: status, code,
// and a message that is bodega's sentence rather than a bare status.
func assertOCIError(t *testing.T, rec *httptest.ResponseRecorder, status int, code string, wantInMessage ...string) string {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status %d, want %d: %s", rec.Code, status, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("error Content-Type %q, want application/json", ct)
	}
	var body struct {
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || len(body.Errors) != 1 {
		t.Fatalf("body is not the spec's error JSON (%v): %s", err, rec.Body.String())
	}
	e := body.Errors[0]
	if e.Code != code {
		t.Errorf("code %q, want %q (message %q)", e.Code, code, e.Message)
	}
	if e.Message == "" || e.Message == http.StatusText(status) {
		t.Errorf("message %q carries no reason", e.Message)
	}
	for _, want := range wantInMessage {
		if !strings.Contains(e.Message, want) {
			t.Errorf("message does not name %q: %s", want, e.Message)
		}
	}
	if rec.Header().Get(ociAPIVersionHeader) != "registry/2.0" {
		t.Errorf("error carries no %s header", ociAPIVersionHeader)
	}
	return e.Message
}

func TestOCIPing(t *testing.T) {
	s := ociServer(t, newOCIFixture(t))
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		rec := doRequest(s, method, "/v2/", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s /v2/: %d %s", method, rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get(ociAPIVersionHeader); got != "registry/2.0" {
			t.Errorf("%s /v2/: %s = %q", method, ociAPIVersionHeader, got)
		}
		if method == http.MethodGet && rec.Body.String() != "{}" {
			t.Errorf("GET /v2/ body %q, want {}", rec.Body.String())
		}
	}
}

func TestOCIRegistryResolution(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	for _, tc := range []struct {
		name, path string
		reg        *ociRegistry
		upstream   string
	}{
		{"Docker Engine: no registry named, official image", "/v2/nginx/manifests/1.27", f.hub, "/v2/library/nginx/manifests/1.27"},
		{"Docker Engine: no registry named, two segments", "/v2/example-corp/web/manifests/2.0", f.hub, "/v2/example-corp/web/manifests/2.0"},
		{"containerd: ns parameter", "/v2/example-corp/api/manifests/v1?ns=ghcr.io", f.ghcr, "/v2/example-corp/api/manifests/v1"},
		{"containerd: ns for Docker Hub", "/v2/library/nginx/manifests/1.27?ns=docker.io", f.hub, "/v2/library/nginx/manifests/1.27"},
		{"podman: registry as the first segment", "/v2/quay.io/example-corp/tool/manifests/v3", f.quay, "/v2/example-corp/tool/manifests/v3"},
		{"podman: Docker Hub as the first segment", "/v2/docker.io/nginx/manifests/1.27", f.hub, "/v2/library/nginx/manifests/1.27"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := tc.reg.hitsFor(tc.upstream)
			rec := doRequest(s, http.MethodGet, tc.path, nil)
			if rec.Code != http.StatusOK || rec.Body.String() != string(f.image.index) {
				t.Fatalf("%d %s", rec.Code, rec.Body.String())
			}
			// A fresh tag is a cache hit, so only the first request of a
			// path reaches the registry; what matters is which one it was.
			if tc.reg.hitsFor(tc.upstream) == 0 && before == 0 {
				t.Errorf("%s never reached %s on the registry it names", tc.path, tc.upstream)
			}
		})
	}

	total := func() int { return f.hub.total() + f.ghcr.total() + f.quay.total() + f.tokens.count() }
	before := total()
	for _, p := range []string{
		"/v2/example-corp/api/manifests/v1?ns=registry.example.com",
		"/v2/registry.example.com/example-corp/api/manifests/v1",
		"/v2/registry.example.com/example-corp/api/blobs/" + f.image.amd64LayerD,
	} {
		rec := doRequest(s, http.MethodGet, p, nil)
		assertOCIError(t, rec, http.StatusNotFound, "NAME_UNKNOWN", "registry.example.com", "oci_upstreams")
	}
	if n := total() - before; n != 0 {
		t.Errorf("an unknown registry contacted %d upstream hosts", n)
	}
}

func TestParseOCIPackagePath(t *testing.T) {
	for _, tc := range []struct{ path, ns, name, version string }{
		{"/v2/nginx/manifests/1.27", "", "docker.io/library/nginx", "1.27"},
		{"/v2/example-corp/api/blobs/sha256:ab", "ghcr.io", "ghcr.io/example-corp/api", "sha256:ab"},
		{"/v2/quay.io/example-corp/tool/tags/list", "", "quay.io/example-corp/tool", ""},
	} {
		name, version := parseOCIPackagePath(tc.path, tc.ns)
		if name != tc.name || version != tc.version {
			t.Errorf("parseOCIPackagePath(%q, %q) = %q %q, want %q %q", tc.path, tc.ns, name, version, tc.name, tc.version)
		}
	}
	if typ, name, _ := parsePackagePath("/v2/nginx/manifests/1.27"); typ != manifest.TypeOCI || name != "docker.io/library/nginx" {
		t.Errorf("parsePackagePath = %q %q, want oci docker.io/library/nginx", typ, name)
	}
}

// A multi-arch pull: the index by tag, then one platform's manifest and its
// blobs by digest, each with the type and digest the registry sent.
func TestOCIMultiArchPull(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	im := f.image

	rec := doRequest(s, http.MethodGet, "/v2/library/nginx/manifests/1.27", nil)
	if rec.Code != http.StatusOK || rec.Body.String() != string(im.index) {
		t.Fatalf("index by tag: %d %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != mediaOCIIndex {
		t.Errorf("index Content-Type %q, want %s", ct, mediaOCIIndex)
	}
	if d := rec.Header().Get(ociDigestHeader); d != im.indexDigest {
		t.Errorf("index %s %q, want %s", ociDigestHeader, d, im.indexDigest)
	}

	head := doRequest(s, http.MethodHead, "/v2/library/nginx/manifests/1.27", nil)
	if head.Code != http.StatusOK || head.Header().Get(ociDigestHeader) != im.indexDigest || head.Body.Len() != 0 {
		t.Errorf("HEAD by tag: %d digest %q body %d bytes", head.Code, head.Header().Get(ociDigestHeader), head.Body.Len())
	}

	for i := range 2 {
		rec = doRequest(s, http.MethodGet, "/v2/library/nginx/manifests/"+im.amd64Digest, nil)
		if rec.Code != http.StatusOK || rec.Body.String() != string(im.amd64) {
			t.Fatalf("amd64 manifest by digest, request %d: %d %s", i+1, rec.Code, rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); ct != mediaOCIManifest {
			t.Errorf("request %d: manifest Content-Type %q, want %s", i+1, ct, mediaOCIManifest)
		}
		if d := rec.Header().Get(ociDigestHeader); d != im.amd64Digest {
			t.Errorf("request %d: manifest %s %q", i+1, ociDigestHeader, d)
		}
	}
	if n := f.hub.hitsFor("/v2/library/nginx/manifests/" + im.amd64Digest); n != 1 {
		t.Errorf("registry asked for the manifest by digest %d times, want 1: it is immutable", n)
	}

	for _, b := range []struct {
		digest string
		body   []byte
	}{{im.amd64ConfigD, im.amd64Config}, {im.amd64LayerD, im.amd64Layer}} {
		rec = doRequest(s, http.MethodGet, "/v2/library/nginx/blobs/"+b.digest, nil)
		if rec.Code != http.StatusOK || rec.Body.String() != string(b.body) {
			t.Fatalf("blob %s: %d %s", b.digest, rec.Code, rec.Body.String())
		}
		if d := rec.Header().Get(ociDigestHeader); d != b.digest {
			t.Errorf("blob %s header %q", ociDigestHeader, d)
		}
		if info, _ := s.typeStore(manifest.TypeOCI).Head(t.Context(), manifest.OCIBlobKey(b.digest)); info == nil || !info.Exists {
			t.Errorf("blob %s not stored under %s", b.digest, manifest.OCIBlobKey(b.digest))
		}
	}
}

// A tag is mutable: within metadata_ttl it is answered from the cache, past it
// the registry is asked again, and during an outage B156's stale copy is
// served within stale_grace.
func TestOCITagCachingAndOutage(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	tagPath := "/v2/library/nginx/manifests/1.27"
	for i := range 2 {
		if rec := doRequest(s, http.MethodGet, tagPath, nil); rec.Code != http.StatusOK {
			t.Fatalf("request %d: %d %s", i+1, rec.Code, rec.Body.String())
		}
	}
	if n := f.hub.hitsFor(tagPath); n != 1 {
		t.Errorf("registry asked for a fresh tag %d times over two requests, want 1", n)
	}

	s.cache.MetadataTTL = time.Nanosecond
	if rec := doRequest(s, http.MethodGet, tagPath, nil); rec.Code != http.StatusOK {
		t.Fatalf("stale tag: %d", rec.Code)
	}
	if n := f.hub.hitsFor(tagPath); n != 2 {
		t.Errorf("registry asked for a stale tag %d times in all, want 2", n)
	}

	s.cache.StaleGrace = staleGraceForTest
	f.hub.stopAnswering()
	start := time.Now()
	rec := doRequest(s, http.MethodGet, tagPath, nil)
	elapsed := time.Since(start)
	if rec.Code != http.StatusOK || rec.Body.String() != string(f.image.index) {
		t.Fatalf("during the outage: %d %q, want 200 and the cached manifest", rec.Code, rec.Body.String())
	}
	if rec.Header().Get(ociDigestHeader) != f.image.indexDigest {
		t.Errorf("stale answer %s %q", ociDigestHeader, rec.Header().Get(ociDigestHeader))
	}
	if elapsed > staleGraceForTest+time.Second {
		t.Errorf("stale copy took %s, want within stale_grace (%s) plus 1s", elapsed, staleGraceForTest)
	}
	f.hub.endOutage()
	waitFor(t, refreshIdle(s, manifest.OCITagKey("docker.io", "library/nginx", "1.27")))
}

func TestOCITagListIsProxiedAndMutable(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	s.cache.MetadataTTL = time.Nanosecond
	for i := range 2 {
		rec := doRequest(s, http.MethodGet, "/v2/library/nginx/tags/list", nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"1.27"`) {
			t.Fatalf("request %d: %d %s", i+1, rec.Code, rec.Body.String())
		}
	}
	if n := f.hub.hitsFor("/v2/library/nginx/tags/list"); n != 2 {
		t.Errorf("registry asked for a stale tag list %d times over two requests, want 2", n)
	}
}

// Bytes that do not hash to the digest asked for are a 502 naming both, and
// nothing is stored, for a manifest and for a blob.
func TestOCIDigestMismatchStoresNothing(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	im := f.image
	forged := []byte(`{"schemaVersion":2,"mediaType":"` + mediaOCIManifest + `","layers":[]}`)
	f.hub.tamper["/v2/library/nginx/manifests/"+im.amd64Digest] = forged
	f.hub.tamper["/v2/library/nginx/blobs/"+im.amd64LayerD] = []byte("not the layer")

	for _, tc := range []struct {
		path, want, got, key string
	}{
		{"/v2/library/nginx/manifests/" + im.amd64Digest, im.amd64Digest, ociDigest(forged), manifest.OCIManifestKey("docker.io", "library/nginx", im.amd64Digest)},
		{"/v2/library/nginx/blobs/" + im.amd64LayerD, im.amd64LayerD, ociDigest([]byte("not the layer")), manifest.OCIBlobKey(im.amd64LayerD)},
	} {
		rec := doRequest(s, http.MethodGet, tc.path, nil)
		assertOCIError(t, rec, http.StatusBadGateway, "UNKNOWN", tc.want, tc.got)
		refusalIncident(t, rec.Header(), checkChecksum)
		if info, _ := s.typeStore(manifest.TypeOCI).Head(t.Context(), tc.key); info != nil && info.Exists {
			t.Errorf("%s: forged bytes stored under %s", tc.path, tc.key)
		}
	}
}

// A tag whose bytes disagree with the Docker-Content-Digest the registry sent
// is refused the same way.
func TestOCITagDigestMismatchStoresNothing(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	f.hub.tamper["/v2/library/nginx/manifests/1.27"] = []byte(`{"schemaVersion":2,"manifests":[]}`)
	rec := doRequest(s, http.MethodGet, "/v2/library/nginx/manifests/1.27", nil)
	assertOCIError(t, rec, http.StatusBadGateway, "UNKNOWN", f.image.indexDigest)
	if info, _ := s.typeStore(manifest.TypeOCI).Head(t.Context(), manifest.OCITagKey("docker.io", "library/nginx", "1.27")); info != nil && info.Exists {
		t.Error("a tag whose manifest failed its digest was recorded")
	}
}

// Blobs are content-addressed: the second repository carrying one is served
// the copy the first fetched.
func TestOCIBlobSharedAcrossRepositories(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	d := f.image.amd64LayerD
	for _, p := range []string{"/v2/library/nginx/blobs/" + d, "/v2/example-corp/web/blobs/" + d} {
		rec := doRequest(s, http.MethodGet, p, nil)
		if rec.Code != http.StatusOK || rec.Body.String() != string(f.image.amd64Layer) {
			t.Fatalf("%s: %d %s", p, rec.Code, rec.Body.String())
		}
	}
	got := f.hub.hitsFor("/v2/library/nginx/blobs/"+d) + f.hub.hitsFor("/v2/example-corp/web/blobs/"+d)
	if got != 1 {
		t.Errorf("registry asked for one blob %d times across two repositories, want 1", got)
	}
}

func TestOCIRangeOnACachedBlob(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	p := "/v2/library/nginx/blobs/" + f.image.amd64LayerD
	if rec := doRequest(s, http.MethodGet, p, nil); rec.Code != http.StatusOK {
		t.Fatalf("fill: %d", rec.Code)
	}
	rec := doRequest(s, http.MethodGet, p, map[string]string{"Range": "bytes=6-10"})
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("range: %d %s, want 206", rec.Code, rec.Body.String())
	}
	if want := string(f.image.amd64Layer[6:11]); rec.Body.String() != want {
		t.Errorf("range body %q, want %q", rec.Body.String(), want)
	}
	if got := rec.Header().Get("Content-Range"); got != fmt.Sprintf("bytes 6-10/%d", len(f.image.amd64Layer)) {
		t.Errorf("Content-Range %q", got)
	}
	if rec.Header().Get("Accept-Ranges") != "bytes" {
		t.Errorf("Accept-Ranges %q, want bytes", rec.Header().Get("Accept-Ranges"))
	}
	if n := f.hub.hitsFor(p); n != 1 {
		t.Errorf("registry asked %d times, want 1: the range is served from the cache", n)
	}
}

// The seekable-or-not split: a body with no Seek still serves a range. The
// Content-Type is set first, as serveOCIBlobHit sets it, or ServeContent
// sniffs the head and seeks back.
func TestForwardSeekerServesARange(t *testing.T) {
	body := "0123456789abcdef"
	rs := &forwardSeeker{r: strings.NewReader(body), size: int64(len(body))}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Range", "bytes=10-13")
	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(rec, req, "", time.Time{}, rs)
	if rec.Code != http.StatusPartialContent || rec.Body.String() != "abcd" {
		t.Errorf("forwardSeeker range: %d %q, want 206 abcd", rec.Code, rec.Body.String())
	}
}

func TestOCIOversizeBlobRefused(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	s.spool = newSpoolLimiter(t.TempDir(), 8, 1<<20)
	rec := doRequest(s, http.MethodGet, "/v2/library/nginx/blobs/"+f.image.amd64LayerD, nil)
	assertOCIError(t, rec, http.StatusServiceUnavailable, "UNKNOWN", "spool_max_artifact_bytes")
}

func TestOCITokenAnonymousAndReused(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	im := f.image
	for _, p := range []string{
		"/v2/library/nginx/manifests/1.27",
		"/v2/library/nginx/manifests/" + im.amd64Digest,
		"/v2/library/nginx/blobs/" + im.amd64ConfigD,
		"/v2/library/nginx/blobs/" + im.amd64LayerD,
	} {
		if rec := doRequest(s, http.MethodGet, p, nil); rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", p, rec.Code, rec.Body.String())
		}
	}
	if n := f.tokens.count(); n != 1 {
		t.Errorf("token host asked %d times for one repository within the token's lifetime, want 1", n)
	}
	if len(f.tokens.basic) != 0 {
		t.Errorf("an anonymous upstream sent credentials %v to the token host", f.tokens.basic)
	}
}

func TestOCITokenWithUserinfo(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	s.cfg.OCIUpstreams["docker.io"] = strings.Replace(f.hub.ts.URL, "http://", "http://robot:s3cret@", 1)
	rec := doRequest(s, http.MethodGet, "/v2/library/nginx/manifests/1.27", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if len(f.tokens.basic) != 1 || f.tokens.basic[0] != "robot:s3cret" {
		t.Errorf("token host saw credentials %v, want robot:s3cret once", f.tokens.basic)
	}
	if f.hub.sawBasic {
		t.Error("the credential reached the registry host; it belongs to the token realm alone")
	}
}

// A realm on a host that is neither the registry's own nor listed is refused
// before anything is sent to it.
func TestOCITokenRealmOnAnUnlistedHostRefused(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	s.cfg.OCITokenHosts = []string{"auth.docker.io"}
	rec := doRequest(s, http.MethodGet, "/v2/library/nginx/manifests/1.27", nil)
	assertOCIError(t, rec, http.StatusBadGateway, "UNKNOWN", "127.0.0.1", "oci_token_hosts")
	refusalIncident(t, rec.Header(), checkTokenHost)
	if n := f.tokens.count(); n != 0 {
		t.Errorf("token host contacted %d times though oci_token_hosts does not list it", n)
	}
}

func TestOCIParseBearerChallenge(t *testing.T) {
	p, ok := parseBearerChallenge(`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull,push"`)
	if !ok || p["realm"] != "https://auth.docker.io/token" || p["service"] != "registry.docker.io" || p["scope"] != "repository:library/nginx:pull,push" {
		t.Errorf("parsed %v (ok %v)", p, ok)
	}
	if _, ok := parseBearerChallenge(`Basic realm="x"`); ok {
		t.Error("a Basic challenge parsed as Bearer")
	}
}

func TestOCISchema1Refused(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	f.hub.mu.Lock()
	f.hub.manifests["library/legacy@1.0"] = ociObject{mediaDockerSchema1JW, []byte(`{"schemaVersion":1,"name":"library/legacy","tag":"1.0","fsLayers":[]}`)}
	f.hub.mu.Unlock()
	rec := doRequest(s, http.MethodGet, "/v2/legacy/manifests/1.0", nil)
	assertOCIError(t, rec, http.StatusNotFound, "MANIFEST_UNKNOWN", "schema 1")
	refusalIncident(t, rec.Header(), checkSchema)
}

// Every push method is a 405 from the handler, including the three the admin
// gate would otherwise refuse as mutations from an address outside
// admin_permit_cidr.
func TestOCIPushMethodsUnsupported(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	for _, method := range []string{http.MethodPut, http.MethodPost, http.MethodPatch, http.MethodDelete} {
		req := httptest.NewRequest(method, "/v2/library/nginx/manifests/1.27", strings.NewReader("{}"))
		req.RemoteAddr = "203.0.113.7:4444"
		rec := httptest.NewRecorder()
		s.handler().ServeHTTP(rec, req)
		assertOCIError(t, rec, http.StatusMethodNotAllowed, "UNSUPPORTED", "pull-only")
	}
	if n := f.hub.total(); n != 0 {
		t.Errorf("a push method reached the registry %d times", n)
	}
}

func TestOCIAllowListRefusal(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	if err := s.auditDB.SetAdmissionMode(t.Context(), audit.AdmissionMode{Ecosystem: manifest.TypeOCI, Mode: audit.ModeListed}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		"/v2/library/nginx/manifests/1.27",
		"/v2/library/nginx/manifests/" + f.image.amd64Digest,
		"/v2/library/nginx/blobs/" + f.image.amd64LayerD,
		"/v2/library/nginx/tags/list",
	} {
		rec := doRequest(s, http.MethodGet, p, nil)
		assertOCIError(t, rec, http.StatusForbidden, "DENIED", "bodega policy add oci docker.io/library/nginx")
		refusalIncident(t, rec.Header(), checkAllowList)
	}
	if n := f.hub.total(); n != 0 {
		t.Errorf("registry contacted %d times for a repository the allow-list refused", n)
	}

	if err := s.auditDB.InsertPolicy(t.Context(), audit.PolicyInfo{ID: "o1", RegistryType: manifest.TypeOCI, RuleKind: policy.KindPackage, Pattern: "docker.io/library/*"}); err != nil {
		t.Fatal(err)
	}
	s.policy.Invalidate()
	if rec := doRequest(s, http.MethodGet, "/v2/library/nginx/blobs/"+f.image.amd64LayerD, nil); rec.Code != http.StatusOK {
		t.Fatalf("after docker.io/library/*: %d %s", rec.Code, rec.Body.String())
	}
	// The blob is now cached, and another repository the rule does not
	// cover is still refused it.
	rec := doRequest(s, http.MethodGet, "/v2/example-corp/web/blobs/"+f.image.amd64LayerD, nil)
	assertOCIError(t, rec, http.StatusForbidden, "DENIED", "docker.io/example-corp/web")
}

func TestOCIRefusedWhenHidden(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	addVersion(t, s, manifest.TypeOCI, "docker.io/library/nginx", manifest.VersionEntry{Version: "1.27", Mode: manifest.ModeProxy, Hidden: true})
	rec := doRequest(s, http.MethodGet, "/v2/library/nginx/manifests/1.27", nil)
	assertOCIError(t, rec, http.StatusNotFound, "MANIFEST_UNKNOWN", "docker.io/library/nginx")
	refusalIncident(t, rec.Header(), checkHidden)

	// Every version hidden is the package hidden, which refuses its blobs.
	addVersion(t, s, manifest.TypeOCI, "docker.io/example-corp/web", manifest.VersionEntry{Version: "2.0", Mode: manifest.ModeProxy, Hidden: true})
	rec = doRequest(s, http.MethodGet, "/v2/example-corp/web/blobs/"+f.image.amd64LayerD, nil)
	assertOCIError(t, rec, http.StatusNotFound, "BLOB_UNKNOWN", "docker.io/example-corp/web")
	if n := f.hub.total(); n != 0 {
		t.Errorf("registry contacted %d times for hidden content", n)
	}
}

// A version constraint judges a tag, a digest by the tag that resolved it
// (an index's platform manifests included), and refuses a digest no tag
// resolved.
func TestOCIRefusedByAVersionConstraint(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	im := f.image
	f.hub.publish("library/nginx", "1.28", im)
	addVersion(t, s, manifest.TypeOCI, "docker.io/library/nginx", manifest.VersionEntry{
		Version: "1.27", Mode: manifest.ModeProxy, VersionConstraint: manifest.ConstraintExact,
	})

	rec := doRequest(s, http.MethodGet, "/v2/library/nginx/manifests/1.28", nil)
	assertOCIError(t, rec, http.StatusForbidden, "DENIED", "1.28")
	refusalIncident(t, rec.Header(), checkConstraint)

	rec = doRequest(s, http.MethodGet, "/v2/library/nginx/manifests/"+im.strayDigest, nil)
	assertOCIError(t, rec, http.StatusForbidden, "DENIED", "no tag it resolved")
	refusalIncident(t, rec.Header(), checkConstraint)
	if n := f.hub.total(); n != 0 {
		t.Errorf("registry contacted %d times for refused versions", n)
	}

	for _, p := range []string{"/v2/library/nginx/manifests/1.27", "/v2/library/nginx/manifests/" + im.arm64Digest} {
		if rec := doRequest(s, http.MethodGet, p, nil); rec.Code != http.StatusOK {
			t.Errorf("%s: %d %s, want 200 under the pin", p, rec.Code, rec.Body.String())
		}
	}
}

// A manifest request leaves a discovery row under the package identity at
// the tag, and a blob request one under the repository it was asked for.
func TestOCIDiscoveryRows(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	for _, p := range []string{"/v2/library/nginx/manifests/1.27", "/v2/example-corp/web/blobs/" + f.image.amd64LayerD} {
		if rec := doRequest(s, http.MethodGet, p, nil); rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", p, rec.Code)
		}
	}
	want := map[string]string{"docker.io/library/nginx": "1.27", "docker.io/example-corp/web": f.image.amd64LayerD}
	deadline := time.Now().Add(3 * time.Second)
	for {
		rows, err := s.auditDB.ListDiscovery(t.Context(), audit.DiscoveryFilter{RegistryType: manifest.TypeOCI})
		if err != nil {
			t.Fatal(err)
		}
		found := 0
		for _, r := range rows {
			if v, ok := want[r.PkgName]; ok && r.PkgVersion == v {
				found++
				if r.PatternHint != r.PkgName {
					t.Errorf("pattern_hint %q, want the package identity %q", r.PatternHint, r.PkgName)
				}
			}
		}
		if found == len(want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("discovery rows %+v, want %v", rows, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestOCIMalformedPathsAnswerTheSpecError(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	for _, tc := range []struct{ path, code string }{
		{"/v2/library/nginx/blobs/latest", "DIGEST_INVALID"},
		{"/v2/Library/Nginx/manifests/1.27", "NAME_INVALID"},
		{"/v2/library/nginx/manifests/.bad", "MANIFEST_UNKNOWN"},
		{"/v2/library/nginx/uploads/x", "NAME_UNKNOWN"},
	} {
		rec := doRequest(s, http.MethodGet, tc.path, nil)
		var body ociErrors
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || len(body.Errors) != 1 || body.Errors[0].Code != tc.code {
			t.Errorf("%s: %d %s, want the %s error", tc.path, rec.Code, rec.Body.String(), tc.code)
		}
	}
	if n := f.hub.total(); n != 0 {
		t.Errorf("malformed paths reached the registry %d times", n)
	}
}

// A Docker manifest need not repeat its media type in its body, so the type
// a digest is served under has to come from what the registry said when it
// was fetched: on the fill, on every cache hit, after a tag fetched it, and
// on a server that never saw the fetch.
func TestOCIDigestManifestKeepsUpstreamMediaType(t *testing.T) {
	f := newOCIFixture(t)
	s := ociServer(t, f)
	manifestBody := []byte(`{"schemaVersion":2,"config":{},"layers":[]}`)
	listBody := []byte(`{"schemaVersion":2,"manifests":[]}`)
	byTag := []byte(`{"schemaVersion":2,"config":{"size":1},"layers":[]}`)
	f.hub.mu.Lock()
	f.hub.manifests["library/nginx@"+ociDigest(manifestBody)] = ociObject{mediaDockerManifest, manifestBody}
	f.hub.manifests["library/nginx@"+ociDigest(listBody)] = ociObject{mediaDockerList, listBody}
	f.hub.manifests["library/nginx@docker-tag"] = ociObject{mediaDockerManifest, byTag}
	f.hub.manifests["library/nginx@"+ociDigest(byTag)] = ociObject{mediaDockerManifest, byTag}
	f.hub.mu.Unlock()

	check := func(s *Server, method, digest, want string) {
		t.Helper()
		rec := doRequest(s, method, "/v2/nginx/manifests/"+digest, nil)
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != want || rec.Header().Get(ociDigestHeader) != digest {
			t.Fatalf("%s %s: %d Content-Type %q digest %q, want %q", method, digest, rec.Code, rec.Header().Get("Content-Type"), rec.Header().Get(ociDigestHeader), want)
		}
	}
	for _, c := range []struct {
		body []byte
		want string
	}{{manifestBody, mediaDockerManifest}, {listBody, mediaDockerList}} {
		d := ociDigest(c.body)
		check(s, http.MethodGet, d, c.want)
		check(s, http.MethodHead, d, c.want)
		check(s, http.MethodGet, d, c.want)
		if n := f.hub.hitsFor("/v2/library/nginx/manifests/" + d); n != 1 {
			t.Errorf("%s fetched %d times, want 1", d, n)
		}
	}

	if rec := doRequest(s, http.MethodGet, "/v2/nginx/manifests/docker-tag", nil); rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != mediaDockerManifest {
		t.Fatalf("by tag: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	check(s, http.MethodGet, ociDigest(byTag), mediaDockerManifest)
	if n := f.hub.hitsFor("/v2/library/nginx/manifests/" + ociDigest(byTag)); n != 0 {
		t.Errorf("a manifest the tag stored was fetched again by digest %d times", n)
	}

	// A server sharing only the storage stands in for a restart; the
	// registry dropping the manifests proves the answer came from storage.
	restarted := ociServer(t, f)
	restarted.stores = s.stores
	f.hub.mu.Lock()
	for _, b := range [][]byte{manifestBody, listBody, byTag} {
		delete(f.hub.manifests, "library/nginx@"+ociDigest(b))
	}
	f.hub.mu.Unlock()
	check(restarted, http.MethodGet, ociDigest(manifestBody), mediaDockerManifest)
	check(restarted, http.MethodHead, ociDigest(listBody), mediaDockerList)
	check(restarted, http.MethodGet, ociDigest(byTag), mediaDockerManifest)
}

// A schema 1 manifest is told by its body when the registry names it with a
// generic type or none, by digest as by tag, and nothing of it is stored.
func TestOCISchema1RefusedByDigest(t *testing.T) {
	for _, ct := range []string{"application/json", ""} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			t.Run(method+" "+ct, func(t *testing.T) {
				f := newOCIFixture(t)
				s := ociServer(t, f)
				body := []byte(`{"schemaVersion":1,"name":"library/nginx","fsLayers":[]}`)
				d := ociDigest(body)
				f.hub.mu.Lock()
				f.hub.manifests["library/nginx@"+d] = ociObject{ct, body}
				f.hub.mu.Unlock()
				rec := doRequest(s, method, "/v2/nginx/manifests/"+d, nil)
				if method == http.MethodGet {
					assertOCIError(t, rec, http.StatusNotFound, "MANIFEST_UNKNOWN", "schema 1")
				} else if rec.Code != http.StatusNotFound || rec.Body.Len() != 0 {
					t.Fatalf("HEAD: %d %q, want a bodiless 404", rec.Code, rec.Body.String())
				}
				store := s.typeStore(manifest.TypeOCI)
				for _, key := range []string{manifest.OCIManifestKey("docker.io", "library/nginx", d), manifest.OCIManifestTypeKey("docker.io", "library/nginx", d)} {
					if info, err := store.Head(t.Context(), key); err != nil || info.Exists {
						t.Errorf("%s stored after a schema 1 refusal (%v)", key, err)
					}
				}
			})
		}
	}
}

// A refusal written by middleware before the request reaches the /v2/
// handler still carries the spec's error body and bodega's reason: the deny
// list and a token whose scopes do not reach oci.
func TestOCIRefusalsOutsideTheHandler(t *testing.T) {
	denied := newACLServer(t, &config.Config{DenyList: []string{"127.0.0.1/32"}})
	for _, p := range []string{"/v2/", "/v2/nginx/manifests/1.27", "/v2/nginx/blobs/sha256:" + strings.Repeat("a", 64)} {
		rec := doRequest(denied, http.MethodGet, p, nil)
		assertOCIError(t, rec, http.StatusForbidden, "DENIED", "deny list", "127.0.0.1/32")
		if rec := doRequest(denied, http.MethodHead, p, nil); rec.Code != http.StatusForbidden || rec.Body.Len() != 0 {
			t.Errorf("HEAD %s: %d %q", p, rec.Code, rec.Body.String())
		}
	}

	//nolint:gosec // G101: a test fixture, not a credential.
	const npmOnly = "bodega_ak_npm_only"
	s := newInventoryServer(t, []string{"127.0.0.1/32"})
	if err := s.auditDB.InsertScopedToken(t.Context(), "npm-only", "npm-only", audit.HashToken(npmOnly, invPepper), "", "read:npm", "test-operator", nil); err != nil {
		t.Fatal(err)
	}
	rec := send(s, http.MethodGet, "/v2/nginx/tags/list", localAddr, npmOnly, "")
	assertOCIError(t, rec, http.StatusForbidden, "DENIED", "npm-only", "read:oci")
}

// pagingRegistry serves one repository's tag list in pages of two, unasked,
// as a registry with a server-side page size does.
func pagingRegistry(t *testing.T, tags []string, link func(last string) string) (*httptest.Server, func() int) {
	t.Helper()
	var mu sync.Mutex
	hits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		rest := tags
		if last := r.URL.Query().Get("last"); last != "" {
			for i, tag := range tags {
				if tag == last {
					rest = tags[i+1:]
				}
			}
		}
		if len(rest) > 2 {
			rest = rest[:2]
			w.Header().Set("Link", link(rest[1]))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "library/nginx", "tags": rest})
	}))
	t.Cleanup(ts.Close)
	return ts, func() int {
		mu.Lock()
		defer mu.Unlock()
		return hits
	}
}

func tagListOf(t *testing.T, rec *httptest.ResponseRecorder) []string {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("tags/list: %d %s", rec.Code, rec.Body.String())
	}
	var l ociTagList
	if err := json.Unmarshal(rec.Body.Bytes(), &l); err != nil {
		t.Fatalf("tags/list body: %v: %s", err, rec.Body.String())
	}
	return l.Tags
}

// bodega reads every page a registry offers into one cached list and pages
// it again for a client that asks, with next links that name bodega and keep
// the registry the client chose.
func TestOCITagListPagination(t *testing.T) {
	up, hits := pagingRegistry(t, []string{"a", "b", "c", "d", "e"}, func(last string) string {
		return `</v2/library/nginx/tags/list?last=` + last + `&n=2>; rel="next"`
	})
	s := ociServer(t, newOCIFixture(t))
	s.cfg.OCIUpstreams["docker.io"] = up.URL
	s.cfg.OCIUpstreams["ghcr.io"] = up.URL

	rec := doRequest(s, http.MethodGet, "/v2/nginx/tags/list", nil)
	if got := strings.Join(tagListOf(t, rec), ","); got != "a,b,c,d,e" || rec.Header().Get("Link") != "" {
		t.Fatalf("whole list %q Link %q, want every page and no link", got, rec.Header().Get("Link"))
	}
	if n := hits(); n != 3 {
		t.Errorf("registry asked %d times for three pages", n)
	}

	next := "/v2/nginx/tags/list?n=2"
	var pages []string
	for next != "" && len(pages) < 5 {
		rec := doRequest(s, http.MethodGet, next, nil)
		pages = append(pages, strings.Join(tagListOf(t, rec), ","))
		next = ""
		if l := rec.Header().Get("Link"); l != "" {
			target, _, _ := strings.Cut(l, ">")
			next = strings.TrimPrefix(target, "<")
			if !strings.HasPrefix(next, "/v2/nginx/tags/list?") || !strings.HasSuffix(l, `; rel="next"`) {
				t.Fatalf("next link %q does not name bodega's route", l)
			}
		}
	}
	if got := strings.Join(pages, " | "); got != "a,b | c,d | e" {
		t.Errorf("pages %q, want a,b | c,d | e", got)
	}
	if n := hits(); n != 3 {
		t.Errorf("paging a cached list asked the registry again: %d requests", n)
	}

	rec = doRequest(s, http.MethodGet, "/v2/acme/app/tags/list?ns=ghcr.io&n=1&last=b", nil)
	if got := strings.Join(tagListOf(t, rec), ","); got != "c" || !strings.Contains(rec.Header().Get("Link"), "ns=ghcr.io") {
		t.Errorf("ns page %q Link %q, want c and a link keeping ns=ghcr.io", got, rec.Header().Get("Link"))
	}
	if got := tagListOf(t, doRequest(s, http.MethodGet, "/v2/nginx/tags/list?n=0", nil)); len(got) != 0 {
		t.Errorf("n=0 listed %q", got)
	}
	if got := strings.Join(tagListOf(t, doRequest(s, http.MethodGet, "/v2/nginx/tags/list?last=c", nil)), ","); got != "d,e" {
		t.Errorf("last=c listed %q, want d,e", got)
	}
	assertOCIError(t, doRequest(s, http.MethodGet, "/v2/nginx/tags/list?n=many", nil), http.StatusBadRequest, "PAGINATION_NUMBER_INVALID", "n=")
}

// A next link is followed only on the registry's own host, since the
// registry's token rides on every request, and a list whose next link never
// moves is refused rather than read forever.
func TestOCITagListRefusesLinksItCannotFollow(t *testing.T) {
	var foreignHits atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { foreignHits.Add(1) }))
	t.Cleanup(foreign.Close)
	for name, link := range map[string]func(string) string{
		"foreign host": func(last string) string {
			return `<` + foreign.URL + `/v2/library/nginx/tags/list?last=` + last + `>; rel="next"`
		},
		"no progress": func(string) string { return `</v2/library/nginx/tags/list>; rel="next"` },
	} {
		t.Run(name, func(t *testing.T) {
			up, _ := pagingRegistry(t, []string{"a", "b", "c"}, link)
			s := ociServer(t, newOCIFixture(t))
			s.cfg.OCIUpstreams["docker.io"] = up.URL
			assertOCIError(t, doRequest(s, http.MethodGet, "/v2/nginx/tags/list", nil), http.StatusBadGateway, "UNKNOWN")
		})
	}
	if n := foreignHits.Load(); n != 0 {
		t.Errorf("a next link on another host was followed %d times", n)
	}
}
