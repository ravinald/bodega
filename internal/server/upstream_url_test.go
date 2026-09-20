package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/manifest"
)

// Both defects these tests pin were URL composition against a host that does
// not serve what was asked for, so what is asserted is the *shape* of what
// reached the upstream, not that a fetch succeeded. A fixture cannot notice a
// wrong host on its own — it answers whatever it is asked — so every case here
// records the paths its fixture saw and compares them.

// recordingUpstream is a fixture registry that remembers every path requested
// of it.
type recordingUpstream struct {
	ts     *httptest.Server
	mu     sync.Mutex
	seen   []string
	routes map[string]string
}

// newRecordingUpstream starts the fixture with no routes. They are added after
// it is listening because a PEP 503 index names the host serving it, so the
// body cannot be written until the URL exists.
func newRecordingUpstream(t *testing.T) *recordingUpstream {
	t.Helper()
	u := &recordingUpstream{routes: map[string]string{}}
	u.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.seen = append(u.seen, r.URL.Path)
		body, ok := u.routes[r.URL.Path]
		u.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(u.ts.Close)
	return u
}

func (u *recordingUpstream) route(path, body string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.routes[path] = body
}

func (u *recordingUpstream) paths() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.seen...)
}

func (u *recordingUpstream) sawPath(p string) bool {
	for _, got := range u.paths() {
		if got == p {
			return true
		}
	}
	return false
}

// allowLoopbackUpstreams swaps the SSRF guard for the scheme check alone. The
// real guard rejects loopback, which is the whole point of it, and a fixture
// registry can only run there.
func allowLoopbackUpstreams(t *testing.T) {
	t.Helper()
	saved := upstreamGuard
	upstreamGuard = func(rawURL string) error {
		if strings.HasPrefix(rawURL, "http://127.0.0.1:") || strings.HasPrefix(rawURL, "http://[::1]:") {
			return nil
		}
		return saved(rawURL)
	}
	t.Cleanup(func() { upstreamGuard = saved })
}

// proxyingServer is a discovery server with the cache on, which is what makes
// a miss reach upstream at all.
func proxyingServer(t *testing.T) *Server {
	t.Helper()
	s := newDiscoveryServer(t)
	s.cache = CacheConfig{Enabled: true, MetadataTTL: time.Hour}
	allowLoopbackUpstreams(t)
	return s
}

func getStatusAndBody(t *testing.T, s *Server, path string) (int, string) {
	t.Helper()
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+path, nil)
	if err != nil {
		t.Fatalf("build request for %s: %v", path, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body strings.Builder
	buf := make([]byte, 4096)
	for {
		n, readErr := resp.Body.Read(buf)
		body.Write(buf[:n])
		if readErr != nil {
			break
		}
	}
	return resp.StatusCode, body.String()
}

const (
	testWheel    = "six-1.16.0-py2.py3-none-any.whl"
	testWheelRel = "/files/d9/5a/e7c31adfe0b98ea9b9f6bd4c1ae2f0d3b0e6d8f3a1c2b4d5e6f7a8b9c0d1e2f3/" + testWheel
	wheelBytes   = "PK\x03\x04 wheel bytes"
)

// seedProxyPypi puts one proxy-mode pypi distribution in the store.
func seedProxyPypi(t *testing.T, s *Server, dist, url string) {
	t.Helper()
	pm := &manifest.PackageManifest{
		ConfigVersion: manifest.CurrentConfigVersion,
		Name:          dist,
		Type:          manifest.TypePypi,
		Versions:      []manifest.VersionEntry{{Version: "1.16.0", URL: url, Mode: manifest.ModeProxy}},
	}
	if err := s.store.SavePackage(t.Context(), pm); err != nil {
		t.Fatalf("seed pypi/%s: %v", dist, err)
	}
}

// TestPypiWheelResolvesThroughSimpleIndex pins that a wheel request reads the
// simple index and fetches the href it lists. The fixture serves the artifact
// under a content-hash path no amount of string concatenation from the wheel
// filename could produce, so a handler that composes a URL cannot pass.
func TestPypiWheelResolvesThroughSimpleIndex(t *testing.T) {
	s := proxyingServer(t)
	up := newRecordingUpstream(t)
	up.route("/simple/six/", fmt.Sprintf(
		`<!DOCTYPE html><html><body><a href="%s%s#sha256=deadbeef">%s</a><br/></body></html>`,
		up.ts.URL, testWheelRel, testWheel))
	up.route(testWheelRel, wheelBytes)

	s.cfg.PypiUpstream = up.ts.URL
	seedProxyPypi(t, s, "six", up.ts.URL)

	status, body := getStatusAndBody(t, s, "/pypi/wheels/"+testWheel)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q); upstream saw %v", status, body, up.paths())
	}
	if body != wheelBytes {
		t.Errorf("body = %q, want the fixture's wheel bytes", body)
	}
	if !up.sawPath("/simple/six/") {
		t.Errorf("upstream saw %v, want a read of /simple/six/: the hash path exists nowhere else", up.paths())
	}
	if !up.sawPath(testWheelRel) {
		t.Errorf("upstream saw %v, want a fetch of %s", up.paths(), testWheelRel)
	}
	for _, p := range up.paths() {
		if strings.HasPrefix(p, "/packages/") {
			t.Errorf("upstream saw %s: the wheel URL was composed from the filename, not read from the index", p)
		}
	}
}

// TestPypiWheelNotInIndexIsDiagnosable pins the refusal for a filename the
// index does not list: a 404 naming the index that was consulted, not a 502
// from a URL nobody can check.
func TestPypiWheelNotInIndexIsDiagnosable(t *testing.T) {
	s := proxyingServer(t)
	up := newRecordingUpstream(t)
	// A relative href, which PEP 503 also permits, resolved against the index.
	up.route("/simple/six/", `<!DOCTYPE html><html><body><a href="../../files/aa/six-1.17.0-py2.py3-none-any.whl">six-1.17.0-py2.py3-none-any.whl</a></body></html>`)
	s.cfg.PypiUpstream = up.ts.URL
	seedProxyPypi(t, s, "six", up.ts.URL)

	status, body := getStatusAndBody(t, s, "/pypi/wheels/"+testWheel)
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for a wheel the index does not list (body %q)", status, body)
	}
	if !strings.Contains(body, up.ts.URL+"/simple/six/") {
		t.Errorf("body = %q, want the index URL that was consulted", body)
	}
	if !strings.Contains(body, testWheel) {
		t.Errorf("body = %q, want the filename that was not found", body)
	}
}

// TestCargoDownloadUsesDownloadHost pins that the crate tarball comes from
// cargo_dl_upstream and the sparse index from cargo_upstream. The two are
// separate hosts in the protocol, and pointing both at the index host is what
// made every crate fetch 502.
func TestCargoDownloadUsesDownloadHost(t *testing.T) {
	s := proxyingServer(t)
	index := newRecordingUpstream(t)
	index.route("/se/rd/serde", `{"name":"serde","vers":"1.0.200","deps":[],"cksum":"","features":{},"yanked":false}`+"\n")
	dl := newRecordingUpstream(t)
	dl.route("/crates/serde/1.0.200/download", "crate tarball bytes")
	s.cfg.CargoUpstream = index.ts.URL
	s.cfg.CargoDLUpstream = dl.ts.URL + "/crates"

	if status, body := getStatusAndBody(t, s, "/cargo/se/rd/serde"); status != http.StatusOK {
		t.Fatalf("index status = %d, want 200 (body %q)", status, body)
	}
	status, body := getStatusAndBody(t, s, "/cargo/serde/1.0.200/download")
	if status != http.StatusOK {
		t.Fatalf("download status = %d, want 200 (body %q); index saw %v, dl saw %v",
			status, body, index.paths(), dl.paths())
	}
	if body != "crate tarball bytes" {
		t.Errorf("body = %q, want the fixture's tarball bytes", body)
	}
	if !dl.sawPath("/crates/serde/1.0.200/download") {
		t.Errorf("download host saw %v, want /crates/serde/1.0.200/download", dl.paths())
	}
	for _, p := range index.paths() {
		if strings.HasSuffix(p, "/download") {
			t.Errorf("index host saw %s: the tarball was composed against cargo_upstream, which serves the index and nothing else", p)
		}
	}
}
