package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// The module the fixture upstream publishes. A path with two slashes, so the
// key parse that recovers the name has something to get wrong.
const (
	proxyAuditModule  = "github.com/pkg/errors"
	proxyAuditVersion = "v0.9.1"
)

// gomodUpstreamFixture is a module proxy serving one version of one module:
// the listing, the .info, the .mod and a .zip of n bytes with the length
// declared. Every other path is a 404, which is what the real proxy answers
// for a module it does not publish.
func gomodUpstreamFixture(t *testing.T, zipBytes int) *httptest.Server {
	t.Helper()
	zip := strings.Repeat("Z", zipBytes)
	files := map[string]string{
		"list":                      proxyAuditVersion + "\n",
		proxyAuditVersion + ".info": `{"Version":"` + proxyAuditVersion + `","Time":"2020-01-14T12:00:00Z"}`,
		proxyAuditVersion + ".mod":  "module " + proxyAuditModule + "\n",
		proxyAuditVersion + ".zip":  zip,
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idx := strings.Index(r.URL.Path, "/@v/")
		if idx < 0 {
			http.NotFound(w, r)
			return
		}
		body, ok := files[r.URL.Path[idx+len("/@v/"):]]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(http.StatusOK)
		//nolint:gosec // G705: fixture bytes with an explicit Content-Type; nothing here comes from the request.
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// newProxyAuditServer is a proxying bodega pointed at a fixture upstream, with
// its own spool directory so the per-artifact ceiling can be set low enough to
// refuse without moving real bytes.
//
// discover_mode is left off on purpose. The cache row and the discovery row
// answer different questions, and gating both on one switch is the wiring gap
// this file exists to hold shut.
func newProxyAuditServer(t *testing.T, upstream string, maxArtifactBytes int64) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		LogDir:                dir,
		AuditDB:               filepath.Join(dir, "audit.db"),
		StoragePath:           dir,
		SpoolDir:              filepath.Join(dir, "spool"),
		SpoolMaxArtifactBytes: maxArtifactBytes,
		GomodUpstream:         upstream,
		ProxyCacheEnabled:     true,
		AllowPlaintext:        true,
	}
	s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), storage.NewSingle(storage.NewMemory()),
		"127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { _ = s.auditDB.Close() })
	return s
}

// cacheRows is every audit row of type cache, in the order the query returns.
func cacheRows(t *testing.T, s *Server) []audit.StoredEvent {
	t.Helper()
	rows, err := s.auditDB.Query(context.Background(), audit.Filter{EventType: audit.EventCache})
	if err != nil {
		t.Fatalf("query cache events: %v", err)
	}
	return rows
}

// getProxy issues one request through the full handler chain and returns the
// status and body.
func getProxy(t *testing.T, s *Server, path string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "127.0.0.1:33333"
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// TestProxiedFetchWritesOneCacheRowPerOutcome is B58's first finding: the
// `cache` event type was defined and the only writes to it were the two
// refusals, so a trail with 140 serve_fetch rows carried nothing saying which
// artifacts had come from upstream.
//
// One row per request and no more. A second write on the same fetch is the
// counting error in the other direction: an operator reading the trail to size
// an upstream's egress would double it.
func TestProxiedFetchWritesOneCacheRowPerOutcome(t *testing.T) {
	allowLoopbackUpstream(t)
	up := gomodUpstreamFixture(t, 4096)
	s := newProxyAuditServer(t, up.URL, 0)

	zipPath := "/go/" + proxyAuditModule + "/@v/" + proxyAuditVersion + ".zip"

	code, body := getProxy(t, s, zipPath)
	if code != http.StatusOK {
		t.Fatalf("first GET %s = %d, want 200 (%s)", zipPath, code, body)
	}
	rows := cacheRows(t, s)
	if len(rows) != 1 {
		t.Fatalf("cache rows after the miss = %d, want 1 (%+v)", len(rows), rows)
	}
	miss := rows[0]
	if miss.Status != audit.CacheMiss {
		t.Errorf("miss row status = %q, want %q", miss.Status, audit.CacheMiss)
	}
	// The four things the row has to name for an incident to be answerable
	// from it: which type, which package, which version, which upstream.
	if miss.PkgType != manifest.TypeGomod {
		t.Errorf("miss row pkg_type = %q, want %q", miss.PkgType, manifest.TypeGomod)
	}
	if miss.PkgName != proxyAuditModule {
		t.Errorf("miss row pkg_name = %q, want %q", miss.PkgName, proxyAuditModule)
	}
	if miss.PkgVersion != proxyAuditVersion {
		t.Errorf("miss row pkg_version = %q, want %q", miss.PkgVersion, proxyAuditVersion)
	}
	if !strings.Contains(miss.Details, up.URL) {
		t.Errorf("miss row details = %q, want the upstream %q in it", miss.Details, up.URL)
	}

	// The second request is answered from storage. It gets its own row: a
	// trail that records only misses cannot tell an artifact nobody asked for
	// again from one the cache has been serving all week.
	code, body = getProxy(t, s, zipPath)
	if code != http.StatusOK {
		t.Fatalf("second GET %s = %d, want 200 (%s)", zipPath, code, body)
	}
	rows = cacheRows(t, s)
	if len(rows) != 2 {
		t.Fatalf("cache rows after the hit = %d, want 2 (%+v)", len(rows), rows)
	}
	var hits, misses int
	for _, row := range rows {
		switch row.Status {
		case audit.CacheHit:
			hits++
			if row.PkgName != proxyAuditModule || row.PkgVersion != proxyAuditVersion {
				t.Errorf("hit row names %q/%q, want %q/%q",
					row.PkgName, row.PkgVersion, proxyAuditModule, proxyAuditVersion)
			}
		case audit.CacheMiss:
			misses++
		}
	}
	if hits != 1 || misses != 1 {
		t.Errorf("cache rows = %d hit / %d miss, want 1 and 1 (%+v)", hits, misses, rows)
	}
}

// TestGomodProxiesAModuleNoManifestNames is B58's third finding. npm and cargo
// answered an uncatalogued name upstream and gomod 404'd it, against a README
// that advertises the proxy for all three.
//
// The .zip as well as the listing: `go get` reads list, then .info, .mod and
// .zip, so a listing served alone fails the resolution one step later.
func TestGomodProxiesAModuleNoManifestNames(t *testing.T) {
	allowLoopbackUpstream(t)
	up := gomodUpstreamFixture(t, 4096)
	s := newProxyAuditServer(t, up.URL, 0)

	for _, file := range []string{"list", proxyAuditVersion + ".info", proxyAuditVersion + ".mod", proxyAuditVersion + ".zip"} {
		path := "/go/" + proxyAuditModule + "/@v/" + file
		code, body := getProxy(t, s, path)
		if code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200 (%s)", path, code, body)
		}
		// Served is not cached. The finding was measured by the object landing
		// in storage, because a server that proxies every request and stores
		// nothing answers 200 just as well.
		key := manifest.GomodFileKey(proxyAuditModule, file)
		info, err := s.typeStore(manifest.TypeGomod).Head(t.Context(), key)
		if err != nil {
			t.Fatalf("head %s: %v", key, err)
		}
		if info == nil || !info.Exists {
			t.Errorf("GET %s served 200 but cached nothing at %s", path, key)
		}
	}
}

// TestSpoolRefusalWritesADenialRow is B58's second finding. The refusal itself
// was correct and the reason reached the log; what an operator queries is the
// denial table, and `bodega audit events --type denied` carried no spool row
// at all in the window the bound was firing.
func TestSpoolRefusalWritesADenialRow(t *testing.T) {
	allowLoopbackUpstream(t)
	up := gomodUpstreamFixture(t, 4096)
	// Below the .zip the fixture publishes, and below the listing too, so the
	// refusal is decided on the declared length before a byte is copied.
	s := newProxyAuditServer(t, up.URL, 16)

	zipPath := "/go/" + proxyAuditModule + "/@v/" + proxyAuditVersion + ".zip"
	code, _ := getProxy(t, s, zipPath)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("GET %s = %d, want 503", zipPath, code)
	}

	rows, err := s.auditDB.Query(context.Background(), audit.Filter{EventType: audit.EventDenied})
	if err != nil {
		t.Fatalf("query denied events: %v", err)
	}
	var refusals int
	for _, row := range rows {
		if row.Status == audit.DenialSpoolArtifactTooLarge {
			refusals++
		}
	}
	if refusals != 1 {
		t.Errorf("spool_artifact_too_large rows = %d, want 1 (%+v)", refusals, rows)
	}
	// A refusal is not a fetch, so it must not also claim the artifact came
	// from upstream.
	for _, row := range cacheRows(t, s) {
		if row.Status == audit.CacheMiss {
			t.Errorf("a refused fetch wrote a cache_miss row (%+v)", row)
		}
	}
}

// TestCacheRowIsWrittenForEveryProxiedType holds the fix at proxyOrResolve
// rather than at one handler. The rows were absent on npm and cargo too, on a
// tree where both proxied correctly, so a gomod-shaped fix would leave the
// finding standing for the two types that did work.
func TestCacheRowIsWrittenForEveryProxiedType(t *testing.T) {
	allowLoopbackUpstream(t)
	index := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		//nolint:gosec // G705: fixture bytes with an explicit Content-Type; nothing here comes from the request.
		_, _ = io.WriteString(w, `{"name":"anyhow","vers":"1.0.0","cksum":"x","deps":[],"yanked":false,"features":{}}`+"\n")
	}))
	t.Cleanup(index.Close)

	dir := t.TempDir()
	cfg := &config.Config{
		LogDir:            dir,
		AuditDB:           filepath.Join(dir, "audit.db"),
		StoragePath:       dir,
		SpoolDir:          filepath.Join(dir, "spool"),
		CargoUpstream:     index.URL,
		ProxyCacheEnabled: true,
		AllowPlaintext:    true,
	}
	s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), storage.NewSingle(storage.NewMemory()),
		"127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { _ = s.auditDB.Close() })

	for i := range 2 {
		if code, body := getProxy(t, s, "/cargo/an/yh/anyhow"); code != http.StatusOK {
			t.Fatalf("GET %d of the cargo index = %d, want 200 (%s)", i+1, code, body)
		}
	}
	rows := cacheRows(t, s)
	if len(rows) != 2 {
		t.Fatalf("cargo cache rows = %d, want 2 (%+v)", len(rows), rows)
	}
	for _, row := range rows {
		if row.PkgType != manifest.TypeCargo || row.PkgName != "anyhow" {
			t.Errorf("cargo cache row names %q/%q, want cargo/anyhow", row.PkgType, row.PkgName)
		}
	}
}
