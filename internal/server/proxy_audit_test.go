package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/placement"
	"github.com/ravinald/bodega/internal/storage"
)

// The module the fixture upstream publishes. A path with two slashes, so the
// key parse that recovers the name has something to get wrong.
const (
	proxyAuditModule  = "github.com/pkg/errors"
	proxyAuditVersion = "v0.9.1"
)

// gomodFixtureFiles is the one version of one module the proxy fixtures
// publish: the listing, the .info, the .mod and a .zip of n bytes.
func gomodFixtureFiles(zipBytes int) map[string]string {
	return map[string]string{
		"list":                      proxyAuditVersion + "\n",
		proxyAuditVersion + ".info": `{"Version":"` + proxyAuditVersion + `","Time":"2020-01-14T12:00:00Z"}`,
		proxyAuditVersion + ".mod":  "module " + proxyAuditModule + "\n",
		proxyAuditVersion + ".zip":  strings.Repeat("Z", zipBytes),
	}
}

// serveGomodFixture answers one path under @v/ out of files and 404s
// everything else, which is what a real module proxy does for a module it does
// not publish. The length is declared, so the spool decides on it rather than
// on bytes copied.
func serveGomodFixture(w http.ResponseWriter, r *http.Request, files map[string]string) {
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
}

// gomodUpstreamFixture is a module proxy serving gomodFixtureFiles.
func gomodUpstreamFixture(t *testing.T, zipBytes int) *httptest.Server {
	t.Helper()
	files := gomodFixtureFiles(zipBytes)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveGomodFixture(w, r, files)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// outageFixture is gomodUpstreamFixture with a lever. Flipping it mid-test is
// the only way to reach the stale-serve branches: they need an object the
// cache already holds and an upstream that has since stopped answering, and a
// fixture fixed at construction can be one or the other.
type outageFixture struct {
	ts     *httptest.Server
	status atomic.Int32
}

// fail makes every later request answer code. Zero restores the fixture.
func (f *outageFixture) fail(code int32) { f.status.Store(code) }

func gomodOutageFixture(t *testing.T, zipBytes int) *outageFixture {
	t.Helper()
	f := &outageFixture{}
	files := gomodFixtureFiles(zipBytes)
	f.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if code := f.status.Load(); code != 0 {
			http.Error(w, "fixture upstream is down", int(code))
			return
		}
		serveGomodFixture(w, r, files)
	}))
	t.Cleanup(f.ts.Close)
	return f
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

// splitCacheRows counts the two serving outcomes and returns the hit rows, so
// a caller can assert on what the hit says as well as that it happened.
func splitCacheRows(t *testing.T, s *Server) (hits []audit.StoredEvent, misses int) {
	t.Helper()
	for _, row := range cacheRows(t, s) {
		switch row.Status {
		case audit.CacheHit:
			hits = append(hits, row)
		case audit.CacheMiss:
			misses++
		}
	}
	return hits, misses
}

// requireOneHitNaming asserts a single cache_hit whose details credit want and
// nothing else. The negative half is the point: a row naming a host that
// supplied none of those bytes is worse than one admitting it does not know.
func requireOneHitNaming(t *testing.T, s *Server, want string, notWant ...string) audit.StoredEvent {
	t.Helper()
	hits, _ := splitCacheRows(t, s)
	if len(hits) != 1 {
		t.Fatalf("cache_hit rows = %d, want 1 (%+v)", len(hits), cacheRows(t, s))
	}
	if want != "" && !strings.Contains(hits[0].Details, want) {
		t.Errorf("hit row details = %q, want the upstream %q in it", hits[0].Details, want)
	}
	for _, bad := range notWant {
		if strings.Contains(hits[0].Details, bad) {
			t.Errorf("hit row details = %q, credits %q which answered nothing", hits[0].Details, bad)
		}
	}
	return hits[0]
}

// TestStaleServeAfterAnUpstreamFailureWritesACacheHit covers the branch an
// outage runs through. docs/USAGE.md promises a cache_hit when stale bytes
// answer an upstream that could not be reached, and the fail closure served
// them straight out of storage with no cache row at all — so the trail went
// quiet exactly while the cache was carrying the fleet.
func TestStaleServeAfterAnUpstreamFailureWritesACacheHit(t *testing.T) {
	allowLoopbackUpstream(t)
	up := gomodOutageFixture(t, 4096)
	s := newProxyAuditServer(t, up.ts.URL, 0)

	listPath := "/go/" + proxyAuditModule + "/@v/list"
	if code, body := getProxy(t, s, listPath); code != http.StatusOK {
		t.Fatalf("first GET %s = %d, want 200 (%s)", listPath, code, body)
	}

	// The listing is mutable, so the refetch is decided by the TTL rather than
	// by an eviction — which is the shape an operator actually meets.
	s.cache.MetadataTTL = time.Nanosecond
	up.fail(http.StatusServiceUnavailable)

	code, body := getProxy(t, s, listPath)
	if code != http.StatusOK {
		t.Fatalf("stale GET %s = %d, want 200 from the cached copy", listPath, code)
	}
	if body != proxyAuditVersion+"\n" {
		t.Fatalf("stale GET body = %q, want the cached listing", body)
	}

	hits, misses := splitCacheRows(t, s)
	if len(hits) != 1 || misses != 1 {
		t.Fatalf("cache rows = %d hit / %d miss, want 1 and 1 (%+v)", len(hits), misses, cacheRows(t, s))
	}
	requireOneHitNaming(t, s, up.ts.URL)
}

// TestSpoolRefusalOverAStaleObjectWritesBothRows is the same branch under the
// other refusal. The denial row alone leaves a 200 whose bytes came from the
// cache indistinguishable from a request nothing was served for.
func TestSpoolRefusalOverAStaleObjectWritesBothRows(t *testing.T) {
	allowLoopbackUpstream(t)
	up := gomodUpstreamFixture(t, 4096)
	s := newProxyAuditServer(t, up.URL, 0)

	listPath := "/go/" + proxyAuditModule + "/@v/list"
	if code, body := getProxy(t, s, listPath); code != http.StatusOK {
		t.Fatalf("first GET %s = %d, want 200 (%s)", listPath, code, body)
	}

	s.cache.MetadataTTL = time.Nanosecond
	// One byte, so the refusal is decided on the declared length of a listing
	// the cache already holds.
	s.spool = newSpoolLimiter(t.TempDir(), 1, 0)

	code, body := getProxy(t, s, listPath)
	if code != http.StatusOK {
		t.Fatalf("refused refetch GET %s = %d, want 200 from the cached copy", listPath, code)
	}
	if body != proxyAuditVersion+"\n" {
		t.Fatalf("refused refetch body = %q, want the cached listing", body)
	}

	hits, misses := splitCacheRows(t, s)
	if len(hits) != 1 || misses != 1 {
		t.Fatalf("cache rows = %d hit / %d miss, want 1 and 1 (%+v)", len(hits), misses, cacheRows(t, s))
	}
	denials, err := s.auditDB.Query(context.Background(), audit.Filter{EventType: audit.EventDenied})
	if err != nil {
		t.Fatalf("query denied events: %v", err)
	}
	var refusals int
	for _, row := range denials {
		if row.Status == audit.DenialSpoolArtifactTooLarge {
			refusals++
		}
	}
	if refusals != 1 {
		t.Errorf("spool_artifact_too_large rows = %d, want 1 (%+v)", refusals, denials)
	}
}

// TestCacheHitNamesTheUpstreamThatSuppliedTheBytes pins provenance against a
// configuration edit. The hit row used to serialize whatever the caller held
// at the time, so moving gomod_upstream made every later hit on an immutable
// object credit a host that was never contacted for it.
func TestCacheHitNamesTheUpstreamThatSuppliedTheBytes(t *testing.T) {
	allowLoopbackUpstream(t)
	up := gomodUpstreamFixture(t, 4096)
	s := newProxyAuditServer(t, up.URL, 0)

	zipPath := "/go/" + proxyAuditModule + "/@v/" + proxyAuditVersion + ".zip"
	if code, body := getProxy(t, s, zipPath); code != http.StatusOK {
		t.Fatalf("first GET %s = %d, want 200 (%s)", zipPath, code, body)
	}

	const replacement = "https://replacement.invalid"
	s.cfg.GomodUpstream = replacement

	if code, body := getProxy(t, s, zipPath); code != http.StatusOK {
		t.Fatalf("second GET %s = %d, want 200 (%s)", zipPath, code, body)
	}
	requireOneHitNaming(t, s, up.URL, replacement)
}

// TestCacheOriginSurvivesAServerRestart holds the origin in the store rather
// than in memory. A resolved URL kept per process answers the second request
// of a session and nothing after a restart, which is most of the window an
// incident asks about.
func TestCacheOriginSurvivesAServerRestart(t *testing.T) {
	allowLoopbackUpstream(t)
	up := gomodUpstreamFixture(t, 4096)

	dir := t.TempDir()
	manifests := t.TempDir()
	// One object store across both processes: the artifact outlives the
	// server, which is the whole premise of a cache.
	store := storage.NewSingle(storage.NewMemory())
	start := func(upstream string) *Server {
		return newServer(&config.Config{
			LogDir:            dir,
			AuditDB:           filepath.Join(dir, "audit.db"),
			StoragePath:       dir,
			SpoolDir:          filepath.Join(dir, "spool"),
			GomodUpstream:     upstream,
			ProxyCacheEnabled: true,
			AllowPlaintext:    true,
		}, manifest.NewLocalStore(manifests), store, "127.0.0.1:0",
			slog.New(slog.NewTextHandler(io.Discard, nil)))
	}

	zipPath := "/go/" + proxyAuditModule + "/@v/" + proxyAuditVersion + ".zip"
	first := start(up.URL)
	if code, body := getProxy(t, first, zipPath); code != http.StatusOK {
		t.Fatalf("GET %s before the restart = %d, want 200 (%s)", zipPath, code, body)
	}
	if err := first.auditDB.Close(); err != nil {
		t.Fatalf("close the first audit db: %v", err)
	}

	// Restarted onto a different upstream, so the row can be right only if the
	// origin outlived the process that fetched the bytes. The object is
	// immutable and cached, so nothing here contacts the replacement.
	const replacement = "https://elsewhere.invalid"
	second := start(replacement)
	t.Cleanup(func() { _ = second.auditDB.Close() })
	if code, body := getProxy(t, second, zipPath); code != http.StatusOK {
		t.Fatalf("GET %s after the restart = %d, want 200 (%s)", zipPath, code, body)
	}
	requireOneHitNaming(t, second, up.URL, replacement)
}

// TestPypiWheelCacheHitNamesTheResolvedUpstream is the route that holds no URL
// at all on a hit. A wheel's path is the file's content hash, recoverable only
// from the simple index, so the handler passes "" rather than pay for a
// resolution the response will not use — and the hit row carried that "".
func TestPypiWheelCacheHitNamesTheResolvedUpstream(t *testing.T) {
	s := proxyingServer(t)
	up := newRecordingUpstream(t)
	up.route("/simple/six/", fmt.Sprintf(
		`<!DOCTYPE html><html><body><a href="%s%s#sha256=deadbeef">%s</a><br/></body></html>`,
		up.ts.URL, testWheelRel, testWheel))
	up.route(testWheelRel, wheelBytes)

	s.cfg.PypiUpstream = up.ts.URL
	seedProxyPypi(t, s, "six", up.ts.URL)

	if status, body := getStatusAndBody(t, s, "/pypi/wheels/"+testWheel); status != http.StatusOK {
		t.Fatalf("first wheel GET = %d, want 200 (%s); upstream saw %v", status, body, up.paths())
	}
	fetched := len(up.paths())
	if status, body := getStatusAndBody(t, s, "/pypi/wheels/"+testWheel); status != http.StatusOK {
		t.Fatalf("second wheel GET = %d, want 200 (%s)", status, body)
	}
	// Reading the index again would be a network round trip that still could
	// not prove where the cached bytes came from.
	if got := len(up.paths()); got != fetched {
		t.Errorf("the cache hit made %d upstream request(s): %v", got-fetched, up.paths()[fetched:])
	}
	requireOneHitNaming(t, s, up.ts.URL+testWheelRel)
}

// TestHitOnAnObjectWithNoRecordedOriginSaysSo covers every artifact cached
// before origins were kept. Filling the column with the candidate the config
// names today would make a row that reads as evidence and is not.
func TestHitOnAnObjectWithNoRecordedOriginSaysSo(t *testing.T) {
	allowLoopbackUpstream(t)
	up := gomodUpstreamFixture(t, 4096)
	s := newProxyAuditServer(t, up.URL, 0)

	key := manifest.GomodFileKey(proxyAuditModule, proxyAuditVersion+".zip")
	if err := s.typeStore(manifest.TypeGomod).Put(t.Context(), key, []byte("cached by an older bodega")); err != nil {
		t.Fatalf("seed %s: %v", key, err)
	}

	zipPath := "/go/" + proxyAuditModule + "/@v/" + proxyAuditVersion + ".zip"
	if code, body := getProxy(t, s, zipPath); code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200 (%s)", zipPath, code, body)
	}
	hit := requireOneHitNaming(t, s, "", up.URL)
	if !strings.Contains(hit.Details, cacheOriginUnrecorded) {
		t.Errorf("hit row details = %q, want %q where no origin was recorded", hit.Details, cacheOriginUnrecorded)
	}
}

// TestAptPoolCacheHitIsRecordedWithDiscoveryOff is the third of B58's serving
// paths. handleAptMirrorPool answers a cached .deb from storage directly, and
// its only recorder returned on discover_mode being empty — so on a default
// install every mirrored .deb after the first was served with nothing in the
// trail saying so.
func TestAptPoolCacheHitIsRecordedWithDiscoveryOff(t *testing.T) {
	archive := newFixtureArchive(t, map[string]string{fixtureDeb: fixtureDebBody})
	s := mirrorServer(t, archive)
	s.discoverMode = ""

	for i := range 2 {
		code, body := mirrorGet(t, s, "/apt/"+fixtureDeb)
		if code != http.StatusOK {
			t.Fatalf("pool GET %d = %d, want 200", i+1, code)
		}
		if string(body) != fixtureDebBody {
			t.Fatalf("pool GET %d body = %q, want the archive's bytes", i+1, body)
		}
	}
	// One GET for two responses is what makes the second a cache hit rather
	// than a second fetch that happens to match.
	if got := archive.count(fixtureDeb); got != 1 {
		t.Fatalf("upstream GETs = %d, want 1", got)
	}

	hits, misses := splitCacheRows(t, s)
	if len(hits) != 1 || misses != 1 {
		t.Fatalf("cache rows = %d hit / %d miss, want 1 and 1 (%+v)", len(hits), misses, cacheRows(t, s))
	}
	hit := hits[0]
	if hit.PkgType != manifest.TypeApt || hit.PkgName != "nginx" || hit.PkgVersion != "1.24.0-2ubuntu7.1" {
		t.Errorf("hit row names %q/%q/%q, want apt/nginx/1.24.0-2ubuntu7.1",
			hit.PkgType, hit.PkgName, hit.PkgVersion)
	}
	if !strings.Contains(hit.Details, archive.URL()) {
		t.Errorf("hit row details = %q, want the archive %q in it", hit.Details, archive.URL())
	}
}

// TestAptPoolCacheHitWithNoRouteAndSeveralArchives separates the two rows the
// shortcut owes. With no fresh route and more than one archive configured,
// nothing in memory can name an archive for the discovery row without a
// network probe — but the audit row is owed anyway, and it reads the origin
// recorded when the bytes were fetched rather than guessing a candidate.
func TestAptPoolCacheHitWithNoRouteAndSeveralArchives(t *testing.T) {
	archive := newFixtureArchive(t, map[string]string{fixtureDeb: fixtureDebBody})
	other := newFixtureArchive(t, map[string]string{})
	s := mirrorServer(t, archive, other)

	if code, _ := mirrorGet(t, s, "/apt/"+fixtureDeb); code != http.StatusOK {
		t.Fatalf("first pool GET = %d, want 200", code)
	}
	// An empty route is what an expired one decays to: fresh, and naming no
	// archive. aptPoolHitUpstream then has two candidates and no way to pick.
	s.aptRoutes.put(fixtureDeb, "")

	if code, body := mirrorGet(t, s, "/apt/"+fixtureDeb); code != http.StatusOK || string(body) != fixtureDebBody {
		t.Fatalf("second pool GET = %d body %q, want 200 and the archive's bytes", code, body)
	}
	if got := archive.count(fixtureDeb); got != 1 {
		t.Fatalf("upstream GETs = %d, want 1", got)
	}
	requireOneHitNaming(t, s, archive.URL(), other.URL())
}

// TestCacheRowsNameTheServerThatAnsweredARedirect pins provenance through a
// redirect. upstreamClient follows one, so the URL bodega composed and the URL
// that supplied the bytes are two different hosts: recording the first credits
// a redirector for content it never held, and leaves the server that did hold
// it absent from the trail an incident reads.
func TestCacheRowsNameTheServerThatAnsweredARedirect(t *testing.T) {
	allowLoopbackUpstream(t)
	target := gomodUpstreamFixture(t, 4096)

	var hops atomic.Int64
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops.Add(1)
		//nolint:gosec // G710: the destination is this test's own fixture; only the path comes from the request, and that path is what bodega asked for.
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	s := newProxyAuditServer(t, redirector.URL, 0)
	zipPath := "/go/" + proxyAuditModule + "/@v/" + proxyAuditVersion + ".zip"
	for i := range 2 {
		if code, body := getProxy(t, s, zipPath); code != http.StatusOK {
			t.Fatalf("GET %s #%d = %d, want 200 (%s)", zipPath, i+1, code, body)
		}
	}

	// One contact for two requests. The hit reads its origin out of the audit
	// store, and a hit that re-walked the chain to find out who answered would
	// be paying upstream latency for a row.
	if got := hops.Load(); got != 1 {
		t.Errorf("redirector was contacted %d times, want 1 — the hit resolved upstream", got)
	}

	want := target.URL + "/" + proxyAuditModule + "/@v/" + proxyAuditVersion + ".zip"
	hits, misses := splitCacheRows(t, s)
	if misses != 1 || len(hits) != 1 {
		t.Fatalf("cache rows = %d hit / %d miss, want 1 each (%+v)", len(hits), misses, cacheRows(t, s))
	}
	for _, row := range cacheRows(t, s) {
		if !strings.Contains(row.Details, want) {
			t.Errorf("%s row details = %q, want the responding server %q", row.Status, row.Details, want)
		}
		if strings.Contains(row.Details, redirector.URL) {
			t.Errorf("%s row details = %q, credits the redirector, which supplied no bytes", row.Status, row.Details)
		}
	}
}

// TestARedirectOntoABlockedHostIsRefused keeps the SSRF guard on every hop.
// The validated URL is the one bodega composed; an upstream that answers 302
// chooses the next one, and following it unchecked would hand any registry a
// route to the metadata service through bodega's own credentials.
func TestARedirectOntoABlockedHostIsRefused(t *testing.T) {
	// The destination is up and serving, so the guard is the only thing that
	// can stop the fetch reaching it. A target that merely refuses the
	// connection would let this pass with no guard at all.
	blocked := gomodUpstreamFixture(t, 64)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//nolint:gosec // G710: see the fixture in TestCacheRowsNameTheServerThatAnsweredARedirect; the destination is test-owned.
		http.Redirect(w, r, blocked.URL+r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	saved := upstreamGuard
	upstreamGuard = func(rawURL string) error {
		if strings.HasPrefix(rawURL, redirector.URL) {
			return nil
		}
		return fmt.Errorf("upstream URL resolves to a private address: %s", rawURL)
	}
	t.Cleanup(func() { upstreamGuard = saved })

	up, err := openUpstream(t.Context(), redirector.URL+"/"+proxyAuditModule+"/@v/list")
	if err == nil {
		up.body.Close()
		t.Fatalf("openUpstream followed a redirect onto %s, which the guard refuses", blocked.URL)
	}
}

// TestUploadedBytesDoNotInheritTheProxyOrigin is the defect a key-keyed origin
// cannot see: 'bodega pkg upload' writes a locally built artifact over a
// mirrored one at the same key and fetches nothing, so the next hit served the
// new bytes and credited the archive that supplied the old ones. No delete is
// involved, which is why pruning origins for deleted keys does not reach it.
func TestUploadedBytesDoNotInheritTheProxyOrigin(t *testing.T) {
	archive := newFixtureArchive(t, map[string]string{fixtureDeb: fixtureDebBody})
	s := mirrorServer(t, archive)
	debPath := "/apt/" + fixtureDeb
	if code, body := mirrorGet(t, s, debPath); code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200 (%s)", debPath, code, body)
	}

	const replacement = "replacement built locally"
	local := filepath.Join(t.TempDir(), "replacement.deb")
	if err := os.WriteFile(local, []byte(replacement), 0o600); err != nil {
		t.Fatalf("write the replacement artifact: %v", err)
	}
	// The production upload path, not a store write: the point is that a
	// supported command puts these bytes there.
	placer := placement.NewWith(s.stores, s.store, io.Discard, false)
	n, err := placer.UploadPaths(t.Context(), manifest.TypeApt, []builder.ArtifactPath{{
		Local:     local,
		ObjectKey: manifest.AptKey(fixtureDeb),
		Package:   "nginx",
		Version:   "1.24.0-2ubuntu7.1",
	}})
	if err != nil || n != 1 {
		t.Fatalf("UploadPaths wrote %d objects, err = %v", n, err)
	}

	code, body := mirrorGet(t, s, debPath)
	if code != http.StatusOK || string(body) != replacement {
		t.Fatalf("GET %s = %d %q, want 200 %q", debPath, code, body, replacement)
	}
	if got := archive.count(fixtureDeb); got != 1 {
		t.Fatalf("upstream GETs = %d, want 1 — the replacement was refetched", got)
	}
	// The first GET was the miss that filled the cache, so the replacement is
	// the only request the cache answered.
	hit := requireOneHitNaming(t, s, "", archive.URL())
	if !strings.Contains(hit.Details, cacheOriginUnrecorded) {
		t.Errorf("hit row details = %q, want %q for an object no fetch produced", hit.Details, cacheOriginUnrecorded)
	}
}

// pausedPutStore holds the first PutFile open after the bytes have landed,
// which is the window a fill is readable in and unattributed in. Nothing in
// the recorders changes under it: it only pins a scheduling order that the
// race detector cannot produce on demand, because every store and audit call
// on this path is individually synchronized.
type pausedPutStore struct {
	storage.ObjectStore
	written chan struct{}
	resume  chan struct{}
	puts    atomic.Int32
}

func (p *pausedPutStore) PutFile(ctx context.Context, localPath, key string) error {
	err := p.ObjectStore.PutFile(ctx, localPath, key)
	if err == nil && p.puts.Add(1) == 1 {
		close(p.written)
		<-p.resume
	}
	return err
}

// TestAHitDuringAFillNamesTheUpstreamPublishingIt covers the gap between the
// bytes becoming readable and the origin row landing. A second client arriving
// inside it was served the fetched artifact and recorded as unrecorded, which
// reports the one fetch bodega could account for as the one it could not.
func TestAHitDuringAFillNamesTheUpstreamPublishingIt(t *testing.T) {
	allowLoopbackUpstream(t)
	up := gomodUpstreamFixture(t, 4096)
	s := newProxyAuditServer(t, up.URL, 0)
	held := &pausedPutStore{
		ObjectStore: storage.NewMemory(),
		written:     make(chan struct{}),
		resume:      make(chan struct{}),
	}
	s.stores = storage.NewSingle(held)

	zipPath := "/go/" + proxyAuditModule + "/@v/" + proxyAuditVersion + ".zip"
	filled := make(chan int, 1)
	go func() {
		code, _ := getProxy(t, s, zipPath)
		filled <- code
	}()

	select {
	case <-held.written:
	case <-time.After(10 * time.Second):
		t.Fatal("the fill never published its bytes")
	}

	code, body := getProxy(t, s, zipPath)
	close(held.resume)
	if first := <-filled; first != http.StatusOK || code != http.StatusOK || len(body) != 4096 {
		t.Fatalf("responses = %d and %d, body = %d bytes, want 200, 200, 4096", first, code, len(body))
	}
	requireOneHitNaming(t, s, up.URL)
}

// requireHitsUnrecorded asserts that want cache_hit rows exist and that not one
// of them credits an upstream.
//
// Every row rather than the newest: the trail is ordered by a millisecond
// timestamp, so two requests inside one tick have no defined order and a test
// reading "the last row" reads whichever the tie fell to.
func requireHitsUnrecorded(t *testing.T, s *Server, phase string, want int) {
	t.Helper()
	hits, _ := splitCacheRows(t, s)
	if len(hits) != want {
		t.Fatalf("%s: cache_hit rows = %d, want %d (%+v)", phase, len(hits), want, cacheRows(t, s))
	}
	for _, hit := range hits {
		if !strings.Contains(hit.Details, cacheOriginUnrecorded) {
			t.Errorf("%s: hit row details = %q, want %q — the upload inherited the fill's origin",
				phase, hit.Details, cacheOriginUnrecorded)
		}
	}
}

// TestAnUploadDuringAFillIsNotCreditedToIt covers the window the previous
// origin check could not see. A fill's bytes become readable partway through
// the store write, and a locally built artifact landing before that write's
// origin row was identified inherited the archive the fetch was reading — at
// the key, and then permanently, because the row was bound to whatever a Head
// found at the key afterwards.
//
// Both lengths, because the first version told them apart by length: equal
// lengths are what an attribution scheme reading a size cannot distinguish,
// and unequal ones are what it can, so a pass on one says nothing about the
// other.
func TestAnUploadDuringAFillIsNotCreditedToIt(t *testing.T) {
	for _, sameLength := range []bool{true, false} {
		t.Run(fmt.Sprintf("same_length_%v", sameLength), func(t *testing.T) {
			archive := newFixtureArchive(t, map[string]string{fixtureDeb: fixtureDebBody})
			s := mirrorServer(t, archive)
			held := &pausedPutStore{
				ObjectStore: storage.NewLocal(t.TempDir()),
				written:     make(chan struct{}),
				resume:      make(chan struct{}),
			}
			s.stores = storage.NewSingle(held)

			debPath := "/apt/" + fixtureDeb
			filled := make(chan int, 1)
			go func() {
				code, _ := mirrorGet(t, s, debPath)
				filled <- code
			}()
			select {
			case <-held.written:
			case <-time.After(10 * time.Second):
				t.Fatal("the fill never published its bytes")
			}
			released := false
			defer func() {
				if !released {
					close(held.resume)
					<-filled
				}
			}()

			replacement := "replacement built locally"
			if sameLength {
				replacement = strings.Repeat("L", len(fixtureDebBody))
			}
			local := filepath.Join(t.TempDir(), "replacement.deb")
			if err := os.WriteFile(local, []byte(replacement), 0o600); err != nil {
				t.Fatalf("write the replacement artifact: %v", err)
			}
			// The production upload path, holding no lock the proxy holds:
			// coordinating the two would still leave every writer outside this
			// process, which is why the check is on the bytes.
			placer := placement.NewWith(s.stores, s.store, io.Discard, false)
			n, err := placer.UploadPaths(t.Context(), manifest.TypeApt, []builder.ArtifactPath{{
				Local:     local,
				ObjectKey: manifest.AptKey(fixtureDeb),
				Package:   "nginx",
				Version:   "1.24.0-2ubuntu7.1",
			}})
			if err != nil || n != 1 {
				t.Fatalf("UploadPaths wrote %d objects, err = %v", n, err)
			}

			serve := func(phase string, wantHits int) {
				t.Helper()
				code, body := mirrorGet(t, s, debPath)
				if code != http.StatusOK || string(body) != replacement {
					t.Fatalf("%s: GET %s = %d %q, want 200 %q", phase, debPath, code, body, replacement)
				}
				requireHitsUnrecorded(t, s, phase, wantHits)
			}
			serve("during the fill", 1)
			close(held.resume)
			released = true
			if code := <-filled; code != http.StatusOK {
				t.Fatalf("the fill responded %d, want 200", code)
			}
			serve("after the fill", 2)
		})
	}
}

// pausedOpenStore holds one GetStream after the backend has opened the object
// and taken its metadata, which is the window a cache hit streams its body in.
// Pausing at Head instead finishes before this window opens: the open that
// supplies the bytes is a later call.
type pausedOpenStore struct {
	storage.ObjectStore
	armed  atomic.Bool
	opened chan struct{}
	resume chan struct{}
}

func (p *pausedOpenStore) GetStream(ctx context.Context, key string) (*storage.StreamResult, error) {
	res, err := p.ObjectStore.GetStream(ctx, key)
	if err == nil && res != nil && p.armed.CompareAndSwap(true, false) {
		close(p.opened)
		<-p.resume
	}
	return res, err
}

// TestAnUploadAfterTheCacheOpenDoesNotReachTheReader pins the guarantee to the
// bytes rather than to a lock. A hit's origin is taken from the handle that
// serves it, so a backend publishing over the file behind that handle would
// hand the client one artifact under the provenance of another — the length
// and timestamp in the row describing neither.
//
// The upload runs through the production Placer, holding nothing the proxy
// holds, because the writer that matters is a 'pkg upload' in another process.
// An equal-length replacement keeps the response valid against the
// Content-Length already taken, and is the case a size comparison cannot see.
func TestAnUploadAfterTheCacheOpenDoesNotReachTheReader(t *testing.T) {
	archive := newFixtureArchive(t, map[string]string{fixtureDeb: fixtureDebBody})
	s := mirrorServer(t, archive)
	held := &pausedOpenStore{
		ObjectStore: storage.NewLocal(t.TempDir()),
		opened:      make(chan struct{}),
		resume:      make(chan struct{}),
	}
	s.stores = storage.NewSingle(held)

	debPath := "/apt/" + fixtureDeb
	if code, body := mirrorGet(t, s, debPath); code != http.StatusOK || string(body) != fixtureDebBody {
		t.Fatalf("the fill responded %d %q, want 200 and the archive's bytes", code, body)
	}

	replacement := strings.Repeat("L", len(fixtureDebBody))
	local := filepath.Join(t.TempDir(), "replacement.deb")
	if err := os.WriteFile(local, []byte(replacement), 0o600); err != nil {
		t.Fatalf("write the replacement artifact: %v", err)
	}

	held.armed.Store(true)
	type served struct {
		code int
		body string
	}
	answered := make(chan served, 1)
	go func() {
		code, body := mirrorGet(t, s, debPath)
		answered <- served{code, string(body)}
	}()
	select {
	case <-held.opened:
	case <-time.After(10 * time.Second):
		t.Fatal("the cache open never happened")
	}

	placer := placement.NewWith(s.stores, s.store, io.Discard, false)
	n, err := placer.UploadPaths(t.Context(), manifest.TypeApt, []builder.ArtifactPath{{
		Local:     local,
		ObjectKey: manifest.AptKey(fixtureDeb),
		Package:   "nginx",
		Version:   "1.24.0-2ubuntu7.1",
	}})
	close(held.resume)
	got := <-answered
	if err != nil || n != 1 {
		t.Fatalf("UploadPaths wrote %d objects, err = %v", n, err)
	}
	if got.code != http.StatusOK || got.body != fixtureDebBody {
		t.Fatalf("the concurrent hit served %d %q, want 200 %q — the upload reached a reader already on the object",
			got.code, got.body, fixtureDebBody)
	}
	requireOneHitNaming(t, s, archive.URL())

	// The upload is readable from the next open, and credits nobody: no fetch
	// produced it.
	code, body := mirrorGet(t, s, debPath)
	if code != http.StatusOK || string(body) != replacement {
		t.Fatalf("the next hit served %d %q, want 200 %q", code, body, replacement)
	}
	// By content rather than by position: the trail orders on a millisecond
	// timestamp and these two hits land inside one tick, so "the second row"
	// is whichever way the tie fell.
	hits, _ := splitCacheRows(t, s)
	if len(hits) != 2 {
		t.Fatalf("cache_hit rows = %d, want 2 (%+v)", len(hits), cacheRows(t, s))
	}
	var credited, unrecorded int
	for _, hit := range hits {
		switch {
		case strings.Contains(hit.Details, cacheOriginUnrecorded):
			unrecorded++
		case strings.Contains(hit.Details, archive.URL()):
			credited++
		}
	}
	if credited != 1 || unrecorded != 1 {
		t.Errorf("hit rows credit the archive %d times and admit no origin %d times, want 1 and 1 (%+v)",
			credited, unrecorded, hits)
	}
}

// pausedHeadStore holds one Head open after it has read the object's metadata,
// which is the window between deciding a request is a cache hit and opening
// the bytes that answer it.
type pausedHeadStore struct {
	storage.ObjectStore
	armed  atomic.Bool
	read   chan struct{}
	resume chan struct{}
}

func (p *pausedHeadStore) Head(ctx context.Context, key string) (*storage.ObjectInfo, error) {
	info, err := p.ObjectStore.Head(ctx, key)
	if err == nil && p.armed.CompareAndSwap(true, false) {
		close(p.read)
		<-p.resume
	}
	return info, err
}

// TestAReplacementAfterTheCacheReadIsNotCreditedToWhatItDisplaced is the same
// defect on the serving side. The identity came from the Head that decided the
// request was a hit, and the bytes came from a separate open afterwards, so an
// object replaced between the two was served under the previous tenant's
// origin — a row naming a host that supplied none of what the client got.
func TestAReplacementAfterTheCacheReadIsNotCreditedToWhatItDisplaced(t *testing.T) {
	allowLoopbackUpstream(t)
	up := gomodUpstreamFixture(t, 4096)
	s := newProxyAuditServer(t, up.URL, 0)
	held := &pausedHeadStore{
		ObjectStore: storage.NewLocal(t.TempDir()),
		read:        make(chan struct{}),
		resume:      make(chan struct{}),
	}
	s.stores = storage.NewSingle(held)

	zipPath := "/go/" + proxyAuditModule + "/@v/" + proxyAuditVersion + ".zip"
	if code, _ := getProxy(t, s, zipPath); code != http.StatusOK {
		t.Fatalf("the fill responded %d, want 200", code)
	}

	const replacement = "replacement written after the cache read"
	held.armed.Store(true)
	type served struct {
		code int
		body string
	}
	answered := make(chan served, 1)
	go func() {
		code, body := getProxy(t, s, zipPath)
		answered <- served{code, body}
	}()
	select {
	case <-held.read:
	case <-time.After(10 * time.Second):
		t.Fatal("the cache read never happened")
	}
	err := held.Put(t.Context(), manifest.GomodFileKey(proxyAuditModule, proxyAuditVersion+".zip"), []byte(replacement))
	close(held.resume)
	got := <-answered
	if err != nil {
		t.Fatalf("write the replacement object: %v", err)
	}
	if got.code != http.StatusOK || got.body != replacement {
		t.Fatalf("GET %s = %d %q, want 200 %q", zipPath, got.code, got.body, replacement)
	}
	hits, _ := splitCacheRows(t, s)
	if len(hits) != 1 {
		t.Fatalf("cache_hit rows = %d, want 1 (%+v)", len(hits), cacheRows(t, s))
	}
	if !strings.Contains(hits[0].Details, cacheOriginUnrecorded) {
		t.Errorf("hit row details = %q, want %q — the bytes served came from no fetch",
			hits[0].Details, cacheOriginUnrecorded)
	}
}

// TestARedirectLoopStopsAtTheHopBound guards the limit that supplying
// CheckRedirect displaces. net/http applies its own ten-hop bound only while
// the field is nil, so an upstream redirecting to itself spent a request per
// hop and held the client's for the full 90-second client timeout.
func TestARedirectLoopStopsAtTheHopBound(t *testing.T) {
	allowLoopbackUpstream(t)
	var hops atomic.Int32
	loop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops.Add(1)
		http.Redirect(w, r, "/loop", http.StatusFound)
	}))
	t.Cleanup(loop.Close)

	// A deadline well under the client timeout, so a lost bound fails this in
	// under a second instead of running for a minute and a half.
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	up, err := openUpstream(ctx, loop.URL+"/loop")
	if up != nil {
		up.body.Close()
	}
	if err == nil {
		t.Fatal("openUpstream followed a redirect loop to completion")
	}
	if got := int(hops.Load()); got > maxUpstreamRedirects {
		t.Errorf("upstream requests = %d, want at most %d — the hop bound is gone", got, maxUpstreamRedirects)
	}
	if !strings.Contains(err.Error(), "stopped after") {
		t.Errorf("openUpstream error = %v, want the redirect bound rather than a timeout", err)
	}
}
