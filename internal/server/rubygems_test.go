package server

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// gemRegistry is a fixture RubyGems registry: a compact index naming two gems,
// one of them with a platform build, their gem and gemspec files, the three
// full index files and the dependency API. It counts every path it is asked
// for, so a test can tell a cache hit from a refetch and a refusal from a
// request that reached it.
type gemRegistry struct {
	ts     *httptest.Server
	mu     sync.Mutex
	hits   map[string]int
	routes map[string]string
	hang   chan struct{} // closed when the registry stops answering
	resume chan struct{} // closed when a hung request may fail with 503
}

const gemVersions = "created_at: 2026-10-01T00:00:00Z\n---\n" +
	"concurrent-ruby 1.3.4 0123456789abcdef0123456789abcdef\n" +
	"nokogiri 1.16.7,1.16.7-x86_64-linux fedcba9876543210fedcba9876543210\n"

func newGemRegistry(t *testing.T) *gemRegistry {
	t.Helper()
	g := &gemRegistry{
		hits:   map[string]int{},
		hang:   make(chan struct{}),
		resume: make(chan struct{}),
		routes: map[string]string{
			"/versions":                                           gemVersions,
			"/info/concurrent-ruby":                               "---\n1.3.4 |checksum:aaaa,ruby:>= 2.3\n",
			"/info/nokogiri":                                      "---\n1.16.7 mini_portile2:~> 2.8.2,racc:~> 1.4|checksum:bbbb\n1.16.7-x86_64-linux racc:~> 1.4|checksum:cccc\n",
			"/gems/concurrent-ruby-1.3.4.gem":                     "\x00concurrent-ruby gem bytes",
			"/gems/nokogiri-1.16.7.gem":                           "\x00nokogiri ruby gem bytes",
			"/gems/nokogiri-1.16.7-x86_64-linux.gem":              "\x00nokogiri x86_64-linux gem bytes",
			"/quick/Marshal.4.8/concurrent-ruby-1.3.4.gemspec.rz": "\x78\x9cgemspec",
			"/specs.4.8.gz":                                       "\x1f\x8bspecs",
			"/latest_specs.4.8.gz":                                "\x1f\x8blatest",
			"/prerelease_specs.4.8.gz":                            "\x1f\x8bprerelease",
			"/api/v1/dependencies":                                "",
		},
	}
	g.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Path
		if r.URL.RawQuery != "" {
			key += "?" + r.URL.RawQuery
		}
		g.mu.Lock()
		g.hits[key]++
		body, ok := g.routes[r.URL.Path]
		if r.URL.Path == "/api/v1/dependencies" && r.URL.Query().Get("gems") != "" {
			body = "deps for " + r.URL.Query().Get("gems")
		}
		g.mu.Unlock()
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
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		//nolint:gosec // G705: a test fixture answering plain text; the only request-derived part is the gem list it echoes.
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(func() {
		g.stopAnswering()
		g.endOutage()
		g.ts.Close()
	})
	return g
}

func (g *gemRegistry) hitsFor(path string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.hits[path]
}

func (g *gemRegistry) total() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for _, v := range g.hits {
		n += v
	}
	return n
}

// endOutage lets every hung request fail, so a background refresh finishes.
func (g *gemRegistry) endOutage() {
	select {
	case <-g.resume:
	default:
		close(g.resume)
	}
}

func (g *gemRegistry) stopAnswering() {
	select {
	case <-g.hang:
	default:
		close(g.hang)
	}
}

// gemServer proxies to g with a metadata TTL short enough that every mutable
// document is stale by its second request, so a refetch is what tells a
// mutable route from an immutable one.
func gemServer(t *testing.T, g *gemRegistry) *Server {
	t.Helper()
	s := proxyingServer(t)
	s.cache.MetadataTTL = time.Nanosecond
	s.cfg.RubygemsUpstream = g.ts.URL
	return s
}

func TestRubygemsRoutesProxyByteForByteInTheirCacheClass(t *testing.T) {
	for _, tc := range []struct {
		path, upstream string
		immutable      bool
	}{
		{"/rubygems/versions", "/versions", false},
		{"/rubygems/info/nokogiri", "/info/nokogiri", false},
		{"/rubygems/gems/concurrent-ruby-1.3.4.gem", "/gems/concurrent-ruby-1.3.4.gem", true},
		{"/rubygems/gems/nokogiri-1.16.7-x86_64-linux.gem", "/gems/nokogiri-1.16.7-x86_64-linux.gem", true},
		{"/rubygems/quick/Marshal.4.8/concurrent-ruby-1.3.4.gemspec.rz", "/quick/Marshal.4.8/concurrent-ruby-1.3.4.gemspec.rz", true},
		{"/rubygems/specs.4.8.gz", "/specs.4.8.gz", false},
		{"/rubygems/latest_specs.4.8.gz", "/latest_specs.4.8.gz", false},
		{"/rubygems/prerelease_specs.4.8.gz", "/prerelease_specs.4.8.gz", false},
		{"/rubygems/api/v1/dependencies?gems=rack,concurrent-ruby", "/api/v1/dependencies?gems=rack,concurrent-ruby", false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			g := newGemRegistry(t)
			s := gemServer(t, g)
			want, _ := strings.CutPrefix(tc.upstream, "/")
			wantBody := g.routes["/"+want]
			if strings.Contains(tc.upstream, "gems=") {
				wantBody = "deps for rack,concurrent-ruby"
			}

			for i := range 2 {
				rec := doRequest(s, http.MethodGet, tc.path, nil)
				if rec.Code != http.StatusOK || rec.Body.String() != wantBody {
					t.Fatalf("request %d: %d %q, want 200 and the upstream's bytes %q", i+1, rec.Code, rec.Body.String(), wantBody)
				}
			}
			wantHits := 2
			if tc.immutable {
				wantHits = 1
			}
			if got := g.hitsFor(tc.upstream); got != wantHits {
				t.Errorf("upstream asked for %s %d times over two requests, want %d (immutable=%v)", tc.upstream, got, wantHits, tc.immutable)
			}
		})
	}
}

// Bundler appends to the versions file it holds: a Range past its copy, with
// If-None-Match on the ETag it was given, and the joined file checked against
// Repr-Digest.
func TestRubygemsCompactIndexAnswersRangeAndValidators(t *testing.T) {
	g := newGemRegistry(t)
	s := gemServer(t, g)
	s.cache.MetadataTTL = time.Hour

	full := doRequest(s, http.MethodGet, "/rubygems/versions", nil)
	if full.Code != http.StatusOK || full.Body.String() != gemVersions {
		t.Fatalf("versions: %d %q", full.Code, full.Body.String())
	}
	sum := sha256.Sum256([]byte(gemVersions))
	if got, want := full.Header().Get("Repr-Digest"), "sha-256=:"+base64.StdEncoding.EncodeToString(sum[:])+":"; got != want {
		t.Errorf("Repr-Digest = %q, want %q", got, want)
	}
	etag := full.Header().Get("ETag")
	if etag == "" {
		t.Fatal("versions carries no ETag, so Bundler cannot ask whether it changed")
	}

	offset := len(gemVersions) - 10
	part := doRequest(s, http.MethodGet, "/rubygems/versions", map[string]string{"Range": "bytes=" + strconv.Itoa(offset) + "-"})
	if part.Code != http.StatusPartialContent || part.Body.String() != gemVersions[offset:] {
		t.Errorf("Range from %d: %d %q, want 206 and the tail %q", offset, part.Code, part.Body.String(), gemVersions[offset:])
	}
	if part.Header().Get("Repr-Digest") != full.Header().Get("Repr-Digest") {
		t.Errorf("a ranged answer's Repr-Digest %q is not the whole document's", part.Header().Get("Repr-Digest"))
	}

	same := doRequest(s, http.MethodGet, "/rubygems/versions", map[string]string{"If-None-Match": etag})
	if same.Code != http.StatusNotModified {
		t.Errorf("If-None-Match on the current ETag: %d, want 304", same.Code)
	}
	if got := g.hitsFor("/versions"); got != 1 {
		t.Errorf("upstream asked for versions %d times, want 1: the ranged and conditional requests are cache hits", got)
	}
}

func TestRubygemsUnknownPathsNotFoundWithoutUpstream(t *testing.T) {
	g := newGemRegistry(t)
	s := gemServer(t, g)
	for _, p := range []string{
		"/rubygems/",
		"/rubygems/names",
		"/rubygems/api/v1/gems/rack.json",
		"/rubygems/gems/rack.gem",
		"/rubygems/gems/rack-3.1.8.tgz",
		"/rubygems/info/",
		"/rubygems/info/a/b",
		"/rubygems/quick/Marshal.4.8/rack-3.1.8.gemspec",
		"/rubygems/specs.4.8",
		"/rubygems/latest_specs.4.8.gz/x",
	} {
		if rec := doRequest(s, http.MethodGet, p, nil); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", p, rec.Code)
		}
	}
	if n := g.total(); n != 0 {
		t.Errorf("upstream contacted %d times for paths no client asks for", n)
	}
}

// The discovery row names the gem and the version from the file name, a
// platform build's suffix included, and a name with hyphens stays whole.
func TestRubygemsGemFetchRecordsItsDiscoveryRow(t *testing.T) {
	g := newGemRegistry(t)
	s := gemServer(t, g)
	for _, p := range []string{"/rubygems/gems/nokogiri-1.16.7-x86_64-linux.gem", "/rubygems/gems/concurrent-ruby-1.3.4.gem"} {
		if rec := doRequest(s, http.MethodGet, p, nil); rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", p, rec.Code, rec.Body.String())
		}
	}
	want := map[string]string{"nokogiri": "1.16.7-x86_64-linux", "concurrent-ruby": "1.3.4"}
	deadline := time.Now().Add(3 * time.Second)
	for {
		rows, err := s.auditDB.ListDiscovery(t.Context(), audit.DiscoveryFilter{RegistryType: manifest.TypeRubygems})
		if err != nil {
			t.Fatalf("list discovery: %v", err)
		}
		got := map[string]string{}
		for _, r := range rows {
			got[r.PkgName] = r.PkgVersion
			if r.PatternHint != r.PkgName {
				t.Errorf("row for %s has pattern_hint %q, want the gem name", r.PkgName, r.PatternHint)
			}
		}
		if got["nokogiri"] == want["nokogiri"] && got["concurrent-ruby"] == want["concurrent-ruby"] {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("discovery rows %v, want %v", got, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRubygemsGemRefusedByTheAllowList(t *testing.T) {
	g := newGemRegistry(t)
	s := gemServer(t, g)
	if err := s.auditDB.SetAdmissionMode(t.Context(), audit.AdmissionMode{Ecosystem: manifest.TypeRubygems, Mode: audit.ModeListed}); err != nil {
		t.Fatal(err)
	}
	rec := doRequest(s, http.MethodGet, "/rubygems/gems/concurrent-ruby-1.3.4.gem", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	refusalIncident(t, rec.Header(), checkAllowList)
	if !strings.Contains(rec.Body.String(), "bodega policy add rubygems concurrent-ruby") {
		t.Errorf("refusal does not name the command that admits the gem:\n%s", rec.Body.String())
	}
	if n := g.total(); n != 0 {
		t.Errorf("upstream contacted %d times for a gem the allow-list refused", n)
	}

	if err := s.auditDB.InsertPolicy(t.Context(), audit.PolicyInfo{ID: "r1", RegistryType: manifest.TypeRubygems, RuleKind: policy.KindPackage, Pattern: "concurrent-ruby"}); err != nil {
		t.Fatalf("add rule: %v", err)
	}
	s.policy.Invalidate()
	if rec := doRequest(s, http.MethodGet, "/rubygems/gems/concurrent-ruby-1.3.4.gem", nil); rec.Code != http.StatusOK {
		t.Errorf("after the rule: %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
}

func TestRubygemsGemRefusedWhenHidden(t *testing.T) {
	g := newGemRegistry(t)
	s := gemServer(t, g)
	addVersion(t, s, manifest.TypeRubygems, "nokogiri", manifest.VersionEntry{Version: "1.16.6", Mode: manifest.ModeProxy})
	addVersion(t, s, manifest.TypeRubygems, "nokogiri", manifest.VersionEntry{Version: "1.16.7", Mode: manifest.ModeProxy, Hidden: true})
	addVersion(t, s, manifest.TypeRubygems, "concurrent-ruby", manifest.VersionEntry{Version: "1.3.4", Mode: manifest.ModeProxy})

	// Hiding a release withholds each of its builds.
	for _, p := range []string{"/rubygems/gems/nokogiri-1.16.7.gem", "/rubygems/gems/nokogiri-1.16.7-x86_64-linux.gem"} {
		rec := doRequest(s, http.MethodGet, p, nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d, want the hidden refusal's 404", p, rec.Code)
			continue
		}
		refusalIncident(t, rec.Header(), checkHidden)
	}
	if n := g.total(); n != 0 {
		t.Errorf("upstream contacted %d times for a hidden gem", n)
	}
	if rec := doRequest(s, http.MethodGet, "/rubygems/gems/concurrent-ruby-1.3.4.gem", nil); rec.Code != http.StatusOK {
		t.Errorf("a gem nothing hides: %d, want 200", rec.Code)
	}
}

func TestRubygemsHiddenPackageRefusedOnInfo(t *testing.T) {
	g := newGemRegistry(t)
	s := gemServer(t, g)
	addVersion(t, s, manifest.TypeRubygems, "nokogiri", manifest.VersionEntry{Version: "1.16.7", Mode: manifest.ModeProxy, Hidden: true})
	rec := doRequest(s, http.MethodGet, "/rubygems/info/nokogiri", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("info for a hidden gem: %d, want 404", rec.Code)
	}
	if n := g.hitsFor("/info/nokogiri"); n != 0 {
		t.Errorf("upstream asked for a hidden gem's info %d times", n)
	}
}

// The constraint reads the release a platform build belongs to, so an exact
// pin admits every build of the pinned release and none of another.
func TestRubygemsGemRefusedByAVersionConstraint(t *testing.T) {
	g := newGemRegistry(t)
	s := gemServer(t, g)
	g.routes["/gems/nokogiri-1.16.6-x86_64-linux.gem"] = "\x00nokogiri 1.16.6"
	addVersion(t, s, manifest.TypeRubygems, "nokogiri", manifest.VersionEntry{
		Version: "1.16.6", Mode: manifest.ModeProxy, VersionConstraint: manifest.ConstraintExact,
	})

	rec := doRequest(s, http.MethodGet, "/rubygems/gems/nokogiri-1.16.7-x86_64-linux.gem", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a version outside the constraint: %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	refusalIncident(t, rec.Header(), checkConstraint)
	if n := g.total(); n != 0 {
		t.Errorf("upstream contacted %d times for a version the constraint refused", n)
	}
	if rec := doRequest(s, http.MethodGet, "/rubygems/gems/nokogiri-1.16.6-x86_64-linux.gem", nil); rec.Code != http.StatusOK {
		t.Errorf("a platform build of the pinned release: %d, want 200 (%s)", rec.Code, rec.Body.String())
	}

	// An operator pins a platform build in the form bodega create prompts
	// for, and the pin is still a statement about the release.
	t.Run("pin on a platform build", func(t *testing.T) {
		g := newGemRegistry(t)
		s := gemServer(t, g)
		g.routes["/gems/nokogiri-1.16.7-aarch64-linux.gem"] = "\x00nokogiri 1.16.7 aarch64"
		g.routes["/gems/nokogiri-1.16.6-x86_64-linux.gem"] = "\x00nokogiri 1.16.6"
		addVersion(t, s, manifest.TypeRubygems, "nokogiri", manifest.VersionEntry{
			Version: "1.16.7-x86_64-linux", Mode: manifest.ModeProxy, VersionConstraint: manifest.ConstraintExact,
		})

		for _, file := range []string{"nokogiri-1.16.7-x86_64-linux.gem", "nokogiri-1.16.7-aarch64-linux.gem", "nokogiri-1.16.7.gem"} {
			if rec := doRequest(s, http.MethodGet, "/rubygems/gems/"+file, nil); rec.Code != http.StatusOK {
				t.Errorf("%s under a pin on 1.16.7-x86_64-linux: %d, want 200 (%s)", file, rec.Code, rec.Body.String())
			}
		}
		before := g.total()
		rec := doRequest(s, http.MethodGet, "/rubygems/gems/nokogiri-1.16.6-x86_64-linux.gem", nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("another release's build under the pin: %d, want 403 (%s)", rec.Code, rec.Body.String())
		}
		refusalIncident(t, rec.Header(), checkConstraint)
		if n := g.total() - before; n != 0 {
			t.Errorf("upstream contacted %d times for a version the constraint refused", n)
		}
	})
}

// B156: during an outage a stale info or versions file is served within
// stale_grace rather than after the upstream gives up.
func TestRubygemsStaleCompactIndexServedDuringOutage(t *testing.T) {
	for _, p := range []string{"versions", "info/nokogiri"} {
		t.Run(p, func(t *testing.T) {
			g := newGemRegistry(t)
			s := gemServer(t, g)
			s.cache.StaleGrace = staleGraceForTest
			first := doRequest(s, http.MethodGet, "/rubygems/"+p, nil)
			if first.Code != http.StatusOK {
				t.Fatalf("first request: %d", first.Code)
			}

			g.stopAnswering()
			start := time.Now()
			rec := doRequest(s, http.MethodGet, "/rubygems/"+p, nil)
			elapsed := time.Since(start)
			if rec.Code != http.StatusOK || rec.Body.String() != first.Body.String() {
				t.Fatalf("during the outage: %d %q, want 200 and the cached copy", rec.Code, rec.Body.String())
			}
			if elapsed > staleGraceForTest+time.Second {
				t.Errorf("stale copy took %s, want within stale_grace (%s) plus 1s", elapsed, staleGraceForTest)
			}
			if rec.Header().Get("Repr-Digest") != first.Header().Get("Repr-Digest") {
				t.Errorf("the stale copy's Repr-Digest %q is not the one first served", rec.Header().Get("Repr-Digest"))
			}
			g.endOutage()
			waitFor(t, refreshIdle(s, manifest.RubygemsIndexKey(p)))
		})
	}
}

func TestRubygemsDependenciesRefusesANonGemName(t *testing.T) {
	g := newGemRegistry(t)
	s := gemServer(t, g)
	rec := doRequest(s, http.MethodGet, "/rubygems/api/v1/dependencies?gems=rack,../x", nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400", rec.Code)
	}
	if n := g.total(); n != 0 {
		t.Errorf("upstream contacted %d times", n)
	}
}

// gateGems runs the proxy fill's real admission checks with the rubygems OSV
// gate blocking, answered from a database holding one advisory against
// nokogiri releases before 1.16.8.
func gateGems(t *testing.T, s *Server) {
	t.Helper()
	prev := fetchCheckers
	fetchCheckers = admit.VersionCheckers
	t.Cleanup(func() { fetchCheckers = prev })
	rec := map[string]any{
		"id": "GHSA-test-gem1",
		"affected": []map[string]any{{
			"package": map[string]string{"name": "nokogiri", "ecosystem": "RubyGems"},
			"ranges": []map[string]any{{"type": "ECOSYSTEM",
				"events": []map[string]string{{"introduced": "0"}, {"fixed": "1.16.8"}}}},
		}},
	}
	export := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		f, _ := zw.Create("GHSA-test-gem1.json")
		_ = json.NewEncoder(f).Encode(rec)
		_ = zw.Close()
		_, _ = w.Write(buf.Bytes())
	}))
	t.Cleanup(export.Close)
	s.cfg.OSVDBDir = t.TempDir()
	db := policy.NewOSVDatabase(s.cfg.OSVDBDir)
	db.ExportBase = export.URL
	if _, err := db.Sync(t.Context(), "RubyGems"); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if err := s.auditDB.SetOSVPolicy(t.Context(), audit.OSVPolicy{Ecosystem: manifest.TypeRubygems, Action: policy.ActionBlock}); err != nil {
		t.Fatalf("set osv policy: %v", err)
	}
}

// A vulnerable release is refused at the gem file route before upstream is
// asked for it, whichever platform build is requested, and the refusal names
// the advisory.
func TestRubygemsGemRefusedByOSV(t *testing.T) {
	g := newGemRegistry(t)
	s := gemServer(t, g)
	gateGems(t, s)
	for _, p := range []string{"/gems/nokogiri-1.16.7-x86_64-linux.gem", "/gems/nokogiri-1.16.7.gem", "/quick/Marshal.4.8/nokogiri-1.16.7.gemspec.rz"} {
		rec := doRequest(s, http.MethodGet, "/rubygems"+p, nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: status %d, want 403 (%s)", p, rec.Code, rec.Body.String())
		}
		refusalIncident(t, rec.Header(), checkOSV)
		if !strings.Contains(rec.Body.String(), "GHSA-test-gem1") {
			t.Errorf("%s: refusal does not name the advisory:\n%s", p, rec.Body.String())
		}
		if n := g.hitsFor(p); n != 0 {
			t.Errorf("%s: upstream asked %d times for a refused gem", p, n)
		}
	}
	if rec := doRequest(s, http.MethodGet, "/rubygems/gems/concurrent-ruby-1.3.4.gem", nil); rec.Code != http.StatusOK {
		t.Errorf("a gem no advisory names: %d %s", rec.Code, rec.Body.String())
	}
}

// The age gate dates a gem at rubygems_upstream, the host the gem itself is
// fetched from, and refuses one too new before fetching it.
func TestRubygemsGemRefusedByAge(t *testing.T) {
	g := newGemRegistry(t)
	g.mu.Lock()
	g.routes["/api/v1/versions/concurrent-ruby.json"] = fmt.Sprintf(`[{"number":"1.3.4","platform":"ruby","created_at":%q}]`,
		time.Now().Add(-time.Hour).UTC().Format(time.RFC3339))
	g.mu.Unlock()
	s := gemServer(t, g)
	gateGems(t, s)
	if err := s.auditDB.SetAgePolicy(t.Context(), audit.AgePolicy{Ecosystem: manifest.TypeRubygems, MinAgeSeconds: 86400, Action: policy.ActionBlock}); err != nil {
		t.Fatalf("set age policy: %v", err)
	}
	rec := doRequest(s, http.MethodGet, "/rubygems/gems/concurrent-ruby-1.3.4.gem", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	refusalIncident(t, rec.Header(), checkAge)
	if n := g.hitsFor("/api/v1/versions/concurrent-ruby.json"); n != 1 {
		t.Errorf("versions API read %d times at rubygems_upstream, want 1", n)
	}
	if n := g.hitsFor("/gems/concurrent-ruby-1.3.4.gem"); n != 0 {
		t.Errorf("upstream asked %d times for a gem the age gate refused", n)
	}
}
