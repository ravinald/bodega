package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

const (
	consoleRef515 = "0a3bd4fd5bcb6d5b4b9d1b5d9e0e7c9f1f0f8a3c"
	consoleRef514 = "1b4ce5ae6cdc7e6c5c0e2c6e0f1f8d0a2a1a9b4d"
	logRef        = "f16e1d5863e37f8d8c2a01719f5b34baa2b714d3"
	consoleDevRef = "9c0ffee0c0ffee0c0ffee0c0ffee0c0ffee0c0ff"
)

// countingHost is an httptest server answering fixed bodies by path, and
// counting every path it is asked for so a test can tell a cache hit from a
// refetch and a refusal from a request that reached it.
type countingHost struct {
	ts     *httptest.Server
	mu     sync.Mutex
	hits   map[string]int
	routes map[string]string
	hang   chan struct{}
	resume chan struct{}
}

func newCountingHost(t *testing.T, contentType string) *countingHost {
	t.Helper()
	h := &countingHost{hits: map[string]int{}, routes: map[string]string{}, hang: make(chan struct{}), resume: make(chan struct{})}
	h.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.hits[r.URL.Path]++
		body, ok := h.routes[r.URL.Path]
		h.mu.Unlock()
		select {
		case <-h.hang:
			select {
			case <-h.resume:
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
		w.Header().Set("Content-Type", contentType)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(func() {
		h.stopAnswering()
		h.endOutage()
		h.ts.Close()
	})
	return h
}

func (h *countingHost) set(path, body string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.routes[path] = body
}

func (h *countingHost) hitsFor(path string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hits[path]
}

func (h *countingHost) total() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, v := range h.hits {
		n += v
	}
	return n
}

func (h *countingHost) stopAnswering() {
	select {
	case <-h.hang:
	default:
		close(h.hang)
	}
}

func (h *countingHost) endOutage() {
	select {
	case <-h.resume:
	default:
		close(h.resume)
	}
}

// packagistFixture is a Packagist serving minified metadata for two
// packages, symfony/console depending on psr/log, and an archive host. The
// console archives sit on the archive host directly; psr/log's dist is a
// GitHub API zipball, which bodega fetches from codeload, here the archive
// host too. Slashes are escaped in the metadata as Packagist escapes them.
type packagistFixture struct {
	packagist, archives *countingHost
	console, consoleDev string
	log                 string
}

func newPackagistFixture(t *testing.T) *packagistFixture {
	t.Helper()
	f := &packagistFixture{packagist: newCountingHost(t, "application/json"), archives: newCountingHost(t, "application/zip")}
	esc := func(s string) string { return strings.ReplaceAll(s, "/", `\/`) }
	arch := f.archives.ts.URL
	f.console = `{"packages":{"symfony/console":[` +
		`{"name":"symfony/console","description":"Eases the creation of beautiful and testable command line interfaces","version":"v7.1.5","version_normalized":"7.1.5.0",` +
		`"source":{"url":"https:\/\/github.com\/symfony\/console.git","type":"git","reference":"` + consoleRef515 + `"},` +
		`"dist":{"url":"` + esc(arch+"/archives/symfony/console/"+consoleRef515) + `","type":"zip","shasum":"","reference":"` + consoleRef515 + `"},` +
		`"require":{"php":">=8.2","psr\/log":"^1|^2|^3"}},` +
		`{"version":"v7.1.4","version_normalized":"7.1.4.0",` +
		`"source":{"url":"https:\/\/github.com\/symfony\/console.git","type":"git","reference":"` + consoleRef514 + `"},` +
		`"dist":{"url":"` + esc(arch+"/archives/symfony/console/"+consoleRef514) + `","type":"zip","shasum":"","reference":"` + consoleRef514 + `"}},` +
		`{"version":"v7.1.3","version_normalized":"7.1.3.0","dist":"__unset"}` +
		`]},"minified":"composer/2.0"}`
	f.consoleDev = `{"packages":{"symfony/console":[` +
		`{"name":"symfony/console","version":"dev-main","version_normalized":"dev-main",` +
		`"dist":{"url":"` + esc(arch+"/archives/symfony/console/"+consoleDevRef) + `","type":"zip","shasum":"","reference":"` + consoleDevRef + `"}}` +
		`]},"minified":"composer/2.0"}`
	f.log = `{"packages":{"psr/log":[` +
		`{"name":"psr/log","version":"3.0.2","version_normalized":"3.0.2.0",` +
		`"dist":{"url":"https:\/\/api.github.com\/repos\/php-fig\/log\/zipball\/` + logRef + `","type":"zip","shasum":"","reference":"` + logRef + `"},` +
		`"require":{"php":">=8.0.0"}}` +
		`]},"minified":"composer/2.0"}`
	f.packagist.set("/p2/symfony/console.json", f.console)
	f.packagist.set("/p2/symfony/console~dev.json", f.consoleDev)
	f.packagist.set("/p2/psr/log.json", f.log)
	f.archives.set("/archives/symfony/console/"+consoleRef515, "PK\x03\x04 console 7.1.5")
	f.archives.set("/archives/symfony/console/"+consoleRef514, "PK\x03\x04 console 7.1.4")
	f.archives.set("/archives/symfony/console/"+consoleDevRef, "PK\x03\x04 console dev-main")
	f.archives.set("/php-fig/log/legacy.zip/"+logRef, "PK\x03\x04 psr/log 3.0.2")
	return f
}

// composerServer proxies to f with a metadata TTL short enough that every
// metadata document is stale by its second request, and the archive host and
// GitHub's two hosts on composer_dist_hosts.
func composerServer(t *testing.T, f *packagistFixture) *Server {
	t.Helper()
	s := proxyingServer(t)
	s.cache.MetadataTTL = time.Nanosecond
	s.cfg.ComposerUpstream = f.packagist.ts.URL
	s.cfg.ComposerDistHosts = []string{"127.0.0.1", "api.github.com", "codeload.github.com"}
	saved := composerCodeloadBase
	composerCodeloadBase = f.archives.ts.URL
	t.Cleanup(func() { composerCodeloadBase = saved })
	return s
}

func consoleDistPath(version, ref string) string {
	return "/composer/dist/symfony/console/" + version + "/" + ref + ".zip"
}

func TestComposerRootDocumentNamesOnlyTheMetadataURL(t *testing.T) {
	f := newPackagistFixture(t)
	s := composerServer(t, f)
	rec := doRequest(s, http.MethodGet, "/composer/packages.json", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("packages.json: %d %s", rec.Code, rec.Body.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("packages.json is not JSON: %v\n%s", err, rec.Body.String())
	}
	if got := doc["metadata-url"]; got != "/composer/p2/%package%.json" {
		t.Errorf("metadata-url = %v, want /composer/p2/%%package%%.json", got)
	}
	for _, k := range []string{"providers-url", "notify-batch", "search", "providers", "provider-includes"} {
		if _, ok := doc[k]; ok {
			t.Errorf("packages.json carries %q, which sends Composer to a URL other than per-package metadata", k)
		}
	}
	if n := f.packagist.total(); n != 0 {
		t.Errorf("Packagist contacted %d times for bodega's own root document", n)
	}
}

func TestComposerMetadataIsMutableAndRewritten(t *testing.T) {
	for _, tc := range []struct{ path, upstream string }{
		{"/composer/p2/symfony/console.json", "/p2/symfony/console.json"},
		{"/composer/p2/symfony/console~dev.json", "/p2/symfony/console~dev.json"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			f := newPackagistFixture(t)
			s := composerServer(t, f)
			var first string
			for i := range 2 {
				rec := doRequest(s, http.MethodGet, tc.path, nil)
				if rec.Code != http.StatusOK {
					t.Fatalf("request %d: %d %s", i+1, rec.Code, rec.Body.String())
				}
				if strings.Contains(rec.Body.String(), f.archives.ts.URL[len("http://"):]) {
					t.Fatalf("request %d still names the archive host:\n%s", i+1, rec.Body.String())
				}
				if i == 0 {
					first = rec.Body.String()
				} else if rec.Body.String() != first {
					t.Errorf("a refetch answered other bytes:\n%s\nwant\n%s", rec.Body.String(), first)
				}
			}
			if got := f.packagist.hitsFor(tc.upstream); got != 2 {
				t.Errorf("Packagist asked for %s %d times over two stale requests, want 2: metadata is mutable", tc.upstream, got)
			}
		})
	}
}

// Every dist.url is replaced and every other byte, the escaped slashes and
// the minified diffs included, is what Packagist served. The version whose
// dist is "__unset" is source-only and passes through as it came.
func TestComposerMetadataRewritesEveryDistURLAndNothingElse(t *testing.T) {
	f := newPackagistFixture(t)
	s := composerServer(t, f)
	esc := func(s string) string { return strings.ReplaceAll(s, "/", `\/`) }
	want := f.console
	for _, ref := range []string{consoleRef515, consoleRef514} {
		want = strings.Replace(want, `"url":"`+esc(f.archives.ts.URL+"/archives/symfony/console/"+ref)+`"`, "\x00"+ref, 1)
	}
	want = strings.Replace(want, "\x00"+consoleRef515, `"url":"http://example.com/composer/dist/symfony/console/v7.1.5/`+consoleRef515+`.zip"`, 1)
	want = strings.Replace(want, "\x00"+consoleRef514, `"url":"http://example.com/composer/dist/symfony/console/v7.1.4/`+consoleRef514+`.zip"`, 1)

	rec := doRequest(s, http.MethodGet, "/composer/p2/symfony/console.json", nil)
	if rec.Code != http.StatusOK || rec.Body.String() != want {
		t.Fatalf("metadata: %d\n%s\nwant\n%s", rec.Code, rec.Body.String(), want)
	}

	rec = doRequest(s, http.MethodGet, "/composer/p2/psr/log.json", nil)
	wantLog := strings.Replace(f.log, `"url":"https:\/\/api.github.com\/repos\/php-fig\/log\/zipball\/`+logRef+`"`,
		`"url":"http://example.com/composer/dist/psr/log/3.0.2/`+logRef+`.zip"`, 1)
	if rec.Code != http.StatusOK || rec.Body.String() != wantLog {
		t.Fatalf("psr/log metadata: %d\n%s\nwant\n%s", rec.Code, rec.Body.String(), wantLog)
	}
}

// Under minification a version with no dist key of its own carries the
// previous version's, whose URL names the previous version's archive. The
// rewrite gives it one naming its own.
func TestComposerRewriteGivesAnInheritedDistItsOwnURL(t *testing.T) {
	doc := `{"packages":{"a/b":[{"version":"1.0.1","dist":{"url":"https://gitlab.com/x.zip","type":"zip","reference":"r1"}},{"version":"1.0.0"},{}]},"minified":"composer/2.0"}`
	got, err := rewriteComposerDists([]byte(doc), "https://bodega.example/composer/dist")
	if err != nil {
		t.Fatal(err)
	}
	want := `{"packages":{"a/b":[{"version":"1.0.1","dist":{"url":"https://bodega.example/composer/dist/a/b/1.0.1/r1.zip","type":"zip","reference":"r1"}},` +
		`{"version":"1.0.0","dist":{"url":"https://bodega.example/composer/dist/a/b/1.0.0/r1.zip","type":"zip","reference":"r1"}},` +
		`{"dist":{"url":"https://bodega.example/composer/dist/a/b/1.0.0/r1.zip","type":"zip","reference":"r1"}}]},"minified":"composer/2.0"}`
	if string(got) != want {
		t.Errorf("rewrite:\n%s\nwant\n%s", got, want)
	}

	// Not minified, nothing is inherited, and a version with no dist stays
	// without one.
	plain := `{"packages":{"a/b":[{"version":"1.0.1","dist":{"url":"https://gitlab.com/x.zip","type":"zip","reference":"r1"}},{"version":"1.0.0"}]}}`
	got, err = rewriteComposerDists([]byte(plain), "https://bodega.example/composer/dist")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(got), `{"version":"1.0.0"}]}}`) {
		t.Errorf("an unminified version with no dist was given one:\n%s", got)
	}
}

// B156: during an outage the stale metadata is served within stale_grace
// rather than after Packagist gives up.
func TestComposerStaleMetadataServedDuringOutage(t *testing.T) {
	f := newPackagistFixture(t)
	s := composerServer(t, f)
	s.cache.StaleGrace = staleGraceForTest
	first := doRequest(s, http.MethodGet, "/composer/p2/symfony/console.json", nil)
	if first.Code != http.StatusOK {
		t.Fatalf("first request: %d", first.Code)
	}

	f.packagist.stopAnswering()
	start := time.Now()
	rec := doRequest(s, http.MethodGet, "/composer/p2/symfony/console.json", nil)
	elapsed := time.Since(start)
	if rec.Code != http.StatusOK || rec.Body.String() != first.Body.String() {
		t.Fatalf("during the outage: %d %q, want 200 and the cached copy", rec.Code, rec.Body.String())
	}
	if elapsed > staleGraceForTest+time.Second {
		t.Errorf("stale copy took %s, want within stale_grace (%s) plus 1s", elapsed, staleGraceForTest)
	}
	f.packagist.endOutage()
	waitFor(t, refreshIdle(s, manifest.ComposerMetadataKey("symfony/console", false)))
}

// The archive comes from the URL the metadata names, not from anything in
// the request path, and is cached as immutable.
func TestComposerDistServedFromTheURLTheMetadataNames(t *testing.T) {
	f := newPackagistFixture(t)
	s := composerServer(t, f)
	for i := range 2 {
		rec := doRequest(s, http.MethodGet, consoleDistPath("v7.1.5", consoleRef515), nil)
		if rec.Code != http.StatusOK || rec.Body.String() != "PK\x03\x04 console 7.1.5" {
			t.Fatalf("request %d: %d %q", i+1, rec.Code, rec.Body.String())
		}
	}
	if got := f.archives.hitsFor("/archives/symfony/console/" + consoleRef515); got != 1 {
		t.Errorf("archive host asked %d times over two requests, want 1: an archive is immutable", got)
	}
	if got := f.packagist.hitsFor("/p2/symfony/console.json"); got != 1 {
		t.Errorf("Packagist asked %d times, want 1: the second request is a cache hit and reads no metadata", got)
	}

	// A branch version resolves through ~dev.json.
	rec := doRequest(s, http.MethodGet, consoleDistPath("dev-main", consoleDevRef), nil)
	if rec.Code != http.StatusOK || rec.Body.String() != "PK\x03\x04 console dev-main" {
		t.Errorf("dev-main: %d %q", rec.Code, rec.Body.String())
	}
}

func TestComposerDistNotListedInTheMetadataIsNotFetched(t *testing.T) {
	for _, p := range []string{
		consoleDistPath("v7.1.5", "deadbeef"),    // a reference the version does not carry
		consoleDistPath("v7.1.5", consoleRef514), // another version's reference
		consoleDistPath("v7.1.3", consoleRef515), // a source-only version
		consoleDistPath("v9.9.9", consoleRef515), // a version Packagist does not list
		"/composer/dist/symfony/console/v7.1.5/" + consoleRef515 + ".tar",
	} {
		t.Run(p, func(t *testing.T) {
			f := newPackagistFixture(t)
			s := composerServer(t, f)
			rec := doRequest(s, http.MethodGet, p, nil)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status %d, want 404 (%s)", rec.Code, rec.Body.String())
			}
			if n := f.archives.total(); n != 0 {
				t.Errorf("archive host contacted %d times for an archive the metadata does not list", n)
			}
		})
	}
}

func TestComposerZipballFetchedFromCodeload(t *testing.T) {
	f := newPackagistFixture(t)
	s := composerServer(t, f)
	rec := doRequest(s, http.MethodGet, "/composer/dist/psr/log/3.0.2/"+logRef+".zip", nil)
	if rec.Code != http.StatusOK || rec.Body.String() != "PK\x03\x04 psr/log 3.0.2" {
		t.Fatalf("psr/log: %d %q", rec.Code, rec.Body.String())
	}
	if got := f.archives.hitsFor("/php-fig/log/legacy.zip/" + logRef); got != 1 {
		t.Errorf("codeload asked for legacy.zip %d times, want 1", got)
	}

	for named, want := range map[string]string{
		"https://api.github.com/repos/php-fig/log/zipball/" + logRef:  composerCodeloadBase + "/php-fig/log/legacy.zip/" + logRef,
		"https://api.github.com/repos/php-fig/log/tarball/" + logRef:  "https://api.github.com/repos/php-fig/log/tarball/" + logRef,
		"https://gitlab.com/api/v4/projects/1/repository/archive.zip": "https://gitlab.com/api/v4/projects/1/repository/archive.zip",
	} {
		if got, err := composerFetchURL(named); err != nil || got != want {
			t.Errorf("composerFetchURL(%q) = %q, %v, want %q", named, got, err, want)
		}
	}
}

func TestComposerDistOnAnUnlistedHostIsRefused(t *testing.T) {
	f := newPackagistFixture(t)
	s := composerServer(t, f)
	s.cfg.ComposerDistHosts = []string{"api.github.com", "codeload.github.com"}
	rec := doRequest(s, http.MethodGet, consoleDistPath("v7.1.5", consoleRef515), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	refusalIncident(t, rec.Header(), checkDistHost)
	for _, want := range []string{"127.0.0.1", "composer_dist_hosts"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("refusal does not name %q:\n%s", want, rec.Body.String())
		}
	}
	if n := f.archives.total(); n != 0 {
		t.Errorf("archive host contacted %d times for a host composer_dist_hosts does not list", n)
	}
}

func TestComposerRefusedByTheAllowList(t *testing.T) {
	f := newPackagistFixture(t)
	s := composerServer(t, f)
	if err := s.auditDB.SetAdmissionMode(t.Context(), audit.AdmissionMode{Ecosystem: manifest.TypeComposer, Mode: audit.ModeListed}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{consoleDistPath("v7.1.5", consoleRef515), "/composer/p2/symfony/console.json"} {
		rec := doRequest(s, http.MethodGet, p, nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: status %d, want 403 (%s)", p, rec.Code, rec.Body.String())
		}
		refusalIncident(t, rec.Header(), checkAllowList)
		if !strings.Contains(rec.Body.String(), "bodega policy add composer symfony/console") {
			t.Errorf("%s: refusal does not name the command that admits the package:\n%s", p, rec.Body.String())
		}
	}
	if n := f.packagist.total() + f.archives.total(); n != 0 {
		t.Errorf("upstream contacted %d times for a package the allow-list refused", n)
	}

	if err := s.auditDB.InsertPolicy(t.Context(), audit.PolicyInfo{ID: "c1", RegistryType: manifest.TypeComposer, RuleKind: policy.KindPackage, Pattern: "symfony/console"}); err != nil {
		t.Fatalf("add rule: %v", err)
	}
	s.policy.Invalidate()
	if rec := doRequest(s, http.MethodGet, consoleDistPath("v7.1.5", consoleRef515), nil); rec.Code != http.StatusOK {
		t.Errorf("after the rule: %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
}

// The discovery row names the package as <vendor>/<package> and the version
// as Packagist's version field.
func TestComposerDistRecordsItsDiscoveryRow(t *testing.T) {
	f := newPackagistFixture(t)
	s := composerServer(t, f)
	if rec := doRequest(s, http.MethodGet, consoleDistPath("v7.1.5", consoleRef515), nil); rec.Code != http.StatusOK {
		t.Fatalf("dist: %d %s", rec.Code, rec.Body.String())
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		rows, err := s.auditDB.ListDiscovery(t.Context(), audit.DiscoveryFilter{RegistryType: manifest.TypeComposer})
		if err != nil {
			t.Fatalf("list discovery: %v", err)
		}
		for _, r := range rows {
			if r.PkgName == "symfony/console" && r.PkgVersion == "v7.1.5" {
				if r.PatternHint != "symfony/console" {
					t.Errorf("pattern_hint %q, want the package name", r.PatternHint)
				}
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no discovery row for symfony/console@v7.1.5 in %+v", rows)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestComposerRefusedWhenHidden(t *testing.T) {
	f := newPackagistFixture(t)
	s := composerServer(t, f)
	addVersion(t, s, manifest.TypeComposer, "symfony/console", manifest.VersionEntry{Version: "v7.1.4", Mode: manifest.ModeProxy})
	addVersion(t, s, manifest.TypeComposer, "symfony/console", manifest.VersionEntry{Version: "v7.1.5", Mode: manifest.ModeProxy, Hidden: true})

	rec := doRequest(s, http.MethodGet, consoleDistPath("v7.1.5", consoleRef515), nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("hidden version: %d, want the hidden refusal's 404", rec.Code)
	}
	refusalIncident(t, rec.Header(), checkHidden)
	if n := f.packagist.total() + f.archives.total(); n != 0 {
		t.Errorf("upstream contacted %d times for a hidden version", n)
	}
	if rec := doRequest(s, http.MethodGet, consoleDistPath("v7.1.4", consoleRef514), nil); rec.Code != http.StatusOK {
		t.Errorf("a version nothing hides: %d, want 200 (%s)", rec.Code, rec.Body.String())
	}

	addVersion(t, s, manifest.TypeComposer, "psr/log", manifest.VersionEntry{Version: "3.0.2", Mode: manifest.ModeProxy, Hidden: true})
	before := f.packagist.total()
	if rec := doRequest(s, http.MethodGet, "/composer/p2/psr/log.json", nil); rec.Code != http.StatusNotFound {
		t.Errorf("metadata of a hidden package: %d, want 404", rec.Code)
	}
	if n := f.packagist.total() - before; n != 0 {
		t.Errorf("Packagist asked %d times for a hidden package's metadata", n)
	}
}

func TestComposerRefusedByAVersionConstraint(t *testing.T) {
	f := newPackagistFixture(t)
	s := composerServer(t, f)
	addVersion(t, s, manifest.TypeComposer, "symfony/console", manifest.VersionEntry{
		Version: "v7.1.4", Mode: manifest.ModeProxy, VersionConstraint: manifest.ConstraintExact,
	})
	rec := doRequest(s, http.MethodGet, consoleDistPath("v7.1.5", consoleRef515), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a version outside the constraint: %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	refusalIncident(t, rec.Header(), checkConstraint)
	if n := f.packagist.total() + f.archives.total(); n != 0 {
		t.Errorf("upstream contacted %d times for a version the constraint refused", n)
	}
	if rec := doRequest(s, http.MethodGet, consoleDistPath("v7.1.4", consoleRef514), nil); rec.Code != http.StatusOK {
		t.Errorf("the pinned version: %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
}

func TestComposerUnknownPathsNotFoundWithoutUpstream(t *testing.T) {
	f := newPackagistFixture(t)
	s := composerServer(t, f)
	for _, p := range []string{
		"/composer/",
		"/composer/packages.json/x",
		"/composer/p2/symfony.json",
		"/composer/p2/Symfony/Console.json",
		"/composer/p2/symfony/console/x.json",
		"/composer/p2/symfony/console",
		"/composer/search.json",
		"/composer/dist/symfony/console/v7.1.5",
		"/composer/dist/symfony/console/v7.1.5/" + consoleRef515,
		"/composer/dist/symfony/console/v7.1.5/../x.zip",
		"/composer/dist/symfony/console/v7.1.5/a/b.zip",
	} {
		// The mux redirects a path holding ".." to its cleaned form before
		// any handler runs, which is no answer either.
		switch rec := doRequest(s, http.MethodGet, p, nil); rec.Code {
		case http.StatusNotFound, http.StatusMovedPermanently, http.StatusTemporaryRedirect:
		default:
			t.Errorf("%s: %d, want 404", p, rec.Code)
		}
	}
	if n := f.packagist.total() + f.archives.total(); n != 0 {
		t.Errorf("upstream contacted %d times for paths no client asks for", n)
	}
}

func TestParsePackagePathComposer(t *testing.T) {
	for path, want := range map[string][3]string{
		"/composer/p2/symfony/console.json":                  {"composer", "symfony/console", ""},
		"/composer/p2/symfony/console~dev.json":              {"composer", "symfony/console", ""},
		"/composer/dist/symfony/console/v7.1.5/abc.zip":      {"composer", "symfony/console", "v7.1.5"},
		"/composer/dist/symfony/console/dev-feature/x/a.zip": {"composer", "symfony/console", "dev-feature/x"},
		"/composer/packages.json":                            {"composer", "", ""},
	} {
		typ, name, version := parsePackagePath(path)
		if [3]string{typ, name, version} != want {
			t.Errorf("parsePackagePath(%q) = %q %q %q, want %q", path, typ, name, version, want)
		}
	}
}

func TestComposerMetadataRewriteFailureNamesTheRewrite(t *testing.T) {
	f := newPackagistFixture(t)
	f.packagist.set("/p2/symfony/console.json", `{"packages":`)
	s := composerServer(t, f)
	rec := doRequest(s, http.MethodGet, "/composer/p2/symfony/console.json", nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("truncated metadata: %d %s, want 502", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "dist URL rewrite") || !strings.Contains(body, "around bodega") || strings.Contains(body, "profile") {
		t.Errorf("502 body = %q, want it to name the dist URL rewrite and not a profile filter", body)
	}
}
