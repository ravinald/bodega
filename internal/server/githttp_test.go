package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/logging"
	"github.com/ravinald/bodega/internal/manifest"
)

// The repository every end-to-end test in this file clones. "team/tool.git"
// exercises a multi-segment path, which is what a real forge URL looks like
// and what the PATH_INFO pattern has to admit.
const gitTestRepo = "team/tool.git"

// requireGitTool skips when the host has no git-http-backend. Every test below
// drives the real binary: a fake would assert bodega's idea of the CGI
// protocol rather than git's.
func requireGitTool(t *testing.T, s *Server) {
	t.Helper()
	if s.gitTool == nil {
		t.Skip("git-http-backend not found on this host; smart-HTTP is unrouted")
	}
}

// runGitCLI runs git for test setup with an explicit identity, so the test
// does not depend on the developer's global config.
func runGitCLI(t *testing.T, dir string, args ...string) string {
	t.Helper()
	full := append([]string{
		"-c", "user.name=bodega test",
		"-c", "user.email=test@bodega.invalid",
		"-c", "commit.gpgsign=false",
		"-c", "init.defaultBranch=main",
		"-c", "protocol.file.allow=always",
	}, args...)
	cmd := exec.Command("git", full...) //nolint:gosec // test-owned argv
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// newGitUpstream builds a bare repository at <root>/team/tool.git and returns
// the root, so a git_upstreams URL of "file://<root>/" composes onto it the
// same way "https://github.com/" composes onto "octocat/Hello-World.git".
func newGitUpstream(t *testing.T) string {
	t.Helper()
	return newGitUpstreamSubject(t, "first")
}

// newGitUpstreamSubject is newGitUpstream with the commit subject chosen, so a
// test can tell two upstreams apart by what a clone of them contains.
func newGitUpstreamSubject(t *testing.T, subject string) string {
	t.Helper()
	work := t.TempDir()
	runGitCLI(t, work, "init", "-q", ".")
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("bodega\n"), 0o600); err != nil {
		t.Fatalf("write upstream file: %v", err)
	}
	runGitCLI(t, work, "add", "README.md")
	runGitCLI(t, work, "commit", "-q", "-m", subject)

	root := t.TempDir()
	bare := filepath.Join(root, filepath.FromSlash(gitTestRepo))
	if err := os.MkdirAll(filepath.Dir(bare), 0o750); err != nil {
		t.Fatalf("mkdir upstream parent: %v", err)
	}
	runGitCLI(t, work, "clone", "--bare", "-q", work, bare)
	return root
}

// newGitServer wires a discovery server to a file:// upstream root under one
// open namespace and one catalog namespace.
func newGitServer(t *testing.T, upstreamRoot string) *Server {
	t.Helper()
	s := newDiscoveryServer(t)
	requireGitTool(t, s)
	url := "file://" + upstreamRoot + "/"
	s.cfg.GitUpstreams = map[string]config.GitUpstream{
		"corp":   {URL: url, Mode: config.UpstreamModeOpen},
		"vetted": {URL: url, Mode: config.UpstreamModeCatalog},
	}
	return s
}

// mirrorDir is where the handler is expected to put a namespace's mirror.
func mirrorDir(s *Server, ns string) string {
	return filepath.Join(s.gitTool.root, ns, filepath.FromSlash(gitTestRepo))
}

// A real git clone through bodega, end to end: the client speaks smart-HTTP,
// bodega mirrors the upstream on the first request, and the second clone is
// answered from that mirror with the upstream unreachable.
func TestGitSmartCloneEndToEnd(t *testing.T) {
	upstream := newGitUpstream(t)
	s := newGitServer(t, upstream)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	dest := filepath.Join(t.TempDir(), "first")
	runGitCLI(t, t.TempDir(), "clone", "-q", ts.URL+"/git/corp/"+gitTestRepo, dest)
	if got := runGitCLI(t, dest, "log", "-1", "--format=%s"); got != "first" {
		t.Errorf("cloned HEAD subject = %q, want %q", got, "first")
	}
	if _, err := os.Stat(mirrorDir(s, "corp")); err != nil {
		t.Fatalf("mirror not created at %s: %v", mirrorDir(s, "corp"), err)
	}

	// Remove the upstream. A second clone that still succeeds proves the
	// mirror served it rather than a fresh fetch from the forge.
	if err := os.RemoveAll(upstream); err != nil {
		t.Fatalf("remove upstream: %v", err)
	}
	second := filepath.Join(t.TempDir(), "second")
	runGitCLI(t, t.TempDir(), "clone", "-q", ts.URL+"/git/corp/"+gitTestRepo, second)
	if got := runGitCLI(t, second, "log", "-1", "--format=%s"); got != "first" {
		t.Errorf("second clone HEAD subject = %q, want %q", got, "first")
	}
}

// The clone leaves a discovery row with an empty version, because a clone
// negotiates over many refs and no single one names what was asked for. F1's
// promote turns that row into an entry with version_constraint "any".
func TestGitSmartRecordsVersionlessDiscoveryRow(t *testing.T) {
	upstream := newGitUpstream(t)
	s := newGitServer(t, upstream)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	runGitCLI(t, t.TempDir(), "clone", "-q", ts.URL+"/git/corp/"+gitTestRepo, filepath.Join(t.TempDir(), "c"))

	rows := waitForBinaryRows(t, s, audit.DecisionNoPolicy, 1)
	row := rows[0]
	if row.RegistryType != manifest.TypeGit {
		t.Errorf("registry_type = %q, want %q", row.RegistryType, manifest.TypeGit)
	}
	if row.PkgName != "corp/team/tool" {
		t.Errorf("pkg_name = %q, want %q — catalog mode looks the manifest up under this name", row.PkgName, "corp/team/tool")
	}
	if row.PkgVersion != "" {
		t.Errorf("pkg_version = %q, want empty", row.PkgVersion)
	}
	if !strings.HasSuffix(row.UpstreamURL, gitTestRepo) {
		t.Errorf("upstream_url = %q, want it to end in %q", row.UpstreamURL, gitTestRepo)
	}
}

// catalog mode must never trigger a clone. The status code alone would not
// prove that — a 404 written after a successful clone looks identical — so the
// assertion is on the filesystem.
func TestGitSmartCatalogModeNeverClones(t *testing.T) {
	upstream := newGitUpstream(t)
	s := newGitServer(t, upstream)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/git/vetted/" + gitTestRepo + "/info/refs?service=git-upload-pack") //nolint:gosec,noctx // test-owned loopback URL
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("uncataloged path = %d, want 404", resp.StatusCode)
	}
	if _, err := os.Stat(mirrorDir(s, "vetted")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stat mirror after a catalog 404 = %v, want not-exist — catalog mode cloned an uncataloged upstream", err)
	}
	if entries, err := os.ReadDir(s.gitTool.root); err == nil && len(entries) != 0 {
		t.Errorf("git root holds %d entries after a catalog 404, want 0", len(entries))
	}

	rows := waitForBinaryRows(t, s, audit.DecisionNoManifest, 1)
	if rows[0].PkgName != "vetted/team/tool" {
		t.Errorf("pkg_name = %q, want %q", rows[0].PkgName, "vetted/team/tool")
	}
}

// Once a manifest entry names the path, the same catalog request serves.
func TestGitSmartCatalogModeServesCatalogedRepo(t *testing.T) {
	upstream := newGitUpstream(t)
	s := newGitServer(t, upstream)
	if err := s.store.AddVersion(t.Context(), manifest.TypeGit, "vetted/team/tool", manifest.VersionEntry{
		URL:               "file://" + upstream + "/" + gitTestRepo,
		Mode:              manifest.ModeProxy,
		VersionConstraint: manifest.ConstraintAny,
	}); err != nil {
		t.Fatalf("seed manifest: %v", err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	dest := filepath.Join(t.TempDir(), "cataloged")
	runGitCLI(t, t.TempDir(), "clone", "-q", ts.URL+"/git/vetted/"+gitTestRepo, dest)
	if got := runGitCLI(t, dest, "log", "-1", "--format=%s"); got != "first" {
		t.Errorf("cloned HEAD subject = %q, want %q", got, "first")
	}
}

// A store key folds "/" to "--", so a lookup of "team--tool" resolves the
// manifest written for "team/tool". Catalog mode has to reject that or a
// request can name an upstream nobody cataloged and still be cloned.
func TestGitSmartCatalogRejectsFoldedName(t *testing.T) {
	upstream := newGitUpstream(t)
	s := newGitServer(t, upstream)
	if err := s.store.AddVersion(t.Context(), manifest.TypeGit, "vetted/team/tool", manifest.VersionEntry{
		URL:  "file://" + upstream + "/" + gitTestRepo,
		Mode: manifest.ModeProxy,
	}); err != nil {
		t.Fatalf("seed manifest: %v", err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/git/vetted/team--tool.git/info/refs?service=git-upload-pack") //nolint:gosec,noctx // test-owned loopback URL
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("folded-name request = %d, want 404 — it resolved the manifest for team/tool", resp.StatusCode)
	}
}

// Pushes are refused before the exec, on both shapes a client uses: the
// info/refs probe that asks whether receive-pack is advertised, and the POST
// that would carry the pack.
func TestGitSmartRefusesPush(t *testing.T) {
	upstream := newGitUpstream(t)
	s := newGitServer(t, upstream)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	for _, path := range []string{
		"/git/corp/" + gitTestRepo + "/info/refs?service=git-receive-pack",
		"/git/corp/" + gitTestRepo + "/git-receive-pack",
	} {
		resp, err := http.Post(ts.URL+path, "application/x-git-receive-pack-request", strings.NewReader("")) //nolint:noctx // test-owned loopback URL
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("POST %s = %d, want 403", path, resp.StatusCode)
		}
	}
	if _, err := os.Stat(mirrorDir(s, "corp")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused push created a mirror at %s", mirrorDir(s, "corp"))
	}
}

// Layer one of the push refusal: every mirror bodega creates carries
// http.receivepack=false, so a drifted handler still cannot accept a push.
func TestGitMirrorConfigRefusesReceivePack(t *testing.T) {
	upstream := newGitUpstream(t)
	s := newGitServer(t, upstream)
	dir := mirrorDir(s, "corp")
	if err := s.ensureGitMirror(t.Context(), "corp/"+gitTestRepo, dir, "file://"+upstream+"/"+gitTestRepo); err != nil {
		t.Fatalf("ensureGitMirror: %v", err)
	}
	if got := runGitCLI(t, dir, "config", "--get", "http.receivepack"); got != "false" {
		t.Errorf("http.receivepack = %q, want %q", got, "false")
	}
	if got := runGitCLI(t, dir, "config", "--get", "http.uploadpack"); got != "true" {
		t.Errorf("http.uploadpack = %q, want %q", got, "true")
	}
}

// Anything that is not one of the two smart-HTTP suffixes 404s, and does so
// before a mirror directory could be computed or created.
func TestGitSmartRejectsNonSmartSuffix(t *testing.T) {
	upstream := newGitUpstream(t)
	s := newGitServer(t, upstream)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	for _, path := range []string{
		"/git/corp/" + gitTestRepo + "/HEAD",
		"/git/corp/" + gitTestRepo + "/objects/info/packs",
		"/git/corp/team/tool/info/refs", // no .git suffix
		"/git/corp/team/info/refs",
	} {
		resp, err := http.Get(ts.URL + path) //nolint:gosec,noctx // test-owned loopback URL
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, resp.StatusCode)
		}
	}
	if entries, err := os.ReadDir(s.gitTool.root); err == nil && len(entries) != 0 {
		t.Errorf("git root holds %d entries after four rejected suffixes, want 0", len(entries))
	}
}

// Each smart-HTTP endpoint answers one method. info/refs is a GET and
// git-upload-pack is a POST; the other pairing is a 405, not a child process.
func TestGitSmartRejectsWrongMethod(t *testing.T) {
	upstream := newGitUpstream(t)
	s := newGitServer(t, upstream)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/git/corp/" + gitTestRepo + "/git-upload-pack") //nolint:gosec,noctx // test-owned loopback URL
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET git-upload-pack = %d, want 405", resp.StatusCode)
	}
}

// The child's environment is the whole security boundary of the exec, so it is
// asserted exactly rather than described. An inherited PATH, HOME or GIT_DIR is
// invisible in review and decides what the child does in production.
func TestGitCGIEnvIsExactAndInheritsNothing(t *testing.T) {
	s := newDiscoveryServer(t)
	requireGitTool(t, s)

	r := httptest.NewRequest(http.MethodPost, "/git/corp/team/tool.git/git-upload-pack?service=git-upload-pack", nil)
	r.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	r.Header.Set("Content-Encoding", "gzip")
	r.Header.Set("User-Agent", "git/2.50.1")
	r.RemoteAddr = "203.0.113.7:5555"

	want := []string{
		"GIT_PROJECT_ROOT=" + s.gitTool.root,
		"GIT_HTTP_EXPORT_ALL=1",
		"PATH_INFO=/corp/team/tool.git/git-upload-pack",
		// Empty on the POST leg: the child reads its service from PATH_INFO
		// and ignores the query, and nothing from the request is forwarded.
		"QUERY_STRING=",
		"REQUEST_METHOD=POST",
		"CONTENT_TYPE=application/x-git-upload-pack-request",
		"HTTP_CONTENT_ENCODING=gzip",
		"HTTP_USER_AGENT=git/2.50.1",
		"REMOTE_ADDR=203.0.113.7",
		"REMOTE_USER=",
	}
	query, ok := gitQueryString(gitServiceUploadPack, r.URL.Query()["service"])
	if !ok {
		t.Fatal("gitQueryString refused a git-upload-pack POST")
	}
	got := s.gitCGIEnv(r, "/corp/team/tool.git/git-upload-pack", query)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("child environment mismatch\ngot:  %q\nwant: %q", got, want)
	}
	for _, banned := range []string{"PATH=", "HOME=", "GIT_DIR=", "GIT_CONFIG", "LD_PRELOAD="} {
		for _, kv := range got {
			if strings.HasPrefix(kv, banned) {
				t.Errorf("child environment carries %q", kv)
			}
		}
	}
}

// gitSmartService and the PATH_INFO pattern are the shape half of the two
// path checks. Table-driven because the failures are all one character apart.
func TestGitSmartServiceAndPathInfoPattern(t *testing.T) {
	for _, tc := range []struct {
		rest, repo, service string
		ok                  bool
	}{
		{"team/tool.git/info/refs", "team/tool.git", gitServiceInfoRefs, true},
		{"tool.git/git-upload-pack", "tool.git", gitServiceUploadPack, true},
		{"team/tool.git/HEAD", "", "", false},
		{"team/tool/info/refs", "", "", false},
		{"team/tool.git/git-receive-pack", "", "", false},
		{".git/info/refs", "", "", false},
		{"info/refs", "", "", false},
		{"", "", "", false},
	} {
		repo, service, ok := gitSmartService(tc.rest)
		if ok != tc.ok || repo != tc.repo || service != tc.service {
			t.Errorf("gitSmartService(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.rest, repo, service, ok, tc.repo, tc.service, tc.ok)
		}
	}

	for _, bad := range []string{
		"/ns/team/tool.git/info/refs;id",
		"/ns/team/../tool.git/info/refs",
		"/ns/team/tool.git/info/refs?x=1",
		"/ns/team/to ol.git/info/refs",
		"/ns/team/tool.git/HEAD",
		"ns/team/tool.git/info/refs",
	} {
		if gitPathInfoOK(bad) {
			t.Errorf("PATH_INFO pattern accepted %q", bad)
		}
	}
	for _, good := range []string{
		"/ns/team/tool.git/info/refs",
		"/ns/tool.git/git-upload-pack",
		"/ns/a/b/c/d.git/info/refs",
	} {
		if !gitPathInfoOK(good) {
			t.Errorf("PATH_INFO pattern rejected %q", good)
		}
	}
}

// Twenty concurrent first requests for one repository produce one mirror.
// Without the per-key lock the nineteen that lose the race run `git clone
// --mirror` into a directory the winner is filling, and git refuses.
func TestEnsureGitMirrorSerializesFirstClone(t *testing.T) {
	upstream := newGitUpstream(t)
	s := newGitServer(t, upstream)
	dir := mirrorDir(s, "corp")
	url := "file://" + upstream + "/" + gitTestRepo

	const clones = 20
	errs := make([]error, clones)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range clones {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = s.ensureGitMirror(context.Background(), "corp/"+gitTestRepo, dir, url)
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent clone %d: %v", i, err)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(dir))
	if err != nil {
		t.Fatalf("read mirror parent: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("mirror parent holds %d entries, want 1", len(entries))
	}
	if _, err := os.Stat(filepath.Join(dir, "HEAD")); err != nil {
		t.Errorf("mirror is not a git directory: %v", err)
	}
}

// A clone that fails leaves nothing behind. A partial mirror that survives
// answers later requests with a truncated history, which is worse than the 502
// the caller turns this error into.
func TestEnsureGitMirrorLeavesNothingOnFailure(t *testing.T) {
	s := newGitServer(t, t.TempDir())
	dir := mirrorDir(s, "corp")

	err := s.ensureGitMirror(t.Context(), "corp/"+gitTestRepo, dir, "file://"+t.TempDir()+"/nope.git")
	if err == nil {
		t.Fatal("ensureGitMirror on a missing upstream returned nil")
	}
	if _, statErr := os.Stat(dir); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("stat after a failed clone = %v, want not-exist", statErr)
	}
}

// A mirror older than metadata_ttl re-fetches before serving info/refs, so a
// clone through bodega sees a commit pushed upstream after the mirror was made.
func TestGitSmartRefreshesStaleMirror(t *testing.T) {
	upstream := newGitUpstream(t)
	s := newGitServer(t, upstream)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	first := filepath.Join(t.TempDir(), "first")
	runGitCLI(t, t.TempDir(), "clone", "-q", ts.URL+"/git/corp/"+gitTestRepo, first)

	// Add a commit to the upstream through a working clone of it.
	work := filepath.Join(t.TempDir(), "work")
	bare := filepath.Join(upstream, filepath.FromSlash(gitTestRepo))
	runGitCLI(t, t.TempDir(), "clone", "-q", bare, work)
	if err := os.WriteFile(filepath.Join(work, "second.txt"), []byte("2\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	runGitCLI(t, work, "add", "second.txt")
	runGitCLI(t, work, "commit", "-q", "-m", "second")
	runGitCLI(t, work, "push", "-q", "origin", "HEAD")

	// Age the fetch stamp past metadata_ttl, which defaults to one hour.
	stamp := filepath.Join(mirrorDir(s, "corp"), gitFetchStamp)
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stamp, old, old); err != nil {
		t.Fatalf("age fetch stamp: %v", err)
	}

	second := filepath.Join(t.TempDir(), "second")
	runGitCLI(t, t.TempDir(), "clone", "-q", ts.URL+"/git/corp/"+gitTestRepo, second)
	if got := runGitCLI(t, second, "log", "-1", "--format=%s"); got != "second" {
		t.Errorf("HEAD subject after a stale refresh = %q, want %q", got, "second")
	}
}

// A failed refresh serves the history already on disk rather than failing the
// request, and stamps anyway so a dead upstream costs one fetch per TTL rather
// than one per request.
func TestGitSmartRefreshFailureStillServes(t *testing.T) {
	upstream := newGitUpstream(t)
	s := newGitServer(t, upstream)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	runGitCLI(t, t.TempDir(), "clone", "-q", ts.URL+"/git/corp/"+gitTestRepo, filepath.Join(t.TempDir(), "first"))

	if err := os.RemoveAll(upstream); err != nil {
		t.Fatalf("remove upstream: %v", err)
	}
	stamp := filepath.Join(mirrorDir(s, "corp"), gitFetchStamp)
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stamp, old, old); err != nil {
		t.Fatalf("age fetch stamp: %v", err)
	}

	second := filepath.Join(t.TempDir(), "second")
	runGitCLI(t, t.TempDir(), "clone", "-q", ts.URL+"/git/corp/"+gitTestRepo, second)
	if got := runGitCLI(t, second, "log", "-1", "--format=%s"); got != "first" {
		t.Errorf("HEAD subject after a failed refresh = %q, want %q", got, "first")
	}
	fi, err := os.Stat(stamp)
	if err != nil {
		t.Fatalf("stat stamp: %v", err)
	}
	if time.Since(fi.ModTime()) > time.Minute {
		t.Errorf("fetch stamp was not refreshed after a failed fetch; every request would retry the dead upstream")
	}
}

// The child's stderr names filesystem paths and upstream URLs. It goes to the
// log; the response says what failed and what to try.
func TestGitSmartErrorBodyLeaksNoPaths(t *testing.T) {
	s := newGitServer(t, t.TempDir())
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/git/corp/" + gitTestRepo + "/info/refs?service=git-upload-pack") //nolint:gosec,noctx // test-owned loopback URL
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	got := string(body[:n])
	for _, leak := range []string{s.gitTool.root, "file://", "fatal:"} {
		if strings.Contains(got, leak) {
			t.Errorf("error body leaks %q: %s", leak, got)
		}
	}
	if !strings.Contains(got, "bodega server log") {
		t.Errorf("error body names no next step: %s", got)
	}
}

// keyedMutex forgets a key once nothing holds it. An open namespace lets a
// client invent keys, and a map that only grows is a slow leak with a remote
// trigger.
func TestKeyedMutexReleasesKeys(t *testing.T) {
	var k keyedMutex
	for i := range 100 {
		unlock := k.lock(fmt.Sprintf("key-%d", i))
		unlock()
	}
	k.mu.Lock()
	n := len(k.m)
	k.mu.Unlock()
	if n != 0 {
		t.Errorf("keyedMutex retains %d keys after every holder released, want 0", n)
	}
}

// writeCGIResponse translates the child's header block. A Status line becomes
// the HTTP status; everything else becomes a header.
func TestWriteCGIResponse(t *testing.T) {
	rec := httptest.NewRecorder()
	body := "Status: 404 Not Found\r\nContent-Type: text/plain\r\nCache-Control: no-cache\r\n\r\nnot found\n"
	wrote, err := writeCGIResponse(rec, strings.NewReader(body))
	if err != nil || !wrote {
		t.Fatalf("writeCGIResponse = (%v, %v), want (true, nil)", wrote, err)
	}
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-cache")
	}
	if got := rec.Body.String(); got != "not found\n" {
		t.Errorf("body = %q", got)
	}

	rec = httptest.NewRecorder()
	if wrote, err := writeCGIResponse(rec, strings.NewReader("")); wrote || err == nil {
		t.Errorf("empty child output = (%v, %v), want (false, error)", wrote, err)
	}
}

// hideGitBackend makes git-http-backend unfindable for the duration of the
// test: PATH holds only a git(1) shim whose --exec-path names nothing, and the
// fixed candidate list is emptied.
func hideGitBackend(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	shim := filepath.Join(dir, "git")
	body := "#!/bin/sh\nif [ \"$1\" = \"--exec-path\" ]; then echo " + filepath.Join(dir, "nowhere") + "; exit 0; fi\nexit 1\n"
	if err := os.WriteFile(shim, []byte(body), 0o700); err != nil { //nolint:gosec // test-owned shim
		t.Fatalf("write git shim: %v", err)
	}
	t.Setenv("PATH", dir)

	saved := gitBackendCandidates
	gitBackendCandidates = nil
	t.Cleanup(func() { gitBackendCandidates = saved })
}

// A host with no git-http-backend gets an ERROR naming every path searched,
// and no *gitTool. Failing per request instead would hand the operator a
// broken clone with nothing in the startup log to explain it.
//
// The handler is the one serve builds at the shipped log_level, not one this
// test raised. Unregistering a route is a startup condition that changes what
// bodega serves, so it belongs above the default floor; asserting through a
// permissive handler would pass either way.
func TestResolveGitToolLogsTheSearchAtTheDefaultLevel(t *testing.T) {
	hideGitBackend(t)

	var buf bytes.Buffer
	logger := slog.New(logging.NewHandler(&buf, logging.SlogLevel(0)))
	if got := resolveGitTool(&config.Config{StoragePath: t.TempDir()}, logger); got != nil {
		t.Fatalf("resolveGitTool = %+v, want nil when git-http-backend is absent", got)
	}
	log := buf.String()
	for _, want := range []string{"ERROR", "searched", "PATH=", "nowhere"} {
		if !strings.Contains(log, want) {
			t.Errorf("the startup log at the default level does not name %q: %s", want, log)
		}
	}
}

// With no backend the smart-HTTP route is not registered: the POST half is a
// 405 from the mux, a configured namespace 404s as it did before F4, and the
// legacy bundle route is untouched.
func TestNoGitBackendLeavesSmartHTTPUnrouted(t *testing.T) {
	hideGitBackend(t)

	s := newDiscoveryServer(t)
	if s.gitTool != nil {
		t.Fatalf("gitTool resolved despite a hidden backend: %+v", s.gitTool)
	}
	s.cfg.GitUpstreams = map[string]config.GitUpstream{
		"corp": {URL: "https://git.corp.invalid/", Mode: config.UpstreamModeOpen},
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL+"/git/corp/"+gitTestRepo+"/git-upload-pack", "application/x-git-upload-pack-request", strings.NewReader("")) //nolint:noctx // test-owned loopback URL
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST git-upload-pack with no backend = %d, want 405 from the unregistered route", resp.StatusCode)
	}

	getResp, err := http.Get(ts.URL + "/git/corp/" + gitTestRepo + "/info/refs?service=git-upload-pack") //nolint:gosec,noctx // test-owned loopback URL
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = getResp.Body.Close()
	if getResp.StatusCode != http.StatusNotFound {
		t.Errorf("GET info/refs with no backend = %d, want 404", getResp.StatusCode)
	}

	// The bundle route keeps working: it needs no git binary at all.
	key := manifest.GitKey("netbox", "v4.5.7", false)
	if err := s.typeStore(manifest.TypeGit).Put(t.Context(), key, []byte("bundle")); err != nil {
		t.Fatalf("seed bundle: %v", err)
	}
	bundleResp, err := http.Get(ts.URL + "/git/netbox/netbox-v4.5.7.bundle") //nolint:gosec,noctx // test-owned loopback URL
	if err != nil {
		t.Fatalf("GET bundle: %v", err)
	}
	_ = bundleResp.Body.Close()
	if bundleResp.StatusCode != http.StatusOK {
		t.Errorf("GET legacy bundle with no git backend = %d, want 200", bundleResp.StatusCode)
	}
}

// makePartialMirror reproduces what `git clone --mirror` leaves behind when it
// is killed mid-transfer, measured against a real interrupted clone of
// github.com/git/git: HEAD is present and reads "ref: refs/heads/.invalid",
// refs/ is empty, and objects/pack holds a tmp_pack_ that never became a pack.
// A check that took HEAD's presence for completeness would pass on this.
func makePartialMirror(t *testing.T, dir string) {
	t.Helper()
	for _, sub := range []string{"hooks", "info", "refs", filepath.Join("objects", "pack")} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", sub, err)
		}
	}
	files := map[string]string{
		"config":      "[core]\n\tbare = true\n",
		"description": "Unnamed repository\n",
		"HEAD":        "ref: refs/heads/.invalid\n",
		filepath.Join("objects", "pack", "tmp_pack_HMlYFb"): "not a pack\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "HEAD")); err != nil {
		t.Fatalf("the fixture wrote no HEAD; it would not reproduce an interrupted clone: %v", err)
	}
}

// A directory a clone got partway through is not a mirror. os.Stat says it
// exists, git says nothing is in it, and before this the handler served the
// first answer forever: every later request 404d with nothing retrying.
func TestGitSmartRepairsAnInterruptedClone(t *testing.T) {
	upstream := newGitUpstream(t)
	s := newGitServer(t, upstream)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	dir := mirrorDir(s, "corp")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir mirror: %v", err)
	}
	makePartialMirror(t, dir)

	dest := filepath.Join(t.TempDir(), "clone")
	runGitCLI(t, t.TempDir(), "clone", "-q", ts.URL+"/git/corp/"+gitTestRepo, dest)
	if got := runGitCLI(t, dest, "log", "-1", "--format=%s"); got != "first" {
		t.Errorf("cloned HEAD subject = %q, want %q", got, "first")
	}
	if !s.gitMirrorComplete(t.Context(), dir) {
		t.Errorf("mirror at %s is still incomplete after a request", dir)
	}
}

// The git-upload-pack POST is the leg with no refresh behind it: it arrives
// while the info/refs clone is still running, and before this it walked past a
// half-written directory into a 404 with an empty body. It has to block on the
// same key and repair the same way.
func TestGitUploadPackPostRepairsAnInterruptedClone(t *testing.T) {
	upstream := newGitUpstream(t)
	s := newGitServer(t, upstream)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	dir := mirrorDir(s, "corp")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir mirror: %v", err)
	}
	makePartialMirror(t, dir)

	resp, err := http.Post(ts.URL+"/git/corp/"+gitTestRepo+"/git-upload-pack", //nolint:noctx // test-owned loopback URL
		"application/x-git-upload-pack-request", strings.NewReader(""))
	if err != nil {
		t.Fatalf("POST git-upload-pack: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		t.Errorf("POST git-upload-pack over a partial mirror = 404; the leg skipped the repair")
	}
	if !s.gitMirrorComplete(t.Context(), dir) {
		t.Errorf("mirror at %s is still incomplete after the POST leg", dir)
	}
}

// Repointing git_upstreams[ns].url is a forge migration, a host swap or a typo
// correction. Every already-mirrored repository under that namespace has the
// old URL written into its own config, so without this check the mirror keeps
// serving the old forge's history and keeps re-fetching from it.
func TestGitMirrorReclonesWhenTheUpstreamIsRepointed(t *testing.T) {
	first := newGitUpstreamSubject(t, "old forge")
	s := newGitServer(t, first)
	before := httptest.NewServer(s.Handler())

	dest := filepath.Join(t.TempDir(), "before")
	runGitCLI(t, t.TempDir(), "clone", "-q", before.URL+"/git/corp/"+gitTestRepo, dest)
	if got := runGitCLI(t, dest, "log", "-1", "--format=%s"); got != "old forge" {
		t.Fatalf("first clone subject = %q, want %q", got, "old forge")
	}

	// Shut the listener before repointing. The handler reads cfg.GitUpstreams
	// per request and an operator repoints by editing config.json and
	// restarting, so mutating it under a live server would be a race the
	// server never runs.
	before.Close()
	second := newGitUpstreamSubject(t, "new forge")
	s.cfg.GitUpstreams["corp"] = config.GitUpstream{URL: "file://" + second + "/", Mode: config.UpstreamModeOpen}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	after := filepath.Join(t.TempDir(), "after")
	runGitCLI(t, t.TempDir(), "clone", "-q", ts.URL+"/git/corp/"+gitTestRepo, after)
	if got := runGitCLI(t, after, "log", "-1", "--format=%s"); got != "new forge" {
		t.Errorf("clone after repointing = %q, want %q — the mirror still serves the old forge", got, "new forge")
	}
	if got := runGitCLI(t, mirrorDir(s, "corp"), "config", "--get", "remote.origin.url"); got != "file://"+second+"/"+gitTestRepo {
		t.Errorf("mirror origin = %q, want the repointed upstream", got)
	}
}

// net/url keeps the first value of a repeated key and git-http-backend's
// string_list_insert keeps the last, so a duplicated parameter used to read as
// a fetch here and a push in the child.
func TestGitSmartRefusesADuplicatedServiceParameter(t *testing.T) {
	upstream := newGitUpstream(t)
	s := newGitServer(t, upstream)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/git/corp/" + gitTestRepo + "/info/refs?service=git-upload-pack&service=git-receive-pack") //nolint:gosec,noctx // test-owned loopback URL
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("duplicated service parameter = %d, want 403", resp.StatusCode)
	}
	if _, err := os.Stat(mirrorDir(s, "corp")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused push probe created a mirror at %s", mirrorDir(s, "corp"))
	}
}

// The child's QUERY_STRING is rebuilt from the one service the handler
// validated, so there is no repeated key left for the two parsers to disagree
// over.
func TestGitQueryStringIsRebuiltNotForwarded(t *testing.T) {
	for _, tc := range []struct {
		name, service string
		values        []string
		want          string
		ok            bool
	}{
		{"info/refs with the service", gitServiceInfoRefs, []string{gitServiceUploadPack}, "service=git-upload-pack", true},
		{"info/refs with it repeated", gitServiceInfoRefs, []string{gitServiceUploadPack, gitServiceUploadPack}, "service=git-upload-pack", true},
		{"info/refs with no service", gitServiceInfoRefs, nil, "", true},
		{"info/refs naming a service bodega does not serve", gitServiceInfoRefs, []string{"git-archive"}, "", false},
		{"the POST leg, which reads PATH_INFO", gitServiceUploadPack, []string{gitServiceUploadPack}, "", true},
	} {
		got, ok := gitQueryString(tc.service, tc.values)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: gitQueryString(%q, %q) = (%q, %v), want (%q, %v)",
				tc.name, tc.service, tc.values, got, ok, tc.want, tc.ok)
		}
	}
}

// A namespace directory symlinked onto another volume resolves outside
// GIT_PROJECT_ROOT while filepath.Rel still answers "corp/team/tool.git".
// bodega creates its namespace directories with MkdirAll, so this is the
// operator case, not a client-plantable one.
func TestGitSmartRefusesASymlinkedNamespace(t *testing.T) {
	upstream := newGitUpstream(t)
	s := newGitServer(t, upstream)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	elsewhere := t.TempDir()
	if err := os.MkdirAll(s.gitTool.root, 0o750); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(s.gitTool.root, "corp")); err != nil {
		t.Skipf("this filesystem refuses symlinks: %v", err)
	}

	resp, err := http.Get(ts.URL + "/git/corp/" + gitTestRepo + "/info/refs?service=git-upload-pack") //nolint:gosec,noctx // test-owned loopback URL
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET through a symlinked namespace = %d, want 404", resp.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(elsewhere, filepath.FromSlash(gitTestRepo))); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the handler cloned through the symlink into %s", elsewhere)
	}
}

// gitDirWithinRoot has to answer before the mirror exists, which is every
// first clone, and it has to follow the link when it does.
func TestGitDirWithinRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "git")
	if err := os.MkdirAll(filepath.Join(root, "corp"), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	inside := filepath.Join(root, "corp", "team", "tool.git")
	if ok, err := gitDirWithinRoot(root, inside); err != nil || !ok {
		t.Errorf("gitDirWithinRoot(%q) = (%v, %v), want (true, nil) for a path whose leaf does not exist yet", inside, ok, err)
	}

	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(root, "linked")); err != nil {
		t.Skipf("this filesystem refuses symlinks: %v", err)
	}
	linked := filepath.Join(root, "linked", "team", "tool.git")
	if ok, err := gitDirWithinRoot(root, linked); err != nil || ok {
		t.Errorf("gitDirWithinRoot(%q) = (%v, %v), want (false, nil) — it resolves outside the root", linked, ok, err)
	}
}

// A git_upstreams key and an uploaded git package may carry the same name.
// The decision is that this is legal: the two routes coexist by depth, a
// bundle path being two segments under /git/ and a clone path at least four.
// Nothing rejects the pair at startup, because manifest names are runtime data
// and a startup check would refuse a config that was legal when written.
func TestGitBundleAndNamespaceMayShareAName(t *testing.T) {
	upstream := newGitUpstream(t)
	s := newGitServer(t, upstream)
	if err := s.store.AddVersion(t.Context(), manifest.TypeGit, "corp", manifest.VersionEntry{
		URL: "https://forge.example/corp",
		Ref: "v1.2.0",
	}); err != nil {
		t.Fatalf("seed manifest: %v", err)
	}
	if err := s.typeStore(manifest.TypeGit).Put(t.Context(), manifest.GitKey("corp", "v1.2.0", false), []byte("bundle bytes")); err != nil {
		t.Fatalf("seed bundle: %v", err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/git/corp/corp-v1.2.0.bundle") //nolint:gosec,noctx // test-owned loopback URL
	if err != nil {
		t.Fatalf("GET bundle: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "bundle bytes" {
		t.Errorf("bundle GET = %d %q, want 200 %q — the namespace shadowed the package", resp.StatusCode, body, "bundle bytes")
	}

	dest := filepath.Join(t.TempDir(), "clone")
	runGitCLI(t, t.TempDir(), "clone", "-q", ts.URL+"/git/corp/"+gitTestRepo, dest)
	if got := runGitCLI(t, dest, "log", "-1", "--format=%s"); got != "first" {
		t.Errorf("clone under the shared name = %q, want %q — the package shadowed the namespace", got, "first")
	}
}
