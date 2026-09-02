package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
	work := t.TempDir()
	runGitCLI(t, work, "init", "-q", ".")
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("bodega\n"), 0o600); err != nil {
		t.Fatalf("write upstream file: %v", err)
	}
	runGitCLI(t, work, "add", "README.md")
	runGitCLI(t, work, "commit", "-q", "-m", "first")

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
		"QUERY_STRING=service=git-upload-pack",
		"REQUEST_METHOD=POST",
		"CONTENT_TYPE=application/x-git-upload-pack-request",
		"HTTP_CONTENT_ENCODING=gzip",
		"HTTP_USER_AGENT=git/2.50.1",
		"REMOTE_ADDR=203.0.113.7",
		"REMOTE_USER=",
	}
	got := s.gitCGIEnv(r, "/corp/team/tool.git/git-upload-pack")
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

// A host with no git-http-backend gets a WARN naming every path searched, and
// no *gitTool. Failing per request instead would hand the operator a broken
// clone with nothing in the startup log to explain it.
func TestResolveGitToolWarnsAndNamesTheSearch(t *testing.T) {
	hideGitBackend(t)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	if got := resolveGitTool(&config.Config{StoragePath: t.TempDir()}, logger); got != nil {
		t.Fatalf("resolveGitTool = %+v, want nil when git-http-backend is absent", got)
	}
	log := buf.String()
	if !strings.Contains(log, "level=WARN") {
		t.Errorf("resolution failure was not logged at WARN: %s", log)
	}
	for _, want := range []string{"searched", "PATH=", "nowhere"} {
		if !strings.Contains(log, want) {
			t.Errorf("WARN does not name %q: %s", want, log)
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
