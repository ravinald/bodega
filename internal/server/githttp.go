package server

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// ---- Git smart-HTTP --------------------------------------------------------

// The two smart-HTTP endpoints bodega answers. A clone is a GET of info/refs
// followed by a POST of git-upload-pack; nothing else in the protocol is
// needed to read a repository, and every other suffix 404s.
const (
	gitServiceInfoRefs    = "info/refs"
	gitServiceUploadPack  = "git-upload-pack"
	gitServiceReceivePack = "git-receive-pack"
)

// gitFetchStamp records when a mirror last completed a fetch. git writes no
// single file whose mtime means "the whole mirror is current" — FETCH_HEAD is
// absent after a --mirror clone and the directory mtime moves for reasons that
// have nothing to do with the upstream — so the stamp is bodega's own.
const gitFetchStamp = ".bodega-fetched"

// gitBackendTimeout is the hard ceiling on one git-http-backend child.
// exec.CommandContext already ties the child to the request, so a client that
// hangs up kills it; this bound covers the other direction, where the client
// waits patiently while the child does not finish. Five minutes is longer than
// any healthy upload-pack negotiation against a local mirror (the expensive
// half, cloning from the real upstream, happens before the exec and is bounded
// separately) and short enough that a wedged child cannot outlive a deploy.
const gitBackendTimeout = 5 * time.Minute

// gitCloneTimeout and gitFetchTimeout bound the two git(1) invocations that
// reach the network. A first mirror of a large forge repository is minutes of
// transfer, so it gets the wider bound; a refresh of an existing mirror moves
// far less and fails faster when the upstream is gone.
const (
	gitCloneTimeout = 15 * time.Minute
	gitFetchTimeout = 5 * time.Minute
)

// gitConfigTimeout bounds the two local git invocations that inspect a mirror
// before it is served: the rev-parse that separates a finished clone from an
// interrupted one, and the config read that compares its recorded origin
// against the configured upstream. Neither touches the network, and both run
// on the request path, so a hung invocation is a wedged request.
const gitConfigTimeout = 10 * time.Second

// gitPathInfoPattern is the shape PATH_INFO must have before any exec. It
// admits a namespace, a repository path ending in .git, and one of the two
// smart-HTTP suffixes: no shell metacharacters, no query string smuggled
// through the path, no suffix bodega does not serve.
var gitPathInfoPattern = regexp.MustCompile(`^/[A-Za-z0-9._/-]+\.git/(info/refs|git-upload-pack)$`)

// gitPathInfoOK is the shape half of the two path checks.
//
// The pattern's character class contains "." and "/", so ".." matches it. The
// CGI child resolves PATH_INFO against GIT_PROJECT_ROOT itself, and a ".." that
// reached it would resolve outside — so the traversal refusal is spelled out
// here rather than left to the pattern or to git-http-backend's own hygiene.
//
// This is one of two checks, not the check. It sees only the string; the
// gitDirWithinRoot test in handleGitSmart follows symlinks on the path that
// string produces, which is what catches a namespace directory an operator
// linked onto another volume.
func gitPathInfoOK(pathInfo string) bool {
	return gitPathInfoPattern.MatchString(pathInfo) && !strings.Contains(pathInfo, "..")
}

// gitTool holds everything the smart-HTTP path executes, resolved once when
// the server is constructed.
//
// Resolving here rather than per request is a security property, not a
// performance one: a runtime exec.LookPath means the binary a request runs
// depends on the PATH the process happened to inherit, and an operator
// debugging a bad response at 03:00 has no way to find out which binary
// answered. A nil *gitTool means the smart-HTTP route was never registered.
type gitTool struct {
	git     string // git(1), for the mirror clone and refresh
	backend string // git-http-backend, the CGI that speaks the protocol
	root    string // GIT_PROJECT_ROOT: <storage_path>/git
}

// gitBackendCandidates are the fixed locations git-http-backend ships in when
// it is not on PATH. It is not a PATH binary on most platforms: git installs
// it in libexec and finds it through `git --exec-path`, which resolveGitTool
// consults first. macOS adds two more roots because the Xcode and Command Line
// Tools copies of git live outside the filesystem hierarchy standard.
var gitBackendCandidates = []string{
	"/usr/lib/git-core/git-http-backend",
	"/usr/libexec/git-core/git-http-backend",
	"/opt/homebrew/Cellar/git/*/libexec/git-core/git-http-backend",
	"/usr/local/Cellar/git/*/libexec/git-core/git-http-backend",
	"/Library/Developer/CommandLineTools/usr/libexec/git-core/git-http-backend",
	"/Applications/Xcode.app/Contents/Developer/usr/libexec/git-core/git-http-backend",
}

// resolveGitTool finds git(1) and git-http-backend, or returns nil after
// logging every path it looked in.
//
// Returning nil is the whole point of the function. A server that registers
// the smart-HTTP route and then fails per request tells an operator nothing
// until a client complains; one that refuses the route at startup and names
// the search says what to install before anyone clones.
//
// Both refusals log at Error because both unregister a route: the shipped
// default log_level prints only Error, so a Warn saying "clone is disabled"
// said it to nobody.
func resolveGitTool(cfg *config.Config, logger *slog.Logger) *gitTool {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		logger.Error("git not found on PATH — git smart-HTTP is disabled; the /git/{name}/{file} bundle route is unaffected",
			"searched", os.Getenv("PATH"), "error", err)
		return nil
	}

	var searched []string
	backend := ""
	if p, lookErr := exec.LookPath("git-http-backend"); lookErr == nil {
		backend = p
	} else {
		searched = append(searched, "PATH="+os.Getenv("PATH"))
	}
	if backend == "" {
		// `git --exec-path` is the authoritative answer for the git that is
		// actually installed, which a fixed candidate list cannot be: Homebrew
		// puts it under a Cellar path that carries the version number.
		if out, execErr := exec.Command(gitPath, "--exec-path").Output(); execErr == nil {
			cand := filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")
			searched = append(searched, cand)
			if st, statErr := os.Stat(cand); statErr == nil && !st.IsDir() {
				backend = cand
			}
		}
	}
	for _, pattern := range gitBackendCandidates {
		if backend != "" {
			break
		}
		searched = append(searched, pattern)
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			if st, statErr := os.Stat(m); statErr == nil && !st.IsDir() {
				backend = m
				break
			}
		}
	}
	if backend == "" {
		logger.Error("git-http-backend not found — git smart-HTTP is disabled; install git's libexec helpers to enable 'git clone' through bodega. The /git/{name}/{file} bundle route is unaffected",
			"searched", strings.Join(searched, ", "))
		return nil
	}

	root := filepath.Join(firstNonEmpty(cfg.StoragePath, config.DefaultStoragePath), "git")
	logger.Info("git smart-HTTP enabled", "git", gitPath, "git_http_backend", backend, "git_project_root", root)
	return &gitTool{git: gitPath, backend: backend, root: root}
}

// firstNonEmpty returns the first non-empty argument, or "".
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// handleGitSmart answers one smart-HTTP request against a configured
// namespace: it validates the shape, honors the namespace's mode, enforces the
// allow-list, ensures a local mirror exists, and execs git-http-backend
// against it.
//
// ns and rest come from splitNamespace, which has already refused traversal
// and absolute paths. Everything after that is this function's own hygiene,
// because the string reaches both a filesystem path and a child process.
func (s *Server) handleGitSmart(w http.ResponseWriter, r *http.Request, ns, rest string, gu config.GitUpstream) {
	ctx := r.Context()

	// Layer two of the push refusal. Layer one is http.receivepack=false in
	// every mirror bodega creates; this one holds when that config drifts, and
	// catches the info/refs probe a client makes before it ever POSTs.
	//
	// Every occurrence of the parameter, not the first: Query().Get returns the
	// first value while git-http-backend's own parser keeps the last, so
	// "?service=git-upload-pack&service=git-receive-pack" reads as a fetch here
	// and as a push in the child.
	serviceParams := r.URL.Query()["service"]
	if strings.HasSuffix(rest, "/"+gitServiceReceivePack) || slices.Contains(serviceParams, gitServiceReceivePack) {
		// A write attempt by a caller who already passed the read gate, which
		// is the same question "who was turned away" asks of every other
		// refusal. The namespace is the subject; the repository is in the path
		// the row's details carry.
		recordDenialFor(s.auditDB, r, manifest.TypeGit, ns, "", audit.DenialPushRefused, nil)
		http.Error(w, "bodega mirrors are read-only; pushes are refused", http.StatusForbidden)
		return
	}

	repo, service, ok := gitSmartService(rest)
	if !ok {
		// Not smart-HTTP. No path is computed and no child is started for a
		// suffix bodega does not serve.
		http.NotFound(w, r)
		return
	}
	if (service == gitServiceInfoRefs) != (r.Method == http.MethodGet) {
		w.Header().Set("Allow", methodForGitService(service))
		http.Error(w, "method not allowed for this git endpoint", http.StatusMethodNotAllowed)
		return
	}
	query, ok := gitQueryString(service, serviceParams)
	if !ok {
		http.Error(w, "bodega serves git-upload-pack only", http.StatusForbidden)
		return
	}

	// pkgName is the manifest name catalog mode looks up and the name
	// 'discover promote --as manifest' writes an entry under. The two have to
	// be the same string or promoting a no_manifest row leaves the 404 in
	// place. The upstream keeps the .git suffix; the manifest name drops it.
	pkgName := ns + "/" + strings.TrimSuffix(repo, ".git")
	upstream := gu.URL + repo

	if gu.Mode != config.UpstreamModeOpen {
		if !s.gitCataloged(ctx, pkgName) {
			s.recordNoManifest(ctx, r, manifest.TypeGit, pkgName, "", upstream)
			http.NotFound(w, r)
			return
		}
	}

	// pkg_version is empty on every git row: a clone negotiates over many refs
	// at once, so no single version names what was asked for. F1's promote
	// turns the versionless row into one entry with version_constraint "any".
	// Recorded on the info/refs leg only. Both legs of one clone pass through
	// here and RecordDiscovery upserts, so recording both would file one clone
	// as two requests against a table every other type fills per request.
	if !s.enforceUpstreamPolicyRecording(w, r, manifest.TypeGit, upstream, upstream, pkgName, "", service == gitServiceInfoRefs) {
		return
	}

	pathInfo := "/" + ns + "/" + repo + "/" + service
	if !gitPathInfoOK(pathInfo) {
		http.NotFound(w, r)
		return
	}
	dir := filepath.Join(s.gitTool.root, filepath.FromSlash(ns), filepath.FromSlash(repo))
	within, err := gitDirWithinRoot(s.gitTool.root, dir)
	if err != nil || !within {
		// The pattern above catches the shape of the string; this catches
		// where that string lands once symlinks are followed.
		s.logger.Warn("git smart-HTTP path resolved outside GIT_PROJECT_ROOT",
			"namespace", ns, "repo", repo, "root", s.gitTool.root, "dir", dir, "error", err)
		http.NotFound(w, r)
		return
	}

	if err := s.ensureGitMirror(ctx, ns+"/"+repo, dir, upstream); err != nil {
		// The git error carries the upstream URL and local paths, so it goes
		// to the log and never to the client.
		s.logger.Error("git mirror clone failed",
			"namespace", ns, "repo", repo, "dir", dir, "upstream", upstream, "error", err)
		http.Error(w, "could not mirror this repository from its upstream — check the bodega server log for the git error, and confirm the upstream exists and is public", http.StatusBadGateway)
		return
	}
	if service == gitServiceInfoRefs {
		s.refreshGitMirror(ns, repo, dir)
	}

	s.runGitBackend(w, r, ns, repo, pathInfo, query)
}

// gitQueryString is the QUERY_STRING the CGI child gets. It is rebuilt from
// the one service this handler validated rather than forwarded from the
// request, so the two parsers have nothing to disagree about: net/url keeps
// the first value of a repeated key and git-http-backend's string_list_insert
// keeps the last.
//
// A POST carries its service in PATH_INFO and the child ignores the query
// entirely, so that leg gets an empty string. An info/refs GET with no service
// parameter is a dumb-protocol probe and keeps getting the empty string it
// always got.
func gitQueryString(service string, values []string) (string, bool) {
	if service != gitServiceInfoRefs || len(values) == 0 {
		return "", true
	}
	for _, v := range values {
		if v != gitServiceUploadPack {
			return "", false
		}
	}
	return "service=" + gitServiceUploadPack, true
}

// gitDirWithinRoot reports whether dir resolves inside root once symlinks are
// followed.
//
// filepath.Rel is string arithmetic over cleaned paths and never reads the
// filesystem, so on its own it answers "corp/team/tool.git" for a namespace
// directory an operator symlinked onto another volume, and GIT_HTTP_EXPORT_ALL
// then exports whatever is on the far end. A mirror path does not exist before
// its first clone, so the resolution runs against the deepest ancestor of it
// that does.
func gitDirWithinRoot(root, dir string) (bool, error) {
	realRoot, err := resolveExistingAncestor(root)
	if err != nil {
		return false, err
	}
	realDir, err := resolveExistingAncestor(dir)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(realRoot, realDir)
	if err != nil {
		return false, err
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)), nil
}

// resolveExistingAncestor evaluates symlinks on the deepest ancestor of p that
// exists and re-joins the components that do not. filepath.EvalSymlinks fails
// outright on a path whose leaf is missing, which every mirror path is until
// its clone lands.
func resolveExistingAncestor(p string) (string, error) {
	missing := ""
	for cur := filepath.Clean(p); ; {
		resolved, err := filepath.EvalSymlinks(cur)
		if err == nil {
			return filepath.Join(resolved, missing), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", err
		}
		missing = filepath.Join(filepath.Base(cur), missing)
		cur = parent
	}
}

// gitCataloged reports whether a manifest entry names exactly this path.
//
// The name equality test is not redundant with the lookup. Store keys fold a
// slash to "--", so a request for "octocat--Hello-World" resolves the manifest
// written for "octocat/Hello-World" and would clone an upstream nobody
// cataloged. Catalog mode exists to make that impossible.
func (s *Server) gitCataloged(ctx context.Context, pkgName string) bool {
	pm, err := s.store.GetPackage(ctx, manifest.TypeGit, pkgName)
	if err != nil {
		s.logger.Error("git catalog lookup failed", "package", pkgName, "error", err)
		return false
	}
	return pm != nil && pm.Name == pkgName
}

// methodForGitService returns the one method each smart-HTTP endpoint accepts.
func methodForGitService(service string) string {
	if service == gitServiceInfoRefs {
		return http.MethodGet
	}
	return http.MethodPost
}

// gitSmartService splits a namespaced path into the repository directory and
// the smart-HTTP suffix it carries.
//
// A repository path must end in .git, which is what the clone URL a client
// types produces. Requiring it keeps the served namespace and the mirror
// directory the same shape, and leaves every other path under /git/ free.
func gitSmartService(rest string) (repo, service string, ok bool) {
	switch {
	case strings.HasSuffix(rest, "/"+gitServiceUploadPack):
		service = gitServiceUploadPack
	case strings.HasSuffix(rest, "/"+gitServiceInfoRefs):
		service = gitServiceInfoRefs
	default:
		return "", "", false
	}
	repo = strings.TrimSuffix(rest, "/"+service)
	if !strings.HasSuffix(repo, ".git") || repo == ".git" {
		return "", "", false
	}
	return repo, service, true
}

// ensureGitMirror clones the upstream on first request and does nothing on
// every request after.
//
// The clone is serialized per repository so twenty concurrent first clones
// produce one `git clone --mirror`. It runs on its own deadline rather than
// the request's: the clients queued behind the lock all lose the mirror if the
// first one hangs up, and the next request would start the same clone over.
//
// What is on disk is inspected rather than counted. `git clone --mirror`
// creates the destination at the start of the transfer, so a restart, an OOM
// kill or a RemoveAll that lost to a permission error leaves a directory that
// exists, holds no refs and answers every later request with a 404 forever.
func (s *Server) ensureGitMirror(ctx context.Context, key, dir, upstream string) error {
	if ok, _ := s.gitMirrorUsable(ctx, dir, upstream); ok {
		return nil
	}

	unlock := s.gitClone.lock(key)
	defer unlock()
	// The second look is what covers the git-upload-pack POST that arrives
	// while the info/refs clone is still running: it blocks here rather than
	// racing past a half-written directory into a 404 with an empty body.
	ok, why := s.gitMirrorUsable(ctx, dir, upstream)
	if ok {
		return nil
	}
	if why != "" {
		s.logger.Warn("discarding the mirror on disk and cloning again", "dir", dir, "upstream", upstream, "reason", why)
	}
	// A failed removal is the error the operator needs. Left unreported it is
	// the permanent 404 this whole function exists to prevent.
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove unusable mirror %s: %w", dir, err)
	}

	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return fmt.Errorf("create mirror parent directory %s: %w", filepath.Dir(dir), err)
	}
	cloneCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), gitCloneTimeout)
	defer cancel()

	// http.receivepack=false is the first of the two push refusals, written
	// into the mirror itself so GIT_HTTP_EXPORT_ALL cannot make it writable.
	out, err := s.runGit(cloneCtx, "", "clone", "--mirror", "--quiet",
		"--config", "http.uploadpack=true",
		"--config", "http.receivepack=false",
		"--", upstream, dir)
	if err != nil {
		// A partial mirror that survives answers later requests with a
		// truncated history, which is worse than the 502 this produces.
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			s.logger.Error("could not remove the partial mirror left by a failed clone — later requests would serve a truncated history from it",
				"dir", dir, "error", rmErr)
		}
		return fmt.Errorf("git clone --mirror %s: %w: %s", upstream, err, out)
	}
	s.stampGitFetch(dir)
	return nil
}

// gitMirrorUsable reports whether dir holds a mirror this request may serve
// and, when it does not, why — the reason goes in the log line that precedes
// the re-clone. An empty reason with a false verdict means nothing is there
// yet: a first clone, not a repair.
//
// Two ways to fail. A directory git got partway through has neither HEAD nor
// the fetch stamp, both of which a finished mirror has. And a mirror whose
// recorded origin is no longer the configured upstream is the old forge's
// history: after an operator repoints git_upstreams[ns].url for a migration,
// a host swap or a typo correction, every already-mirrored repository under
// that namespace would otherwise keep serving and keep re-fetching from the
// URL the first clone wrote.
func (s *Server) gitMirrorUsable(ctx context.Context, dir, upstream string) (bool, string) {
	if _, err := os.Stat(dir); err != nil {
		return false, ""
	}
	if !s.gitMirrorComplete(ctx, dir) {
		return false, "HEAD resolves to nothing and there is no fetch stamp, so a clone was interrupted before it finished"
	}
	if origin := s.gitMirrorOrigin(ctx, dir); origin != "" && origin != upstream {
		return false, fmt.Sprintf("the mirror records origin %s, which is not the configured upstream %s", origin, upstream)
	}
	return true, ""
}

// gitMirrorComplete reports whether dir holds a mirror git finished writing.
//
// The fetch stamp is the cheap answer and the usual one: bodega writes it after
// every successful clone and refresh, so a stat settles it without an exec.
//
// Without a stamp, ask git. The presence of HEAD proves nothing — `git clone`
// runs `git init` in the destination before it fetches anything, so an
// interrupted clone leaves a HEAD reading "ref: refs/heads/.invalid" beside an
// empty refs/ and a tmp_pack_* still in objects/. rev-parse resolves HEAD,
// which needs the refs and the objects behind them, and that is the line
// between a mirror and a directory git got partway through.
//
// It is also what keeps a mirror written before the stamp existed, or one
// whose stamp write lost to a permission error, from being destroyed and
// cloned again on the next request.
func (s *Server) gitMirrorComplete(ctx context.Context, dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, gitFetchStamp)); err == nil {
		return true
	}
	revCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), gitConfigTimeout)
	defer cancel()
	_, err := s.runGit(revCtx, dir, "rev-parse", "--verify", "--quiet", "HEAD")
	return err == nil
}

// gitMirrorOrigin returns the upstream the mirror itself records, or "" when
// it cannot be read.
//
// "" is deliberately indistinguishable from a match: a mirror whose config is
// unreadable is served rather than destroyed, because re-cloning on a
// transient read failure trades a stale answer for no answer at all.
func (s *Server) gitMirrorOrigin(ctx context.Context, dir string) string {
	cfgCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), gitConfigTimeout)
	defer cancel()
	out, err := s.runGit(cfgCtx, dir, "config", "--get", "remote.origin.url")
	if err != nil {
		s.logger.Warn("could not read the mirror's recorded origin; serving it without comparing against the configured upstream",
			"dir", dir, "error", err, "git_output", out)
		return ""
	}
	return out
}

// refreshGitMirror re-fetches a mirror that has gone stale, best effort.
//
// Staleness is governed by metadata_ttl, the same interval the proxy cache
// uses for a mutable object. A refs advertisement is exactly that: a mutable
// listing whose freshness the operator already tuned in one place.
//
// A failed fetch serves what is on disk rather than failing the request, and
// still stamps: an upstream that has gone away otherwise costs one failed
// fetch per request instead of one per TTL.
func (s *Server) refreshGitMirror(ns, repo, dir string) {
	if s.gitMirrorFresh(dir) {
		return
	}
	unlock := s.gitClone.lock(ns + "/" + repo)
	defer unlock()
	if s.gitMirrorFresh(dir) {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), gitFetchTimeout)
	defer cancel()
	if out, err := s.runGit(ctx, dir, "remote", "update", "--prune"); err != nil {
		s.logger.Warn("git mirror refresh failed; serving the history already on disk",
			"namespace", ns, "repo", repo, "dir", dir, "error", err, "git_output", out)
	}
	s.stampGitFetch(dir)
}

// gitMirrorFresh reports whether the mirror fetched within metadata_ttl.
// A missing stamp is stale, so a mirror created before the stamp existed
// refreshes once and then behaves.
func (s *Server) gitMirrorFresh(dir string) bool {
	fi, err := os.Stat(filepath.Join(dir, gitFetchStamp))
	return err == nil && time.Since(fi.ModTime()) < s.cache.MetadataTTL
}

// stampGitFetch records the fetch time. Failure is logged and ignored: a
// mirror that cannot be stamped refreshes more often than it needs to, which
// is the harmless direction.
func (s *Server) stampGitFetch(dir string) {
	stamp := filepath.Join(dir, gitFetchStamp)
	f, err := os.OpenFile(stamp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		s.logger.Warn("could not write the mirror fetch stamp; this mirror will refresh on every request",
			"stamp", stamp, "error", err)
		return
	}
	_ = f.Close()
	_ = os.Chtimes(stamp, time.Now(), time.Now())
}

// runGit executes git(1) with an explicit environment, in dir when dir is set,
// and returns its combined output for the log.
//
// The environment is the same shape the CGI child gets and for the same
// reason: no PATH, no HOME, no inherited GIT_* that could repoint the config,
// the object store or the credential helper. GIT_TERMINAL_PROMPT=0 turns a
// private upstream into an immediate failure rather than a child blocked on a
// username prompt until the timeout fires — bodega clones public upstreams
// only, so there is no credential to supply.
func (s *Server) runGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, s.gitTool.git, args...)
	cmd.Dir = dir
	cmd.Env = []string{
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

// runGitBackend execs git-http-backend as a CGI child and streams its response.
//
// The child gets an explicit environment and nothing else: no inherited PATH,
// no HOME, and no GIT_* beyond GIT_PROJECT_ROOT and GIT_HTTP_EXPORT_ALL. An
// inherited GIT_DIR repoints the repository the child serves and an inherited
// PATH decides which helpers it runs, neither of which shows up in a diff, so
// gitCGIEnv builds the list rather than appending to os.Environ.
func (s *Server) runGitBackend(w http.ResponseWriter, r *http.Request, ns, repo, pathInfo, query string) {
	ctx, cancel := context.WithTimeout(r.Context(), gitBackendTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.gitTool.backend)
	cmd.Env = s.gitCGIEnv(r, pathInfo, query)
	cmd.Dir = s.gitTool.root
	cmd.Stdin = r.Body
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		s.logger.Error("could not open a pipe to git-http-backend", "namespace", ns, "repo", repo, "error", err)
		http.Error(w, "git backend unavailable", http.StatusInternalServerError)
		return
	}
	if err := cmd.Start(); err != nil {
		s.logger.Error("could not start git-http-backend",
			"binary", s.gitTool.backend, "namespace", ns, "repo", repo, "error", err)
		http.Error(w, "git backend unavailable", http.StatusInternalServerError)
		return
	}

	wrote, copyErr := writeCGIResponse(w, stdout)
	if copyErr != nil {
		// Drain the rest so the child is not blocked writing into a pipe
		// nobody reads while Wait blocks on it.
		_, _ = io.Copy(io.Discard, stdout)
	}
	waitErr := cmd.Wait()

	if waitErr != nil || copyErr != nil {
		// A CGI child emits filesystem paths and upstream URLs on stderr.
		// It is logged with the namespace and the repository path, and never
		// written to the response.
		s.logger.Warn("git-http-backend failed",
			"namespace", ns, "repo", repo, "path_info", pathInfo,
			"git_stderr", stderr.String(), "exit_error", waitErr, "response_error", copyErr)
	}
	if !wrote {
		http.Error(w, "the git backend produced no response — see the bodega server log for the git error", http.StatusBadGateway)
	}
}

// gitCGIEnv is the complete environment of the git-http-backend child. Every
// variable is listed here; nothing is inherited. Assert this list in a test,
// not in a comment.
func (s *Server) gitCGIEnv(r *http.Request, pathInfo, query string) []string {
	return []string{
		"GIT_PROJECT_ROOT=" + s.gitTool.root,
		"GIT_HTTP_EXPORT_ALL=1",
		"PATH_INFO=" + pathInfo,
		"QUERY_STRING=" + query,
		"REQUEST_METHOD=" + r.Method,
		"CONTENT_TYPE=" + r.Header.Get("Content-Type"),
		"HTTP_CONTENT_ENCODING=" + r.Header.Get("Content-Encoding"),
		"HTTP_USER_AGENT=" + r.UserAgent(),
		"REMOTE_ADDR=" + ClientIP(r),
		// Empty and present on purpose: git-http-backend reads REMOTE_USER for
		// the pusher identity, and bodega authenticates no git client.
		"REMOTE_USER=",
	}
}

// writeCGIResponse translates the child's CGI header block onto w and streams
// the body after it. wrote reports whether a status line reached the client,
// which is the only thing that decides whether the caller may still write an
// error of its own.
func writeCGIResponse(w http.ResponseWriter, out io.Reader) (wrote bool, err error) {
	br := bufio.NewReader(out)
	status := http.StatusOK
	for {
		line, readErr := br.ReadString('\n')
		if readErr != nil {
			return false, fmt.Errorf("read CGI header block: %w", readErr)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		name, value, found := strings.Cut(line, ":")
		if !found {
			return false, fmt.Errorf("malformed CGI header %q", line)
		}
		value = strings.TrimSpace(value)
		if strings.EqualFold(name, "Status") {
			code, _, _ := strings.Cut(value, " ")
			n, convErr := strconv.Atoi(code)
			if convErr != nil {
				return false, fmt.Errorf("malformed CGI Status header %q", value)
			}
			status = n
			continue
		}
		w.Header().Add(name, value)
	}
	w.WriteHeader(status)
	_, err = io.Copy(newFlushWriter(w), br)
	return true, err
}

// flushWriter pushes each chunk out as it arrives. git sends sideband progress
// during a long upload-pack, and a client whose http.lowSpeedLimit is set gives
// up on a connection that goes quiet while the response sits in a buffer.
type flushWriter struct {
	w io.Writer
	f http.Flusher
}

func newFlushWriter(w http.ResponseWriter) io.Writer {
	f, _ := w.(http.Flusher)
	return &flushWriter{w: w, f: f}
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if fw.f != nil {
		fw.f.Flush()
	}
	return n, err
}

// keyedMutex serializes work per key and forgets a key once nothing holds it.
//
// A plain map of mutexes grows one entry per key forever, and an open
// namespace lets a client invent keys. Reference counting keeps the map the
// size of the work actually in flight.
type keyedMutex struct {
	mu sync.Mutex
	m  map[string]*keyedLock
}

type keyedLock struct {
	mu   sync.Mutex
	refs int
}

// lock blocks until key is free and returns the function that releases it.
func (k *keyedMutex) lock(key string) func() {
	k.mu.Lock()
	if k.m == nil {
		k.m = make(map[string]*keyedLock)
	}
	l, ok := k.m[key]
	if !ok {
		l = &keyedLock{}
		k.m[key] = l
	}
	l.refs++
	k.mu.Unlock()

	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		k.mu.Lock()
		l.refs--
		if l.refs == 0 {
			delete(k.m, key)
		}
		k.mu.Unlock()
	}
}
