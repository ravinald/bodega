package server

import (
	"net/http"
	"strings"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// ---- Git bundles -----------------------------------------------------------

// handleGitBundle serves a bundle or release archive from the key the uploader
// wrote, rebuilt from the ref parsed out of the request rather than pasted
// from it.
//
// This is the legacy git route. Smart-HTTP under /git/{namespace}/ is what a
// git client speaks; /git/{name}/{file} predates it and stays because scripts
// fetch those bundles by URL. The two do not collide: a bundle path is two
// segments and a clone path is at least four.
//
// The ref recovered here is also the manifest entry's identity, which is what
// lets the read resolve through the backend the version records rather than
// through the type rule. Resolving by type was safe only while nothing could
// place one git package away from the rest of its type, and 'bodega pkg move'
// writes VersionEntry.Storage directly.
func (s *Server) handleGitBundle(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	file := r.PathValue("file")
	if !isSafePath(name) || !isSafePath(file) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	// Storage first, shape second, so a backend that never came up is reported
	// as such instead of as a missing package.
	if !s.requireStorage(w, s.typeStore(manifest.TypeGit)) {
		return
	}
	ref, release, ok := gitRefFromFile(name, file)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w = cacheImmutableOn200(w, file)
	s.proxyVersion(w, r, manifest.TypeGit, name, ref, manifest.GitKey(name, ref, release))
}

// handleGitNamespace answers /git/<namespace>/<path...>, the namespaced form
// that maps onto a configured upstream forge.
//
// It resolves the namespace and hands the rest to the smart-HTTP handler. A
// namespace no config names 404s and leaves a discovery row, which is the
// operator-facing half: a request for a namespace no config names is a request
// for a key nobody added, and that is the fact worth recording.
//
// A configured namespace still 404s when git-http-backend did not resolve at
// startup. That is the same answer this handler gave before smart-HTTP existed,
// and the startup WARN naming the search is where the operator learns why.
//
// The two-segment bundle route (/git/{name}/{file}) is more specific than this
// pattern and keeps winning for the paths it already served.
func (s *Server) handleGitNamespace(w http.ResponseWriter, r *http.Request) {
	ns, rest, ok := splitNamespace(strings.TrimPrefix(r.URL.Path, "/git/"))
	if !ok {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	gu, configured := s.cfg.GitUpstreams[ns]
	if !configured {
		// pattern_hint and pkg_name are both the namespace: the actionable
		// unit is the key an operator would add to git_upstreams, and keying
		// the row on the full request path would let any client grow the
		// table one row per URL it invents.
		s.recordDiscoveryRaw(r.Context(), r, manifest.TypeGit, "", ns, ns, "", audit.DecisionNoNamespace, "")
		http.NotFound(w, r)
		return
	}
	if s.gitTool == nil {
		http.NotFound(w, r)
		return
	}
	s.handleGitSmart(w, r, ns, rest, gu)
}

// splitNamespace splits a namespaced upstream path into its first segment and
// the remainder: "github/torvalds/linux.git" > ("github", "torvalds/linux.git").
//
// It is the one splitter, called by every handler that resolves a namespace
// rather than reimplemented next to each. The namespace becomes a directory
// name and the remainder is appended to an upstream URL, so both halves escape
// their tree if a traversal survives: ok is false for an empty or absolute
// path, and for anything isSafePath refuses.
func splitNamespace(p string) (namespace, rest string, ok bool) {
	if strings.HasPrefix(p, "/") || !isSafePath(p) {
		return "", "", false
	}
	namespace, rest, _ = strings.Cut(p, "/")
	if namespace == "" || namespace == "." {
		return "", "", false
	}
	for _, el := range strings.Split(rest, "/") {
		if el == "." {
			return "", "", false
		}
	}
	return namespace, rest, true
}

// gitRefFromFile recovers the ref from a bundle or release-archive filename.
// The uploader writes <name>-<ref>.bundle for a clone and <name>-<ref>.tar.gz
// for a release; a filename carrying neither shape names no object.
func gitRefFromFile(name, file string) (ref string, release, ok bool) {
	rest, found := strings.CutPrefix(file, name+"-")
	if !found {
		return "", false, false
	}
	if r, found := strings.CutSuffix(rest, ".bundle"); found && r != "" {
		return r, false, true
	}
	if r, found := strings.CutSuffix(rest, ".tar.gz"); found && r != "" {
		return r, true, true
	}
	return "", false, false
}
