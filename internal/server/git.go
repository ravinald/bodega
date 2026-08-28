package server

import (
	"net/http"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

// ---- Git bundles -----------------------------------------------------------

// handleGitBundle serves a bundle or release archive from the key the uploader
// wrote, rebuilt from the ref parsed out of the request rather than pasted
// from it.
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
	setCacheImmutable(w, file)
	s.proxyVersion(w, r, manifest.TypeGit, name, ref, manifest.GitKey(name, ref, release))
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
