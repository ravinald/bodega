package server

import (
	"net/http"
)

// ---- Git bundles -----------------------------------------------------------

// handleGitBundle proxies /git/{name}/{file} → S3 repos/{name}/{file}
func (s *Server) handleGitBundle(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	file := r.PathValue("file")
	if !isSafePath(name) || !isSafePath(file) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	key := "repos/" + name + "/" + file
	setCacheImmutable(w, file)
	s.proxyS3(w, r, key)
}
