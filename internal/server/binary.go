package server

import (
	"net/http"
)

// ---- Binaries --------------------------------------------------------------

// handleBinary proxies /binaries/{path...} → S3 binaries/{path}
func (s *Server) handleBinary(w http.ResponseWriter, r *http.Request) {
	p := r.PathValue("path")
	if !isSafePath(p) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	key := "binaries/" + p
	s.proxyS3(w, r, key)
}
