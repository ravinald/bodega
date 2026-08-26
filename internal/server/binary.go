package server

import (
	"net/http"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
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
	pkg, version := binaryPathIdentity(p)
	s.proxyVersion(w, r, manifest.TypeBinary, pkg, version, key)
}

// binaryPathIdentity recovers the manifest entry that owns a binaries/ key.
// The uploader writes <name>/<version>/<file>, dropping the version segment
// for an entry that has none, so a two-segment path yields an empty version
// rather than mistaking the filename for one.
func binaryPathIdentity(p string) (pkg, version string) {
	parts := strings.Split(p, "/")
	switch len(parts) {
	case 2:
		return parts[0], ""
	case 3:
		return parts[0], parts[1]
	}
	return "", ""
}
