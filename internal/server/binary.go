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
	// Storage first, shape second. An install whose backend never came up owes
	// the operator a 503 naming that; a 404 would send them looking for a
	// package that is sitting right there.
	if !s.requireStorage(w, s.typeStore(manifest.TypeBinary)) {
		return
	}
	pkg, version, filename := binaryPathIdentity(p)
	if pkg == "" {
		// Not a shape the uploader writes, so no key can be derived for it.
		http.NotFound(w, r)
		return
	}
	s.proxyVersion(w, r, manifest.TypeBinary, pkg, version, manifest.BinaryKey(pkg, version, filename))
}

// binaryPathIdentity recovers the manifest entry that owns a binaries/ key.
// The uploader writes <name>/<version>/<file>, dropping the version segment
// for an entry that has none, so a two-segment path yields an empty version
// rather than mistaking the filename for one. Any other segment count names
// nothing and returns an empty package.
func binaryPathIdentity(p string) (pkg, version, filename string) {
	parts := strings.Split(p, "/")
	switch len(parts) {
	case 2:
		return parts[0], "", parts[1]
	case 3:
		return parts[0], parts[1], parts[2]
	}
	return "", "", ""
}
