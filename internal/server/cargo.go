package server

import (
	"encoding/json"
	"net/http"
	"path"
	"regexp"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

// ---- Cargo sparse registry -------------------------------------------------
//
// Bodega serves cargo's sparse-HTTP registry protocol (default in cargo ≥ 1.70).
// Three URL shapes flow through `/cargo/{path...}`:
//
//   /cargo/config.json                 — synthesized; tells cargo where downloads live.
//   /cargo/<a>/<b>/<crate>             — sparse index NDJSON (mutable, TTL'd).
//     plus the short-name special cases:
//        /cargo/1/<crate>              — 1-character crate names
//        /cargo/2/<crate>              — 2-character crate names
//        /cargo/3/<first>/<crate>      — 3-character crate names
//   /cargo/<crate>/<version>/download  — crate tarball (immutable, content-addressed).
//
// Crate names are lowercased by cargo before request; we reject any path that
// contains uppercase or non-spec characters as a defense-in-depth measure.

// cargoCrateNamePattern is the cargo registry constraint on crate names.
// (https://doc.rust-lang.org/cargo/reference/manifest.html#the-name-field)
var cargoCrateNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// cargoVersionPattern is a permissive semver-ish check; cargo handles the
// strict parsing client-side so we only need to refuse path-traversal.
var cargoVersionPattern = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)

// handleCargoConfig synthesizes the registry config endpoint that cargo
// fetches on first contact. We point both the download and api URLs at our
// own /cargo prefix so cargo never reaches upstream directly.
func (s *Server) handleCargoConfig(w http.ResponseWriter, r *http.Request) {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	base := scheme + "://" + r.Host + "/cargo"
	resp := struct {
		DL  string `json:"dl"`
		API string `json:"api"`
	}{
		DL:  base + "/{crate}/{version}/download",
		API: base,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleCargo dispatches sparse-index and crate-download requests. The split
// happens here rather than via separate routes because cargo's URL shapes
// overlap on segment count for short crate names.
func (s *Server) handleCargo(w http.ResponseWriter, r *http.Request) {
	p := r.PathValue("path")
	if p == "" {
		http.NotFound(w, r)
		return
	}
	if p == "config.json" {
		s.handleCargoConfig(w, r)
		return
	}

	// Crate download: trailing /<version>/download (4+ segments).
	if strings.HasSuffix(p, "/download") {
		s.handleCargoDownload(w, r, p)
		return
	}

	// Otherwise: sparse index lookup. The trailing path segment is the crate
	// name regardless of which short-name shape we received.
	s.handleCargoIndex(w, r, p)
}

func (s *Server) handleCargoIndex(w http.ResponseWriter, r *http.Request, p string) {
	crate, ok := cargoCrateFromIndexPath(p)
	if !ok {
		http.Error(w, "invalid cargo index path", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	pm, _ := s.store.GetPackage(ctx, manifest.TypeCargo, crate)
	if pm != nil && isPackageHidden(pm) {
		http.NotFound(w, r)
		return
	}

	upstream := strings.TrimRight(s.cfg.CargoUpstream, "/") + "/" + p
	s3Key := "cargo/index/" + p
	forceProxy := pm != nil && packageMode(pm) == manifest.ModeProxy
	s.proxyOrCache(w, r, s3Key, upstream, manifest.TypeCargo, crate, crate, false, forceProxy)
}

func (s *Server) handleCargoDownload(w http.ResponseWriter, r *http.Request, p string) {
	// Path shape: <crate>/<version>/download.
	parts := strings.Split(p, "/")
	if len(parts) != 3 || parts[2] != "download" {
		http.Error(w, "invalid cargo download path", http.StatusBadRequest)
		return
	}
	crate, version := parts[0], parts[1]
	if !cargoCrateNamePattern.MatchString(crate) || !cargoVersionPattern.MatchString(version) {
		http.Error(w, "invalid cargo crate or version", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	pm, _ := s.store.GetPackage(ctx, manifest.TypeCargo, crate)
	if pm != nil {
		if isPackageHidden(pm) {
			http.NotFound(w, r)
			return
		}
		if isVersionHidden(pm, version) {
			http.NotFound(w, r)
			return
		}
	}

	setCacheImmutable(w, path.Base(p))
	upstream := strings.TrimRight(s.cfg.CargoUpstream, "/") + "/" + crate + "/" + version + "/download"
	s3Key := "cargo/crates/" + crate + "-" + version + ".crate"
	forceProxy := pm == nil || packageMode(pm) == manifest.ModeProxy
	s.proxyOrCache(w, r, s3Key, upstream, manifest.TypeCargo, crate, crate, true, forceProxy)
}

// cargoCrateFromIndexPath validates the sparse-index path shape and returns
// the crate name. Accepts the four spec-defined forms:
//
//	1/<crate>                  (1 char)
//	2/<crate>                  (2 chars)
//	3/<first-char>/<crate>     (3 chars)
//	<aa>/<bb>/<crate>          (4+ chars, aa = first 2, bb = chars 3-4)
func cargoCrateFromIndexPath(p string) (string, bool) {
	parts := strings.Split(p, "/")
	switch len(parts) {
	case 2:
		// "1/<crate>" or "2/<crate>"
		if (parts[0] == "1" && len(parts[1]) == 1) || (parts[0] == "2" && len(parts[1]) == 2) {
			if cargoCrateNamePattern.MatchString(parts[1]) {
				return parts[1], true
			}
		}
		return "", false
	case 3:
		crate := parts[2]
		if !cargoCrateNamePattern.MatchString(crate) {
			return "", false
		}
		// "3/<first-char>/<crate>"
		if parts[0] == "3" && len(crate) == 3 && len(parts[1]) == 1 && parts[1] == string(crate[0]) {
			return crate, true
		}
		// "<aa>/<bb>/<crate>" — 4+ char crates
		if len(parts[0]) == 2 && len(parts[1]) == 2 && len(crate) >= 4 &&
			parts[0] == crate[:2] && parts[1] == crate[2:4] {
			return crate, true
		}
		return "", false
	}
	return "", false
}
