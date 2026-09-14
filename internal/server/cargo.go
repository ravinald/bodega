package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/ravinald/bodega/internal/builder"
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
//
// The base comes from publicBase, not from r.TLS. cargo consumes these URLs
// rather than displaying them, so a plaintext dl behind a terminating proxy is
// not a cosmetic error: every crate download leaves TLS.
func (s *Server) handleCargoConfig(w http.ResponseWriter, r *http.Request) {
	base := s.publicBase(r) + "/cargo"
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
	noSharedCache(w)
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

	// The sparse index names no version, so it is decided at the membership
	// level here and by version in the filter below.
	if !s.entitleGate(w, r, manifest.TypeCargo, crate, "") {
		return
	}
	permit := profileVersionFilter(s.profileFor(r), manifest.TypeCargo, crate)

	// A hosted entry is bodega's own claim about the crate, so the index line
	// is generated from it rather than fetched. Proxied instead, every hosted
	// crate 404s on the route cargo resolves through while its /download route
	// serves the bytes to nobody who can find them.
	//
	// Mode, not merely the presence of an entry: a proxy-mode entry names the
	// versions somebody pinned, not the versions crates.io publishes, and a
	// document generated from it would hide the rest.
	if pm != nil && packageMode(pm) != manifest.ModeProxy {
		s.serveManifestCargoIndex(w, r, crate, pm, permit)
		return
	}

	upstream := strings.TrimRight(s.cfg.CargoUpstream, "/") + "/" + p
	s3Key := manifest.CargoIndexKey(p)
	forceProxy := pm != nil && packageMode(pm) == manifest.ModeProxy
	if permit == nil {
		s.proxyOrCache(w, r, s.typeStore(manifest.TypeCargo), s3Key, upstream, manifest.TypeCargo, crate, crate, false, forceProxy)
		return
	}
	rw := &indexFilterWriter{
		ResponseWriter: w,
		subject:        "the cargo index for " + crate,
		filter:         func(b []byte) []byte { return filterCargoIndex(b, permit) },
	}
	s.proxyOrCache(rw, r, s.typeStore(manifest.TypeCargo), s3Key, upstream, manifest.TypeCargo, crate, crate, false, forceProxy)
	if err := rw.flush(); err != nil {
		s.logger.Error("cargo index response failed", "crate", crate, "error", err)
	}
}

// cargoIndexLine is one line of cargo's sparse-index document. The field
// order is the one crates.io publishes: cargo reads by name, a person reading
// a line does not.
type cargoIndexLine struct {
	Name string `json:"name"`
	Vers string `json:"vers"`
	// Always empty: bodega records no cargo dependency metadata, and a
	// resolver fed a dependency list nobody uploaded resolves against a claim
	// this server cannot support. The cost is that a hosted crate needing a
	// dependency fails to compile, since cargo fetches what this line names
	// and nothing else. Stated as a gap in docs/USAGE.md, tracked in #356.
	Deps     []cargoIndexDep     `json:"deps"`
	Cksum    string              `json:"cksum"`
	Features map[string][]string `json:"features"`
	Yanked   bool                `json:"yanked"`
}

// cargoIndexDep is the dependency record cargo's sparse protocol defines.
// Declared so deps serializes as a typed empty list rather than as null, which
// cargo refuses to deserialize.
type cargoIndexDep struct {
	Name            string   `json:"name"`
	Req             string   `json:"req"`
	Features        []string `json:"features"`
	Optional        bool     `json:"optional"`
	DefaultFeatures bool     `json:"default_features"`
	Target          *string  `json:"target"`
	Kind            string   `json:"kind"`
}

// serveManifestCargoIndex answers a sparse-index document out of the manifest
// store, with no upstream in the path at all.
//
// A version is dropped when it is hidden, when the entry's constraint excludes
// it, or when no sha256 can be established for its crate. The last is not
// caution: cargo verifies every download against cksum and reports a mismatch
// as a corrupt crate, which sends whoever hits it looking at their disk rather
// than at this registry.
func (s *Server) serveManifestCargoIndex(w http.ResponseWriter, r *http.Request, crate string, pm *manifest.PackageManifest, permit func(string) bool) {
	ctx := r.Context()
	vc, baseVer := packageVersionConstraint(pm)
	hasConstraint := vc != "" && vc != manifest.ConstraintAny && baseVer != ""

	var out bytes.Buffer
	for _, ve := range pm.Versions {
		if ve.Version == "" || ve.Hidden {
			continue
		}
		if hasConstraint && !versionAllowed(baseVer, ve.Version, vc) {
			continue
		}
		cksum := s.cargoCksum(ctx, crate, ve)
		if cksum == "" {
			s.logger.Warn("cargo index line dropped: no sha256 for the crate",
				"crate", crate, "version", ve.Version)
			continue
		}
		line, err := json.Marshal(cargoIndexLine{
			Name:     crate,
			Vers:     ve.Version,
			Deps:     []cargoIndexDep{},
			Cksum:    cksum,
			Features: map[string][]string{},
		})
		if err != nil {
			s.logger.Error("cargo index line failed to marshal", "crate", crate, "version", ve.Version, "error", err)
			continue
		}
		out.Write(line)
		out.WriteByte('\n')
	}

	// The same profile filter that runs over a proxied index, through the same
	// function. A generated document that skipped it would hand a scoped host
	// the versions its profile excludes.
	body := filterCargoIndex(out.Bytes(), permit)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	//nolint:gosec // G705: body is the generated NDJSON index; Content-Type is set above.
	_, _ = w.Write(body)
}

// cargoCksum is the sha256 cargo verifies a download against.
//
// The recorded checksum first: `bodega build fetch` writes one for every crate
// it pulls, so the stored bytes are read only for an entry that arrived some
// other way. That read is the whole crate on a metadata request, which is why
// it is the fallback and not the source — and why a missing checksum is not
// made up from nothing.
func (s *Server) cargoCksum(ctx context.Context, crate string, ve manifest.VersionEntry) string {
	if cs := ve.Checksum; cs != nil && cs.Algorithm == "sha256" && isSHA256Hex(cs.Value) {
		return strings.ToLower(cs.Value)
	}
	store, err := s.versionStore(ctx, manifest.TypeCargo, crate, ve.Version)
	if err != nil || store == nil {
		return ""
	}
	data, err := store.Get(ctx, manifest.CargoCrateKey(crate, ve.Version))
	if err != nil || data == nil {
		return ""
	}
	return builder.ComputeBytesSHA256(data)
}

// isSHA256Hex reports whether v is a full hex sha256 digest. A truncated or
// otherwise malformed value is not a checksum cargo can use.
func isSHA256Hex(v string) bool {
	raw, err := hex.DecodeString(v)
	return err == nil && len(raw) == sha256.Size
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

	if !s.entitleGate(w, r, manifest.TypeCargo, crate, version) {
		return
	}

	w = cachePrivateOn200(w, path.Base(p))
	// cargo_dl_upstream, not cargo_upstream: the sparse index host serves the
	// index and nothing else, and crates.io names the download root separately
	// in the index's own config.json.
	upstream := strings.TrimRight(s.cfg.CargoDLUpstream, "/") + "/" + crate + "/" + version + "/download"
	s3Key := manifest.CargoCrateKey(crate, version)
	forceProxy := pm == nil || packageMode(pm) == manifest.ModeProxy
	// A hosted crate reads from the backend its entry records; a proxied one
	// has no entry to record anything, so it caches under the type rule.
	store, err := s.versionStore(ctx, manifest.TypeCargo, crate, version)
	if err != nil {
		s.logger.Error("storage backend recorded for artifact is not configured",
			"type", manifest.TypeCargo, "package", crate, "version", version, "error", err)
		http.Error(w, "storage backend error", http.StatusBadGateway)
		return
	}
	s.proxyOrCache(w, r, store, s3Key, upstream, manifest.TypeCargo, crate, crate, true, forceProxy)
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
