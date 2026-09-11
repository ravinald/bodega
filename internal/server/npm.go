package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

func (s *Server) handleNpm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	fullPath := r.PathValue("path")

	// Tarball request: path contains "/-/"
	if idx := strings.Index(fullPath, "/-/"); idx >= 0 {
		pkgName := fullPath[:idx]   // canonical, e.g. "@bitwarden/cli"
		tarball := fullPath[idx+3:] // URL form, e.g. "cli-2026.3.0.tgz"
		w = cachePrivateOn200(w, tarball)

		// Storage uses the safe-encoded form everywhere; the URL does not, so
		// the version has to come back out of the wire filename before a key
		// can be derived. An unparseable filename names no artifact.
		reqVersion := npmVersionFromTarball(pkgName, tarball)
		if reqVersion == "" {
			http.NotFound(w, r)
			return
		}
		storageKey := manifest.NpmTarballKey(pkgName, reqVersion)

		pm, _ := s.store.GetPackage(ctx, manifest.TypeNpm, pkgName)
		if pm != nil {
			if isPackageHidden(pm) {
				http.NotFound(w, r)
				return
			}
			if isVersionHidden(pm, reqVersion) {
				http.NotFound(w, r)
				return
			}
			// 403 (not 404) below — the version exists upstream, we're
			// refusing by policy. Mirrors the gomod path in versionAllowed.
			vc, baseVer := packageVersionConstraint(pm)
			if vc != "" && vc != manifest.ConstraintAny && baseVer != "" {
				if !versionAllowed(baseVer, reqVersion, vc) {
					s.recordVersionRefusal(r, manifest.TypeNpm, pkgName, baseVer, reqVersion, vc)
					http.Error(w, "version not allowed by constraint", http.StatusForbidden)
					return
				}
			}
		}
		if !s.entitleGate(w, r, manifest.TypeNpm, pkgName, reqVersion) {
			return
		}

		upstream := s.cfg.NpmUpstream + "/" + pkgName + "/-/" + tarball
		if pm != nil && packageMode(pm) == manifest.ModeProxy {
			s.proxyOrCache(w, r, s.typeStore(manifest.TypeNpm), storageKey, upstream, manifest.TypeNpm, pkgName, pkgName, true, true)
			return
		}
		if pm == nil {
			s.recordNoManifest(ctx, r, manifest.TypeNpm, pkgName, reqVersion, upstream)
		}
		s.proxyVersion(w, r, manifest.TypeNpm, pkgName, reqVersion, storageKey)
		return
	}

	// Packument request: path is just the package name (possibly scoped).
	noSharedCache(w)
	pkgName := fullPath
	pm, _ := s.store.GetPackage(ctx, manifest.TypeNpm, pkgName)

	if pm != nil && isPackageHidden(pm) {
		http.NotFound(w, r)
		return
	}
	if !s.entitleGate(w, r, manifest.TypeNpm, pkgName, "") {
		return
	}
	permit := profileVersionFilter(s.profileFor(r), manifest.TypeNpm, pkgName)

	w.Header().Set("Content-Type", "application/json")

	// The manifest-filtered packument is still not cached: that path builds its
	// document from the manifest rather than from the upstream's, so what it
	// would write is not the object the key names. The profile filter below
	// runs over the buffered response instead, which is why this path caches:
	// the object stays the upstream packument.
	if pm != nil && (hasHiddenVersion(pm) || hasVersionConstraint(pm)) {
		s.serveFilteredPackument(w, r, pkgName, pm, permit)
		return
	}

	upstream := s.cfg.NpmUpstream + "/" + pkgName
	s3Key := manifest.NpmPackumentKey(pkgName)
	forceProxy := pm != nil && packageMode(pm) == manifest.ModeProxy
	rw := &npmPackumentWriter{ResponseWriter: w, base: s.npmPublicRoot(r), pkg: pkgName, permit: permit}
	s.proxyOrCache(rw, r, s.typeStore(manifest.TypeNpm), s3Key, upstream, manifest.TypeNpm, pkgName, pkgName, false, forceProxy)
	if err := rw.flush(); err != nil {
		s.logger.Error("npm packument response failed", "package", pkgName, "error", err)
	}
}

// npmPublicRoot is the /npm route root on this bodega: the base every
// dist.tarball is rewritten onto.
//
// publicBase, not r.TLS or r.Host on their own. A client consumes these URLs
// rather than reading them, so a wrong scheme here is not cosmetic: it is
// every tarball fetch leaving TLS, which is the defect B19 fixed for cargo.
func (s *Server) npmPublicRoot(r *http.Request) string {
	return s.publicBase(r) + "/npm"
}

// @bitwarden/cli + cli-2026.4.0.tgz → 2026.4.0. "" on unexpected shape.
func npmVersionFromTarball(pkgName, tarball string) string {
	basename := pkgName
	if idx := strings.LastIndex(basename, "/"); idx >= 0 {
		basename = basename[idx+1:]
	}
	prefix := basename + "-"
	if !strings.HasPrefix(tarball, prefix) {
		return ""
	}
	v := strings.TrimPrefix(tarball, prefix)
	v = strings.TrimSuffix(v, ".tgz")
	return v
}

// Silent on unknown versions; the manifest's silence is not a hide.
func isVersionHidden(pm *manifest.PackageManifest, version string) bool {
	for _, ve := range pm.Versions {
		if ve.Version == version || ve.Ref == version {
			return ve.Hidden
		}
	}
	return false
}

func hasHiddenVersion(pm *manifest.PackageManifest) bool {
	for _, ve := range pm.Versions {
		if ve.Hidden {
			return true
		}
	}
	return false
}

func hasVersionConstraint(pm *manifest.PackageManifest) bool {
	vc, baseVer := packageVersionConstraint(pm)
	return vc != "" && vc != manifest.ConstraintAny && baseVer != ""
}

func (s *Server) serveFilteredPackument(w http.ResponseWriter, r *http.Request, pkgName string, pm *manifest.PackageManifest, permit func(string) bool) {
	upstream := s.cfg.NpmUpstream + "/" + pkgName
	data, ct, err := fetchUpstream(r.Context(), upstream)
	if err != nil {
		s.logger.Error("packument fetch failed", "url", upstream, "error", err)
		http.Error(w, "upstream fetch failed", http.StatusBadGateway)
		return
	}

	filtered, err := filterPackumentByManifest(data, pm)
	if err != nil {
		s.logger.Error("packument filter failed", "pkg", pkgName, "error", err)
		http.Error(w, "packument filter failed", http.StatusInternalServerError)
		return
	}

	filtered, err = filterPackumentByProfile(filtered, permit)
	if err != nil {
		s.logger.Error("packument profile filter failed", "pkg", pkgName, "error", err)
		http.Error(w, "packument filter failed", http.StatusInternalServerError)
		return
	}

	// The same rewrite the unfiltered path applies, through the same function.
	// A client whose package trips the filter and one whose package does not
	// have to be told the same URL for the same version; two composition sites
	// is two that can drift.
	filtered, err = rewriteNpmPackument(filtered, s.npmPublicRoot(r), pkgName)
	if err != nil {
		s.logger.Error("packument rewrite failed", "pkg", pkgName, "error", err)
		http.Error(w, "packument rewrite failed", http.StatusBadGateway)
		return
	}

	if ct == "" {
		ct = "application/json"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(filtered)))
	w.WriteHeader(http.StatusOK)
	//nolint:gosec // G705: filtered is the JSON packument body; Content-Type set to application/json above.
	_, _ = w.Write(filtered)
}

// Strip hidden + out-of-constraint versions (and any dist-tags pointing at
// them) from a raw npm packument, so clients never see a version we'd
// refuse to serve.
func filterPackumentByManifest(body []byte, pm *manifest.PackageManifest) ([]byte, error) {
	hidden := make(map[string]bool)
	for _, ve := range pm.Versions {
		if ve.Hidden && ve.Version != "" {
			hidden[ve.Version] = true
		}
	}

	vc, baseVer := packageVersionConstraint(pm)
	hasConstraint := vc != "" && vc != manifest.ConstraintAny && baseVer != ""

	if len(hidden) == 0 && !hasConstraint {
		return body, nil
	}

	return filterPackumentVersions(body, func(v string) bool {
		if hidden[v] {
			return true
		}
		return hasConstraint && !versionAllowed(baseVer, v, vc)
	})
}

// npmPackumentWriter buffers a proxied packument so every dist.tarball can be
// pointed back at bodega before the client sees it.
//
// Served as it arrives, a packument names registry.npmjs.org. pacote replaces
// the origin and keeps the upstream path, so the client asks bodega for
// /<pkg>/-/<file> with no /npm prefix and gets a 404 — and on a deployment
// where the path happened to line up it would get the tarball from a request
// bodega never sees, past the hidden-package and hidden-version checks, the
// version constraint, the audit row and the cache write, all of which live in
// handleNpm's tarball branch.
//
// The rewrite runs after the cache write, not before it. Rewriting first would
// store one instance's public_url in the cached object: wrong the moment that
// key changes, wrong for every other instance the moment two share a store,
// and it would stop the cached copy being evidence of what the registry
// published. The cost is a parse per packument request, paid on the metadata
// path only — no artifact goes through here.
//
// Buffering rather than streaming: a JSON value cannot be rewritten from a
// chunk that may have split it in half. proxyOrCache has already spooled the
// bytes to disk and written them to the cache before the first Write lands
// here, so nothing about spool_max_artifact_bytes changes — a packument that
// is refused by the spool today is still refused there, and one served today
// is still served. What the buffer adds is one in-memory copy, capped at
// maxUpstreamBody so a stream bounded by the spool does not become an
// unbounded allocation. Over that cap the response is refused rather than
// relayed unrewritten, which is the same ceiling and the same answer the
// filtered path already gives through fetchUpstream.
//
// It is not an http.Flusher and has no ReadFrom. Both would defeat the buffer.
type npmPackumentWriter struct {
	http.ResponseWriter
	base string // bodega's own /npm root
	pkg  string // the package name the client asked for
	// permit is the profile's version rule for this package, nil when no
	// profile governs it. Applied before the tarball rewrite, so a version the
	// profile refuses never acquires a bodega URL to be fetched by.
	permit func(string) bool
	status int
	body   bytes.Buffer
	tooBig bool
}

func (p *npmPackumentWriter) WriteHeader(code int) {
	if p.status == 0 {
		p.status = code
	}
}

func (p *npmPackumentWriter) Write(b []byte) (int, error) {
	if p.status == 0 {
		p.status = http.StatusOK
	}
	if int64(p.body.Len()+len(b)) > maxUpstreamBody {
		p.tooBig = true
		p.body.Reset()
		// An error rather than a silent discard: it stops the copy at the
		// ceiling instead of reading the rest of a body nothing will use, and
		// no status line has gone out yet, so flush can still refuse.
		return 0, fmt.Errorf("packument for %s exceeds bodega's %d-byte rewrite buffer", p.pkg, maxUpstreamBody)
	}
	return p.body.Write(b)
}

// flush rewrites a successful packument and writes the buffered response
// through. A refusal or an error passes untouched: those bodies carry no
// tarball URLs, and a 403 from the allow-list must reach the client as the
// handler wrote it.
func (p *npmPackumentWriter) flush() error {
	if p.status == 0 {
		p.status = http.StatusOK
	}
	body := p.body.Bytes()
	if p.status == http.StatusOK {
		if p.tooBig {
			err := fmt.Errorf("packument for %s exceeds bodega's %d-byte rewrite buffer: serving it unrewritten would point the client at the upstream registry", p.pkg, maxUpstreamBody)
			http.Error(p.ResponseWriter, err.Error(), http.StatusBadGateway)
			return err
		}
		filtered, err := filterPackumentByProfile(body, p.permit)
		if err != nil {
			http.Error(p.ResponseWriter, "packument filter failed", http.StatusBadGateway)
			return err
		}
		rewritten, err := rewriteNpmPackument(filtered, p.base, p.pkg)
		if err != nil {
			http.Error(p.ResponseWriter, "packument rewrite failed", http.StatusBadGateway)
			return err
		}
		body = rewritten
		// proxyS3 sets ETag from the stored object, which is the upstream
		// document rather than what is going out. Left on, it labels the
		// rewritten body with a validator for different bytes.
		p.Header().Del("ETag")
	}
	p.Header().Set("Content-Length", strconv.Itoa(len(body)))
	p.ResponseWriter.WriteHeader(p.status)
	//nolint:gosec // G705: body is the JSON packument; Content-Type is set by the handler.
	_, err := p.ResponseWriter.Write(body)
	return err
}

// npmPackageNamePattern is the npm registry constraint on package names,
// applied to the name the upstream document carries because that name is what
// a rewritten URL is composed from. A registry that answered with a name
// containing path syntax would otherwise choose the route bodega hands its own
// clients.
var npmPackageNamePattern = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$`)

// rewriteNpmPackument points every dist.tarball in a packument at this
// bodega's /npm route. base is npmPublicRoot; pkgName is the package the
// client asked for, used when the document names no usable name of its own.
//
// The document's own name wins where it is one npm would accept, so the
// version-manifest route (/npm/{pkg}/{version}, which carries a top-level
// dist) composes the package's URL rather than the request path's.
//
// Numbers survive as they were written: json.Number rather than float64, so
// re-serializing does not reformat a field bodega never read.
func rewriteNpmPackument(body []byte, base, pkgName string) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse packument for %s: %w", pkgName, err)
	}

	name := pkgName
	if n, ok := doc["name"].(string); ok && npmPackageNamePattern.MatchString(n) {
		name = n
	}
	prefix := base + "/" + npmEscapeName(name) + "/-/"

	rewriteNpmDistTarball(doc, prefix)
	if versions, ok := doc["versions"].(map[string]any); ok {
		for _, v := range versions {
			if entry, ok := v.(map[string]any); ok {
				rewriteNpmDistTarball(entry, prefix)
			}
		}
	}
	return json.Marshal(doc)
}

// rewriteNpmDistTarball points one version entry's dist.tarball at bodega,
// keeping the filename the upstream published.
//
// The filename is the only part of the upstream URL that carries information
// bodega needs: its own tarball route parses the version back out of it and
// composes the upstream URL from npm_upstream. So the host and path the
// document arrived with are dropped rather than edited, and a packument whose
// tarballs already live on a private registry or a CDN rewrites the same way
// registry.npmjs.org's does.
//
// An entry naming no file is left as it stands: a rewrite that cannot name a
// target is a guess, and bodega's route would 404 it anyway.
func rewriteNpmDistTarball(entry map[string]any, prefix string) {
	dist, ok := entry["dist"].(map[string]any)
	if !ok {
		return
	}
	tarball, ok := dist["tarball"].(string)
	if !ok || tarball == "" {
		return
	}
	u, err := url.Parse(tarball)
	if err != nil {
		return
	}
	file := path.Base(u.EscapedPath())
	if file == "" || file == "." || file == "/" {
		return
	}
	dist["tarball"] = prefix + file
}

// npmEscapeName renders a package name into a URL path, leaving the scope
// separator a separator: "@scope/pkg" is two path segments on the wire and
// handleNpm splits the request back on "/-/" to recover it.
func npmEscapeName(name string) string {
	parts := strings.Split(name, "/")
	for i, seg := range parts {
		parts[i] = url.PathEscape(seg)
	}
	return strings.Join(parts, "/")
}
