package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/ravinald/bodega/internal/builder"
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

	// Packument request: the path is the package name, followed on the
	// version-manifest route by the version segment.
	//
	// The manifest is looked up under the package rather than under the whole
	// path. Under the path, /npm/left-pad/1.3.0 finds no entry and every
	// policy below it — the hidden package, the hidden version, the
	// constraint — is decided by a lookup that was never going to hit (#319).
	noSharedCache(w)
	pkgName := npmPackageFromPath(fullPath)
	reqVersion := strings.TrimPrefix(strings.TrimPrefix(fullPath, pkgName), "/")
	pm, _ := s.store.GetPackage(ctx, manifest.TypeNpm, pkgName)

	if pm != nil {
		if isPackageHidden(pm) {
			http.NotFound(w, r)
			return
		}
		// The same two refusals the tarball branch makes, in the same shape:
		// 404 for a hidden version, 403 for one the constraint excludes.
		if reqVersion != "" {
			if isVersionHidden(pm, reqVersion) {
				http.NotFound(w, r)
				return
			}
			vc, baseVer := packageVersionConstraint(pm)
			if vc != "" && vc != manifest.ConstraintAny && baseVer != "" && !versionAllowed(baseVer, reqVersion, vc) {
				s.recordVersionRefusal(r, manifest.TypeNpm, pkgName, baseVer, reqVersion, vc)
				http.Error(w, "version not allowed by constraint", http.StatusForbidden)
				return
			}
		}
	}
	if !s.entitleGate(w, r, manifest.TypeNpm, pkgName, reqVersion) {
		return
	}
	permit := profileVersionFilter(s.profileFor(r), manifest.TypeNpm, pkgName)

	w.Header().Set("Content-Type", "application/json")

	// A hosted entry is bodega's own claim about the package, so the document
	// is generated from it rather than fetched. Proxying it instead is what
	// 404s every hosted npm package on an install with proxy_cache_enabled
	// false: the tarballs are already here and nothing but this document tells
	// a client where they are.
	//
	// Mode, not merely the presence of an entry. A proxy-mode entry exists to
	// say "this comes from upstream", and its manifest names the versions
	// somebody pinned rather than the versions the registry publishes —
	// generated from it, the document would hide every other release while the
	// tarball route went on serving them.
	if pm != nil && packageMode(pm) != manifest.ModeProxy {
		s.serveManifestPackument(w, r, pkgName, reqVersion, pm, permit)
		return
	}

	// The manifest-filtered packument is still not cached: that path builds its
	// document from the manifest rather than from the upstream's, so what it
	// would write is not the object the key names. The profile filter below
	// runs over the buffered response instead, which is why this path caches:
	// the object stays the upstream packument.
	if pm != nil && (hasHiddenVersion(pm) || hasVersionConstraint(pm)) {
		s.serveFilteredPackument(w, r, fullPath, pkgName, pm, permit)
		return
	}

	// fullPath upstream and in the key, pkgName everywhere a package is named.
	// The version-manifest route and the packument are two documents, and one
	// cache key for both would serve whichever was fetched first.
	upstream := s.cfg.NpmUpstream + "/" + fullPath
	s3Key := manifest.NpmPackumentKey(fullPath)
	forceProxy := pm != nil && packageMode(pm) == manifest.ModeProxy
	rw := &npmPackumentWriter{ResponseWriter: w, base: s.npmPublicRoot(r), pkg: fullPath, permit: permit}
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

// reqPath is what the client asked for and pkgName is the package it names:
// the two differ on the version-manifest route, where the upstream document to
// fetch is the version's and the package every filter is keyed on is not.
func (s *Server) serveFilteredPackument(w http.ResponseWriter, r *http.Request, reqPath, pkgName string, pm *manifest.PackageManifest, permit func(string) bool) {
	upstream := s.cfg.NpmUpstream + "/" + reqPath
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

// serveManifestPackument answers a packument out of the manifest store, with
// no upstream in the path at all.
//
// What bodega records about a version is the version, its checksum and where
// its tarball lives. Everything else an upstream packument carries —
// dependencies, engines, publish times — is absent rather than invented: a
// client resolves against this document, and a dependency list bodega guessed
// would be a claim nobody uploaded. A hosted package with dependencies needs
// each of them hosted too, which is the same requirement the tarball route has
// always had.
//
// reqVersion is set on the version-manifest route, where npm asks for one
// version and expects that version's object rather than the whole document.
func (s *Server) serveManifestPackument(w http.ResponseWriter, r *http.Request, pkgName, reqVersion string, pm *manifest.PackageManifest, permit func(string) bool) {
	body, err := json.Marshal(npmPackumentFromManifest(pkgName, s.npmPublicRoot(r), pm))
	if err != nil {
		s.logger.Error("packument generation failed", "pkg", pkgName, "error", err)
		http.Error(w, "packument generation failed", http.StatusInternalServerError)
		return
	}

	// The two filters the proxied document goes through, in the same order and
	// through the same functions. A generated document that skipped them would
	// serve a scoped host the versions its profile excludes, and would be the
	// one npm path where hiding a version did nothing.
	if body, err = filterPackumentByManifest(body, pm); err != nil {
		s.logger.Error("packument filter failed", "pkg", pkgName, "error", err)
		http.Error(w, "packument filter failed", http.StatusInternalServerError)
		return
	}
	if body, err = filterPackumentByProfile(body, permit); err != nil {
		s.logger.Error("packument profile filter failed", "pkg", pkgName, "error", err)
		http.Error(w, "packument filter failed", http.StatusInternalServerError)
		return
	}

	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		s.logger.Error("packument reparse failed", "pkg", pkgName, "error", err)
		http.Error(w, "packument generation failed", http.StatusInternalServerError)
		return
	}
	versions, _ := doc["versions"].(map[string]any)

	if reqVersion != "" {
		entry, ok := versions[reqVersion]
		if !ok {
			http.NotFound(w, r)
			return
		}
		doc = map[string]any{}
		if m, ok := entry.(map[string]any); ok {
			doc = m
		}
	} else if latest := npmLatestVersion(versions); latest != "" {
		// After the filters, never before. A dist-tag is written last because
		// latest has to name a version that survived them: pointed at one the
		// profile removed, `npm install <pkg>` resolves what this host is
		// refused and fails on the tarball.
		doc["dist-tags"] = map[string]any{"latest": latest}
	}

	body, err = json.Marshal(doc)
	if err != nil {
		s.logger.Error("packument generation failed", "pkg", pkgName, "error", err)
		http.Error(w, "packument generation failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	//nolint:gosec // G705: body is the generated JSON packument; Content-Type is set by the handler.
	_, _ = w.Write(body)
}

// npmPackumentFromManifest renders every version an entry records. base is
// npmPublicRoot, so dist.tarball composes exactly as rewriteNpmPackument
// composes it for a proxied document: a client must not be told two URLs for
// one version depending on which path answered.
//
// An entry whose version is a floating dist-tag names no artifact — the
// builder resolves it at fetch time and leaves the entry alone — so it is
// skipped rather than published as a version literally called "latest".
func npmPackumentFromManifest(pkgName, base string, pm *manifest.PackageManifest) map[string]any {
	versions := map[string]any{}
	for _, ve := range pm.Versions {
		if ve.Version == "" || isNpmFloatingVersion(ve.Version) {
			continue
		}
		dist := map[string]any{
			"tarball": base + "/" + npmEscapeName(pkgName) + "/-/" + npmTarballFilename(pkgName, ve.Version),
		}
		if integrity := npmIntegrity(ve.Checksum); integrity != "" {
			dist["integrity"] = integrity
		}
		entry := map[string]any{
			"name":    pkgName,
			"version": ve.Version,
			"dist":    dist,
		}
		if desc := firstNonEmpty(ve.Description, pm.Description); desc != "" {
			entry["description"] = desc
		}
		versions[ve.Version] = entry
	}
	doc := map[string]any{"name": pkgName, "versions": versions}
	if pm.Description != "" {
		doc["description"] = pm.Description
	}
	return doc
}

// isNpmFloatingVersion reports the dist-tag spellings the builder accepts in
// place of a version.
func isNpmFloatingVersion(v string) bool {
	return v == "latest"
}

// npmTarballFilename is the name the tarball route parses a version back out
// of: the package basename, so a scoped package drops its scope.
func npmTarballFilename(pkgName, version string) string {
	basename := pkgName
	if idx := strings.LastIndex(basename, "/"); idx >= 0 {
		basename = basename[idx+1:]
	}
	return basename + "-" + version + ".tgz"
}

// npmIntegrity renders a recorded sha256 as the subresource-integrity string
// npm checks a tarball against.
//
// Empty for anything else, including a digest under another algorithm. npm
// fails a mismatch as a corrupt download rather than as a metadata problem, so
// an integrity field bodega cannot stand behind costs more than none at all.
func npmIntegrity(cs *manifest.Checksum) string {
	if cs == nil || cs.Algorithm != "sha256" {
		return ""
	}
	raw, err := hex.DecodeString(cs.Value)
	if err != nil || len(raw) != sha256.Size {
		return ""
	}
	return "sha256-" + base64.StdEncoding.EncodeToString(raw)
}

// npmLatestVersion is the highest version left in a generated packument.
//
// A version no semver parse can place is skipped rather than ordered by
// string, which is an ordering only by accident: with nothing placeable the
// document carries no dist-tags at all, and npm asks for an explicit version
// instead of installing whichever one sorted last.
func npmLatestVersion(versions map[string]any) string {
	best := ""
	var bestSV builder.SemVer
	for v := range versions {
		sv, ok := builder.ParseSemVer(v)
		if !ok {
			continue
		}
		if best == "" || bestSV.Less(sv) {
			best, bestSV = v, sv
		}
	}
	return best
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

// npmPackageFromPath recovers the package a /npm request names, dropping the
// trailing version segment the version-manifest route carries.
//
// The shape is unambiguous because a scope is the only thing that puts a slash
// in a package name: no slash is a bare packument, one slash is either a
// scoped packument or "<pkg>/<version>" depending on the leading @, and two is
// "@scope/pkg/<version>". Go decodes %2f before PathValue, so a scoped name
// arrives here already canonical.
//
// The request path and not the document's own name. Preferring the document
// was how the version segment ended up inside a composed tarball prefix for a
// legacy uppercase name, since such a name fails npm's own pattern and fell
// back to the raw path. It also let an upstream answering /npm/victim with
// {"name":"other"} move every rewritten URL onto /npm/other/-/, which is a
// substitution no pattern catches: "other" is a perfectly legal name.
func npmPackageFromPath(fullPath string) string {
	scoped := strings.HasPrefix(fullPath, "@")
	parts := strings.Split(fullPath, "/")
	switch {
	case scoped && len(parts) > 2:
		return parts[0] + "/" + parts[1]
	case !scoped && len(parts) > 1:
		return parts[0]
	}
	return fullPath
}

// rewriteNpmPackument points every dist.tarball in a packument at this
// bodega's /npm route. base is npmPublicRoot; pkgName is the request path,
// which npmPackageFromPath reduces to the package.
//
// Both routes reach here: the packument route, whose path is the package, and
// the version-manifest route (/npm/{pkg}/{version}), whose path carries a
// version segment that must not land inside the composed prefix.
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

	prefix := base + "/" + npmEscapeName(npmPackageFromPath(pkgName)) + "/-/"

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
