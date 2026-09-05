package server

import (
	"context"
	"fmt"
	"html"
	"net/url"
	"path"
	"regexp"
	"strings"

	"net/http"

	"github.com/ravinald/bodega/internal/manifest"
)

// ---- PyPI ------------------------------------------------------------------

// handlePypiIndex generates a PEP 503 root index listing all packages found
// under the pypi/wheels/ S3 prefix.
func (s *Server) handlePypiIndex(w http.ResponseWriter, r *http.Request) {
	if !s.requireStorage(w, s.typeStore(manifest.TypePypi)) {
		return
	}
	keys, err := s.listFanout(r.Context(), manifest.TypePypi, manifest.PypiWheelPrefix)
	if err != nil {
		s.logger.Error("list wheels failed", "error", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}

	names := uniquePackageNames(keys)

	// Filter out hidden packages.
	var visible []string
	for _, n := range names {
		pkg, _ := s.store.GetPackage(r.Context(), manifest.TypePypi, n)
		if pkg != nil && isPackageHidden(pkg) {
			continue
		}
		visible = append(visible, n)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, "<!DOCTYPE html>\n<html>\n  <head><title>Simple Index</title></head>\n  <body>\n")
	for _, n := range visible {
		_, _ = fmt.Fprintf(w, "    <a href=\"/pypi/simple/%s/\">%s</a>\n", html.EscapeString(n), html.EscapeString(n))
	}
	_, _ = fmt.Fprintf(w, "  </body>\n</html>\n")
}

// handlePypiPackage generates a PEP 503 per-package index listing wheel files.
func (s *Server) handlePypiPackage(w http.ResponseWriter, r *http.Request) {
	if !s.requireStorage(w, s.typeStore(manifest.TypePypi)) {
		return
	}
	pkgName := r.PathValue("package")
	if pkg, _ := s.store.GetPackage(r.Context(), manifest.TypePypi, pkgName); pkg != nil && isPackageHidden(pkg) {
		http.NotFound(w, r)
		return
	}
	normalized := normalizePkgName(pkgName)

	keys, err := s.listFanout(r.Context(), manifest.TypePypi, manifest.PypiWheelPrefix)
	if err != nil {
		s.logger.Error("list wheels failed", "error", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}

	// Collect matching wheel paths. We keep the path relative to "pypi/wheels/"
	// so links work with versioned subdirs (e.g. "0.4.6/boto3-1.35.0-py3-none-any.whl").
	type wheelEntry struct {
		relPath  string // relative to pypi/wheels/, e.g. "0.4.6/boto3-1.35.0.whl"
		filename string // base filename for display
	}
	var wheels []wheelEntry
	for _, key := range keys {
		filename := path.Base(key)
		if !strings.HasSuffix(filename, ".whl") {
			continue
		}
		dist := wheelDistName(filename)
		if normalizePkgName(dist) != normalized {
			continue
		}
		relPath := strings.TrimPrefix(key, manifest.PypiWheelPrefix)
		wheels = append(wheels, wheelEntry{relPath: relPath, filename: filename})
	}

	if len(wheels) == 0 {
		// Check if this package is in proxy mode.
		pkg, _ := s.store.GetPackage(r.Context(), manifest.TypePypi, pkgName)
		if pkg != nil && packageMode(pkg) == manifest.ModeProxy {
			// Proxy the simple index from upstream PyPI.
			upstream := s.pypiSimpleURL(normalized)
			s.proxyOrCache(w, r, s.typeStore(manifest.TypePypi), "pypi/simple/"+normalized+"/index.html", upstream, manifest.TypePypi, pkgName, pkgName, false, true)
			return
		}
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	escapedName := html.EscapeString(pkgName)
	_, _ = fmt.Fprintf(w, "<!DOCTYPE html>\n<html>\n  <head><title>Links for %s</title></head>\n  <body>\n", escapedName)
	_, _ = fmt.Fprintf(w, "    <h1>Links for %s</h1>\n", escapedName)
	for _, whl := range wheels {
		_, _ = fmt.Fprintf(w, "    <a href=\"/pypi/wheels/%s\">%s</a>\n", html.EscapeString(whl.relPath), html.EscapeString(whl.filename))
	}
	_, _ = fmt.Fprintf(w, "  </body>\n</html>\n")
}

// handlePypiWheel proxies /pypi/wheels/{path...} → S3 pypi/wheels/{path...}
// Supports versioned subdirs (e.g. pypi/wheels/0.4.6/boto3-1.26.0-py3-none-any.whl).
// For proxy-mode packages, falls back to fetching from upstream PyPI.
func (s *Server) handlePypiWheel(w http.ResponseWriter, r *http.Request) {
	p := r.PathValue("path")
	if !isSafePath(p) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	key := manifest.PypiWheelPrefix + p
	file := path.Base(p)
	// Wrapped rather than set: proxyOrResolve and proxyVersion below can both
	// answer 403 or 404, and http.Error leaves the header map alone.
	w = cacheImmutableOn200(w, file)

	// Extract package name and version from the wheel filename
	// (e.g. "boto3-1.26.0-py3-none-any.whl" → "boto3", "1.26.0").
	dist, distVersion := wheelIdentity(file)
	if dist != "" {
		normalized := normalizePkgName(dist)
		pkg, _ := s.store.GetPackage(r.Context(), manifest.TypePypi, dist)
		if pkg != nil && packageMode(pkg) == manifest.ModeProxy {
			resolve := func(ctx context.Context) (string, error) {
				return s.resolvePypiWheel(ctx, normalized, file)
			}
			s.proxyOrResolve(w, r, s.typeStore(manifest.TypePypi), key, resolve, "", manifest.TypePypi, dist, dist, true, true)
			return
		}
		if pkg == nil {
			// The simple index, not the artifact: a wheel URL cannot be
			// composed without reading the index, so the index is the only
			// fetchable URL this branch knows. `discover promote --as manifest`
			// stores it, and manifestURL trims it back to the registry root.
			s.recordNoManifest(r.Context(), r, manifest.TypePypi, dist, distVersion, s.pypiSimpleURL(normalized))
		}
	}
	s.proxyVersion(w, r, manifest.TypePypi, dist, distVersion, key)
}

// pypiSimpleURL is the PEP 503 index URL for one distribution under the
// configured index root.
func (s *Server) pypiSimpleURL(normalized string) string {
	return strings.TrimRight(s.cfg.PypiUpstream, "/") + "/simple/" + normalized + "/"
}

// pypiHrefPattern pulls the link targets out of a PEP 503 index. The document
// is generated HTML with one anchor per file and no nesting, so a full parser
// buys nothing over this; the match is only a candidate, and the filename
// comparison below is what decides.
var pypiHrefPattern = regexp.MustCompile(`href="([^"]*)"`)

// resolvePypiWheel returns the upstream URL for one wheel by reading the
// simple index for its distribution.
//
// PyPI serves artifacts from files.pythonhosted.org under a path derived from
// the file's content hash, which is not recoverable from the filename. The
// index is the only document that carries the mapping, so resolution is a
// lookup rather than a concatenation, and a filename the index does not list
// is refused here instead of becoming a fetch of a URL nobody can check.
func (s *Server) resolvePypiWheel(ctx context.Context, normalized, filename string) (string, error) {
	indexURL := s.pypiSimpleURL(normalized)
	body, _, err := fetchUpstream(ctx, indexURL)
	if err != nil {
		return "", fmt.Errorf("read the pypi simple index %s: %w", indexURL, err)
	}
	base, err := url.Parse(indexURL)
	if err != nil {
		return "", fmt.Errorf("parse the pypi simple index URL %s: %w", indexURL, err)
	}

	listed := 0
	for _, m := range pypiHrefPattern.FindAllSubmatch(body, -1) {
		href := html.UnescapeString(string(m[1]))
		u, err := base.Parse(href)
		if err != nil {
			continue
		}
		listed++
		name, err := url.PathUnescape(path.Base(u.Path))
		if err != nil || name != filename {
			continue
		}
		// The #sha256= fragment is the publisher's checksum, not part of the
		// object; dropping it keeps the logged URL the thing that was fetched.
		u.Fragment = ""
		return u.String(), nil
	}
	return "", fmt.Errorf("%w: %s lists %d file(s) and none of them is %s — the index is authoritative for what pypi publishes, so check the filename and the version against it",
		errUpstreamNotFound, indexURL, listed, filename)
}

// wheelIdentity splits a wheel filename into its distribution and version.
// PEP 427 fixes the first two hyphen-separated fields, so this is exact for a
// conforming name and yields an empty version for anything else, which routes
// by type instead of guessing.
func wheelIdentity(filename string) (dist, version string) {
	base := strings.TrimSuffix(filename, ".whl")
	parts := strings.Split(base, "-")
	if len(parts) < 2 {
		return wheelDistName(filename), ""
	}
	return parts[0], parts[1]
}
