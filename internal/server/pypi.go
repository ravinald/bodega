package server

import (
	"fmt"
	"html"
	"path"
	"strings"

	"net/http"

	"github.com/ravinald/bodega/internal/manifest"
)

// ---- PyPI ------------------------------------------------------------------

// handlePypiIndex generates a PEP 503 root index listing all packages found
// under the pypi/wheels/ S3 prefix.
func (s *Server) handlePypiIndex(w http.ResponseWriter, r *http.Request) {
	if !s.requireS3(w) {
		return
	}
	keys, err := s.objects.List(r.Context(), "pypi/wheels/")
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
	if !s.requireS3(w) {
		return
	}
	pkgName := r.PathValue("package")
	if pkg, _ := s.store.GetPackage(r.Context(), manifest.TypePypi, pkgName); pkg != nil && isPackageHidden(pkg) {
		http.NotFound(w, r)
		return
	}
	normalized := normalizePkgName(pkgName)

	keys, err := s.objects.List(r.Context(), "pypi/wheels/")
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
		relPath := strings.TrimPrefix(key, "pypi/wheels/")
		wheels = append(wheels, wheelEntry{relPath: relPath, filename: filename})
	}

	if len(wheels) == 0 {
		// Check if this package is in proxy mode.
		pkg, _ := s.store.GetPackage(r.Context(), manifest.TypePypi, pkgName)
		if pkg != nil && packageMode(pkg) == manifest.ModeProxy {
			// Proxy the simple index from upstream PyPI.
			upstream := "https://pypi.org/simple/" + normalized + "/"
			s.proxyOrCache(w, r, "pypi/simple/"+normalized+"/index.html", upstream, manifest.TypePypi, pkgName, false, true)
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
	key := "pypi/wheels/" + p
	file := path.Base(p)
	setCacheImmutable(w, file)

	// Extract package name from wheel filename (e.g. "boto3-1.26.0-py3-none-any.whl" → "boto3").
	dist := wheelDistName(file)
	if dist != "" {
		pkg, _ := s.store.GetPackage(r.Context(), manifest.TypePypi, dist)
		if pkg != nil && packageMode(pkg) == manifest.ModeProxy {
			upstream := "https://pypi.org/packages/" + file
			s.proxyOrCache(w, r, key, upstream, manifest.TypePypi, dist, true, true)
			return
		}
	}
	s.proxyS3(w, r, key)
}
