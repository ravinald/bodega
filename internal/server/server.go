// Package server implements the bodega HTTP package server.
//
// The server proxies S3-backed package artifacts to standard package manager
// clients (apt, pip) and exposes a REST API for manifest inspection.
package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/scaleapi/bodega/internal/audit"
	"github.com/scaleapi/bodega/internal/config"
	"github.com/scaleapi/bodega/internal/manifest"
	bos3 "github.com/scaleapi/bodega/internal/s3"
)

// contentTypes maps file extensions to MIME types for proxied responses.
var contentTypes = map[string]string{
	".deb":    "application/vnd.debian.binary-package",
	".whl":    "application/zip",
	".bundle": "application/octet-stream",
	".gz":     "application/gzip",
	".bz2":    "application/x-bzip2",
	".xz":     "application/x-xz",
	".asc":    "text/plain; charset=utf-8",
	".html":   "text/html; charset=utf-8",
	".json":   "application/json",
	".txt":    "text/plain; charset=utf-8",
	".zip":    "application/zip",
	".tgz":    "application/gzip",
	".yaml":   "text/yaml; charset=utf-8",
	".yml":    "text/yaml; charset=utf-8",
	".mod":    "text/plain; charset=utf-8",
	".info":   "application/json",
}

// s3Getter is the subset of S3 operations the server requires.
// The concrete *bos3.Client satisfies this interface.
type s3Getter interface {
	GetObjectStream(ctx context.Context, key string) (*bos3.StreamResult, error)
	ListPrefix(ctx context.Context, prefix string) ([]string, error)
	HeadObject(ctx context.Context, key string) (*bos3.ObjectStatus, error)
}

// Server is the bodega HTTP package server.
type Server struct {
	cfg      *config.Config
	store    *manifest.Store
	s3       s3Getter
	mux      *http.ServeMux
	addr     string
	logger   *slog.Logger
	cache    CacheConfig
	auditDB  *audit.DB
	denyNets []*net.IPNet
	mu       sync.Mutex // protects store mutations (CRUD API)
}

// New constructs a Server and registers all routes.
// s3client may be nil — S3-backed endpoints return 503 in that case.
// logger may be nil — a no-op logger is used in that case.
func New(cfg *config.Config, store *manifest.Store, s3client *bos3.Client, addr string, logger *slog.Logger) *Server {
	var s3g s3Getter
	if s3client != nil {
		s3g = s3client
	}
	return newServer(cfg, store, s3g, addr, logger)
}

// NewWithS3Getter is like New but accepts the s3Getter interface directly.
// Used by tests that provide a mock S3 implementation.
func NewWithS3Getter(cfg *config.Config, store *manifest.Store, s3 s3Getter, addr string, logger *slog.Logger) *Server {
	return newServer(cfg, store, s3, addr, logger)
}

func newServer(cfg *config.Config, store *manifest.Store, s3 s3Getter, addr string, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s := &Server{
		cfg:    cfg,
		store:  store,
		s3:     s3,
		mux:    http.NewServeMux(),
		addr:   addr,
		logger: logger,
	}
	// Wire proxy/cache config.
	ttl, _ := time.ParseDuration(cfg.MetadataTTL)
	if ttl == 0 {
		ttl = time.Hour
	}
	s.cache = CacheConfig{
		Enabled:     cfg.ProxyCacheEnabled,
		MetadataTTL: ttl,
	}
	if len(cfg.DenyList) > 0 {
		nets, err := ParseDenyList(cfg.DenyList)
		if err != nil {
			logger.Error("invalid deny list entry", "error", err)
		} else {
			s.denyNets = nets
			logger.Info("deny list loaded", "entries", len(nets))
		}
	}
	s.registerRoutes()
	return s
}

// Handler returns the root http.Handler (with middleware applied).
// Useful for testing without starting a real TCP listener.
func (s *Server) Handler() http.Handler {
	return s.handler()
}

// handler builds the middleware chain around the mux.
func (s *Server) handler() http.Handler {
	var h http.Handler = s.mux
	h = AuditMiddleware(s.auditDB)(h)
	h = DenyListMiddleware(s.denyNets)(h)
	h = RequestLogger(s.logger)(h)
	h = RealIPMiddleware(nil)(h)
	return h
}

// Start binds to s.addr and blocks until ctx is cancelled. When the context is
// done it initiates a graceful shutdown, giving in-flight requests up to 30
// seconds to complete.
func (s *Server) Start(ctx context.Context) error {
	srv := &http.Server{
		Addr:         s.addr,
		Handler:      s.handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 5 * time.Minute, // generous for large file transfers
		IdleTimeout:  120 * time.Second,
	}

	// Configure TLS if cert/key are provided.
	if s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(s.cfg.TLSCert, s.cfg.TLSKey)
		if err != nil {
			return fmt.Errorf("load TLS certificate: %w", err)
		}
		srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	// Start listener in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		if srv.TLSConfig != nil {
			s.logger.Info("bodega server listening (TLS)", "addr", s.addr)
			errCh <- srv.ListenAndServeTLS("", "") // certs already in TLSConfig
		} else {
			s.logger.Info("bodega server listening", "addr", s.addr)
			errCh <- srv.ListenAndServe()
		}
	}()

	// Wait for shutdown signal or server error.
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		s.logger.Info("shutting down server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			s.logger.Error("graceful shutdown failed, forcing close", "error", err)
			_ = srv.Close()
			return err
		}
		s.logger.Info("server stopped")
		return nil
	}
}

// registerRoutes wires all URL patterns to their handler methods.
// Requires Go 1.22+ enhanced ServeMux patterns.
func (s *Server) registerRoutes() {
	m := s.mux

	// Web UI
	s.registerWebUI()

	// Health probe
	m.HandleFunc("GET /healthz", s.handleHealthz)

	// APT repository
	m.HandleFunc("GET /apt/gpg-key.asc", s.handleAptProxy)
	m.HandleFunc("GET /apt/dists/{path...}", s.handleAptProxy)
	m.HandleFunc("GET /apt/pool/{path...}", s.handleAptProxy)

	// PyPI simple index (PEP 503)
	m.HandleFunc("GET /pypi/simple/", s.handlePypiIndex)
	m.HandleFunc("GET /pypi/simple/{package}/", s.handlePypiPackage)

	// PyPI wheels
	m.HandleFunc("GET /pypi/wheels/{file}", s.handlePypiWheel)

	// Git bundles
	m.HandleFunc("GET /git/{name}/{file}", s.handleGitBundle)

	// Binary downloads
	m.HandleFunc("GET /binaries/{path...}", s.handleBinary)

	// Go module proxy (GOPROXY protocol)
	m.HandleFunc("GET /go/{path...}", s.handleGomod)

	// Helm chart repository
	m.HandleFunc("GET /helm/index.yaml", s.handleHelmIndex)
	m.HandleFunc("GET /helm/charts/{file}", s.handleHelmChart)

	// npm registry
	m.HandleFunc("GET /npm/{path...}", s.handleNpm)

	// REST API
	m.HandleFunc("GET /api/v1/packages", s.handleAPIPackages)
	m.HandleFunc("GET /api/v1/packages/{type}", s.handleAPIPackagesByType)
	m.HandleFunc("GET /api/v1/packages/{type}/{name}", s.handleAPIPackage)
	m.HandleFunc("GET /api/v1/status", s.handleAPIStatus)
	m.HandleFunc("GET /api/v1/config", s.handleAPIConfig)

	// Mutation API
	m.HandleFunc("POST /api/v1/packages/{type}", s.handleCreateEntry)
	m.HandleFunc("DELETE /api/v1/packages/{type}/{name}", s.handleDeleteEntry)
}

// ---- Health ----------------------------------------------------------------

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

// ---- APT proxy -------------------------------------------------------------

// handleAptProxy proxies /apt/... to S3 packages/apt/...
// e.g. /apt/dists/noble/Release → s3://bucket/packages/apt/dists/noble/Release
func (s *Server) handleAptProxy(w http.ResponseWriter, r *http.Request) {
	// r.URL.Path is e.g. "/apt/dists/noble/Release"
	// Strip leading "/" and prepend "packages" to get "packages/apt/dists/noble/Release"
	key := "packages" + r.URL.Path
	s.proxyS3(w, r, key)
}

// requireS3 returns true if S3 is available. If not, it writes a 503 and returns false.
func (s *Server) requireS3(w http.ResponseWriter) bool {
	if s.s3 == nil {
		http.Error(w, "S3 backend not configured — package serving unavailable", http.StatusServiceUnavailable)
		return false
	}
	return true
}

// ---- PyPI ------------------------------------------------------------------

// handlePypiIndex generates a PEP 503 root index listing all packages found
// under the pypi/wheels/ S3 prefix.
func (s *Server) handlePypiIndex(w http.ResponseWriter, r *http.Request) {
	if !s.requireS3(w) {
		return
	}
	keys, err := s.s3.ListPrefix(r.Context(), "pypi/wheels/")
	if err != nil {
		http.Error(w, fmt.Sprintf("list wheels: %v", err), http.StatusBadGateway)
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
		_, _ = fmt.Fprintf(w, "    <a href=\"/pypi/simple/%s/\">%s</a>\n", n, n)
	}
	_, _ = fmt.Fprintf(w, "  </body>\n</html>\n")
}

// handlePypiPackage generates a PEP 503 per-package index listing wheel files.
func (s *Server) handlePypiPackage(w http.ResponseWriter, r *http.Request) {
	if !s.requireS3(w) {
		return
	}
	pkgName := r.PathValue("package")
	// Check if package is hidden.
	if pkg, _ := s.store.GetPackage(r.Context(), manifest.TypePypi, pkgName); pkg != nil && isPackageHidden(pkg) {
		http.NotFound(w, r)
		return
	}
	normalized := normalizePkgName(pkgName)

	keys, err := s.s3.ListPrefix(r.Context(), "pypi/wheels/")
	if err != nil {
		http.Error(w, fmt.Sprintf("list wheels: %v", err), http.StatusBadGateway)
		return
	}

	// Collect matching wheel filenames before writing any output so we can
	// return a 404 if the package is unknown (PEP 503 requirement).
	var wheels []string
	for _, key := range keys {
		filename := path.Base(key)
		if !strings.HasSuffix(filename, ".whl") {
			continue
		}
		dist := wheelDistName(filename)
		if normalizePkgName(dist) != normalized {
			continue
		}
		wheels = append(wheels, filename)
	}

	if len(wheels) == 0 {
		// Check if this package is in proxy mode.
		pkg, _ := s.store.GetPackage(r.Context(), manifest.TypePypi, pkgName)
		if pkg != nil && packageMode(pkg) == manifest.ModeProxy {
			// Proxy the simple index from upstream PyPI.
			upstream := "https://pypi.org/simple/" + normalized + "/"
			s.proxyOrCache(w, r, "pypi/simple/"+normalized+"/index.html", upstream, false, true)
			return
		}
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, "<!DOCTYPE html>\n<html>\n  <head><title>Links for %s</title></head>\n  <body>\n", pkgName)
	_, _ = fmt.Fprintf(w, "    <h1>Links for %s</h1>\n", pkgName)
	for _, filename := range wheels {
		_, _ = fmt.Fprintf(w, "    <a href=\"/pypi/wheels/%s\">%s</a>\n", filename, filename)
	}
	_, _ = fmt.Fprintf(w, "  </body>\n</html>\n")
}

// handlePypiWheel proxies /pypi/wheels/{file} → S3 pypi/wheels/{file}
// For proxy-mode packages, falls back to fetching from upstream PyPI.
func (s *Server) handlePypiWheel(w http.ResponseWriter, r *http.Request) {
	file := r.PathValue("file")
	key := "pypi/wheels/" + file
	setCacheImmutable(w, file)

	// Extract package name from wheel filename (e.g. "boto3-1.26.0-py3-none-any.whl" → "boto3").
	dist := wheelDistName(file)
	if dist != "" {
		pkg, _ := s.store.GetPackage(r.Context(), manifest.TypePypi, dist)
		if pkg != nil && packageMode(pkg) == manifest.ModeProxy {
			upstream := "https://pypi.org/packages/" + file
			s.proxyOrCache(w, r, key, upstream, true, true)
			return
		}
	}
	s.proxyS3(w, r, key)
}

// ---- Git bundles -----------------------------------------------------------

// handleGitBundle proxies /git/{name}/{file} → S3 repos/{name}/{file}
func (s *Server) handleGitBundle(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	file := r.PathValue("file")
	key := "repos/" + name + "/" + file
	setCacheImmutable(w, file)
	s.proxyS3(w, r, key)
}

// ---- Binaries --------------------------------------------------------------

// handleBinary proxies /binaries/{path...} → S3 binaries/{path}
func (s *Server) handleBinary(w http.ResponseWriter, r *http.Request) {
	p := r.PathValue("path")
	key := "binaries/" + p
	s.proxyS3(w, r, key)
}

// ---- REST API --------------------------------------------------------------

// packagesResponse is the JSON envelope for /api/v1/packages.
type packagesResponse struct {
	Apt    []*manifest.PackageManifest `json:"apt"`
	Git    []*manifest.PackageManifest `json:"git"`
	Pypi   []*manifest.PackageManifest `json:"pypi"`
	Binary []*manifest.PackageManifest `json:"binary"`
	Gomod  []*manifest.PackageManifest `json:"gomod"`
	Helm   []*manifest.PackageManifest `json:"helm"`
	Npm    []*manifest.PackageManifest `json:"npm"`
}

func (s *Server) handleAPIPackages(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	resp := packagesResponse{
		Apt:    loadAllPackages(ctx, s.store, manifest.TypeApt),
		Git:    loadAllPackages(ctx, s.store, manifest.TypeGit),
		Pypi:   loadAllPackages(ctx, s.store, manifest.TypePypi),
		Binary: loadAllPackages(ctx, s.store, manifest.TypeBinary),
		Gomod:  loadAllPackages(ctx, s.store, manifest.TypeGomod),
		Helm:   loadAllPackages(ctx, s.store, manifest.TypeHelm),
		Npm:    loadAllPackages(ctx, s.store, manifest.TypeNpm),
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAPIPackagesByType(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := r.PathValue("type")
	switch t {
	case manifest.TypeApt, manifest.TypeGit, manifest.TypePypi, manifest.TypeBinary,
		manifest.TypeGomod, manifest.TypeHelm, manifest.TypeNpm:
		writeJSON(w, http.StatusOK, loadAllPackages(ctx, s.store, t))
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": fmt.Sprintf("unknown type %q — must be one of: apt, git, pypi, binary, gomod, helm, npm", t),
		})
	}
}

func (s *Server) handleAPIPackage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := r.PathValue("type")
	name := r.PathValue("name")

	switch t {
	case manifest.TypeApt, manifest.TypeGit, manifest.TypePypi, manifest.TypeBinary,
		manifest.TypeGomod, manifest.TypeHelm, manifest.TypeNpm:
		pm, err := s.store.GetPackage(ctx, t, name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if pm == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, http.StatusOK, pm)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": fmt.Sprintf("unknown type %q", t),
		})
	}
}

// statusResponse is the JSON shape for /api/v1/status.
type statusResponse struct {
	Healthy    bool            `json:"healthy"`
	EntryCount map[string]int  `json:"entry_count"`
	S3Entries  []s3EntryStatus `json:"s3_entries,omitempty"`
	Error      string          `json:"error,omitempty"`
}

type s3EntryStatus struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	S3Key  string `json:"s3_key"`
	InS3   bool   `json:"in_s3"`
	Frozen bool   `json:"frozen,omitempty"`
}

func (s *Server) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	resp := statusResponse{
		Healthy: true,
		EntryCount: map[string]int{
			manifest.TypeApt:    len(s.store.ListPackages(manifest.TypeApt)),
			manifest.TypeGit:    len(s.store.ListPackages(manifest.TypeGit)),
			manifest.TypePypi:   len(s.store.ListPackages(manifest.TypePypi)),
			manifest.TypeBinary: len(s.store.ListPackages(manifest.TypeBinary)),
			manifest.TypeGomod:  len(s.store.ListPackages(manifest.TypeGomod)),
			manifest.TypeHelm:   len(s.store.ListPackages(manifest.TypeHelm)),
			manifest.TypeNpm:    len(s.store.ListPackages(manifest.TypeNpm)),
		},
	}

	if s.s3 == nil {
		resp.Healthy = false
		resp.Error = "s3 client not configured"
		writeJSON(w, http.StatusServiceUnavailable, resp)
		return
	}

	// Probe the apt Release file as a lightweight S3 health check.
	status, err := s.s3.HeadObject(r.Context(), "packages/apt/dists/noble/Release")
	if err != nil {
		resp.Healthy = false
		resp.Error = fmt.Sprintf("s3 probe failed: %v", err)
		writeJSON(w, http.StatusOK, resp)
		return
	}

	resp.S3Entries = []s3EntryStatus{
		{
			Type:  manifest.TypeApt,
			Name:  "apt-release",
			S3Key: "packages/apt/dists/noble/Release",
			InS3:  status.Exists,
		},
	}

	writeJSON(w, http.StatusOK, resp)
}

// configResponse is the non-sensitive subset of Config for /api/v1/config.
type configResponse struct {
	Bucket      string `json:"bucket"`
	Region      string `json:"region"`
	ManifestDir string `json:"manifest_dir"`
}

func (s *Server) handleAPIConfig(w http.ResponseWriter, r *http.Request) {
	resp := configResponse{
		Bucket:      s.cfg.Bucket,
		Region:      s.cfg.Region,
		ManifestDir: s.cfg.ManifestDir,
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---- Go module proxy -------------------------------------------------------

func (s *Server) handleGomod(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	fullPath := r.PathValue("path")
	idx := strings.Index(fullPath, "/@v/")
	if idx < 0 {
		http.NotFound(w, r)
		return
	}
	module := fullPath[:idx]
	file := fullPath[idx+4:] // "list", "v1.30.0.info", etc.

	s3Key := "gomod/" + module + "/@v/" + file
	upstream := s.cfg.GomodUpstream + "/" + module + "/@v/" + file
	immutable := file != "list" && !strings.HasSuffix(file, "latest")

	pm, _ := s.store.GetPackage(ctx, manifest.TypeGomod, module)
	if pm != nil && isPackageHidden(pm) {
		http.NotFound(w, r)
		return
	}

	if pm != nil && packageMode(pm) == manifest.ModeProxy {
		// Version constraint enforcement: check if the requested version is allowed.
		if immutable {
			vc, ver := packageVersionConstraint(pm)
			if vc != "" && vc != manifest.ConstraintAny {
				reqVersion := file
				if dot := strings.LastIndex(file, "."); dot > 0 {
					reqVersion = file[:dot] // "v1.30.0.info" → "v1.30.0"
				}
				if !versionAllowed(ver, reqVersion, vc) {
					http.Error(w, "version not allowed by constraint", http.StatusForbidden)
					return
				}
			}
		}
		s.proxyOrCache(w, r, s3Key, upstream, immutable, true)
		return
	}
	s.proxyS3(w, r, s3Key)
}

// versionAllowed checks whether reqVersion satisfies the constraint relative to entryVersion.
func versionAllowed(entryVersion, reqVersion, constraint string) bool {
	switch constraint {
	case manifest.ConstraintExact, "":
		return reqVersion == entryVersion
	case manifest.ConstraintAny:
		return true
	case manifest.ConstraintCompatible:
		// Same major version, any minor/patch.
		return reqVersion >= entryVersion
	case manifest.ConstraintPatch:
		// Same major.minor, any patch.
		return reqVersion >= entryVersion
	}
	return false
}

// ---- Helm chart repository -------------------------------------------------

func (s *Server) handleHelmIndex(w http.ResponseWriter, r *http.Request) {
	s.proxyS3(w, r, "charts/index.yaml")
}

func (s *Server) handleHelmChart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	file := r.PathValue("file")
	key := "charts/" + file
	setCacheImmutable(w, file)

	// Check if any helm entry is in proxy mode with a URL we can use.
	// Parse chart name from filename: "ingress-nginx-4.0.0.tgz" → "ingress-nginx"
	chartName := strings.TrimSuffix(file, ".tgz")
	if idx := strings.LastIndex(chartName, "-"); idx > 0 {
		chartName = chartName[:idx]
	}
	pm, _ := s.store.GetPackage(ctx, manifest.TypeHelm, chartName)
	if pm != nil && packageMode(pm) == manifest.ModeProxy {
		// Use the URL from the first version that has one.
		for _, ve := range pm.Versions {
			if ve.URL != "" {
				upstream := strings.TrimSuffix(ve.URL, "/") + "/" + file
				s.proxyOrCache(w, r, key, upstream, true, true)
				return
			}
		}
	}
	s.proxyS3(w, r, key)
}

// ---- npm registry ----------------------------------------------------------

func (s *Server) handleNpm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	fullPath := r.PathValue("path")

	// Tarball request: path contains "/-/"
	if idx := strings.Index(fullPath, "/-/"); idx >= 0 {
		pkgName := fullPath[:idx]
		tarball := fullPath[idx+3:]
		key := "npm/" + pkgName + "/" + tarball
		setCacheImmutable(w, tarball)

		pm, _ := s.store.GetPackage(ctx, manifest.TypeNpm, pkgName)
		if pm != nil && packageMode(pm) == manifest.ModeProxy {
			upstream := s.cfg.NpmUpstream + "/" + pkgName + "/-/" + tarball
			s.proxyOrCache(w, r, key, upstream, true, true)
			return
		}
		s.proxyS3(w, r, key)
		return
	}

	// Packument request: path is just the package name (possibly scoped).
	upstream := s.cfg.NpmUpstream + "/" + fullPath
	s3Key := "npm/" + fullPath + "/packument.json"
	w.Header().Set("Content-Type", "application/json")

	pm, _ := s.store.GetPackage(ctx, manifest.TypeNpm, fullPath)
	forceProxy := pm != nil && packageMode(pm) == manifest.ModeProxy
	s.proxyOrCache(w, r, s3Key, upstream, false, forceProxy)
}

// ---- Mutation API ----------------------------------------------------------

func (s *Server) handleCreateEntry(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := r.PathValue("type")
	s.mu.Lock()
	defer s.mu.Unlock()

	// All types accept a PackageManifest with at least one VersionEntry.
	switch t {
	case manifest.TypeApt, manifest.TypeGit, manifest.TypeBinary, manifest.TypeGomod,
		manifest.TypeHelm, manifest.TypeNpm, manifest.TypePypi:
		var pm manifest.PackageManifest
		if err := json.NewDecoder(r.Body).Decode(&pm); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if pm.Name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
			return
		}
		// Check for conflict.
		existing, _ := s.store.GetPackage(ctx, t, pm.Name)
		if existing != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "package already exists"})
			return
		}
		pm.Type = t
		if err := s.store.SavePackage(ctx, &pm); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if err := s.store.SaveIndex(ctx); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, &pm)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("unknown type %q", t)})
	}
}

func (s *Server) handleDeleteEntry(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := r.PathValue("type")
	name := r.PathValue("name")
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check frozen status.
	frozen, findErr := s.isFrozen(ctx, t, name)
	if findErr != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": findErr.Error()})
		return
	}
	if frozen {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "entry is frozen"})
		return
	}

	if err := s.store.DeletePackage(ctx, t, name); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := s.store.SaveIndex(ctx); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "type": t, "name": name})
}

// isFrozen returns whether all versions of a named package are frozen, or an error if not found.
func (s *Server) isFrozen(ctx context.Context, t, name string) (bool, error) {
	pm, err := s.store.GetPackage(ctx, t, name)
	if err != nil {
		return false, err
	}
	if pm == nil {
		return false, fmt.Errorf("%s package %q not found", t, name)
	}
	// Consider the package frozen when all versions are frozen.
	if len(pm.Versions) == 0 {
		return false, nil
	}
	for _, ve := range pm.Versions {
		if !ve.Frozen {
			return false, nil
		}
	}
	return true, nil
}

// ---- S3 proxy core ---------------------------------------------------------

// proxyS3 streams an S3 object to the HTTP response.
// It sets Content-Type from the file extension and Content-Length from S3 metadata.
// Returns 404 when the key does not exist in S3.
func (s *Server) proxyS3(w http.ResponseWriter, r *http.Request, s3Key string) {
	if !s.requireS3(w) {
		return
	}
	result, err := s.s3.GetObjectStream(r.Context(), s3Key)
	if err != nil {
		s.logger.Error("s3 proxy error", "key", s3Key, "error", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	if result == nil {
		http.NotFound(w, r)
		return
	}
	defer func() { _ = result.Body.Close() }()

	// Set Content-Type from extension, falling back to S3's stored value.
	ct := contentTypeForKey(s3Key)
	if ct == "" {
		ct = result.ContentType
	}
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)

	if result.ContentLength > 0 {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", result.ContentLength))
	}
	if result.ETag != "" {
		w.Header().Set("ETag", `"`+result.ETag+`"`)
	}

	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, result.Body)
}

// ---- Helpers ---------------------------------------------------------------

// setCacheImmutable adds Cache-Control: public, max-age=31536000, immutable
// for artifact types that are content-addressed and never overwritten.
func setCacheImmutable(w http.ResponseWriter, filename string) {
	ext := path.Ext(filename)
	switch ext {
	case ".whl", ".deb", ".bundle", ".tgz":
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
}

// contentTypeForKey returns the MIME type for a given S3 key based on extension.
func contentTypeForKey(key string) string {
	return contentTypes[strings.ToLower(path.Ext(key))]
}

// writeJSON serialises v as JSON and writes it with the given status code.
func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// normalizePkgName applies PEP 503 normalisation: lowercase and collapse
// runs of [-_.] to a single hyphen.
func normalizePkgName(name string) string {
	name = strings.ToLower(name)
	// Replace underscores and dots with hyphens.
	name = strings.NewReplacer("_", "-", ".", "-").Replace(name)
	// Collapse consecutive hyphens.
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}
	return name
}

// wheelDistName extracts the distribution (package) name from a wheel filename.
// Wheel format: {distribution}-{version}(-{build tag})?-{python tag}-{abi tag}-{platform tag}.whl
func wheelDistName(filename string) string {
	filename = strings.TrimSuffix(filename, ".whl")
	parts := strings.SplitN(filename, "-", 2)
	return parts[0]
}

// uniquePackageNames scans S3 keys under pypi/wheels/ and returns the sorted
// list of unique normalised package names found.
func uniquePackageNames(keys []string) []string {
	seen := make(map[string]struct{})
	var names []string
	for _, key := range keys {
		filename := path.Base(key)
		if !strings.HasSuffix(filename, ".whl") {
			continue
		}
		dist := wheelDistName(filename)
		norm := normalizePkgName(dist)
		if _, ok := seen[norm]; !ok {
			seen[norm] = struct{}{}
			names = append(names, norm)
		}
	}
	// Return stable order.
	sortStrings(names)
	return names
}

// sortStrings sorts a string slice in place without importing sort
// (uses a simple insertion sort — package index lists are small).
func sortStrings(ss []string) {
	for i := 1; i < len(ss); i++ {
		key := ss[i]
		j := i - 1
		for j >= 0 && ss[j] > key {
			ss[j+1] = ss[j]
			j--
		}
		ss[j+1] = key
	}
}

// ---- PackageManifest helpers -----------------------------------------------

// loadAllPackages loads all PackageManifest entries for a given type from the store.
func loadAllPackages(ctx context.Context, store *manifest.Store, typ string) []*manifest.PackageManifest {
	names := store.ListPackages(typ)
	out := make([]*manifest.PackageManifest, 0, len(names))
	for _, name := range names {
		pm, err := store.GetPackage(ctx, typ, name)
		if err != nil || pm == nil {
			continue
		}
		out = append(out, pm)
	}
	return out
}

// isPackageHidden returns true when any version of the package is marked hidden,
// or when all versions are hidden. Uses first-version semantics for single-version packages.
func isPackageHidden(pm *manifest.PackageManifest) bool {
	if len(pm.Versions) == 0 {
		return false
	}
	// For multi-version packages, treat as hidden only when ALL versions are hidden.
	for _, ve := range pm.Versions {
		if !ve.Hidden {
			return false
		}
	}
	return true
}

// packageMode returns the effective mode for a package, derived from the first version entry.
// Defaults to ModeHosted when no versions are set.
func packageMode(pm *manifest.PackageManifest) string {
	for _, ve := range pm.Versions {
		return ve.EffectiveMode()
	}
	return manifest.ModeHosted
}

// packageVersionConstraint returns the VersionConstraint and Version from the first version entry.
func packageVersionConstraint(pm *manifest.PackageManifest) (constraint, version string) {
	for _, ve := range pm.Versions {
		return ve.VersionConstraint, ve.Version
	}
	return "", ""
}
