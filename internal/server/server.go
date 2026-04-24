// Package server implements the bodega HTTP package server.
//
// The server proxies S3-backed package artifacts to standard package manager
// clients (apt, pip) and exposes a REST API for manifest inspection.
package server

import (
	"bytes"
	"compress/gzip"
	"context"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
	"github.com/ravinald/bodega/internal/storage"
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

// Server is the bodega HTTP package server.
type Server struct {
	cfg       *config.Config
	store     *manifest.Store
	objects   storage.ObjectStore
	mux       *http.ServeMux
	addr      string
	logger    *slog.Logger
	cache     CacheConfig
	auditDB   *audit.DB
	policy    *policy.Checker
	denyNets  []*net.IPNet
	adminNets []*net.IPNet // CIDRs allowed to hit mutation API (admin_permit_cidr)
	pepper    string       // pepper for token hash verification
	quiet     bool         // suppress stderr startup banner (slog output unaffected)
	mu        sync.Mutex   // protects store mutations (CRUD API)
}

// SetQuiet suppresses the human-facing stderr startup banner. Log-level
// routed events are unaffected. Default is false.
func (s *Server) SetQuiet(q bool) { s.quiet = q }

// New constructs a Server and registers all routes.
// s3client may be nil — S3-backed endpoints return 503 in that case.
// logger may be nil — a no-op logger is used in that case.
func New(cfg *config.Config, store *manifest.Store, objects storage.ObjectStore, addr string, logger *slog.Logger) *Server {
	return newServer(cfg, store, objects, addr, logger)
}

func newServer(cfg *config.Config, store *manifest.Store, objects storage.ObjectStore, addr string, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s := &Server{
		cfg:     cfg,
		store:   store,
		objects: objects,
		mux:     http.NewServeMux(),
		addr:    addr,
		logger:  logger,
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
	// Parse admin permit CIDRs for mutation API access control.
	if len(cfg.AdminPermitCIDR) > 0 {
		nets, err := ParseDenyList(cfg.AdminPermitCIDR)
		if err != nil {
			logger.Error("invalid admin_permit_cidr entry", "error", err)
		} else {
			s.adminNets = nets
			logger.Info("admin permit CIDRs loaded", "entries", len(nets))
		}
	}
	// Load or create pepper for token auth.
	pepperExisted := false
	if _, err := audit.LoadPepper(audit.DefaultPepperPaths); err == nil {
		pepperExisted = true
	}
	if pepper, err := audit.LoadOrCreatePepper(audit.DefaultPepperPaths); err == nil {
		s.pepper = pepper
		if !pepperExisted {
			logger.Info("pepper file created (first run)")
		}
	} else {
		logger.Error("could not load or create pepper file — token auth will not work", "error", err)
	}
	// Open the audit DB if configured. Best-effort — server keeps serving
	// even if this fails, but token auth and upstream-policy enforcement
	// both depend on it.
	if dbPath := resolveAuditDBPath(cfg); dbPath != "" {
		if db, err := audit.Open(dbPath); err != nil {
			logger.Warn("could not open audit db; token auth and policy enforcement disabled",
				"path", dbPath, "error", err)
		} else {
			s.auditDB = db
			s.policy = policy.NewChecker(db)
			logger.Info("audit db opened", "path", dbPath)
		}
	}
	s.registerRoutes()
	return s
}

// resolveAuditDBPath returns the audit database path from config, falling
// back to <log_dir>/audit.db when AuditDB is unset.
func resolveAuditDBPath(cfg *config.Config) string {
	if cfg.AuditDB != "" {
		return cfg.AuditDB
	}
	if cfg.LogDir != "" {
		return filepath.Join(cfg.LogDir, "audit.db")
	}
	return ""
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
	h = MutationAuthMiddleware(s.adminNets, s.auditDB, s.pepper, s.logger)(h)
	h = DenyListMiddleware(s.denyNets)(h)
	h = RequestLogger(s.logger)(h)
	h = RealIPMiddleware(nil)(h)
	h = SecurityHeadersMiddleware(h)
	return h
}

// Start binds to s.addr and blocks until ctx is cancelled. When the context is
// done it initiates a graceful shutdown, giving in-flight requests up to 30
// seconds to complete.
func (s *Server) Start(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.addr,
		Handler:           s.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      5 * time.Minute, // generous for large file transfers
		IdleTimeout:       120 * time.Second,
	}

	// Reject misconfigured autocert — the flag is accepted but not yet
	// implemented, so starting silently in plain HTTP would be a security hazard.
	if s.cfg.TLSAutocert && s.cfg.TLSCert == "" && s.cfg.TLSKey == "" {
		return fmt.Errorf("tls_autocert is enabled but not yet implemented; provide tls_cert and tls_key instead")
	}

	// Configure TLS if cert/key are provided.
	if s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(s.cfg.TLSCert, s.cfg.TLSKey)
		if err != nil {
			return fmt.Errorf("load TLS certificate: %w", err)
		}
		srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}
	}

	// Write PID file so CLI commands can signal us to reload.
	pidPath := filepath.Join(s.cfg.LogDir, "bodega.pid")
	if err := os.MkdirAll(filepath.Dir(pidPath), 0o755); err == nil {
		if err := os.WriteFile(pidPath, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644); err == nil {
			s.logger.Info("PID file written", "path", pidPath)
			defer func() { _ = os.Remove(pidPath) }()
		}
	}

	// Bind the listener synchronously so we can surface bind failures
	// (port in use, privilege denied, bad address) before spawning the
	// serve goroutine — and so the startup banner + sd_notify only fire
	// once the socket is actually accepting.
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.addr, err)
	}
	boundAddr := ln.Addr().String()

	tlsMode := srv.TLSConfig != nil
	if tlsMode {
		ln = tls.NewListener(ln, srv.TLSConfig)
	}

	// User-facing startup banner on stderr. Bypasses log-level so a
	// default-configured bodega serve gives immediate visual confirmation
	// that binding succeeded. --quiet (see SetQuiet) silences it for
	// scripting use; slog output is separately controlled by log_level.
	if !s.quiet {
		scheme := "http"
		if tlsMode {
			scheme = "https"
		}
		_, _ = fmt.Fprintf(os.Stderr, "bodega listening on %s://%s\n", scheme, boundAddr)
	}
	if tlsMode {
		s.logger.Info("bodega server listening (TLS)", "addr", boundAddr)
	} else {
		s.logger.Info("bodega server listening", "addr", boundAddr)
	}

	// Notify systemd we're ready. No-op outside systemd (NOTIFY_SOCKET unset).
	sdNotifyReady()

	// Start the serve loop.
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ln)
	}()

	// SIGHUP reloads the manifest index and clears the package cache.
	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	go func() {
		for range sighupCh {
			s.logger.Info("SIGHUP received, reloading manifests...")
			if err := s.store.LoadIndex(context.Background()); err != nil {
				s.logger.Error("reload failed", "error", err)
			} else {
				s.logger.Info("manifests reloaded")
			}
		}
	}()

	// Wait for shutdown signal or server error.
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		s.logger.Info("shutting down server...")
		// Tell systemd we're intentionally stopping so it can distinguish
		// a graceful shutdown from a crash.
		sdNotifyStopping()
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

	// APT repository — dynamic index generation
	m.HandleFunc("GET /apt/gpg-key.asc", s.handleAptGPGKey)
	m.HandleFunc("GET /apt/dists/{distpath...}", s.handleAptDists)
	m.HandleFunc("GET /apt/pool/{path...}", s.handleAptPool)

	// PyPI simple index (PEP 503)
	m.HandleFunc("GET /pypi/simple/", s.handlePypiIndex)
	m.HandleFunc("GET /pypi/simple/{package}/", s.handlePypiPackage)

	// PyPI wheels (path... to support versioned subdirs like pypi/wheels/0.4.6/foo.whl)
	m.HandleFunc("GET /pypi/wheels/{path...}", s.handlePypiWheel)

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
	m.HandleFunc("GET /api/v1/packages/{type}/{name}/{version}", s.handleAPIPackageVersion)
	m.HandleFunc("GET /api/v1/status", s.handleAPIStatus)
	m.HandleFunc("GET /api/v1/config", s.handleAPIConfig)
	m.HandleFunc("GET /api/v1/metrics", s.handleAPIMetrics)

	// Mutation API
	m.HandleFunc("POST /api/v1/packages/{type}", s.handleCreateEntry)
	m.HandleFunc("DELETE /api/v1/packages/{type}/{name}", s.handleDeleteEntry)
	m.HandleFunc("PATCH /api/v1/packages/{type}/{name}/hide", s.handleToggleHidden)
	m.HandleFunc("PATCH /api/v1/packages/{type}/{name}/hide/{version}", s.handleToggleHidden)
	m.HandleFunc("PATCH /api/v1/packages/{type}/{name}/freeze", s.handleToggleFreeze)
	m.HandleFunc("PATCH /api/v1/packages/{type}/{name}/freeze/{version}", s.handleToggleFreeze)

	// Audit query
	m.HandleFunc("GET /api/v1/audit", s.handleAPIAudit)

	// Token management (mutation-gated)
	m.HandleFunc("GET /api/v1/tokens", s.handleListTokens)
	m.HandleFunc("POST /api/v1/tokens", s.handleCreateToken)
	m.HandleFunc("DELETE /api/v1/tokens/{id}", s.handleRevokeToken)

	// Upstream allow-list policies (mutation-gated)
	m.HandleFunc("GET /api/v1/policies", s.handleListPolicies)
	m.HandleFunc("POST /api/v1/policies", s.handleCreatePolicy)
	m.HandleFunc("DELETE /api/v1/policies/{id}", s.handleRevokePolicy)
}

// isAdminRequest checks whether the request originates from an IP in
// admin_permit_cidr. Used to gate sensitive read endpoints (audit, tokens,
// config) that don't go through the mutation middleware.
func (s *Server) isAdminRequest(r *http.Request) bool {
	// If no admin CIDRs are configured, allow all (no restriction).
	if len(s.adminNets) == 0 {
		return true
	}
	clientIP := net.ParseIP(ClientIP(r))
	if clientIP == nil {
		return false
	}
	for _, n := range s.adminNets {
		if n.Contains(clientIP) {
			return true
		}
	}
	return false
}

// ---- Health ----------------------------------------------------------------

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

// ---- APT repository (dynamic index generation) ----------------------------

// handleAptGPGKey proxies the GPG public key from S3.
func (s *Server) handleAptGPGKey(w http.ResponseWriter, r *http.Request) {
	s.proxyS3(w, r, "packages/apt/gpg-key.asc")
}

// handleAptPool proxies .deb files from S3 pool/main/...
func (s *Server) handleAptPool(w http.ResponseWriter, r *http.Request) {
	p := r.PathValue("path")
	if !isSafePath(p) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	key := "packages/apt/pool/" + p
	setCacheImmutable(w, path.Base(p))
	s.proxyS3(w, r, key)
}

// handleAptDists routes /apt/dists/{distpath...} to the appropriate handler
// based on the path structure. Go's ServeMux doesn't support mid-segment
// wildcards like "binary-{arch}", so we parse the path here.
func (s *Server) handleAptDists(w http.ResponseWriter, r *http.Request) {
	distpath := r.PathValue("distpath")
	parts := strings.Split(distpath, "/")

	// <codename>/Release or <codename>/InRelease
	if len(parts) == 2 && (parts[1] == "Release" || parts[1] == "InRelease") {
		s.handleAptRelease(w, r, parts[0])
		return
	}

	// <codename>/<component>/binary-<arch>/Packages[.gz]
	if len(parts) == 4 && strings.HasPrefix(parts[2], "binary-") {
		codename := parts[0]
		component := parts[1]
		arch := strings.TrimPrefix(parts[2], "binary-")
		file := parts[3]
		switch file {
		case "Packages":
			s.handleAptPackages(w, r, codename, component, arch)
			return
		case "Packages.gz":
			s.handleAptPackagesGz(w, r, codename, component, arch)
			return
		}
	}

	http.NotFound(w, r)
}

// handleAptRelease generates a Debian Release file from the manifest store.
func (s *Server) handleAptRelease(w http.ResponseWriter, r *http.Request, codename string) {
	if codename != s.cfg.AptCodename {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()
	debKeys, err := s.aptPoolKeys(ctx)
	if err != nil {
		s.logger.Error("apt release: list pool keys", "error", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}

	// Collect unique architectures from manifest metadata.
	arches := s.aptArchitectures(ctx)
	if len(arches) == 0 {
		arches = []string{"amd64"}
	}

	// Generate Packages content for each arch to compute checksums.
	type indexEntry struct {
		path string
		data []byte
	}
	var entries []indexEntry
	for _, arch := range arches {
		pkgData := s.generateAptPackages(ctx, arch, debKeys)
		entries = append(entries, indexEntry{
			path: "main/binary-" + arch + "/Packages",
			data: pkgData,
		})
		// Gzip variant.
		var gz bytes.Buffer
		gw := gzip.NewWriter(&gz)
		_, _ = gw.Write(pkgData)
		_ = gw.Close()
		entries = append(entries, indexEntry{
			path: "main/binary-" + arch + "/Packages.gz",
			data: gz.Bytes(),
		})
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "Origin: bodega\n")
	fmt.Fprintf(&buf, "Label: bodega\n")
	fmt.Fprintf(&buf, "Codename: %s\n", codename)
	fmt.Fprintf(&buf, "Components: main\n")
	fmt.Fprintf(&buf, "Architectures: %s\n", strings.Join(arches, " "))
	now := time.Now().UTC().Add(-24 * time.Hour) // backdate to tolerate client clock skew
	fmt.Fprintf(&buf, "Date: %s\n", now.Format(time.RFC1123Z))
	fmt.Fprintf(&buf, "Valid-Until: %s\n", now.Add(7*24*time.Hour).Format(time.RFC1123Z))
	fmt.Fprintf(&buf, "SHA256:\n")
	for _, e := range entries {
		h := sha256.Sum256(e.data)
		fmt.Fprintf(&buf, " %s %d %s\n", hex.EncodeToString(h[:]), len(e.data), e.path)
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// handleAptPackages generates a Debian Packages index for a specific architecture.
func (s *Server) handleAptPackages(w http.ResponseWriter, r *http.Request, codename, component, arch string) {
	if codename != s.cfg.AptCodename || component != "main" {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()
	debKeys, err := s.aptPoolKeys(ctx)
	if err != nil {
		s.logger.Error("apt packages: list pool keys", "error", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}

	data := s.generateAptPackages(ctx, arch, debKeys)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// handleAptPackagesGz serves the gzip-compressed Packages index.
func (s *Server) handleAptPackagesGz(w http.ResponseWriter, r *http.Request, codename, component, arch string) {
	if codename != s.cfg.AptCodename || component != "main" {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()
	debKeys, err := s.aptPoolKeys(ctx)
	if err != nil {
		s.logger.Error("apt packages.gz: list pool keys", "error", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}

	data := s.generateAptPackages(ctx, arch, debKeys)
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	_, _ = gw.Write(data)
	_ = gw.Close()

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(gz.Bytes())
}

// aptPoolKeys returns all S3 keys under the apt pool prefix.
func (s *Server) aptPoolKeys(ctx context.Context) ([]string, error) {
	if s.objects == nil {
		return nil, nil
	}
	return s.objects.List(ctx, "packages/apt/pool/")
}

// aptArchitectures returns sorted unique architectures from all apt manifest entries.
func (s *Server) aptArchitectures(ctx context.Context) []string {
	seen := map[string]bool{}
	for _, name := range s.store.ListPackages(manifest.TypeApt) {
		pm, _ := s.store.GetPackage(ctx, manifest.TypeApt, name)
		if pm == nil {
			continue
		}
		for _, ve := range pm.Versions {
			if ve.Hidden || ve.Version == "*" {
				continue
			}
			if arch := ve.Metadata["Architecture"]; arch != "" && arch != "all" {
				seen[arch] = true
			}
		}
	}
	var arches []string
	for a := range seen {
		arches = append(arches, a)
	}
	sort.Strings(arches)
	return arches
}

// generateAptPackages builds a Debian Packages file for the given architecture
// from manifest metadata and the S3 pool key listing.
func (s *Server) generateAptPackages(ctx context.Context, arch string, debKeys []string) []byte {
	// Build a map of source-name+version → S3 pool key for Filename lookup.
	poolMap := make(map[string]string) // "pkgname_version" → relative pool path
	for _, key := range debKeys {
		filename := path.Base(key)
		if !strings.HasSuffix(filename, ".deb") {
			continue
		}
		// Key is like "packages/apt/pool/main/a/amazon-efs-utils/amazon-efs-utils_2.4.2_amd64.deb"
		// We want the relative path after "packages/apt/" for the Filename field.
		relPath := strings.TrimPrefix(key, "packages/apt/")
		// Index by base filename for matching.
		poolMap[filename] = relPath
	}

	var buf bytes.Buffer
	for _, name := range s.store.ListPackages(manifest.TypeApt) {
		pm, _ := s.store.GetPackage(ctx, manifest.TypeApt, name)
		if pm == nil || isPackageHidden(pm) {
			continue
		}
		for _, ve := range pm.Versions {
			if ve.Hidden || ve.Version == "*" {
				continue
			}
			veArch := ve.Metadata["Architecture"]
			if veArch == "" {
				continue
			}
			// Include if arch matches request or package is arch "all".
			if veArch != arch && veArch != "all" {
				continue
			}

			pkgName := ve.SourceName
			if pkgName == "" {
				pkgName = pm.Name
			}

			// Determine the pool path: prefer stored _pool_path, fall back to S3 lookup.
			poolPath := ve.Metadata["_pool_path"]
			if poolPath == "" {
				poolPath = s.findDebInPool(poolMap, pkgName, ve.Version, veArch)
			}
			if poolPath == "" {
				continue // no .deb uploaded yet
			}

			// If we have the raw control data extracted from the .deb, emit it
			// verbatim with Filename/Size/hashes appended. This produces output
			// identical to a real repository.
			if control := ve.Metadata["_control"]; control != "" {
				buf.WriteString(control)
				buf.WriteString("\n")
				fmt.Fprintf(&buf, "Filename: %s\n", poolPath)
				if ve.ArtifactSize > 0 {
					fmt.Fprintf(&buf, "Size: %d\n", ve.ArtifactSize)
				}
				if md5 := ve.Metadata["_md5"]; md5 != "" {
					fmt.Fprintf(&buf, "MD5sum: %s\n", md5)
				}
				if sha1 := ve.Metadata["_sha1"]; sha1 != "" {
					fmt.Fprintf(&buf, "SHA1: %s\n", sha1)
				}
				if sha256 := ve.Metadata["_sha256"]; sha256 != "" {
					fmt.Fprintf(&buf, "SHA256: %s\n", sha256)
				}
				buf.WriteString("\n")
				continue
			}

			// Fallback: build stanza from manifest metadata fields.
			writeDebField(&buf, "Package", pkgName)
			writeDebField(&buf, "Version", ve.Version)
			writeDebField(&buf, "Architecture", veArch)
			writeDebField(&buf, "Maintainer", ve.Metadata["Maintainer"])
			writeDebField(&buf, "Installed-Size", ve.Metadata["Installed-Size"])
			if dep := ve.Metadata["Pre-Depends"]; dep != "" {
				writeDebField(&buf, "Pre-Depends", dep)
			}
			if dep := ve.Metadata["Depends"]; dep != "" {
				writeDebField(&buf, "Depends", dep)
			}
			writeDebField(&buf, "Section", ve.Metadata["Section"])
			writeDebField(&buf, "Priority", ve.Metadata["Priority"])
			writeDebField(&buf, "Filename", poolPath)
			if ve.ArtifactSize > 0 {
				fmt.Fprintf(&buf, "Size: %d\n", ve.ArtifactSize)
			}
			if ve.Checksum != nil && ve.Checksum.Algorithm == "sha256" {
				writeDebField(&buf, "SHA256", ve.Checksum.Value)
			}
			desc := ve.Description
			if desc == "" {
				desc = pm.Description
			}
			if desc != "" {
				writeDebField(&buf, "Description", desc)
				if full := ve.Metadata["Description-Full"]; full != "" {
					for _, line := range strings.Split(full, "\n") {
						line = strings.TrimRight(line, "\r")
						if line == "" {
							buf.WriteString(" .\n")
						} else {
							buf.WriteString(" " + line + "\n")
						}
					}
				}
			}
			buf.WriteString("\n")
		}
	}
	return buf.Bytes()
}

// findDebInPool searches the pool map for a .deb matching the given package name,
// version, and architecture.
func (s *Server) findDebInPool(poolMap map[string]string, pkgName, version, arch string) string {
	// Try the standard Debian naming convention first.
	candidate := pkgName + "_" + version + "_" + arch + ".deb"
	if rel, ok := poolMap[candidate]; ok {
		return rel
	}
	// Fallback: scan all pool entries for a match containing name and version.
	prefix := pkgName + "_" + version
	for filename, rel := range poolMap {
		if strings.HasPrefix(filename, prefix) {
			return rel
		}
	}
	return ""
}

// writeDebField writes a single "Key: Value" line to buf, sanitizing val to
// prevent field injection via embedded newlines.
func writeDebField(buf *bytes.Buffer, key, val string) {
	if val == "" {
		return
	}
	// Strip newlines and carriage returns to prevent field injection.
	val = strings.ReplaceAll(val, "\n", " ")
	val = strings.ReplaceAll(val, "\r", "")
	fmt.Fprintf(buf, "%s: %s\n", key, val)
}

// isSafePath rejects path values that contain traversal sequences or encoded
// traversal attempts. Use on any {path...} wildcard before constructing S3 keys.
func isSafePath(p string) bool {
	if strings.Contains(p, "..") {
		return false
	}
	if strings.Contains(p, "%2e") || strings.Contains(p, "%2E") {
		return false
	}
	return p != ""
}

// requireS3 returns true if S3 is available. If not, it writes a 503 and returns false.
func (s *Server) requireS3(w http.ResponseWriter) bool {
	if s.objects == nil {
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
	// Check if package is hidden.
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

// ---- Git bundles -----------------------------------------------------------

// handleGitBundle proxies /git/{name}/{file} → S3 repos/{name}/{file}
func (s *Server) handleGitBundle(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	file := r.PathValue("file")
	if !isSafePath(name) || !isSafePath(file) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	key := "repos/" + name + "/" + file
	setCacheImmutable(w, file)
	s.proxyS3(w, r, key)
}

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
			s.logger.Error("get package failed", "type", t, "name", name, "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
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

// handleAPIPackageVersion returns a PackageManifest scoped to a single
// version — all top-level fields intact, Versions containing only the
// matching entry. The payload remains a valid PackageManifest so clients
// can round-trip it through `pkg import` or the editor. 404s when the
// package or the version is not found.
func (s *Server) handleAPIPackageVersion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := r.PathValue("type")
	name := r.PathValue("name")
	version := r.PathValue("version")

	switch t {
	case manifest.TypeApt, manifest.TypeGit, manifest.TypePypi, manifest.TypeBinary,
		manifest.TypeGomod, manifest.TypeHelm, manifest.TypeNpm:
		pm, err := s.store.GetPackage(ctx, t, name)
		if err != nil {
			s.logger.Error("get package failed", "type", t, "name", name, "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}
		if pm == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "package not found"})
			return
		}
		scoped := pm.ScopeToVersion(version)
		if scoped == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{
				"error": fmt.Sprintf("version %q not found in %s/%s", version, t, name),
			})
			return
		}
		writeJSON(w, http.StatusOK, scoped)
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

	if s.objects == nil {
		resp.Healthy = false
		resp.Error = "s3 client not configured"
		writeJSON(w, http.StatusServiceUnavailable, resp)
		return
	}

	// Probe the apt Release file as a lightweight S3 health check.
	status, err := s.objects.Head(r.Context(), "packages/apt/dists/noble/Release")
	if err != nil {
		resp.Healthy = false
		resp.Error = "s3 probe failed"
		s.logger.Error("s3 probe failed", "error", err)
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
	if !s.isAdminRequest(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	resp := configResponse{
		Bucket:      s.cfg.Bucket,
		Region:      s.cfg.Region,
		ManifestDir: s.cfg.ManifestDir,
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAPIMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// Try cached metrics first (fast path).
	m, err := s.store.LoadMetrics(ctx)
	if err != nil || m == nil {
		// Fallback: compute on demand.
		m = s.store.ComputeMetrics(ctx)
	}
	writeJSON(w, http.StatusOK, m)
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
		s.proxyOrCache(w, r, s3Key, upstream, manifest.TypeGomod, module, immutable, true)
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
				s.proxyOrCache(w, r, key, upstream, manifest.TypeHelm, upstream, true, true)
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
		pkgName := fullPath[:idx]   // canonical, e.g. "@bitwarden/cli"
		tarball := fullPath[idx+3:] // URL form, e.g. "cli-2026.3.0.tgz"
		setCacheImmutable(w, tarball)

		// S3 and local disk both use the safe-encoded form throughout: the
		// directory is "npm/@bitwarden--cli/" and the tarball file is
		// "@bitwarden--cli-2026.3.0.tgz". Translate here so proxyS3 and
		// proxyOrCache look at the right place.
		storageKey := npmStorageKeyForTarball(pkgName, tarball)

		pm, _ := s.store.GetPackage(ctx, manifest.TypeNpm, pkgName)
		if pm != nil {
			// Whole-package hidden → 404 the tarball outright.
			if isPackageHidden(pm) {
				http.NotFound(w, r)
				return
			}
			// Per-version hidden → 404 just this version's tarball. Other
			// versions of the same package remain reachable. This is the
			// quarantine path for a single compromised release.
			reqVersion := npmVersionFromTarball(pkgName, tarball)
			if reqVersion != "" && isVersionHidden(pm, reqVersion) {
				http.NotFound(w, r)
				return
			}
			// Version-constraint enforcement. Mirrors the gomod path at
			// versionAllowed — the first VersionEntry's constraint governs
			// the whole package. 403 (not 404) because the version exists
			// upstream; we're declining to serve it by policy.
			if reqVersion != "" {
				vc, baseVer := packageVersionConstraint(pm)
				if vc != "" && vc != manifest.ConstraintAny && baseVer != "" {
					if !versionAllowed(baseVer, reqVersion, vc) {
						http.Error(w, "version not allowed by constraint", http.StatusForbidden)
						return
					}
				}
			}
		}

		if pm != nil && packageMode(pm) == manifest.ModeProxy {
			// Upstream still wants the canonical URL form with "/-/".
			upstream := s.cfg.NpmUpstream + "/" + pkgName + "/-/" + tarball
			s.proxyOrCache(w, r, storageKey, upstream, manifest.TypeNpm, pkgName, true, true)
			return
		}
		s.proxyS3(w, r, storageKey)
		return
	}

	// Packument request: path is just the package name (possibly scoped).
	pkgName := fullPath
	pm, _ := s.store.GetPackage(ctx, manifest.TypeNpm, pkgName)

	// Whole-package hidden → 404 the packument too; clients see the package
	// as if it does not exist here.
	if pm != nil && isPackageHidden(pm) {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Per-version hidden OR a non-trivial version_constraint → rewrite the
	// packument on the fly so clients never see a version we'd refuse to
	// serve anyway. Filtered packuments are not cached to S3 — cache keyed
	// by pkgName would collide with the unfiltered upstream copy.
	if pm != nil && (hasHiddenVersion(pm) || hasVersionConstraint(pm)) {
		s.serveFilteredPackument(w, r, pkgName, pm)
		return
	}

	upstream := s.cfg.NpmUpstream + "/" + pkgName
	s3Key := "npm/" + npmSafeName(pkgName) + "/packument.json"
	forceProxy := pm != nil && packageMode(pm) == manifest.ModeProxy
	s.proxyOrCache(w, r, s3Key, upstream, manifest.TypeNpm, pkgName, false, forceProxy)
}

// npmSafeName converts a canonical npm package name to the safe-encoded form
// used throughout bodega storage (S3 keys, local manifest dirs, local
// artifact dirs). Scoped packages "@scope/pkg" become "@scope--pkg";
// unscoped names pass through unchanged. The same helper lives in
// internal/builder as `safeName`; duplicated here to avoid pulling the
// builder package into the server's dependency graph.
func npmSafeName(pkgName string) string {
	return strings.ReplaceAll(pkgName, "/", "--")
}

// npmStorageKeyForTarball builds the S3 key for an npm tarball from the
// canonical URL form. The uploader writes tarballs to
// "npm/@scope--pkg/@scope--pkg-<version>.tgz"; this recreates that layout
// from the pieces the handler receives on the wire.
//
// The URL-form tarball filename is "pkg-<version>.tgz" (the npm standard).
// On disk/S3 it becomes "@scope--pkg-<version>.tgz" when scoped. For
// unscoped packages the two forms are identical.
func npmStorageKeyForTarball(pkgName, urlTarball string) string {
	safe := npmSafeName(pkgName)
	if pkgName == safe {
		return "npm/" + safe + "/" + urlTarball
	}
	ver := npmVersionFromTarball(pkgName, urlTarball)
	if ver == "" {
		// Shape we don't recognize; fall back to the URL form so we still
		// 404 cleanly instead of building a bogus key.
		return "npm/" + safe + "/" + urlTarball
	}
	return "npm/" + safe + "/" + safe + "-" + ver + ".tgz"
}

// npmVersionFromTarball extracts the version from an npm tarball filename
// given the owning package name. For `@bitwarden/cli` → `cli-2026.4.0.tgz`,
// returns `2026.4.0`. Returns "" when the filename doesn't match the
// expected shape.
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

// isVersionHidden reports whether a specific version of a package is marked
// Hidden in the manifest. A non-matching version returns false — the
// manifest's silence about a version is not a hide.
func isVersionHidden(pm *manifest.PackageManifest, version string) bool {
	for _, ve := range pm.Versions {
		if ve.Version == version || ve.Ref == version {
			return ve.Hidden
		}
	}
	return false
}

// hasHiddenVersion reports whether at least one VersionEntry is Hidden. Used
// to decide whether the packument needs on-the-fly filtering.
func hasHiddenVersion(pm *manifest.PackageManifest) bool {
	for _, ve := range pm.Versions {
		if ve.Hidden {
			return true
		}
	}
	return false
}

// hasVersionConstraint reports whether the package has a non-trivial
// version_constraint on its first entry (the "package-level" constraint,
// matching the gomod convention at packageVersionConstraint). A constraint
// of "" or "any" is trivial and does not require filtering.
func hasVersionConstraint(pm *manifest.PackageManifest) bool {
	vc, baseVer := packageVersionConstraint(pm)
	return vc != "" && vc != manifest.ConstraintAny && baseVer != ""
}

// serveFilteredPackument fetches the upstream packument and strips every
// hidden version from `versions`, `time`, and `dist-tags` before writing it
// to w. Filtered bodies are not written back to the S3 cache — doing so
// would pollute it with a hidden-version-dependent artifact.
func (s *Server) serveFilteredPackument(w http.ResponseWriter, r *http.Request, pkgName string, pm *manifest.PackageManifest) {
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

	if ct == "" {
		ct = "application/json"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(filtered)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(filtered)
}

// filterPackumentByManifest trims a raw npm packument JSON body to match the
// local PackageManifest policy: Hidden versions are removed outright, and
// any version that violates the package-level version_constraint is dropped
// too. Any `dist-tags` entry (including `latest`) that points at a removed
// version is also stripped — callers that relied on `latest` will start
// seeing the next-highest visible version, which is the correct behavior
// for a quarantined or out-of-constraint release.
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

	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}

	// rejected reports whether a specific upstream version should be stripped
	// from the packument: hidden beats constraint (both paths return true),
	// but the two rules are otherwise independent.
	rejected := func(v string) bool {
		if hidden[v] {
			return true
		}
		if hasConstraint && !versionAllowed(baseVer, v, vc) {
			return true
		}
		return false
	}

	if versions, ok := doc["versions"].(map[string]any); ok {
		for v := range versions {
			if rejected(v) {
				delete(versions, v)
			}
		}
	}
	if times, ok := doc["time"].(map[string]any); ok {
		for v := range times {
			if v == "created" || v == "modified" {
				continue
			}
			if rejected(v) {
				delete(times, v)
			}
		}
	}
	if tags, ok := doc["dist-tags"].(map[string]any); ok {
		for tag, v := range tags {
			s, ok := v.(string)
			if !ok {
				continue
			}
			if rejected(s) {
				delete(tags, tag)
			}
		}
	}

	return json.Marshal(doc)
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
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB ceiling
		var pm manifest.PackageManifest
		if err := json.NewDecoder(r.Body).Decode(&pm); err != nil {
			if err.Error() == "http: request body too large" {
				writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body too large"})
				return
			}
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
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
		// Allow-list enforcement: reject upstream URLs/names that aren't in policy.
		if s.policy != nil {
			for _, ve := range pm.Versions {
				candidate := policy.CandidateFor(t, pm.Name, ve.URL)
				if candidate == "" {
					continue
				}
				if err := s.policy.Check(ctx, t, candidate); err != nil {
					if policy.IsViolation(err) {
						s.logger.Warn("create rejected by policy",
							"type", t, "name", pm.Name, "version", ve.Version, "candidate", candidate)
						if s.auditDB != nil {
							_ = s.auditDB.Record(ctx, audit.Event{
								EventType:  audit.EventCreate,
								PkgType:    t,
								PkgName:    pm.Name,
								PkgVersion: ve.Version,
								Status:     "policy_violation",
								Details:    fmt.Sprintf("candidate=%s", candidate),
							})
						}
						writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
						return
					}
					s.logger.Error("policy check failed", "error", err)
					writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "policy check failed"})
					return
				}
			}
		}
		pm.Type = t
		if err := s.store.SavePackage(ctx, &pm); err != nil {
			s.logger.Error("save package failed", "type", t, "name", pm.Name, "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}
		if err := s.store.SaveIndex(ctx); err != nil {
			s.logger.Error("save index failed", "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
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
		s.logger.Error("delete package failed", "type", t, "name", name, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if err := s.store.SaveIndex(ctx); err != nil {
		s.logger.Error("save index failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
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

// ---- Hide / Freeze API -----------------------------------------------------

func (s *Server) handleToggleHidden(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := r.PathValue("type")
	name := r.PathValue("name")
	version := r.PathValue("version") // empty if not in URL
	s.mu.Lock()
	defer s.mu.Unlock()

	pm, err := s.store.GetPackage(ctx, t, name)
	if err != nil || pm == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	for i := range pm.Versions {
		if version != "" && pm.Versions[i].Version != version {
			continue
		}
		pm.Versions[i].Hidden = !pm.Versions[i].Hidden
	}
	if err := s.store.SavePackage(ctx, pm); err != nil {
		s.logger.Error("save package failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	_ = s.store.SaveIndex(ctx)
	writeJSON(w, http.StatusOK, pm)
}

func (s *Server) handleToggleFreeze(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t := r.PathValue("type")
	name := r.PathValue("name")
	version := r.PathValue("version")
	s.mu.Lock()
	defer s.mu.Unlock()

	pm, err := s.store.GetPackage(ctx, t, name)
	if err != nil || pm == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	for i := range pm.Versions {
		if version != "" && pm.Versions[i].Version != version {
			continue
		}
		pm.Versions[i].Frozen = !pm.Versions[i].Frozen
	}
	if err := s.store.SavePackage(ctx, pm); err != nil {
		s.logger.Error("save package failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	_ = s.store.SaveIndex(ctx)
	writeJSON(w, http.StatusOK, pm)
}

// ---- Audit API -------------------------------------------------------------

func (s *Server) handleAPIAudit(w http.ResponseWriter, r *http.Request) {
	if !s.isAdminRequest(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if s.auditDB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit database not configured"})
		return
	}
	q := r.URL.Query()
	f := audit.Filter{
		EventType: audit.EventType(q.Get("type")),
		PkgType:   q.Get("pkg_type"),
		PkgName:   q.Get("name"),
		ClientIP:  q.Get("client"),
		Limit:     50,
	}
	if since := q.Get("since"); since != "" {
		if t, err := time.Parse("2006-01-02", since); err == nil {
			f.Since = t
		} else if t, err := time.Parse(time.RFC3339, since); err == nil {
			f.Since = t
		}
	}
	if limit := q.Get("limit"); limit != "" {
		if n, err := fmt.Sscanf(limit, "%d", &f.Limit); n == 1 && err == nil && f.Limit > 0 {
			// parsed
		}
	}
	const maxAuditLimit = 5000
	if f.Limit > maxAuditLimit {
		f.Limit = maxAuditLimit
	}
	events, err := s.auditDB.Query(r.Context(), f)
	if err != nil {
		s.logger.Error("audit query failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, events)
}

// ---- Token API -------------------------------------------------------------

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	if !s.isAdminRequest(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if s.auditDB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit database not configured"})
		return
	}
	tokens, err := s.auditDB.ListTokens(r.Context())
	if err != nil {
		s.logger.Error("list tokens failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, tokens)
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	if s.auditDB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit database not configured"})
		return
	}
	if s.pepper == "" {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "pepper not configured"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Label   string `json:"label"`
		Expiry  string `json:"expiry"`
		Comment string `json:"comment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Label == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "label is required"})
		return
	}

	// Generate token.
	b := make([]byte, 32)
	if _, err := cryptoRand.Read(b); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	token := "bodega_ak_" + hex.EncodeToString(b)

	// Hash with pepper.
	hash := audit.HashToken(token, s.pepper)

	// Generate short ID.
	idBytes := make([]byte, 16)
	_, _ = cryptoRand.Read(idBytes)
	id := hex.EncodeToString(idBytes)

	// Parse expiry.
	var expiresAt *time.Time
	expiry := req.Expiry
	if expiry == "" {
		expiry = "365d"
	}
	if expiry != "never" {
		t, err := parseTokenExpiry(expiry)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid expiry: " + err.Error()})
			return
		}
		expiresAt = &t
	}

	ctx := r.Context()
	if err := s.auditDB.InsertToken(ctx, id, req.Label, hash, req.Comment, expiresAt); err != nil {
		s.logger.Error("insert token failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	resp := map[string]interface{}{
		"token": token,
		"id":    id,
		"label": req.Label,
	}
	if expiresAt != nil {
		resp["expires_at"] = expiresAt.Format(time.RFC3339)
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	if s.auditDB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit database not configured"})
		return
	}
	id := r.PathValue("id")
	found, err := s.auditDB.DeleteToken(r.Context(), id)
	if err != nil {
		s.logger.Error("revoke token failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "token not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "id": id})
}

// ---- Policy API ------------------------------------------------------------

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	if !s.isAdminRequest(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if s.auditDB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit database not configured"})
		return
	}
	typeFilter := r.URL.Query().Get("type")
	var rules []audit.PolicyInfo
	var err error
	if typeFilter != "" {
		rules, err = s.auditDB.GetPoliciesByType(r.Context(), typeFilter)
	} else {
		rules, err = s.auditDB.ListPolicies(r.Context())
	}
	if err != nil {
		s.logger.Error("list policies failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, rules)
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	if s.auditDB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit database not configured"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		RegistryType string `json:"registry_type"`
		Pattern      string `json:"pattern"`
		Comment      string `json:"comment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if err := policy.ValidateType(req.RegistryType); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Pattern == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "pattern is required"})
		return
	}
	kind := policy.RuleKindForType(req.RegistryType)

	idBytes := make([]byte, 16)
	if _, err := cryptoRand.Read(idBytes); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	id := hex.EncodeToString(idBytes)

	rule := audit.PolicyInfo{
		ID:           id,
		RegistryType: req.RegistryType,
		RuleKind:     kind,
		Pattern:      req.Pattern,
		Comment:      req.Comment,
		CreatedBy:    "api",
	}
	ctx := r.Context()
	if err := s.auditDB.InsertPolicy(ctx, rule); err != nil {
		s.logger.Error("insert policy failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if s.policy != nil {
		s.policy.Invalidate()
	}
	_ = s.auditDB.Record(ctx, audit.Event{
		EventType: audit.EventCreate,
		PkgType:   "policy",
		PkgName:   req.RegistryType + ":" + req.Pattern,
		ClientIP:  ClientIP(r),
		Status:    "success",
		Details:   fmt.Sprintf("id=%s kind=%s", id, kind),
	})
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) handleRevokePolicy(w http.ResponseWriter, r *http.Request) {
	if s.auditDB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit database not configured"})
		return
	}
	id := r.PathValue("id")
	found, err := s.auditDB.DeletePolicyByID(r.Context(), id)
	if err != nil {
		s.logger.Error("revoke policy failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy not found"})
		return
	}
	if s.policy != nil {
		s.policy.Invalidate()
	}
	_ = s.auditDB.Record(r.Context(), audit.Event{
		EventType: audit.EventDelete,
		PkgType:   "policy",
		PkgName:   id,
		ClientIP:  ClientIP(r),
		Status:    "success",
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "id": id})
}

// parseTokenExpiry converts an expiry string to a time. Accepts "30d", "1y", "2027-01-01".
func parseTokenExpiry(s string) (time.Time, error) {
	now := time.Now().UTC()
	if strings.HasSuffix(s, "d") {
		var days int
		if _, err := fmt.Sscanf(s, "%dd", &days); err == nil && days > 0 {
			return now.AddDate(0, 0, days), nil
		}
	}
	if strings.HasSuffix(s, "y") {
		var years int
		if _, err := fmt.Sscanf(s, "%dy", &years); err == nil && years > 0 {
			return now.AddDate(years, 0, 0), nil
		}
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("expected duration (30d, 1y), date (2027-01-01), or 'never'")
}

// ---- S3 proxy core ---------------------------------------------------------

// proxyS3 streams an S3 object to the HTTP response.
// It sets Content-Type from the file extension and Content-Length from S3 metadata.
// Returns 404 when the key does not exist in S3.
func (s *Server) proxyS3(w http.ResponseWriter, r *http.Request, s3Key string) {
	if !s.requireS3(w) {
		return
	}
	result, err := s.objects.GetStream(r.Context(), s3Key)
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
