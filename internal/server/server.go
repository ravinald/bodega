// Package server implements the bodega HTTP package server.
//
// The server proxies S3-backed package artifacts to standard package manager
// clients (apt, pip) and exposes a REST API for manifest inspection.
package server

import (
	"context"
	cryptoRand "crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
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

// sd_notify: hand-rolled so bodega stays single-binary. No-op when
// $NOTIFY_SOCKET is unset.
func sdNotify(state string) {
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		return
	}
	if strings.HasPrefix(sock, "@") {
		sock = "\x00" + sock[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_, _ = conn.Write([]byte(state))
}

func sdNotifyReady()    { sdNotify("READY=1") }
func sdNotifyStopping() { sdNotify("STOPPING=1") }

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
	m.HandleFunc("GET /api/v1/packages/{type}/{name}/{version}/attestation", s.handleAttestation)
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
		// Version-level checks (age). Run separately from the URL allow-list
		// above so a stale package is blocked even when its URL is on the
		// allow-list.
		if s.auditDB != nil {
			checkers := []policy.VersionChecker{
				policy.NewAgeChecker(s.auditDB),
				policy.NewOSVChecker(s.auditDB),
			}
			for i := range pm.Versions {
				ve := &pm.Versions[i]
				combined := policy.RunChecks(ctx, &pm, ve, checkers...)
				if details := combined.AuditDetails(); details != nil {
					blob, _ := json.Marshal(details)
					status := "policy_warn"
					if combined.Blocked() {
						status = "policy_violation"
					}
					_ = s.auditDB.Record(ctx, audit.Event{
						EventType:  audit.EventCreate,
						PkgType:    t,
						PkgName:    pm.Name,
						PkgVersion: ve.Version,
						Status:     status,
						Details:    string(blob),
					})
				}
				if combined.Blocked() {
					writeJSON(w, http.StatusForbidden, map[string]string{
						"error": fmt.Sprintf("policy: %s", combined.Reasons()),
					})
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
