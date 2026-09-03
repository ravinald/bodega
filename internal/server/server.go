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
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ravinald/bodega/internal/admit"
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
	cfg          *config.Config
	store        *manifest.Store
	stores       storage.Resolver
	mux          *http.ServeMux
	addr         string
	logger       *slog.Logger
	cache        CacheConfig
	auditDB      *audit.DB
	policy       *policy.Checker
	discoverMode string             // "" or "observe" — see internal/server/discovery.go
	discovery    *DiscoveryRecorder // nil when discover_mode == "" or auditDB == nil
	denyNets     []*net.IPNet
	adminNets    []*net.IPNet // CIDRs allowed to reach the admin surface (admin_permit_cidr)
	adminErr     error        // set when admin_permit_cidr parses to nothing; Start refuses on it
	// trustedNets are the proxies whose forwarded headers are believed.
	// trustedNetsSet distinguishes "operator wrote an empty list" from
	// "operator wrote nothing": the first trusts no header from anyone, the
	// second takes the built-in loopback + RFC1918 default. Collapsing them
	// would silently restore header trust to a deployment that removed it.
	trustedNets    []*net.IPNet
	trustedNetsSet bool
	pepper         string     // pepper for token hash verification
	quiet          bool       // suppress stderr startup banner (slog output unaffected)
	mu             sync.Mutex // protects store mutations (CRUD API)

	// acl is the live answer for all three CIDR lists, resolved from the audit
	// database over the three fields above. Held behind an atomic pointer and
	// a TTL rather than rebuilt on the handler chain, because the chain is
	// built once at Start and an operator changing a list on a running server
	// has nothing to rebuild it. See internal/server/acl.go.
	acl   atomic.Pointer[aclSet]
	aclAt atomic.Int64 // UnixNano the cached set was resolved
	aclMu sync.Mutex   // serializes refreshes so a stale cache costs one query

	// aptSign is the signing key and the two served renderings of its public
	// half. nil when no key is installed, which is a supported configuration:
	// signed and unsigned coexist at the same URLs, and the signature is
	// metadata a client opts into checking.
	//
	// Atomic and swapped whole because SIGHUP re-reads the key while request
	// handlers are reading it. Whole matters as much as atomic: a keyring
	// route answering from the incoming key while InRelease still carried the
	// outgoing signature is a client being told the archive is forged.
	aptSign atomic.Pointer[aptSigning]

	// aptSnap is the generated apt index. Held whole so Release and the
	// Packages bodies it digests are always served from one generation.
	aptSnap atomic.Pointer[aptSnapshot]

	// gitTool is the resolved git toolchain the smart-HTTP path executes,
	// or nil when git-http-backend could not be found at startup. Nil is what
	// leaves POST /git/{namespace}/{path...} unregistered, so a clone fails
	// with a method the mux never answers rather than per-request inside a
	// handler that cannot work.
	gitTool *gitTool
	// gitClone serializes the first clone of each mirror, so concurrent first
	// requests for one repository produce one `git clone --mirror`.
	gitClone keyedMutex

	// aptPool caches the pool listing behind metadata_ttl. Every apt-touching
	// API write rebuilds the snapshot and the rebuild lists the whole pool, so
	// a burst of writes paid for a full listing each — multiplied by the
	// number of backends once the listing fans out.
	aptPool atomic.Pointer[aptPoolListing]

	// aptRoutes remembers which configured archive answered for each pool
	// path, because a pool request carries no codename to resolve it by.
	aptRoutes aptRouteCache
	// aptMirror serializes concurrent misses for one mirrored object, so a
	// fleet running `apt install` at the same minute makes one upstream fetch
	// of a .deb rather than one per host.
	aptMirror keyedMutex
}

// SetQuiet suppresses the human-facing stderr startup banner. Log-level
// routed events are unaffected. Default is false.
func (s *Server) SetQuiet(q bool) { s.quiet = q }

// New constructs a Server and registers all routes.
// stores may be nil — package-serving endpoints return 503 in that case.
// logger may be nil — a no-op logger is used in that case.
func New(cfg *config.Config, store *manifest.Store, stores storage.Resolver, addr string, logger *slog.Logger) *Server {
	return newServer(cfg, store, stores, addr, logger)
}

func newServer(cfg *config.Config, store *manifest.Store, stores storage.Resolver, addr string, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s := &Server{
		cfg:    cfg,
		store:  store,
		stores: stores,
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
	// Parse admin permit CIDRs for the admin surface: the mutation verbs and
	// the four admin read endpoints. Held for Start to refuse on rather than
	// logged and discarded, because an admin list bodega cannot read is not a
	// list it may substitute a default for.
	if nets, err := parseAdminPermitCIDR(cfg.AdminPermitCIDR); err != nil {
		s.adminErr = err
	} else if len(nets) > 0 {
		s.adminNets = nets
		logger.Info("admin permit CIDRs loaded", "entries", len(nets))
	}
	// trusted_proxies. A non-nil slice, empty included, is an explicit answer.
	if cfg.TrustedProxies != nil {
		nets, err := ParseDenyList(cfg.TrustedProxies)
		if err != nil {
			logger.Error("invalid trusted_proxies entry", "error", err)
		} else {
			if nets == nil {
				nets = []*net.IPNet{}
			}
			s.trustedNets = nets
			s.trustedNetsSet = true
			logger.Info("trusted proxies loaded", "entries", len(nets))
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
	// Discover mode: only meaningful with both an audit DB (to write rows)
	// and a non-empty mode. Validation of the mode value happens at config
	// load time, so we trust cfg.DiscoverMode here.
	s.discoverMode = cfg.DiscoverMode
	if s.discoverMode != "" && s.auditDB != nil {
		s.discovery = NewDiscoveryRecorder(s.auditDB, logger)
	}
	// Access control lists: copy the config file's values into the audit DB on
	// first sight, then resolve the live set the middleware chain reads.
	s.seedACLs(context.Background())
	s.refreshACLs(context.Background())

	// Resolve the git toolchain before routes are registered: whether
	// git-http-backend exists decides which routes exist.
	s.gitTool = resolveGitTool(cfg, logger)

	s.loadAptSigner()
	s.registerRoutes()

	// Build the first apt index here rather than in Start, so a Server can
	// never answer an apt request from an empty snapshot. loadStore has
	// already run LoadIndex by this point, so the manifests are current.
	s.rebuildAptSnapshot(context.Background())
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
	h = MutationAuthMiddleware(s.adminNetsFunc(), s.auditDB, s.pepper, s.logger)(h)
	h = DenyListMiddleware(s.denyNetsFunc(), s.auditDB)(h)
	h = RequestLogger(s.logger)(h)
	h = RealIPMiddleware(s.trustedNetsFunc())(h)
	h = SecurityHeadersMiddleware(h)
	return h
}

// guardPlaintext refuses to bind an unencrypted listener nobody requested.
//
// Four states arrive at the same hazard — autocert accepted but unimplemented,
// half a certificate pair, an empty pair, and an empty pair on the port every
// client reads as TLS — and all four refuse through this one function.
// Starting silently in plain HTTP is the security hazard the autocert case
// already named; two refusals for one hazard, worded differently, is how an
// operator learns to route around the second.
//
// allow_plaintext is the request. An empty tls_cert is not one: Save marshals
// the whole resolved Config back over the file, so a cert path cleared in the
// TUI reaches this function with nothing else having noticed.
func (s *Server) guardPlaintext() error {
	// Re-checked after config.Load has already run it: --tls-cert and
	// --tls-key are written into the Config afterwards, so a clean file plus
	// one flag reaches here as a half pair.
	if err := s.cfg.ValidateTLSPair(); err != nil {
		return err
	}
	if s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
		return nil
	}
	// Named before AllowPlaintext on purpose: autocert plus plaintext is a
	// contradictory pair and refusing it is the right answer. What the message
	// may not do is offer allow_plaintext as the escape, because an operator
	// who already set it arrives here anyway. It names the one change that
	// clears the refusal, and names the flag that will not.
	if s.cfg.TLSAutocert {
		return fmt.Errorf(`tls_autocert is enabled but not yet implemented; set "tls_autocert": false in the config file, then either set tls_cert and tls_key or set allow_plaintext to serve without TLS. --tls-autocert=false will not clear it: the flag can only turn autocert on`)
	}
	if s.cfg.AllowPlaintext {
		if tlsPort(s.addr) {
			s.logger.Warn("serving plaintext HTTP on the port clients read as TLS; every request and response is in the clear",
				"addr", s.addr, "authorized_by", "allow_plaintext")
		}
		return nil
	}
	if tlsPort(s.addr) {
		return fmt.Errorf("refusing to serve plaintext HTTP on %s: tls_cert and tls_key are empty and clients reach that port expecting TLS; set both, or set allow_plaintext (--allow-plaintext) if something in front terminates TLS", s.addr)
	}
	return fmt.Errorf("refusing to serve plaintext HTTP on %s: tls_cert and tls_key are empty, which means nothing was configured rather than serve in the clear; set both, or set allow_plaintext (--allow-plaintext) to serve unencrypted on purpose", s.addr)
}

// tlsPort reports whether addr names the port clients read as TLS. A port is
// not authorization, but it is the strongest evidence available that whoever
// wrote listen_addr expected a certificate to be in play.
func tlsPort(addr string) bool {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return port == "443" || port == "https"
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

	if s.adminErr != nil {
		return s.adminErr
	}

	if err := s.guardPlaintext(); err != nil {
		return err
	}

	// Configure TLS if cert/key are provided.
	if s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(s.cfg.TLSCert, s.cfg.TLSKey)
		if err != nil {
			return fmt.Errorf("load TLS certificate: %w", err)
		}
		minVer, err := s.cfg.ResolveTLSMinVersion()
		if err != nil {
			return err
		}
		srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   minVer,
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
		_, _ = fmt.Fprint(os.Stderr, s.aptSourcesBanner())
	}
	if tlsMode {
		s.logger.Info("bodega server listening (TLS)", "addr", boundAddr)
	} else {
		s.logger.Info("bodega server listening", "addr", boundAddr)
	}

	// Notify systemd we're ready. No-op outside systemd (NOTIFY_SOCKET unset).
	sdNotifyReady()

	// Lifecycle rows bracket every other row in the database, so a reader can
	// tell "nothing happened" from "the server was not running". Recorded here
	// rather than at the top of Start because a bind that failed never served
	// anything; the deferred stop pairs with this one on every exit path,
	// including the one where Serve returns an error.
	s.recordLifecycle(audit.EventServeStart, boundAddr, tlsMode)
	defer s.recordLifecycle(audit.EventServeStop, boundAddr, tlsMode)

	// Apt index refresh. Valid-Until is stamped when a snapshot is built and
	// does not move, so without this loop a long-running server eventually
	// serves an expired Release and every client fails apt update at once.
	go s.aptRefreshLoop(ctx)

	// Discovery worker — drains the recorder's queue until ctx is cancelled.
	if s.discovery != nil {
		go s.discovery.Start(ctx)
		s.logger.Info("upstream discovery enabled", "mode", s.discoverMode)
	}

	// Start the serve loop.
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ln)
	}()

	// SIGHUP reloads the manifest index, the signing key, and the caches
	// built from them.
	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	//nolint:gosec // G118: signal handler is server-lifecycle, intentionally decoupled from any request context.
	go func() {
		for range sighupCh {
			s.reload(context.Background())
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

// recordLifecycle writes a serve_start or serve_stop row. The context is
// deliberately not the caller's: a stop is recorded while the shutdown context
// is already cancelled, and a lifecycle row that vanishes precisely when the
// server goes down is the one nobody can afford to lose.
func (s *Server) recordLifecycle(ev audit.EventType, addr string, tlsMode bool) {
	if s.auditDB == nil {
		return
	}
	details, err := json.Marshal(map[string]any{
		"addr": addr,
		"tls":  tlsMode,
		"pid":  os.Getpid(),
	})
	if err != nil {
		details = []byte("{}")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.auditDB.Record(ctx, audit.Event{
		EventType: ev,
		Status:    "success",
		Details:   string(details),
		Actor:     audit.CurrentActor(),
	}); err != nil {
		s.logger.Error("could not record server lifecycle event",
			"event", string(ev), "error", err)
	}
}

// reload is what SIGHUP does: re-read everything the server holds outside its
// own memory and rebuild what is derived from it.
//
// The CIDR access lists are re-read here as well as behind their own cache
// TTL. The cache is what makes `bodega acl` land on a running server at all;
// the call here is what keeps `systemctl reload bodega` honest, because a
// reload that silently skipped the list an operator had just edited would be
// worse than having no reload.
//
// The signing key is re-read here rather than only at startup because the
// published rotation runbook has the operator write a key and reload. With
// only a restart honoring it, `generate --rotate` would leave the served
// keyring carrying the outgoing key alone while clients were being told to
// re-fetch, and `retire` would leave the process signing with a key no longer
// on disk until something restarted it and broke every client at once.
//
// Order matters twice. The key is installed before the rebuild, because the
// rebuild is what signs. And a manifest read that fails does not abandon the
// rest: the key half of a reload staying inert because the backend hiccuped is
// the same trap in a rarer shape, and the hourly tick already treats a failed
// manifest read as non-fatal and rebuilds anyway.
func (s *Server) reload(ctx context.Context) {
	s.logger.Info("reload requested, re-reading manifests, the apt signing key and the CIDR access lists")
	s.reloadManifests(ctx)
	s.loadAptSigner()
	s.rebuildAptSnapshot(ctx)
	s.refreshACLs(ctx)
	s.logger.Info("reload complete")
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

	// APT repository: generated index, served from a snapshot.
	// dists/{distpath...} carries Release, InRelease and Release.gpg;
	// handleAptDists splits them, since ServeMux has no mid-segment wildcard
	// for binary-{arch}. The keyring routes serve the loaded signing key and
	// 404 when there is none; .gpg is the dearmored form signed-by= wants, so
	// a client needs no gpg binary to consume it.
	m.HandleFunc("GET /apt/dists/{distpath...}", s.handleAptDists)
	m.HandleFunc("GET /apt/pool/{path...}", s.handleAptPool)
	m.HandleFunc("GET /apt/bodega-archive-keyring.gpg", s.handleAptKeyring)
	m.HandleFunc("GET /apt/bodega-archive-keyring.asc", s.handleAptPublicKey)

	// PyPI simple index (PEP 503)
	m.HandleFunc("GET /pypi/simple/", s.handlePypiIndex)
	m.HandleFunc("GET /pypi/simple/{package}/", s.handlePypiPackage)

	// PyPI wheels (path... to support versioned subdirs like pypi/wheels/0.4.6/foo.whl)
	m.HandleFunc("GET /pypi/wheels/{path...}", s.handlePypiWheel)

	// Git bundles, and the namespaced smart-HTTP form. The bundle pattern is
	// the more specific of the two, so it keeps every path it already served;
	// {path...} takes the deeper paths a clone URL carries.
	m.HandleFunc("GET /git/{name}/{file}", s.handleGitBundle)
	m.HandleFunc("GET /git/{namespace}/{path...}", s.handleGitNamespace)
	if s.gitTool != nil {
		// The POST half of smart-HTTP exists only when the CGI that answers it
		// does. Without it a clone gets a 405 from the mux instead of reaching
		// a handler with no backend to exec.
		m.HandleFunc("POST /git/{namespace}/{path...}", s.handleGitNamespace)
	}

	// Binary downloads
	m.HandleFunc("GET /binaries/{path...}", s.handleBinary)

	// Go module proxy (GOPROXY protocol)
	m.HandleFunc("GET /go/{path...}", s.handleGomod)

	// Helm chart repository
	m.HandleFunc("GET /helm/index.yaml", s.handleHelmIndex)
	m.HandleFunc("GET /helm/charts/{file}", s.handleHelmChart)

	// npm registry
	m.HandleFunc("GET /npm/{path...}", s.handleNpm)

	// cargo sparse registry (sparse+https://bodega/cargo/)
	m.HandleFunc("GET /cargo/{path...}", s.handleCargo)

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
	m.HandleFunc("POST /api/v1/packages/import", s.handleBulkImport)
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

// requireAdmin gates the sensitive read endpoints, writing the 403 and the
// audit row when the caller is not permitted. It exists so that refusing a
// read of the audit trail is itself in the audit trail: these handlers sit
// behind the mutation middleware, not inside it, so nothing else would record
// them.
//
// Returns true when the request may proceed.
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.isAdminRequest(r) {
		return true
	}
	s.logger.Warn("admin endpoint blocked: IP not in admin_permit_cidr",
		"client_ip", ClientIP(r), "method", r.Method, "path", r.URL.Path)
	recordDenial(s.auditDB, r, audit.DenialAdminOnly, nil)
	http.Error(w, "Forbidden", http.StatusForbidden)
	return false
}

// isAdminRequest checks whether the request originates from an IP in
// admin_permit_cidr. Used to gate sensitive read endpoints (audit, tokens,
// policies, config) that don't go through the mutation middleware, and it
// answers with the same predicate that middleware uses.
func (s *Server) isAdminRequest(r *http.Request) bool {
	return AdminPermits(s.aclNow().admin, net.ParseIP(ClientIP(r)))
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
	Apt        aptStatus       `json:"apt"`
	S3Entries  []s3EntryStatus `json:"s3_entries,omitempty"`
	Error      string          `json:"error,omitempty"`
}

type s3EntryStatus struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	S3Key   string `json:"s3_key"`
	InS3    bool   `json:"in_s3"`
	Frozen  bool   `json:"frozen,omitempty"`
	Backend string `json:"backend,omitempty"`
	Error   string `json:"error,omitempty"`
}

func (s *Server) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	resp := statusResponse{
		Healthy: true,
		Apt:     s.aptStatusFor(r),
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

	if s.stores == nil {
		resp.Healthy = false
		resp.Error = "storage backend not configured"
		writeJSON(w, http.StatusServiceUnavailable, resp)
		return
	}

	// Probe the apt pool on every backend, one row each. dists/ is generated
	// per request and never stored, so it cannot answer whether the object
	// store holds anything; the pool is what upload writes, and its prefix
	// names no codename.
	//
	// This is the inverse of the listing fan-out's policy, and deliberately.
	// A package index fails the whole request on a backend error, because a
	// short index is indistinguishable from packages having been withdrawn and
	// apt acts on the difference. A diagnostic exists to say which backend is
	// broken, so it reports every backend it could reach, marks the one it
	// could not, and calls the server unhealthy.
	for _, ns := range s.stores.All() {
		row := s3EntryStatus{
			Type:    manifest.TypeApt,
			Name:    "apt-pool",
			S3Key:   manifest.AptPoolPrefix,
			Backend: ns.Name,
		}
		keys, err := ns.Store.List(r.Context(), manifest.AptPoolPrefix)
		if err != nil {
			resp.Healthy = false
			resp.Error = "one or more storage backends failed to respond"
			row.Error = err.Error()
			s.logger.Error("object store probe failed", "backend", ns.Name, "prefix", manifest.AptPoolPrefix, "error", err)
		} else {
			row.InS3 = len(keys) > 0
		}
		resp.S3Entries = append(resp.S3Entries, row)
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
	if !s.requireAdmin(w, r) {
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

	if !manifest.IsKnownType(t) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("unknown type %q", t)})
		return
	}

	// All types accept a PackageManifest with at least one VersionEntry.
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
	pm.Type = t

	// An HTTP caller is not the process owner, so the audit rows this writes
	// carry no actor rather than the server's.
	res := admit.Admit(ctx, s.policy, s.auditDB, s.cfg, &pm, "")
	for _, warning := range res.Warnings {
		s.logger.Warn("manifest accepted with a warning", "type", t, "name", pm.Name, "warning", warning)
	}
	switch res.Decision {
	case admit.Invalid:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": res.Reason})
		return
	case admit.PolicyBlocked:
		s.logger.Warn("create rejected by policy", "type", t, "name", pm.Name, "reason", res.Reason)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": res.Reason})
		return
	}

	// Conflict is checked after admission so a manifest that is both refused
	// and already present reports the refusal, which is the answer the caller
	// can act on.
	existing, _ := s.store.GetPackage(ctx, t, pm.Name)
	if existing != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "package already exists"})
		return
	}

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
	s.rebuildAptIndexAfterWrite(ctx, t)
	writeJSON(w, http.StatusCreated, &pm)
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
	s.rebuildAptIndexAfterWrite(ctx, t)

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "type": t, "name": name})
}

// rebuildAptIndexAfterWrite regenerates the apt snapshot when a mutation
// touched apt. Without it the snapshot outlives the write that invalidated it,
// which is the same stale-index defect the snapshot was introduced to fix,
// only slower. Other package types have no generated index to go stale, and
// the rebuild lists the pool, so it is not free.
//
// The request context is deliberately dropped. The write has already
// committed by this point, so a client that hangs up mid-response would
// otherwise cancel the pool listing and leave the index describing the state
// before its own write — a 201 that is honest about the write and silent
// about the index. The startup and SIGHUP paths detach for the same reason.
func (s *Server) rebuildAptIndexAfterWrite(_ context.Context, t string) {
	if t != manifest.TypeApt {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), aptRebuildTimeout)
	defer cancel()
	s.rebuildAptSnapshot(ctx)
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
	s.rebuildAptIndexAfterWrite(ctx, t)
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
	s.rebuildAptIndexAfterWrite(ctx, t)
	writeJSON(w, http.StatusOK, pm)
}

// ---- Audit API -------------------------------------------------------------

func (s *Server) handleAPIAudit(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
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
		var n int
		if _, err := fmt.Sscanf(limit, "%d", &n); err == nil && n > 0 {
			f.Limit = n
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
	if !s.requireAdmin(w, r) {
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
	if !s.requireAdmin(w, r) {
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

// ---- Storage resolution ----------------------------------------------------

// typeStore returns the backend for regenerable, type-scoped objects:
// generated indexes, proxy-cache entries, attestation blobs and artifacts
// whose handler holds no manifest entry. Returns nil when no storage backend
// was configured, which every caller reports as 503 via requireStorage.
func (s *Server) typeStore(typ string) storage.ObjectStore {
	if s.stores == nil {
		return nil
	}
	return s.stores.ForType(typ)
}

// versionStore returns the backend recorded for one artifact.
//
// It reads the name on the version entry and never the config hierarchy. The
// hierarchy decides where the next write goes; an artifact already written is
// wherever it was written, so consulting it here would 404 everything placed
// under the previous rule. An empty recorded name is the default backend —
// see the contract on manifest.VersionEntry.Storage.
//
// A request whose manifest entry does not exist is not an error. Generated
// indexes, proxy-cache entries and attestation blobs carry no version to
// record a name against, and every one of them is regenerable, so
// the type rule is safe for them at both read and write.
func (s *Server) versionStore(ctx context.Context, typ, pkg, version string) (storage.ObjectStore, error) {
	if s.stores == nil {
		return nil, nil
	}
	if pkg == "" {
		return s.stores.ForType(typ), nil
	}
	pm, err := s.store.GetPackage(ctx, typ, pkg)
	if err != nil || pm == nil {
		return s.stores.ForType(typ), nil
	}
	for _, ve := range pm.Versions {
		if ve.Version == version || (version != "" && ve.Ref == version) {
			return s.stores.ByName(ve.Storage)
		}
	}
	return s.stores.ForType(typ), nil
}

// proxyVersion serves an artifact from the backend its manifest entry names.
//
// An unresolvable name is 502, not a fallback to another backend: the digest
// generateAptPackages publishes is recorded against one specific backend, so
// serving bytes from a different one is the signature the checksum machinery
// exists to flag.
func (s *Server) proxyVersion(w http.ResponseWriter, r *http.Request, typ, pkg, version, key string) {
	store, err := s.versionStore(r.Context(), typ, pkg, version)
	if err != nil {
		s.logger.Error("storage backend recorded for artifact is not configured",
			"type", typ, "package", pkg, "version", version, "key", key, "error", err)
		http.Error(w, "storage backend error", http.StatusBadGateway)
		return
	}
	s.proxyS3(w, r, store, key)
}

// listFanout unions List across every backend a read of typ may reach.
//
// One backend failing fails the whole call. A partial index is worse than an
// error: a client cannot tell a short PEP 503 or Packages list from packages
// having been withdrawn, and acts on the difference.
//
// The union is sorted here rather than merged: ObjectStore.List guarantees each
// backend's own order, but concatenating two sorted lists is not sorted and
// deduplication drops entries from either one. Packages.gz is gzipped per
// request, so an unstable order changes the bytes and every client refetches.
func (s *Server) listFanout(ctx context.Context, typ, prefix string) ([]string, error) {
	if s.stores == nil {
		return nil, nil
	}
	seen := map[string]struct{}{}
	var keys []string
	for _, ns := range s.stores.Fanout(ctx, typ, s.recordedBackends(ctx, typ)) {
		got, err := ns.Store.List(ctx, prefix)
		if err != nil {
			return nil, fmt.Errorf("list %q on storage backend %q: %w", prefix, ns.Name, err)
		}
		for _, k := range got {
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

// recordedBackends returns every backend name the manifests hold for this
// type: the name on each version entry, plus each package's storage_policy for
// the versions it has not been applied to yet.
//
// The fan-out needs this because config cannot answer it. A package moved with
// 'bodega pkg move', or placed by its own policy, sits on a backend no
// storage_by_type key for its type names, and an index built without it would
// be short by exactly that package.
func (s *Server) recordedBackends(ctx context.Context, typ string) []string {
	seen := map[string]struct{}{}
	var names []string
	add := func(name string) {
		if name == "" {
			return
		}
		if _, dup := seen[name]; dup {
			return
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	for _, pkg := range s.store.ListPackages(typ) {
		pm, err := s.store.GetPackage(ctx, typ, pkg)
		if err != nil || pm == nil {
			continue
		}
		add(pm.StoragePolicy)
		for _, ve := range pm.Versions {
			add(ve.Storage)
		}
	}
	return names
}

// ---- S3 proxy core ---------------------------------------------------------

// proxyS3 streams an object to the HTTP response from the given backend.
// It sets Content-Type from the file extension and Content-Length from the
// store's metadata. Returns 404 when the key does not exist.
//
// The backend is a parameter rather than something resolved in here from
// s3Key: a key carries the artifact's type but not its package or version, and
// placement is recorded per version, so the key cannot answer which backend
// holds it. Callers that hold a manifest entry resolve by its recorded name;
// callers serving regenerable, type-scoped objects pass typeStore.
func (s *Server) proxyS3(w http.ResponseWriter, r *http.Request, store storage.ObjectStore, s3Key string) {
	if !s.requireStorage(w, store) {
		return
	}
	result, err := store.GetStream(r.Context(), s3Key)
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
