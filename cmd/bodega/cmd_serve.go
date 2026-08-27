package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/logging"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/server"
	"github.com/ravinald/bodega/internal/storage"
)

func newServeCmd(gf *globalFlags) *cobra.Command {
	var (
		addr        string
		tlsCert     string
		tlsKey      string
		tlsAutocert bool
		tlsDomain   string
		quiet       bool
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the HTTP(S) package server",
		Long: `serve starts an HTTP(S) server that serves packages to standard package manager clients.

Clients can use the server as follows:

  apt:  /etc/apt/sources.list.d/bodega.sources, deb822 form:
          Types: deb
          URIs: https://bodega-host:8080/apt/
          Suites: <suite>
          Components: main
          Signed-By: /etc/apt/keyrings/bodega-archive-keyring.gpg
  pip:  pip install --index-url https://bodega-host:8080/pypi/simple/ <package>
  git:  curl https://bodega-host:8080/git/<name>/<name>-<ref>.bundle -o <name>.bundle

<suite> is any entry in the config's apt_suites list (default: the single value
of apt_codename, "noble"). Several suites go on one Suites: line; the pool is
shared.

Fetch the keyring from /apt/bodega-archive-keyring.gpg, which serves the
dearmored form Signed-By takes directly. That first fetch is authenticated by
TLS alone, so compare the fingerprint against "bodega apt key show".

With no signing key installed the repository is served unsigned and a client
needs "deb [trusted=yes] https://bodega-host:8080/apt/ <suite> main" instead,
which turns off verification for that source permanently. TLS is then the only
thing authenticating the packages, so serve over https either way.

Run "bodega apt key generate" to sign. Signed and unsigned coexist at the same
URLs, so adding a key breaks no existing client.

The server also exposes a REST API at /api/v1/ for manifest inspection and
health checking.

S3 objects are streamed directly to clients — the server does not buffer
artifacts in memory.

TLS can be enabled in two ways:
  --tls-cert and --tls-key     Manual PEM certificate files
  --tls-autocert --tls-domain  Automatic Let's Encrypt certificates

Listen address resolution (highest priority first):
  --addr flag → $BODEGA_LISTEN_ADDR → config.json "listen_addr" → :8080

Use --quiet to suppress the startup banner for scripted use; log-level
output continues to respect log_level in the config.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
			// Clean up stale PID file from a previous server instance.
			server.CleanStalePID(cfg.LogDir)
			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}

			// Set up structured logger.
			level := logging.SlogLevel(cfg.LogLevel)
			handler := logging.NewHandler(os.Stderr, level)
			logger := slog.New(handler)

			// An empty index is indistinguishable from a healthy repository
			// from the outside: the unit reaches active (running), /healthz
			// answers 200, and dists/<suite>/Release lists the SHA-256 of the
			// empty string for Packages. Error, not Warn, because the shipped
			// default log_level prints only Error.
			if totalPackages(store) == 0 {
				logger.Error("no packages loaded — every repository index will publish as empty",
					"manifests", store.Label(), "config", config.ConfigPath())
			}

			// Resolve TLS config: flags override config file.
			if tlsCert != "" {
				cfg.TLSCert = tlsCert
			}
			if tlsKey != "" {
				cfg.TLSKey = tlsKey
			}
			if tlsAutocert {
				cfg.TLSAutocert = true
			}
			if tlsDomain != "" {
				cfg.TLSDomain = tlsDomain
			}

			// Object storage is optional. Without it, API endpoints still work
			// but package proxying returns 503.
			//
			// Logged at Error, not Warn: the shipped default log_level maps to
			// slog.LevelError, so a Warn here printed nothing and the whole
			// observable symptom was "server is up, apt gets 503, logs empty".
			var stores storage.Resolver
			ctx := backgroundCtx()
			resolved, err := storage.NewResolver(ctx, cfg)
			if err != nil {
				logger.Error("storage backend unavailable — package routes will answer 503; the API and /healthz still serve",
					"backend", storageBackendName(cfg), "config", config.ConfigPath(), "error", err)
			} else {
				stores = resolved
			}

			// Resolve listen address: flag → env → config file → default.
			resolvedAddr := cfg.ResolveListenAddr(addr)

			srv := server.New(cfg, store, stores, resolvedAddr, logger)
			srv.SetQuiet(quiet)

			// Graceful shutdown on SIGTERM/SIGINT.
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
			defer stop()

			return srv.Start(ctx)
		},
	}

	// Flag default is intentionally empty — precedence is applied in
	// cfg.ResolveListenAddr so $BODEGA_LISTEN_ADDR and config.json
	// "listen_addr" can win when --addr isn't given on the command line.
	cmd.Flags().StringVar(&addr, "addr", "", fmt.Sprintf("TCP address to listen on (default %s; env: %s)", config.DefaultListenAddr, config.EnvListenAddr))
	cmd.Flags().StringVar(&tlsCert, "tls-cert", "", "Path to TLS certificate PEM file")
	cmd.Flags().StringVar(&tlsKey, "tls-key", "", "Path to TLS private key PEM file")
	cmd.Flags().BoolVar(&tlsAutocert, "tls-autocert", false, "Enable automatic TLS via Let's Encrypt (requires --tls-domain)")
	cmd.Flags().StringVar(&tlsDomain, "tls-domain", "", "Domain name for autocert (e.g. bodega.example.com)")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "Suppress the stderr startup banner (log_level output is unaffected)")
	return cmd
}

// totalPackages counts every package name in the loaded index, across types.
func totalPackages(store *manifest.Store) int {
	n := 0
	for _, names := range store.AllPackages() {
		n += len(names)
	}
	return n
}
