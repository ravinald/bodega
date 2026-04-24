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

  apt:  deb [trusted=yes] http://bodega-host:8080/apt/ noble main
  pip:  pip install --index-url http://bodega-host:8080/pypi/simple/ <package>
  git:  curl http://bodega-host:8080/git/<name>/<name>-<ref>.bundle -o <name>.bundle

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
			var objects storage.ObjectStore
			ctx := backgroundCtx()
			obj, err := storage.New(ctx, cfg)
			if err != nil {
				logger.Warn("storage backend not available — package serving disabled", "error", err)
			} else {
				objects = obj
			}

			// Resolve listen address: flag → env → config file → default.
			resolvedAddr := cfg.ResolveListenAddr(addr)

			srv := server.New(cfg, store, objects, resolvedAddr, logger)
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
