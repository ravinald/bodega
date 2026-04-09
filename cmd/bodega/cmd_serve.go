package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/scaleapi/bodega/internal/logging"
	bos3 "github.com/scaleapi/bodega/internal/s3"
	"github.com/scaleapi/bodega/internal/server"
)

func newServeCmd(gf *globalFlags) *cobra.Command {
	var (
		addr        string
		tlsCert     string
		tlsKey      string
		tlsAutocert bool
		tlsDomain   string
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
  --tls-autocert --tls-domain  Automatic Let's Encrypt certificates`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
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

			// S3 client is optional. Without it, API endpoints still work
			// but package proxying returns 503.
			var s3client *bos3.Client
			if cfg.Bucket != "" {
				ctx := backgroundCtx()
				c, err := bos3.NewClient(ctx, cfg.Bucket, cfg.Region)
				if err != nil {
					logger.Warn("S3 not available — package serving disabled", "error", err)
				} else {
					s3client = c
				}
			} else {
				logger.Warn("no bucket configured — package serving disabled, API only")
			}

			srv := server.New(cfg, store, s3client, addr, logger)

			// Graceful shutdown on SIGTERM/SIGINT.
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
			defer stop()

			return srv.Start(ctx)
		},
	}

	cmd.Flags().StringVar(&addr, "addr", ":8080", "TCP address to listen on (e.g. :8080 or 0.0.0.0:9090)")
	cmd.Flags().StringVar(&tlsCert, "tls-cert", "", "Path to TLS certificate PEM file")
	cmd.Flags().StringVar(&tlsKey, "tls-key", "", "Path to TLS private key PEM file")
	cmd.Flags().BoolVar(&tlsAutocert, "tls-autocert", false, "Enable automatic TLS via Let's Encrypt (requires --tls-domain)")
	cmd.Flags().StringVar(&tlsDomain, "tls-domain", "", "Domain name for autocert (e.g. bodega.example.com)")
	return cmd
}
