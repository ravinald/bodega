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
		addr       string
		tlsCert    string
		tlsKey     string
		allowPlain bool
		publicURL  string
		quiet      bool
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the HTTP(S) package server",
		Long: `serve starts an HTTP(S) server that serves packages to standard package manager clients.

Clients can use the server as follows:

  apt:  the startup banner prints the stanza for
        /etc/apt/sources.list.d/bodega.sources, carrying the suites this
        instance serves, the URL from public_url, and Signed-By: or the
        [trusted=yes] fallback according to whether a signing key is loaded.
        The same block is on GET /api/v1/status.
  pip:  pip install --index-url https://bodega-host:8080/pypi/simple/ <package>
  git:  curl https://bodega-host:8080/git/<name>/<name>-<ref>.bundle -o <name>.bundle

Run "bodega apt key generate" to sign. Signed and unsigned coexist at the same
URLs, so adding a key breaks no existing client.

The server also exposes a REST API at /api/v1/ for manifest inspection and
health checking.

S3 objects are streamed directly to clients — the server does not buffer
artifacts in memory.

TLS is enabled by --tls-cert and --tls-key, a PEM pair bodega reads at
startup. bodega has no ACME client: obtain the pair from certbot or your CA,
or terminate TLS at a proxy in front and set public_url.

Serving in the clear is an explicit request, not the absence of one. With no
certificate pair, serve refuses to bind unless --allow-plaintext (config key
allow_plaintext) is set. Setting only one of --tls-cert/--tls-key is an error
either way: bodega will not read half a pair as a request for plaintext.

Listen address resolution (highest priority first):
  --addr flag > $BODEGA_LISTEN_ADDR > config.json "listen_addr" > :8080

public_url is the base URL clients reach this server at. Set it whenever a
reverse proxy terminates TLS or publishes a different hostname: bodega then
sees a loopback listener with no TLS and cannot derive the URL an operator
would copy, so it prints a placeholder instead of guessing.
  --public-url flag > $BODEGA_PUBLIC_URL > config.json "public_url"

On a filesystem backend serve checks manifest_dir before binding. An absent
directory is created, so a fresh install comes up with an empty repository and
apt update succeeds. One that cannot be created or opened stops the start: a
server that publishes an empty Release over a manifest root nothing can read is
indistinguishable from a healthy one that holds no packages.

Use --quiet to suppress the startup banner for scripted use; log-level
output continues to respect log_level in the config.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
			// Before anything opens a socket: a server that starts over an
			// unreadable manifest root publishes an empty repository and looks
			// healthy doing it.
			if err := ensureManifestRoot(cfg); err != nil {
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

			// A repository with no packages is legal and serves a valid
			// Release whose Packages digest is the SHA-256 of the empty
			// string. So does one whose manifest root is missing, and from
			// the outside the two are the same bytes. ensureManifestRoot has
			// already refused the second case, which leaves this log meaning
			// only "nothing imported yet". Error, not Warn, because the
			// shipped default log_level prints only Error.
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
			reportRetiredTLSKeys(cfg, logger)
			// Gated on Changed rather than on the value, so --allow-plaintext=false
			// turns off a config file that set it true. --tls-cert and --tls-key
			// resolve on the value instead, which is harmless only because their
			// zero value is the same "not configured" the guard already refuses.
			if cmd.Flags().Changed("allow-plaintext") {
				cfg.AllowPlaintext = allowPlain
			}
			// Resolved into the Config rather than passed alongside it: every
			// client-facing URL this process emits reads it back off cfg, and
			// serve never writes the config file.
			cfg.PublicURL = cfg.ResolvePublicURL(publicURL)

			ctx := backgroundCtx()
			stores := startupStorage(ctx, cfg, logger)

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
	cmd.Flags().BoolVar(&allowPlain, "allow-plaintext", false, "Serve without TLS; required when tls_cert/tls_key are unset (config: allow_plaintext)")
	cmd.Flags().StringVar(&publicURL, "public-url", "", fmt.Sprintf("Base URL clients reach this server at, e.g. https://bodega.example.com (env: %s)", config.EnvPublicURL))
	cmd.Flags().BoolVar(&quiet, "quiet", false, "Suppress the stderr startup banner (log_level output is unaffected)")
	return cmd
}

// startupStorage builds the resolver serve reads artifacts through, and
// returns nil when it cannot be built.
//
// Storage staying non-fatal is a decision, not an oversight. /healthz, the
// REST API, the audit surface and the TUI are exactly what an operator needs
// while a bucket or a directory is unreachable, and exiting takes them away at
// the moment they are wanted. What was wrong was the silence: the failure was
// logged below the shipped default log_level, so the whole observable symptom
// was "server is up, apt gets 503, logs empty".
//
// Error, not Warn, because every package route answers 503 from here on. The
// message names the configured backend and the underlying error, since the
// 503 body deliberately names no driver — it cannot know one, and the old
// wording guessed S3 on installs whose config never mentioned it.
func startupStorage(ctx context.Context, cfg *config.Config, logger *slog.Logger) storage.Resolver {
	stores, err := storage.NewResolver(ctx, cfg)
	if err != nil {
		logger.Error("storage backend unavailable — package routes will answer 503; the API and /healthz still serve",
			"backend", storageBackendName(cfg), "config", config.ConfigPath(), "error", err)
		return nil
	}
	return stores
}

// reportRetiredTLSKeys says that a config file still carrying tls_autocert is
// carrying a key nothing reads.
//
// Save preserves keys it did not parse, so retiring the option left the value
// sitting in the file looking like a setting in force. The level splits on
// whether serving changes: with a certificate pair the listener does what the
// operator wanted and only the key is dead, so Warn. Without one, the config
// that used to say "get a certificate automatically" now says nothing, and
// this server is about to refuse to bind or serve in the clear.
func reportRetiredTLSKeys(cfg *config.Config, logger *slog.Logger) {
	raw, ok := cfg.RawFileValue("tls_autocert")
	if !ok || string(raw) != "true" {
		return
	}
	const msg = "tls_autocert was removed and is ignored; bodega has no ACME client"
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		logger.Warn(msg+" — tls_cert and tls_key are serving this listener; delete the key",
			"config", config.ConfigPath())
		return
	}
	logger.Error(msg+" — no certificate pair is configured, so this server serves in the clear or refuses to bind; set tls_cert and tls_key, or terminate TLS in front and set allow_plaintext",
		"config", config.ConfigPath())
}

// totalPackages counts every package name in the loaded index, across types.
func totalPackages(store *manifest.Store) int {
	n := 0
	for _, names := range store.AllPackages() {
		n += len(names)
	}
	return n
}
