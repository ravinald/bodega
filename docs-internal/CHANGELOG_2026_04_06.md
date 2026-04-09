# Changelog — 2026-04-06

## Leveled logging system (`internal/logging/`)

Added structured, leveled logging built on Go's stdlib `log/slog`.

### New files

**`internal/logging/level.go`**
- `LevelTrace` constant (`slog.Level(-8)`) — custom level below Debug for
  full request/response body tracing
- `SlogLevel(verbosity int) slog.Level` — maps user-facing `--log-level 0–4`
  to slog levels: 0=Error, 1=Warn, 2=Info, 3=Debug, 4=Trace
- `LevelName(l slog.Level) string` — returns human-readable level names

**`internal/logging/handler.go`**
- Custom `slog.Handler` implementation that writes human-readable single-line
  records to an `io.Writer`
- Format: `15:04:05 LEVEL message key=value key=value`
- Thread-safe via internal mutex
- Full `slog.Handler` contract: `Enabled`, `Handle`, `WithAttrs`, `WithGroup`
- Automatic quoting for values containing spaces, equals, or quotes

**`internal/logging/handler_test.go`** — 9 unit tests:
- `TestSlogLevel` — all verbosity mappings
- `TestLevelName` — all named levels including Trace
- `TestHandlerEnabled` — level filtering
- `TestHandlerOutput` — timestamp, level, message, and attribute formatting
- `TestHandlerDropsBelowLevel` — disabled levels
- `TestHandlerWithAttrs` — pre-set attribute propagation
- `TestHandlerWithGroup` — grouped attribute prefix
- `TestHandlerQuotesSpecialValues` — quoting for spaces
- `TestNeedsQuoting` — table-driven quoting logic

## HTTP request logging and real IP middleware (`internal/server/`)

### New files

**`internal/server/middleware.go`**
- `RequestLogger(logger *slog.Logger) func(http.Handler) http.Handler` — HTTP
  middleware with verbosity-dependent detail:
  - Info: method, path, status, duration, bytes, client IP
  - Debug: + request headers, response headers
  - Trace: + request body, response body (capped at 64KB, binary skipped)
  - Skips `/healthz` to avoid noise
- `RealIPMiddleware(trustedNets []*net.IPNet) func(http.Handler) http.Handler`
  — extracts client IP from `X-Real-IP` / `X-Forwarded-For` when peer is in
  trusted networks; stores in request context
- `ClientIP(r *http.Request) string` — retrieves resolved client IP from context
- `responseRecorder` — captures status code, response size, and optionally
  response body for logging
- Default trusted networks: RFC 1918 + loopback (IPv4 and IPv6)

**`internal/server/middleware_test.go`** — 14 unit tests:
- RequestLogger at Info/Debug/Trace levels
- Health endpoint skip
- Binary content body skip
- Error-level-only no-output
- RealIP from X-Real-IP, X-Forwarded-For, untrusted peer, no headers, custom nets
- responseRecorder status, size, body capture, body cap
- Helper function tests (formatDuration, isBinaryContentType)

## HTTPS support and graceful shutdown (`internal/server/server.go`)

### Modified files

**`internal/server/server.go`**
- Added `logger *slog.Logger` field to `Server` struct
- Updated `New()` and `NewWithS3Getter()` to accept `*slog.Logger` (nil-safe)
- Replaced bare `log.Printf("s3 proxy error...")` with structured
  `s.logger.Error("s3 proxy error", "key", s3Key, "error", err)`
- `Start()` now accepts `context.Context` for graceful shutdown:
  - Listens in a goroutine; waits for context cancellation or server error
  - On shutdown: 30-second grace period via `srv.Shutdown()`, force-close fallback
- Added TLS support: when `cfg.TLSCert` and `cfg.TLSKey` are set, loads
  certificate and starts with `ListenAndServeTLS`
  - TLS 1.2 minimum, HTTP/2 auto-negotiated
- `Handler()` now returns the full middleware chain (RealIP → RequestLogger → mux)
- Removed `"log"` import; all logging through `log/slog`

**`internal/server/server_test.go`**
- Updated `newTestServer` to pass `nil` logger to `NewWithS3Getter`

## Config and CLI changes

**`internal/config/config.go`**
- Added `LogLevel int` to `Config` and `fileConfig` (`json:"log_level"`)
- Added `TLSCert`, `TLSKey`, `TLSAutocert`, `TLSDomain` string/bool fields
- Added `EnvLogLevel = "BODEGA_LOG_LEVEL"` constant
- Updated `Load()` to resolve log level and TLS fields from config file
- Updated `Save()` and `defaultConfigContent()` with new fields

**`cmd/bodega/main.go`**
- Added `logLevel int` to `globalFlags`
- Added `--log-level` persistent flag (int, default 0)
- `loadConfig()` now resolves log level: flag > `BODEGA_LOG_LEVEL` env > config
  file; `--verbose` maps to `--log-level 2` when log-level is unset

**`cmd/bodega/cmd_serve.go`**
- Added `--tls-cert`, `--tls-key`, `--tls-autocert`, `--tls-domain` flags
- Creates `slog.Logger` from config log level and passes to `server.New()`
- Graceful shutdown via `signal.NotifyContext` (SIGTERM/SIGINT)
- TLS flags override config file values

### Key design decisions

- Built on stdlib `log/slog` (Go 1.21+) — zero external logging dependencies
- Custom `Handler` implementation for human-readable terminal output rather than
  JSON (appropriate for an infrastructure CLI tool)
- Verbosity levels map to slog's built-in level system with one custom level
  (Trace at -8); the 4-unit gap between standard levels is intentional in slog's
  design for exactly this purpose
- RealIP middleware only trusts forwarded headers from RFC 1918 peers by default,
  preventing IP spoofing from untrusted clients
- TLS uses stdlib `crypto/tls` — no certmagic dependency yet (manual certs only
  in this iteration; autocert flags are accepted but not wired to certmagic)
- Response body capture is capped at 64KB and skips binary content types to
  avoid memory pressure on large artifact downloads
