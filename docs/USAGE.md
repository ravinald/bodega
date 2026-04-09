# bodega Usage Guide

Comprehensive documentation for the bodega package repository manager.

## Table of Contents

- [Commands](#commands)
- [Global Flags](#global-flags)
- [Configuration](#configuration)
- [Manifest Types](#manifest-types)
- [Pipeline](#pipeline)
- [HTTP Server](#http-server)
- [REST API](#rest-api)
- [Proxy/Cache](#proxycache)
- [Checksum Verification](#checksum-verification)
- [Audit Trail](#audit-trail)
- [TUI](#tui)
- [Manifest Integrity](#manifest-integrity)
- [Frozen Entries](#frozen-entries)
- [S3 Layout](#s3-layout)
- [Development](#development)

---

## Commands

### `bodega init`

Creates the S3 bucket with server-side encryption (AES-256), versioning enabled,
and all public access blocked. Idempotent.

### `bodega fetch [TYPE...] [--entry NAME]`

Downloads raw sources without building or packaging. If no types are given, all
types are fetched in dependency order: `binary → git → apt → pypi → gomod → helm → npm`.

The `--entry` flag restricts the operation to a single named entry.

### `bodega build [TYPE...] [--entry NAME]`

Compiles or prepares sources. Auto-fetches if sources are not already present
(stage cascading). Types without a build stage (binary, gomod) are skipped.

### `bodega package [TYPE...] [--entry NAME]`

Creates final distributable artifacts. Cascades through fetch and build as
needed.

| Type | Package output |
|------|---------------|
| git | `.bundle` file |
| apt | `.deb` via reprepro |
| pypi | `MANIFEST.sha256` |
| helm | `index.yaml` |
| npm | `packument.json` |

### `bodega upload [TYPE...]`

Runs the full pipeline (fetch → build → package) then uploads artifacts to S3.
This is the most common command for end-to-end operation.

### `bodega sync [TYPE...]`

Pushes whatever local artifacts exist to S3 **without** running any pipeline
stages. Useful when artifacts were built on a different machine.

### `bodega status [TYPE...]`

Compares each manifest entry against S3 and prints a table showing whether each
artifact is present.

### `bodega verify`

Checks that every `.md5` companion file matches its manifest. Use this to detect
out-of-band modifications.

### `bodega create <type>`

Adds a new entry to a manifest. Missing flags are prompted interactively.

```bash
bodega create git --name myrepo --url https://github.com/org/repo.git --ref v1.0.0
bodega create binary --name tool --url https://example.com/tool.tar.gz
bodega create gomod --name github.com/aws/sdk --ref v1.30.0
bodega create helm --name nginx --url https://charts.example.com/nginx-1.0.tgz --ref 1.0.0
bodega create npm --name lodash --ref 4.17.21
bodega create apt   # interactive prompts
```

**Create flags:**

| Flag | Purpose |
|------|---------|
| `--name` | Entry name |
| `--url` | URL (git remote, download URL, registry URL) |
| `--ref` | Version / git ref |
| `--sha256` | Expected SHA-256 (binary only) |
| `--filename` | Filename override (binary only) |
| `--build-cmd` | Shell command to build .deb (apt only) |
| `--deb-glob` | Glob to locate produced .deb (apt only) |
| `--source-name` | Source package name (apt only) |

### `bodega delete <type> <name> [--remove-from-s3]`

Removes an entry from the manifest. Pass `--remove-from-s3` to also delete the
artifact from S3. Frozen entries cannot be deleted.

### `bodega remove <type> <name>`

Removes an artifact from S3 without touching the manifest.

### `bodega freeze <type> <name>`

Toggles the `frozen` flag. Frozen entries cannot be built, edited, or deleted.
Running `freeze` on a frozen entry unfreezes it.

### `bodega serve [flags]`

Starts the HTTP(S) package server.

| Flag | Default | Purpose |
|------|---------|---------|
| `--addr` | `:8080` | TCP address to listen on |
| `--tls-cert` | | Path to TLS certificate PEM file |
| `--tls-key` | | Path to TLS private key PEM file |
| `--tls-autocert` | `false` | Enable automatic TLS via Let's Encrypt |
| `--tls-domain` | | Domain name for autocert |

The server handles graceful shutdown on SIGTERM/SIGINT, giving in-flight
requests up to 30 seconds to complete.

### `bodega shell`

Launches the interactive TUI. See [TUI](#tui) section for keybindings.

### `bodega audit [flags]`

Queries the SQLite audit database.

| Flag | Default | Purpose |
|------|---------|---------|
| `--type` | | Event type: fetch, build, create, delete, cache |
| `--pkg-type` | | Package type filter |
| `--name` | | Package name filter |
| `--client` | | Client IP filter |
| `--since` | | Show events after this time (RFC3339 or YYYY-MM-DD) |
| `--limit` | `20` | Max events to show |

```bash
bodega audit                                    # last 20 events
bodega audit --type fetch --limit 50            # last 50 fetches
bodega audit --pkg-type gomod --since 2026-04-07
bodega audit --client 10.0.0.5
```

### `bodega checksum list [--type TYPE] [--name NAME]`

Lists cached SHA-256 checksums stored in the audit database.

### `bodega checksum clear <type> <name> [--version VER]`

Clears cached checksums for a package. The next fetch will recompute and store
a fresh checksum. Use `--version` to clear only a specific version.

### `bodega --break-glass-update-md5 <type>`

Recomputes the MD5 digest for a manifest that was edited outside of the tool.

---

## Global Flags

| Flag | Env Var | Default | Purpose |
|------|---------|---------|---------|
| `--bucket` | `REPO_BUCKET` | | S3 bucket name |
| `--region` | `AWS_REGION` | `us-west-2` | AWS region |
| `--build-root` | `BOOTSTRAP_BUILD_ROOT` | `/opt/bodega` | Local build directory |
| `--manifest-dir` | | auto-detected | Path to manifests/ directory |
| `--local-config` | | `false` | Use local filesystem instead of S3 for manifests |
| `-v, --verbose` | | `false` | Verbose output (equivalent to `--log-level 2`) |
| `--log-level` | `BODEGA_LOG_LEVEL` | `0` | Logging verbosity: 0=errors, 1=warn, 2=info, 3=debug, 4=trace |
| `-V, --version` | | | Print version and exit |

---

## Configuration

Config files are loaded from (first found wins):

1. `/etc/bodega/config.json` (system-wide)
2. `~/.config/bodega/config.json` (per-user)

A default config is created on first run. All fields are optional.

```json
{
  "bucket": "bodega-864617344058",
  "region": "us-west-2",
  "build_root": "/opt/bodega",
  "manifest_dir": "manifests",
  "log_dir": "/var/log/bodega",
  "logwindow_height": 12,
  "log_level": 0,
  "custom_paths": false,
  "apt_root": "",
  "git_root": "",
  "pypi_root": "",
  "binary_root": "",
  "gomod_root": "",
  "helm_root": "",
  "npm_root": "",
  "tls_cert": "",
  "tls_key": "",
  "tls_autocert": false,
  "tls_domain": "",
  "proxy_cache_enabled": false,
  "metadata_ttl": "1h",
  "gomod_upstream": "https://proxy.golang.org",
  "npm_upstream": "https://registry.npmjs.org",
  "audit_db": ""
}
```

**Resolution priority:** CLI flags > environment variables > config file > built-in defaults.

### Per-type build roots

When `custom_paths` is `true`, each type can use a separate build directory. This
is useful when types have different storage requirements (e.g., wheels on a large
volume, binaries on fast SSD).

### Audit database

The audit DB path defaults to `{log_dir}/audit.db`. The database is created
automatically on first use.

---

## Manifest Types

Seven artifact types, each with a JSON manifest in the `manifests/` directory.

### apt

Debian packages built from source or downloaded from apt repositories.

```json
{
  "config_version": 1,
  "entries": [
    {
      "name": "amazon-efs-utils",
      "version": "2.4.2",
      "url": "https://github.com/aws/efs-utils.git",
      "build_cmd": "make deb",
      "deb_glob": "build/*.deb"
    }
  ]
}
```

When `url` is omitted, the package is fetched via `apt-get download`.

### git

Git repositories bundled at a specific ref.

```json
{
  "config_version": 1,
  "entries": [
    {
      "name": "netbox",
      "url": "https://github.com/netbox-community/netbox",
      "ref": "v4.5.5",
      "source": "release"
    }
  ]
}
```

`source` controls the fetch strategy: `"release"` (default) downloads the
release tarball; `"clone"` does a full bare clone + bundle.

### pypi

Python wheels built from a combined requirements set. This type uses a different
schema — a single manifest object rather than an entries array.

```json
{
  "config_version": 1,
  "version": "v4.5.5",
  "base_requirements": {
    "netbox": "v4.5.5"
  },
  "packages": [
    { "name": "boto3", "required_by": ["netbox"] },
    { "name": "django" }
  ]
}
```

### binary

Files downloaded directly from a URL.

```json
{
  "config_version": 1,
  "entries": [
    {
      "name": "awscli-v2",
      "version": "2.34.24",
      "url": "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip",
      "sha256": "abc123..."
    }
  ]
}
```

### gomod

Go modules fetched from upstream GOPROXY.

```json
{
  "config_version": 1,
  "entries": [
    {
      "name": "github.com/aws/aws-sdk-go-v2",
      "version": "v1.30.0"
    }
  ]
}
```

`url` overrides the upstream proxy (defaults to `proxy.golang.org`).

### helm

Helm charts fetched from chart repositories.

```json
{
  "config_version": 1,
  "entries": [
    {
      "name": "ingress-nginx",
      "version": "4.11.0",
      "url": "https://kubernetes.github.io/ingress-nginx/charts/ingress-nginx-4.11.0.tgz",
      "app_version": "1.11.0"
    }
  ]
}
```

### npm

npm packages fetched from registries.

```json
{
  "config_version": 1,
  "entries": [
    {
      "name": "lodash",
      "version": "4.17.21"
    }
  ]
}
```

`url` overrides the upstream registry (defaults to `registry.npmjs.org`).

### Common fields

All entry types support:

| Field | Type | Purpose |
|-------|------|---------|
| `frozen` | bool | Prevents building, editing, or deletion |
| `checksum` | object | `{"algorithm": "sha256", "value": "hex..."}` — auto-populated on first fetch |

---

## Pipeline

The build pipeline has four stages, processed in dependency order:

```
fetch → build → package → upload
```

**Stage cascading:** Each stage automatically runs its prerequisites if outputs
are missing. Running `bodega upload` on a fresh system will cascade through all
four stages.

**Build order:** `binary → git → apt → pypi → gomod → helm → npm`. This order
reflects dependencies (e.g., pypi may reference git-cloned repos for its base
requirements).

**Per-entry failures** are logged but do not abort the run. A non-zero exit code
is returned if any entry failed.

---

## HTTP Server

`bodega serve` starts a package server that clients use directly.

### Client configuration

**APT** (`/etc/apt/sources.list.d/bodega.list`):
```
deb [trusted=yes] http://bodega-host:8080/apt/ noble main
```

**pip** (per-command or `pip.conf`):
```bash
pip install --index-url http://bodega-host:8080/pypi/simple/ <package>
```

**Go modules**:
```bash
export GOPROXY=http://bodega-host:8080/go
go get github.com/aws/aws-sdk-go-v2@v1.30.0
```

**Helm**:
```bash
helm repo add bodega http://bodega-host:8080/helm
```

**npm** (per-command or `.npmrc`):
```bash
npm install --registry http://bodega-host:8080/npm <package>
```

### TLS

Manual certificates:
```bash
bodega serve --tls-cert cert.pem --tls-key key.pem
```

Or set in config:
```json
{ "tls_cert": "/etc/bodega/cert.pem", "tls_key": "/etc/bodega/key.pem" }
```

### Behind nginx

bodega is designed to work behind nginx. The server extracts real client IPs from
`X-Real-IP` and `X-Forwarded-For` headers when the request comes from a trusted
private network (RFC 1918 + loopback).

Minimal nginx config:
```nginx
server {
    listen 443 ssl;
    server_name bodega.example.com;

    ssl_certificate /etc/ssl/certs/bodega.pem;
    ssl_certificate_key /etc/ssl/private/bodega.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## REST API

All API responses are JSON.

### Read endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/packages` | All entries across all types |
| GET | `/api/v1/packages/{type}` | Entries for one type |
| GET | `/api/v1/packages/{type}/{name}` | Single entry details |
| GET | `/api/v1/status` | Health check with entry counts and S3 probe |
| GET | `/api/v1/config` | Non-sensitive config (bucket, region, manifest_dir) |
| GET | `/healthz` | Health probe (returns `ok`) |

### Mutation endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/packages/{type}` | Create a new entry (JSON body) |
| DELETE | `/api/v1/packages/{type}/{name}` | Delete an entry |

**Create example:**
```bash
curl -X POST http://localhost:8080/api/v1/packages/gomod \
  -H 'Content-Type: application/json' \
  -d '{"name": "github.com/aws/aws-sdk-go-v2", "version": "v1.30.0"}'
```

**Response codes:**
- `201 Created` — entry added
- `400 Bad Request` — missing required fields or invalid type
- `409 Conflict` — entry already exists
- `403 Forbidden` — entry is frozen (delete only)

---

## Proxy/Cache

When `proxy_cache_enabled` is `true`, the server fetches from upstream on cache
miss for gomod, helm, and npm routes.

**Flow:**
1. Client requests a package (e.g., `GET /go/github.com/foo/@v/v1.0.0.zip`)
2. Server checks S3 for cached copy
3. **Cache hit** (immutable or within TTL): serve from S3
4. **Cache miss**: fetch from upstream, verify checksum, cache in S3, serve

**Immutable vs mutable resources:**

| Resource | TTL | Examples |
|----------|-----|---------|
| Immutable | Forever | `.zip`, `.mod`, `.info`, `.tgz` (versioned) |
| Mutable | `metadata_ttl` | `@v/list`, `index.yaml`, packument |

Configure the TTL:
```json
{ "metadata_ttl": "1h" }
```

---

## Checksum Verification

Checksums protect against upstream tampering and bit-rot.

**Builder path** (hosted entries):
- First `bodega fetch`: computes SHA-256, stores on the manifest entry
- Subsequent fetches: verifies against stored checksum; fails on mismatch

**Proxy path** (cached entries):
- First proxy fetch: computes SHA-256, stores in audit DB
- Subsequent proxy fetches: verifies against stored; returns **502 Bad Gateway** on mismatch

**Management:**
```bash
bodega checksum list                        # view all cached checksums
bodega checksum list --type gomod           # filter by type
bodega checksum clear gomod github.com/foo  # clear, next fetch recomputes
```

---

## Audit Trail

Every package fetch, build, CRUD mutation, and cache event is recorded in a
SQLite database at `{log_dir}/audit.db`.

**Event types:**

| Type | Trigger |
|------|---------|
| `fetch` | Client downloads a package via HTTP |
| `build` | Build pipeline completes for an entry |
| `create` | Manifest entry created (CLI or API) |
| `delete` | Manifest entry deleted |
| `cache` | Proxy cache miss → upstream fetch |

**Query examples:**
```bash
bodega audit --type fetch --limit 50
bodega audit --name lodash --since 2026-04-07
bodega audit --client 10.0.0.5
```

The audit middleware records: timestamp, event type, package type/name/version,
client IP, user agent, HTTP status, and request duration.

---

## TUI

`bodega shell` launches a three-pane terminal interface.

```
┌─ Sources ──────────┬─ Details ──────────────────┐
│ apt/               │ Name:    netbox            │
│ git/               │ Ref:     v4.5.5            │
│   netbox@v4.5.5    │ URL:     https://github... │
│ pypi/              │ Frozen:  no                │
│ binary/            │ S3:      ✓ uploaded        │
│ gomod/             │                            │
│ helm/              │                            │
│ npm/               │                            │
├─ Log ──────────────┴────────────────────────────┤
│ [gomod] github.com/aws/sdk: fetching...         │
│ [gomod] github.com/aws/sdk: checksum verified   │
└─────────────────────────────────────────────────┘
```

### Keybindings

| Key | Action |
|-----|--------|
| `Tab` | Switch focus between Sources and Log pane |
| `Up`/`Down` or `j`/`k` | Navigate |
| `Enter` | Expand/collapse group |
| `/` | Filter sources |
| `?` | Show help |
| `q` | Quit |
| `C` | Open config editor |

### Config editor

Press `C` to open the config form. `Ctrl+S` saves, `Ctrl+T` loads defaults,
`Ctrl+R` resets. Changes take effect immediately.

---

## Manifest Integrity

Each manifest file has a companion `.md5` file:

```
manifests/
  apt.json
  apt.json.md5
  git.json
  git.json.md5
  ...
```

The tool verifies MD5 on every manifest read and writes a fresh MD5 after every
modification. Use `bodega verify` to check integrity, and
`bodega --break-glass-update-md5 <type>` to recompute after a manual edit.

---

## Frozen Entries

Set `"frozen": true` on any entry (or use `bodega freeze`) to prevent it from
being built, edited, or deleted. The toggle is audit-friendly — use it to pin a
known-good artifact.

```bash
bodega freeze git netbox     # freeze
bodega freeze git netbox     # unfreeze (toggle)
```

---

## S3 Layout

| Type | S3 prefix | Example key |
|------|-----------|-------------|
| apt | `packages/apt/` | `packages/apt/dists/noble/Release` |
| git | `repos/` | `repos/netbox/netbox-v4.5.5.bundle` |
| pypi | `pypi/wheels/` | `pypi/wheels/boto3-1.35.0-py3-none-any.whl` |
| binary | `binaries/` | `binaries/awscli-v2/2.34.24/awscli-exe-linux-x86_64.zip` |
| gomod | `gomod/` | `gomod/github.com/aws/sdk/@v/v1.30.0.zip` |
| helm | `charts/` | `charts/ingress-nginx-4.11.0.tgz` |
| npm | `npm/` | `npm/lodash/lodash-4.17.21.tgz` |
| manifests | `manifests/` | `manifests/git.json` |

---

## Development

### Build targets

```bash
make build          # compile to ./dist/bodega
make cross          # cross-compile for linux/amd64
make test           # run tests with race detector
make test-verbose   # verbose test output
make bench          # run benchmarks
make vet            # go vet
make fmt            # goimports / gofmt
make lint           # golangci-lint
make tidy           # go mod tidy + verify
make clean          # remove build artifacts
make depend         # install Go + golangci-lint
```

### Project structure

```
cmd/bodega/              Cobra commands + pipeline helpers
internal/
  audit/                SQLite audit trail + checksum storage
  builder/              Build orchestration per type
  config/               Configuration resolution
  logging/              Structured leveled logging (slog)
  manifest/             Manifest types, loader, MD5 integrity
  s3/                   AWS S3 client
  server/               HTTP server, proxy/cache, middleware
  tui/                  Bubbletea three-pane TUI
manifests/              JSON manifest files (source of truth)
schemas/                JSON Schema validation files
docs/                   Public documentation
docs-internal/          Development documentation + changelogs
```

### Adding a new source type

1. Add entry struct + manifest envelope in `internal/manifest/types.go`
2. Add type constant to `AllTypes`
3. Add Store methods in `internal/manifest/loader.go` (Find, Remove, Save)
4. Create builder in `internal/builder/<type>.go` (Fetch, Check, ArtifactPaths)
5. Add HTTP routes in `internal/server/server.go`
6. Add CLI cases in `cmd/bodega/cmd_create.go`, `cmd_delete.go`, `cmd_fetch.go`
7. Add TUI rendering in `internal/tui/sources.go` and `details.go`
8. Create JSON schema in `schemas/<type>.schema.json`
