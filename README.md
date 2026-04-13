# bodega

[![CI](https://github.com/ravinald/bodega/actions/workflows/ci.yml/badge.svg)](https://github.com/ravinald/bodega/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/ravinald/bodega.svg)](https://pkg.go.dev/github.com/ravinald/bodega)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A self-hosted package repository manager backed by pluggable object storage. Fetches, builds, and serves seven package types to standard clients without leaving your network.

| Type | Client | Protocol |
|------|--------|----------|
| apt | `apt-get` | Debian repository |
| git | `git clone` | Git bundles |
| pypi | `pip install` | PEP 503 simple index |
| binary | `curl` | Direct download |
| gomod | `go get` | GOPROXY |
| helm | `helm install` | Chart repository |
| npm | `npm install` | npm registry |

## Features

- **Pipeline**: fetch → build → upload with automatic stage cascading
- **HTTP(S) server**: serves all 7 types to native clients, REST API, TLS support
- **Proxy/cache**: optional upstream caching for gomod, helm, npm
- **TUI**: three-pane interactive terminal interface (sources, details, log)
- **Web dashboard**: live metrics, status view, copy-to-clipboard utilities
- **Audit trail**: SQLite database recording every fetch, build, and mutation
- **Checksum verification**: computed on first fetch, enforced on subsequent fetches
- **Manifest integrity**: MD5 verification on every read/write
- **Access control**: IP-based mutation API gating with optional Bearer token auth
- **Supply chain control**: hide bad versions, freeze known-good artifacts

## Quick start

```bash
make build

./dist/bodega pkg create git netbox        # add a git entry (interactive prompts)
./dist/bodega build fetch                  # download sources
./dist/bodega build upload                 # build + upload to storage
./dist/bodega serve                        # start HTTP server on :8080
```

bodega uses local filesystem storage by default. For S3, set `storage_backend` to `"s3"` in your config and run `bodega init` to create the bucket.

For a guided walkthrough, see [docs/QUICKSTART.md](docs/QUICKSTART.md). For comprehensive documentation, see [docs/USAGE.md](docs/USAGE.md).

## Development

```bash
make test       # run tests with race detector
make vet        # go vet
make lint       # golangci-lint
make fmt        # goimports / gofmt
make tidy       # go mod tidy + verify
```

## Configuration

Resolved in priority order: CLI flags → environment variables → config file → defaults.

Config files: `/etc/bodega/config.json` or `~/.config/bodega/config.json`.

| Environment variable | Purpose |
|---------------------|---------|
| `REPO_BUCKET` | S3 bucket name (when using S3 backend) |
| `AWS_REGION` | AWS region (default: us-west-2) |
| `BODEGA_LOG_LEVEL` | Logging verbosity 0-4 |

The default storage backend is `local` (filesystem at `/var/lib/bodega`). Set `storage_backend` to `"s3"` in your config file for S3-backed storage.
