# bodega

A manifest-driven package repository manager with an S3 backend. Builds, caches,
and serves seven artifact types to standard package manager clients.

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

- **Pipeline**: fetch → build → package → upload with automatic stage cascading
- **HTTP(S) server**: serves all 7 types to native clients, REST API, TLS support
- **Proxy/cache**: fetches from upstream on cache miss, caches in S3, verifies checksums
- **TUI**: three-pane interactive terminal UI (sources tree, details, log)
- **Audit trail**: SQLite database tracking every fetch, build, and mutation
- **Checksum verification**: auto-computed on first fetch, enforced on subsequent fetches
- **Manifest integrity**: MD5 companion files verified on every read

## Quick start

```bash
make build
export REPO_BUCKET=my-bucket
export AWS_REGION=us-west-2

./dist/bodega init          # create S3 bucket
./dist/bodega create git    # add a git entry (interactive)
./dist/bodega fetch         # download sources
./dist/bodega upload        # build + upload to S3
./dist/bodega serve         # start HTTP server on :8080
./dist/bodega shell         # launch TUI
```

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for a guided walkthrough and
[docs/USAGE.md](docs/USAGE.md) for comprehensive documentation.

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
| `REPO_BUCKET` | S3 bucket name |
| `AWS_REGION` | AWS region (default: us-west-2) |
| `BODEGA_LOG_LEVEL` | Logging verbosity 0–4 |
