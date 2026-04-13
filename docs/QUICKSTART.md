# Quick Start Guide

This guide walks you through setting up bodega, adding your first packages, and serving them.

## Prerequisites

- Go 1.22+ (or run `make depend` to install it)

## 1. Build and install

```bash
make build                    # builds to ./dist/bodega
sudo make install             # installs to /usr/local/bin/bodega
```

Cross-compile for Linux from macOS:

```bash
make cross                    # builds ./dist/bodega-linux-amd64
```

## 2. Configure

bodega works out of the box with local filesystem storage. A config file is created automatically on first run at `~/.config/bodega/config.json`.

For S3-backed storage, set the backend and bucket:

```json
{
  "storage_backend": "s3",
  "bucket": "my-bodega-bucket",
  "region": "us-west-2"
}
```

Then initialize the bucket:

```bash
bodega init
```

For local storage, no initialization is needed. Artifacts are stored at `/var/lib/bodega` by default (configurable via `storage_path`).

## 4. Add packages

### Git repository

```bash
bodega pkg create git netbox
# Prompts for: Source URL, Ref (tag/branch/SHA)
```

### Apt package by name

```bash
bodega pkg create apt python3
```

Bodega queries apt-cache, resolves the concrete version (e.g. `3.12.3-0ubuntu2.1`), and optionally auto-discovers dependencies.

### Other types

```bash
bodega pkg create binary awscli-v2       # prompts for URL, SHA256
bodega pkg create gomod github.com/aws/aws-sdk-go-v2   # prompts for version
bodega pkg create helm ingress-nginx     # prompts for URL, version
bodega pkg create npm lodash             # prompts for version
```

All fields are prompted interactively. For automation, use `bodega pkg import` with a JSON manifest file. See [USAGE.md](USAGE.md#bodega-pkg-import-file-file) for details.

## 5. Fetch and upload

Fetch all sources, build, and upload to S3:

```bash
bodega build upload
```

Or run individual stages:

```bash
bodega build fetch                       # download sources only
bodega build fetch git                   # download git sources only
bodega build fetch git netbox            # download only the netbox entry
bodega build run                         # compile/prepare (cascades fetch if needed)
bodega build sync                        # push to S3 (cascades all stages)
```

## 6. Start the HTTP server

```bash
bodega serve
```

The server listens on `:8080` by default. Clients configure their package managers:

**APT** — add to `/etc/apt/sources.list.d/bodega.list`:
```
deb [trusted=yes] http://bodega-host:8080/apt/ noble main
```

**pip**:
```bash
pip install --index-url http://bodega-host:8080/pypi/simple/ boto3
```

**Go modules**:
```bash
GOPROXY=http://bodega-host:8080/go go get github.com/aws/aws-sdk-go-v2@v1.30.0
```

**Helm**:
```bash
helm repo add bodega http://bodega-host:8080/helm
helm install my-release bodega/ingress-nginx
```

**npm**:
```bash
npm install --registry http://bodega-host:8080/npm lodash
```

**Git bundles**:
```bash
curl http://bodega-host:8080/git/netbox/netbox-v4.5.7.bundle -o netbox.bundle
git clone netbox.bundle netbox
```

## 7. Launch the TUI

```bash
bodega shell
```

Three-pane interface:
- **Sources** (left): tree view of all packages, expand/collapse with Enter
- **Details** (right): metadata for the selected entry
- **Log** (bottom): command output

Press `Tab` to switch focus, `?` for help, `q` to quit.

## 8. Supply chain scenario: handling a bad dependency

When a dependency like `libssl3` has a security issue or checksum mismatch:

```bash
# Hide the bad version from clients (stays in manifest as a record)
bodega pkg hide apt libssl3

# Fetch again — bodega skips the hidden version
bodega build fetch apt
```

If you want to allow new versions to be auto-resolved in the future, leave the `*` policy entry unfrozen. If you want to block all future versions temporarily, freeze it.

See [docs/USAGE.md](docs/USAGE.md) for the full supply chain section.

## 9. Check status

```bash
bodega status                  # compare all entries against S3
bodega pkg verify                  # verify manifest MD5 integrity
bodega audit events --limit 10        # view recent audit events
bodega pkg checksum list           # view cached checksums
```

## 10. Enable HTTPS

With manual certificates:
```bash
bodega serve --tls-cert /path/to/cert.pem --tls-key /path/to/key.pem
```

## 11. Enable proxy/cache

Edit config to enable upstream proxy caching for gomod, helm, and npm:

```json
{
  "proxy_cache_enabled": true,
  "metadata_ttl": "1h"
}
```

With proxy enabled, when a client requests a package not in S3, bodega fetches it from upstream (proxy.golang.org, registry.npmjs.org, etc.), caches it in S3, and serves it. Subsequent requests are served from cache. Checksums are verified automatically.

## 12. Mutation API access

The REST API's create and delete endpoints are restricted to localhost by default. If you need to create or delete entries from another host (e.g., CI), widen the allow-list and generate a token:

```json
{
  "admin_permit_cidr": ["127.0.0.0/8", "::1/128", "10.0.0.0/8"]
}
```

```bash
bodega token generate ci-pipeline expiry 90d "CI deploy token"
# Displays the token once — save it. A hashed copy is stored in the audit DB.
```

Manage tokens with `bodega token list` and `bodega token revoke`. In the TUI, press `T` to open the token manager. See [USAGE.md](USAGE.md#rest-api) for full details.

## Next steps

- Set up a systemd service for `bodega serve`
- Put nginx in front for TLS termination and caching at scale
- Use the REST API for CI/CD integration (`POST /api/v1/packages/{type}`)
- Query the audit trail to track package usage (`bodega audit events --type fetch`)
- Read [docs/DESIGN.md](docs/DESIGN.md) for architecture details