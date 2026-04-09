# Quick Start Guide

This guide walks you through setting up bodega, adding your first packages, and
serving them to clients.

## Prerequisites

- Go 1.24+ (or run `make depend` to install it)
- AWS credentials configured (via `aws-sso`, IAM role, or environment variables)
- An S3 bucket for package storage

## 1. Build and install

```bash
cd tools/bodega
make build                    # builds to ./dist/bodega
sudo make install             # installs to /usr/local/bin/bodega
```

Cross-compile for Linux from macOS:

```bash
make cross                    # builds ./dist/bodega-linux-amd64
```

## 2. Configure

Set your bucket and region:

```bash
export REPO_BUCKET=bodega-864617344058
export AWS_REGION=us-west-2
```

Or edit the config file (created automatically on first run):

```bash
sudo vim /etc/bodega/config.json
```

```json
{
  "bucket": "bodega-864617344058",
  "region": "us-west-2"
}
```

## 3. Initialize the S3 bucket

```bash
bodega init
```

Creates the bucket with encryption, versioning, and public access blocked.
Idempotent — safe to run multiple times.

## 4. Add packages

### Git repository (e.g., NetBox)

```bash
bodega create git \
  --name netbox \
  --url https://github.com/netbox-community/netbox \
  --ref v4.5.5
```

### Binary download (e.g., AWS CLI)

```bash
bodega create binary \
  --name awscli-v2 \
  --url https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip
```

### Go module

```bash
bodega create gomod \
  --name github.com/aws/aws-sdk-go-v2 \
  --ref v1.30.0
```

### Helm chart

```bash
bodega create helm \
  --name ingress-nginx \
  --url https://kubernetes.github.io/ingress-nginx/charts/ingress-nginx-4.11.0.tgz \
  --ref 4.11.0
```

### npm package

```bash
bodega create npm \
  --name lodash \
  --ref 4.17.21
```

Or run `bodega create <type>` without flags for interactive prompts.

## 5. Fetch and upload

Fetch all sources, build, and upload to S3:

```bash
bodega upload
```

Or run individual stages:

```bash
bodega fetch                   # download sources only
bodega fetch git               # download git sources only
bodega fetch git --entry netbox  # download only the netbox entry
bodega build                   # compile/prepare (cascades fetch if needed)
bodega package                 # create distributable artifacts
bodega upload                  # push to S3 (cascades all stages)
```

## 6. Start the HTTP server

```bash
bodega serve
```

The server listens on `:8080` by default. Clients configure their package
managers to point at it:

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
curl http://bodega-host:8080/git/netbox/netbox-v4.5.5.bundle -o netbox.bundle
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

## 8. Check status

```bash
bodega status                  # compare all entries against S3
bodega verify                  # verify manifest MD5 integrity
bodega audit --limit 10        # view recent audit events
bodega checksum list           # view cached checksums
```

## 9. Enable HTTPS

With manual certificates:
```bash
bodega serve --tls-cert /path/to/cert.pem --tls-key /path/to/key.pem
```

## 10. Enable proxy/cache

Edit config to enable upstream proxy caching:

```json
{
  "proxy_cache_enabled": true,
  "metadata_ttl": "1h"
}
```

With proxy enabled, when a client requests a package not in S3, bodega fetches
it from upstream (proxy.golang.org, registry.npmjs.org, etc.), caches it in S3,
and serves it. Subsequent requests are served from cache. Checksums are verified
automatically.

## Next steps

- Set up a systemd service for `bodega serve`
- Put nginx in front for TLS termination and caching at scale
- Use the REST API for CI/CD integration (`POST /api/v1/packages/{type}`)
- Query the audit trail to track package usage (`bodega audit --type fetch`)
