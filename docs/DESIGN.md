# Bodega Design Document

## What is it

Bodega is a self-hosted package repository that sits between your infrastructure and the public internet. It fetches, builds, and serves seven artifact types through native package manager protocols. Your instances talk to bodega instead of the internet, and bodega decides where the bits come from.

It replaces the grab bag of internal mirrors, S3 scripts, and "just curl it" patterns that tend to accumulate when you operate package infrastructure at scale. One tool, one config file, one S3 bucket.

## Why it exists

Three problems kept showing up:

1. **Build reproducibility.** Upstream packages disappear, change, or get compromised. Pinning versions in a manifest and verifying checksums on every fetch means Tuesday's build produces the same artifact as last Tuesday's build.

2. **Air-gapped and restricted networks.** When instances can't reach the internet (or shouldn't), they need a local source for packages. Bodega serves everything over standard protocols that apt, pip, go, helm, and npm already understand.

3. **Dependency visibility.** Knowing what your infrastructure actually depends on requires more than grepping requirements files. Bodega tracks every package, its source, its checksum, and whether that checksum was verified against the upstream publisher.

## Architecture

```
                          +------------------+
                          |   bodega serve   |
                          |   (HTTP server)  |
                          +--------+---------+
                                   |
                    +--------------+--------------+
                    |              |               |
               native clients   REST API     TUI & dashboard
              (apt, pip, go,   (/api/v1/)  (bodega shell)
               helm, npm)
                    |              |               |
                    +--------------+--------------+
                                   |
                          +--------+---------+
                          |    S3 backend    |
                          |  (single bucket) |
                          +------------------+
```

The server is a single Go binary. No database server, no message queue, no container runtime. State lives in two places: manifest JSON files (what should exist) and an S3 bucket (what does exist). A SQLite file handles the audit trail.

### S3 bucket layout

```
s3://<bucket>/
  manifests/
    apt/python3/manifest.json
    apt/libssl3/manifest.json
    git/netbox/manifest.json
    pypi/django/manifest.json
    ...
  index.json                 # fast startup without loading every manifest
  graph.json                 # dependency graph with typed edges
  metrics.json               # dashboard metrics (updated on SaveIndex)
  packages/apt/              # Debian repository (Release, Packages.gz, pool/)
  pypi/wheels/               # Python wheels
  repos/                     # Git bundles (.bundle) and release archives (.tar.gz)
  binaries/                  # Direct downloads, versioned subdirectories
  gomod/                     # Go module archives (@v/*.zip, *.info, *.mod)
  charts/                    # Helm chart .tgz files
  npm/                       # npm tarballs and packument metadata
```

Each package gets its own manifest file at `manifests/{type}/{safeName}/manifest.json`. This replaces the old monolithic per-type JSON files and enables parallel operations without lock contention.

One bucket. Versioning enabled. KMS encryption. Public access blocked.

## Package types

| Type | Source | Artifact | Client protocol |
|------|--------|----------|-----------------|
| apt | Package name, git repo, or apt-get source | .deb in Debian repo layout | `deb [trusted=yes] http://bodega/apt/ noble main` |
| git | GitHub release tarball or bare clone | .tar.gz or .bundle | `curl http://bodega/git/<name>/<file>` |
| pypi | Wheel build from requirements.txt | .whl files | `pip install --index-url http://bodega/pypi/simple/` |
| binary | Direct URL download | Original file | `curl http://bodega/binaries/<name>/<ver>/<file>` |
| gomod | GOPROXY upstream or local build | .zip, .mod, .info | `GOPROXY=http://bodega/go,direct go get <module>` |
| helm | Chart repo or direct URL | .tgz | `helm repo add bodega http://bodega/helm` |
| npm | Registry upstream or local | .tgz | `npm install --registry http://bodega/npm/` |

## Manifest structure (config_version 1)

Each package is a `PackageManifest` JSON file:

```json
{
  "config_version": 1,
  "name": "python3",
  "type": "apt",
  "description": "Python interpreter and libraries",
  "dep_policy": "direct",
  "versions": [
    {
      "version": "*",
      "version_constraint": "any",
      "hidden": false,
      "frozen": false
    },
    {
      "version": "3.12.3-0ubuntu2.1",
      "url": "http://archive.ubuntu.com/ubuntu/pool/main/p/python3.12/...",
      "source_name": "python3.12",
      "checksum": {
        "algorithm": "sha256",
        "value": "abc123..."
      },
      "checksum_verified": true,
      "artifact_size": 5242880,
      "metadata": {
        "Architecture": "amd64",
        "Maintainer": "Ubuntu Core developers",
        "Section": "python",
        "Priority": "optional"
      }
    }
  ]
}
```

The manifest envelope contains:
- **config_version**: schema version (always 1)
- **name**: canonical package name
- **type**: package ecosystem
- **description**: human-readable summary
- **dep_policy**: auto-discovery policy ("none", "direct", "transitive")
- **versions**: array of VersionEntry objects

Each VersionEntry represents a concrete or policy version:
- Policy entries use `version: "*"` with `version_constraint: "any"`
- Concrete versions have a specific version identifier and full metadata
- `hidden: true` excludes the version from client view but keeps it in the record
- `frozen: true` prevents building, editing, or deletion
- `metadata` holds ecosystem-specific key-value pairs (apt: Architecture, Maintainer, etc.)

## Version policies and constraints

A version policy entry is created with a wildcard version (`*`) and a constraint:

| Constraint | Behavior | Example |
|-----------|----------|---------|
| `exact` | Only this exact version | `python3@3.12.3` |
| `compatible` | Same major version, any minor/patch (^) | `django@5.x` |
| `patch` | Same major.minor, any patch (~) | `numpy@1.26.x` |
| `any` | All versions (*) | `libssl3@*` |

A policy entry with `version_constraint: "any"` displayed as `python3@*` allows bodega to auto-resolve new versions from apt-cache or upstream registries. Concrete versions are stored alongside the policy entry.

### Dep policy

The `dep_policy` on a PackageManifest controls automatic dependency creation:

- **"none"** (default): no auto-discovery
- **"direct"**: immediate dependencies only
- **"transitive"**: full recursive closure

When you fetch a git entry with `dep_policy: "direct"`, bodega scans the source for dependency files (requirements.txt, go.mod, package.json) and creates manifest entries for immediate dependencies. Transitive dependencies are discovered recursively.

## Serve modes

Every gomod, helm, and npm entry has a `mode` field:

- **hosted** (default): The artifact is built or fetched locally, uploaded to S3, served from S3. You control exactly what's there. Nothing reaches upstream at serve time.
- **proxy**: On cache miss, bodega fetches from the upstream registry, caches in S3, and serves the response. Subsequent requests hit the cache. Mutable metadata (version lists, indexes) refreshes after a configurable TTL.

Apt, git, binary, and pypi are always hosted. They don't have natural upstream proxies that speak the right protocol at serve time.

## Apt three-mode workflow

Apt entries support three distinct workflows:

### 1. Package name mode

Provide a package name (e.g. "python3"):

```bash
bodega pkg create apt python3
```

Bodega queries apt-cache, resolves the concrete version with full metadata, and optionally discovers dependencies.

### 2. Direct URL mode

Download a .deb from a URL:

```bash
bodega pkg create binary mypackage --url https://example.com/package.deb
```

### 3. Source build mode

Two sub-options:

**3a. Git repo + build command:**

```bash
bodega pkg create apt amazon-efs-utils \
  --url https://github.com/aws/efs-utils.git \
  --build-cmd "make deb" \
  --deb-glob "build/*.deb"
```

**3b. apt-get source + dpkg-buildpackage:**

```bash
bodega pkg create apt openssh-client --source-build
```

Mode 3b gives you supply chain control by building from Debian source packages locally.

## Pipeline

The build pipeline has four stages that run in dependency order:

```
fetch  -->  build  -->  sync  -->  upload
```

Wait, let me correct that based on the code. Looking at the commands, it's:

```
fetch  -->  build  -->  upload  -->  (S3 sync)
```

Actually, the command structure shows `build fetch`, `build run`, `build sync`, `build upload`. Let me recheck... The commands are subcommands of `build`:

- **build fetch**: Download sources
- **build run**: Compile or transform
- **build sync**: Push artifacts to S3 without running pipeline stages
- **build upload**: Full pipeline (fetch → run) then upload

- **fetch**: Download sources. Release-mode git entries download a tarball. Clone-mode entries do a bare git clone.
- **build**: Compile or transform. Apt runs dpkg-buildpackage. Pypi runs pip wheel. Git and binary have no build step.
- **sync**: Pushes whatever local artifacts exist to S3 without running any pipeline stages.
- **upload**: Runs the full pipeline (fetch → build) then uploads to S3.

The pipeline cascades automatically. Running `bodega build upload` will fetch and build first if needed.

### Dependency discovery

When bodega fetches a git entry, it scans the extracted source for dependency files and auto-creates manifest entries:

| File found | Action |
|------------|--------|
| `requirements.txt` | Populate pypi base_requirements, create PypiPackage entries |
| `go.mod` | Create GomodEntry for each require (mode: proxy) |
| `package.json` | Create NpmEntry for each dependency (mode: proxy) |
| `Gemfile`, `pom.xml`, etc. | Log as found, unsupported ecosystem |

Discovered entries default to proxy mode. The operator can change any entry to hosted if they want to build and pin it locally. Duplicate entries are skipped.

## Security model

### Checksum verification

Every downloaded artifact gets a SHA-256 computed at fetch time. The checksum is stored in the manifest.

On subsequent fetches, the stored checksum is compared against the freshly downloaded artifact. A mismatch halts the fetch and logs a warning. Nothing is saved when a checksum fails.

The `checksum_verified` field tracks whether the checksum was confirmed against a source-published digest (e.g., a SHA256SUMS file in a GitHub release). `true` means the checksum matches what the publisher says it should be. `false` means bodega computed it but couldn't find an upstream reference to compare against.

For proxy mode, the server verifies checksums on immutable resources (versioned archives) and records mismatches in the audit trail.

### Deny list

The config file accepts a `deny_list` of CIDR entries. Bare IPs are treated as /32 (IPv4) or /128 (IPv6). Requests from denied addresses get a 403. The deny list is parsed at startup and applies to all routes.

```json
"deny_list": ["10.99.0.0/16", "fd00::bad:1"]
```

### IP resolution

The `RealIPMiddleware` extracts the client IP from `X-Real-IP` or `X-Forwarded-For` headers, but only when the direct peer is in a trusted network (RFC 1918 + loopback by default). Untrusted peers can't spoof their IP via headers.

### Mutation access control

The mutation API (POST and DELETE on `/api/v1/packages/...`) is gated by two layers:

1. **IP allow-list** (`admin_permit_cidr`): Only requests from permitted CIDRs can reach mutation endpoints. Defaults to `["127.0.0.0/8", "::1/128"]`, so out of the box only localhost can create or delete entries.

2. **Bearer token** (`api_token`): When `admin_permit_cidr` extends beyond localhost, a valid `Authorization: Bearer <token>` header is required on mutation requests. Generate tokens with `bodega token generate`.

Read endpoints remain unauthenticated. Package manager clients (apt, pip, go, npm, helm) use standard protocols that don't support auth headers, so read paths stay open by design.

### Response hardening

All HTTP responses include security headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy`, and `Referrer-Policy`. When TLS is active, `Strict-Transport-Security` is also set.

Upstream proxy fetches validate that target URLs use HTTPS and don't resolve to private or loopback addresses, preventing SSRF through manifest-controlled URLs.

### TLS

Two options: provide a cert/key pair, or enable Let's Encrypt autocert with a domain name. Minimum TLS 1.3.

### Manifest integrity

Every manifest JSON file has a companion `.md5` file. On load, the MD5 is verified. On save, it's recomputed. This catches accidental corruption and makes S3 sync conflicts visible.

## Audit trail

A SQLite database (WAL mode) records:

- **fetch events**: Which client IP downloaded which package, when, and how long it took
- **build events**: Pipeline stage completions
- **mutation events**: Entry creates and deletes
- **cache events**: Proxy cache misses and upstream fetch results, including checksum verification outcomes

Queryable via `bodega audit` with filters for event type, package type, client IP, and time range.

## Configuration

One JSON file at `/etc/bodega/config.json` or `~/.config/bodega/config.json`. Priority: CLI flags > environment variables > config file > defaults.

Key fields:

| Field | Default | Purpose |
|-------|---------|---------|
| `bucket` | (required) | S3 bucket name |
| `region` | us-west-2 | AWS region |
| `build_root` | /opt/bodega | Where artifacts are built locally |
| `proxy_cache_enabled` | false | Global proxy/cache toggle |
| `metadata_ttl` | 1h | How long mutable proxy resources are cached |
| `deny_list` | [] | CIDR entries to block |
| `admin_permit_cidr` | [127.0.0.0/8, ::1/128] | CIDRs allowed to hit mutation API |
| `api_token` | (none) | Bearer token for mutation API |
| `tls_cert` / `tls_key` | (none) | Manual TLS |
| `tls_autocert` / `tls_domain` | (none) | Let's Encrypt |
| `audit_db` | {log_dir}/audit.db | Audit database path |

The TUI config editor (`C` key in `bodega shell`) writes to the same file.

## TUI

`bodega shell` launches a three-pane terminal interface:

```
┌─ Sources ──────────┬─ Details ──────────────────┐
│ apt/               │ Name:    netbox            │
│ git/               │ Ref:     v4.5.7            │
│   netbox@v4.5.7    │ Source URL: https://git... │
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

From the TUI you can create entries, run the full build pipeline, manage S3 uploads, and edit configuration. Forms support inline dropdowns, bracket paste, and a raw JSON editor fallback.

## Web UI and dashboard

`bodega serve` serves a dashboard on `/dashboard`:

- Live metrics: package counts by type, artifact sizes, version statistics
- Status view: per-package build/upload status
- Copy-to-clipboard utilities for URLs and package JSON configs
- Browser-based package browsing

## REST API

The server exposes a mutation API at `/api/v1/`:

- `GET /api/v1/packages` - List all entries
- `GET /api/v1/packages/{type}` - List by type
- `GET /api/v1/packages/{type}/{name}` - Single entry
- `POST /api/v1/packages/{type}` - Create entry
- `DELETE /api/v1/packages/{type}/{name}` - Delete entry
- `GET /api/v1/status` - Health and entry counts
- `GET /api/v1/config` - Non-sensitive configuration

Frozen entries cannot be deleted through the API.

## Deployment

Bodega is a single static binary. A typical deployment:

1. Terraform creates the S3 bucket and an EC2 instance with an IAM role granting S3 read/write.
2. The bootstrap script installs the binary, writes `/etc/bodega/config.json`, and enables a systemd service running `bodega serve --addr :8080`.
3. Other instances discover the bucket via SSM parameters (`/infra/repo/bucket`, `/infra/repo/region`) and configure their package managers to point at bodega.

The binary runs on the build host. The server runs on the same host or a dedicated package server. There is no separate worker process.

SIGHUP-based reload is supported via a PID file: send `SIGHUP` to the running process to reload config and manifests without losing in-flight requests.
