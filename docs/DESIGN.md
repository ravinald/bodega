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
  packages/apt/pool/         # Debian .deb pool: locally built .debs and, on a
                             #   mirroring instance, cached upstream ones. One flat
                             #   pool shared across suites is correct Debian layout.
  packages/apt/dists/        # only for codenames in apt_upstreams — the cached
                             #   proxy of the upstream index. A generated suite's
                             #   dists/ is built from the manifests into an
                             #   in-memory snapshot and never stored.
  pypi/wheels/               # Python wheels
  repos/                     # Git bundles (.bundle) and release archives (.tar.gz)
  binaries/                  # Direct downloads, versioned subdirectories
  gomod/                     # Go module archives, module path verbatim:
                             #   gomod/github.com/aws/sdk/@v/v1.30.0.{zip,info,mod}
  charts/                    # Helm chart .tgz files
  npm/                       # npm tarballs and packument metadata
  cargo/crates/              # Rust .crate tarballs
  cargo/index/               # cached sparse-index entries
```

Every key is derived in one place: `manifest.ArtifactKeys` and its per-type helpers in `internal/manifest/keys.go`. The uploader, every server handler, `bodega build status`, `bodega pkg move` and the delete path all resolve through it. Three independent derivations existed before, and they disagreed.

A name containing a slash encodes to `--` for every type except gomod, which keeps its slashes. A Go client requests `GET /<module>/@v/<version>.zip` with the module path verbatim and nothing on the wire can re-encode it, so the uploader is the side that has to write the wire form. Any install that uploaded a Go module before that landed has bytes at the old encoded key; `bodega repair keys` moves them.

Each package gets its own manifest file at `manifests/{type}/{safeName}/manifest.json`. This replaces the old monolithic per-type JSON files and enables parallel operations without lock contention.

One bucket. Versioning enabled. KMS encryption. Public access blocked.

### Storage placement

That layout describes one backend. `storage_backend`/`storage_path`/`bucket`/`region` define it, and its reserved name is `default`. `storage_backends` adds more by name; each backend carries the same key layout, optionally under a `prefix`.

Three levels decide where a write goes, most specific first: `storage_policy` on the package manifest, then `storage_by_type` for its type, then the default backend. The package level exists for the narrow case the type level cannot express — one package whose artifacts must live in a specific bucket under a specific KMS key, where the type is shared with packages that must not. `bodega pkg storage <type> <name>` prints the answer and the level that produced it.

Placement and resolution are separate questions and share no code path. The config decides where the **next** write goes. Where an artifact **already written** lives is the name recorded in `storage` on its version entry, and reads consult only that. So a rule change moves nothing and breaks nothing: everything already uploaded stays where it is and stays readable.

An absent `storage` is `default`, not "recompute from config" — that is the answer for every artifact uploaded before named backends existed. A name nothing answers to fails the read rather than searching the other backends: serving bytes from one store under a digest recorded against another is the signature the checksum machinery exists to catch.

Objects with no version entry — generated indexes, proxy-cache entries, attestation blobs — follow the type rule at both ends, which is safe because every one of them is regenerable. Manifests stay on `default`: they are what records placement.

Moving an artifact between backends is `bodega pkg move`, which copies, verifies at the destination, writes the manifest, and only then considers the source. Deleting first would be unrecoverable: both backends answer a missing object with "not found" rather than an error, so an artifact lost mid-move is indistinguishable from one that was never uploaded.

## Package types

| Type | Source | Artifact | Client protocol |
|------|--------|----------|-----------------|
| apt | Package name, git repo, or apt-get source | .deb in Debian repo layout | deb822 `.sources` with `Signed-By:`; see below |
| git | GitHub release tarball or bare clone | .tar.gz or .bundle | `curl https://bodega/git/<name>/<file>` |
| pypi | Wheel build from requirements.txt | .whl files | `pip install --index-url https://bodega/pypi/simple/` |
| binary | Direct URL download | Original file | `curl https://bodega/binaries/<name>/<ver>/<file>` |
| gomod | GOPROXY upstream or local build | .zip, .mod, .info | `GOPROXY=https://bodega/go,direct go get <module>` |
| helm | Chart repo or direct URL | .tgz | `helm repo add bodega https://bodega/helm` |
| npm | Registry upstream or local | .tgz | `npm install --registry https://bodega/npm/` |

`internal/server/apt.go` generates `Release` and the `Packages` bodies it digests as one snapshot, and signs it there with a key `internal/aptsign` loads at startup and re-reads on every `SIGHUP`, held behind an `atomic.Pointer` because the reload writes it while request handlers read it. `InRelease` is the clearsigned `Release`; `Release.gpg` is the armored detached signature; `/apt/bodega-archive-keyring.{asc,gpg}` serve the public key from memory. With no key installed all four 404 and the unsigned `Release` still serves, which is the ordinary fallback apt has always taken. Signed and unsigned coexist at the same URLs indefinitely.

An unsigned source needs `deb [trusted=yes] https://bodega/apt/ noble main`, which turns off verification for that source permanently. TLS authenticates the packages in that case, which is why every client line above is `https://`.

The signature seals the last hop only: it proves the bytes are the ones this bodega asserted. It carries no claim about upstream, because bodega records no upstream verification result and a source-built `.deb` never had an upstream signature. `docs/USAGE.md` states the full scope.

### Mirrored codenames

A codename in `apt_upstreams` is served from an upstream archive instead of generated. `internal/server/apt_mirror.go` proxies `dists/<codename>/...` through `proxyOrCache` — `by-hash/` paths immutable, everything else mutable under `metadata_ttl` — and the pool artifacts the index points at, immutable. bodega parses no upstream index: apt reads the proxied `Packages` and composes the next request itself, so every component and architecture the upstream publishes resolves without bodega knowing they exist.

`InRelease` and `Release.gpg` are forwarded unchanged, so the archive's own signature reaches the client and verifies against the distro keyring already on the host. bodega's key signs generated suites and nothing else, and `config.Load` refuses a codename that appears in both `apt_suites` and `apt_upstreams`: a signature over a `Release` is a signature over the digests of the `Packages` beside it, one URL serves one `Packages` per component and architecture, so a shared codename would hand a client an index its signature does not describe. `docs-internal/DESIGN_apt-suites-and-signing_2026_08_25.md` records the two rejected alternatives.

A pool request carries no codename, so bodega probes the configured archives in sorted order with a `HEAD` and remembers which one answered, positively or negatively, for an hour. A pool path a manifest entry owns is never probed: the entry's `Packages` stanza already published a `SHA256` computed at package time, and caching another archive's artifact there would serve bytes the client's own hash check rejects.

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
- `storage` names the backend holding this version's bytes; absent means `default`
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

pypi entries are always hosted. git and binary reach upstream through `git_upstreams` and `binary_upstreams`, which carry a per-namespace `mode` of the same two values.

apt reaches upstream through `apt_upstreams`, and it has **no** `catalog` mode and no per-package allow-list. apt decides what to request by reading a `Packages` index, so the first `Depends:` chain reaching a package nobody cataloged would 404 mid-install and surface as a broken dependency rather than a policy refusal. `git_upstreams` and `binary_upstreams` can offer `catalog` because a client there asks for one artifact it already named. Constraint for apt is the host-level allow-list (`bodega policy add apt <host>`), checked before the fetch and before the pool probe.

## Filling the catalog

A manifest entry is what makes a package servable, so how entries get written is how a bodega install becomes useful. There are four ways, and they answer different questions.

| Path | Answers | Use it when |
|------|---------|-------------|
| `bodega pkg create` | "add this one package" | You know what you want. Interactive, one entry at a time |
| `bodega pkg convert` + `pkg import` | "what does this host already have" | Standing up a server for hosts that already exist |
| `bodega discover promote` | "what did clients reach for that we could not serve" | A catalog is in place and something fell through it |
| `POST /api/v1/packages...` | the same, from other tooling | Provisioning, CI, anything not a person at a terminal |

`pkg convert` reads a package manager's own inventory on the host: `dpkg-query`, `pip list`, `npm ls`, `go list -m all`, `cargo install --list`, `helm list`. That answer is complete on the first run and needs no observation window, which is what distinguishes it from discovery. A host that has been stable for six months fetches nothing, so a proxy watching it learns nothing; the host's package database still knows everything it has.

It also settles an ordering problem. Catalog mode returns 404 against an empty store, so a fleet pointed at a fresh bodega breaks until the catalog exists. Importing fills the catalog before any client is repointed.

`git` and `binary` have no importer, because nothing on a host records a clone or a downloaded binary. Those two are what discovery still covers: run with `discover_mode` set to `"observe"`, let catalog mode record the misses as `no_manifest` and `no_namespace` rows, and promote them.

Every path runs the same admission checks (`internal/admit`): structural validation, the upstream allow-list, then the age and OSV version checks. A manifest's fate does not depend on which surface it arrived through.

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

### Where the CIDR lists live

`admin_permit_cidr`, `deny_list` and `trusted_proxies` live in the audit database, in `acl_lists` and `acl_entries` (migration `008`). They are the only runtime values that have moved out of `config.json` so far; `docs-internal/CONFIG_TO_DB_MIGRATION.md` scopes the rest.

The move buys two things. A change lands on a running server, within 30 seconds on its own or at once on `systemctl reload bodega`, so widening the admin list no longer means a restart. And the write path is `bodega acl`, which touches one row, rather than `Config.Save()`, which rewrites the whole file including keys the caller never named.

**The config file is copied once, not read as a fallback.** On the first start against a database that does not own a list, bodega copies the file's value in and logs `acl source list=<name> source=database detail="copied from config file on this start"`. From then on the database answers alone and the file's entry is inert; a start where the two disagree logs a `WARN` naming both. The alternative — reading the file as a fallback forever — would make `bodega acl admin remove` unable to remove anything the file still names.

`acl_lists` carries one marker row per list because "no rows in `acl_entries`" is two different answers for `trusted_proxies`. A list with a marker is answered from the table even when empty; a list without one is still answered from the file. See **IP resolution** below for why collapsing those matters.

A list bodega cannot read from the database, or one holding a CIDR it cannot parse there, keeps its config file value rather than emptying. An empty admin list permits nobody and an empty deny list refuses nobody, so both directions of failure are worse than the last good answer. The config file itself has no such fallback: an `admin_permit_cidr` that parses to nothing stops the start, because there is no earlier answer to keep.

### Deny list

`deny_list` holds CIDR entries. Bare IPs are treated as /32 (IPv4) or /128 (IPv6). Requests from denied addresses get a 403, on all routes.

```bash
bodega acl deny add 10.99.0.0/16
bodega acl deny list
```

### IP resolution

The `RealIPMiddleware` extracts the client IP from `X-Real-IP` or `X-Forwarded-For` headers, but only when the direct peer is in a trusted network. Untrusted peers can't spoof their IP via headers.

`trusted_proxies` names that set, and it is tri-state. The three answers survive the move to the database, which is what the `acl_lists` marker row is for:

| Value | In the database | Meaning |
|-------|-----------------|---------|
| absent / `null` | no marker row | Built-in default: loopback plus RFC 1918 |
| `[]` | marker row, no entries | Trust no forwarded header from any peer |
| `["10.9.0.0/16", ...]` | marker row plus entries | Trust exactly these |

An operator who wrote `[]` disabled header trust on purpose. Handing the RFC 1918 default back because a table came up empty would restore it to a deployment that asked to have none, so `bodega acl proxies add` on a list that was never set says out loud that the built-in default has just ended.

The default is wide on purpose, because the common deployment puts a proxy on the same host. It is the wrong default anywhere the private network has other tenants: a Linode with private networking, a Docker bridge, a pod network. Every peer in RFC 1918 is then believed, `admin_permit_cidr` defaults to loopback, and `X-Real-IP: 127.0.0.1` from any of them reaches the mutation API with no token. Name your proxy on those networks, or write `[]` and let bodega answer to the peer address alone.

### Admin access control

`admin_permit_cidr` gates the whole admin surface, which is two sets of endpoints:

- **The mutation API**: POST, DELETE and PATCH on `/api/v1/...`, gated by `MutationAuthMiddleware`.
- **The four admin reads**: `GET /api/v1/audit`, `/api/v1/tokens`, `/api/v1/policies` and `/api/v1/config`, gated by `requireAdmin` inside each handler. They sit outside the mutation middleware, which passes GET through so apt, pip, go and npm can fetch packages with no credential.

Two callers, one predicate: `server.AdminPermits`. They read the same list and used to answer separately, which is how they came to disagree about what an empty list means.

The mutation half carries a second layer:

1. **IP allow-list** (`admin_permit_cidr`): Only requests from permitted CIDRs reach the admin surface. Defaults to `["127.0.0.0/8", "::1/128"]`, so out of the box only localhost can create or delete entries, or read the audit trail. Change it with `bodega acl admin add|remove`.

2. **Bearer token** (`api_token`): When `admin_permit_cidr` extends beyond localhost, a valid `Authorization: Bearer <token>` header is required on mutation requests. Generate tokens with `bodega token generate`. The admin reads take the IP layer alone.

Both layers read the client IP that `trusted_proxies` resolved, so a permissive trusted set widens the first layer no matter how narrow `admin_permit_cidr` looks.

#### An empty admin list permits nobody

An empty `admin_permit_cidr` refuses every mutation **and** all four admin reads, from localhost included. It is a list an operator can empty, never a statement that there is nothing to control: reading it as "no restriction" left `/api/v1/audit` and `/api/v1/tokens` open to every source address that could reach the listener, while every mutation from the same address was refused.

Three ways the list can end up empty, and what each gets:

| Route | Result |
| --------------------------------------------------- | ---------------------------------------------------------------------------------- |
| Key absent from `config.json` on a fresh install | `config.Load` substitutes `["127.0.0.0/8", "::1/128"]`. The empty state is unreachable through the file. |
| Key present but parsing to nothing (a typo, or blank entries) | `Start` refuses, naming the entry and pointing at `bodega acl admin list`. |
| `bodega acl admin remove <last> --force` | Accepted, and it locks the operator out of both halves. That is what `--force` is for; the refusal text says so. |

The localhost default stays the first line and the startup refusal is the second, because they cover different cases. The default answers an absent key; it never sees a key the operator wrote. The startup refusal answers a key that is present and unusable, which is the one case where falling back to a default would substitute bodega's access control list for the operator's.

Both are re-read per request rather than captured when the handler chain is built, because widening the list is exactly what turns layer 2 on. A set frozen at startup would leave a widened server admitting unauthenticated mutations until something restarted it.

`bodega acl admin` refuses two changes that fail silently otherwise, each with a `--force` escape:

- **An add that takes the list past localhost while no token exists.** It turns on the Bearer requirement, and the next mutation (including one from localhost that worked a moment earlier) answers 401 with nothing naming the cause.
- **A remove that empties the list.** An empty `admin_permit_cidr` permits nobody, mutations and admin reads alike, so nothing could put an entry back over HTTP.

Every add and remove is recorded in the audit database as a `create` or `delete` event with `pkg_type=acl`, the list in `pkg_name`, the CIDR in `pkg_version` and the OS user in `actor`. Who changed the rule sits beside the record of who the rule turned away.

Package-serving read endpoints remain unauthenticated. Package manager clients (apt, pip, go, npm, helm) use standard protocols that don't support auth headers, so those read paths stay open by design. The four admin reads above are the exception, and a refusal on one is itself recorded in the audit database.

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

**Concurrency.** `database/sql` pools connections, so several writers through one handle are several SQLite connections contending for the write lock. The DSN carries `busy_timeout=5000`, which makes the loser wait rather than take `SQLITE_BUSY` and lose its row. Serializing with `SetMaxOpenConns(1)` would also work and is not used: it takes the concurrent reads WAL exists to allow, so a dashboard query would queue behind every write. On an M1 Ultra with an internal NVMe SSD, eight concurrent writers sustain ~2,600 inserts/sec through one handle.

**Discovery losses are counted in two places.** `DiscoveryRecorder` drops on a full queue and counts that as `dropped`; a row that reaches the writer and is then rejected by the database counts as `failed` and logs at Error. Backpressure and a broken database are different problems, so the summary log names them apart. A `policy_violation` event that fails to write does not change the refusal: the request is still denied, and the lost event is logged at Error with its fields so it can be reconstructed.

## Configuration

One JSON file at `/etc/bodega/config.json` or `~/.config/bodega/config.json`. Priority: CLI flags > environment variables > config file > defaults.

Key fields:

| Field | Default | Purpose |
|-------|---------|---------|
| `bucket` | (required) | S3 bucket name |
| `storage_backends` | {} | Additional backends, by name |
| `storage_by_type` | {} | Which named backend each type's next write targets |
| `storage_policy` | (per package) | Manifest field overriding `storage_by_type` for one package |
| `region` | us-west-2 | AWS region |
| `build_root` | /opt/bodega | Where artifacts are built locally |
| `manifest_dir` | {storage_path}/manifests | Where manifests live on a filesystem backend. Always absolute: a relative value under a unit with no `WorkingDirectory=` resolves against `/`. `bodega serve` creates it when absent and refuses to start when it cannot |
| `proxy_cache_enabled` | false | Global proxy/cache toggle |
| `metadata_ttl` | 1h | How long mutable proxy resources are cached |
| `deny_list` | [] | CIDR entries to block. **Bootstrap only**: copied into the audit DB on first start, then owned by `bodega acl deny` |
| `admin_permit_cidr` | [127.0.0.0/8, ::1/128] | CIDRs allowed to reach the admin surface: mutations and the four admin reads. Empty permits nobody; a value that parses to nothing stops the start. **Bootstrap only**: owned by `bodega acl admin` after the first start |
| `trusted_proxies` | null (loopback + RFC 1918) | Peers whose forwarded headers are believed; `[]` trusts none. **Bootstrap only**: owned by `bodega acl proxies` after the first start |
| `tls_min_version` | 1.3 | Floor for bodega's own listener; `1.2` or `1.3` |
| `api_token` | (none) | Bearer token for mutation API |
| `tls_cert` / `tls_key` | (none) | Manual TLS. Setting one without the other is fatal at load, not a request for plaintext |
| `tls_autocert` / `tls_domain` | (none) | Let's Encrypt. Accepted and refused at startup; see [#113](https://github.com/ravinald/bodega/issues/113) |
| `allow_plaintext` | false | Authorizes an unencrypted listener. With no cert pair `bodega serve` refuses to bind without it, and refuses on `:443` naming the port |
| `audit_db` | {log_dir}/audit.db | Audit database path |
| `git_upstreams` | {} | Namespaces under `/git/` mapped onto an upstream forge, each in `open` or `catalog` mode |
| `binary_upstreams` | {} | Namespaces under `/binaries/` mapped onto an upstream download host, each in `open` or `catalog` mode. While empty, `/binaries/` serves from storage as before |

The TUI config editor (`C` key in `bodega shell`) writes to the same file.

### The empty repository

A repository with no packages is legal. `bodega serve` starts, `/healthz` answers 200, and `dists/<suite>/Release` carries `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 0 main/binary-amd64/Packages`, the SHA-256 of the empty string. That is the correct answer on a fresh install with nothing imported yet, and it lets `apt update` succeed before the first package lands.

A broken install produces the same bytes: a `manifest_dir` nothing can read lists zero packages, which is indistinguishable from a repository that holds none. `bodega serve` separates the two before it opens a socket. An absent root is created; one that cannot be created, opened, or is a file rather than a directory refuses the start, naming the path and the config file it came from. So an empty `Release` means "nothing imported yet" and nothing else, and the `no packages loaded` line at `log_level` 0 marks it in the journal.

### Git upstreams

`git_upstreams` maps a namespace under `/git/` onto an upstream forge, because one flat key cannot express two forges at once and a corporate GitLab and github.com are the same protocol under different trust:

```json
"git_upstreams": {
  "internal": { "url": "https://git.corp.example/", "mode": "open" },
  "github":   { "url": "https://github.com/",       "mode": "catalog" }
}
```

The key becomes a URL segment and a directory name, so it matches `^[a-zA-Z][a-zA-Z0-9_-]*$` and may not take a name bodega already serves or stores under (`api`, `apt`, `repos`, `pool` and the rest). The URL must be `https`, name a host, and end in `/`. A malformed entry stops the load and the error names the namespace; nothing is silently corrected to a default.

Mode decides what happens when a client asks for something no manifest entry names:

- `catalog`, the default when mode is absent or empty, resolves only paths an existing manifest entry covers. Everything else gets a 404 and a `no_manifest` discovery row to promote later. This is the posture for a public forge.
- `open` composes the upstream URL for any path under the namespace and fetches it. On a public forge that means any client which can reach bodega can make bodega fetch arbitrary upstream repositories. Pick it for a forge whose publishing is already controlled, and read that sentence before you do.

A request under `/git/` naming a namespace no entry covers gets a 404 and a `no_namespace` discovery row, which is how an operator finds the key they have not added yet.

A configured namespace is served by the git smart-HTTP proxy: `git clone https://bodega-host/git/<namespace>/<org>/<repo>.git` mirrors the upstream on the first request and answers from that mirror after. See [Git smart-HTTP](USAGE.md#git-smart-http) in the usage reference for the routes, the refresh interval, the operational requirements and what is out of scope. The bundle route `/git/{name}/{file}` is unaffected and still serves uploaded bundles from storage.

Only public, unauthenticated upstreams are supported. No credential is read from the config file or the environment, so a private forge answers bodega as an anonymous client: the operator sees a 404, not an auth error. Credential handling is a follow-on.

### Binary upstreams

`binary_upstreams` is the same shape applied to `/binaries/`, and shares the validator, the modes and the defaults with `git_upstreams`. Binaries are the type most likely to come from many vendors at once — a releases host, a forge serving release assets, a vendor CDN — which is why a single flat key cannot name what an install pulls from:

```json
"binary_upstreams": {
  "hashicorp": { "url": "https://releases.hashicorp.com/", "mode": "open" },
  "github":    { "url": "https://github.com/",             "mode": "catalog" }
}
```

`/binaries/<namespace>/<rest>` composes `<url><rest>` and caches the result under `binaries/<namespace>/<rest>`. `open` fetches on a miss and enforces the allow-list; `catalog` looks `<namespace>/<rest>` up in the manifest store first and 404s a miss with a `no_manifest` row, without contacting the upstream. `bodega discover promote binary <namespace>/<rest> --as manifest` is what turns that row into the entry catalog mode is waiting for.

The empty map is the migration path and the default: while `binary_upstreams` has no entries, `/binaries/{path...}` reads storage exactly as it always has. Once any entry exists, a first segment naming no key 404s with a `no_namespace` row rather than falling through to a storage read — **including a path that resolved before**. The alternative, falling through, was rejected: the storage read misses too, so the 404 arrives either way and the discovery log ends up holding nothing that names the key the operator meant to type. An install that serves local binaries and namespaced ones at once needs a namespace for each tree it still serves locally.

Authenticated upstreams are out of scope here as they are for git. A namespace pointing at a private release endpoint fails as a 404 with no credential prompt, which is indistinguishable from a typo in the path; check the upstream by hand before hunting the path.

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
- `GET /api/v1/status` - Health, entry counts, and the apt client state (signing, served suites, public URL, rendered sources)
- `GET /api/v1/config` - Non-sensitive configuration

Frozen entries cannot be deleted through the API.

## Deployment

Bodega is a single static binary. A typical deployment:

1. Terraform creates the S3 bucket and an EC2 instance with an IAM role granting S3 read/write.
2. The bootstrap script installs the binary, writes `/etc/bodega/config.json`, and enables a systemd service running `bodega serve --addr :8080`.
3. Other instances discover the bucket via SSM parameters (`/infra/repo/bucket`, `/infra/repo/region`) and configure their package managers to point at bodega.

The binary runs on the build host. The server runs on the same host or a dedicated package server. There is no separate worker process.

SIGHUP-based reload is supported via a PID file: send `SIGHUP` to the running process to reload the manifests, the apt signing key and the CIDR access lists without losing in-flight requests. It does not re-read `config.json`; nothing else in that file is reloadable, and a change to one still takes a restart.
