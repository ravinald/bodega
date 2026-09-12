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

The server is a single Go binary. No database server, no message queue, no container runtime. State lives in two places: manifest JSON files (what should exist) and an S3 bucket (what does exist). A SQLite file handles the audit trail, and `audit_sink` can send the event half of it to postgres, syslog or a JSONL file instead.

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

### Generated suites and mirrored codenames

A codename is served in one of two shapes, and this document and `docs/USAGE.md` use these two names for them throughout. A **generated suite** is a codename in `apt_suites`: bodega builds `Release` and the `Packages` bodies from its own manifest entries and signs them. A **mirrored codename** is a codename in `apt_upstreams`: bodega proxies an upstream archive's `dists/` tree and the pool artifacts it names, and forwards the archive's signature untouched. A codename is one or the other, never both.

`internal/server/apt_mirror.go` proxies `dists/<codename>/...` through `proxyOrCache` — `by-hash/` paths immutable, everything else mutable under `metadata_ttl` — and the pool artifacts the index points at, immutable. bodega parses no upstream index: apt reads the proxied `Packages` and composes the next request itself, so every component and architecture the upstream publishes resolves without bodega knowing they exist.

A mirror gives an operator four things: a chokepoint, because every fetch leaves the network through bodega and the host allow-list (`bodega policy add apt <host>`) decides which archives it may reach at all; a cache, so the second host to install a package pays no upstream bandwidth; an audit row per request; and discovery rows naming the dependency closure the fleet actually installed. It gives no per-package control. There is no allow-list, no version pin, and no `hidden` or `frozen` under a mirrored codename, because bodega parses no upstream index and so has nothing to filter against: every package the archive publishes is reachable, and one that was not would 404 mid-install on the first `Depends:` chain that reached it. Per-package control is what a generated suite is for, since an `apt_suites` codename publishes the manifest entries an operator put in it and nothing else.

`InRelease` and `Release.gpg` are forwarded unchanged, so the archive's own signature reaches the client and verifies against the distro keyring already on the host. bodega's key signs generated suites and nothing else, and `config.Load` refuses a codename that appears in both `apt_suites` and `apt_upstreams`: a signature over a `Release` is a signature over the digests of the `Packages` beside it, one URL serves one `Packages` per component and architecture, so a shared codename would hand a client an index its signature does not describe.

Two alternatives were rejected. Leaving the codename in `apt_suites` while `apt_upstreams` takes over its `dists/` tree, with bodega simply not signing it, gives silent partial service: the locally built `.deb`s stay in the store and `bodega status apt` keeps listing them while the forwarded `Packages` names only upstream packages, so nothing serves them and every diagnostic reports success. Merging the two indexes under bodega's own signature is the shape that would put a local and an upstream `.deb` in one suite, and it costs the multi-paragraph `deb822` parser deferred in `internal/deb822`, run over an index tens of megabytes uncompressed per component and architecture; a precedence rule for a package name present on both sides, which is a supply-chain decision, because local-wins lets anyone with manifest write access shadow `libc6`; republished or stripped `by-hash/` bodies, since the upstream `Release` advertises digests of the upstream bytes; and a second refresh loop, because a merged index has to track the upstream's freshness as well as bodega's. An operator who wants both in one apt transaction gets it today by listing two suites in one `.sources` stanza.

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

pypi entries carry the same two values. A `proxy` distribution resolves a wheel by reading `<pypi_upstream>/simple/{dist}/`, because pypi serves artifacts under a content-hash path no filename produces, and bodega republishes that index with its links pointed back at `/pypi/wheels/` rather than relaying pypi's absolute ones. Relayed, they route the client around the proxy entirely. See [Republishing a proxied index](USAGE.md#republishing-a-proxied-index).

git and binary reach upstream through `git_upstreams` and `binary_upstreams`, which carry a per-namespace `mode` of the same two values.

apt reaches upstream through `apt_upstreams`, and it has **no** `catalog` mode and no per-package allow-list. apt decides what to request by reading a `Packages` index, so the first `Depends:` chain reaching a package nobody cataloged would 404 mid-install and surface as a broken dependency rather than a policy refusal. `git_upstreams` and `binary_upstreams` can offer `catalog` because a client there asks for one artifact it already named. Constraint for apt is the host-level allow-list (`bodega policy add apt <host>`), checked before the fetch and before the pool probe.

### Startup conditions and log levels

**A non-fatal startup condition that changes what bodega serves logs at `Error`. `Warn` is for conditions that do not.**

The rule exists because `log_level` defaults to `0` and `internal/logging/level.go` maps `0` to `slog.LevelError`. Anything below that is invisible on a default install, so a `Warn` describing a degraded server is a line written for nobody: three states put bodega into `active (running)` with `/healthz` answering 200 while it served nothing an operator wanted, and all three were `Warn`. The level is not a severity opinion, it is the decision about whether the operator finds out.

`Error` here does not mean the process failed. It means the running server is not doing what the config asked, which is the one thing a `journalctl -u bodega` with no arguments has to show. What is on the wrong side of the line stays on the wrong side for years, because nothing fails and no test catches it — a test that raises the verbosity passes against every one of these defects, so the tests assert on output captured at `log_level: 0`.

Currently logged at `Error` under this rule, from `serve`, `newServer` and `Start` before the listener binds. Runtime `Error` lines on the request path are not startup conditions and are not listed:

| Condition | What changes | Site |
|-----------|--------------|------|
| Storage backend fails to construct | Every package route answers 503; the API and `/healthz` still serve | `startupStorage`, `cmd/bodega/cmd_serve.go` |
| `deny_list` has an unparseable entry | The whole deny list is dropped, so every address it named is served | `newServer`, `internal/server/server.go` |
| `trusted_proxies` has an unparseable entry | The whole list is dropped, so `X-Forwarded-For` is ignored and every request is attributed to the proxy | `newServer`, `internal/server/server.go` |
| No packages loaded | Every repository index publishes as empty | `cmd/bodega/cmd_serve.go` |
| Plaintext authorized on `:443` | Every request and response is in the clear on the port clients read as TLS | `guardPlaintext`, `internal/server/server.go` |
| A retired `tls_autocert: true`, or `--tls-autocert`/`--tls-domain`, with no cert pair | The option that promised TLS promises nothing; the server binds in the clear or refuses | `reportRetiredTLSKeys`, `cmd/bodega/cmd_serve.go` |
| Pepper file unreadable | Token auth does not work | `newServer`, `internal/server/server.go` |
| `audit_events` omits `denied` | No refusal the server makes is recorded, and the journal is the only copy | `newServer`, `internal/server/server.go` |
| `audit_sink` is write-only | `GET /api/v1/audit` answers 501 and the discovery reads refuse, rather than returning an empty page | `newServer`, `internal/server/server.go` |
| `git` or `git-http-backend` absent | The smart-HTTP route is never registered, so `git clone` 404s; the bundle route is unaffected | `resolveGitTool`, `internal/server/githttp.go` |
| apt signing key present but unusable | The apt repository is signed with the previously loaded key, or not at all | `loadAptSigner`, `internal/server/apt.go` |
| apt signing key loaded but its public half will not render | The key is never installed, so `Signed-By:` has nothing to point at and clients fall back to `[trusted=yes]` | `loadAptSigner`, `internal/server/apt.go` |
| apt signing key loaded but its keyring will not render | The key is never installed, so the repository is served unsigned | `loadAptSigner`, `internal/server/apt.go` |

Two audit conditions moved past this rule and are now **fatal for `serve`**: an audit store that will not open, and an `audit_db` the process cannot write. Both used to log at `Error` and continue, which left a server that answers `/healthz` while dropping the record of every request it refuses. Held on `Server.auditErr` and returned from `Start` before the listener binds, the same shape `adminErr` already had. An unset `audit_db` is not one of them: that is an install that asked for no audit trail.

Left below `Error` on purpose, because what gets served is what was asked for: an authorized plaintext listener off `:443` (the documented reverse-proxy deployment), a retired `tls_autocert: true` on a host whose `tls_cert`/`tls_key` are serving, and the ACL disagreement line, where the database is the documented owner and is doing what the operator told it — the config file's copy is inert by design, not degraded. Those three are `Warn`. `no apt signing key installed` is `Info`, one step lower again: an absent key is a configuration and not a fault, unsigned is a documented mode with a `[trusted=yes]` sources line the banner prints, and every install that never runs `bodega apt key generate` would otherwise open with a line about a key it does not want. The neighboring case where a key _was_ loaded and is now gone from every search path stays `Warn`: serving does not change until the restart that drops it.

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

## Apt entry-creation modes

Three ways to write an apt manifest entry, and all three answer where the `.deb` comes from. None of them decides how the repository is served. That is the generated-suite versus mirrored-codename split under [Generated suites and mirrored codenames](#generated-suites-and-mirrored-codenames), and an operator asking whether bodega can proxy a whole distribution wants that section rather than this one. The answer is yes.

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

The mechanisms described below — checksum verification, deny lists, mutation
gating, response hardening, TLS, manifest integrity — operate inside the
boundary defined by bodega's threat model. That model, including the
distribution formats (snap, flatpak, AppImage auto-updaters, Homebrew casks)
that are intentionally out of scope, lives in
[docs/THREAT_MODEL.md](THREAT_MODEL.md). Operators standing up locked-down
build hosts should read that document first and run `bodega doctor` to verify
the host configuration aligns with it.

### Checksum verification

Every downloaded artifact gets a SHA-256 computed at fetch time. The checksum is stored in the manifest.

On subsequent fetches, the stored checksum is compared against the freshly downloaded artifact. A mismatch halts the fetch and logs a warning. Nothing is saved when a checksum fails.

The `checksum_verified` field tracks whether the checksum was confirmed against a source-published digest (e.g., a SHA256SUMS file in a GitHub release). `true` means the checksum matches what the publisher says it should be. `false` means bodega computed it but couldn't find an upstream reference to compare against.

For proxy mode, the server verifies checksums on immutable resources (versioned archives) and records mismatches in the audit trail.

Each cached row is keyed by its object key and also carries the package type, name and version, so `bodega pkg checksum list --type` and `bodega pkg checksum clear <type> <name>` have something to filter on. That identity is derived by `manifest.ParseKey`, the inverse of the key constructors in the same file — not by the request-path parser in `internal/server/middleware.go`, which reads a different string. Seven of the eight trees key their storage under a string the request-path parser does not recognize: apt, gomod, helm, git and cargo reached the table with no type and no name at all, and npm and pypi with a name assembled out of the wrong path segments. Only binary came out right, and `checksum clear` matched nothing for the rest. `TestParseKeyRoundTripsEveryType` builds a key for every member of `manifest.AllTypes` with its constructor and reads it back, so a ninth ecosystem cannot ship a constructor without the arm that inverts it.

helm and cargo are the two trees whose key flattens name and version into one filename, and `-` is legal inside both a chart name and a prerelease version. `ParseKey` splits at the first `-` that opens a digit run ending at `.` or at the end of the name, so `cert-manager-1.14.0-rc.1.tgz` reads as `cert-manager` at `1.14.0-rc.1` and the crate `md-5-0.10.6.crate` keeps its numeric tail. A `v` or `V` may sit in front of the run, because helm charts are routinely published at `v1.2.3` and `builder.ParseSemVer` accepts the prefix and keeps it; prefixed, the run has to be dotted, so a chart named `my-v1` stays whole. Neither name can hold a `/`, so neither is encoded going in and neither is decoded coming out: `SafeName` collapses a slash to `--` for npm, git and binary alone, and `ParseKey` restores it for those three alone. Running the decode over a chart or a crate read the literal name `foo--bar` as `foo/bar`. The cost of that is the recorded identity and nothing more: every read path applies `SafeName` again, so `GetPackage(helm, "foo/bar")` resolves to `helm/foo--bar/manifest.json` and the entry is found. Measured with the decode restored, the request serves 200, the upstream sees `/charts/foo--bar-1.2.3.tgz` and the object key is the one the request named; only the discovery row and the `serve_fetch` event say `foo/bar`, and that is the name `discover promote --as manifest` would write into a manifest.

Two shapes have no answer from the key alone, both of them a name that reads as a version. An unversioned chart whose name ends in a digit segment reads that segment as a version, and charts are the only type that can omit a version, so nothing else is exposed to that one. A name whose own tail is a dotted digit run splits there rather than at the version: `foo-2.0-1.0.tgz` reads as `foo` at `2.0-1.0` where the uploader may have meant `foo-2.0` at `1.0`, and nothing in the key says which.

The chart request path reads the same rule, ambiguities included. `handleHelmChart` builds the requested key with `HelmChartKey` and takes the name and version back out of it with `ParseKey`, so the proxy-mode lookup, the `no_manifest` discovery row and the per-version storage backend name the chart a client would type for every shape the rule answers, and the two it cannot answer resolve there the same way they resolve in the checksum table. The key itself is the request's own filename either way, so where a chart is stored does not depend on the split. The two other derivations over the same request now read it as well. `pkgVersionFromKey` is gone: `recordDiscovery` takes the row's version off the key with `ParseKey` unconditionally, so a proxy-mode fetch and the `no_manifest` miss beside it carry one version between them. The name is the other way round, preferring the caller and falling back to the key: `ParseKey` restores a slash for npm, git and binary, so it cannot tell an encoded `/` from a literal `--` and reported the npm package `foo--bar` as `foo/bar` against a `serve_fetch` event and an object key that both said `foo--bar`. The caller read the name off the request path and knows which it is. A chart request still has one source either way, `handleHelmChart` deriving the name it passes from `ParseKey` too. `parsePackagePath`'s helm arm runs the two lines `handleHelmChart` runs, so the `serve_fetch` audit event names what the request path resolved.

The same split survived one arm over. `parsePackagePath`'s npm arm cut its tarball at the last `-` as well, so a prerelease reached `bodega audit events` as version `rc.1` while the object key and the discovery row both carried `1.0.0-rc.1`. It now calls `npmVersionFromTarball`, the derivation `handleNpm` already stores under, which anchors on the package name. That is the whole set on the request and key paths: nothing serving a request or reading an object key splits at the last `-` any more. One rule remains outside them. `internal/hostpkg/helm.go`'s `splitChart` recovers a chart identity from the single field `helm list` reports it in, scanning backwards for the last `-` that opens a digit, and it disagrees with `ParseKey` on a `v`-prefixed version: `mychart-v1.2.3` imports whole as a name with no version. It reads a host's own inventory rather than a request, so it is filed against the item that owns host import (#260) rather than fixed here.

### Where the CIDR lists live

`admin_permit_cidr`, `deny_list` and `trusted_proxies` live in the audit database, in `acl_lists` and `acl_entries` (migration `008`). They are the only runtime values that have moved out of `config.json` so far. The rest of the runtime set (`proxy_cache_enabled`, `metadata_ttl`, the upstream URLs, `audit_events`) is a candidate and unscheduled. The bootstrap set stays in the file by definition: `storage_backend`, `bucket`, `region` and the filesystem paths are what locate the database the other values would live in.

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

Package-serving read endpoints remain unauthenticated. That is a policy, not a limitation: this document used to justify it by saying package-manager clients cannot send auth headers, and that was wrong for all eight of them. What they can send is described under **Read-path identity** below, and bodega now reads it to attribute a request. What may be fetched is a separate question, and **Host profiles** below is the model that answers it: the read path consults it on every package route for the seven non-apt types. The four admin reads above are the exception, and a refusal on one is itself recorded in the audit database.

### Read-path identity

Every package route is open, and until migration `013` the only client attribute the serve path read was the resolved IP, which reached the deny list and the audit rows and stopped there. An operator asking "which host pulled this" got an address and a DHCP lease to correlate it against.

A binding maps something the serve path can observe to a name. Two kinds, in `identity_bindings`:

| Kind    | Key                | Answers                                 | Costs                                                     |
| ------- | ------------------ | --------------------------------------- | --------------------------------------------------------- |
| `token` | an `api_tokens` id | "this credential belongs to build-07"   | the host needs the credential before it can be attributed |
| `cidr`  | a masked CIDR      | "everything on this subnet is a devbox" | no bootstrap problem; needs `trusted_proxies` answered    |

Neither replaces the other. A token binding is the precise statement and has a bootstrap problem on a host that did not exist an hour ago; a CIDR binding has none and cannot tell two hosts on one subnet apart.

**What each client sends.** Eight routes, three header shapes, and `credentialFrom` in `internal/server/identity.go` parses all three without asking which route the request landed on:

| Client | Where the credential lives        | On the wire              |
| ------ | --------------------------------- | ------------------------ |
| apt    | `/etc/apt/auth.conf.d/`           | `Authorization: Basic`   |
| pip    | `~/.netrc`, or the index URL      | `Authorization: Basic`   |
| npm    | `_authToken` in `.npmrc`          | `Authorization: Bearer`  |
| go     | `~/.netrc` for the `GOPROXY` host | `Authorization: Basic`   |
| cargo  | `~/.cargo/credentials.toml`       | `Authorization: <token>` |
| helm   | `--username` / `--password`       | `Authorization: Basic`   |
| git    | `~/.netrc`, read by libcurl       | `Authorization: Basic`   |
| binary | `~/.netrc`, read by curl or wget  | `Authorization: Basic`   |

On `Basic`, the password wins and the username is the fallback: apt, go and git all carry a login plus the secret, while a pip index URL of the form `https://<token>@host/pypi/simple/` has only the user half to put it in. Cargo is the one client that sends its token with no scheme at all, which is why a single unrecognized word is read as a credential and `Digest`, `Negotiate` and a scheme with an empty value are not.

**Resolution order is token, then longest-prefix CIDR, then unidentified.** The token wins because it is the more specific statement: an operator who issued a credential to one host said more about that host than the subnet it happens to sit in. A credential that matches no token, or matches an expired one, or matches a token nothing is bound to, falls through to the CIDR rather than refusing. This path adds attribution and never admission, so a request served yesterday is served today; all that changes is what the row says.

**One token or one CIDR resolves to at most one identity, and the second write is what says so.** `NormalizeBindCIDR` masks the host bits and folds the IPv4-mapped spelling back to IPv4 before anything is stored, so the key is the address set rather than one way of writing it: `10.0.0.5/8`, `10.0.0.0/8` and `::ffff:10.0.0.0/104` are one row. That is what makes the primary key `(kind, bind_key)` sufficient. Two bindings of the same prefix length covering one address are refused when the second is written, naming the first, and after normalization every one of those refusals is the key collision, because two masked prefixes of equal length are either identical or disjoint. The separate overlap check in `findBindingConflict` guards a row that reached the table around `AddIdentityBinding` and carries an unmasked key; it is unreachable through the CLI. Resolving any of this at read time would make the answer depend on row order, which nothing about the table guarantees.

**`bodega serve` refuses to start when a CIDR binding exists and `trusted_proxies` is still the built-in default.** The default is loopback plus RFC 1918, and bodega returns `X-Real-IP` verbatim from any peer in that set (see **IP resolution**), so on a default-configured instance a CIDR binding is assertable by whoever sends a header: any RFC 1918 peer claims an address inside a bound network and collects that identity. Both remedies are accepted and the refusal names both: `bodega acl proxies add <cidr>` names the proxy and claims the list for the database, and `"trusted_proxies": []` in the config file claims it empty on the next start. Leaving the default is what is not. `acl proxies remove` is deliberately not a way out of the default, because it refuses a CIDR the list does not hold rather than claiming the list as a side effect. A token binding has no such hole, because the credential is the claim, and an instance carrying only token bindings starts unchanged.

It is a refusal rather than a warning for the same reason the empty `admin_permit_cidr` refusal is: `log_level` defaults to `Error`, so a warning here is written for nobody and the instance runs anyway. `bodega identity bind cidr` prints the same guidance at bind time, because discovering an interlock from a server that will not come back up is worse than discovering it from the command that armed it.

**The interlock is enforced where the binding is read, not only where the process starts.** Startup is the rarer way into that state; the ordinary operator order is the reverse, because the server is already running when the bind happens. `guardCIDRBindings` passed at boot with nothing bound, and both paths that install a binding afterwards, `SIGHUP` and the 30-second cache, reach the read path behind it. So `resolve` takes the same `trusted_proxies` predicate the startup refusal uses and gates the CIDR half on it: unanswered, a CIDR binding resolves as absent, the request is served exactly as before, and the row names nobody rather than naming a host any RFC 1918 peer could have claimed with a header. Token bindings resolve throughout, because a credential is a claim the caller had to hold. Entering that state logs once at `Error` with both remedies and leaving it logs once at `Info`, since the operator who reached it by binding never saw the refusal and `identity bind` writes its warning to the stderr of a command that commonly runs under config management.

**The identity sits beside the address, never in place of it.** `events.identity` and `upstream_discovery.last_identity` are new columns next to `client_ip` and `last_client`. The deny list matched on the address, one identity holds several addresses, and a row that dropped the address would lose which of them asked.

`IdentityMiddleware` sits inside `DenyListMiddleware` and outside everything downstream of it that writes an audit row. Inside the deny list, so a refused address costs no token hash: a deny-listed peer is the one client that can flood this server on purpose. Outside the audit and mutation gates, so the fetch row, the mutation denial and the discovery observation all name the host. The deny-list denial is the one row that does not, and that is the price of the order: `DenyListMiddleware` writes its own row before identity has been resolved, so `events.identity` on a `deny_list` denial is empty and the address is the whole record. That is the address the deny list matched on, which is the question such a row exists to answer. The binding table is read per request through a 30-second cache, on the same schedule and through the same `SIGHUP` refresh as the CIDR lists, so `bodega identity bind` and `bodega acl` issued in the same minute land together.

`bodega doctor --write-credentials --token <tok> --url <base>` writes the credential into each client's own file, because a feature that costs eight hand edits does not get adopted. Five files serve the eight clients: pip, go, git and curl/wget all read `~/.netrc`, and writing four copies of one secret would be four things to rotate. apt is the one that cannot share it: its `machine` line takes a scheme prefix, and without one apt matches the host and then refuses to send the credential over plain HTTP, which leaves the entry inert on every plaintext deployment. `doctor` writes `machine <scheme>://<host>` there, taking the scheme from `--url`. A second run removes bodega's own entry before placing the fresh one, so nothing an operator wrote in those files is touched. A marker comment fences the entry where the format takes a comment anywhere, but the fence is never what finds it again: the clients own these files and rewrite them, and `cargo login`, `helm repo add` and `npm config set` re-serialize and discard comments, so by the second run the marker is gone and an append would leave two bodega entries with the older token first. Each of those three targets carries a locator for the entry bodega owns: the `[registries.bodega]` table, the repository named `bodega`, the `//<host>/npm/:_authToken=` line. So what a second run guarantees is one entry holding the new token in a file the client still parses, not that the marker survived. `~/.netrc` gets no fence, because a comment is not safe everywhere an append can put one there. Python's `netrc` module refuses a `#` line preceded by a blank one and refuses the whole file for it, so a fence landing after the blank line that separates stanzas costs pip every credential in the file rather than only bodega's, and costs it silently: `requests` catches `NetrcParseError` and sends nothing, while libcurl parses the same file happily, so git and curl keep working. Go's parser is no safer a home for one, since `cmd/go`'s `parseNetrc` scans `strings.Fields` in pairs and ignores `#` rather than stripping it, which leaves a fence inert only while no keyword lands on an even index. The `machine <host>` stanza is the whole anchor there, which is what it already had to be: no client rewrites that file, but the operator who configured bodega by hand before this command existed wrote a stanza in it, and two credentials for one host in that file are read two ways, libcurl taking the first match and Python's `netrc` module the last. apt is the only target that needs no locator, because that file is bodega's alone and replaced whole. helm's path is resolved the way helm resolves it (`$HELM_REPOSITORY_CONFIG`, then XDG, then `~/Library/Preferences/helm` on macOS and `~/.config/helm` elsewhere); it is the only target here whose location is platform-dependent, and a hardcoded Linux path would land the credential in a file helm never opens while the table reported it written. helm's `repositories.yaml` is the one target where appending is not always legal, and it refuses with the `helm repo add` line to run instead rather than writing a repository entry into whatever key followed, or under the `repositories: []` that `helm repo remove` leaves behind, where an appended sequence is a second value for one key and costs the operator every later `helm repo add`. On a host with no helm config the whole document is written, keys and all: helm unmarshals that file into a struct, so a bare list is not a partial file it tolerates but one it rejects outright, taking every later `helm repo add` with it.

**The credential this writes is not read-only, and `doctor` says so before it writes.** `api_tokens` rows carry no scope, and `MutationAuthMiddleware` accepts any unexpired one of them as the credential half of the mutation gate whenever `admin_permit_cidr` reaches past loopback. So a token in a client host's `~/.netrc` authorizes `POST` and `DELETE` from that host if its address is also inside `admin_permit_cidr`. Read-path identity did not create that; the absence of token scopes did, and it surfaces here because the read path is the first place those tokens live on machines other than an operator's. Two remedies exist today: keep `admin_permit_cidr` at loopback, which makes the mutation gate ignore tokens entirely, or treat every host written a credential as admin-capable. Scoped tokens are the answer that severs the two, and they are not in this change.

**The credential never reaches the request log.** `formatHeaders` writes every header at `log_level: 3`, so a token would have landed in the journal in both spellings: plaintext behind `Bearer`, and inside the base64 blob behind `Basic`. `Authorization`, `Proxy-Authorization`, `Cookie` and `Set-Cookie` now log their name and a fixed `[redacted]` in place of the value, matched on the folded header name because the same function is handed response headers a handler may have set through the map directly. A prefix or a hash would still be reversible against a token whose alphabet and length are published, so nothing derived from the value is written either. `recordDenial` already takes that position for audit rows, which copy no header into one; the logger contradicted it. Read-path identity is what made it pressing rather than theoretical: before it the only `Authorization` headers arriving were operator mutations, and now every package GET can carry one, on eight client hosts per `doctor` run, and the tokens are unscoped.

### Host profiles

Nothing bodega serves varies by consumer. Migration `014` adds the model that changes that and stops short of applying it. The upstream allow-list, the age and OSV gates, hidden and frozen versions and every version constraint hold one answer for the whole fleet, so the control is "what may anyone here fetch". In a fleet of any size that set is the union of every host's needs, which is the widest set anybody needs rather than the set any host needs: a wheel cataloged for one CI runner is offered to every database server, and the operator who tightens it breaks the runner.

A profile names the set one class of host may fetch, and the version rule each package carries for that class. Four tables in `014`: `profiles`, `profile_bindings`, `profile_types` and `profile_entries`.

**A profile is a view over one catalog, never a second catalog.** Storage, object keys, the checksum table and the manifests do not learn about profiles. The rejected alternative was a catalog per profile, and it fails the way per-backend storage would have: `checksums` is keyed by object key (`011_checksum_package_identity.up.sql`), so one artifact reached through two profiles acquires two identities, and they drift on the first refresh that touches only one of them. One artifact, one checksum, one object; the profile decides who is answered with it.

**A binding attaches a profile to an identity, which is what `013` already resolves a request to.** That reuse is what keeps one resolution path: the serve path answers "which host is this" once, from a token or a CIDR, and the profile answers "what may that host fetch". A second table keyed by token or CIDR would be a parallel resolver free to disagree with the first about which host a request came from, and the disagreement would surface as a fetch nobody could explain. `identity` is the primary key, so one host resolves to at most one profile; binding an identity that is already bound moves it and says where it came from.

**Three levels, not two.**

| Level           | Where it lives    | What it decides                                                                                   |
| --------------- | ----------------- | ------------------------------------------------------------------------------------------------- |
| the profile     | `profiles`        | which hosts it governs, through `profile_bindings`                                                |
| the type marker | `profile_types`   | membership (`closed`, `open`), the version default (`pinned`, `floating`) and the expansion action (`warn`, `block`, `ignore`) for one package type |
| the entry       | `profile_entries` | one package, and optionally a constraint that overrides its type's version default                |

Collapsing the third level into the first makes an open set with one pinned package look impossible, and that is the ordinary case: everything tracks except postgres, held at 14 because 15 breaks the config. The same shape runs the other way, one package tracking inside a type that otherwise pins, and an entry carrying `constraint_kind: any` expresses it.

`constraint_kind` holds the four values already on `manifest.VersionEntry`: `exact`, `compatible`, `patch`, `any`. A fifth spelling of the same idea is a defect waiting for the day the two disagree about what `^` matches. Empty is the third level declining to override, which defers to the type's default. An entry with an empty `constraint_kind` still carries a `version`, and a `pinned` default reads it as the version that package is held at; a `floating` default ignores it. That is the shape `bodega profile unpin` leaves behind, which is why it clears the constraint and keeps the version: erasing both under a pinned default would turn a released hold into a total refusal.

**The marker table exists because "no entries for this type" is two different answers**, the same reason `acl_lists` carries one (`008_acl_lists.up.sql`). A type with a marker is decided by the profile even when no entry names a package: closed with nothing listed permits nothing of that type. A type with no marker is one the profile states no rule for, and the fleet-wide controls decide it alone. Without the marker those two collapse, and a profile covering apt would silently deny every helm chart or silently permit every one, with nothing in the table recording which the operator meant.

**Expansion decides a package outside a closed set, and defaults to `warn`** (`015_profile_expansion.up.sql`). Membership says which packages a profile covers; expansion says what happens to a fetch outside that set, and the honest default is not a refusal. A new transitive dependency is ordinary upstream maintenance, and blocking one leaves the host unpatched, so `warn` serves the fetch and records the reach as a `denied` discovery row — the detection half, which works before anyone trusts the enforcement half. `block` refuses; `ignore` serves and records nothing. The values are the `warn`/`block`/`ignore` triple `age_policy` (`004`) and `osv_policy` (`005`) already carry, because a fourth spelling of one idea is a defect waiting for the day two of them disagree. Expansion has no meaning on an open type, which lists nothing to be outside of, and it does not soften a version constraint: an entry's constraint is a version an operator named on purpose.

**One predicate, in `internal/entitle`.** `(*entitle.Profile).Permits(type, name, version)` is the only place the answer is computed, and `Covers(type, name)` is its first two levels, which is what an index generator asks when it has no version in hand. The request path and the index generators are the same two-caller shape that grew two copies of one sequence and drifted before `internal/admit` existed, so the answer lives in one package before the first drift rather than after. Its `Decision` carries `Governed` beside `Permitted`, which separates "permitted because the profile says so" from "permitted because the profile states no rule for this type": the same boolean, different facts, and a caller enforcing profiles needs the second to fall through to the fleet-wide controls. `Refusal` names which rule said no — `membership` or `constraint` — because the operator's repair is opposite in each case, and `Reportable()` is the narrower question of whether a package outside a closed set should be recorded. A package expansion permitted skips the version rule: no entry names a version for a package the profile does not carry, so holding it to the type default would turn `warn` into `block` through the back door. A nil profile is the host nothing binds and permits everything ungoverned, because that is the state every host is in before the first profile is written and a refusal there would make `bodega profile create` a fleet-wide outage.

`exact` and `any` are string comparisons on purpose. An apt version carries an epoch and a Debian revision and a git entry carries a ref, so parsing either as semver to decide equality would refuse versions that are equal. `compatible` and `patch` have no such shortcut and go through `builder.FilterVersions`, which is bodega's one implementation of what `^` and `~` mean; a version neither side can place as semver is refused, naming what it could not compare.

**Building a profile from a host goes through a file.** `bodega profile create <name> --from-origin <host> --out <file>` collects the packages carrying that origin — the field `bodega pkg convert --origin` records — and writes them as a document, creating nothing. `--from-file` creates the profile from the document. The round trip is the control: a host's inventory holds its accidents alongside its requirements, and locking membership to it enshrines whatever was installed by hand at 03:00. `bodega pkg convert` is two commands with an editor between them for the same reason, and stdin and stdout are refused on both halves here, because a baseline piped straight from the command that produced it was never read by anyone. `--out` refuses an existing file for the same reason one step later: after the first run that path holds the operator's edits, and overwriting them silently discards the review while reporting a successful write. `--overwrite` is the way to say it was meant.

Baseline entries default to name-only with `constraint_kind: any`, so the document says what the host may fetch and not which build of it. `--pin <name>` names the exceptions. A baseline that pins every version by default is re-authored monthly until somebody stops, which is how a control becomes ignored; a pin is a claim an operator makes about one package, and `bodega profile pin` requires `--reason` for the same reason. A `--pin` that does not name one package is refused rather than resolved, on either axis: a package the host reports at two versions, because the version meant is the one thing a pin has to get right, and a bare name cataloged under two types, because the baseline is walked in `manifest.AllTypes` order and letting that order decide would hold one package and leave the other floating with the pin counted. `--pin <type>/<name>` is the qualified spelling. One package named twice is refused on the same grounds: the pin count is what an operator checks against the flags they typed, so counting the second spelling hides a slip that could equally have been two versions meant for one entry.

**A pin is a tracked decision, not an unlabeled version string.** `bodega profile pin` requires `--reason` and takes `--review-after <YYYY-MM-DD>`, both stored on the entry, and `pinned_at` (`016_profile_pinned_at.up.sql`) records when the held version was last decided. That column is separate from `created_at` because the two answer different questions: `created_at` is when the package joined the profile, and it does not move when the version does, so a pin moved yesterday under an entry written two years ago would read as two years stale to the report that measures a review date. An unparsable review date is refused at the write, because stored it is a pin that is never overdue and the gate reading it passes forever.

`bodega profile pins` is the report only bodega can print, and it is a stronger argument for profiles than the enforcement is, because it needs no enforcement to be useful. Nothing else in a normal stack holds both halves: `apt-mark hold` knows the hold and not the advisories, a scanner knows the advisories and not why you are on that version. The pin comes from `profile_entries` and the advisories from the `vetting.osv.*` stamp `bodega policy osv rescan` keeps current, with the per-advisory scores `005`'s gate records. A pinned version no run has ever answered for reports `unchecked` rather than `clean`: an empty advisory list means nobody looked as often as it means there is nothing to find, and a pin is the one place that distinction decides whether somebody acts. `--stale` narrows to the overdue pins and exits non-zero, the same CI contract `profile check` has, and `GET /api/v1/profiles/{name}/pins` returns the same records for a tool that consumes them. That endpoint is admin-gated with the audit trail and the token list, because a pin report is the list of versions a class of host is deliberately not patching.

**A pin accepts the known vulnerabilities in that version for the life of the pin, and bodega tracks no remediation.** No suppression workflow, no ticket integration, no severity SLA: the reason and the review date are the whole of the suppression concept, and the boundary is deliberate. bodega reports what it knows about what it serves; the tool that owns remediation reads the endpoint.

**A pin is not local, and the closure is reported rather than applied.** Holding postgresql-14 at 14.9 holds everything 14.9 was built against, because a dependency edge names the version the parent needs and pinning the parent does not move it; apt meets that during an upgrade as a widening set held back or a proposal to remove the package. `internal/pins` walks `graph.json` downward from the pinned package — the packages it depends on, not the ones that depend on it — and `bodega profile pin` prints that closure before it writes, naming any member the profile's own rules contradict. The walk reads the graph whole rather than probing by reference, because a node is not spelled one way (`apt/nginx` against `pypi/django@5.2.12`) and an exact-match walk sees one spelling's edges alone. It is not version-blind for that reason: a parent recording a version is matched on the version, and only a parent recording none applies to whatever release you pinned. A catalog holds two releases of one package routinely, and merging their children would report a pin on 4.2.11 as holding 5.2.12's dependencies, which `--strict-closure` would then write as real pins at versions nothing chose. Each member carries its own version to the next hop for the same reason.

**Which release a dependency holds still comes from the relation it was declared with.** `apt-cache depends` enumerates package names and drops every version relation, so the apt discoverer reads `Depends` and `Pre-Depends` out of the control stanza instead: `libpq5 (= 14.9)` writes the child as `apt/libpq5@14.9` and holds a release, while `libssl3 (>= 3.0.0)` is a floor that may move upward whatever the parent is pinned at and stays unversioned. Without it every apt closure member resolved to nothing, the feasibility check could never find a conflict on an apt graph, and `--strict-closure` had nothing to pin to on the type the item was aimed at. `graph.json` accumulates across imports rather than being replaced by each one, which it was not doing: every import path builds a fresh `manifest.Store`, and one that never read the file starts from an empty graph that `SaveGraph` then writes over the top. The edge is written whether or not the package is new, because a dependency already in the catalog is still a dependency, and any earlier edge from that parent to the same package is removed first: the graph dedupes on the exact pair, so a rebuild after the declared version moved would leave both recorded and the walk would answer with whichever was listed first.

**`--strict-closure` never overwrites an entry somebody else gave a reason.** It names each one it left alone and points at `profile pin` for the deliberate move. The refusal matters because the entry it would overwrite is usually the one the conflict line names, which makes it the entry the command is being run to resolve: overwriting takes the version backward across whatever fix the reason records and replaces the reason with a generated string, leaving the word `Updated` as the only trace. An entry the command wrote itself opens with `implied by the` and is refreshed on the next run, which is how the two are told apart without a second column.

The same check runs at apt index generation beside `auditAptEntries`, where it reports and extends nothing. Extending by default is the rejected alternative and it fails in slow motion: each package pinned drags its own dependencies in, so a host stops receiving security updates for a growing set with nobody having decided that it should. `--strict-closure` is the deliberate form, available on the command where the operator has just read the report, and a closure member the graph records no version for is left floating rather than pinned to a release nobody chose.

**Closed with nothing listed and `--expansion block` is refused without `--force`.** It permits nothing of that type, it is reachable from two directions — setting the marker before listing anything, and removing the last entry under it — and it is almost never meant. Both commands refuse and name what the flag does, following the empty `admin_permit_cidr` precedent above. `bodega profile show` reports the state on a profile that reached it with `--force`, because a profile permitting nothing reads exactly like one nobody consults.

**Two commands make a profile falsifiable.** `bodega profile diff <profile> --origin <host>` names what the host has that the profile does not and the reverse; without it a baseline written six months ago and a host that has moved on look identical from the outside. `bodega profile check` is the CI gate and exits non-zero on a violation, the same contract `bodega policy check` has: it asks the predicate whether each entry permits any version the catalog actually carries, so a pin the catalog dropped and a range constraint nothing satisfies are caught as the one defect they are — a control that refuses everything it names. A hidden version counts as absent there, because every handler that builds an answer excludes it; `frozen` does not, because it blocks build, edit and delete and the version still serves. A manifest the store cannot read stops the gate rather than joining the violations, because the two repairs are opposite: a missing package tells an operator to delete the entry, which is the wrong fix for a catalog that is merely unreadable.

**Two enforcement points on the read path, and the order matters.** The request predicate is the control: it runs on every package route for pypi, npm, gomod, cargo, helm, git and binary, answers 403, and writes a denial row whose status is `profile_membership` or `profile_constraint`. A client that already holds a tarball URL fetches it without reading any index, so an implementation that only filtered indexes would enforce nothing. The index filter is what makes the refusal legible to the client's own resolver instead of arriving as an opaque 403 mid-install: the pypi simple root and its per-distribution pages, the npm packument's `versions` map, the gomod `@v/list`, the cargo sparse index and the helm `index.yaml`. git and binary publish no index, so the predicate is the whole story there. The helm index route is the one package route that is not gated: a 403 there fails `helm repo add` itself, and helm prints neither the profile nor a chart name, so the index answers 200 with the refused charts absent and the refusal arrives at the chart pull.

**apt inverts the order, and the inversion is deliberate.** For the seven other types the request predicate is the control and the filter makes a refusal legible. For apt the filtered index is the control and the predicate is the backstop, because refusing an apt fetch at the pool is worse than having no control at all. An apt client decides what to request by reading a `Packages` index, so a `Depends:` chain reaching a denied package takes a 403 after apt has already resolved and begun a transaction: apt aborts the whole run, and every security update in the same invocation goes with it, quietly, in a cron log. The same package absent from the index produces `The following packages have been kept back: <name>` and the rest of the upgrade proceeds. Same policy, same verdict, opposite outcome.

**So a profile that scopes apt is served a codename of its own.** `bodega profile set <profile> apt --membership closed --base <codename>` names the mirrored codename it derives from (`apt_base`, `017_profile_apt_base.up.sql`), and bodega serves `<base>-<profile>`: a filtered view of that base's `Packages`, with a matching `Release` signed by bodega's own key, generated once per index rebuild like any other generated suite. Filtering `Packages` forces a matching `Release`, and `Release` is signed — the rejected alternative was signing per profile on render, which puts a key operation on the hottest cached path and makes `InRelease` uncacheable across hosts. The per-codename `dists/` tree already exists and is already signed once per codename, so the existing machinery carries it. A base gets no filtered codename unless the apt rule both closes membership and sets expansion to `block`, and the two refusals guard one end state from opposite directions. An open set admits every package the archive publishes. A closed set at `warn` or `ignore` permits everything it does not list, which `entitle.Covers` answers `Permitted` for and `filterAptPackages` therefore copies through paragraph by paragraph. Either way the filtered view is the same document under a second name, signed by bodega instead of the archive: it replaces a signature the host already verifies against the distro keyring with one covering identical bytes, and turns the pool's profile gate on, dropping `/apt/pool/` from `public` to `private` for no filtering in return. `warn` stays the fleet default for the seven other types, where the predicate is the control and an unlisted package is served and reported; apt is the only type whose unfiltered outcome costs a signature, so it is the only one where the posture is stated rather than inherited. `checkProfileAptBase` and `validateDoc` refuse the combination at the write on both roads `set` and `--from-file` offer, so an operator meets it as an error naming the repair rather than as a codename that never appears. Two profiles deriving one codename is the collision `set` cannot refuse, because it validates one profile against the config and the other profile is in neither: `security-web` over `noble` and `web` over `noble-security` both give `noble-security-web`. The rebuild serves neither and names both, since serving one of them hands the other's hosts an index filtered for a set they are not in, and their next install takes the mid-transaction 403 this whole shape avoids.

**Membership for apt closes over the source package, not the binary.** Ubuntu renames, splits and transitions binary packages within one stable source as ordinary maintenance, and a set closed on binary names fires on every one of those until somebody sets the type to `ignore` — a control switched off by the noise it makes rather than by a decision. `internal/deb822` reads `Source:` off each paragraph, falling back to `Package:` where Debian omits it and stripping the `expat (2.4.7-1)` form where the source was built at a version the binary does not share. The name closes over the source and the version stays the paragraph's own `Version:`, because the two sides have to compare one version and the pool has only a `.deb` filename: `aptPoolGate` reads the source out of the path — Debian lays the pool out as `pool/<component>/<prefix>/<source>/<binary>_<version>_<arch>.deb` — and has no index in which to resolve a source version. A filter judging the source version instead offers a binNMU's binary and leaves the backstop to refuse it after apt has resolved a transaction, which is the mid-run 403 this whole shape exists to avoid. What it costs is the binNMU itself: source `nginx` at `1.24.0-2ubuntu7.1` ships `nginx-common` at `+b1`, so an exact pin written from either version keeps part of that source's binaries and drops the rest, and apt reports the dependent group as kept back rather than installing half of it. `bodega profile check` prints that at the write, naming the binary and the version it drops; it is not counted as a violation, because the entry resolves and the only repair available today is to widen the constraint to `any`, which deletes the acceptance record the pin is. A pin naming the source version proper needs a capture recording `${source:Version}`, which no catalog holds. The pool's own layout is the one place the path is not the source: `builder.PackageApt` writes bodega-built artifacts under `ve.SourceName`, which every importer fills with the binary name, so a generated-suite artifact whose two names differ is refused under a profile listing sources. That fails closed and stays off the documented road, since `doctor --write-apt-sources` installs the filtered stanza alone.

**Which means the write side has to produce source names, and dpkg reports binaries.** `bodega pkg convert apt` catalogs each binary under its own name with the source parked on the version entry, so a baseline copying the catalog's names lists `nginx-common` where the filter looks up `nginx`, and the operator's own installed set comes back reported as kept back — one `lib*`, `*-common`, `*-core` and `*-dev` at a time, which is the silent partial service that decided against not signing. `--from-origin` writes `SourcePackage` for apt entries, collapsing several binaries of one source onto one entry and naming every collapse in its own output; a capture predating the five-field `dpkg-query` format recorded no source and falls back to the binary name, which is right whenever the two coincide. `bodega profile check` reports the remaining case, an apt entry naming a cataloged binary whose source differs, and resolves an entry naming a source the catalog holds only as binaries. Teaching the filter to match either spelling was the rejected repair: it reinstates the binary-name closure this whole paragraph exists to avoid.

**Kept paragraphs are copied, not re-serialized.** `deb822.ParseSingle` answers with a map, so emitting from it would be a second grammar to get wrong — and it gets it wrong silently, producing an index that still parses with a `Description` that lost its continuation prefix. `deb822.ParseStreamRaw` hands the filter each paragraph's own bytes beside the parsed fields, and the filter writes through what it keeps. `Filename:` needs no rewrite either: it is relative to the archive root and bodega serves the pool at the same offset, which is also what keeps one pool object answering every profile. A paragraph bodega cannot parse is dropped rather than copied, because this document is re-signed under bodega's key and vouching for bytes bodega could not read is worse than a missing package.

**Parsing the upstream index is what this costs, and F6's "an index bodega does not parse is an index bodega cannot get wrong" is what it spends.** That property still holds for a mirrored codename, which is proxied byte for byte. What replaces it for a filtered one is narrower and stated rather than implied: bodega reads the base's `Release`, takes the architectures it both declares and publishes a `main/binary-*/Packages.gz` for, checks each fetched index against the digest that `Release` names, and re-signs the filtered result. The digest check is not a signature — bodega holds no distro keyring — and it catches the failure a mirror produces on its own, a `Packages` body from one sync beside a `Release` from the next. One component, `main`, matching every other generated suite; a base publishing more is named in the log rather than half-served. The fetched documents are cached behind `metadata_ttl`, the same clock the mirrored `dists/` tree is served under, because every profile write signals a reload and an operator writing a baseline writes one entry per package. A filter that keeps nothing fails the same way when the profile lists apt packages at all, because a signed empty `Packages` tells the host its whole installed set stopped existing: closed with nothing listed permits nothing on purpose and serves its empty index, while closed with entries none of which match a paragraph is a misspelled source or an unsatisfiable pin reaching the identical served result. A paragraph that does not parse fails the whole regeneration rather than shortening the index: `ParseStreamRaw` stops where it could not read, so emitting what it had would sign a document missing every stanza after the break, and the kept and dropped counts in the log would read exactly like a correct filter of a shorter archive. The codename is withdrawn instead, which fails `apt update` on the source line the operator installed and names the instance that stopped answering.

**The boundary lives in the client's `sources.list`, and that is a scoping control rather than an authorization one.** `bodega doctor --write-apt-sources` asks the server which codename this host reads and installs the keyring and the stanza; the stanza carries `Signed-By:` naming that keyring, because the unsigned fallback needs `[trusted=yes]` and would discard the reason the filtered index is signed. A host that edits the file reaches the unfiltered mirrored codename, so the filtered index scopes what a correctly configured host is told exists and authorizes nothing on its own. That is why the request predicate still runs at `/apt/pool/` for a profile that scopes apt: it is the backstop for a client that composed a URL without reading an index. `docs/THREAT_MODEL.md` states the limit in full. It closes only when F11's token gates the codename as well.

**No filtered index is stored.** A document filtered for one host class and cached under the shared key would be served to every other class with no error anywhere: the second host gets a document that is valid, parseable and wrong about what it may install. Nothing filtered reaches the cache, so that cannot happen. Every filter runs over the buffered response on the way out, where the pypi href rewrite and the npm tarball rewrite already run, so the cached object stays the document the upstream served and a cache hit filters identically to a miss: one cached object answers every host class correctly, and an operator's profile edit lands within the binding cache TTL rather than at the next upstream refresh. The rejected alternative was a `profiles/<profile>/` prefix on each filtered index's key. It closes the same hazard and charges a private copy of every index per profile plus an upstream fetch to fill each one: measured on one cargo sparse index, three byte-identical objects and three upstream fetches for two profiles and one unidentified request. Under the default posture (closed membership, `warn` expansion) that multiplies index storage and upstream index traffic by the number of profiles in the fleet, for no change in what any client receives. `TestTwoProfilesGetTwoDocumentsFromOneCachedIndex` asserts the cached bytes against the upstream document rather than against a response body, because a body comparison passes whenever the two profiles happen to agree. The helm `index.yaml` is generated into storage by `bodega build` rather than cached from an upstream, and is filtered on the way out like the other four.

**A shared cache is kept out of every response a profile decides.** Storage is one layer; HTTP is the other, and the same document that must not be cached under a shared key must not be stored by an nginx in front either. An artifact route sends `private, max-age=31536000, immutable` where the filename names bytes that never change under it, and a bare `private` where it does not — the client keeps its year, the proxy loses the grant to answer a second host from the first host's copy. Every index route sends `no-cache, no-store, must-revalidate`, which is what the apt index handlers already carry: a filtered index is valid, parseable and wrong about what any other host may install, so it is not merely unshared but unstored. The apt pool sends `public` while the requesting host's profile does not scope apt, and `private` the moment it does. Every host is served the same `.deb` either way — the filtered index decides what a host is told exists, not which bytes it receives — but a shared cache holding a public copy would answer a refused host out of a permitted host's fetch, and the request would never reach the predicate.

`Vary` was the rejected alternative and cannot carry this. A token-identified host varies on `Authorization`, and a host bound by `bodega identity bind cidr` sends no request header at all, so `Vary` would fix one identification mode and leave the other exactly as it was. `public` was also not incidental to the hazard: RFC 9111 section 3.5 stops a shared cache storing a response to a request carrying `Authorization` unless the response carries `public`, so the token path had opted back into the unsafe behavior and the CIDR path was never covered by that clause. git's smart-HTTP route strips the `Cache-Control` git-http-backend emits rather than forwarding it, because that is `public, max-age=31536000` on a loose object from a namespace a profile gates. None of these directives depends on whether a profile is bound: gated on that, a cache filled by an unidentified request would still answer a profiled one. `TestProfileEnforcedRoutesKeepASharedCacheOut` asserts on the header rather than on a second client's body, which passes against any server with no cache in front of it.

The binding table is resolved once and swapped whole behind an atomic pointer on the same TTL as the ACL and identity sets, and `SIGHUP` re-reads it, because the handler chain is built at `Start` and an operator writing `bodega profile add` against a running server has nothing to rebuild it.

`bodega pin` is the host-side half of the same idea and is a different thing: it emits apt preferences for a host to apply, where a profile decides what bodega will answer.

### Response hardening

All HTTP responses include security headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy`, and `Referrer-Policy`. `Strict-Transport-Security` follows the scheme clients use rather than the one this listener answers on: `public_url` when set, otherwise the request, which honors `X-Forwarded-Proto` only from a peer inside `trusted_proxies`. Gating it on the local TLS state instead meant the recommended deployment, a loopback listener behind a terminating proxy, sent HSTS to nobody.

Upstream proxy fetches validate that target URLs use HTTPS and don't resolve to private or loopback addresses, preventing SSRF through manifest-controlled URLs.

### TLS

One option: a cert/key pair in `tls_cert` and `tls_key`. Minimum TLS 1.3.

bodega has no ACME client and does not plan one. `tls_autocert` and `tls_domain` were accepted by the config and the flag set and then refused at startup, which is worse than absent: an operator configured TLS, got a start failure, and had no way to reach the feature the message implied existed. The refusal was right and the offer was not, so the offer is gone. The deployment that prompted the question runs behind a firewall whose 443 is allowlisted, and `autocert` validates over TLS-ALPN-01 on 443 or HTTP-01 on a port 80 open to the whole internet, so neither challenge was reachable there anyway. Use `certbot`, or terminate TLS at a proxy in front and set `public_url`.

Both halves of the retirement report rather than vanish, and neither is silent. `Save` preserves keys it did not parse, so a config file that still carries `tls_autocert: true` goes on looking like a setting in force until startup says otherwise. `--tls-autocert` and `--tls-domain` stay registered hidden and deprecated for the same reason in reverse: unregistered they gave an upgraded unit file `unknown flag: --tls-autocert` and exit 1, and under `Restart=always` that is a crash loop whose only output names the flag and nothing to set instead. Hidden keeps them off `--help`, so nothing is offered; `MarkDeprecated` prints one line at parse time, and `reportRetiredTLSKeys` prints the same next step the config key gets. Nothing reads the values — only whether they were given.

### Manifest integrity

Every manifest JSON file has a companion `.md5` file. On load, the MD5 is verified. On save, it's recomputed. This catches accidental corruption and makes S3 sync conflicts visible.

## Audit trail

The trail has two halves that look alike and are not, and only one of them is pluggable.

The **event stream** is append-only: written on the hot path, read for reporting, never read to make a decision. It is `EventSink`, two methods (`Record`, `RecordDiscovery`), selected by `audit_sink` from a closed set of four — `sqlite` (the default), `postgres`, `syslog`, `jsonl`. **Operational state** — ACL lists, API tokens, cached checksums, the age, OSV and upstream policies — stays in the embedded SQLite database at `audit_db` under every sink. The request path reads it to decide whether an address is permitted, whether a Bearer token is live and whether an upstream is allowed; those reads need a transactional read-modify-write and a queryable store, so a sink that can only append cannot hold them, and a remote one would put a network round trip inside every request bodega serves.

`*audit.DB` is that embedded store and also the front door to the sink. Reads either delegate to a sink implementing `EventReader` or refuse with an `UnqueryableSinkError` naming the configured sink. They never fall back to the local tables: answering from a store the events are no longer going to is the lie this split exists to avoid. `internal/audit/conformance_test.go` holds all four sinks to one contract, B9'"'"'s eight-writers case included, the way `internal/storage/conformance_test.go` does for the object stores.

**One sink, not a list.** Teeing a write-only sink alongside `sqlite` would keep `bodega discover promote` working while events reached the SIEM, and would also keep the write rate the operator switched away from, plus a second write per event on the hot path. `postgres` is the answer for "queryable at fleet rates"; choosing `syslog` or `jsonl` is choosing to give up the queries, and bodega refuses those reads by name rather than half-answering.

**Postgres reuses none of the ten SQLite migrations.** `internal/audit/migrations_postgres/` is one file holding `events` and `upstream_discovery`, because a sink implements two tables and the other eight files describe operational state that never moves. The `decision` CHECK is copied verbatim so a sink swap cannot widen what the discovery table accepts, and the write-only sinks enforce the same set in code, having no constraint to lean on. The two migration sets are versioned independently, each with its own downgrade guardrail. An operator switching an existing install to `postgres` keeps the SQLite file — it still holds the ACLs and tokens — and its historical events stay there, invisible to a query answered by postgres. Nothing copies them across; see `docs/USAGE.md`.

Under `sqlite`, a SQLite database (WAL mode) records:

- **fetch events**: Which client IP downloaded which package, when, and how long it took
- **build events**: Pipeline stage completions
- **mutation events**: Entry creates and deletes
- **cache events**: Proxy cache misses and upstream fetch results, including checksum verification outcomes
- **denial events**: Every request the server refused, one `denied` row per refusal with the gate that refused it in `status` — a deny-listed IP, any of the five mutation-auth gates, an admin-only read, a `DELETE` on a frozen entry, or a version outside its constraint. No credential is recorded; an invalid Bearer is identified by a 12-character prefix of its peppered hash
- **lifecycle events**: `serve_start` and `serve_stop`, so a reader can tell "nobody was turned away" from "the server was not running"

Queryable via `bodega audit` with filters for event type, package type, client IP, and time range.

**Refusal rows are written on a detached context.** `net/http` cancels the request context when the client closes the connection, and `ExecContext` refuses an insert on a cancelled one — so a caller that fires and hangs up got its 403 and left no row, which made the rows least reliable exactly where they matter most. `recordDenial` and the `policy_violation` write derive from `context.WithoutCancel` with a 10s bound, as `recordLifecycle` already did. So does the allow-list verdict itself: on a cold rule cache it is a database read, and run on the request context a hang-up made it fail, answered 500 and returned above the deny branch — losing the 403 and the row together, for the fire-and-forget callers the row is there to name.

**`audit_events` and `timezone` reach both handles**, the CLI's and the one `bodega serve` opens for itself. They did not always: only the CLI applied them, so the key limited nothing the server wrote and the display timezone never reached `GET /api/v1/audit`.

**Concurrency.** `database/sql` pools connections, so several writers through one handle are several SQLite connections contending for the write lock. The DSN carries `busy_timeout=5000`, which makes the loser wait rather than take `SQLITE_BUSY` and lose its row. Serializing with `SetMaxOpenConns(1)` would also work and is not used: it takes the concurrent reads WAL exists to allow, so a dashboard query would queue behind every write. On an M1 Ultra with an internal NVMe SSD, eight concurrent writers sustain ~2,600 inserts/sec through one handle.

**Discovery counts requests, not cache misses.** The row is written on the hit path as well as the miss path, so `request_count` ranks by demand and `last_client` names the last host to ask. Three of the five branches that serve the cached object count: the fresh hit, the stale copy served because no upstream is configured, and the stale copy served because upstream resolution failed. The other two sit below the allow-list gate, which already recorded that request, so writing there too would count one client fetch twice: a stale copy served after a failed fetch, and the cached copy served when the proxy spool is at `spool_max_total_bytes` and refuses to fetch (that one writes a `denied` row instead, and [Large artifacts and the spool directory](USAGE.md#large-artifacts-and-the-spool-directory) covers the refusal). Recording misses alone made both columns describe the cache: three requests for one artifact produced one row with count 1. `decision` still means "what the allow-list says about this candidate" rather than "what happened to this request" — a hit contacts no upstream, and recording the current verdict is what keeps it on the same row as the miss that filled the cache. The cost on the serving path is one policy verdict (a read-through cache, 30s TTL) plus a send on the recorder's buffered channel: ~10 µs per served request on an M1 Ultra, against ~113 µs for the request itself.

**The allow-list verdict runs before the URL it will log.** `proxyOrResolve` takes the decision, then resolves, then writes the discovery row with whatever the resolver produced. The two halves were one call until a pypi wheel needed a resolver that is itself a fetch of `<pypi_upstream>/simple/{dist}/`: a verdict waiting on the URL had already put the denied distribution's name on the wire, which is a refusal that leaks the thing it refused. Every other type composes its URL offline, which is why the old ordering held for as long as it did. `upstreamPolicyGate` is the refusal half — verdict, 403, `policy_violation` row — and `recordUpstreamAttempt` is the row the permitted path writes afterward. A resolution that fails still writes one, so a wheel the index does not list is visible in discovery instead of 404ing without a trace.

**The drain writes in batches.** The worker accumulates up to 128 observations or 50 ms, whichever comes first, and hands the batch to the sink as one write. Serially it was one write latency per row, which capped the drain at about 2,700 rows/s on `sqlite` and about 900/s on `postgres` (where each upsert costs a network round trip) however wide the pool underneath was. The queryable sinks merge the rows sharing an upsert key before writing: postgres refuses an `ON CONFLICT DO UPDATE` that would touch one row twice in one statement, and a live request stream repeats keys constantly. The merged row carries how many observations it stands for and the upsert adds that to the stored count, so the counts come out where they would have serially. The write-only sinks still emit one record per observation, having no key to collapse on. Whatever the worker is holding when the server stops is written before it returns.

**Discovery losses are counted in two places.** `DiscoveryRecorder` drops on a full queue and counts that as `dropped`; a batch the sink rejects counts every observation the sink did not take as `failed` and logs at Error, naming the batch size and how much of it landed. Backpressure and a broken database are different problems, so the summary log names them apart, and a sink that takes part of a batch is charged only for the part it refused. A `policy_violation` event that fails to write does not change the refusal: the request is still denied, and the lost event is logged at Error with its fields so it can be reconstructed.

## Configuration

One JSON file, named by `$BODEGA_CONFIG_FILE` when that is set and otherwise the first of `/etc/bodega/config.json` and `~/.config/bodega/config.json` that **exists** — falling back, when neither does, to the system path as root and the user path as anyone else. Existence decides, never writability: `Load`, `Save` and `EnsureConfigFile` share the one answer, so an edit lands in the file the process reads rather than in a second copy beside it. Priority: CLI flags > environment variables > config file > defaults.

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
| `allow_plaintext` | false | Authorizes an unencrypted listener. With no cert pair `bodega serve` refuses to bind without it, and refuses on `:443` naming the port |
| `audit_db` | {log_dir}/audit.db | Embedded store: the event stream under `audit_sink: sqlite`, and the ACLs, tokens, checksums and policies under every sink |
| `audit_sink` | sqlite | Where the event stream goes: `sqlite`, `postgres`, `syslog` or `jsonl`. An unknown value is refused at load |
| `audit_sink_dsn` | (none) | Destination for the sink: a libpq string, a syslog `scheme://address`, or an absolute JSONL path. Refused with `sqlite` rather than ignored |
| `git_upstreams` | {} | Namespaces under `/git/` mapped onto an upstream forge, each in `open` or `catalog` mode |
| `binary_upstreams` | {} | Namespaces under `/binaries/` mapped onto an upstream download host, each in `open` or `catalog` mode. While empty, `/binaries/` serves from storage as before |

The TUI config editor (`C` key in `bodega shell`) writes to the same file, and reports the path `Save` returned rather than a second guess at it.

**A save edits the file; it does not replace it.** `Load` keeps the bytes it read, so `Save` rewrites only the keys whose value now differs from what `Load` resolved. Everything else survives as the operator wrote it: every `_comment_` block carrying the guidance bodega ships, and any key written by a release newer than the binary doing the save.

Marshalling the resolved `Config` over the file instead was destructive twice over. It deleted the comments, one of which is the only place an operator is told that `"mode": "open"` on a public forge lets any client make bodega fetch arbitrary upstream repositories. And it recorded every flag and built-in default as though the operator had typed it, so `bodega --manifest-dir /tmp/x shell` plus one save pinned `/tmp/x`, `log_dir`, `audit_db`, `metadata_ttl` and `apt_codename` permanently, past the reach of any later change to those defaults. A `Config` built in code rather than by `Load` carries no such file and is still written whole.

### The empty repository

A repository with no packages is legal. `bodega serve` starts, `/healthz` answers 200, and `dists/<suite>/Release` carries `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 0 main/binary-amd64/Packages`, the SHA-256 of the empty string. That is the correct answer on a fresh install with nothing imported yet, and it lets `apt update` succeed before the first package lands.

A broken install produces the same bytes: a `manifest_dir` nothing can read lists zero packages, which is indistinguishable from a repository that holds none. `bodega serve` separates the two before it opens a socket. An absent root is created; one that cannot be created, opened, or is a file rather than a directory refuses the start, naming the path and the config file it came from.

Creating the absent case is what keeps first boot working, and it is also the hole in the separation: a `manifest_dir` that is merely wrong (a typo under a writable parent) is created empty and publishes the identical `e3b0c442…` digest. On a host that already holds packages under the intended root that is the angus failure with a different first cause: the unit reaches `active (running)`, `/healthz` answers 200, and apt clients are told the packages were withdrawn. Nothing at startup can tell that root from a fresh install's, because on disk they are the same empty directory. What separates them is the `no packages loaded` Error, which names the root it read at `log_level` 0: an operator who knows the packages exist reads the path in that line and sees it is not the one they meant.

### Git upstreams

`git_upstreams` maps a namespace under `/git/` onto an upstream forge, because one flat key cannot express two forges at once and a corporate GitLab and github.com are the same protocol under different trust:

```json
"git_upstreams": {
  "internal": { "url": "https://git.corp.example/", "mode": "open" },
  "github":   { "url": "https://github.com/",       "mode": "catalog" }
}
```

The key becomes a URL segment and a directory name, so it matches `^[a-zA-Z][a-zA-Z0-9_-]*$` and may not take a name bodega already serves or stores under (`api`, `apt`, `repos`, `pool` and the rest). The reserved check folds the key to lower case first: on a case-insensitive filesystem `Repos/` and the `repos/` bundle root are one directory, and on Linux they are two an operator still reads as shadowing.

The URL must be `https`, name a host, and end in `/`. It may not carry userinfo, a query string, a fragment, or a path that is not already in cleaned form. Userinfo because the no-credential property below is otherwise unenforced and the token would land in every `upstream_url` column, log line and error message that carries the composed URL; a query or fragment because the request path is appended and would land after the `?` or the `#`, which surfaces as a 502 with nothing pointing at the config; a `..` because it escapes the intended root, which is the check the request half already gets. A malformed entry stops the load and the error names the namespace; nothing is silently corrected to a default.

Mode decides what happens when a client asks for something no manifest entry names:

- `catalog`, the default when mode is absent or empty, resolves only paths an existing manifest entry covers. Everything else gets a 404 and a `no_manifest` discovery row to promote later. This is the posture for a public forge.
- `open` composes the upstream URL for any path under the namespace and fetches it. On a public forge that means any client which can reach bodega can make bodega fetch arbitrary upstream repositories. Pick it for a forge whose publishing is already controlled, and read that sentence before you do.

A request under `/git/` naming a namespace no entry covers gets a 404 and a `no_namespace` discovery row, which is how an operator finds the key they have not added yet.

Repointing a namespace's URL — a forge migration, a host swap, a typo correction — re-clones every repository already mirrored under it. Each mirror records the URL its first clone used, and bodega compares that against the configured upstream on the way in: a mismatch is treated as a first clone, with the old directory removed and both URLs named in a `WARN`. Serving the old forge's history from a namespace an operator has repointed is the alternative, and it is silent.

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
