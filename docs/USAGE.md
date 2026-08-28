# bodega Usage Guide

Comprehensive documentation for the bodega package repository manager.

## Table of Contents

- [Commands](#commands)
- [Global Flags](#global-flags)
- [Configuration](#configuration)
- [Manifest Structure](#manifest-structure)
- [Pipeline](#pipeline)
- [HTTP Server](#http-server)
- [REST API](#rest-api)
- [Supply Chain Management](#supply-chain-management)
- [Proxy/Cache](#proxycache)
- [Checksum Verification](#checksum-verification)
- [Audit Trail](#audit-trail)
- [TUI](#tui)
- [Web Dashboard](#web-dashboard)
- [Manifest Integrity](#manifest-integrity)
- [S3 Layout](#s3-layout)
- [Development](#development)

---

## Commands

### `bodega init`

Creates the S3 bucket with server-side encryption (AES-256), versioning enabled, and all public access blocked. Idempotent. Only needed when `storage_backend` is `"s3"`. Local storage requires no initialization.

### `bodega build fetch [TYPE...] [NAME]`

Downloads raw sources without building or packaging. If no types are given, all types are fetched in dependency order: `binary → git → apt → pypi → gomod → helm → npm`.

When a name is given after the type, only that entry is fetched.

```bash
bodega build fetch                 # fetch all types
bodega build fetch git             # fetch git sources only
bodega build fetch git netbox      # fetch only netbox
```

### `bodega build run [TYPE...] [NAME]`

Compiles or prepares sources. Auto-fetches if sources are not already present (stage cascading). Types without a build step (binary, gomod, helm, npm) are skipped for the build phase.

```bash
bodega build run                   # build all types
bodega build run apt               # build apt sources only
bodega build run apt python3
```

### `bodega build sync [TYPE...]`

Pushes whatever local artifacts exist to S3 **without** running any pipeline stages. Useful when artifacts were built on a different machine.

```bash
bodega build sync                  # push all local artifacts
bodega build sync pypi helm        # push pypi and helm only
```

### `bodega build upload [TYPE...] [NAME]`

Runs the full pipeline (fetch → build) then uploads artifacts to S3. This is the most common command for end-to-end operation.

```bash
bodega build upload                # fetch, build, and upload all types
bodega build upload git            # fetch, build, and upload git only
bodega build upload git netbox
```

### `bodega build status [TYPE...]`

Probes each manifest entry against the backend its version entry records, and prints a table showing whether each artifact is present. Every configured backend is reachable, `local` and `s3` alike, and the `BACKEND` column names the one each row was probed on.

A backend that fails to answer marks its own rows `ERROR`, prints the failure under them, and exits non-zero; rows belonging to backends that did answer still print. That is the opposite of the package indexes, deliberately: an index fails the whole request because a short index is indistinguishable from packages having been withdrawn, while a diagnostic exists to say which backend is broken.

`bodega status` is a different command — the repository dashboard.

```bash
bodega build status                # check all types
bodega build status apt pypi       # check apt and pypi only
```

### `bodega pkg verify`

Checks that every `.md5` companion file matches its manifest. Use this to detect out-of-band modifications.

### `bodega pkg refresh [TYPE] [NAME] [--force]`

Discovers available versions from upstream registries for entries with `version_constraint: "any"` or `version_constraint: "compatible"`. Creates manifest records for new versions without fetching them.

For proxy-mode entries, versions are served on demand when a client requests them.

```bash
bodega pkg refresh                     # refresh all entries
bodega pkg refresh pypi                # refresh all pypi packages
bodega pkg refresh pypi django         # refresh only django
bodega pkg refresh --force             # re-discover even if versions exist
```

### `bodega repair [check]`

Detects and fixes inconsistencies in the manifest store:

1. **Index consistency**: packages in the index must have manifest files
2. **Dependency linking**: git entries with fetched sources should have their dependencies discovered and linked
3. **Artifact sizes**: backfill ArtifactSize from local files
4. **Manifest sync**: all manifests are re-saved to the backend (S3)
5. **Graph rebuild**: dependency edges are rebuilt from RequiredBy fields

```bash
bodega repair                          # detect and fix
bodega repair check                    # detect only, no changes
```

### `bodega repair keys [--dry-run] [--delete-source] [--type TYPE]`

Moves artifacts sitting at an object key no current code path reads to the key the uploader and the server now agree on. Each object is copied, verified at its destination, and only then is the source considered — the ordering `bodega pkg move` uses, for the same reason: a backend answers a missing object with "not found" rather than an error, so an artifact lost mid-repair would look exactly like one that was never uploaded.

Source and destination are the same backend. Nothing in the manifest changes, because the key is derived rather than recorded, and re-running after an interruption is safe.

One superseded layout exists. Go modules were uploaded under the filesystem-safe name (`gomod/github.com--aws--aws-sdk-go-v2/@v/...`) while a Go client asks for the module path with its slashes intact, so **no module uploaded before this release could be served**. Any install that ever uploaded a gomod artifact has data at the old key and needs one run of this command.

```bash
bodega repair keys --dry-run                  # report, write nothing
bodega repair keys                            # copy and verify; leave the old copies
bodega repair keys --type gomod --delete-source
```

### `bodega show repo [TYPE] [PACKAGE] [VERSION]`

Display what clients can install from this repository. Hidden packages and versions are excluded (client view).

```bash
bodega show repo                   # all types with counts
bodega show repo git               # packages in git type
bodega show repo git netbox        # versions of netbox
bodega show repo git netbox v4.5.7 # version details
bodega show repo git json          # JSON output
```

### `bodega show pkg [TYPE] [PACKAGE] [VERSION|all]`

Display full package configuration including hidden versions, frozen flags, build environment, and raw JSON (admin view).

```bash
bodega show pkg                       # all types with counts
bodega show pkg pypi                  # all pypi packages
bodega show pkg pypi django           # django versions
bodega show pkg pypi django all       # verbose with build_env
bodega show pkg pypi django 5.2.12    # specific version detail
bodega show pkg pypi django json      # JSON output
```

### `bodega pkg hide TYPE NAME [VERSION]`

Toggle the hidden flag on a package or version. Hidden packages are not served to clients but remain in the manifest for record-keeping.

When VERSION is given, only that specific version is toggled. Without VERSION, all versions of the package are toggled.

```bash
bodega pkg hide apt libssl3                # hide all versions
bodega pkg hide apt libssl3 3.0.0-ubuntu2  # hide specific version
bodega pkg hide apt libssl3                # unhide (toggle)
```

### `bodega pkg freeze TYPE NAME [VERSION]`

Toggle the `frozen` flag on a package or version. Frozen entries cannot be built, edited, or deleted. Running `freeze` on a frozen entry unfreezes it.

```bash
bodega pkg freeze git netbox       # freeze
bodega pkg freeze git netbox       # unfreeze (toggle)
```

### `bodega pkg create <type> [name]`

Adds a new entry to a manifest interactively. The name can be given as a positional argument or prompted. All other fields (URL, version, etc.) are prompted.

For automation, use `bodega pkg import` with a JSON manifest file instead.

```bash
bodega pkg create git netbox                  # prompts for url and ref
bodega pkg create apt python3                 # prompts for apt-specific fields
bodega pkg create gomod github.com/aws/aws-sdk-go-v2   # prompts for version
bodega pkg create apt                         # fully interactive (prompts for name too)
bodega pkg create git netbox --storage archive   # pin this package's writes
```

`--storage` sets `storage_policy` on the new package and is never prompted for. Almost every package answers it "whatever the type rule says", and `bodega pkg edit` opens the whole manifest, so the field is reachable interactively without a ninth question in an already-long form. An unknown backend name is rejected before the first prompt, and a name on an `apt`, `git` or `pypi` entry warns that the write path will not consult it.

### `bodega pkg delete <type> <name> [--remove-from-s3]`

Removes an entry from the manifest. Pass `--remove-from-s3` to also delete the artifacts first. Frozen entries cannot be deleted.

Every version is removed, each from the backend its own entry records, and each key is checked with a `Head` before the delete so the output distinguishes "removed" from "was already gone". An entry no key resolves for (pypi, or an apt entry with no recorded pool path) fails the command with the manifest entry intact: the entry is the only record of which bytes to clean up, so dropping it after a delete that looked nowhere would orphan them.

### `bodega pkg remove <type> <name>`

Removes an entry's artifacts from the object store without touching the manifest. Resolution, per-version backends and the no-key refusal are the same as `pkg delete --remove-from-s3`.

### `bodega pkg import <file> [file...]`

Imports package manifests from JSON files. Use `-` to read from stdin. This is the preferred method for automation and CI/CD pipelines.

```bash
bodega pkg import nginx.json                       # import from file
bodega pkg import packages/*.json                  # import multiple files
cat manifest.json | bodega pkg import -            # import from stdin
bodega pkg import --merge updated.json             # add versions to existing package
```

The JSON format is the same `PackageManifest` used internally:

```json
{
  "name": "nginx",
  "type": "helm",
  "versions": [
    {
      "version": "4.11.0",
      "url": "https://kubernetes.github.io/ingress-nginx/charts/ingress-nginx-4.11.0.tgz"
    }
  ]
}
```

Without `--merge`, importing a package that already exists is an error. With `--merge`, new versions are added to the existing package.

### `bodega pkg export [type] [name]`

Exports package manifests as JSON to stdout. Useful for backups, migrations, and inspecting manifest state.

```bash
bodega pkg export                          # all packages, all types
bodega pkg export apt                      # all apt packages
bodega pkg export apt python3              # single package
bodega pkg export apt python3 > python3.json   # save to file
```

A single package is output as a JSON object. Multiple packages are output as a JSON array.

### `bodega pkg storage <type> <name>`

Resolves the placement hierarchy for one package and names the level that decided it.

```bash
$ bodega pkg storage binary awscli-v2
binary/awscli-v2 -> bulk     (package policy)
$ bodega pkg storage apt nginx
apt/nginx  -> bulk     (type rule: storage_by_type.apt)
$ bodega pkg storage git netbox
git/netbox -> default  (global default; no type or package rule)
```

`apt`, `git` and `pypi` upload a whole directory at a time, so the package level is never consulted for them. A `storage_policy` on one of their packages is reported as skipped rather than as the level that won:

```bash
$ bodega pkg storage git netbox
git/netbox -> default  (global default; no type or package rule; storage_policy "bulk" is not consulted for git)
  warning: storage_policy "bulk" has no effect for git: git uploads whole directories with SyncDir, so one package cannot be placed apart from the rest of its type. Set storage_by_type.git to place the whole type; 'bodega pkg move' refuses git for the same reason.
```

An operator reads this command to find out why a package landed where it did, so a level the write path will not use is worse than no level at all.

This is the write side. It says where the _next_ version goes and nothing about where versions already uploaded live; each of those records its own backend in `storage`.

### `bodega pkg move <type> <name>[@<version>] --to <backend>`

Copies the objects backing a package's versions to another named backend and repoints the manifest at the copy.

```bash
bodega pkg move binary awscli-v2 --to bulk
bodega pkg move npm @bitwarden/cli@2026.4.0 --to archive
bodega pkg move gomod github.com/aws/aws-sdk-go-v2@v1.30.0 --to archive --delete-source
```

Movable types: `binary`, `npm`, `cargo`, `gomod`, `helm`. See [Whole-directory types are not movable](#whole-directory-types-are-not-movable) for the other three.

Order is the design:

1. Resolve the source from the recorded `storage`, refusing a version already on the destination.
2. Refuse the whole command if any selected version is frozen, mirroring `pkg delete`.
3. Copy each object through a temp file under `build_root`, never through RAM: a bundle can be larger than the host has.
4. Verify at the destination with `Head` against `artifact_size`, and stream the bytes back to check `checksum` when one is recorded.
5. Write the manifest.
6. Only then consider the source.

Deletion is behind `--delete-source` and defaults to off. A delete that fails prints a warning and leaves the manifest pointing at the copy: a stranded object costs space, while a manifest rolled back after the bytes were removed costs the artifact. Both backends answer a missing object with "not found" rather than an error, so an artifact lost mid-move is indistinguishable from one that was never uploaded.

Without a version, every version of the package moves; versions already on the destination are skipped, so an interrupted move can be re-run.

Two backend names resolving to one directory or bucket is refused before anything is copied:

```text
binary/awscli-v2: backends "default" and "mirror" are the same location (file:///mnt/bulk/bodega) — every object would be copied onto itself, and --delete-source would then remove the only copy. Name a different --to, or drop the duplicate entry from storage_backends
```

Two names for one place is a documented way to stage a migration, and `Load` rejects a colliding name but not a colliding path. Each object would be read and written at the same key, the verify would re-read what it had just overwritten and pass, and `--delete-source` would then remove the artifact the manifest points at. Both backends answer a missing object with "not found", so nothing afterwards could tell it had ever existed.

#### Whole-directory types are not movable

`apt`, `git` and `pypi` upload with `SyncDir`: one local directory to one key prefix, with no per-version granularity at either end. Moving one package of those types splits a tree that nothing can reunite — `git` and `apt` are served with no listing to fan out over, and `pypi` has no per-version object key at all — and `bodega build sync` then refuses for the whole type. All three are refused:

```text
git is not movable: git uploads whole directories with SyncDir, so one package cannot be placed apart from the rest of its type; repoint storage_by_type.git and re-upload instead
```

Point `storage_by_type.<type>` at the backend you want and re-upload. Per-package placement for these three types needs per-package upload, which does not exist yet ([#87](https://github.com/ravinald/bodega/issues/87)).

### `bodega serve [flags]`

Starts the HTTP(S) package server.

| Flag | Default | Purpose |
|------|---------|---------|
| `--addr` | `:8080` | TCP address to listen on |
| `--tls-cert` | | Path to TLS certificate PEM file |
| `--tls-key` | | Path to TLS private key PEM file |
| `--tls-autocert` | `false` | Enable automatic TLS via Let's Encrypt |
| `--tls-domain` | | Domain name for autocert |

The server handles graceful shutdown on SIGTERM/SIGINT, giving in-flight requests up to 30 seconds to complete.

### `bodega shell`

Launches the interactive TUI. See [TUI](#tui) section for keybindings.

### `bodega audit events [flags]`

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
bodega audit events                                    # last 20 events
bodega audit events --type fetch --limit 50            # last 50 fetches
bodega audit events --pkg-type gomod --since 2026-04-07
bodega audit events --client 10.0.0.5
```

### `bodega pkg checksum list [--type TYPE] [--name NAME]`

Lists cached SHA-256 checksums stored in the audit database.

### `bodega pkg checksum clear <type> <name> [--version VER]`

Clears cached checksums for a package. The next fetch will recompute and store a fresh checksum. Use `--version` to clear only a specific version.

### `bodega token generate <label> [expiry <duration|date|never>] [comment]`

Generates a cryptographically random API token. The raw token is displayed once and cannot be retrieved later. A SHA-256 hash (with a server-side pepper) is stored in the audit database.

```bash
bodega token generate ci-pipeline                        # expires in 365 days (default)
bodega token generate ci-pipeline expiry 90d             # expires in 90 days
bodega token generate ci-pipeline expiry 2027-06-01      # expires on a specific date
bodega token generate ci-pipeline expiry never            # no expiry
bodega token generate ci-pipeline "Jenkins deploy key"    # with a comment
bodega token generate ci-pipeline expiry 90d "CI token"   # expiry + comment
```

On first run, a pepper file is auto-generated at `/etc/bodega/pepper` (or `~/.config/bodega/pepper`) with `0600` permissions. This pepper is combined with the token before hashing, so the stored hash alone cannot be used to forge tokens.

### `bodega token list`

Lists all API tokens with their ID, label, creation date, expiry, last use, and comment. Expired tokens are marked.

### `bodega token revoke <id|label>`

Revokes a token by its short ID or label, removing it from the database.

### `bodega policy list [--type TYPE]`

Lists configured upstream allow-list rules. Without `--type`, shows every rule grouped by registry type.

### `bodega policy add <type> <pattern> [comment]`

Adds an allow-list rule. The rule kind is determined by type:

| Type | Kind | Pattern example |
|------|------|-----------------|
| apt | host | `archive.ubuntu.com` |
| git | org (prefix) | `github.com/netbox-community/` |
| pypi | package | `django` |
| npm | package | `lodash` or `@aws-sdk/*` |
| gomod | prefix | `github.com/aws/` |
| helm | prefix | `https://kubernetes.github.io/ingress-nginx/` |
| binary | prefix | `https://releases.hashicorp.com/` |

```bash
bodega policy add pypi django
bodega policy add git github.com/netbox-community/ "NetBox maintainers"
bodega policy add npm @aws-sdk/*
```

An empty allow-list means enforcement is off for that registry type — everything is accepted. Add at least one rule to switch it on. PyPI names are normalized per PEP 503 (lowercased, `_` and `-` unified).

### `bodega policy remove <id|pattern> [--type TYPE]`

Removes a rule. Tries by ID first; falls back to deleting by pattern, scoped to `--type` when provided.

### `bodega policy check`

Walks every manifest in the store and reports any entry whose upstream URL or package name would be rejected by the current policy. Exits with code 1 on any violation — suitable for CI.

### `bodega --break-glass-update-md5 <type>`

Recomputes the MD5 digest for a manifest that was edited outside of the tool.

---

## Global Flags

| Flag | Env Var | Default | Purpose |
|------|---------|---------|---------|
| `--bucket` | `REPO_BUCKET` | | S3 bucket name |
| `--region` | `AWS_REGION` | `us-west-2` | AWS region |
| `--build-root` | `BOOTSTRAP_BUILD_ROOT` | `/opt/bodega` | Local build directory |
| `--manifest-dir` | `BODEGA_MANIFEST_DIR` | `{storage_path}/manifests` | Path to manifests/ directory |
| `--local-config` | | `false` | Use local filesystem instead of S3 for manifests |
| `-v, --verbose` | | `false` | Verbose output (equivalent to `--log-level 2`) |
| `--log-level` | `BODEGA_LOG_LEVEL` | `0` | Logging verbosity: 0=errors, 1=warn, 2=info, 3=debug, 4=trace |
| `-V, --version` | | | Print version and exit |

---

## Configuration

### Which file is the config

Exactly one file is in force. The same rule answers for reading, writing, creating and reporting, so an edit lands in the file the process reads:

1. `$BODEGA_CONFIG_FILE`, when set: that exact path, whether or not it exists. Pointing the override at a scratch path means the generated default is written there too, and nothing touches `/etc` or `~/.config`.
2. The first of `/etc/bodega/config.json` and `~/.config/bodega/config.json` that **exists**. Existence decides, not readability and not whether it parses. A file you can see is the file you will edit; one bodega cannot read is an error it reports, never a reason to read a different file.
3. Neither exists: the system path when running as root, the user path otherwise.

There is no writability probe. A config bodega cannot write fails loudly, naming the path, rather than quietly writing a second copy somewhere `Load` will not read it:

```text
Failed to save config: write config /etc/bodega/config.json: permission denied
```

`bodega serve` prints the file it read in every startup diagnostic (`config=…`), and the TUI's save confirmation names the file `Save` wrote, not a guess at it.

### Unreadable or unparsable

Both are fatal. Falling back to built-in defaults means `tls_cert`/`tls_key` empty, so a server that served TLS yesterday binds plaintext today, and `deny_list` empty, so nothing is denied. The error names the file and, where the JSON decoder can say it, the key:

```console
$ bodega show repo
Error: parse config /etc/bodega/config.json: key "audit_events": cannot use string as []string
```

That one is the common typo: a single-value list written as a bare string. Write `["upload"]`.

A default config is created on first run. All fields are optional.

```json
{
  "storage_backend": "local",
  "storage_path": "/var/lib/bodega/data",
  "storage_backends": {
    "bulk": { "driver": "local", "path": "/mnt/bulk/bodega" },
    "archive": {
      "driver": "s3",
      "bucket": "bodega-archive",
      "region": "us-east-1",
      "prefix": "cold/"
    }
  },
  "storage_by_type": { "pypi": "bulk" },
  "bucket": "my-bodega-bucket",
  "region": "us-west-2",
  "build_root": "/opt/bodega",
  "manifest_dir": "",
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
  "listen_addr": ":8080",
  "proxy_cache_enabled": false,
  "metadata_ttl": "1h",
  "gomod_upstream": "https://proxy.golang.org",
  "npm_upstream": "https://registry.npmjs.org",
  "apt_codename": "noble",
  "apt_suites": ["noble"],
  "audit_db": "",
  "timezone": "",
  "audit_events": [],
  "deny_list": [],
  "admin_permit_cidr": ["127.0.0.0/8", "::1/128"]
}
```

`apt_codename` is the default suite for apt manifest entries that name no `suites`; `apt_suites` is the full set served under `/apt/dists/`, and `apt_codename` is always included in it whether listed or not. A suite name containing `/` is rejected at load.

`timezone` sets the display timezone for audit queries (default UTC) and `audit_events` limits which event types are recorded (empty records all).

Config files are written with mode `0600` (owner read/write only).

**Resolution priority:** CLI flags > environment variables > config file > built-in defaults. Every flag in the table above is registered with an empty default so it cannot shadow the env var and config key beneath it; `--log-level` is the one exception, where `0` is both a valid level and the zero value, so bodega asks whether the flag was typed rather than reading its value.

`manifest_dir` is where manifests live on the `local` backend. The built-in is `{storage_path}/manifests` and is always absolute: a relative path resolves against the process working directory, which under a systemd unit with no `WorkingDirectory=` is `/`. When the binary runs from a source tree with a `manifests/` directory beside it, that directory wins instead: a development convenience, never reached on an installed host.

A server that loads zero packages says so at `ERROR`, naming the directory it read, because from the outside an empty repository is indistinguishable from a healthy one: the unit reaches `active (running)`, `/healthz` answers 200, and `dists/<suite>/Release` lists `e3b0c44298fc…` (the SHA-256 of the empty string) for `Packages`.

```text
ERROR no packages loaded — every repository index will publish as empty
  manifests=/var/lib/bodega/manifests config=/etc/bodega/config.json
```

### Storage backends

bodega supports two storage backends:

- **`local`** (default): Stores artifacts on the local filesystem. Set `storage_path` to change the root directory (default: `/var/lib/bodega`). No initialization needed, and no bucket: every command that touches storage runs without one.
- **`s3`**: Stores artifacts in an S3 bucket. Set `bucket` and `region`, then run `bodega init` to create the bucket with encryption and versioning.

Manifests follow the backend. On `s3` they live under the `manifests/` prefix in the bucket; on `local` they live in `manifest_dir` on disk, which is also what `--local-config` selects against any backend.

A backend that fails to construct is not fatal for `bodega serve`. The server starts, `/healthz` and the `/api/v1/` routes answer, and every package route returns 503 naming no driver — the driver in the config is rarely the thing that broke. The reason is logged once at `ERROR` on startup, so it prints at the default `log_level` of 0:

```text
ERROR storage backend unavailable — package routes will answer 503; the API and /healthz still serve
  backend=local config=/etc/bodega/config.json error=create storage root /dev/null/nope: mkdir /dev/null: not a directory
```

### Named backends and per-type placement

`storage_backend`, `storage_path`, `bucket` and `region` describe one backend, whose reserved name is `default`. `storage_backends` adds more, by name. `storage_by_type` says which name the _next_ write of each package type goes to.

```json
{
  "storage_backends": {
    "bulk": { "driver": "local", "path": "/mnt/bulk/bodega" },
    "archive": {
      "driver": "s3",
      "bucket": "bodega-archive",
      "region": "us-east-1",
      "prefix": "cold/"
    }
  },
  "storage_by_type": { "pypi": "bulk", "binary": "bulk" }
}
```

Per backend: `driver` is required and is one of the same values `storage_backend` takes. `path` is read by `local`; `bucket` and `region` by `s3`; `prefix` roots every key under it, on either driver.

The two namespaces never mix, and `Load` enforces it. `storage_backend` is a **driver**. `storage_backends` keys and `storage_by_type` values are **names**. A name equal to `default` or to a driver is rejected, as is a `storage_by_type` value naming a backend nothing defines:

```text
storage_by_type["apt"] names undefined storage backend "archive" (defined: default, bulk)
```

#### The placement hierarchy

Three levels decide where the next write goes, most specific first:

| Level | Where it lives | Reason |
|-------|----------------|--------|
| Package | `storage_policy` on the package manifest | One package whose bytes must live in a specific bucket, under a specific KMS key, while its type is shared with packages that must not |
| Type | `storage_by_type.<type>` in the config | A whole ecosystem on a separate volume |
| Global | `storage_backend`/`storage_path`/`bucket`/`region` | Everything else |

The most specific rule wins. A package policy that lost to a type rule would be a trap: it is set precisely for the package that must not go where the rest of its type goes, and adding a type rule later would silently move it.

`bodega pkg storage <type> <name>` prints the resolved backend and which level decided it. Naming the winning level is what makes a three-level hierarchy debuggable — `bulk` on its own does not say whether a package policy took effect or a forgotten type rule did.

`apt`, `pypi` and `git` upload whole directories with `SyncDir`, so the package level is not consulted for them: honoring it for some packages of the type and not others would split the tree across backends with no listing to reunite it. There is no per-package placement for these three — `bodega pkg move` refuses them for the same reason, and setting `storage_policy` on one warns rather than taking effect. Set `storage_by_type.<type>` to place the whole type.

#### `storage_policy` and `storage` are different fields on purpose

`PackageManifest.storage_policy` is future tense: put new versions here. `VersionEntry.storage` is past tense: this version's bytes are here. Setting a policy moves nothing; `bodega pkg move` does that. One name for both would mislead every future reader of a manifest.

`bodega pkg create --storage`, `bodega pkg edit` and `bodega pkg import` all record a `storage_policy` on a whole-directory type and warn that it will not be read. The field is recorded rather than rejected so that an existing manifest stays importable and the value survives a round trip through `pkg edit`.

#### Placement is recorded, not recomputed

Each version records the backend it was written to, in `storage` on its manifest entry. Reads use that recorded name and never the config. Change a rule and everything already uploaded stays exactly where it is and stays readable; only the next write moves.

An entry with no `storage` key is on `default`. That is not "resolve it now" — it is the answer, and it is the correct one for every artifact uploaded before named backends existed.

A name no backend answers to is an error rather than a search of the others. Serving bytes from a second backend under a digest recorded against the first is indistinguishable from tampering, which is what the checksum machinery exists to catch.

#### Changing a rule

`upload` and `sync` honor a name a version already records. Change `storage_by_type` and they keep writing where the manifest says, so two runs either side of the change cannot produce divergent copies.

`--replace-placement` is the deliberate move. It applies the current rule to versions already placed elsewhere, repoints the manifest, and warns for every object it leaves behind — nothing copies the old bytes. `bodega pkg move` is the one that copies.

`apt`, `pypi` and `git` upload whole directories with no per-version granularity, so a changed rule refuses outright rather than splitting a tree across backends:

```text
storage_by_type["apt"] now resolves to "bulk", but 2 apt version(s) are recorded elsewhere:
  nginx@1.24.0 (on "default")
  redis@7.2.4 (on "default")
apt uploads whole directories, so proceeding would split the tree across backends with no listing to reunite it.
Pass --replace-placement to repoint the manifest at "bulk" and re-upload; the old copies stay where they are and nothing copies them
```

`--replace-placement` is the only remedy offered, because `bodega pkg move` refuses these three types. It repoints the manifest and copies nothing, so the objects in the previous backend stay there and must be removed by hand once the re-upload has landed.

#### What is not placed

Generated indexes, proxy-cache entries and attestation blobs have no version to record a name against. They follow the type rule at both read and write, which is safe because every one of them is regenerable.

#### Listing and diagnostics disagree on purpose

The PEP 503 indexes and the apt pool listing union every backend and fail the whole request with 502 if any one of them errors. A short index is indistinguishable from packages having been withdrawn, and apt acts on the difference.

`/api/v1/status` does the opposite: one row per backend, the failing one carrying its error, `healthy: false`. A diagnostic exists to say which backend is broken. `bodega build status` and the `bodega status` dashboard follow the same policy — the dashboard's `By Backend` table exists because one volume filling up is invisible in a combined byte count.

#### Object size

S3 uploads go through the multipart uploader, so an artifact larger than 5 GB reaches an S3 backend. The part size is 16 MiB against S3's 10,000-part cap, which puts the ceiling at 160 GiB.

### Per-type build roots

When `custom_paths` is `true`, each type can use a separate build directory. This is useful when types have different storage requirements (e.g., wheels on a large volume, binaries on fast SSD).

### Audit database

The audit DB path defaults to `{log_dir}/audit.db`. The database is created automatically on first use.

---

## Manifest Structure

Each package is stored as a JSON file at `{manifest_dir}/{type}/{safeName}/manifest.json` on the `local` backend, or `s3://{bucket}/manifests/{type}/{safeName}/manifest.json` on `s3`, with a `PackageManifest` wrapper:

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

### Package-level fields

| Field | Type | Purpose |
|-------|------|---------|
| `name` | string | Canonical package name |
| `type` | string | Package ecosystem |
| `description` | string | Short human-readable summary |
| `dep_policy` | string | `none`, `direct`, or `transitive` |
| `storage_policy` | string | Backend this package's _next_ version is written to, overriding `storage_by_type`. Absent means the type rule decides; see [the placement hierarchy](#the-placement-hierarchy) |

### Common fields on VersionEntry

All version entries support:

| Field | Type | Purpose |
|-------|------|---------|
| `version` | string | Version identifier (semver, git ref, chart version, etc.) |
| `url` | string | Download, repository, or registry URL (labeled "Source URL" in UI) |
| `version_constraint` | string | One of: exact, compatible, patch, any |
| `checksum` | object | `{"algorithm": "sha256", "value": "hex..."}` |
| `checksum_verified` | bool | Whether checksum matches upstream publisher |
| `artifact_size` | int64 | Size in bytes (set at fetch time) |
| `hidden` | bool | Excludes from client view but keeps in manifest |
| `frozen` | bool | Prevents building, editing, or deletion |
| `storage` | string | Backend holding this version's bytes. Absent means `default`; see [Named backends](#named-backends-and-per-type-placement) |
| `metadata` | object | Ecosystem-specific key-value pairs |
| `build_env` | object | Build server's environment at artifact creation time |

### Git-specific fields

```json
{
  "version": "v4.5.7",
  "url": "https://github.com/netbox-community/netbox",
  "ref": "v4.5.7",
  "source": "release",
  "checksum": {
    "algorithm": "sha256",
    "value": "abc123..."
  },
  "checksum_verified": true
}
```

- **ref**: git ref (tag, branch, or commit SHA)
- **source**: "release" (download tarball) or "clone" (bare clone + bundle)

### Apt-specific fields

```json
{
  "version": "2.4.2",
  "source_name": "amazon-efs-utils",
  "url": "https://github.com/aws/efs-utils.git",
  "build_cmd": "make deb",
  "deb_glob": "build/*.deb",
  "suites": ["noble", "jammy"]
}
```

- **source_name**: upstream Debian package / source directory name
- **build_cmd**: shell command to produce .deb
- **deb_glob**: path glob to locate produced .deb
- **suites**: apt suites this .deb is published to. Absent means the server's default suite (`apt_codename`). A suite name may not contain `/`. The pool is flat and shared, so one entry listed in two suites is one `.deb` served under both `dists/` trees.

### Binary-specific fields

```json
{
  "version": "2.34.24",
  "url": "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip",
  "filename": "awscli-exe-linux-x86_64.zip",
  "sha256": "abc123..."
}
```

- **filename**: overrides basename derived from URL
- **sha256**: expected hex digest

### Helm-specific fields

```json
{
  "version": "4.11.0",
  "url": "https://kubernetes.github.io/ingress-nginx/charts/ingress-nginx-4.11.0.tgz",
  "app_version": "1.11.0"
}
```

- **app_version**: application version the chart deploys

### Pypi-specific fields

```json
{
  "version": "1.35.0",
  "required_by": ["netbox"]
}
```

- **required_by**: list of packages that depend on this version

---

## Pipeline

The build pipeline has four operations, processed in dependency order:

```
fetch → build → sync → (upload to S3)
```

Actually, the operations are more granular: fetch, build/run, sync, upload.

**Stage cascading:** Each stage automatically runs its prerequisites if outputs are missing. Running `bodega build upload` on a fresh system will cascade through fetch and build stages first.

**Build order:** `binary → git → apt → pypi → gomod → helm → npm`. This order reflects dependencies (e.g., pypi may reference git-cloned repos for its base requirements).

**Per-entry failures** are logged but do not abort the run. A non-zero exit code is returned if any entry failed.

---

## HTTP Server

`bodega serve` starts a package server that clients use directly.

### Client configuration

**APT** (`/etc/apt/sources.list.d/bodega.sources`), against a signed repository:
```
Types: deb
URIs: https://bodega-host:8080/apt/
Suites: noble
Components: main
Signed-By: /etc/apt/keyrings/bodega-archive-keyring.gpg
```

Install the keyring first. The `.gpg` route serves the dearmored form `Signed-By:` takes directly, so the client needs no `gpg` binary:

```bash
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSL https://bodega-host:8080/apt/bodega-archive-keyring.gpg \
  -o /etc/apt/keyrings/bodega-archive-keyring.gpg
```

The deb822 `.sources` form is preferred over the one-line `.list` form because `Signed-By:` there is a path rather than a bracket option, and one stanza can carry several suites. The one-line equivalent is `deb [signed-by=/etc/apt/keyrings/bodega-archive-keyring.gpg] https://bodega-host:8080/apt/ noble main`.

The suite (`noble` above) is any entry in `apt_suites`. One instance serves several: list them on the `Suites:` line, or give each its own sources line in the one-line format. A `.deb` listed in two suites is stored once in the shared `pool/` and appears in both `Packages` indexes with the same `Filename:`.

See [Signing the apt repository](#signing-the-apt-repository) below for creating the key, rotating it, what the signature does and does not prove, and the `[trusted=yes]` fallback for a repository with no key.

**pip** (per-command or `pip.conf`):
```bash
pip install --index-url https://bodega-host:8080/pypi/simple/ <package>
```

**Go modules**:
```bash
export GOPROXY=https://bodega-host:8080/go
go get github.com/aws/aws-sdk-go-v2@v1.30.0
```

**Helm**:
```bash
helm repo add bodega https://bodega-host:8080/helm
```

**npm** (per-command or `.npmrc`):
```bash
npm install --registry https://bodega-host:8080/npm <package>
```

### Signing the apt repository

The server only ever **loads** a key. Generation is a CLI operation, so a compromised server process cannot mint a key clients would then be asked to trust.

The search order, first hit wins:

| Order | Path | Notes |
|-------|------|-------|
| 1 | `$CREDENTIALS_DIRECTORY/apt-signing.key` | systemd `LoadCredential=`; a per-service tmpfs, mode 0400 |
| 2 | `/etc/bodega/apt-signing.key` | packaged location |
| 3 | `<storage_path>/apt-signing.key` | beside the artifacts |

A key file readable beyond its owner is **refused**, not warned about, and the error names the `chmod`. A key that is present and unparsable is logged at `ERROR` and the repository stays unsigned: apt reports nothing in that case, since a missing `InRelease` is indistinguishable from an archive that never had one, so the journal is the only place it can surface.

The key carries **no passphrase**, deliberately. On an unattended service the passphrase has to be readable from somewhere with the same permissions as the key, so it adds a failure mode and protects nothing. File permissions are the boundary.

```bash
bodega apt key generate              # Ed25519, mode 0600, at the first writable path above
bodega apt key generate --rsa        # RSA-4096, for gnupg older than 2.1
bodega apt key show                  # fingerprints, algorithms, UIDs, and the file they came from
bodega apt key export                # armored public key
bodega apt key export --keyring      # dearmored, for /etc/apt/keyrings/
```

`apt_signing_name` and `apt_signing_email` in `config.json` supply the UID; `--name` and `--email` override them. The server must be restarted or sent `SIGHUP` before a new key takes effect.

Signing happens once per snapshot rebuild, not per request. `InRelease` is the clearsigned form of `Release`, and `Release.gpg` is the armored detached signature. The clearsigned body is byte-identical to `Release`, so a verifying client and a `[trusted=yes]` client read the same index. Both use SHA-512: apt's `gpgv` rejects SHA-1 on current releases.

#### Rotation

apt does not refresh keyrings on its own, so replacing a key outright breaks every client that has not updated. Rotate across a transition window instead: both keys sign, both public keys are published, and apt accepts an `InRelease` when any one signature verifies.

```bash
bodega apt key generate --rotate     # the new key joins the old one
systemctl reload bodega              # both now sign
# ... clients re-fetch bodega-archive-keyring.gpg, which now carries both ...
bodega apt key retire <old-fingerprint>
systemctl reload bodega
```

`retire` refuses to remove the last key: a file with no keys loads as an error and takes the repository unsigned, which apt reports as nothing at all.

#### Unsigned fallback

With no signing key installed, `dists/<suite>/InRelease`, `dists/<suite>/Release.gpg` and both keyring routes return 404. apt fetches `InRelease` first and falls back to `Release` on 404, the ordinary path for an archive predating `InRelease`, so `apt update` logs `Ign:` for both and proceeds — but only for a source that does not ask for verification:

```
deb [trusted=yes] https://bodega-host:8080/apt/ noble main
```

`[trusted=yes]` turns off signature verification for this source, permanently and silently, and nothing else re-enables it. It propagates into Ansible templates and cloud-init files, where it outlives whatever made it necessary. Signed and unsigned coexist at the same URLs indefinitely, so a client using it keeps working after a key is installed and can move to `Signed-By:` on its own schedule.

TLS is what authenticates an unsigned source, which is why every URL here is `https://`. `http://` plus `[trusted=yes]` is unauthenticated code delivery to a root-privileged installer.

#### What a signature proves, and what it does not

It seals the last hop: the bytes are the ones **this bodega** asserted, and the hash chain from `Release` to `Packages` to each `.deb` holds under a key the client pinned.

It carries no claim about upstream. `apt-get download` does verify against the distro's own keyring on the build host, but that result is recorded nowhere and does not reach the client; a source-built `.deb` never had an upstream signature at all. For mirrored packages, forwarding the upstream signature unchanged is the better answer and is a separate piece of work.

It does not catch a tampered `.deb` that manifests were not also edited; the client already catches that. `_sha256` is computed once at package time and served from the manifest, never recomputed from disk, so swapping a pooled file fails the client's own hash check whether or not the repository is signed. What signing adds is coverage of an attacker who can write manifests too.

It does not survive a compromised host. The key is loaded into the serving process, so an attacker who owns the process owns the signature.

#### Bootstrap

The first fetch of the keyring over `https://` is authenticated by TLS, and by nothing else. That is a claim about your certificate, not about the key.

To make it a claim about the key, publish the fingerprint somewhere that is not the server — a README in a configuration-management repository, a wiki, an onboarding doc — and check it after fetching:

```bash
bodega apt key show                                                              # on the server
gpg --show-keys --with-fingerprint /etc/apt/keyrings/bodega-archive-keyring.gpg  # on the client
```

Or skip the network entirely: `bodega apt key export --keyring` writes the same bytes to stdout for delivery through whatever channel you already trust with the rest of the host's configuration.

### APT index generation

`dists/<suite>/Release` and the `Packages` bodies under it are generated together into one snapshot and served from memory until the next rebuild. Nothing is written to storage: the only stored part of the apt repository is `pool/`.

They are generated together because `Release` records the SHA256 and byte length of each `Packages` body, and apt fetches the two in separate requests. Regenerating per request lets a write land between them, and the client rejects the result as `Hash Sum mismatch`.

A rebuild happens on:

| Trigger | Notes |
|---------|-------|
| Server start | Before the listener binds, so no request ever sees an empty index |
| `SIGHUP` | After the manifest reload. Every mutating `bodega pkg` verb sends one |
| A mutation-API write to an apt entry | `POST`, `DELETE`, and the hide and freeze toggles |
| A ticker | Hourly once an index exists, every 15 seconds until one does |

**A manifest edited by hand is picked up on the next tick, or at once on `SIGHUP`** (`kill -HUP $(cat <log_dir>/bodega.pid)`). The tick re-reads the manifest index from the backend before rebuilding, so an edit made outside the process reaches the index without a signal; the wait is up to an hour. Every mutating CLI verb signals, so the normal workflow never waits.

The retry interval matters because a snapshot that never built is a 503 on every apt request, and the ordinary way to land there is transient: expired credentials, or a network that was not up when systemd started the unit.

A mutation-API rebuild runs on a background context rather than the request's. The write commits before the rebuild starts, so a client that hangs up in between would otherwise get its change persisted and the index left describing the state before it.

`Release` carries `Date` backdated 24 hours to tolerate client clock skew, and `Valid-Until` 14 days after that. The expiry is stamped when the snapshot is built and does not move on its own, which is why the refresh ticker is not an optimization: a server whose refresh loop stops eventually serves an expired `Release`, and every client fails `apt update` at once — including with `[trusted=yes]`, since `Acquire::Check-Valid-Until` is independent of trust. Within 24 hours of expiry the server logs at `WARN` on every `Release` fetch.

Two cases drop an entry from the index silently, so both are logged at `WARN` once per rebuild:

- The entry names suites, none of which is in `apt_suites`.
- The entry has no `version`. No CLI verb can address a versionless entry, so publishing one hands clients a package nobody can withdraw.

An architecture is served only if some entry published to that suite declares it. `Release` advertises exactly those architectures in `Architectures:`, and `binary-<arch>/Packages` 404s for any other, since `Release` records no digest for it. With no architecture-specific entry at all the suite falls back to `amd64`.

### TLS

Manual certificates (minimum TLS 1.3):
```bash
bodega serve --tls-cert cert.pem --tls-key key.pem
```

Or set in config:
```json
{ "tls_cert": "/etc/bodega/cert.pem", "tls_key": "/etc/bodega/key.pem" }
```

When TLS is active, responses include `Strict-Transport-Security` (HSTS).

### Security headers

All responses include the following headers regardless of TLS:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy: default-src 'self'; ...`
- `Referrer-Policy: strict-origin-when-cross-origin`

### Behind nginx

bodega is designed to work behind nginx. The server extracts real client IPs from `X-Real-IP` and `X-Forwarded-For` headers when the request comes from a trusted private network (RFC 1918 + loopback).

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

All API responses are JSON. The full API is documented in [OpenAPI 3.0 format](../api/openapi.yaml).

### Read endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/packages` | All entries across all types |
| GET | `/api/v1/packages/{type}` | Entries for one type |
| GET | `/api/v1/packages/{type}/{name}` | Single entry details |
| GET | `/api/v1/status` | Health check with entry counts and S3 probe |
| GET | `/api/v1/config` | Non-sensitive config (bucket, region, manifest_dir) |
| GET | `/api/v1/audit` | Query audit events (supports filters) |
| GET | `/healthz` | Health probe (returns `ok`) |

### Mutation endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/packages/{type}` | Create a new entry (JSON body) |
| DELETE | `/api/v1/packages/{type}/{name}` | Delete an entry |
| PATCH | `/api/v1/packages/{type}/{name}/hide` | Toggle hidden (all versions) |
| PATCH | `/api/v1/packages/{type}/{name}/hide/{version}` | Toggle hidden (specific version) |
| PATCH | `/api/v1/packages/{type}/{name}/freeze` | Toggle frozen (all versions) |
| PATCH | `/api/v1/packages/{type}/{name}/freeze/{version}` | Toggle frozen (specific version) |

### Token endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/tokens` | List all tokens |
| POST | `/api/v1/tokens` | Create a new token (JSON body: `{label, expiry, comment}`) |
| DELETE | `/api/v1/tokens/{id}` | Revoke a token |

### Policy endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/policies[?type=TYPE]` | List allow-list rules (optionally scoped to one registry type) |
| POST | `/api/v1/policies` | Add a rule (JSON body: `{registry_type, pattern, comment}`) |
| DELETE | `/api/v1/policies/{id}` | Remove a rule by ID |

Policy mutations invalidate the in-memory cache, so changes take effect on the next request without a restart.

Mutation endpoints are restricted by `admin_permit_cidr`, which defaults to localhost only (`127.0.0.0/8`, `::1/128`). Requests from IPs outside the permit list get a 403.

When `admin_permit_cidr` includes non-localhost addresses, a Bearer token is also required. Generate tokens with `bodega token generate` and pass them in the `Authorization` header.

**Create example (from localhost):**
```bash
curl -X POST http://localhost:8080/api/v1/packages/gomod \
  -H 'Content-Type: application/json' \
  -d '{"name": "github.com/aws/aws-sdk-go-v2", "version": "v1.30.0"}'
```

**Create example (from a remote host):**
```bash
curl -X POST https://bodega-host:8080/api/v1/packages/gomod \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer bodega_ak_7f3a...' \
  -d '{"name": "github.com/aws/aws-sdk-go-v2", "version": "v1.30.0"}'
```

**Response codes:**
- `201 Created` — entry added
- `400 Bad Request` — missing required fields or invalid type
- `401 Unauthorized` — missing or invalid Bearer token
- `403 Forbidden` — IP not in `admin_permit_cidr`, or entry is frozen (delete)
- `409 Conflict` — entry already exists
- `413 Request Entity Too Large` — request body exceeds 1 MiB

---

## Supply Chain Management

When a dependency has a security issue, fails checksum verification, or is otherwise compromised, bodega provides tools to manage it without losing the historical record.

### Upstream allow-list

The allow-list declares which upstream sources bodega is permitted to fetch from, at the granularity that matters for each ecosystem. It's opt-in: add a rule for a registry type and enforcement switches on for that type. Leave it empty and everything is accepted (pre-v0.2.0 behavior).

Enforcement happens in four places, so there's no way around it:

- **Server proxy** (`bodega serve`) — cache-miss fetches check policy before leaving the box. Blocked fetches return 403.
- **Builder** (`bodega build fetch`) — each fetch stage validates entries before any network I/O.
- **Create API + import** (`POST /api/v1/packages/...`, `bodega pkg import`) — manifests referencing blocked upstreams are rejected at creation time. Fail early, not at first fetch.
- **Interactive create** (`bodega pkg create`) — warns the operator and asks y/N to proceed. The only path that allows override, and the override writes a `policy_override` audit event.

Every mutation (`policy add`, `policy remove`) and every violation (fetch, import, server) writes an event to the audit trail with `pkg_type="policy"` or `status="policy_violation"`.

```bash
# Turn on enforcement for git by pinning allowed orgs
bodega policy add git github.com/netbox-community/
bodega policy add git github.com/aws/

# Scope pypi to a curated list
bodega policy add pypi django
bodega policy add pypi requests

# Audit existing manifests for any violations
bodega policy check
```

The allow-list is stored in SQLite (`upstream_policies` table in the audit DB) and is hot-mutable — server changes are picked up within 30 seconds, and policy mutations invalidate the cache immediately.

### Scenario: Bad version of libssl3

A vulnerability is discovered in `libssl3` version `3.0.0-ubuntu1`:

```bash
# 1. Hide the bad version from clients (stays in manifest as a record)
bodega pkg hide apt libssl3 3.0.0-ubuntu1

# 2. Fetch again — bodega skips the hidden version
bodega build fetch apt

# 3. Inspect the dependency graph
bodega show repo apt                  # see which packages depend on libssl3
```

The hidden version remains in the manifest. You always know why the package was there, who added it, and when. The dependency graph edges remain intact.

### Scenario: Block all future auto-resolved versions temporarily

If you want to temporarily freeze version auto-discovery for a package:

```bash
# View the current policy entry
bodega show pkg apt libssl3

# Freeze the wildcard policy entry to prevent new version resolution
bodega pkg freeze apt libssl3 "*"

# Later, when safe, unfreeze to allow new versions
bodega pkg freeze apt libssl3 "*"
```

When the policy entry is frozen, `bodega pkg refresh` will not create new version records. When unfrozen, it will again discover versions.

### Scenario: Supply chain audit

Track all the packages and versions in your repository, including hidden ones:

```bash
# Full manifest view (includes hidden, frozen, checksums)
bodega show pkg apt

# Specific package audit trail
bodega show pkg apt libssl3

# Rebuild dependency graph to verify links
bodega repair check
```

---

## Proxy/Cache

When `proxy_cache_enabled` is `true`, the server fetches from upstream on cache miss for gomod, helm, and npm routes.

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
- First `bodega build fetch`: computes SHA-256, stores on the manifest entry
- Subsequent fetches: verifies against stored checksum; fails on mismatch

**Proxy path** (cached entries):
- First proxy fetch: computes SHA-256, stores in audit DB
- Subsequent proxy fetches: verifies against stored; returns **502 Bad Gateway** on mismatch

**Management:**
```bash
bodega pkg checksum list                        # view all cached checksums
bodega pkg checksum list --type gomod           # filter by type
bodega pkg checksum clear gomod github.com/foo  # clear, next fetch recomputes
```

---

## Audit Trail

Every package fetch, build, CRUD mutation, and cache event is recorded in a SQLite database at `{log_dir}/audit.db`.

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
bodega audit events --type fetch --limit 50
bodega audit events --name lodash --since 2026-04-07
bodega audit events --client 10.0.0.5
```

The audit middleware records: timestamp, event type, package type/name/version, client IP, user agent, HTTP status, and request duration.

---

## TUI

`bodega shell` launches a three-pane terminal interface.

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
| `T` | Open token manager |

### Config editor

Press `C` to open the config form. `Ctrl+S` saves, `Ctrl+T` loads defaults, `Ctrl+R` resets. Changes take effect immediately.

---

## Web Dashboard

Access the dashboard at `https://bodega-host:8080/` when the server is running.

**Features:**
- **Live metrics**: package counts by type, total artifact size, version statistics
- **Status view**: per-package build and upload status
- **Copy utilities**: one-click copy for Package URL and Package JSON Config
- **Browser-based browsing**: explore packages by type and version

The dashboard is read-only. Mutations are made via CLI, TUI, or REST API.

---

## Manifest Integrity

Each manifest file has a companion `.md5` file:

```
manifests/
  apt/python3/manifest.json
  apt/python3/manifest.json.md5
  git/netbox/manifest.json
  git/netbox/manifest.json.md5
  ...
```

The tool verifies MD5 on every manifest read and writes a fresh MD5 after every modification. Use `bodega pkg verify` to check integrity, and `bodega --break-glass-update-md5 <type>` to recompute after a manual edit.

---

## Storage Layout

The key layout is the same regardless of backend (local filesystem or S3). Every key is derived in one place, `manifest.ArtifactKeys` and its per-type helpers, which the uploader, every server handler, `bodega build status`, `bodega pkg move` and the delete path all resolve through.

A name containing a slash is encoded to `--` for every type **except gomod**, which keeps its slashes: a Go client requests `GET /<module>/@v/<version>.zip` with the module path verbatim, and nothing on the wire can rewrite it back. So `@bitwarden/cli` stores as `npm/@bitwarden--cli/@bitwarden--cli-2026.4.0.tgz` while `github.com/aws/sdk` stores as `gomod/github.com/aws/sdk/@v/...`.

| Type | S3 prefix | Example key |
|------|-----------|-------------|
| apt | `packages/apt/` | `packages/apt/pool/main/h/hello/hello_2.10-3build1_amd64.deb` |
| git | `repos/` | `repos/netbox/netbox-v4.5.7.bundle` |
| pypi | `pypi/wheels/` | `pypi/wheels/boto3-1.35.0-py3-none-any.whl` |
| binary | `binaries/` | `binaries/awscli-v2/2.34.24/awscli-exe-linux-x86_64.zip` |
| gomod | `gomod/` | `gomod/github.com/aws/sdk/@v/v1.30.0.zip` |
| helm | `charts/` | `charts/ingress-nginx-4.11.0.tgz` |
| npm | `npm/` | `npm/lodash/lodash-4.17.21.tgz` |
| cargo | `cargo/crates/` | `cargo/crates/serde-1.0.200.crate` |
| manifests | `manifests/` | `manifests/apt/python3/manifest.json` |
| index | `index.json` | Fast startup without loading every manifest |
| graph | `graph.json` | Dependency graph with typed edges |
| metrics | `metrics.json` | Dashboard metrics |

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
  s3/                   AWS S3 client (used by storage/s3 adapter)
  server/               HTTP server, proxy/cache, middleware
  storage/              Pluggable object storage (local, S3)
  tui/                  Bubbletea three-pane TUI
schemas/                JSON Schema validation files
docs/                   Public documentation
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
