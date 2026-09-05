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

Every type but `pypi` uploads one object per manifest version, to the backend that version records: a git bundle to `repos/<name>/`, a `.deb` to the pool path its entry carries, a binary to `binaries/<name>/<version>/`. `pypi` wheels have no per-version object key, so they sync as a directory to `pypi/wheels/` on the backend `storage_by_type.pypi` names. A version whose artifact is not on disk is skipped, and so is a type with none.

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
4. **Apt placeholders**: version-less apt entries sitting beside a resolved one are removed
5. **Pypi URLs**: entries recording the retired `pypi.org/packages/<filename>` wheel URL are rewritten to the registry root
6. **Manifest sync**: all manifests are re-saved to the backend (S3)
7. **Graph rebuild**: dependency edges are rebuilt from RequiredBy fields

```bash
bodega repair                          # detect and fix
bodega repair check                    # detect only, no changes
```

Phase 4 is the only way to clear a version-less apt entry. `bodega pkg create apt` in package-name mode stages one before the upstream version is known and fills it once the lookup returns; one left over is addressable by nothing, because `pkg remove`, `pkg delete`, `hide` and `freeze` all name a version. A package whose entries are *all* version-less is reported and left alone — that is a staging record, not a leftover.

Phase 5 corrects what `bodega discover promote --as manifest` wrote while the wheel handler composed `https://pypi.org/packages/<filename>`, a path pypi.org has never served. Nothing reads the field today, so the stored URL breaks no fetch; it is rewritten because promotion never revisits a version it already wrote, and the entry would otherwise carry a URL that 404s for as long as it exists. An entry pointing anywhere else, including an operator's own index, is left untouched. See [Upstream hosts](#upstream-hosts) for how a wheel is resolved now.

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

`--storage` sets `storage_policy` on the new package and is never prompted for. Almost every package answers it "whatever the type rule says", and `bodega pkg edit` opens the whole manifest, so the field is reachable interactively without a ninth question in an already-long form. An unknown backend name is rejected before the first prompt, and a name on a `pypi` entry warns that the write path will not consult it.

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

#### Importing to a remote server

`--server` sends the manifests to a running bodega instead of writing the local manifest store. That is how a host catalogs itself: the package manager runs on the host and bodega usually does not, so the remote path opens no manifest directory, no bucket and no audit database.

```bash
bodega pkg import --server https://bodega.example catalog.json
BODEGA_SERVER=https://bodega.example bodega pkg import catalog.json
```

The server URL resolves through the usual chain: `--server`, then `$BODEGA_SERVER`, then `server_url` in the config file. The bearer token comes from `$BODEGA_TOKEN`, then `token` in the config file, so a token never has to be written to disk on the host being cataloged.

Plaintext `http` is refused. A bearer token on an unencrypted link is readable by anything on the path, so the combination fails rather than warning; `--allow-plaintext` is the deliberate override for a trusted link.

A remote import lands package by package and reports each one. Anything already present, refused by policy, or malformed is named on stderr and the rest still land: one clashing package in a 635-package host catalog must not discard the other 634. The command fails only when nothing landed at all.

### `bodega pkg convert <type> [file|-]`

Converts a package manager's own report of what is installed into bodega manifests, on stdout.

Run it on the host being cataloged. It reads stdin by default, writes JSON to stdout, and touches no manifest store, so the output can be read, diffed and edited before anything reaches bodega. Feed it to `bodega pkg import` when it looks right.

```bash
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\n' | bodega pkg convert apt > catalog.json
apt list --installed | bodega pkg convert apt -o catalog.json
pip list --format=json | bodega pkg convert pypi | bodega pkg import -
```

| Type | Source command |
|------|----------------|
| `apt` | `dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\n'`, or `apt list --installed` |
| `pypi` | `pip list --format=json` |
| `npm` | `npm ls --global --json --depth=0` |
| `gomod` | `go list -m all`, or `go version -m <binary>` |
| `cargo` | `cargo install --list` |
| `helm` | `helm list -o json` |

**`git` and `binary` have no importer.** Nothing on a host records a `git clone` or a downloaded binary, so there is no inventory to read. Catalog those with `bodega pkg create`, or run the server with `discover_mode` set to `"observe"` and promote what clients reach for.

Prefer `dpkg-query` to `apt list --installed`: it is machine readable, it carries the package status, and apt itself warns that its CLI has no stable interface. Both are accepted.

#### What convert does and does not resolve

- **apt** entries carry the name, the version and `source_name`, and no URL. The build pipeline resolves them with `apt-get download`, against the bodega server's own sources.
- **pypi, npm, gomod and cargo** entries carry a name and a version and import as `proxy`. The registry is already known from `pypi_upstream` and its siblings, so nothing else is needed. Flip an entry to `hosted` and run the pipeline to pre-fetch the artifact.
- **helm** entries import with **no URL**. A helm release records the chart it came from (`nginx-18.2.4`) but not the repository, and bodega resolves helm upstreams per version. Fill the URLs in before importing, or resolve them with `helm search repo <chart> -o json`. Guessing a repository would put an unverified URL into a supply-chain catalog.
- **cargo** crates installed from a git or path source are skipped: the registry has no such version to serve.
- **Removed packages are skipped.** `dpkg-query -W` reports a package removed without `--purge` as `deinstall ok config-files`, and it looks installed in every other column. On one Ubuntu 22.04 server that is 139 of 774 rows, mostly superseded kernel images.

Every skip and every gap is reported on stderr, so stdout stays a clean payload that pipes into `pkg import`.

#### Cataloging a host end to end

```bash
# On the host being cataloged. Neither step needs a manifest store here.
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\n' \
  | bodega pkg convert apt > catalog.json

# Read it. This is the review step, and it is the point of the two commands.
$EDITOR catalog.json

# Push it.
BODEGA_TOKEN=bodega_ak_... bodega pkg import --server https://bodega.example catalog.json
```

Re-running later against the same host adds whatever moved on:

```bash
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\n' \
  | bodega pkg convert apt \
  | bodega pkg import --server https://bodega.example --merge -
```

`--merge` never overwrites a recorded version, so an entry someone promoted to `hosted` stays hosted.

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

`pypi` uploads a whole directory at a time, so the package level is never consulted for it. A `storage_policy` on a `pypi` package is reported as skipped rather than as the level that won:

```bash
$ bodega pkg storage pypi boto3
pypi/boto3 -> default  (global default; no type or package rule; storage_policy "bulk" is not consulted for pypi)
  warning: storage_policy "bulk" has no effect for pypi: pypi wheels upload as a directory with no per-version object key, so one package cannot be placed apart from the rest of its type. Set storage_by_type.pypi to place the whole type; 'bodega pkg move' refuses pypi for the same reason.
```

An operator reads this command to find out why a package landed where it did, so a level the write path will not use is worse than no level at all.

This is the write side. It says where the _next_ version goes and nothing about where versions already uploaded live; each of those records its own backend in `storage`.

### `bodega pkg move <type> <name>[@<version>] --to <backend>`

Copies the objects backing a package's versions to another named backend and repoints the manifest at the copy.

```bash
bodega pkg move binary awscli-v2 --to bulk
bodega pkg move npm @bitwarden/cli@2026.4.0 --to archive
bodega pkg move git netbox@v4.5.5 --to bulk
bodega pkg move gomod github.com/aws/aws-sdk-go-v2@v1.30.0 --to archive --delete-source
```

Movable types: `binary`, `npm`, `cargo`, `gomod`, `helm`, `apt`, `git`. See [pypi is not movable](#pypi-is-not-movable) for the one that is not.

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
binary/awscli-v2: backends "default" and "mirror" are the same location (file:///mnt/bulk/bodega) — every object would be copied onto itself, and --delete-source would then remove the only copy. Name a different --to, or point one of the two at another path or bucket
```

Both names are in the message because the configuration is deliberate: two names for one place is a documented way to stage a migration, so the operator needs to know which half to repoint. `Load` rejects a colliding name but not a colliding path, and does not warn about one either — see [Named backends](#named-backends-and-per-type-placement). Each object would be read and written at the same key, the verify would re-read what it had just overwritten and pass, and `--delete-source` would then remove the artifact the manifest points at. Both backends answer a missing object with "not found", so nothing afterwards could tell it had ever existed.

#### pypi is not movable

`pypi` wheels upload as one local directory to one key prefix, and the PEP 503 index is generated from a listing over that whole tree. A package placed on another backend drops out of the index that finds it, so there is no per-version object to move:

```text
pypi is not movable: pypi wheels upload as a directory with no per-version object key, so one package cannot be placed apart from the rest of its type; repoint storage_by_type.pypi and re-upload instead
```

Point `storage_by_type.pypi` at the backend you want and re-upload.

`apt` and `git` were here until their uploaders learned to walk manifest entries. A `.deb` is addressed by the pool path its version entry records, a bundle by its ref, and both routes resolve a read through `storage` on the version entry, so either type moves one package at a time like the rest.

### `bodega serve [flags]`

Starts the HTTP(S) package server.

| Flag | Default | Purpose |
|------|---------|---------|
| `--addr` | `:8080` | TCP address to listen on |
| `--tls-cert` | | Path to TLS certificate PEM file |
| `--tls-key` | | Path to TLS private key PEM file |
| `--allow-plaintext` | `false` | Serve without TLS; required when `tls_cert`/`tls_key` are unset |

The server handles graceful shutdown on SIGTERM/SIGINT, giving in-flight requests up to 30 seconds to complete.

### `bodega shell`

Launches the interactive TUI. See [TUI](#tui) section for keybindings.

### `bodega audit events [flags]`

Queries the configured audit sink. Under `audit_sink: "syslog"` or `"jsonl"` it refuses by name: those sinks ship events out and keep nothing to read back. See [Audit Trail](#audit-trail).

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

### `bodega acl <admin|deny|proxies> <add|remove|list> [cidr]`

Manages the three CIDR access lists. They live in the audit database, not in `config.json`, so a change lands on a running server with no restart: within 30 seconds on its own, or at once on `systemctl reload bodega`.

The list names are the config keys they replace:

| Name      | Config key          | What it holds                              |
| --------- | ------------------- | ------------------------------------------ |
| `admin`   | `admin_permit_cidr` | CIDRs allowed to reach the admin surface  |
| `deny`    | `deny_list`         | CIDRs refused on every route               |
| `proxies` | `trusted_proxies`   | Peers whose forwarded headers are believed |

There are three lists, so the caller has to name one. `bodega acl add 10.0.0.0/8` is refused and prints the three names.

```bash
bodega acl admin add 10.0.0.0/8 --comment "ops jump host"
bodega acl admin remove 10.0.0.0/8
bodega acl deny add 203.0.113.0/24
bodega acl proxies list
```

A bare address is taken as `/32` or `/128`, and an entry is stored masked: `10.0.0.1/8` added is `10.0.0.0/8` listed and removed.

Two changes are refused because they fail silently otherwise. Both take `--force`, and both errors name the next step:

- **An `admin add` that takes the list past localhost while no token exists.** Widening the list is what turns the Bearer requirement on, so the next mutation (including one from localhost that worked a moment earlier) answers 401 with nothing pointing at the cause. Run `bodega token generate <label>` first.
- **An `admin remove` that empties the list.** An empty `admin_permit_cidr` permits nobody: every mutation is refused, and so are the `/api/v1/audit`, `/api/v1/tokens`, `/api/v1/policies` and `/api/v1/config` reads. Nothing could put an entry back over HTTP.

One change warns and proceeds. It needs no `--force`, because one proxy per network is a real deployment and only the operator knows what else is on that network:

- **A `proxies add` that admits an RFC 1918 range while `admin_permit_cidr` is localhost-only.** bodega returns `X-Real-IP` verbatim from any peer in the trusted set, so a host inside the added range reaches the mutation API and the four admin reads by sending `X-Real-IP: 127.0.0.1`, with no token. A permissive trusted set widens the first layer no matter how narrow `admin_permit_cidr` looks. Add the proxy's own address as a `/32` instead.

#### Repairing an unreadable row

`remove` normalizes its argument before matching, which means it refuses an entry the CIDR parser cannot read: `bodega acl admin remove 10.0.0.0/833` answers `"10.0.0.0/833" is not a CIDR or an address`. Such a row can only have been written by a version that copied `admin_permit_cidr` into the table without parsing it first. `--raw` matches the stored text byte for byte and skips the validation:

```bash
bodega acl admin remove --raw 10.0.0.0/833
```

A server holding one skips it, serves the rest of the list, and names the entry and this command in an `ERROR` line at startup. Seeding now parses the config file's list first and refuses to copy one it cannot read, so a fresh install cannot reach this state.

Every add and remove writes an audit row: a `create` or `delete` event with `pkg_type=acl`, the list name, the CIDR and the OS user who ran the command. `bodega audit events` shows the list in its `NAME` column; the CIDR is in the record's version field, which `GET /api/v1/audit` returns and the table view does not.

The first write to a list copies the config file's value in and says so. After that the database owns the list and the file's entry is inert; see **Configuration** below.

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

### `bodega discover ...`

Discovery records what clients reached for that bodega could not serve from its own manifests, so an operator can turn a real installation run into allow-list rules or manifest entries instead of writing them from memory.

The mode is server-side. Set `discover_mode` in config.json and restart:

| Value          | What gets logged                                                            |
| -------------- | --------------------------------------------------------------------------- |
| `""` (default) | nothing; the hook is off                                                    |
| `"observe"`    | every upstream attempt and every pre-fetch miss, with the decision each got |

`discover_mode` decides whether a row is written. It decides nothing else. The allow-list, `catalog` mode on `git_upstreams` and `binary_upstreams`, hidden versions, version constraints, the CIDR access lists and the mutation gate all behave identically at both values, and a request the allow-list rejects gets its 403 either way. `observe` is safe to leave on permanently, and there is no mode that turns enforcement off.

It is also not the way to bootstrap a catalog. Discovery only sees what clients ask for, so a host that has been stable for six months produces nothing, and `catalog` mode 404s a path before any policy check runs — so an empty store stays empty however long you watch it. Read the host's own inventory instead: [`bodega pkg convert`](#bodega-pkg-convert-type-file-) turns `dpkg-query`, `pip list`, `npm ls -g`, `go list -m all`, `cargo install --list` or `helm list` into a manifest set in one run. What discovery is for is the residue: once a catalog exists, `observe` names what the fleet reaches for that the catalog does not cover, including the two types `pkg convert` has no importer for (git and binary).

Each observation is one row keyed by `(type, pattern, package, version, decision)`, with a request count, the last client IP, and the upstream URL bodega fetched or would have fetched. The count is a count of **requests**, not of cache misses: a request the cache answers bumps the same row the fetch that filled it wrote, so `request_count` ranks by demand and `last_client` names the last host to ask.

`decision` describes the allow-list's verdict on the upstream candidate, not what happened to the request. A cache hit contacts no upstream, and it is recorded under the verdict that applies to the candidate now — which is what keeps it on the same row as the miss before it. The `decision` column carries one of:

| Decision       | Meaning                                                                  |
| -------------- | ------------------------------------------------------------------------ |
| `allowed`      | an allow-list rule matched the upstream                                  |
| `denied`       | the allow-list rejected it; the client got a 403                         |
| `no_policy`    | no allow-list rules exist for the type, so nothing was checked           |
| `no_manifest`  | the request named a package with no manifest entry; the client got a 404 |
| `no_namespace` | the request named a namespace no upstream is configured for              |

An audit database written under the retired `discover_mode: "learn"` also holds `would_deny` rows: an upstream the allow-list rejected while learn mode let the fetch proceed. Upgrading relabels them `denied`, merging counts where a `denied` row for the same package already existed. Nothing is deleted, and nothing writes `would_deny` again.

#### What is observed

| Type | Route | Recorded |
|------|-------|----------|
| apt | `/apt/dists/{codename}/...`, `/apt/pool/...` under a mirrored codename | every request. Metadata rows carry `<codename>/<path>` as the package and no version, except by-hash entries, which collapse to `<codename>/by-hash` — the path is a digest naming no package, and left whole it sizes the `PACKAGE` column in `discover show` past the width of the terminal. The digest is still on the row, in the upstream URL; pool rows carry the package name and version parsed from the `.deb` filename, and together they are the dependency closure of what the fleet installed |
| cargo | sparse index, crate download | every request |
| npm | packument, tarball | every request; `no_manifest` on a tarball for an unknown package |
| pypi | simple index, wheel | every request; `no_manifest` on a wheel for an unknown distribution |
| gomod | `/go/...` | every request; `no_manifest` on a module with no entry |
| helm | `/helm/charts/*.tgz` | every request; `no_manifest` on a chart with no entry, with an empty upstream URL (a chart repo is named per version entry, so with no entry there is no URL to record) |
| git | `/git/{namespace}/...` | one row per clone under an `open` namespace, with an empty version. A clone is two requests, an `info/refs` GET and a `git-upload-pack` POST, and both pass the allow-list; only the `info/refs` leg is recorded, so a git count means the same thing as every other type's. `no_manifest` on an uncataloged repository under a `catalog` one; `no_namespace` on a first segment naming no `git_upstreams` entry, with the namespace as both the package and the pattern |
| binary | `/binaries/{namespace}/...` | every request under an `open` namespace; `no_manifest` on an uncataloged path under a `catalog` one; `no_namespace` on a first segment naming no `binary_upstreams` entry, once any entry exists |

#### Gaps

These are not observed yet. A quiet discovery log for one of them means the hook does not reach it, not that no client asked:

- **apt with no `apt_upstreams`**: `/apt/pool/...` reads storage directly with nothing upstream to fetch, so neither a hit nor a miss is recorded. A pool path a manifest entry owns behaves the same way even on a mirroring instance: it is served from storage and never proxied.
- **generated apt suites**: `dists/` for a codename in `apt_suites` is built from bodega's own manifests, so there is no upstream request to observe. Only mirrored codenames produce rows.
- **git bundles**: `/git/{name}/{file}` serves an uploaded bundle or release archive from storage. Nothing upstream, nothing logged.
- **git mirror refreshes**: a smart-HTTP request records one row per request, but the periodic `git remote update` it triggers is not separately logged. The row says a client asked; it does not say whether that request also refreshed the mirror.
- **binary outside a namespace, with `binary_upstreams` empty**: `/binaries/...` reads storage exactly as it did before the block existed, and records nothing — an install that has not opted in. Once any entry exists, a first segment naming no key is not this case: it 404s without touching storage and records a `no_namespace` row, which is in the table above.
- **helm `index.yaml`** and the generated apt indexes: regenerated locally, never fetched.
- **apt pool hits with several archives configured**: a pool path names no archive, so bodega probes on the first miss and remembers the answer for an hour. A cached `.deb` is served without that probe. With one entry in `apt_upstreams` the archive is unambiguous and the hit is recorded; with several and no remembered route, the row is skipped rather than filed under a pattern that is not the host, which would split one archive's traffic across two buckets. The next miss for that path repopulates the route and hits start counting again.

#### `bodega discover list [type]`

One row per `(type, pattern)` bucket, with the total request count and the distinct decisions seen. The `PATTERN` column is what `promote` will write.

#### `bodega discover show <type> <pattern>`

The raw rows behind one bucket: package, version, decision, count, last client, upstream URL.

#### `bodega discover promote <type> <pattern> [comment] [--as policy|manifest]`

`--as policy` (the default) writes an allow-list rule for the pattern, through the same path as `bodega policy add`.

`--as manifest` writes package manifest entries instead, through the same path as `bodega pkg create`. It reads only the `no_manifest` rows in the bucket and, for each one, adds a version entry in `proxy` mode carrying the upstream URL the handler would have fetched.

A pattern whose every row is `no_namespace` is refused by both targets, and the error names the config key to add. Such a row says a client asked for a namespace nothing is configured for: the repair is a key in `git_upstreams` or `binary_upstreams`, and an allow-list rule bounds which upstreams bodega may talk to without giving the namespace one. `promote-all` reports those patterns per line and promotes the rest.

For apt, `--as policy` is the promotion that matters: `bodega discover promote apt archive.ubuntu.com` turns an observe window into the host rule that keeps the mirror reachable once enforcement is on. `--as manifest` also works — an apt pool row carries the package, the version and the upstream `.deb` URL, so it writes a staged entry that `bodega build fetch apt` resolves from that URL and `bodega build run apt` puts in the pool. That is how a package the fleet keeps pulling from upstream becomes one bodega hosts and signs in its own suite. The staged entry carries no architecture and no pool path, so it stays out of the generated index until those two steps run.

A row with no version becomes one entry with `version_constraint: "any"`, but only for `git` and `binary`, whose entries are fetched from the recorded URL as it stands. Every other type composes the version into the fetch path, so an open entry there resolves to a URL that 404s: `go` alone drives one versionless row per module through `/@v/list` and `/@v/@latest`. Those rows are named on stderr and skipped; the versioned rows for the same package are unaffected.

The URL written is the one the manifest field means for the type, which is not always the one `discover show` prints. For gomod and npm the field is a registry root (`https://proxy.golang.org`, `https://registry.npmjs.org`) that the builder appends a module or package path to, so the recorded artifact URL is narrowed to it. Every other type records a URL that already means what the field means.

It never rewrites what is already there. A version already in the manifest is skipped, so a `hosted` entry is never downgraded to `proxy` and re-running the command adds nothing. Rows with an empty upstream URL are named on stderr and skipped: a `proxy` entry with no URL would 404 as the miss it came from did, so those packages need a URL supplied by hand.

#### `bodega discover promote-all <type> [--as policy|manifest]`

The same two targets, applied to every bucket of the type at once. This is the command to run against an `observe` window, once you have a catalog and want to close the gaps in it. It writes as it goes; [`generate-manifests`](#bodega-discover-generate-manifests-type) is the same bulk work with a review step in the middle.

```bash
# 1. Set "discover_mode": "observe" in config.json, restart bodega. Leave it on.
# 2. Let the fleet run against it for as long as you want to sample.
# 3. Read back what it reached for that bodega could not answer.
bodega discover list

TYPE   PATTERN           HOST                COUNT  DECISIONS    LAST SEEN
gomod  github.com/aws/   proxy.golang.org    18     no_manifest  2026-09-01 14:22
npm    lodash            registry.npmjs.org  4      no_policy    2026-09-01 14:21

# 4. Turn the packages into manifest entries, and the patterns into rules.
bodega discover promote-all gomod --as manifest
bodega discover promote-all gomod
```

Nothing here needs enforcement relaxed, so nothing has to be switched back afterwards. The `denied` rows are the report worth reading twice: each one is a package a client wanted and the allow-list refused, which is either a rule to add or a client to fix.

#### `bodega discover generate-manifests [type]`

Reads the `no_manifest` rows and writes the package manifests they describe to stdout, as a JSON array. Nothing reaches the manifest store and no discovery row is touched: this command only reads.

The output is the same shape [`bodega pkg convert`](#bodega-pkg-convert-type-file-) emits, so `bodega pkg import` takes it with no editing in between — the review step is what the format is for, not a conversion step.

| Flag              | Effect                                                                                     |
| ----------------- | ------------------------------------------------------------------------------------------ |
| `--since`         | Only rows last seen within the window (`7d`, `72h`)                                        |
| `--min-requests`  | Only packages with at least this many recorded requests                                    |
| `--skip-existing` | Omit packages the manifest store already holds, which makes a re-run emit only what is new |
| `-o, --output`    | Write the payload to a file instead of stdout                                              |

`--min-requests` is the flag to reach for on a fleet: a discovery table fills with one-off CI probes, and without a signal filter they land in the catalog beside the packages that matter. The count is a request count — cache hits included — so it ranks by demand rather than by how often the cache missed.

Every generated manifest passes the structural checks and the URL allow-list `bodega pkg import` applies, before it is emitted. A package that fails is named on stderr and left out, rather than emitted for the import to reject halfway through a file and leave the store in a state you did not choose. The age and OSV checks are **not** applied here: they record audit events, and this command reads. A package that clears generation can still be refused by the import on one of those. Versions default to `mode: "proxy"`; flip an entry to `hosted` if you want `bodega build fetch` to pre-fetch the artifact.

Identical rows produce identical bytes, so this week's generation diffs cleanly against last week's.

The summary goes to stderr, one line per disposition, and stdout stays a payload a pipe can carry:

```console
$ bodega discover generate-manifests > catalog.json
WARN skipped a versionless observation of (gomod, github.com/aws/aws-sdk-go): gomod composes the version into the fetch URL, so an open entry would 404 — the versioned rows for this package are unaffected

Generated 3 package manifests (4 version entries) to stdout. Nothing was written to the manifest store; review the payload, then 'bodega pkg import' it.
  1 versionless row(s) skipped for a type that needs a version
  1 no_namespace row(s): a request named a namespace no upstream is configured for, which needs a git_upstreams or binary_upstreams entry rather than a manifest
  1 row(s) record a decision other than no_manifest and are not catalog misses
```

##### Cataloging a fleet, end to end

```bash
# 1. Read each host's own inventory. This is the bulk of any catalog and it is
#    complete on the first run — no waiting, no traffic required.
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\n' | bodega pkg convert apt > apt.json
pip list --format=json | bodega pkg convert pypi > pypi.json
bodega pkg import apt.json pypi.json

# 2. Set "discover_mode": "observe" in config.json and restart. Leave it on.
#    It logs; it relaxes nothing.

# 3. Let the fleet run. Discovery accumulates what the catalog could not answer.
bodega discover list

# 4. Generate manifests for the misses, review them, import them.
bodega discover generate-manifests --skip-existing --min-requests 2 > gaps.json
$EDITOR gaps.json
bodega pkg import gaps.json
```

No step in that sequence relaxes enforcement, and nothing has to be switched back afterwards. `observe` decides only whether a row is written; the allow-list, `catalog` mode and every other check behave the same at both values.

Expect rows from **git and binary** above all. Those are the two types [`bodega pkg convert`](#bodega-pkg-convert-type-file-) has no importer for (nothing on a host records a `git clone` or a downloaded binary), so they arrive at bodega uncataloged and every request for one is a miss. The other types produce rows only for what their importer missed: a package installed after the convert run, a host that was never converted, or a version a client asked for and the catalog does not carry. Run this against a type you imported an hour ago and an empty array is the correct answer, not a failure.

Two kinds of row this command cannot use, both counted in the summary. `no_namespace` rows name a first path segment with no `git_upstreams` or `binary_upstreams` entry: the fix is a config key, not a manifest. Rows with an empty `upstream_url` (every `no_manifest` row helm records, for one) carry nothing to fetch, so the entry has to be written by hand with `bodega pkg create`.

#### `bodega discover clear [type]`

Deletes discovery rows for one type, or all of them when the type is omitted.

#### `bodega discover export <json|csv> [type]`

Dumps the raw rows to stdout for offline analysis.

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

Both are fatal. Falling back to built-in defaults means `tls_cert`/`tls_key` empty, so a server that served TLS yesterday now refuses to start rather than answering unencrypted (see [Serving without TLS](#serving-without-tls)), and `deny_list` empty, so nothing is denied. The error names the file and, where the JSON decoder can say it, the key:

```console
$ bodega show repo
Error: parse config /etc/bodega/config.json: key "audit_events": cannot use string as []string
```

That one is the common typo: a single-value list written as a bare string. Write `["upload"]`.

### What a save writes

A save edits the config file rather than replacing it. `Load` keeps the bytes it read, so `Save` — the TUI's `C` editor and its reset-to-defaults — rewrites only the keys whose value differs from what `Load` resolved. Everything else survives as you wrote it, including every `_comment_` block bodega ships and any key written by a newer release than the binary doing the save.

Two consequences worth knowing:

- **A flag is not a setting.** `bodega --manifest-dir /tmp/x shell` followed by a config save leaves `manifest_dir` in the file exactly as it was. The same holds for `--build-root`, `--bucket`, `--region`, `--log-level` and `-v`, and for every built-in default `Load` filled in: `audit_db`, `metadata_ttl` and `apt_codename` stay empty in the file if that is how you left them, so a later release changing one of those defaults still reaches this host.
- **Clearing a field clears the key.** Emptying a TUI field removes its key from the file; it does not leave the previous value behind. Clearing `tls_cert` and `tls_key` removes both, and `bodega serve` then refuses to start unless `allow_plaintext` is set — see [Serving without TLS](#serving-without-tls).

Editing the file by hand is still supported and is what the comments are there for. A save writes every untouched key back byte for byte, blank lines and all, so a save that changed one setting changes one line.

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
  "allow_plaintext": false,
  "listen_addr": ":8080",
  "public_url": "",
  "proxy_cache_enabled": false,
  "metadata_ttl": "1h",
  "gomod_upstream": "https://proxy.golang.org",
  "npm_upstream": "https://registry.npmjs.org",
  "pypi_upstream": "https://pypi.org",
  "cargo_upstream": "https://index.crates.io",
  "cargo_dl_upstream": "https://static.crates.io/crates",
  "discover_mode": "",
  "apt_codename": "noble",
  "apt_suites": ["noble"],
  "audit_db": "",
  "audit_sink": "sqlite",
  "audit_sink_dsn": "",
  "timezone": "",
  "audit_events": [],
  "deny_list": [],
  "admin_permit_cidr": ["127.0.0.0/8", "::1/128"],
  "trusted_proxies": null,
  "tls_min_version": "1.3"
}
```

`deny_list`, `admin_permit_cidr` and `trusted_proxies` are bootstrap values. bodega copies each one into the audit database the first time it starts against a database that does not hold it, logging `acl source list=<name> source=database detail="copied from config file on this start"`. From then on the database decides and the file's entry is inert; a start where the two disagree logs a `WARN` naming both values and the `bodega acl` command that shows the live one. Edit them with `bodega acl`, not with the file.

The copy happens once rather than the file being read as a fallback on every start. A fallback would make `bodega acl admin remove` unable to remove anything the file still named, which is the lockout guard wearing the opposite sign.

`trusted_proxies` keeps its tri-state across the move. The database records "this list is mine" separately from its entries, so an operator's `[]` still means trust nobody and an absent key still means the built-in loopback + RFC 1918 default.

`apt_codename` is the default suite for apt manifest entries that name no `suites`; `apt_suites` is the full set served under `/apt/dists/`, and `apt_codename` is always included in it whether listed or not. A suite name containing `/` is rejected at load.

`apt_upstreams` maps a codename onto the upstream archives that serve it, and mirrors their `dists/` tree instead of generating one. Keys match `^[a-z][a-z0-9-]*$`; each `url` must be `https` with a host and no query or fragment, and a trailing slash is trimmed at load. An empty map is what an install without the key runs, and changes nothing.

```json
"apt_upstreams": {
  "noble":          [{"url": "https://archive.ubuntu.com/ubuntu"}],
  "noble-updates":  [{"url": "https://archive.ubuntu.com/ubuntu"}],
  "noble-security": [{"url": "https://security.ubuntu.com/ubuntu"}],
  "bookworm":       [{"url": "https://deb.debian.org/debian"}]
}
```

**A codename may not appear in both `apt_suites` and `apt_upstreams`, and the load fails naming it.** bodega signs an index it generated and forwards the signature of one it mirrors; one URL serves one `Packages` per component and architecture, so a shared codename would hand a client an `InRelease` whose digests do not describe the index it gets next. Mirror under the upstream's real codename and name the generated suite something local:

```json
"apt_codename": "internal",
"apt_suites": ["internal"],
"apt_upstreams": {"noble": [{"url": "https://archive.ubuntu.com/ubuntu"}]}
```

Both suites are then served by one instance and apt resolves dependencies across the two, which is how a locally built package can depend on a distro one.

`public_url` is the base URL clients reach the server at, and it decides the scheme and host of every client snippet bodega emits: the `bodega serve` startup banner, the TUI details pane, the web UI, and `GET /api/v1/status`. Resolution is `--public-url` > `$BODEGA_PUBLIC_URL` > `public_url`, with no built-in default.

Set it whenever a reverse proxy terminates TLS or publishes a different hostname. bodega then sees a loopback listener with both TLS keys empty, so `tls_cert`/`tls_key` describe the proxy's back end and nothing describes the URL an operator would copy. Deriving the scheme from that pair is what printed `http://` on the sources line of a deployment that is `https://` everywhere a client can see. With `public_url` unset, callers holding a request answer from the request (honoring `X-Forwarded-Proto` from a trusted peer), and callers with none print `<bodega-host>:8080` as a placeholder and say that it is one.

`discover_mode` turns the upstream-observation log on, and does nothing else: enforcement does not move with it. Valid values are `""` (off) and `"observe"`; anything else is rejected at load. `"learn"` was removed and is refused by name, with the error pointing at `observe` and `bodega pkg convert` — it suppressed the allow-list and recorded nothing `observe` does not. See [`bodega discover ...`](#bodega-discover-) for what gets logged and what to do with it.

`audit_sink` chooses where the event stream goes and `audit_sink_dsn` says how to reach it; see [Audit Trail](#audit-trail) for the four values, what each gives up, and what `bodega serve` does when the destination is unreachable. `timezone` sets the display timezone for audit queries (default UTC) and `audit_events` limits which event types are recorded (empty records all). Both apply to the CLI and to `bodega serve` alike — see [Audit Trail](#audit-trail) for what a filter that omits `denied` costs you.

Config files are written with mode `0600` (owner read/write only).

**Resolution priority:** CLI flags > environment variables > config file > built-in defaults. Every flag in the table above is registered with an empty default so it cannot shadow the env var and config key beneath it; `--log-level` is the one exception, where `0` is both a valid level and the zero value, so bodega asks whether the flag was typed rather than reading its value.

`manifest_dir` is where manifests live on the `local` backend. The built-in is `{storage_path}/manifests` and is always absolute: a relative path resolves against the process working directory, which under a systemd unit with no `WorkingDirectory=` is `/`. When the binary runs from a source tree with a `manifests/` directory beside it, that directory wins instead: a development convenience, never reached on an installed host.

Manifests sit inside `storage_path` so that one directory holds the whole repository. Artifacts already lived there; a manifest tree outside it meant `tar` on `storage_path` produced a backup that restored every package's bytes and none of its metadata.

**Upgrading an install created before that default.** `--manifest-dir` used to be registered with a non-empty default, which made `manifest_dir` in the config file unreachable and sent manifests to `./manifests` relative to whatever directory bodega was started from. Check where yours are, then either move them or name them:

```bash
ls /var/lib/bodega/manifests      # {storage_path}/manifests, the new default

# Move them, if they are elsewhere:
sudo mv /old/path/manifests /var/lib/bodega/manifests
sudo chown -R bodega:bodega /var/lib/bodega/manifests

# Or leave them where they are and set the key:
#   "manifest_dir": "/old/path/manifests"
```

An install that skips this step looks healthy from the outside: bodega creates the empty directory and serves an empty repository.

A server that loads zero packages says so at `ERROR`, naming the directory it read, because from the outside an empty repository is indistinguishable from a healthy one: the unit reaches `active (running)`, `/healthz` answers 200, and `dists/<suite>/Release` lists `e3b0c44298fc…` (the SHA-256 of the empty string) for `Packages`.

```text
ERROR no packages loaded — every repository index will publish as empty
  manifests=/var/lib/bodega/manifests config=/etc/bodega/config.json
```

**A root `serve` cannot read stops the start.** On the `local` backend, and under `--local-config` against any backend, `bodega serve` checks `manifest_dir` before it binds anything. A server that publishes an empty `Release` over a root nothing can read is indistinguishable from a healthy one holding no packages, so three states exit 1 instead:

| State | Message |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------- |
| A file where the directory belongs | `Error: manifest_dir /var/lib/bodega/manifests is not a directory (config: /etc/bodega/config.json)` |
| Absent and uncreatable: `/manifests` under `ProtectSystem=strict`, a parent owned by another user | `Error: manifest_dir … does not exist and cannot be created: mkdir /nope: read-only file system (config: …)` |
| Present but unopenable, which is what a root owned by another user does: it stats fine and reads back empty | `Error: manifest_dir … cannot be opened: permission denied (config: …)` |

Each names the path and the config file the path came from, so the next move is `ls -ld` on the one and an edit to the other.

**An absent root that can be created is created, and the start continues.** On a fresh host neither `storage_path` nor its `manifests/` exists yet, and `systemctl enable --now bodega` has to survive that. The empty repository that follows is the legitimate one, and the `no packages loaded` line above is what marks it in the journal. That carve-out is also why a typo in `manifest_dir` under a writable parent is not caught here: it is created, and the `ERROR` line naming the root it read is the only thing that separates it from a fresh install.

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

Two entries resolving to one bucket or directory is neither rejected nor warned about. It is a supported way to stage a migration, and the identity that decides sameness is the backend's resolved label: comparing the configured strings at load would miss a symlink, a trailing slash or a relative path, and fire on a `path` two different drivers happen to share. `bodega pkg move` is the one command the collision can destroy anything through, and it refuses by label before the first copy.

The resolved label is resolved because the `local` driver is made to resolve it, not because a driver was ever guaranteed to. Until [#136](https://github.com/ravinald/bodega/issues/136), `storage_path` reached the label verbatim: a second backend pointing at a symlink of the first root produced two labels for one directory, the refusal did not fire, and `--delete-source` removed the only copy. `local` now resolves its root once at construction with `filepath.Abs` then `filepath.EvalSymlinks`, falling back to the absolute cleaned path for a root it is about to create. `s3://<bucket>` needs nothing: it is already one string per bucket.

#### The placement hierarchy

Three levels decide where the next write goes, most specific first:

| Level | Where it lives | Reason |
|-------|----------------|--------|
| Package | `storage_policy` on the package manifest | One package whose bytes must live in a specific bucket, under a specific KMS key, while its type is shared with packages that must not |
| Type | `storage_by_type.<type>` in the config | A whole ecosystem on a separate volume |
| Global | `storage_backend`/`storage_path`/`bucket`/`region` | Everything else |

The most specific rule wins. A package policy that lost to a type rule would be a trap: it is set precisely for the package that must not go where the rest of its type goes, and adding a type rule later would silently move it.

`bodega pkg storage <type> <name>` prints the resolved backend and which level decided it. Naming the winning level is what makes a three-level hierarchy debuggable — `bulk` on its own does not say whether a package policy took effect or a forgotten type rule did.

`pypi` is the one type the package level is not consulted for. Its wheels upload as one directory to one prefix and the PEP 503 index is a listing over that tree, so honoring a policy for some packages and not others would split it with no listing to reunite it. `bodega pkg move` refuses `pypi` for the same reason, and setting `storage_policy` on a `pypi` package warns rather than taking effect. Set `storage_by_type.pypi` to place the whole type.

#### `storage_policy` and `storage` are different fields on purpose

`PackageManifest.storage_policy` is future tense: put new versions here. `VersionEntry.storage` is past tense: this version's bytes are here. Setting a policy moves nothing; `bodega pkg move` does that. One name for both would mislead every future reader of a manifest.

`bodega pkg create --storage`, `bodega pkg edit` and `bodega pkg import` all record a `storage_policy` on a `pypi` package and warn that it will not be read. The field is recorded rather than rejected so that an existing manifest stays importable and the value survives a round trip through `pkg edit`.

#### Placement is recorded, not recomputed

Each version records the backend it was written to, in `storage` on its manifest entry. Reads use that recorded name and never the config. Change a rule and everything already uploaded stays exactly where it is and stays readable; only the next write moves.

An entry with no `storage` key is on `default`. That is not "resolve it now" — it is the answer, and it is the correct one for every artifact uploaded before named backends existed.

A name no backend answers to is an error rather than a search of the others. Serving bytes from a second backend under a digest recorded against the first is indistinguishable from tampering, which is what the checksum machinery exists to catch.

#### Changing a rule

`upload` and `sync` honor a name a version already records. Change `storage_by_type` and they keep writing where the manifest says, so two runs either side of the change cannot produce divergent copies.

`--replace-placement` is the deliberate move. It applies the current rule to versions already placed elsewhere, repoints the manifest, and warns for every object it leaves behind — nothing copies the old bytes. `bodega pkg move` is the one that copies.

`pypi` uploads a whole directory with no per-version granularity, so a changed rule refuses outright rather than splitting a tree across backends. `apt` and `git` used to refuse here too and no longer do: both resolve one key per version now, and a rule change repoints only what has not been written yet.

```text
storage_by_type["pypi"] now resolves to "bulk", but 2 pypi version(s) are recorded elsewhere:
  boto3@1.35.0 (on "default")
  django@5.0.6 (on "default")
pypi uploads whole directories, so proceeding would split the tree across backends with no listing to reunite it.
Pass --replace-placement to repoint the manifest at "bulk" and re-upload; the old copies stay where they are and nothing copies them
```

`--replace-placement` is the only remedy offered, because `bodega pkg move` refuses `pypi`. It repoints the manifest and copies nothing, so the objects in the previous backend stay there and must be removed by hand once the re-upload has landed. Only `pypi` reaches this path; every other type places per version and never refuses.

#### What is not placed

Generated indexes, proxy-cache entries and attestation blobs have no version to record a name against. They follow the type rule at both read and write, which is safe because every one of them is regenerable.

Every route that does hold a version entry for an uploaded artifact resolves by record: `binary`, `helm`, `npm`, `cargo`, `gomod`, `pypi` and `git` read the recorded name, and the apt pool reads the reverse `pool/` mapping the snapshot carries, because a `.deb` is addressed by path with no package and version in the request to look an entry up by. Nothing serving an uploaded artifact is left on the type rule.

One read holds an entry and stays on the type rule anyway: a package in `proxy` mode is served from cache, and a cache entry is regenerable whatever its manifest records.

#### Attestation envelopes resolve by the bucket in their URI

An attestation envelope is written by an external sync service rather than by bodega, so `storage` on the version entry says where the artifact went and nothing about where the envelope stayed. `pkg move` does not carry it either, so after a move the two are on different backends by construction.

An `s3://<bucket>/<key>` `attestation_uri` is therefore resolved by its own bucket. `handleAttestation` matches `<bucket>` against every configured backend's label — `s3://<bucket>`, or `s3://<bucket>/<prefix>` for a backend rooted at a key prefix, in which case the URI's key must sit under that prefix — and reads from the one that answers. The URI is already in the manifest, so this needs no new field and nothing has to be migrated.

A bucket no configured backend answers to falls back to the type rule and logs a WARN naming the URI. That is the answer every install gave before backends were named, so an envelope in a bucket bodega does not configure keeps whatever chance of resolving it had, and the WARN is where an operator learns which of the two happened. An `http(s)://` URI is still a 302 to the client, and any other scheme is a 502.

#### Listing and diagnostics disagree on purpose

The PEP 503 indexes and the apt pool listing union every backend and fail the whole request with 502 if any one of them errors. A short index is indistinguishable from packages having been withdrawn, and apt acts on the difference.

`/api/v1/status` does the opposite: one row per backend, the failing one carrying its error, `healthy: false`. A diagnostic exists to say which backend is broken. `bodega build status` and the `bodega status` dashboard follow the same policy — the dashboard's `By Backend` table exists because one volume filling up is invisible in a combined byte count.

#### Object size

S3 uploads go through the multipart uploader, so an artifact larger than 5 GB reaches an S3 backend. The part size is 16 MiB against S3's 10,000-part cap, which puts the ceiling at 160 GiB.

### Per-type build roots

When `custom_paths` is `true`, each type can use a separate build directory. This is useful when types have different storage requirements (e.g., wheels on a large volume, binaries on fast SSD).

### Audit database

The audit DB path defaults to `{log_dir}/audit.db`, and its parent directory and the file are created on first use. It holds the served fetches, the mutations, the cache events, every refused request and the server's own start and stop — unless `audit_sink` sends that stream elsewhere, in which case the file still holds the ACLs, the API tokens, the cached checksums and the policy tables. See [Audit Trail](#audit-trail) for the sinks, the event types and what is deliberately left out.

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
| `name` | string | Canonical package name. `/` is written as `--` in the path, so a name always occupies exactly one directory level. `.` and `..` are refused: see [Package names](#package-names) |
| `type` | string | Package ecosystem |
| `description` | string | Short human-readable summary |
| `dep_policy` | string | `none`, `direct`, or `transitive` |
| `storage_policy` | string | Backend this package's _next_ version is written to, overriding `storage_by_type`. Absent means the type rule decides; see [the placement hierarchy](#the-placement-hierarchy) |

#### Package names

A name is stored as one path segment, with `/` written as `--`, so `@bitwarden/cli` becomes `@bitwarden--cli` and no name can add a directory level.

`.` and `..` are refused, by `bodega pkg create`, `bodega pkg import`, `POST /api/v1/packages/{type}` and `POST /api/v1/packages/import` alike:

```text
invalid package name "..": it is path syntax, not a name — ".." resolves to a manifest path outside its own type directory
```

They are the two names the `/` rule does not neutralize, because they are resolved as path syntax rather than stored as text. `apt/../manifest.json` cleans to `manifest.json` at the manifest root, which is also where `npm/../manifest.json` lands, so two packages of different types would share one file and the second write would replace the first. `apt/./manifest.json` lands at `apt/manifest.json`, inside the type directory where no package belongs. Nothing escapes the manifest root in either case ([#160](https://github.com/ravinald/bodega/issues/160)).

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

The stanza above is the shape, not the values. Your instance prints its own on the `bodega serve` startup banner and serves it on `GET /api/v1/status`, filled in from what the running process holds: the suites it answers for, the URL from `public_url`, and `Signed-By:` or the `[trusted=yes]` fallback according to whether a signing key is loaded. Copy that one. The web UI shows the block it read from this endpoint, so it cannot disagree with the server. The TUI renders through the same renderer but supplies the signing state from the key file rather than the process, which is the one axis where the two can differ — see [Details pane](#details-pane).

Install the keyring first. The `.gpg` route serves the dearmored form `Signed-By:` takes directly, so the client needs no `gpg` binary:

```bash
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSL https://bodega-host:8080/apt/bodega-archive-keyring.gpg \
  -o /etc/apt/keyrings/bodega-archive-keyring.gpg
```

The deb822 `.sources` form is preferred over the one-line `.list` form because `Signed-By:` there is a path rather than a bracket option, and one stanza can carry several suites. The one-line equivalent is `deb [signed-by=/etc/apt/keyrings/bodega-archive-keyring.gpg] https://bodega-host:8080/apt/ noble main`.

The suite (`noble` above) is any entry in `apt_suites`. One instance serves several: list them on the `Suites:` line, or give each its own sources line in the one-line format. A `.deb` listed in two suites is stored once in the shared `pool/` and appears in both `Packages` indexes with the same `Filename:`.

A **mirrored** suite is configured differently, because something else signs it:

```
Types: deb
URIs: https://bodega-host:8080/apt/
Suites: noble noble-updates noble-security
Components: main restricted universe multiverse
```

No `Signed-By:`, no `Trusted: yes`. bodega proxies the upstream `dists/` tree unchanged, so the archive's own `InRelease` arrives with its signature intact and apt verifies it against the distro keyring already on the host. Adding `[trusted=yes]` there would replace a working check with none; adding `Signed-By:` would point apt at a key that signed nothing in that tree. See [Mirroring an upstream archive](#mirroring-an-upstream-archive).

See [Signing the apt repository](#signing-the-apt-repository) below for creating the key, rotating it, what the signature does and does not prove, and the `[trusted=yes]` fallback for a repository with no key of its own.

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

**git** (a `git_upstreams` namespace, clone URL ending in `.git`):
```bash
git clone https://bodega-host:8080/git/github/octocat/Hello-World.git
```

See [Git smart-HTTP](#git-smart-http) for what bodega does with that request.

### Git smart-HTTP

`git clone` against bodega speaks the same protocol it speaks against a forge. A `git_upstreams` namespace (see [Git upstreams](DESIGN.md#git-upstreams) for the config shape) maps onto an upstream, and bodega keeps a bare mirror of every repository a client has asked for.

```
GET  /git/{namespace}/{org}/{repo}.git/info/refs?service=git-upload-pack
POST /git/{namespace}/{org}/{repo}.git/git-upload-pack
```

Those two suffixes are the whole served surface. Every other path under a namespace is a 404, including `HEAD` and `objects/info/packs`: bodega does not serve the dumb-HTTP protocol. The clone URL must end in `.git`, which is what a client types anyway.

On the first request bodega runs `git clone --mirror` into `{storage_path}/git/{namespace}/{org}/{repo}.git` and serves from that mirror afterwards. Concurrent first requests for one repository collapse into one clone. A clone that fails takes its directory with it — a partial mirror would answer later requests with a truncated history — and the client gets a 502 that names no path; the git error is in the server log.

What is on disk is inspected rather than counted. `git clone --mirror` creates the destination at the start of the transfer, so a restart, an OOM kill, or a removal that lost to a permission error leaves a directory holding `config`, `description`, `hooks/` and `info/` and nothing else. bodega treats a directory with neither `HEAD` nor its own `.bodega-fetched` stamp as an interrupted clone: it is removed and cloned again on the next request, and both legs of the protocol do it, so the `git-upload-pack` POST that arrives while the `info/refs` clone is still running blocks on the same lock rather than answering 404 with an empty body. A removal that fails is a 502 naming the reason in the log, not a mirror that 404s forever with nothing retrying.

**Repointing `git_upstreams[ns].url` re-clones.** Every mirror records the URL its own clone used, and bodega compares it against the configured upstream before serving. A mismatch is a forge migration, a host swap or a typo correction, so the mirror is discarded and cloned from the new URL, with both URLs in a `WARN`. Budget for the transfer: repointing a namespace with fifty mirrors under it re-clones all fifty, one per first request after the change.

`open` and `catalog` behave here as they do everywhere: a `catalog` namespace never clones a repository no manifest entry names, and answers 404 with a `no_manifest` discovery row instead. `bodega discover promote git <pattern> --as manifest` turns that row into the entry, after which the same clone succeeds. The allow-list runs before the clone, so a denied upstream is a 403 with nothing written to disk.

#### Refresh

A mirror older than `metadata_ttl` (default `1h`, the same interval that governs a cached package index) re-fetches with `git remote update --prune` before answering `info/refs`. The refresh is best effort: a fetch that fails serves the history already on disk rather than failing the clone, and still marks the mirror fetched, so an upstream that has gone away costs one failed fetch per TTL rather than one per request.

`bodega build fetch git` is a separate pipeline that reads git manifests; it does not walk the smart-HTTP mirrors.

#### Pushes

Refused twice. Every mirror bodega creates carries `http.receivepack=false`, and the handler rejects `git-receive-pack` — both the POST and the `info/refs?service=git-receive-pack` probe that precedes it — before any process is started. bodega is a read-only mirror; one layer would mean one config drift makes it writable.

The handler checks every occurrence of the `service` parameter, not the first. `net/url` returns the first value of a repeated key and `git-http-backend` parses `QUERY_STRING` with `string_list_insert`, where the last wins, so `?service=git-upload-pack&service=git-receive-pack` would otherwise read as a fetch here and a push in the child. The child never sees the client's query string at all: `QUERY_STRING` is rebuilt from the one service the handler validated, which leaves the two parsers nothing to disagree over. A `service` naming anything other than `git-upload-pack` is a 403.

#### Operational requirements

- **`git-http-backend` must be installed.** It ships with git, in `libexec` rather than on `PATH`. bodega resolves it once at startup, through `git --exec-path` and then a fixed list of distribution locations.
- **When it is missing**, bodega logs an `ERROR` at startup naming every path it searched, and does not register the smart-HTTP route. `ERROR` because the route is gone: the shipped `log_level` prints nothing below it, so a lower level would announce a disabled feature to nobody. A clone then gets a 404 on `info/refs` and a 405 on `git-upload-pack`. The legacy bundle route keeps working; nothing else about the server changes.
- **The bodega user must own `{storage_path}/git`.** The mirror clone, the periodic refresh and the CGI child all run as the server's user. Do not run bodega as root to work around a permission error on that tree; fix the ownership.
- **Upstreams are public and unauthenticated only.** No credential is read from the config or the environment, and the child process is given neither. A private repository answers bodega as an anonymous client, so the operator sees a failed clone, not an auth prompt.
- **The child process gets an explicit environment**: `GIT_PROJECT_ROOT`, `GIT_HTTP_EXPORT_ALL`, and the CGI variables for the request. No `PATH`, no `HOME`, no inherited `GIT_*`. It is bounded to five minutes and dies with the request.

#### Legacy bundle route

`/git/{name}/{file}` still serves the `.bundle` and `.tar.gz` artifacts an uploader wrote to storage, unchanged. It predates smart-HTTP and stays because scripts fetch those URLs directly.

**A `git_upstreams` key and an uploaded git package may share a name. That is legal and neither shadows the other.** `GET /git/{name}/{file}` is the more specific ServeMux pattern, so it takes every two-segment path under `/git/`; a clone path is at least four, because the repository directory ends in `.git` and carries `info/refs` or `git-upload-pack` after it. The two coexist by depth. With `"tools"` in `git_upstreams` and a `tools` package in the manifest store, `/git/tools/tools-v1.2.0.bundle` serves the uploaded bundle and `/git/tools/org/repo.git/info/refs` resolves the upstream. Nothing rejects the pair at startup: manifest names are runtime data an operator adds and removes without restarting the server, so a startup check would refuse a config that was legal when it was written.

#### Not implemented

Named here so the gap is visible rather than inferred from a failure:

- **Authenticated upstream clones.** No SSH key, no PAT, no credential helper. A private upstream fails.
- **`git://`.** bodega is HTTP(S) only; `git daemon` is not proxied.
- **Repository deletion.** Removing a mirror is `rm -rf {storage_path}/git/{namespace}/{org}/{repo}.git` by hand. There is no `bodega pkg delete` flow for a smart-HTTP mirror.
- **Shallow clones at the upstream layer.** A client may ask bodega for a shallow clone; bodega's own mirror of the upstream is always full.

### Signing the apt repository

The server only ever **loads** a key. Generation is a CLI operation, so a compromised server process cannot mint a key clients would then be asked to trust.

The search order, first hit wins:

| Order | Path | Notes |
|-------|------|-------|
| 1 | `$CREDENTIALS_DIRECTORY/apt-signing.key` | systemd `LoadCredential=`; a per-service tmpfs, mode 0400 |
| 2 | `/etc/bodega/apt-signing.key` | packaged location |
| 3 | `<storage_path>/apt-signing.key` | beside the artifacts |

A key file readable beyond its owner is **refused**, not warned about, and the error names the `chmod`. A key that is present and unusable is logged at `ERROR` and the repository stays unsigned: apt reports nothing in that case, since a missing `InRelease` is indistinguishable from an archive that never had one, so the journal is the only place it can surface.

"Unusable" includes a key the service cannot read. The search stops at the first path that **exists**, not the first it can open, so a root-owned `/etc/bodega/apt-signing.key` left in place while the service runs as `bodega` produces that `ERROR` on every start. To serve unsigned deliberately, move the key aside rather than only removing whatever pointed at it.

The key carries **no passphrase**, deliberately. On an unattended service the passphrase has to be readable from somewhere with the same permissions as the key, so it adds a failure mode and protects nothing. File permissions are the boundary.

```bash
bodega apt key generate              # Ed25519, mode 0600, at the first writable path above
bodega apt key generate --rsa        # RSA-4096, for gnupg older than 2.1
bodega apt key show                  # fingerprints, algorithms, UIDs, and the file they came from
bodega apt key export                # armored public key
bodega apt key export --keyring      # dearmored, for /etc/apt/keyrings/
```

`apt_signing_name` and `apt_signing_email` in `config.json` supply the UID; `--name` and `--email` override them. A new key takes effect on `systemctl reload bodega` (`SIGHUP`), which re-reads the key file, re-renders the served keyring and re-signs the index in one step. The rotation runbook below depends on that.

One asymmetry: a reload never takes signing **away**. If the key has become unreadable or has gone missing, the previously loaded key keeps signing and the fault goes to the journal, because a client configured with `Signed-By:` has no unsigned fallback and would fail `apt update` outright. Going unsigned is a restart.

Signing happens once per snapshot rebuild, not per request. `InRelease` is the clearsigned form of `Release`, and `Release.gpg` is the armored detached signature. The clearsigned body is byte-identical to `Release`, so a verifying client and a `[trusted=yes]` client read the same index. Both use SHA-512: apt's `gpgv` rejects SHA-1 on current releases.

#### Rotation

apt does not refresh keyrings on its own, so replacing a key outright breaks every client that has not updated. Rotate across a transition window instead: both keys sign, and both public keys are published.

```bash
bodega apt key generate --rotate     # the new key joins the old one
systemctl reload bodega              # both now sign
# ... clients re-fetch bodega-archive-keyring.gpg, which now carries both ...
bodega apt key retire <old-fingerprint>
systemctl reload bodega
```

`retire` takes the full 40-character fingerprint or a prefix of at least 16 characters, and refuses a prefix matching more than one key. It also refuses to remove the last key: a file with no keys loads as an error and takes the repository unsigned, which apt reports as nothing at all.

**"apt accepts an `InRelease` when any one signature verifies" holds only up to the first signature whose key the client does not hold.** Re-measured 2026-09-04 against a dual-signed `InRelease`: gpgv 2.4.4 (`ubuntu:24.04`, `2.4.4-2ubuntu17.4`) walks the whole set and reports `GOODSIG` for whichever signature it can check, while gpgv 2.5.22 stops at the first `NO_PUBKEY` and emits no status at all for the second. Both exit 2 on a partial keyring, so the exit code distinguishes nothing; apt reads gpgv's status-fd, and a `GOODSIG` arriving there is what the accept turns on. It is ordering, not algorithm: RSA-4096 and Ed25519 behave the same way in either position.

So signature order decides who the window covers, and bodega signs **oldest key first**: `--rotate` appends, so the incoming key always signs last. That is the correct order, because the window exists for clients that have **not** updated: they hold the outgoing key, reach its signature first, and get a `GOODSIG` on both gpgv versions. Live on 24.04, `apt update` exits 0 against the outgoing key alone, the incoming key alone and the full keyring, and exits 100 against an unrelated key.

The client it does not cover is one holding the incoming key and not the outgoing one, on gpgv 2.5 or later. That client must fetch the **full served keyring**, `/apt/bodega-archive-keyring.gpg`, which carries both keys for as long as the window is open, rather than the incoming key on its own. Delivering a single key out of band during a rotation is the one thing that breaks here. No released apt ships gpgv 2.5 yet (24.04 and Debian 13 are both on 2.4.x), so that half is measured with `gpgv` directly and is a claim about the next LTS rather than a bug reachable today.

#### Unsigned fallback

With no signing key installed, `dists/<suite>/InRelease`, `dists/<suite>/Release.gpg` and both keyring routes return 404. apt fetches `InRelease` first and falls back to `Release` on 404, the ordinary path for an archive predating `InRelease`, so `apt update` logs `Ign:` for both and proceeds — but only for a source that does not ask for verification:

```
deb [trusted=yes] https://bodega-host:8080/apt/ noble main
```

`[trusted=yes]` turns off signature verification for this source, permanently and silently, and nothing else re-enables it. It propagates into Ansible templates and cloud-init files, where it outlives whatever made it necessary. Signed and unsigned coexist at the same URLs indefinitely, so a client using it keeps working after a key is installed and can move to `Signed-By:` on its own schedule.

TLS is what authenticates an unsigned source, which is why every URL here is `https://`. `http://` plus `[trusted=yes]` is unauthenticated code delivery to a root-privileged installer.

#### What a signature proves, and what it does not

It seals the last hop: the bytes are the ones **this bodega** asserted, and the hash chain from `Release` to `Packages` to each `.deb` holds under a key the client pinned.

It carries no claim about upstream. `apt-get download` does verify against the distro's own keyring on the build host, but that result is recorded nowhere and does not reach the client; a source-built `.deb` never had an upstream signature at all. For a mirrored suite the upstream signature is forwarded unchanged instead, which is a stronger claim than bodega could make about the same bytes — see [Mirroring an upstream archive](#mirroring-an-upstream-archive). bodega's key signs generated suites and nothing else.

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

### Mirroring an upstream archive

A codename listed in `apt_upstreams` is served from upstream rather than generated. bodega proxies `dists/<codename>/...` and the pool artifacts the index points at, caching each on the way through. This is what makes `apt update && apt install <anything>` work against bodega for packages nobody pre-built: apt reads the proxied `Packages`, resolves dependencies locally, then asks bodega for each `.deb` by its `Filename:`.

```json
"apt_upstreams": {
  "noble":          [{"url": "https://archive.ubuntu.com/ubuntu"}],
  "noble-updates":  [{"url": "https://archive.ubuntu.com/ubuntu"}],
  "noble-security": [{"url": "https://security.ubuntu.com/ubuntu"}]
}
```

```
Types: deb
URIs: https://bodega-host:8080/apt/
Suites: noble noble-updates noble-security
Components: main restricted universe multiverse
```

bodega parses no index. The upstream `Release` names the components, architectures and `by-hash` digests, apt reads them, and the next request arrives with the path already composed, so any component the upstream publishes resolves, not only `main`.

#### `[trusted=yes]` is not needed, and is wrong here

The upstream `InRelease` is forwarded byte-for-byte, signature intact, and apt verifies it against the distro keyring already installed on the host (`ubuntu-keyring`, `debian-archive-keyring`). Neither `[trusted=yes]` nor `Signed-By:` belongs on a mirrored source: the first discards a signature that is right there and valid, and the second points apt at bodega's key, which signed nothing in that tree. The startup banner, the TUI, the web UI and `GET /api/v1/status` all render a mirrored suite with neither option, and say why beside the line.

#### Open mode only

There is no `catalog` mode for apt, and no per-package allow-list. apt decides what to request by reading a `Packages` index, so the first `Depends:` chain reaching a package nobody cataloged would 404 mid-install — surfacing to the operator as a broken dependency rather than as a policy refusal, at the point where the transaction is already half planned. `git_upstreams` and `binary_upstreams` can offer `catalog` because a client there asks for one artifact it already named.

Constraint for apt is the host-level allow-list:

```bash
bodega policy add apt archive.ubuntu.com
bodega policy add apt security.ubuntu.com
```

With any apt rule present, an archive not on the list is never contacted: the check runs before the fetch and before the pool probe, and the client gets a 403 with the attempt recorded as `denied`. With no apt rule at all, enforcement for the type is off and every configured upstream is reachable, which is the same rule every other type follows.

#### Resolving a pool path

A pool request carries no codename. apt chose which archive to trust when it read a `Packages` file during `apt update`, and that decision is not recoverable from `GET /apt/pool/main/n/nginx/nginx_1.24.0-2ubuntu7_amd64.deb` — the request looks identical whichever suite produced it.

So bodega probes. Every configured archive is tried in sorted order with a `HEAD`, the first that has the path wins, and the answer is remembered for an hour keyed on the pool path. A path no archive has is remembered as absent for the same hour, because apt retries a failed download and each retry would otherwise fan back out across every host.

The consequence to know: **if two configured archives publish different bytes at one pool path, bodega serves whichever answered the probe first.** Real Debian and Ubuntu archives do not do this — a pool path names one version of one package, and security and updates hosts share the namespace deliberately — but a private mirror rebuilt from source can. Do not point `apt_upstreams` at two archives that disagree.

#### Versions in the discovery log lose the epoch

A pool row's package and version are parsed from the `.deb` filename, which is the only thing a pool request carries. Debian omits an epoch from that filename: `1:2.66-5ubuntu2.4` is published as `libpam-cap_2.66-5ubuntu2.4_arm64.deb`, so the row reads `2.66-5ubuntu2.4` while `apt policy` shows the epoch. The row still names the right artifact — the upstream URL beside it is exact — but a version copied out of `bodega discover show` into a manifest entry may need the epoch put back. Where an archive does encode it (`%3a`), bodega decodes it back to `:`.

#### Sharing `pool/` with the build pipeline

`bodega build fetch apt` builds `.deb`s into the same `pool/` tree that cached upstream artifacts land in. That is correct Debian layout, not a collision to design around: a real archive shares one flat pool across every suite.

A pool path a manifest entry owns is never fetched from upstream. The check is on the entry, not on whether the object happens to be present, which matters in the window between `bodega pkg create` and `bodega pkg build`: the entry exists, storage is empty, and without the guard a miss would fetch some archive's artifact and cache it under bodega's own pool path. The `Packages` stanza already publishes a `SHA256` computed at package time, so the client would then reject bytes bodega handed it, against a package the operator built. Such a request 404s instead, which is the same answer it gave before upstreams were configured.

#### Large artifacts and the spool directory

The proxy path streams: an upstream body is copied to a spool file under `TMPDIR`, checksummed on the way through, then cached and served from there. Per-request memory is one copy buffer whatever the artifact's size, so there is no size ceiling on a proxied artifact — but `TMPDIR` has to hold the largest one in flight, and a small `tmpfs` there is where the old limit reappears. Point `TMPDIR` at real disk on a host that proxies `nvidia-*`, `texlive` collections or game-data packages.

A cut transfer is still refused rather than cached: a body shorter than the `Content-Length` the upstream declared fails, the spool file is removed, and no checksum is recorded. Caching short bytes as authoritative is what made every later fetch of the real artifact fail verification against the truncated digest.

The npm packument and the PyPI simple index are the two responses bodega still reads whole, because it parses them. Those are capped at 256 MB.

### APT index generation

`dists/<suite>/Release` and the `Packages` bodies under it are generated together into one snapshot and served from memory until the next rebuild. Nothing is written to storage: the only stored part of the apt repository is `pool/`.

They are generated together because `Release` records the SHA256 and byte length of each `Packages` body, and apt fetches the two in separate requests. Regenerating per request lets a write land between them, and the client rejects the result as `Hash Sum mismatch`.

A rebuild happens on:

| Trigger | Notes |
|---------|-------|
| Server start | Before the listener binds, so no request ever sees an empty index |
| `SIGHUP` | After the manifest reload and the signing-key reload. Sent by every CLI verb that changes what is served, from one hook on the root command rather than from each verb's own code. The same signal re-reads the CIDR access lists |
| A mutation-API write to an apt entry | `POST`, `DELETE`, and the hide and freeze toggles |
| A ticker | Hourly once an index exists; 15s, 30s, 60s and on up to hourly until one does |

**A manifest edited by hand is picked up on the next tick, or at once on `SIGHUP`** (`kill -HUP $(cat <log_dir>/bodega.pid)`). The tick re-reads the manifest index from the backend before rebuilding, so an edit made outside the process reaches the index without a signal; the wait is up to an hour. A verb that changes what is served signals, so the normal workflow never waits, and the tick is the floor under a signal that never arrived.

The TUI reaches none of that. Its freeze, delete and remove actions call the same work the verbs do without passing through cobra, so they signal from the run helpers themselves; a mutating action added there gets it by construction rather than by remembering. Which CLI verb signals is declared once per command where it is registered in `cmd/bodega/main.go`, and a group answers for its subtree. `TestEveryRunnableCommandIsClassified` fails the build on a command that declares neither, because a verb missing its signal looks exactly like a verb that never needed one: `pkg hide`, `freeze`, `refresh` and `remove` each shipped without it, and a hidden package stayed published until someone restarted the server. `bodega apt key` and `bodega acl` are in the quiet group on purpose: the rotation runbook above signals with `systemctl reload`, and the access lists carry their own 30s cache.

The retry interval matters because a snapshot that never built is a 503 on every apt request, and the ordinary way to land there is transient: expired credentials, or a network that was not up when systemd started the unit. Those clear in seconds and the first few attempts catch them. A wrong bucket, revoked credentials or a role that lost `s3:ListBucket` never clears at all, so the interval doubles up to the hourly one: 7 attempts in the first hour rather than 240, each of which is a manifest reload, a pool listing and an `ERROR` line against a dependency already failing. The first snapshot puts the loop straight back on the hourly interval however far the retry had walked.

A mutation-API rebuild runs on a background context rather than the request's. The write commits before the rebuild starts, so a client that hangs up in between would otherwise get its change persisted and the index left describing the state before it.

`Release` carries `Date` backdated 24 hours to tolerate client clock skew, and `Valid-Until` 14 days after that. The expiry is stamped when the snapshot is built and does not move on its own, which is why the refresh ticker is not an optimization: a server whose refresh loop stops eventually serves an expired `Release`, and every client fails `apt update` at once — including with `[trusted=yes]`, since `Acquire::Check-Valid-Until` is independent of trust. Within 24 hours of expiry the server logs at `WARN` on every `Release` fetch.

Four cases drop an entry from the index silently, and the client sees `Unable to locate package` for all four, which is also what a typo produces. Each is logged at `WARN` once per rebuild:

- The entry names suites, none of which is in `apt_suites`. This one also appears in `GET /api/v1/status` as `apt.unserved`, so an operator holding the API can tell a missing package from a misspelled one without reading the server's log. A suite name no configuration could ever serve (one containing `/`, which `apt_suites` rejects at load) is refused at the write instead, by both `POST /api/v1/packages/apt` and `bodega pkg import`.
- The entry has no `version`. No CLI verb can address a versionless entry, so publishing one hands clients a package nobody can withdraw. `POST /api/v1/packages/apt`, `bodega pkg import` and `bodega pkg edit` refuse to write one; `bodega repair` clears the ones already in a manifest.
- The entry has no `Architecture` in its metadata. deb822 has no default architecture, so there is nothing to substitute; set it with `bodega pkg edit` or re-run the build.
- The entry has no `_pool_path` and no `.deb` in the pool matches its name, version and architecture. Ordinarily this is the gap between `bodega pkg create` and the upload that follows.

An entry that records `_pool_path` addresses its pool object directly, so an index whose entries all carry one is built without listing the pool at all. A listing is taken only for the entries that need the filename match, cached for `metadata_ttl`, and re-taken when the cached one leaves any of them unresolved — but no more often than every 15 seconds. The two bounds answer opposite failures. Without the re-take, a `.deb` uploaded out of band stays out of the index for the whole `metadata_ttl` and stays out silently. Without the floor under it, an entry staged before its `.deb` is uploaded holds the index in the unresolved state indefinitely, and every apt write then pays for a full walk of the pool on every configured backend: one listing per write for the length of a bulk import.

The filename match is exact — `<package>_<version>_<architecture>.deb` and nothing looser — and objects the mirror cached are excluded from it. Both matter only where `apt_upstreams` is set: `pool/` then holds `.deb`s bodega did not build, an entry without `_pool_path` publishes no `SHA256` (that field comes from the same metadata `_pool_path` does), and a client has nothing to check the substitution against. Bodega tells the two apart by the audit checksum table, which holds a row per mirrored fetch. On a mirroring instance whose audit database cannot be read, no entry without `_pool_path` reaches the index at all and the rebuild says so at `WARN`; entries that carry `_pool_path` are unaffected, so the repository keeps serving.

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

Responses include `Strict-Transport-Security` (HSTS) whenever clients reach bodega over https, which is not the same question as whether this listener terminates TLS. The scheme comes from `public_url` when one is set, and from the request otherwise, honoring `X-Forwarded-Proto` only when the peer is inside `trusted_proxies`. So a loopback listener behind a terminating proxy sends HSTS, and a client on plain http that sets the header itself does not get one.

#### Serving without TLS

Plaintext is a request, not the absence of one. With `tls_cert` and `tls_key` both empty, `bodega serve` refuses to bind:

```
refusing to serve plaintext HTTP on :8080: tls_cert and tls_key are empty, which
means nothing was configured rather than serve in the clear; set both, or set
allow_plaintext (--allow-plaintext) to serve unencrypted on purpose
```

Authorize it with the flag or the key:

```bash
bodega serve --allow-plaintext
```
```json
{ "allow_plaintext": true }
```

`--allow-plaintext=false` overrides a config file that set it true, so a host can be pinned to TLS from the unit file without editing `config.json`.

Two refusals sit behind the same guard:

- **Half a pair.** `tls_cert` set with `tls_key` empty, or the reverse, is fatal — at load for the config file, and at startup for `--tls-cert`/`--tls-key`, which are applied after the file is read. `allow_plaintext` does not excuse it: half a pair is a truncated edit, and reading it as a request for plaintext is how a server that served TLS yesterday answers in the clear today. `Config.Save()` marshals the whole resolved config back over the file, so a cert path cleared in the TUI reaches the listener with nothing else in the way.
- **Port 443.** An empty pair on `:443` refuses even though the message differs, naming the port. A port is not authorization, but it is the strongest evidence available that whoever wrote `listen_addr` expected a certificate. `allow_plaintext` still starts it, with an `ERROR` on every start — the shipped `log_level` prints only `ERROR`, and a line the default install cannot see is not a warning. Off `:443` an authorized plaintext listener is silent: it serves what the operator asked for.

bodega has no ACME client. `tls_autocert` and `tls_domain` were config keys that nothing implemented; they are gone, and a file that still carries `tls_autocert: true` logs at startup that it is being ignored. Get a certificate from `certbot` or your CA, or terminate TLS at a proxy in front and set `public_url`.

Behind a TLS-terminating proxy, set `allow_plaintext` together with `public_url` — see [Behind a reverse proxy](#behind-a-reverse-proxy).

### Security headers

All responses include the following headers regardless of TLS:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy: default-src 'self'; ...`
- `Referrer-Policy: strict-origin-when-cross-origin`

### Behind a reverse proxy

bodega is designed to run behind nginx or Apache. The server extracts real client IPs from `X-Real-IP` and `X-Forwarded-For` headers when the request comes from a trusted private network (RFC 1918 + loopback).

**Set `public_url` on the bodega side of every one of these deployments.** The proxy terminates TLS and bodega listens on loopback with no certificate, so every client-facing URL bodega emits — the startup banner, the TUI pane, the web UI, `/api/v1/status` — is derived from a listener that answers `http://127.0.0.1:8080`. `X-Forwarded-Proto` fixes the requests bodega can see; `public_url` fixes the ones it cannot, and it is the only thing that knows the hostname the proxy publishes.

```json
{ "public_url": "https://bodega.example.com", "allow_plaintext": true }
```

`allow_plaintext` belongs in that same object. The back-end listener carries no certificate by design, and without the key `bodega serve` refuses to start.

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

with `"public_url": "https://bodega.example.com"` in bodega's `config.json`. `X-Forwarded-Proto` covers the requests bodega can see; `public_url` covers the startup banner, the TUI and `/api/v1/status`, which have no request to read.

Minimal Apache config. The two `RequestHeader unset` lines are a security control rather than boilerplate: bodega returns `X-Real-IP` verbatim from any peer inside `trusted_proxies`, Apache proxies from `127.0.0.1`, and `admin_permit_cidr` defaults to loopback only, so without them a remote client setting `X-Real-IP: 127.0.0.1` reaches the mutation API with no token.

Stripping at the proxy is still the right belt, but it is no longer the only one. Set `trusted_proxies` to the address your proxy actually connects from, and a header arriving from anywhere else is ignored whether or not the vhost remembered to unset it:

```json
"trusted_proxies": ["127.0.0.1/32"]
```

That matters most when bodega and its proxy do not share a host. The default trusts every RFC 1918 address, so on a private network with other tenants the proxy is not the only peer bodega believes.

```apache
<VirtualHost *:443>
    ServerName bodega.example.com

    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/bodega.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/bodega.example.com/privkey.pem

    RequestHeader unset X-Real-IP
    RequestHeader unset X-Forwarded-For
    RequestHeader set X-Forwarded-Proto "https"

    ProxyPreserveHost On
    ProxyPass        / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/
</VirtualHost>
```

with the same `"public_url": "https://bodega.example.com"` in `config.json`. Neither vhost sets `Strict-Transport-Security` itself: bodega sends it once the scheme resolves to https, and two sources for one header is how they drift.

---

## REST API

All API responses are JSON. The full API is documented in [OpenAPI 3.0 format](../api/openapi.yaml).

### Read endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/packages` | All entries across all types |
| GET | `/api/v1/packages/{type}` | Entries for one type |
| GET | `/api/v1/packages/{type}/{name}` | Single entry details |
| GET | `/api/v1/status` | Health check with entry counts, S3 probe, and the apt client state |
| GET | `/api/v1/config` | Non-sensitive config (bucket, region, manifest_dir) |
| GET | `/api/v1/audit` | Query audit events (supports filters) |
| GET | `/healthz` | Health probe (returns `ok`) |

#### The `apt` block on `/api/v1/status`

`/api/v1/status` carries an `apt` object reporting how apt clients reach this server. It is the answer to what an emitter would otherwise guess at, and the reason the banner, the TUI and the web UI agree.

```json
"apt": {
  "signed": true,
  "fingerprints": ["133A3F2CFEA9512985C769DEC88A9A63077198DA"],
  "keyring_url": "/apt/bodega-archive-keyring.gpg",
  "suites": ["jammy", "noble"],
  "public_url": "https://bodega.example.com",
  "sources": [
    {
      "signed": true,
      "suite": "jammy",
      "uri": "https://bodega.example.com/apt/",
      "deb822": "Types: deb\nURIs: https://bodega.example.com/apt/\nSuites: jammy\nComponents: main\nSigned-By: /etc/apt/keyrings/bodega-archive-keyring.gpg",
      "one_line": "deb [signed-by=/etc/apt/keyrings/bodega-archive-keyring.gpg] https://bodega.example.com/apt/ jammy main",
      "notes": ["Install the keyring from /apt/bodega-archive-keyring.gpg first. …"]
    }
  ]
}
```

- `signed`, `fingerprints` and `keyring_url` come from the key the process has **loaded**, not from a file on disk. A key installed but not yet reloaded reports as absent, which is what clients see.
- `unserved` lists the apt entries naming no suite in `apt_suites`, with `unserved_count` carrying the true total when the list is capped at ten. It is the same set the rebuild logs at `WARN`, in a form a UI can render: the entry reaches no index and the client is told `Unable to locate package`, so without it the operator's only evidence is a log line on the server.
- `sources` carries one rendered block per served suite, so a caller holding a package selects the block for that package's suite rather than composing a line.
- `public_url` is the configured value when there is one. With none set it is the origin of the request that asked, resolved through `X-Forwarded-Proto` when the peer is trusted.
- `notes` are the consequences of the form above them: the permanence of `[trusted=yes]`, or the fact that the first keyring fetch is authenticated by TLS alone.

### Mutation endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/packages/{type}` | Create a new entry (JSON body) |
| POST | `/api/v1/packages/import[?merge=true]` | Import many entries across types (JSON array or NDJSON body) |
| DELETE | `/api/v1/packages/{type}/{name}` | Delete an entry |
| PATCH | `/api/v1/packages/{type}/{name}/hide` | Toggle hidden (all versions) |
| PATCH | `/api/v1/packages/{type}/{name}/hide/{version}` | Toggle hidden (specific version) |
| PATCH | `/api/v1/packages/{type}/{name}/freeze` | Toggle frozen (all versions) |
| PATCH | `/api/v1/packages/{type}/{name}/freeze/{version}` | Toggle frozen (specific version) |

#### `POST /api/v1/packages/import`

Takes a whole host's catalog in one request. `bodega pkg import --server` is the client for it.

It is a separate route from `POST /api/v1/packages/{type}` because the two want opposite semantics. A single create is all-or-nothing and answers 409 on a name clash; a bulk push is expected to land partially and has to say which packages did.

- **Body**: a JSON array of `PackageManifest`, or one manifest per line (NDJSON). Both decode one manifest at a time, so a large catalog never lands in memory whole. Types may be mixed in one push.
- **Size**: 64 MiB, against 1 MiB on the single-package route. A bare 2000-package catalog is only about 220 KB, but a `pkg export` of a populated store carries architecture, section, pool path and description per entry and clears 1 MiB well before it clears the package count.
- **`?merge=true`**: adds versions to packages that already exist, matching `pkg import --merge`. A recorded version is never overwritten, which keeps a `hosted` entry from being downgraded to `proxy` by a re-import.
- **Status**: `200` whenever the body parsed, including when every package was refused. `400` for a body that is not manifests, `413` over the size limit.

```json
{
  "imported": 633,
  "merged": 0,
  "skipped": 2,
  "results": [
    {"type": "apt", "name": "curl", "outcome": "imported"},
    {"type": "apt", "name": "bash", "outcome": "conflict", "reason": "package already exists (retry with merge=true to add versions)"},
    {"type": "apt", "name": "blank", "outcome": "invalid", "reason": "apt/blank has a version entry with no version; give one, or \"*\" to resolve the current upstream"}
  ]
}
```

`outcome` is one of `imported`, `merged`, `conflict`, `invalid`, `policy_blocked` or `failed`. Every manifest passes the same allow-list, age and OSV checks as `bodega pkg import` and `POST /api/v1/packages/{type}`.

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

Mutation endpoints and the four admin reads (`/api/v1/audit`, `/api/v1/tokens`, `/api/v1/policies`, `/api/v1/config`) are restricted by `admin_permit_cidr`, which defaults to localhost only (`127.0.0.0/8`, `::1/128`). Requests from IPs outside the permit list get a 403, and an empty list permits nobody.

That list lives in the audit database and is read per request, so `bodega acl admin add|remove` takes effect on a running server without a restart. `config.json` seeds it on first start and is ignored afterwards; see **Configuration**.

The address compared against that list is the one `trusted_proxies` resolved, not the TCP peer. Behind a proxy the two differ by design; on a shared private network with the default trusted set they differ because a stranger said so.

When `admin_permit_cidr` includes non-localhost addresses, a Bearer token is also required. Generate tokens with `bodega token generate` and pass them in the `Authorization` header. Widening the list is what turns that requirement on, which is why `bodega acl admin add` refuses to widen past localhost while no token exists.

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

The manifests say what is in the repository. The audit database says who put it there and who was turned away trying:

```bash
bodega audit events --type create --limit 50   # who added entries
bodega audit events --type denied --limit 50   # who the server refused, and at which gate
```

On a publicly reachable instance the database is the only queryable record of a refusal. The journal has the same lines, but it rotates on size and time, it is not served on `/api/v1/audit`, and the shipped `log_level: 1` prints none of it.

---

## Proxy/Cache

When `proxy_cache_enabled` is `true`, the server fetches from upstream on cache miss. See [Upstream hosts](#upstream-hosts) for which registry each type reaches.

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

### Upstream hosts

Five flat keys name the registries a proxying instance fetches from. They are not interchangeable, and two ecosystems need two keys each because the registry that answers "which versions exist" is not the one that serves the bytes.

| Key | Default | What that host serves |
|-----|---------|-----------------------|
| `gomod_upstream` | `https://proxy.golang.org` | The whole module proxy protocol: `@v/list`, `@v/{version}.info`, `.mod` and `.zip`, all on one host |
| `npm_upstream` | `https://registry.npmjs.org` | Packuments and tarballs, both on one host |
| `pypi_upstream` | `https://pypi.org` | The PEP 503 index root. bodega reads `/simple/{dist}/` under it and fetches the artifact URL that page lists, which is on `files.pythonhosted.org` under a content-hash path. A wheel URL cannot be composed from a filename, so a request for a file the index does not list is a 404 naming the index that was read |
| `cargo_upstream` | `https://index.crates.io` | The sparse index, and nothing else. A crate tarball request to this host is a 404 |
| `cargo_dl_upstream` | `https://static.crates.io/crates` | Crate tarballs. bodega appends `/{crate}/{version}/download` |

crates.io names its own download root in `https://index.crates.io/config.json`, and bodega does not read it. Fetching that document at startup would make `bodega serve` fail to bind because a registry was unreachable, and an operator mirroring the index is not thereby mirroring the tarballs: point the two keys wherever each actually lives.

The allow-list checks the package name for `pypi`, `npm` and `gomod`, so `bodega policy add pypi <dist>` keeps working across the two pypi hosts. `cargo` is name-scoped the same way, and a rule constrains the crate rather than the host either key names.

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

The audit trail records every package fetch served, every build-pipeline stage, every CRUD mutation, every proxy cache event, every request the server refused, and the server's own start and stop. Where those events go is `audit_sink`; the default writes them into the SQLite database at `{log_dir}/audit.db`.

Two things live in that database and only one of them moves. The **event stream** is append-only, written on the hot path and read for reporting, and it is what a sink holds. **Operational state** — the ACL lists, the API tokens, the cached checksums and the age, OSV and upstream policies — stays in `audit_db` under every sink, because the request path reads it to decide whether an address is permitted, whether a token is live and whether an upstream is allowed. A sink that cannot answer a query cannot hold it, and a store one network round trip away would put that round trip inside every request bodega serves.

### Audit sinks

| `audit_sink` | For | `audit_sink_dsn` | Queryable |
|---|---|---|---|
| `sqlite` | One host. The default, and no new dependency | not accepted | yes |
| `postgres` | A fleet writing at once, and reporting across instances | libpq connection string | yes |
| `syslog` | Shipping into a SIEM you already run | `tcp://`, `udp://`, `unix://` address; empty = the local daemon | no |
| `jsonl` | A file another collector tails; no daemon, no schema migration | absolute path | no |

The default is `sqlite`, so an existing install upgrades with no config change and no migration.

**One sink, not a list.** `audit_sink` takes a single value. Teeing to a write-only sink alongside `sqlite` would keep `bodega discover promote` working while events reached the SIEM, and it would also keep the SQLite write rate you switched away from, plus a second write per event on the hot path. If you need the trail queryable at fleet rates, that is what `postgres` is for; if you do not, choosing `syslog` or `jsonl` is choosing to give up the queries, and bodega says so rather than half-answering.

**The write-only sinks refuse rather than lie.** Under `syslog` and `jsonl` there is no table to read back, so:

- `GET /api/v1/audit` answers **501 Not Implemented** with the sink named in the body. Not 503: this is a configuration the server will keep having, and "try again later" would never come true.
- `bodega audit events` exits non-zero naming the sink and pointing at `sqlite` or `postgres`.
- `bodega discover list`, `show`, `export`, `clear`, `promote-all` and `generate-manifests` do the same.
- **`bodega discover promote` is unavailable.** It reads the discovery table to build the policy rule or the manifest entries it writes, and a stream that has already left the process is not a table. Promote from an instance running `sqlite` or `postgres`, or read the observations where your collector puts them and write the entries with `bodega pkg create`.

The events themselves are one JSON object per line under both sinks, with a `kind` of `event` or `discovery` and field names matching the SQL columns the queryable sinks use, so a SIEM rule and a `postgres` query name the same things. `json.Marshal` escapes control characters, so a User-Agent carrying a newline cannot forge a second record.

**A write-only sink cannot deduplicate.** The queryable sinks collapse repeat observations on `(registry_type, pattern_hint, pkg_name, pkg_version, decision)` and bump `request_count`. `syslog` and `jsonl` emit one record per request and leave the rollup to whatever consumes the stream.

**When the destination is unavailable.** The rule is one line: `bodega serve` refuses to start rather than serving while dropping the record of what it refuses.

| Condition | `bodega serve` | CLI |
|---|---|---|
| `postgres` will not connect (5s ping timeout) | refuses to start, naming `audit_db` and `audit_sink` | read commands exit non-zero; a one-shot write warns on stderr and continues |
| syslog socket is gone at startup | refuses to start | same |
| jsonl path is unwritable | refuses to start | same |
| `audit_db` file exists but is not writable | refuses to start | read commands keep working; this is the documented non-root `bodega audit events` path |
| `audit_db` is unset | starts with no audit trail, token auth and policy enforcement off | unchanged |

An unset `audit_db` is an install that asked for no audit trail, so it is not a failure. Everything else is: an audit store that fails open silently is what this design exists to prevent. The parent directory of `audit_db` (and of a `jsonl` path) is created on first use, so a fresh install is not a startup failure.

A destination that goes away **after** startup does not stop the server. The write error is logged at `Error`, which the shipped default `log_level` prints, and bodega keeps serving packages: killing a package proxy because syslog restarted is the worse outcome.

### Choosing a sink

Measured on an Apple M1 Ultra (Mac13,2), macOS 26.7, internal NVMe over Apple Fabric, APFS; `postgres:17-alpine` in Docker Desktop on the same host over loopback. 64 concurrent writers, 10 s per run, at a fixed offered request rate. Each request is the post-B16 shape: one event row on the hot path plus one discovery observation through the recorder's queue.

| Offered | Sink | Events/s landed | Discovery dropped | Hot-path write p99 |
|---|---|---|---|---|
| 500/s | `sqlite` | 925 | 0% | 1.36 s |
| | `postgres` | 999 | 0% | 23 ms |
| | `syslog` | 1,000 | 0% | 4.3 ms |
| | `jsonl` | 1,000 | 0% | 1.9 ms |
| 1,000/s | `sqlite` | 1,678 | 6.5% | 956 ms |
| | `postgres` | 1,997 | 0% | 18 ms |
| | `syslog` | 1,999 | 0% | 3.0 ms |
| | `jsonl` | 1,999 | 0% | 2.0 ms |
| 2,000/s | `sqlite` | 2,848 | 48.5% | 638 ms |
| | `postgres` | 3,556 | 22.0% | 14 ms |
| | `syslog` | 3,998 | 0% | 3.1 ms |
| | `jsonl` | 3,998 | 0% | 2.2 ms |
| 8,000/s | `sqlite` | 7,058 | 97.3% | 179 ms |
| | `postgres` | 8,355 | 95.5% | 15 ms |
| | `syslog` | 15,987 | 0% | 3.0 ms |
| | `jsonl` | 15,996 | 0% | 1.9 ms |

Unthrottled, the same harness sustains 8,837 hot-path writes/s on `sqlite` (10 of 92,815 lost to the 5 s busy timeout, p99 54 ms), 12,496/s on `postgres` (none lost, p99 20 ms), 133,618/s on `syslog` and 224,466/s on `jsonl`.

Convert a fleet to a request rate with `hosts x updates-per-hour x requests-per-update / 3600`. A thousand hosts running `apt update` twice an hour over a dozen index paths is about 7 requests/s; a CI fleet installing packages per build is one to two orders of magnitude above that.

- **Under ~500 requests/s: `sqlite`.** Nothing drops, and the store you already have needs no daemon. Its hot-path p99 is the worst of the four even here — over a second, because the request goroutine waits on the write lock the discovery worker holds — but that latency is off the response path.
- **~500 to ~2,000 requests/s, or more than one bodega: `postgres`.** It is the only sink that keeps the trail queryable at that rate, and its hot-path p99 stays under 25 ms across the whole range with no writes lost to a timeout. It is also the only way to report across instances: each host keeps its own `audit_db` for ACLs and tokens, and their events land in one place.
- **Above ~2,000 requests/s, or when the SIEM already exists: `syslog` or `jsonl`.** Neither dropped a row at any rate measured. You are trading `bodega discover promote` and `GET /api/v1/audit` for that; if you need them back, run one instance on `postgres`.

**The drops in that table are not the sink.** `DiscoveryRecorder` drains its 1,024-deep queue with a single goroutine doing one synchronous write per row, so the discovery half is capped by one write's latency however wide the pool underneath is: about 2,700 rows/s on `sqlite` and about 900/s on `postgres`, where each upsert costs a network round trip. That is why `postgres` starts dropping observations at 2,000 requests/s despite absorbing 12,500 hot-path writes/s. The hot-path event rows, which are written concurrently, show what the sink can actually take. Batching that worker is filed as [#217](https://github.com/ravinald/bodega/issues/217).

**Event types:**

| Type | Trigger |
|------|---------|
| `serve_fetch` | Client downloaded a package over HTTP |
| `fetch`, `build`, `package`, `upload`, `sync` | Build pipeline stage completed for an entry |
| `create`, `delete`, `hide`, `freeze`, `edit`, `refresh`, `repair` | Manifest mutation (CLI, TUI or API) |
| `init`, `reset`, `status`, `show` | Operator command |
| `cache` | Proxy cache miss > upstream fetch, and upstream policy violations (`status=policy_violation`) |
| `denied` | A request the server refused |
| `serve_start`, `serve_stop` | `bodega serve` bound its listener / shut down |

**Denials.** A `denied` row's `status` column names the gate that turned the request away, so an address that was never permitted reads differently from a token that simply aged out:

| Status | Gate |
|--------|------|
| `deny_list` | Client IP matched `deny_list` |
| `client_ip_unparsable` | Mutation whose resolved client IP is not an address |
| `ip_not_permitted` | Mutation from outside `admin_permit_cidr` |
| `no_tokens_configured` | Remote mutation while no API token exists |
| `token_missing` | Mutation with no Bearer credential |
| `token_invalid` | Bearer presented, matched no stored hash |
| `token_expired` | Bearer matched a token past its `expires_at` |
| `admin_only` | Admin-gated read (`/api/v1/config`, `/api/v1/audit`, tokens, policies) from outside `admin_permit_cidr` |
| `entry_frozen` | `DELETE` on a package whose every version is frozen. The caller cleared the admin gate, which is what makes the attempt worth a row |
| `version_constraint` | A gomod or npm request for a version outside the entry's `version_constraint`. `pkg_version` carries the version that was refused, `details` the constraint and the entry's own version |

The first eight gates run in the middleware chain, before any handler; the last two are decided by the handler itself. Both write the same row, because an operator asking "who was turned away" is asking one question.

The row is written on a context detached from the request. `net/http` cancels the request context the moment a client closes the connection, so a caller that fires a request and hangs up without reading the response — ordinary scanner behavior — got its 403 and left no row, which made the rows least reliable exactly where they matter most.

The row carries the client IP, the User-Agent, and a `details` JSON blob with the method and path. It carries **no credential**: `token_expired` records the token id, `token_invalid` records the first 12 hex of the peppered hash — enough to tell two rejected callers apart, useless without the pepper — and no header is ever copied in. Client-controlled strings are capped at 256 bytes each, so an unauthenticated stranger does not choose how much disk a 403 costs.

The lifecycle rows bracket everything else. Without them a quiet database is ambiguous: nobody was turned away, or the server was not running.

**Query examples:**
```bash
bodega audit events --type serve_fetch --limit 50
bodega audit events --type denied --limit 50      # who was turned away, and when
bodega audit events --type denied --client 203.0.113.9
bodega audit events --name lodash --since 2026-04-07
```

Fields on every row: timestamp, event type, package type/name/version, client IP, user agent, status, duration, actor (the OS user, on CLI and TUI events), and the `details` blob.

**Not recorded**, deliberately:

- **404s on package routes.** `apt update` probes several optional index paths on every run, so recording absences would bury the fetches. A miss that reached upstream is a `cache` event; a miss against an unknown name is in the journal only.
- **Request and response headers or bodies.** Those are a `log_level: 4` (trace) concern in the journal, not an audit record, and a header dump would carry the very credentials the denial rows are careful not to hold.
- **Successful admin reads.** Only the refusals are rows; a permitted `GET /api/v1/audit` is journal-only.

Denials record at every gate in the middleware chain, at the admin-read gate, and at the two refusals a handler decides for itself: a `DELETE` on a frozen entry (`entry_frozen`) and a version outside an entry's `version_constraint` (`version_constraint`). The `status` column names which gate refused.

`audit_events` and `timezone` in `config.json` apply to both handles: the CLI's and the one `bodega serve` opens for itself. A filter that leaves out `denied` therefore throws away the record of every refusal the server makes, which is the one record that has no other home — the journal rotates and is not reachable through `/api/v1/audit`. `bodega serve` logs an error naming the key when it starts with such a filter. Leave `audit_events` empty unless you have a reason.

A read-only audit database used to be the quieter version of the same loss: `Record` no-oped, `Query` kept answering, so `/api/v1/audit` responded and simply stopped growing. `bodega serve` now refuses to start on it, naming the file and the uid. Read commands still work against a database they cannot write, which is what keeps `bodega audit events` usable as a non-root user against a root-owned file.

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

The form edits no ACL. `deny_list`, `admin_permit_cidr` and `trusted_proxies` are seeded from the config file on first start and inert afterwards, so a field writing them to `config.json` would accept a value, save it, report success and change nothing about who the server refuses. Edit them with `bodega acl deny`, `bodega acl admin` and `bodega acl proxies`; the form says so under its title.

### Details pane

The **Sources line** field for an apt entry is a command an operator pastes into `/etc/apt/sources.list.d/`, so it is rendered by the server-side renderer every other emitter uses ([Client configuration](#client-configuration)) rather than composed in the pane. Two things it does that are not obvious:

- **The suite is intersected against the served set.** The pane names the first suite the entry is published to that `apt_suites` (or `apt_codename`) also answers for. An entry naming a suite outside that set reaches no index, and a line pointing at it 404s the whole `dists/` path, which apt reports as "Unable to locate package" — the message a misspelled name produces. The fallback is the first served suite. `GET /api/v1/status` lists such entries under `apt.unserved`.
- **The signing state comes from the key file, not the running server.** The pane applies the same acceptance test `bodega serve` does — the key must load, and both its armored and dearmored public forms must render — but it reads the file. A server that already loaded a key keeps signing after the file is deleted, because a reload never takes signing away (see [Rotation](#rotation)), so the two disagree until a restart. A note beside the line says so and points at `GET /api/v1/status`, which reports what the server is actually doing.

### Build stages

The build menu dispatches all eight entry types. Only `apt` and `pypi` have a build step and only `apt`, `git`, `pypi`, `helm` and `npm` have a package step; the rest say which stage does not apply to them rather than reporting an empty success. `helm` and `npm` package across the whole type — `index.yaml` and the packuments are repository metadata, not per-entry archives — so those two stages ignore the selected entry and regenerate everything.

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

Git smart-HTTP mirrors are the one tree that is not a storage key. They are bare repositories under `{storage_path}/git/{namespace}/{org}/{repo}.git` on the local filesystem, never in a named backend and never in S3: `git-http-backend` reads a real directory, and `bodega pkg move` has nothing to move. Placement rules do not reach them.

---

## Development

### Build targets

```bash
make check          # every job CI blocks on, cheapest leg first
make build          # compile to ./dist/bodega
make cross          # cross-compile for linux/amd64
make test           # run tests with race detector
make test-verbose   # verbose test output
make bench          # run benchmarks
make vet            # go vet
make fmt            # goimports / gofmt
make fmt-check      # fail on gofmt / goimports drift (CI's fmt job)
make lint           # golangci-lint
make tidy           # go mod tidy + verify
make tidy-check     # fail on go.mod / go.sum drift or a checksum mismatch (CI's tidy job)
make ci-drift       # fail if the CI job list and this Makefile disagree
make clean          # remove build artifacts
make depend         # install Go + golangci-lint
```

`make check` is the merge gate. CI's `vet`, `fmt` and `tidy` jobs call the same
targets, so what passes locally is what the merge blocks on. Three lists have to
agree and `make ci-drift` reads all three: `needs:` in
`.github/workflows/ci.yml`, `CI_GATE_JOBS`, and `CI_GATE_TARGETS`, which pairs
each CI job with the make target that runs it. That target must appear in
`CHECK_LEGS`, which is `check`'s own prerequisite list, so a job added to CI
with no leg fails the gate rather than passing it.
`make fmt-check` requires `goimports` on `PATH` rather than skipping it, because
a check that skips is weaker than the merge it stands in for.

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
