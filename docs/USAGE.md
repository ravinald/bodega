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

An apt entry written before the `_pool_path` metadata key existed is located by listing the pool for its exact Debian filename, `<source>_<version>_<arch>.deb`. An entry no such object is named for reports no key and `PRESENT: no`, matching what the server does with it: it publishes no `Packages` stanza for an entry it cannot name an object for, so a `KEY` here would be a key nothing serves.

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

Phase 5 corrects what `bodega discover promote --as manifest` wrote while the wheel handler composed `<index>/packages/<filename>`, a path pypi.org has never served. Nothing reads the field today, so the stored URL breaks no fetch; it is rewritten because promotion never revisits a version it already wrote, and the entry would otherwise carry a URL nothing can fetch for as long as it exists. The match is on the shape, `<scheme>://<host>/packages/<file>`, on any host — an operator's own index that serves that path is rewritten to its root too, which is what the field means there as well. Entries of any other shape are left untouched. See [Upstream hosts](#upstream-hosts) for how a wheel is resolved now.

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

The version list carries an `OSV` and a `CHECKED` column per version, and names the flagged ids underneath. See [`bodega policy osv`](#bodega-policy-osv-syncsetlistremoverescan) for what `unchecked` means and how the date gets written.

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

### `bodega pkg delete <type> <name> [--remove-artifacts]`

Removes an entry from the manifest. Pass `--remove-artifacts` to also delete the artifacts first. Frozen entries cannot be deleted.

Every version is removed, each from the backend its own entry records, and each key is checked with a `Head` before the delete so the output distinguishes "removed" from "was already gone". An entry no key resolves for (pypi, or an apt entry with no recorded pool path) fails the command with the manifest entry intact: the entry is the only record of which bytes to clean up, so dropping it after a delete that looked nowhere would orphan them.

### `bodega pkg remove <type> <name>`

Removes an entry's artifacts from the object store without touching the manifest. Resolution, per-version backends and the no-key refusal are the same as `pkg delete --remove-artifacts`.

### `bodega pkg import <file> [file...]`

Imports package manifests from JSON files. Use `-` to read from stdin. This is the preferred method for automation and CI/CD pipelines.

```bash
bodega pkg import nginx.json                       # import from file
bodega pkg import packages/*.json                  # import multiple files
cat manifest.json | bodega pkg import -            # import from stdin
bodega pkg import --merge updated.json             # add versions to existing package
bodega pkg import --origin db01 catalog.json       # stamp a payload that carries none
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

#### `--origin`

Every version entry records the host it was cataloged from, under the `_origin` metadata key. `bodega pkg convert` stamps it and the import preserves what arrives. The field is what lets a catalog holding four hosts' inventories answer which machine contributed a row, and what lets a baseline set for a class of host be built from the machine that defines the class.

`--origin` sets it on a file that carries none: an inventory captured by hand, or a manifest written before the field existed. A file whose entries already name a _different_ host fails the import, naming both:

```console
$ bodega pkg import --origin db01 db02-catalog.json
Error: db02-catalog.json: pypi/requests version 2.31.0: --origin db01 disagrees with the origin already on the payload (db02); drop the flag to keep what the file records, or re-run 'bodega pkg convert --origin' against the inventory
```

Nothing is written. Two claims about where a row came from cannot both be true, and picking one silently is how the field stops being evidence.

A flag naming a host the entry already lists passes. `--origin db01` over an entry recording `db01,db02` restates what the file says, so re-importing an export that merged two hosts does not have to drop the flag it was captured with.

`--merge` **adds** an origin rather than replacing it. A package installed on `db01` and `db02` came from both, so a second host reporting a version already in the store leaves the entry recording `db01,db02`. Nothing else on that entry moves, which is what keeps a `hosted` version from being downgraded to `proxy`.

`--origin` applies on the `--server` path too: the payload is stamped on the host before it is pushed, so `POST /api/v1/packages/import` receives the same field a local import would have written.

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
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\t${source:Package}\n' | bodega pkg convert apt > catalog.json
apt list --installed | bodega pkg convert apt -o catalog.json
pip list --format=json | bodega pkg convert pypi | bodega pkg import -
bodega pkg convert apt --origin db01 --suite noble db01-installed.txt
```

Every version entry is stamped with the host the inventory describes, under the `_origin` metadata key, defaulting to this machine's hostname. That is what running convert on the host buys beyond reading the inventory: a catalog assembled from four machines can name the contributor of each row, and a baseline for a class of host can be built from the machine that defines the class. `--origin <name>` names the host when the capture was taken there and converted somewhere else. See [`--origin`](#--origin) for what the import does with it.

An apt inventory records one more thing about the host: the release it was captured on, on every version entry's `capture_suite`. That is the field the OSV gate keys apt advisories on, and it has to come from the capture because dpkg reports no codename in either format and the fix for a CVE is a fact about one release: see [apt](#apt) under the OSV gate. It is not `suites`, which decides which `dists/<suite>/` the entry is published to; the two are different values on any server whose `apt_codename` is a name of your own. It defaults to `VERSION_CODENAME` in this machine's `/etc/os-release`, and `--suite <codename>` names the release when the capture came from another one. Either way the run says which release it recorded:

```
apt: recording release "jammy" on every entry (VERSION_CODENAME in /etc/os-release)
```

A host that names no codename resolves none: converting a capture on a Mac, or on a distro that publishes no `VERSION_CODENAME`, records no release and says so. The gate warns on such an entry rather than guessing a release for it, so the flag is the fix:

```
apt: no release recorded on these entries: no --suite, and /etc/os-release names no VERSION_CODENAME.
  The OSV gate answers an apt version from the advisories published for its own release, and warns rather than
  guessing one. Re-run with --suite <codename> to record it.
```

| Type | Source command |
|------|----------------|
| `apt` | `dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\t${source:Package}\n'`, or `apt list --installed` |
| `pypi` | `pip list --format=json` |
| `npm` | `npm ls --global --json --depth=0` |
| `gomod` | `go list -m all`, or `go version -m <binary>` |
| `cargo` | `cargo install --list` |
| `helm` | `helm list -o json` |

**`git` and `binary` have no importer.** Nothing on a host records a `git clone` or a downloaded binary, so there is no inventory to read. Catalog those with `bodega pkg create`, or run the server with `discover_mode` set to `"observe"` and promote what clients reach for.

Prefer `dpkg-query` to `apt list --installed`: it is machine readable, it carries the package status, and apt itself warns that its CLI has no stable interface. Both are accepted.

#### What convert does and does not resolve

- **apt** entries carry the name, the version, `source_name`, `source_package`, `capture_suite` and no URL. The build pipeline resolves them with `apt-get download`, against the bodega server's own sources.
- **The release is recorded on every entry, from `--suite` or this machine's `/etc/os-release`.** `capture_suite` is what the OSV gate keys apt advisories on, because Ubuntu and Debian backport a fix without moving the upstream version. Convert records no `suites`, so the entry publishes to whatever suite the importing server serves: a release written into `suites` would take every converted entry out of the indexes of a bodega whose `apt_codename` is a local name. An entry carrying no `capture_suite` falls back to `suites` and then to the server's `apt_codename`, which is right on a bodega serving one release and a guess on a bodega serving two: see [apt](#apt) under the OSV gate.
- **The source package is recorded from `${source:Package}`, and only from there.** `source_name` is the name `apt-get download` asks for and is always the binary name; `source_package` is what USN and DSA are issued against, and the OSV gate queries that one. The two differ on 73 of the 101 packages a stock `ubuntu:22.04` container installs (`libssl3` from `openssl`, `bsdutils` from `util-linux`), so a capture that drops the field leaves the gate unable to answer for most of the host: see [apt](#apt) under the OSV gate. `apt list --installed` prints the source name in no position at all, so a catalog captured that way can never carry one. A four-field capture taken before bodega asked still parses unchanged; re-capture with the fifth field to give the gate something to query.
- **pypi, npm, gomod and cargo** entries carry a name and a version and import as `proxy`. The registry is already known from `pypi_upstream` and its siblings, so nothing else is needed. Flip an entry to `hosted` and run the pipeline to pre-fetch the artifact.
- **helm** entries import with **no URL**. A helm release records the chart it came from (`nginx-18.2.4`) but not the repository, and bodega resolves helm upstreams per version. Fill the URLs in before importing, or resolve them with `helm search repo <chart> -o json`. Guessing a repository would put an unverified URL into a supply-chain catalog.
- **cargo** crates installed from a git or path source are skipped: the registry has no such version to serve.
- **Removed packages are skipped.** `dpkg-query -W` reports a package removed without `--purge` as `deinstall ok config-files`, and it looks installed in every other column. On one Ubuntu 22.04 server that is 139 of 774 rows, mostly superseded kernel images.

Every skip and every gap is reported on stderr, so stdout stays a clean payload that pipes into `pkg import`.

#### Cataloging a host end to end

```bash
# On the host being cataloged. Neither step needs a manifest store here.
# Every entry is stamped with this machine's hostname, so the catalog can
# still name the contributor once other hosts land in it.
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

`--merge` never overwrites a recorded version, so an entry someone promoted to `hosted` stays hosted. The origins are the one thing it adds to a version already in the store: run the same package through from `db01` and from `db02` and the entry records both, which is the fact the field exists to hold.

Converting a capture taken on another machine needs the name passed, and the release with it:

```bash
# The dpkg-query output was collected on db01, a noble host, and copied here.
bodega pkg convert apt --origin db01 --suite noble db01-installed.txt \
  | bodega pkg import --server https://bodega.example --merge -
```

Both flags default to this machine, so leaving `--suite` off here records the release the _converting_ host runs. That is right when convert runs on the host being cataloged and wrong the moment it does not, and the failure is quiet: the advisories for the wrong release match nothing, and every version in the capture reports clean.

`bodega show pkg apt <name>` prints an `ORIGIN` column naming the hosts behind each version, and `bodega pkg export` carries the field, so a catalog stays attributable across a migration between instances. The `bodega show repo` table withholds it: an origin is an internal hostname, and that view renders what a client may see. `bodega show repo <type> <name> json` still carries the key, as it does `_pool_path` and every other internal metadata key — that output is a manifest dump, not the client-facing rendering.

**A catalog is an inventory, not a repository.** Importing one records what a host has; it does not make bodega able to serve those packages, and pointing the host's `sources.list` at bodega after this step gets an empty index. The two are separate on purpose — the catalog is what `bodega status`, `bodega policy` and the discovery residue read — but the order to do them in is the other way round from the way the request usually arrives. Serve first, catalog second:

| You want                                                 | Read                                                                       |
| -------------------------------------------------------- | -------------------------------------------------------------------------- |
| the host to install from bodega                          | [Mirroring an upstream archive](#mirroring-an-upstream-archive)            |
| bodega to serve `.deb`s you built or downloaded yourself | [APT index generation](#apt-index-generation) and `bodega build fetch apt` |
| a record of what the host already has                    | this section                                                               |
| the host to keep the versions it runs once behind bodega | [`bodega pin apt`](#bodega-pin-apt-file-)                                  |

For apt specifically, `bodega build fetch apt` shells out to `apt-get download <name>` on the bodega host: it passes no version, so a catalog entry's version names the storage key and nothing else, and the host can only resolve releases its own apt sources carry. A bodega on noble cannot fetch a jammy catalog that way. Mirroring is what serves another release.

Once the host installs from bodega, `bodega pin apt` closes the loop the other two rows leave open: it reads the same inventory this section converts, checks each installed version against the indices bodega actually serves, and writes the preferences file that holds the host where it is. That is a different question from the catalog, and it is the one asked on the day a host is moved behind bodega.

### `bodega pin apt [file|-]`

Turns a host's installed apt packages into a preferences file pinning each one to the version it runs, and a list of the packages that cannot be pinned.

Run it after the host's `sources.list` points at bodega. It reads the same inventory `bodega pkg convert apt` reads, asks a bodega whether each installed version is still published by a suite it serves, and writes the answer in two parts.

```bash
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\n' \
  | BODEGA_SERVER=https://bodega.example bodega pin apt - \
      -o bodega-pin --unresolved bodega-hold

sudo install -m 0644 bodega-pin /etc/apt/preferences.d/bodega-pin
sudo apt-mark hold $(cat bodega-hold)
```

```text
apt: skipped 139 package(s) present in the dpkg database but not installed (removed, config files retained)
pin apt: resolving against https://bodega.example ($BODEGA_SERVER)
pin apt: 635 installed, 627 pinned, 8 unresolved
pin apt: hold these instead, their installed version is on no served suite: apt-mark hold cloud-init fwupd linux-generic ...
```

| Flag                | Default            | What it does                                        |
| ------------------- | ------------------ | --------------------------------------------------- |
| `-o`, `--output`    | stdout             | Where the preferences file goes                     |
| `--unresolved`      | stderr             | Where the unresolved package names go, one per line |
| `--priority`        | `1001`             | `Pin-Priority` on every stanza                      |
| `--server`          | config             | Which bodega answers                                |
| `--suite`           | every served suite | Match against these suites only                     |
| `--allow-plaintext` | off                | Permit `--server` over `http`                       |

#### Why two artifacts

Pinning everything is the trap this command exists to remove. A `Pin: version` stanza naming a version no served suite publishes leaves apt with **no candidate at all** for that package: `apt update` stays quiet, and the failure surfaces at the next `apt upgrade` as a package that cannot be installed at any version. On one Ubuntu 22.04 host 8 of 635 installed packages were in that state, because `jammy-updates` drops what it supersedes and those versions had left the archive.

So a package that does not resolve is left out of the preferences file and named in the unresolved list instead. `apt-mark hold` is what to do with that list. Holding freezes the package where it is, which is the honest version of what a pin to an unavailable version was trying to say.

An unresolved package is not an error and never fails the command. It is the expected result for a version the archive has moved past, and exiting non-zero would break every configuration-management run wrapping this.

#### Why `Pin-Priority: 1001`

1000 is the threshold above which apt will downgrade. At 1000 a package that has already drifted ahead of its pin stays ahead; at 1001 apt pulls it back to the pinned version. The generated file says this in its header, because the file outlives the runbook. `--priority` takes any other value, and the header changes to match.

#### How a version is resolved

For each installed package, the command reads the `Packages` indices over HTTP the way an apt client does, and asks whether any suite this bodega serves publishes that exact version. Generated suites and mirrored codenames answer alike: bodega serves both under `/apt/dists/`, so a mirrored archive's index is read through the same route without the command fetching anything from upstream itself.

- The suites come from `GET /api/v1/status`, which reports both sets. `--suite` narrows that to a named list.
- Each suite's `Release` names its components and architectures. Only architectures this host has packages for are fetched.
- `Packages.gz` is read first, uncompressed `Packages` second.
- An **`Architecture: all` package is found inside `binary-<arch>`**, because that is where every archive publishes one. Nothing publishes `binary-all`, and looking for it there is how a naive match loses every architecture-independent package on the host: 158 of the 635 above.

Which bodega answers, in order: `--server`, `$BODEGA_SERVER`, `server_url`, `public_url`, then this host's own listener from `listen_addr`. The last one is for running the command on the bodega host itself. A loopback target is read over plaintext `http` without `--allow-plaintext`, because the refusal exists to keep a bearer token off a network others can read and there is no such network on `127.0.0.1`. The token comes from `$BODEGA_TOKEN` or `token` in the config file.

#### Gaps

- **`Packages.xz` is not read.** Go ships no xz decoder, and every archive publishing `.xz` publishes `.gz` beside it. An archive publishing only `.xz` is named in an error rather than counted as empty, since an index silently read as zero packages would turn every package in it into an unresolved one.
- **Coverage decays from the moment it is measured.** A version that leaves the archive while pinned turns into an apt error at the next `update`, not a warning now. Re-run this after every upgrade window and re-read the counts.
- **Nothing is installed and nothing is written to the manifest store.** The output is a file to review, then copy. Pinning a host is separate from cataloging it: see [Cataloging a host end to end](#cataloging-a-host-end-to-end).

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
| `--identity` | | Identity filter: the host name an identity binding resolved the request to |
| `--actor` | | Actor filter (CLI and TUI events, matched against the OS user) |
| `--since` | | Show events after this time (RFC3339 or YYYY-MM-DD) |
| `--limit` | `20` | Max events to show |

```bash
bodega audit events                                    # last 20 events
bodega audit events --type fetch --limit 50            # last 50 fetches
bodega audit events --pkg-type gomod --since 2026-04-07
bodega audit events --client 10.0.0.5
bodega audit events --identity build-07                # every request one host made
```

The `CLIENT` and `IDENTITY` columns are printed together and neither substitutes for the other: the deny list matched on the address, and one identity holds several. `IDENTITY` is blank on a request no binding resolved, which is every request until `bodega identity bind` runs.

### `bodega pkg checksum list [--type TYPE] [--name NAME]`

Lists cached SHA-256 checksums stored in the audit database.

### `bodega pkg checksum clear <type> <name> [--version VER]`

Clears cached checksums for a package. The next fetch recomputes and stores a fresh checksum. Use `--version` to clear only a specific version.

**The digest goes; the row stays.** For apt that row is also the record that tells a `.deb` the mirror cached from one bodega built, and the cached artifact sits in `pool/` long after its digest is cleared. Deleting the row would drop the artifact out of the mirrored-pool exclusion set while it is still there to be matched by filename, and the next rebuild would publish upstream bytes with no `SHA256` under bodega's own archive key. So a clear blanks the value and leaves the row where the index can still read it; the command says so before it acts.

Clearing twice is not an error and does not report a second removal — a 502 that survives the first clear is not a stale digest, and the output separates that from a package name spelled wrong.

`<type>` and `<name>` are matched against the identity the proxy derived from the object key when it cached the artifact, which is what `bodega pkg checksum list` shows in its `TYPE` and `NAME` columns. A cleared row shows `(cleared)` in that listing's `CHECKSUM` column.

```console
$ bodega pkg checksum clear apt nginx
apt: the digest goes, the row stays. Cached upstream .debs stay out of the index; the next fetch stores a fresh digest.
Cleared 3 checksum(s) for apt/nginx; the next fetch recomputes them.
$ bodega pkg checksum clear apt nginx
apt: the digest goes, the row stays. Cached upstream .debs stay out of the index; the next fetch stores a fresh digest.
3 row(s) for apt/nginx already carry no digest; nothing was cleared. A 502 that survives this is not a stale checksum.
$ bodega pkg checksum clear apt ngnix
apt: the digest goes, the row stays. Cached upstream .debs stay out of the index; the next fetch stores a fresh digest.
No cached checksums matched apt/ngnix; nothing was cleared. Run `bodega pkg checksum list --type apt` for the names this instance recorded.
```

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

### `bodega identity <bind|unbind|list>`

Maps something the serve path can observe about a request to a host name, so the audit and discovery tables say which host asked rather than only which address did.

Two kinds, because they answer different questions:

| Kind    | Key                   | Right for                               | Bootstrap                               |
| ------- | --------------------- | --------------------------------------- | --------------------------------------- |
| `token` | an `api_tokens` id    | naming one host precisely               | the host needs the credential first     |
| `cidr`  | a CIDR, stored masked | "everything on this subnet is a devbox" | none, but `trusted_proxies` must be set |

```bash
bodega identity bind cidr 10.20.0.0/16 devbox
bodega identity bind token 4f3c9a... build-07 --comment "CI runner"
bodega identity list
bodega identity unbind cidr 10.20.0.0/16
```

`bind token` refuses an id no token has, because a binding to a mistyped id is inert and looks identical to one that works: every request from that host resolves through the CIDR fallback, or to nothing, and the rows read as a host that never authenticated. `bodega token list` prints the ids.

**Resolution order on a request is token, then longest-prefix CIDR, then unidentified.** A token beats a CIDR that disagrees, because the credential is the more specific statement. A credential that matches no token, matches an expired one, or matches a token nothing is bound to falls through to the CIDR rather than refusing: this table decides what an audit row says, never what may be fetched. A request carrying no credential is served exactly as it was before any binding existed.

**One token or one CIDR resolves to at most one identity.** A second binding that would make the answer ambiguous is refused here, at write time, and the refusal names the binding it collided with:

```text
$ bodega identity bind cidr ::ffff:10.0.0.0/104 ci
refusing to bind cidr 10.0.0.0/8 to "ci": that cidr is already bound to "fleet".
  Already bound: cidr 10.0.0.0/8 -> fleet
  Remove it first (bodega identity unbind cidr 10.0.0.0/8), or bind to the same identity
```

Keys are normalized before they are stored, which is why that reads as a plain collision rather than an overlap: `10.20.5.9/16` bound is `10.20.0.0/16` listed, a bare address is a `/32` or `/128`, and `::ffff:10.0.0.0/104` is the same key as `10.0.0.0/8`. Two masked prefixes of the same length are then either the same key or disjoint, so the refusal always names the row you collided with and the command that undoes it.

Two prefixes of different lengths over the same addresses are fine, and are what longest-prefix resolution is for: `10.0.0.0/8` as `fleet` and `10.20.0.0/16` as `devbox` coexist, and `10.20.0.9` resolves to `devbox`.

Rebinding a key to the identity it already has is a no-op, not an error, so a config-management run can assert the binding every hour.

#### A CIDR binding needs `trusted_proxies` answered

`bodega serve` **refuses to start** when a CIDR binding exists and `trusted_proxies` is still the built-in default:

```
refusing to serve: 1 CIDR identity binding exists while trusted_proxies is still the
built-in default (loopback + RFC 1918).
  Every peer in that range has its X-Real-IP believed verbatim, so any of them can claim
  an address inside a bound network and collect that identity. Answer trusted_proxies
  either way:
    bodega acl proxies add <proxy-cidr>     name the proxy that terminates for clients
    "trusted_proxies": [] in /etc/bodega/config.json
                                            trust no forwarded header from anyone
  Leaving the default is what is not accepted.
  The live list:  bodega acl proxies list
  The bindings:   bodega identity list
```

The default trusts loopback plus RFC 1918, and bodega returns `X-Real-IP` verbatim from any peer in that set. On a default-configured instance a CIDR binding is therefore assertable by whoever sends a header, which is not a caveat to document: it is the binding meaning nothing. Both remedies are accepted. `bodega acl proxies add <cidr>` names the proxy that terminates for your clients and claims the list for the database, which is what ends the built-in default. `"trusted_proxies": []` in the config file claims it empty on the next start, so bodega answers to the peer address alone. There is no `acl proxies remove` path out of the default, on purpose: `remove` refuses a CIDR the list does not hold rather than claiming the list as a side effect, so a typo cannot silently move an instance from the default to trusting nobody.

It is a refusal rather than a warning because `log_level` defaults to `Error`, so a warning here is written for nobody and the instance runs anyway. `bodega identity bind cidr` prints the same guidance at bind time, so the interlock is discovered from the command that armed it rather than from a server that will not come back up. A token binding needs no proxy answer, because the credential is the claim; an instance carrying only token bindings starts unchanged.

**Binding on a running server is gated the same way, where the binding is read.** Startup is the rarer way into that state: the ordinary operator order is the reverse, because the server is already running when the bind happens. `bodega serve` came up with nothing bound and passed the check, and both paths that install a binding afterwards, `systemctl reload bodega` and the 30-second cache, land it behind that check. So resolution itself asks the same question. While `trusted_proxies` is unanswered, a CIDR binding resolves as absent: the request is served exactly as it was before, and the row names nobody rather than naming a host any RFC 1918 peer could have claimed with a header. Token bindings resolve throughout, because a credential is a claim the caller had to hold.

Entering that state writes one `ERROR` line naming both remedies, and leaving it writes one `INFO`. The operator who got there by binding never saw the startup refusal, and `bodega identity bind cidr` prints its warning to stderr on a command that commonly runs under config management with its output discarded:

```
ERROR CIDR identity bindings are inert while trusted_proxies is still the built-in
default; requests from a bound network are recorded unidentified bindings=1
remedy="bodega acl proxies add <proxy-cidr>, or \"trusted_proxies\": [] to trust no
forwarded header"
```

Answering `trusted_proxies` brings the bindings back with no restart: `bodega acl proxies add <cidr>` is picked up within the cache TTL, and the config-file form on the next start.

#### Where the identity shows up

`bodega audit events` gains an `IDENTITY` column beside `CLIENT`, and `--identity <name>` filters on it. `bodega discover show` gains `LAST IDENTITY` beside `LAST CLIENT`, and the CSV export carries `last_identity`. Neither replaces the address: the deny list matched on the address, one identity holds several, and a row that dropped it would lose which one asked.

```bash
bodega audit events --identity build-07 --limit 50
bodega audit events --type denied --identity build-07
```

Bindings are read per request through a 30-second cache, on the same schedule as the CIDR lists, so a change lands on a running server without a restart and at once on `systemctl reload bodega`.

### `bodega profile <create|list|show|bind|unbind|set|add|remove|pin|pins|unpin|diff|check>`

Declares what one class of host may fetch, and the version rule each package carries for that class. Everything else in bodega holds one answer for the whole fleet; a profile is the axis that varies by consumer.

A profile is a view over one catalog, never a second catalog. Storage, object keys, the checksum table and the manifests do not change: an artifact reached through two profiles is one artifact with one checksum.

The read path enforces this for pypi, npm, gomod, cargo, helm, git and binary. apt is not enforced at fetch time and is the deliberate exception; see [What is enforced, and where](#what-is-enforced-and-where). `bodega pin` is the host-side half of the same idea and is a different thing: it emits apt preferences for a host to apply, where a profile decides what bodega will answer.

Three levels:

| Level           | Command                | Decides                                                                                                         |
| --------------- | ---------------------- | --------------------------------------------------------------------------------------------------------------- |
| the profile     | `create`, `bind`       | which hosts it governs                                                                                          |
| the type marker | `set`                  | membership (`closed`, `open`), the version default (`pinned`, `floating`) and the expansion action for one type |
| the entry       | `add`, `pin`, `remove` | one package, and optionally a constraint overriding its type's default                                          |

```bash
bodega profile create web --description "public web tier"
bodega profile set web apt --membership closed --version-default floating
bodega profile add web apt nginx
bodega profile pin web apt postgresql 14.11 --reason "15 breaks the config" --review-after 2027-01-01
bodega profile pins --stale
bodega profile bind web db01
bodega profile show web
```

#### Membership and the version default

`set` writes the per-type marker. Both flags are optional on a type that already has one: what you do not name keeps the value it has.

| Flag                | Value      | Meaning                                          |
| ------------------- | ---------- | ------------------------------------------------ |
| `--membership`      | `closed`   | only the packages this profile lists             |
| `--membership`      | `open`     | every package of this type in the catalog        |
| `--version-default` | `pinned`   | only the version each entry names                |
| `--version-default` | `floating` | any version                                      |
| `--expansion`       | `warn`     | serve it, and record the reach outside the class |
| `--expansion`       | `block`    | refuse it with 403                               |
| `--expansion`       | `ignore`   | serve it and record nothing                      |

The marker's presence is itself an answer. A type with **no** marker is one the profile states no rule for, and the fleet-wide controls decide it alone; a type **with** a marker is decided by the profile even when no entry names a package.

#### Expansion: what a closed type does about a package it does not list

`--expansion` decides that, per type, and it **defaults to `warn`**. A new transitive dependency is ordinary upstream maintenance, and the cost of refusing one is a host that stops getting patched; `block` is for the profile where an operator has decided otherwise. It is the same `warn | block | ignore` triple `bodega policy age` and `bodega policy osv` carry.

`warn` serves the fetch and writes a discovery row with decision `denied`, so the reach outside the class lands in the table an operator already watches. Read it, then narrow:

```bash
bodega profile set web npm --membership closed   # warn, the default
bodega discover list npm                         # the denied rows are what the fleet reached for
bodega profile add web npm express               # the ones that belong
bodega profile set web npm --expansion block     # now refuse the rest
```

The row's `PATTERN` column carries the command that closes it, because nothing about a reach outside a profile is promoted into an allow-list rule and the column would otherwise hold a hint nobody can act on:

```text
$ bodega discover list gomod
TYPE   PATTERN                                             HOST              COUNT  DECISIONS    LAST SEEN
gomod  bodega profile add web gomod github.com/pkg/errors                    1      denied       2026-09-10 23:51
```

`ignore` writes nothing, which is the operator saying not to hear about this type at all.

Expansion applies to a closed type alone — an open type lists nothing to be outside of, and `bodega profile show` prints `-` for it. It does not touch a version constraint: an entry's constraint is a version an operator named on purpose, so a request outside it is refused whatever the expansion says.

That is why a `closed` type with `--expansion block` and nothing listed is a state you can reach, and why `set` and `remove` refuse it without `--force`:

```text
$ bodega profile set web apt --membership closed --expansion block
profile web would be closed for apt with no apt entries and expansion block, which permits nothing of that type.
  Every apt request from a host bound to this profile is refused, and the refusal names no package because none is listed.
  List something:  bodega profile add web apt <name>
  Open the type:   bodega profile set web apt --membership open
  Detect instead:  bodega profile set web apt --expansion warn
  Mean it:         re-run with --force, which accepts the empty closed set as written
```

#### Entries and constraints

`--constraint` is the third level, and it overrides the type's version default for one package in either direction: one pinned package inside a floating type, one floating package inside a pinned type. The four kinds are the ones a manifest version entry already carries.

```bash
bodega profile add web npm express --constraint exact --version 4.18.2
bodega profile add web npm lodash  --constraint any            # floats inside a pinned type
bodega profile add web gomod k8s   --constraint compatible --version 5.2.0
bodega profile add web pypi numpy  --constraint patch --version 1.26.4
```

With no `--constraint` the entry defers to its type's version default. Adding an entry that already exists edits it: every flag you give is written and every field you leave out keeps what it held, because changing the version a package is held at is the ordinary edit and a remove-then-add loses the reason in the gap. A bare `bodega profile add web apt postgresql` on a pinned entry therefore changes nothing; clearing a constraint is `unpin`.

`pin` is `add` with the pinning arguments filled in, and it **requires `--reason`**: a pin with no reason outlives the problem it was written for, and the next operator cannot tell a deliberate hold from an accident, so it is never lifted. `--review-after <YYYY-MM-DD>` gives it a date it stops looking current on, and it is refused unless it parses: a date stored as "next quarter" is a pin that is never overdue, and `pins --stale` would pass on it forever. Nothing enforces the date; `bodega profile pins` is what reads it.

A pin is not local, so `pin` reports the dependency closure before it writes anything. See [Pins as recorded decisions](#pins-as-recorded-decisions).

`unpin` drops the constraint and keeps the entry, so the package stays a member. The version the pin named stays on the entry as its base, because that is the shape a pinned type default reads: an entry with a version and no constraint of its own is held at that version, and one with neither is a pin with nothing to pin to, which permits no version at all. A floating default ignores the base and takes any version. `unpin` says which of the three it left you in:

```text
$ bodega profile unpin vd pypi numpy
Released the pin on pypi/numpy in vd; the pypi default is pinned, so it holds at 1.26.4.

$ bodega profile unpin fl pypi requests
Released the pin on pypi/requests in fl; the pypi default is floating, so it takes any version.

$ bodega profile unpin nv2 pypi requests
Released the pin on pypi/requests in nv2; the pypi default is pinned and the entry names no version, so it now permits nothing.
  Give it one:   bodega profile pin nv2 pypi requests <version> --reason <why>
  Or float it:   bodega profile add nv2 pypi requests --constraint any
```

A `pypi` entry is matched PEP 503 normalized, on both sides of the comparison: `django` covers the wheel pypi publishes as `Django-4.2.11-py3-none-any.whl`, and `python-3parclient` covers the sdist PEP 625 writes as `python_3parclient-4.2.10.tar.gz`. Compared literally the gate refuses a distribution the profile lists, and worse, the mismatch reads as a package outside the set, where the version rule is skipped and the pin never applies. No other type is normalized: `gomod` module paths and `git` namespaces are case-sensitive by specification, and `cargo` refuses a crate name that is not already lowercase.

The verbs match the same way. `add`, `pin`, `unpin` and `remove` find the entry under whichever spelling you type, so `bodega profile remove ops pypi Django` removes the entry stored as `django` instead of reporting it absent, and re-adding a package under its other spelling edits that entry rather than writing a second row beside it. `bodega profile diff` compares both sides under the same rule, so a profile listing `django` against a host cataloged with `Django` reports no drift. A document naming both spellings is refused at `create --from-file`, because only one of the two constraints would survive:

```text
entries[0] and entries[1] both name pypi/django, which is one entry: the later row would replace the earlier, taking its constraint, reason and review date with it.
  "django" and "Django" are one project once the name is normalized, which is the form the gate compares
  Keep the one you mean
```

`remove` deletes the entry, which on a closed type means the package is no longer permitted at all.

#### Pins as recorded decisions

A pin is a decision to stop receiving updates for one package. "Pinned at 14.9" and "not receiving security updates for postgres" are the same sentence, and only one of them normally gets written down. **A pin accepts the known vulnerabilities in that version for the life of the pin**, and `bodega profile pins` is where that acceptance is legible.

```bash
bodega profile pins            # every pin in every profile
bodega profile pins db         # one profile
bodega profile pins --stale    # only the overdue ones; exits 1 when any is found
bodega profile pins --json     # the records the API returns
```

Nothing else in a normal stack holds both halves. `apt-mark hold` knows the hold and not the advisories; a scanner knows the advisories and not why you are on that version. bodega stores the pin and keeps the OSV answer current, so the report carries the decision and the findings in one row:

```text
$ bodega profile pins
PROFILE  TYPE  PACKAGE  VERSION  PINNED      BY    REVIEW AFTER  OVERDUE  OSV        CHECKED     REASON
web      pypi  django   4.2.11   2026-03-02  ravi  2026-08-01    41d      flagged    2026-09-09  5 drops the middleware
ci       pypi  django   4.2.12   2026-09-11  ravi  -             -        unchecked  -           reproducing a build

web pypi/django at 4.2.11 accepts 1 known advisory(ies) for the life of the pin:
  GHSA-xxxx-yyyy-zzzz  CVSS_V3 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

The `OSV` column is the stamp [`bodega policy osv rescan`](#rescan) writes, and it reads `unchecked` rather than `clean` for a version no run has ever answered for. An empty advisory list means nobody looked as often as it means there is nothing to find, and a pin is the one place that distinction decides whether somebody acts. `n/a` is a registry type OSV holds no records for. A pinned version the catalog no longer carries is called out under the table, because there is no stamp to read for it.

`PINNED` is when the held version was last decided, which is not when the entry was created: moving a pin to a new version re-dates it, and correcting its reason with `add` does not. A row written before that column existed falls back to the entry's own creation date, which is a lower bound rather than a guess.

`--stale` exits 1, so it works as a CI or cron gate the same way `bodega profile check` does. A pin with no review date is never stale, which is what makes `--review-after` worth writing.

**The closure.** Holding postgresql-14 at 14.9 holds everything 14.9 was built against: a dependency edge names the version the parent needs, and pinning the parent does not move it. apt meets that during an upgrade, as a widening set held back or a proposal to remove the package. bodega sits on the index and holds the graph, so `pin` says it first:

```text
$ bodega profile pin db apt postgresql-14 14.9 --reason "15 breaks the config"
Pinning apt/postgresql-14 at 14.9 holds 2 other package(s) still:
  PACKAGE      HELD AT  VIA                SPEC
  apt/libpq5   14.9     apt/postgresql-14  libpq5 (= 14.9)
  apt/libssl3  -        apt/postgresql-14  libssl3 (>= 3.0.0)
  conflict: apt/postgresql-14 at 14.9 needs apt/libpq5 14.9, and the profile refuses it: profile "db" does not permit apt/libpq5 at 14.9: pinned to 15.1
  Pin the closure too:  --strict-closure
Added apt/postgresql-14 in db (exact 14.9).
```

`HELD AT` comes from the relation the dependency was declared with, not from what happens to be installed. `libpq5 (= 14.9)` holds a release still and reads `14.9`; `libssl3 (>= 3.0.0)` is a floor that may move upward whatever postgresql-14 is pinned at, so it reads `-` and `--strict-closure` has nothing to pin it to. The language discoverers record the version on every edge, so a pypi or gomod closure resolves throughout.

**Reporting is the default and freezing is not.** The default pins the one package you named and tells you what it implies. `--strict-closure` pins every closure member at the version the graph records, with a reason naming the pin that implied it. Extending by default would freeze a growing set: each package pinned drags its own dependencies in, and a host would stop receiving security updates for all of them with nobody having decided that it should. A closure member the graph records no version for is left floating and said so, because pinning it would mean choosing a release on your behalf.

`--strict-closure` also leaves alone any entry somebody already gave a reason, and names each one it refused to move:

```text
--strict-closure: left apt/libpq5 at 15.1 alone; it carries a reason somebody wrote: CVE-2026-1111 fixed in 15.1
  Move it deliberately:  bodega profile pin db apt libpq5 <version> --reason <why>
```

That entry is usually the one the conflict line names, which makes it the entry the command is being run to resolve. Overwriting it would take the version backward across whatever fix its reason records and replace the reason with a generated string, leaving the word `Updated` as the only trace. An entry `--strict-closure` wrote itself carries the `implied by` reason and is refreshed on the next run, because that record is this command's own.

The same feasibility check runs at apt index generation, where it reports and extends nothing. A pin whose own closure the profile contradicts is logged with the conflict and the command that would resolve it.

**What this is not.** bodega reports what it knows about what it serves and tracks no remediation: there is no suppression workflow, no ticket integration and no severity SLA here. The pin's own reason and review date are the whole of its suppression concept, and that boundary is deliberate — the tool that tracks remediation reads `GET /api/v1/profiles/{name}/pins` and owns the rest.

#### Building a profile from a host

`--from-origin` collects the packages carrying that host as an origin — the field `bodega pkg convert --origin` records — and writes them to a file. It creates nothing:

```bash
bodega profile create db --from-origin db01 --out db.json --pin postgresql
$EDITOR db.json
bodega profile create db --from-file db.json
```

`--from-file` reads the whole document before it writes anything, through the same checks `add` and `set` make: a package type outside the eight, an entry with no name and a constraint with no version are each refused with the offending line named. A key named twice is refused the same way, naming both lines: one type carries one marker and one package carries one entry, so the later row would replace the earlier and take its constraint, reason and review date with it. The profile, its markers and its entries then land in one transaction. A document rejected halfway would otherwise leave a bindable profile holding a subset of what was authored, which is not a failed create but a working access control permitting less than anyone wrote.

The round trip through a file is the review step, and `--out -` and `--from-file -` are both refused. A host's inventory holds its accidents alongside its requirements, and locking membership to it enshrines whatever was installed by hand at 03:00; a baseline piped straight from the command that produced it was never read by anyone.

For the same reason `--out` refuses a path that already holds something. On every run after the first that file is the one the operator edited, and a silent overwrite discards the review while reporting a successful write. `--overwrite` replaces it:

```text
$ bodega profile create db --from-origin db01 --out db.json
db.json already exists, and a baseline is written to be edited before it is used.
  Read what is there:  bodega profile create <name> --from-file db.json
  Write somewhere else:  --out <other path>
  Replace it, losing whatever it holds:  --overwrite
```

Entries default to name-only with `constraint_kind: any`, so the baseline says what the host may fetch and not which build of it. `--pin <name>` (repeatable) names the exceptions. A baseline that pins every version is re-authored monthly until somebody stops, which is how a control becomes ignored.

A `--pin` that does not name one package is refused rather than resolved, on either axis. Two cataloged versions:

```text
$ bodega profile create db --from-origin db01 --out db.json --pin requests
--pin requests: pypi/requests is cataloged from db01 at 2 versions (2.31.0, 2.32.0), so a pin here would pick one for you.
  Create the profile, then name the version:  bodega profile pin db pypi requests <version> --reason <why>
```

Or one name under two types:

```text
$ bodega profile create db --from-origin db01 --out db.json --pin psycopg2
--pin psycopg2: psycopg2 is cataloged from db01 under 2 types (pypi, npm), so a pin here would pick one for you.
  Name the one you mean:
  --pin pypi/psycopg2
  --pin npm/psycopg2
```

`--pin <type>/<name>` is the qualified spelling, and it pins the one it names while the other stays floating. The baseline is walked in a fixed type order, so resolving a bare name would let that order decide which package an operator holds.

Naming one package twice is refused too, whichever spellings are used. The count in the success line is what an operator checks against the flags they typed, and two names for one package are either a slip or two versions meant for one entry:

```text
$ bodega profile create dp --from-origin db01 --out dp.json --pin psycopg2 --pin pypi/psycopg2
--pin psycopg2 and --pin pypi/psycopg2 both name pypi/psycopg2, which is either a slip or two versions meant for one package.
  Name it once:  --pin pypi/psycopg2
```

A slash is read as the qualifier only when what precedes it names one of the eight types, none of which carries a slash. So `--pin @babel/core` and `--pin github.com/lib/pq` each name one npm or gomod package, and the qualified spellings for them are `npm/@babel/core` and `gomod/github.com/lib/pq`.

#### Binding hosts

`bind` attaches a profile to one of the identities `bodega identity` resolves, so bodega answers "which host is this" once and the profile says what that host may fetch. One identity resolves to at most one profile; binding an identity that is already bound moves it and says where it came from.

```bash
bodega identity bind cidr 10.20.0.0/16 devbox
bodega profile bind web devbox
bodega profile unbind devbox
```

`bind` refuses a name no identity binding produces. A profile bound to a typo is inert: no request ever resolves to that name, so the profile is never consulted and nothing reports it. `--force` binds ahead of the identity binding. The same inertness arrives later when the identity binding is removed underneath a live profile binding, so `bodega profile show` marks a bound host no identity binding still resolves to.

#### Falsifying a profile: `diff` and `check`

```bash
bodega profile diff db --origin db01
bodega profile check
bodega profile check db
```

`diff` names what the host has that the profile does not list and what the profile lists that the host does not have. Without it a baseline written six months ago and a host that has moved on look identical from the outside.

`check` is the CI gate and exits 1 on any violation, the same contract `bodega policy check` has. It asks whether each entry permits at least one version the catalog can serve, so a pin the catalog dropped, a pin whose version was hidden and a range constraint nothing satisfies are all caught:

```text
$ bodega profile check db2
PROFILE  TYPE  PACKAGE   REASON
db2      pypi  requests  exact 9.9.9 permits none of the cataloged versions (2.31.0)
Error: 1 profile violation(s) detected
```

A manifest the store cannot read stops the gate instead of appearing in that table. The two repairs are opposite ones: a missing package means the entry names something the catalog dropped, and an operator reading that in CI deletes the entry, which is the wrong fix for a catalog that is merely unreadable.

```text
$ bodega profile check web
Error: load pypi/requests: parse package pypi/requests: invalid character 'o' in literal null (expecting 'u')
```

#### What is enforced, and where

Two enforcement points, and the order matters.

**The request predicate is the control.** It runs on every package route for pypi, npm, gomod, cargo, helm, git and binary, and answers 403. A client that already holds a tarball URL fetches it without reading any index, so an implementation that only filtered indexes would enforce nothing.

**The index filter is what makes the refusal legible.** A resolver told "no such version" picks another one; a resolver handed an opaque 403 halfway through an install stops with a stack trace and leaves the environment half-built. Six documents are filtered: the pypi simple root and its per-distribution pages, the npm packument's `versions` map (with the `time` entries and `dist-tags` that point at dropped versions), the gomod `@v/list`, the cargo sparse index, and the helm `index.yaml` (which answers 200 with the refused charts absent rather than 403, because a refused index fails `helm repo add` itself). git and binary publish no index, so the predicate is the whole story there.

**apt is deliberately excluded**, and is tracked separately. Refusing an apt fetch at the pool leaves `dpkg` holding a half-configured transaction, which is a worse outcome than no control at all; the apt answer belongs at the generated index, not at fetch time.

No filtered index is stored. Each one is produced by running the profile's filter over the response on the way out, so what sits in the cache is the document the upstream served and one cached object answers every host class correctly. An install with no profiles pays nothing, and a fleet with twenty profiles pays one copy and one upstream fetch per index rather than twenty. A cache hit filters identically to a miss, so a `bodega profile` edit lands within the binding cache TTL rather than at the next upstream refresh. The helm `index.yaml` is generated into storage by `bodega build` rather than cached, and is filtered the same way on the way out.

An HTTP cache in front of bodega is the other half of that, and it is a deployment setting rather than a bodega one: every enforced artifact goes out `private` and every enforced index `no-cache, no-store, must-revalidate`, so a proxy that obeys its response headers is safe and one told to ignore them is not. See [Caching in front of a profile-enforced bodega](#caching-in-front-of-a-profile-enforced-bodega).

Every refusal writes an audit row naming the profile, the package, the version and which rule refused it. The two rules are separate statuses, because the repairs are opposite:

```bash
bodega audit events --type denied
```

```text
TIMESTAMP            EVENT   TYPE   NAME                   STATUS               CLIENT     IDENTITY
2026-09-10 23:52:00  denied  pypi   requests               profile_constraint   127.0.0.1  web01
2026-09-10 23:51:46  denied  gomod  github.com/pkg/errors  profile_membership   127.0.0.1  web01
```

| Status               | Means                                         | Repair                         |
| -------------------- | --------------------------------------------- | ------------------------------ |
| `profile_membership` | the package is outside a closed profile's set | `bodega profile add`, or widen |
| `profile_constraint` | the version is outside the profile's rule     | `bodega profile pin`, or unpin |

#### What each client shows when it is refused

The message differs per ecosystem, and three of the seven print bodega's own body verbatim. That is why the refusal names the repair:

```text
membership: profile "web" does not list gomod/example.com/mod at v1.0.0.
  Add it:      bodega profile add web gomod example.com/mod
  Or open it:  bodega profile set web gomod --membership open
```

**pypi.** A filtered index reads to `pip` as a distribution that publishes nothing, so it resolves against what is left rather than failing on what is gone:

```text
$ pip install django
Looking in indexes: http://bodega:8080/pypi/simple/
ERROR: Could not find a version that satisfies the requirement django (from versions: none)
ERROR: No matching distribution found for django
```

A refused wheel, which is a client that already knew the URL, names the file and the status:

```text
$ pip install ok
Collecting ok
  ERROR: HTTP error 403 while getting http://bodega:8080/pypi/wheels/ok-1.0.0-py3-none-any.whl (from http://bodega:8080/pypi/simple/ok/)
ERROR: Could not install requirement ok from http://bodega:8080/pypi/wheels/ok-1.0.0-py3-none-any.whl because of HTTP error 403 Client Error: Forbidden for url: http://bodega:8080/pypi/wheels/ok-1.0.0-py3-none-any.whl
```

A filename bodega cannot place onto a project and a version is refused under the filename itself, so the body and the audit row name a file where they normally name a package. `pip` never asks for one of these; they are `bdist_wininst` and `.egg` files predating the wheel:

```text
membership: profile "web" does not list pypi/msgpack-python-0.3.0.win-amd64-py2.7.exe.
  Add it:      bodega profile add web pypi msgpack-python-0.3.0.win-amd64-py2.7.exe
  Or open it:  bodega profile set web pypi --membership open
```

Take the repair it prints literally and the entry matches nothing else. Name the real project, or open the type.

**npm.** The same text for a packument and for a tarball, with the URL as the only thing that tells them apart. It does not print bodega's body:

```text
$ npm install ok
npm error code E403
npm error 403 403 Forbidden - GET http://bodega:8080/npm/ok/-/ok-1.0.0.tgz
npm error 403 In most cases, you or one of your dependencies are requesting a package version that is forbidden by your security policy, or on a server you do not have access to.
```

**gomod.** `go` prints the whole response body under `server response:`, so the operator reading the failure gets the repair without opening the audit log:

```text
$ go get example.com/mod@v1.0.0
go: example.com/mod@v1.0.0: reading http://bodega:8080/go/example.com/mod/@v/v1.0.0.info: 403 Forbidden
	server response:
	membership: profile "web" does not list gomod/example.com/mod at v1.0.0.
	  Add it:      bodega profile add web gomod example.com/mod
	  Or open it:  bodega profile set web gomod --membership open
```

**cargo.** Also prints the body, under `body:`, and names the sparse-index URL rather than the crate:

```text
$ cargo fetch
Caused by:
  failed to get successful HTTP response from `http://bodega:8080/cargo/se/rd/serde` (10.0.0.4), got 403
  body:
  membership: profile "web" does not list cargo/serde.
    Add it:      bodega profile add web cargo serde
    Or open it:  bodega profile set web cargo --membership open
```

**helm.** `helm repo add` succeeds and the charts are simply not there. The index answers 200 with the refused charts filtered out of it, because a 403 on `index.yaml` fails the repository rather than the install, so the first thing an operator sees is an empty search:

```text
$ helm repo add bodega http://bodega:8080/helm
"bodega" has been added to your repositories
$ helm search repo bodega
No results found
```

The refusal arrives at the pull, and helm prints neither the chart name nor bodega's body. This is the ecosystem where the audit row is the only place the reason lives:

```text
$ helm pull bodega/cert-manager --version 1.14.0
Error: failed to fetch http://bodega:8080/helm/charts/cert-manager-1.14.0.tgz : 403 Forbidden
```

**git.** `git` relays the body as `remote:` lines before its own error:

```text
$ git clone http://bodega:8080/git/github/foo/bar.git
Cloning into 'bar'...
remote: membership: profile "web" does not list git/github.
remote:   Add it:      bodega profile add web git github
remote:   Or open it:  bodega profile set web git --membership open
fatal: unable to access 'http://bodega:8080/git/github/foo/bar.git/': The requested URL returned error: 403
```

**binary.** Whatever the fetcher says about a 403. `curl -fSL` exits 22 and prints no body; `wget` exits 8 and names the status:

```text
$ curl -fSL http://bodega:8080/binaries/tool/1.0/tool.tar.gz -o tool.tar.gz
curl: (22) The requested URL returned error: 403

$ wget http://bodega:8080/binaries/tool/1.0/tool.tar.gz
HTTP request sent, awaiting response... 403 Forbidden
2026-09-10 16:43:44 ERROR 403: Forbidden.
```

`-f` is what hides the reason: it makes `curl` fail without writing the body. Drop it to read the refusal, and note that it also drops the non-zero exit, so a script needs `-w '%{http_code}'` to keep both.

Every mutation writes an audit event with `pkg_type=profile`, the profile in `pkg_name` and what inside it in `pkg_version`, so `bodega audit events --type create` shows who changed a control and when.

### `bodega doctor [--write-credentials --token TOKEN [--url URL]]`

Without flags, `doctor` reports and changes nothing. With `--write-credentials` it writes one token into the file each of the eight clients reads its credential from, because a feature that costs eight hand edits does not get adopted:

```bash
bodega token generate devbox-3
bodega identity bind token <id> devbox-3
bodega doctor --write-credentials --token bodega_ak_... --url https://bodega.internal
```

`--url` defaults to `public_url` from the config file. Five files serve the eight clients:

| Client   | File                               | Form                                   |
| -------- | ---------------------------------- | -------------------------------------- |
| `apt`    | `/etc/apt/auth.conf.d/bodega.conf` | netrc, `machine <scheme>://<host>`     |
| `pip`    | `~/.netrc`                         | read through requests                  |
| `npm`    | `~/.npmrc`                         | `//host/npm/:_authToken=`              |
| `gomod`  | `~/.netrc`                         | read for the `GOPROXY` host            |
| `cargo`  | `~/.cargo/credentials.toml`        | `[registries.bodega] token`            |
| `helm`   | helm's own config path (see below) | `username` / `password` on the repo    |
| `git`    | `~/.netrc`                         | read through libcurl                   |
| `binary` | `~/.netrc`                         | `curl --netrc`; wget reads it already  |

pip, go, git and curl/wget all read `~/.netrc`, so one host-scoped entry serves four clients and there is one secret to rotate rather than four. The table `doctor` prints reports `current` for the three that find the entry the first already wrote.

apt gets a file to itself because its `machine` line carries the scheme, which plain netrc does not understand. Bare, apt matches the host and then declines: `Credentials for <host> match, but the protocol is not encrypted. Annotate with http:// to use.` — so an unannotated entry is inert on every plaintext deployment. `doctor` writes the scheme from `--url`, which also keeps the credential to the scheme bodega told clients to use rather than offering it on both. Verified against apt 2.8.3 on noble over `http` and `https`; the `#` fence is a comment to apt's parser and is skipped.

A second run replaces bodega's own entry rather than stacking another beside it, and nothing else in those files is touched. Where the format allows a comment anywhere, the entry is fenced by a marker; the fence is never the anchor, because bodega does not own these files. `cargo login`, `helm repo add` and `npm config set` each re-serialize the file and drop comments doing it, which takes the fence with them. So `doctor` finds its own entry by the key that entry carries: cargo's `[registries.bodega]` table, the repository named `bodega`, the `//<host>/npm/:_authToken=` line. `~/.netrc` gets no fence at all. Python's `netrc` module refuses a `#` line preceded by a blank one, and refuses the whole file rather than the entry, so a marker appended after the blank line that idiomatically separates stanzas costs pip every credential in the file, and silently: `requests` catches the parse error and sends no credential, while libcurl reads the same file without complaint, so git and curl keep working while pip stops. There the `machine <host>` stanza is the whole anchor, which is what it already had to be. No client rewrites that file, but an operator who configured bodega by hand before this command existed left a stanza in it, and appending beside it would put two credentials for one host in a file its four readers disagree about. libcurl takes the first match and Python's `netrc` module the last, so git, curl and wget would keep presenting the pre-rotation secret while pip presented the new one, and the table would report four successes. What the second run guarantees is one bodega entry holding the new token, in a file its client still parses. Stacking a second entry is not cosmetic: cargo rejects a duplicate key and stops reading the file at all, taking the operator's crates.io token with it, and helm resolves a chart through the first matching entry, which would be the pre-rotation one. The apt file needs root and the other four do not; a run as a normal user configures seven clients, names the one it could not, and exits 2.

helm's path is the one that is not the same everywhere: `doctor` resolves it the way helm does, `$HELM_REPOSITORY_CONFIG` first, then `$XDG_CONFIG_HOME/helm/repositories.yaml`, then the platform default, which is `~/Library/Preferences/helm/repositories.yaml` on macOS and `~/.config/helm/repositories.yaml` elsewhere. The table prints the path it resolved. `repositories.yaml` is also the one target where appending is not always legal. A file whose `repositories:` list is not last would take an appended entry into whatever key followed, and a `repositories: []`, which is what `helm repo remove` leaves when it removes the last repository, has no list to append under at all: a block sequence written there is a second value for one key, and helm rejects the whole file. `helm repo list` reports no repositories and exits 0 over that, so the damage would surface at the next `helm repo add` with nothing connecting it to the doctor run. Both shapes are refused, with the `helm repo add bodega <url> --username bodega --password <token>` line to run instead.

Writing a credential changes what an audit row says, never what the host may fetch. It does change what the host may **write**, which is why `doctor` prints this before it touches a file:

```text
Before writing: bodega tokens carry no scope, so this same token is the
credential half of the mutation gate. A host that holds it and whose address
is inside admin_permit_cidr can POST and DELETE against this bodega.
  Keep admin_permit_cidr at loopback (bodega acl admin list), or treat every
  host you write a credential to as admin-capable.
```

`bodega token generate` takes a label and nothing else: a token is a token. The mutation gate accepts any unexpired one of them once `admin_permit_cidr` reaches past loopback, so the credential in a build host's `~/.netrc` is also the credential that authorizes `POST /api/v1/...` from that host. Keeping `admin_permit_cidr` at loopback makes the gate ignore tokens entirely and is the remedy that costs nothing; otherwise every host you write a credential to is admin-capable and should be treated that way. Scoped tokens would sever the two and do not exist yet. See [Threat model](THREAT_MODEL.md).

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

### `bodega policy osv <sync|set|list|remove|rescan>`

Matches every `(ecosystem, name, version)` an import carries against a local copy of the OSV database and warns or blocks on the per-ecosystem policy.

```bash
bodega policy osv sync
bodega policy osv set cargo block
bodega policy osv set npm warn
bodega policy osv list
bodega policy osv rescan --type npm
bodega policy osv remove npm
```

`sync` is the only OSV subcommand that reaches the network. Admission reads the synced directory and nothing else, unless `osv_api_fallback` is on.

| Key | Default | Meaning |
|-----|---------|---------|
| `osv_db_dir` | `{storage_path}/osv` | Directory holding one archive and one metadata file per ecosystem |
| `osv_api_fallback` | `false` | Authorize a live `api.osv.dev` query when the local copy cannot answer |
| `osv_db_max_age` | `168h` | How old a synced ecosystem may be before a clean answer warns instead of passing |

The fallback is off by default because the deployment this gate exists for cannot reach `api.osv.dev`: with it on, every version stalls for the 15-second client timeout against a host that never answers, once per version, which a 635-package import pays 635 times.

#### Sync

```
$ bodega policy osv sync
ECOSYSTEM  OSV               RECORDS  PACKAGES  SIZE       FETCHED
apt        Ubuntu:22.04:LTS  36268    2594      8.2 MiB    2026-09-11T21:28:15Z
apt        Ubuntu:24.04:LTS  31958    2399      3.6 MiB    2026-09-11T21:28:15Z
cargo      crates.io         2701     1610      120.1 KiB  2026-09-08T01:53:24Z
gomod      Go                8968     1588      402.9 KiB  2026-09-08T01:53:25Z
npm        npm               228106   224290    3.8 MiB    2026-09-08T01:53:43Z
pypi       PyPI              24755    13281     1.1 MiB    2026-09-08T01:53:27Z

Wrote /var/lib/bodega/osv
skipped apt: OSV publishes no Ubuntu or Debian export for suite "plucky"
```

Name ecosystems to sync a subset (`bodega policy osv sync npm pypi`). The no-argument form syncs everything the gate covers, `apt` included, so it pulls the aggregate `Ubuntu` and `Debian` archives whether or not this install serves apt: name the ecosystems to skip that. `apt` expands to one row per release, and the set is the suites this install serves plus the releases its own manifests record on `capture_suite`: the gate answers an entry from the release that entry carries, which is not always a suite anything is published to, and a release nothing fetched is an entry the gate warns on forever while naming a sync that cannot fix it. Releases that resolve to the same distro come out of one download. Each archive is written under a temporary name and renamed, so an interrupted sync leaves the previous copy in place rather than a half-written one the gate would read as truth. An apt manifest that will not parse is named on stderr and the releases only it records are left out, rather than failing the run: that read happens before the first download, and npm, pypi, gomod and cargo have nothing to do with the file.

A set where nothing resolves to a release is a skip rather than a failure: the mirror configuration under [Mirroring an upstream archive](#mirroring-an-upstream-archive) serves only house names, so an install of it holding no apt captures yet names them on stderr and still exits 0 once the other ecosystems have written. Naming `apt` on the command line there exits non-zero, because that request asked for an export and fetched nothing. Once it has imported one capture, the house name is still named on stderr and that capture's release is fetched beside it.

An export that distills to no packages fails that ecosystem's row and writes nothing. Otherwise it would land a database with a current fetch time, and every version in the ecosystem would read clean for the whole `osv_db_max_age` window: `RECORDS 0` shows once in this table and never again.

The numbers are the distilled database, not the download: OSV's npm export is 222 MB of JSON, and what lands on disk is 3.8 MB because sync keeps the ids, summaries, severities and affected ranges and drops the prose. A full sync of the four language ecosystems takes about 15 seconds on a home connection and leaves around 5.5 MB on disk. `apt` costs more on both counts, because the aggregate `Ubuntu` archive is 681 MB and `Debian` 330 MB: measured 2026-09-11, two Ubuntu releases out of one download took 64 seconds and wrote 11.9 MiB.

#### Air-gapped

`sync` is a network fetch and nothing else, so the connected host and the enforcing host need not be the same:

```bash
# On a host with a route to the internet:
bodega policy osv sync
tar czf osv-db.tar.gz -C /var/lib/bodega osv

# On the restricted host:
tar xzf osv-db.tar.gz -C /srv/bodega
# set "osv_db_dir": "/srv/bodega/osv" in config.json, or unpack under
# {storage_path}/osv and leave the key alone
bodega policy osv list   # confirm the fetch times came across
```

The directory carries its own fetch timestamps, so a copy that stopped being refreshed reports its real age rather than the day it was copied.

#### Staleness and the missing database

A gate that cannot answer does not report a clean result. With no local database for an ecosystem, or one older than `osv_db_max_age`, a version with no known records is `warn`, never `pass`, and the import says so on stderr as it happens:

```
$ bodega pkg import lodash.json
npm/lodash: 4 versions (4.17.4, 4.17.5, 4.17.6, ...): osv: no local OSV database for npm in /var/lib/bodega/osv; run `bodega policy osv sync`; osv_api_fallback is off, so nothing was queried
Imported npm/lodash (4 version(s))

$ bodega pkg import lodash.json     # database synced in March
npm/lodash: 4 versions (4.17.4, 4.17.5, 4.17.6, ...): osv: local OSV database for npm is 178d old (synced 2026-03-14T01:53:43Z); run `bodega policy osv sync`
```

Every version of a package hits the same degraded gate, so the reason is stated once and names the versions it covered rather than repeating per version. The mutation API returns the same lines in the `warnings` array of each import result, and the audit trail records the version-level detail under `policy_warn` either way.

A stale database still blocks on what it does hold — old data names old vulnerabilities correctly — and the age rides along in the reason. With `osv_api_fallback` on, a stale or missing ecosystem is answered from `api.osv.dev` instead, and only a failed query falls back to the stale copy.

`bodega policy osv list` reports the state per ecosystem, so a gate that is current is distinguishable from one that stopped syncing in March:

```
$ bodega policy osv list
ECOSYSTEM  ACTION  UPDATED     DB SYNCED             DB AGE
gomod      block   2026-09-08  never                 -
npm        block   2026-09-08  2026-09-08T01:53:43Z  47s
pypi       warn    2026-09-08  2026-09-08T01:53:27Z  1m4s

Local OSV database: /var/lib/bodega/osv (api.osv.dev fallback: off)
```

The `apt` row spans one index per release, over the same set `sync` resolves: the served suites plus the releases the manifests record on `capture_suite`. It reports the oldest of them and `never` if any one is absent, so a captured-only release nothing has fetched shows up here and not only when `rescan` answers `unanswered` for it.

Coverage is the set of registry types the gate can query, which is also the set of exports `sync` fetches:

| Type  | OSV ecosystem                                                           |
| ----- | ----------------------------------------------------------------------- |
| npm   | `npm`                                                                   |
| pypi  | `PyPI`                                                                  |
| gomod | `Go`                                                                    |
| cargo | `crates.io`                                                             |
| apt   | one per release (`Ubuntu:22.04:LTS`, `Debian:12`); see [apt](#apt)      |

`binary`, `git` and `helm` have no OSV identifier. `set` refuses them:

```
$ bodega policy osv set helm block
Error: the OSV gate does not cover ecosystem "helm": the row would be stored and never read, leaving the gate silently off; set one of apt, cargo, gomod, npm, pypi instead
```

Earlier versions wrote that row, printed `Set helm OSV policy: block`, and then passed every helm version, because the checker short-circuits on any type outside the table above. Nothing reported the gap. The refusal replaces a gate the operator believed was on. It does not remove the rows already written: `bodega policy osv list` names them under the table and `bodega doctor` reports them, in the shape shown under [`bodega policy age`](#bodega-policy-age-setlistremove).

#### apt

apt is keyed on the release rather than on one ecosystem identifier, and that keying is the whole reason it is not another row in the table above.

Ubuntu and Debian fix a vulnerability by backporting the patch into the package revision. The upstream version does not move. `openssl 3.0.2-0ubuntu1.15` on jammy carries fixes for CVEs upstream fixed in 3.0.9; `expat 2.4.7-1ubuntu0.4` carries the fix for CVE-2024-45490, which upstream fixed in 2.6.2. Ask a generic ecosystem about "openssl 3.0.2" and every one of those comes back as a finding against a host that has been patched for a year. Findings at that volume teach an operator to stop reading the output, which costs more than the gate was going to give back.

OSV carries `Ubuntu` and `Debian` ecosystems sourced from USN and DSA, and the fixed versions in them are the distro's own revisions. Three things have to line up before that data can answer.

**The ecosystem comes from the release the entry itself records.** A pocket suffix is stripped, so `jammy-security` resolves the same as `jammy`.

| Suite      | OSV ecosystem      | Suite      | OSV ecosystem |
| ---------- | ------------------ | ---------- | ------------- |
| `trusty`   | `Ubuntu:14.04:LTS` | `wheezy`   | `Debian:7`    |
| `xenial`   | `Ubuntu:16.04:LTS` | `jessie`   | `Debian:8`    |
| `bionic`   | `Ubuntu:18.04:LTS` | `stretch`  | `Debian:9`    |
| `focal`    | `Ubuntu:20.04:LTS` | `buster`   | `Debian:10`   |
| `jammy`    | `Ubuntu:22.04:LTS` | `bullseye` | `Debian:11`   |
| `noble`    | `Ubuntu:24.04:LTS` | `bookworm` | `Debian:12`   |
| `questing` | `Ubuntu:25.10`     | `trixie`   | `Debian:13`   |
| `resolute` | `Ubuntu:26.04:LTS` | `forky`    | `Debian:14`   |

A codename is absent when OSV carries no release's worth of records for it, which is every superseded interim Ubuntu release: measured 2026-09-11, `mantic`, `oracular` and `plucky` answer with 3, 3 and 4 records across ten probed source packages, against 421 for `xenial`. A handful is worse for the operator than none, because it distills to a non-empty index that passes the no-packages check under [Sync](#sync) and then reports the rest of the release clean for the whole `osv_db_max_age` window. The gate warns on an absent codename instead.

The release on the version entry, never `apt_codename`. One catalog holds entries for both releases, and answering both from one codename is wrong about one of them, in the direction that reports a vulnerable host clean: noble's version strings are newer than every jammy advisory's fixed version, so a noble entry checked against jammy's records matches nothing. `bodega pkg convert apt` is what puts the release on the entry, from the host it runs on or from `--suite`; see [`bodega pkg convert`](#bodega-pkg-convert-type-file-).

**The release and the publishing suite are two fields.** `capture_suite` is the release the captured host was running and the gate reads it first. `suites` is the set of `dists/<suite>/` trees the `.deb` is offered under, and the index generator reads that one. They hold the same value on a bodega serving upstream codenames and different values on the mirror configuration under [Mirroring an upstream archive](#mirroring-an-upstream-archive), where `apt_codename` is `internal` and `apt_upstreams` holds noble: a jammy capture there is answered from `Ubuntu:22.04:LTS` and served out of `dists/internal/`, and [Sync](#sync) fetches that release because it reads the captures as well as `apt_suites`. Writing the release into `suites` instead would drop every converted entry out of every generated index, and nothing would say so at convert, import or serve time.

An entry recording neither falls back to `apt_codename`, and only while the codename is the one release this bodega serves. That is the release the server publishes such an entry under, so it is the release whose advisories cover it, and `sync` has already fetched the index because the served set always includes the codename.

With `apt_suites` holding two releases the fallback becomes a guess about the one thing being checked. A catalog imported before capture recorded a release carries jammy and noble entries that look identical on the manifest, so the gate declines rather than picking:

```
apt/libexpat1: 2.6.1-2build1: osv: apt entry libexpat1 names no release and this bodega serves 2 releases (Ubuntu:22.04:LTS, Ubuntu:24.04:LTS), so nothing identifies which release's advisories cover its version; set capture_suite on the version entry, or re-capture the host with 'bodega pkg convert apt --suite <codename>' and re-import
```

Pockets are not releases: `jammy`, `jammy-security` and `jammy-updates` are one set of advisories, so serving all three keeps the fallback unambiguous. A served suite OSV publishes no export for does count as another release, because it is another release an entry could have come from and this gate cannot place it either way.

**One release is two OSV ecosystem strings.** `Ubuntu:22.04:LTS` carries main and `Ubuntu:Pro:22.04:LTS` carries universe, and on the ESM releases very nearly everything. The two sets are disjoint. Measured 2026-09-11, a stock jammy `imagemagick 8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3` answers with 4 records under the first and 179 under the second, and a xenial `expat 2.1.0-7ubuntu0.16.04.5+esm8` answers with none under the first and 37 under the second. Both halves are about the same host and both name stock revisions as their fixed versions, so `sync` folds them into one index per release: the `queried` stamp names `Ubuntu:22.04:LTS` and the answer covers both.

The FIPS, Realtime and Nvidia-BlueField strings are not folded: the fold matches `Ubuntu:Pro:<rel>` as an exact pair, so `Ubuntu:Pro:FIPS-preview:22.04:LTS`, `Ubuntu:Pro:FIPS-updates:22.04:LTS`, `Ubuntu:Pro:Realtime:22.04:LTS` and `Ubuntu:Nvidia-BlueField:22.04:LTS` all fall outside it. Each carries revisions of a build the stock host never installed, so folding one in reports against a version that was never there: `UBUNTU-CVE-2022-40735` fixes jammy `openssl` at `3.0.2-0ubuntu1.16` and the FIPS build at `3.0.2-0ubuntu1.16+Fips1`, and a patched stock host sorts below the second.

**The source package is queried, and it is a different field from `source_name`.** Advisories are issued against the source package, and one source builds many binaries: `expat` builds `libexpat1`, `libexpat1-dev` and `expat` itself. OSV's `Ubuntu` and `Debian` ecosystems are keyed on the source alone, so a lookup for `libexpat1` returns nothing at all while `expat` returns 51 records. The gate reads `source_package`, which `bodega pkg convert apt` fills from dpkg's `${source:Package}` and the builder fills from `apt show`'s `Source:` line. `source_name` is not that field and never was: every importer sets it to the binary name, because `apt-get download` needs the binary name to resolve a `.deb`.

**An entry recording no source package is queried under its binary name, and an empty answer from that query warns rather than passing.** The two cases are indistinguishable from the string alone: `libssl3` matching nothing and a patched `bash` matching nothing look the same. A match is self-validating, so the 28 of 101 packages whose source and binary names agree still report normally; only the empty answer is ambiguous, and B34's rule applies to it. The stamp says which name was used either way, so a finding on `libexpat1` traces back to the `expat` advisory that produced it.

```
apt/libssl3: 3.0.2-0ubuntu1.26: osv: apt entry libssl3 was queried under its binary name in Ubuntu:22.04:LTS and matched nothing, but Ubuntu and Debian advisories are issued against the source package, so an empty answer here is not a clean one; re-capture the host with dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\t${source:Package}\n' and re-import, or set source_package on the version entry
```

**Versions compare under dpkg's ordering, revision included.** Epoch, upstream version and revision compare separately, `~` sorts below the end of the string, and leading zeros carry no weight, so `3.0.2-0ubuntu1.15` is newer than `3.0.2-0ubuntu1.2`. semver gets `2.5.0-1+deb12u1` wrong in the expensive direction: it reads `+deb12u1` as build metadata and discards it, so an unpatched `2.5.0-1` compares equal to the revision carrying the fix and reports clean.

```
$ bodega pkg import expat.json      # jammy, one revision short of the fix
apt/libexpat1: 2.4.7-1ubuntu0.2: osv: libexpat1@2.4.7-1ubuntu0.2 has 2 OSV record(s): USN-6694-1, USN-7000-2, queried as source package expat in Ubuntu:22.04:LTS
```

An entry the gate cannot place warns and never passes, the same rule the missing database follows: a suite OSV publishes no records for (an interim Ubuntu release, or a suite name of your own), an entry whose own suites and `apt_codename` are both unmapped, or an entry whose version is not yet resolved.

```
apt/libexpat1: 2.6.3-2: osv: apt entry libexpat1 names suite(s) plucky, which OSV publishes no Ubuntu or Debian export for
apt/nginx: osv: apt entry nginx carries no version, so no advisory can be evaluated against it
```

An entry published to several suites is queried against each of them and the records are unioned: the same `.deb` is offered to every suite it lists, so a record against any of those releases is a finding on that version. If one of those suites has no export, the entry warns rather than reporting the other suite's answer as the whole answer.

**Sync fetches the aggregate archive, not the per-release one.** OSV publishes `Ubuntu:22.04:LTS/all.zip` and stopped rebuilding it in October 2024: measured 2026-09-11, that archive was last written 2024-10-09 and its newest advisory was from 2024-10-08, while `Ubuntu/all.zip` had been rebuilt that morning. The abandoned copy is also an id scheme behind, carrying Debian records as `CVE-2023-52425` where every other surface calls them `DEBIAN-CVE-2023-52425`. So `sync` pulls the aggregate and distills one index per release out of it, which is also why serving four Ubuntu suites is one download rather than four. Fetching the per-release archive would have shipped a gate reporting `DB SYNCED` two minutes ago over two-year-old advisories, and nothing would have caught it: the age is measured on the fetch, not on the contents.

#### Matching

The local matcher implements OSV's own evaluation: an enumerated `versions` list matches exactly, and a range is walked event by event in version order, under semver for npm, Go and crates.io, PEP 440 for PyPI, and dpkg's ordering for the Ubuntu and Debian releases. Measured against `api.osv.dev` over 240 range-boundary `(package, version)` pairs drawn across the four language ecosystems, it agrees on all 240.

An ecosystem is decompressed on the first version checked against it and held until `sync` replaces the archive, so a bulk import pays one decompression rather than one round trip per version. One process shares that copy across every package it admits: importing 100 npm packages at 4 versions each against the 2026-09 export takes 0.5s. What it holds, measured on the same exports: npm 85 MB, PyPI 47 MB, gomod 6 MB, cargo 1.5 MB. An ecosystem with no policy row is never loaded.

The Ubuntu and Debian releases cost an order of magnitude more, because a distro advisory enumerates every published version it covers rather than bounding a range: measured 2026-09-11, `Ubuntu:22.04:LTS` holds 826 MB once loaded, `Ubuntu:24.04:LTS` 305 MB and `Debian:12` 102 MB, and a release is loaded on the first apt version checked against it.

Decoding one costs about three times what it keeps, and the transient is the figure that gets a host OOM-killed rather than the one it settles at. Measured the same day, one process checking a single version against `Ubuntu:22.04:LTS`: 3478 MB allocated during the decode, 2.4 GB maximum resident, settling to the 826 MB above. `Ubuntu:24.04:LTS` peaks at 1.0 GB for the 305 MB it keeps, `Debian:12` at 0.3 GB for 102 MB. Releases decode one at a time, so provision for the largest release's peak plus what the others retain; adding the retained figures alone sizes a two-release host at 1.1 GB and it dies on the first apt version checked. Or keep the apt gate on a machine that imports rather than on the one that serves.

A running server picks up a sync without a restart: it checks the archive it loaded from on each match and reloads when the file changes. `sync` is a separate process from the server enforcing the gate, so without that check the server would report the fresh fetch time under `bodega policy osv list` while still matching against the copy it loaded before the sync.

Two classes of record it does not answer the way `api.osv.dev` does.

**Withdrawn advisories are dropped at sync.** The API still returns some of them (PYSEC-2024-115, retracted in July 2026, comes back on a `langchain-community` query while other withdrawn records do not). A retracted advisory blocking an import is a false positive the operator has no way to clear.

**A range bound no ordering can place leaves that range unevaluated.** OSV carries 46 of them across the four exports as of 2026-09-08, in 15 packages: `4.1.0-NA` bounding `pynetbox`, `2.6.0-cu124` bounding `torch`, `0.8.3ubuntu7.5` bounding `python-apt`, `9.6.0b1` bounding `github.com/redis/go-redis/v9`. Such a record neither matches nor clears. The gate names it instead, so a version never reports clean on a record nobody could read:

```
$ bodega pkg import pynetbox.json
pypi/pynetbox: 4.1.0: osv: 1 OSV record(s) for pynetbox were not evaluated against 4.1.0: PYSEC-2024-325 (bound "4.1.0-NA")
Imported pypi/pynetbox (1 version(s))
```

A version matching other records blocks on those and carries the unevaluated ids in the same reason, capped at five ids plus a count. Matching one record settles nothing about the one nobody read, so such a version is stamped with its ids and no check date, the same treatment the identical version with zero matches beside that record already gets. `api.osv.dev` is not consistent on this population: over 130 probes at published versions across those 15 packages it agreed 123 times, returning nothing for the record exactly as the local matcher does. The other 7 are the API failing open on a bound it also cannot place, returning GHSA-jqqh-999x-w26w, fixed in `buildbot` 0.7.11p3 in 2007, for `buildbot@4.3.0`. Reproducing that would mean shipping a block no operator can clear, so the matcher reports the record and declines to guess. Turn `osv_api_fallback` on to see what the API says about one.

A version with OSV records is stamped on its `VersionEntry.Metadata`, so the finding follows the version into the manifest rather than living only in the audit event:

| Key | Value |
|-----|-------|
| `vetting.osv.vulns` | comma-separated OSV ids, sorted |
| `vetting.osv.severity` | JSON object keyed by OSV id, each value the record's `severity` array as OSV returned it |
| `vetting.osv.checked_at` | RFC 3339 timestamp of the last check that reached a verdict |
| `vetting.osv.queried` | what the lookup actually asked, on the ecosystems where that is not the package name and type: `source package expat in Ubuntu:22.04:LTS` |

`vetting.osv.severity` is present only when at least one record carried a score, and ids OSV scored nothing for are absent from it; `vetting.osv.vulns` is the full list either way. A version matching several records at different severities keeps them apart by id, so a reader ranking findings parses the stamp instead of querying OSV a second time.

`vetting.osv.checked_at` is what makes the other two readable. Without it a version with no findings and a version nobody ever queried both carry an absent `vetting.osv.vulns`, so "no known vulnerabilities" and "nobody looked" print the same. The date is written on a clean result and a flagged one alike, and only when the gate reached a verdict: a check answered out of a database too old to be trusted names the records it found and drops the date rather than keeping the one already there, an entry whose `version_constraint` is not exact is never dated at all, because the range it names is not the version that was queried, and a record naming the package that nobody could evaluate withholds the date whether or not some other record matched. A date left in place would then sit beside findings the check that wrote it never saw, and `show pkg` would render a fresh flag under the day the version last read clean.

Versions imported before this key existed cannot be backfilled. Nothing on disk records when they were checked, and dating them from the manifest's timestamp would invent the fact the field carries, so they read as `unchecked` until a rescan answers for them.

```json
{"GHSA-xxxx-yyyy-zzzz":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
```

#### Rescan

Admission checks a version once, on the day somebody imported it. That answer never gets revisited, so a version admitted clean fourteen months ago is still recorded as clean, and CVEs published against versions already in the field are the normal case rather than the exception. **Admission-time checking alone does not tell you what is vulnerable today.** It tells you what was vulnerable on the day of the import, and nothing in the output distinguishes those two sentences.

`rescan` closes that gap. It walks the manifests, re-runs the lookup against the local database, and re-stamps every version it can answer for.

```
$ bodega policy osv rescan
TYPE  PACKAGE   VERSION  STATE          DETAIL
npm   minimist  1.2.0    flagged (new)  GHSA-vh95-rmgr-6w4m, GHSA-xvch-5gv4-984h
Rescanned 2 version(s): 2 answered, 1 newly flagged, 0 newly cleared.
```

`--type` and `--name` scope the walk. `--type` refuses an ecosystem OSV has no records for, rather than reporting a clean pass over it. `--name` takes the package name as you would type it anywhere else, scoped npm packages and gomod module paths included: `--name '@types/node'` and `--name 'github.com/spf13/cobra'` both resolve to the encoded key the manifest index stores. A `--name` that matches no package exits 1 rather than reporting a clean walk over nothing.

A manifest the walk cannot read or cannot write back counts as unanswered, with the error as its reason, and the walk continues. A package listed in the index whose manifest file is gone counts the same way, naming that state as its reason: `bodega repair` reports the same drift, and a walk that skipped it silently would report a package nobody could look at as a package with no findings. One corrupt file does not cost you the report on everything beside it; the command still exits 1 so the failure is not silent.

**A non-exact `version_constraint` is not one version, so nothing dates it.** An entry stored under `compatible`, `patch` or `any` names a range the server resolves against upstream, and it serves in-range releases the manifest never lists. A lookup on the base version answers for exactly one of them, so those entries count unanswered, keep the stamp they had, and earn a row naming the constraint. A record matched against the base version is still named in that row, ahead of the reason: it is a real record, and a verb built for the late-published advisory that printed nothing on it would be silent on its own case.

Admission and rescan part company on what they write for such an entry, on purpose. Admission is the moment the record is learned, so it stamps the ids and withholds the date, dropping any date the entry already carried. Rescan writes nothing at all: it is re-reading an entry that already exists, and the only thing it could add is a claim about releases it never queried. `show pkg` applies the same rule at render time, printing `never` in `CHECKED` for a range entry whatever date it carries, because an imported manifest and an edit to the constraint after a check both put a date there that no lookup supports. `bodega pkg refresh` materializes the in-range releases as exact entries, and a rescan dates each of those.

The table lists what an operator has to read: every version carrying findings, the ones that just gained or lost them, and the ones nothing could answer for. Whatever qualified an answer is on the row that answer produced, after the ids: a caveat that reached only the reason counts on stderr leaves one line claiming a verdict the run never had. A version that stayed clean is in the count on stderr and nowhere else. Findings go to stdout and the summary to stderr, so a report pipes cleanly while the counts stay on the terminal.

**Rescan records and decides nothing.** It never blocks, hides, freezes or deletes. An OSV data refresh that flags the base image half a fleet runs on would otherwise take that fleet offline with no operator in the loop, on the strength of a third-party data push. What to do about a version that has become vulnerable is a decision, and it stays with the person reading the report.

**A run that could not read the database does not look like a clean run.** Both print zero newly flagged, so the summary carries an unanswered count and the reason behind it, and the command exits 1 when it answered for nothing:

```
$ bodega policy osv rescan
TYPE  PACKAGE   VERSION  STATE       DETAIL
npm   minimist  1.2.0    unanswered  no local OSV database for npm in /var/lib/bodega/osv; run `bodega policy osv sync`; osv_api_fallback is off, so nothing was queried
npm   minimist  1.2.5    unanswered  no local OSV database for npm in /var/lib/bodega/osv; run `bodega policy osv sync`; osv_api_fallback is off, so nothing was queried
Rescanned 2 version(s): 0 answered, 0 newly flagged, 0 newly cleared.
2 version(s) unanswered; their previous stamp is unchanged.
  2 x no local OSV database for npm in /var/lib/bodega/osv; run `bodega policy osv sync`; osv_api_fallback is off, so nothing was queried
Error: nothing was re-checked: none of 2 version(s) could be answered for; the reasons are above
```

Every unanswered version earns its own row. An unanswered version keeps the stamp it had. Overwriting a real finding with a blank one because the mirror was missing is how a rescan reports a clean fleet it never looked at.

Unlike `set`, `list` and the gate itself, `rescan` reads no policy row. Whether a version is vulnerable today is the same fact under `warn`, `block` and `ignore`; the row decides what admission does with a finding, not whether the finding is recorded. So an install that has configured no OSV policy still gets the report.

A rescan that wrote anything signals a running `bodega serve`, so the API reflects the new stamps without a restart. `manifest.Store` answers a package request from its cache once it has served that package, so without the signal a long-running server would keep calling a freshly flagged version clean for the life of the process. A walk that saved nothing sends nothing, and a walk that saved some packages before failing on others signals anyway before it exits 1.

Nothing schedules a rescan. Pair it with `sync` in the same cron entry: refreshing the mirror and never re-reading it against what is stored leaves the gate current for imports that have not happened yet and stale for everything already served.

Results surface where an operator already looks. `bodega show pkg <type> <name>` carries an `OSV` and a `CHECKED` column per version and names the flagged ids underneath:

```
$ bodega show pkg npm minimist
Package: minimist

VERSION      PLATFORM        STORED FROZEN   HIDDEN   CONSTRAINT OSV         CHECKED
1.2.0        any             -      no       no       exact      2 vuln(s)   2026-09-08
1.2.8        any             -      no       no       exact      clean       2026-09-08

Flagged by OSV:
  1.2.0        GHSA-vh95-rmgr-6w4m, GHSA-xvch-5gv4-984h  (checked 2026-09-08)
```

The `OSV` cell reads `n/a` on `binary`, `git` and `helm`. Those three have no OSV ecosystem identifier, so no rescan can ever answer for them, and `unchecked` would send the operator to a verb that refuses to run on them. On the covered types the cell reads `unchecked`, `clean` or a finding count, and `CHECKED` carries the date of the last conclusive answer. The `Flagged by OSV` block obeys the same rule: a version whose row reads `n/a` never appears in it. `bodega pkg import` accepts a manifest carrying `vetting.osv.*` keys for any type, so a stamp exported from another instance can land on `git`, and printing it as a dated finding under a cell that says the check can never run would contradict the row four lines above it.

`GET /api/v1/packages/{type}/{name}/{version}` carries the same four keys on the version's `metadata`.

### `bodega policy age <set|list|remove>`

Rejects or flags a version whose upstream publish timestamp is newer than the ecosystem's minimum age, which is the cheapest defense against a freshly published malicious release.

A fresh install is seeded with `npm` and `pypi` at `7d warn`, and the startup banner names it. It is the only policy bodega ships turned on; the allow-list and the OSV gate are empty until you add a rule. The week is the window the 2025-2026 npm and PyPI campaigns were caught in, and `warn` rather than `block` so a first install reports instead of breaking a build. Checksum pinning does not reach this case: it guarantees today's bytes match the first fetch, including a first fetch that was already malicious.

The seed is a decision recorded once, in `policy_seeds` in the audit database, not a default re-applied at every start. So `bodega policy age remove npm` is permanent, an empty policy set stays empty across restarts, and an install created before this default gains nothing on upgrade. `bodega doctor` reports an install that enforces nothing.

```bash
bodega policy age set npm 7d warn
bodega policy age set cargo 72h block
bodega policy age list
bodega policy age remove npm
```

`min-age` takes the Go duration shapes plus a plain `<N>d` for days. The action is `warn`, `block` or `ignore`. One rule per ecosystem; `set` overwrites.

Coverage is the set of registry types with an upstream endpoint that carries a publish timestamp:

| Type | Source |
|------|--------|
| npm | packument `time[<version>]` on `registry.npmjs.org` |
| pypi | earliest `urls[].upload_time_iso_8601` on `pypi.org` |
| gomod | `Time` in the proxy's `@v/<version>.info` |
| cargo | `version.created_at` on `crates.io/api/v1/crates/<name>/<version>` |

`apt`, `binary`, `git` and `helm` have no such source. `set` refuses them:

```
$ bodega policy age set apt 7d warn
Error: the age gate does not cover ecosystem "apt": there is no upstream publish timestamp to date a version against, so every version would warn; set one of cargo, gomod, npm, pypi instead
```

The two gates failed differently before they refused. OSV passed silently. Age never did: a missing timestamp is a `warn` with the ecosystem named, so an apt policy made every apt version noisy rather than invisible. Refusing the row up front is a usability fix on that side and a security fix on the OSV side.

`set` grew that refusal after the fact, so a row written before it is still stored and still read by nothing. Both `list` commands name those rows under the table, and `bodega doctor` reports them as `policy-ecosystem`:

```
$ bodega policy age list
ECOSYSTEM  MIN AGE  ACTION  UPDATED
helm       7d       block   2026-03-11
npm        7d       warn    2026-09-06

Not enforced: the age gate cannot evaluate helm, so that row is stored and never read.
Remove with 'bodega policy age remove <ecosystem>'.
```

Nothing else counts such a row as enforcement. The `bodega serve` startup banner names only ecosystems the age gate can date, so an install carrying the `helm` row above with `npm` and `pypi` on `ignore` reports `minimum publish age: none enforced` rather than the block that never runs.

An upstream that is reachable but has no timestamp for the version warns rather than blocking, on the same reasoning: a registry outage should not fail an import closed.

### `bodega discover ...`

Discovery records what clients reached for that bodega could not serve from its own manifests, so an operator can turn a real installation run into allow-list rules or manifest entries instead of writing them from memory.

The mode is server-side. Set `discover_mode` in config.json and restart:

| Value          | What gets logged                                                            |
| -------------- | --------------------------------------------------------------------------- |
| `""` (default) | nothing; the hook is off                                                    |
| `"observe"`    | every upstream attempt and every pre-fetch miss, with the decision each got |

`discover_mode` decides whether a row is written. It decides nothing else. The allow-list, `catalog` mode on `git_upstreams` and `binary_upstreams`, hidden versions, version constraints, the CIDR access lists and the mutation gate all behave identically at both values, and a request the allow-list rejects gets its 403 either way. `observe` is safe to leave on permanently, and there is no mode that turns enforcement off.

It is also not the way to bootstrap a catalog. Discovery only sees what clients ask for, so a host that has been stable for six months produces nothing, and `catalog` mode 404s a path before any policy check runs — so an empty store stays empty however long you watch it. Read the host's own inventory instead: [`bodega pkg convert`](#bodega-pkg-convert-type-file-) turns `dpkg-query`, `pip list`, `npm ls -g`, `go list -m all`, `cargo install --list` or `helm list` into a manifest set in one run. What discovery is for is the residue: once a catalog exists, `observe` names what the fleet reaches for that the catalog does not cover, including the two types `pkg convert` has no importer for (git and binary).

Each observation is one row keyed by `(type, pattern, package, version, decision)`, with a request count, the last client IP, and the upstream URL bodega fetched or would have fetched. The count is a count of **requests**, not of cache misses: a request the cache answers bumps the same row the fetch that filled it wrote, so `request_count` ranks by demand and `last_client` names the last host to ask. That holds for a stale copy served because no upstream is configured, and for one served because the upstream could not be reached — an outage is the window these columns are read in, and they keep moving through it.

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
| pypi | simple index, wheel | every request, including the read of the upstream simple index a wheel is resolved through; `no_manifest` on a wheel for an unknown distribution |
| gomod | `/go/...` | every request; `no_manifest` on a module with no entry |
| helm | `/helm/charts/*.tgz` | every request; `no_manifest` on a chart with no entry, with an empty upstream URL (a chart repo is named per version entry, so with no entry there is no URL to record). A `no_manifest` row takes both halves from the chart key, so `cert-manager-1.14.0-rc.1.tgz` is recorded as `cert-manager` at `1.14.0-rc.1` and a promote names a chart that exists. Every other decision still takes its version from a split at the last `-`, recording the same file at `rc.1`, so a chart observed before its entry existed and fetched after it appears in `discover list` at two versions. `promote --as manifest` and `generate-manifests` read `no_manifest` rows only, so the split version never reaches a manifest |
| git | `/git/{namespace}/...` | one row per clone under an `open` namespace, with an empty version. A clone is two requests, an `info/refs` GET and a `git-upload-pack` POST, and both pass the allow-list; only the `info/refs` leg is recorded, so a git count means the same thing as every other type's. `no_manifest` on an uncataloged repository under a `catalog` one; `no_namespace` on a first segment naming no `git_upstreams` entry, with the namespace as both the package and the pattern |
| binary | `/binaries/{namespace}/...` | every request under an `open` namespace; `no_manifest` on an uncataloged path under a `catalog` one; `no_namespace` on a first segment naming no `binary_upstreams` entry, once any entry exists |

#### Gaps

These are not observed yet. A quiet discovery log for one of them means the hook does not reach it, not that no client asked:

- **apt with no `apt_upstreams`**: `/apt/pool/...` reads storage directly with nothing upstream to fetch, so neither a hit nor a miss is recorded. A pool path a manifest entry owns behaves the same way even on a mirroring instance: it is served from storage and never proxied.
- **generated suites**: `dists/` for a codename in `apt_suites` is built from bodega's own manifests, so there is no upstream request to observe. Only mirrored codenames produce rows.
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
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\t${source:Package}\n' | bodega pkg convert apt > apt.json
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
  "cargo_root": "",
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
  "spool_dir": "",
  "spool_max_artifact_bytes": 8589934592,
  "spool_max_total_bytes": 34359738368,
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

It is also consumed rather than displayed. Every `dist.tarball` bodega writes into an npm packument is built from it (see [Client configuration](#client-configuration)), so a `public_url` naming a host or scheme clients cannot reach fails `npm install` at the tarball fetch rather than at the packument, and npm reports a URL this key composed without naming the key or the packument it came in. Check it first when npm resolves a version and then 404s or times out fetching the `.tgz`.

`discover_mode` turns the upstream-observation log on, and does nothing else: enforcement does not move with it. Valid values are `""` (off) and `"observe"`; anything else is rejected at load. `"learn"` was removed and is refused by name, with the error pointing at `observe` and `bodega pkg convert` — it suppressed the allow-list and recorded nothing `observe` does not. See [`bodega discover ...`](#bodega-discover-) for what gets logged and what to do with it.

`spool_dir`, `spool_max_artifact_bytes` and `spool_max_total_bytes` bound the disk the proxy spends copying upstream artifacts. An empty `spool_dir` means `{build_root}/tmp`, and `bodega serve` refuses to start when it cannot create that directory or write in it. See [Large artifacts and the spool directory](#large-artifacts-and-the-spool-directory) for the two ceilings, what a refused client is told, and where the pressure is reported.

`audit_sink` chooses where the event stream goes and `audit_sink_dsn` says how to reach it; see [Audit Trail](#audit-trail) for the four values, what each gives up, and what `bodega serve` does when the destination is unreachable. `timezone` sets the display timezone for audit queries (default UTC) and `audit_events` limits which event types are recorded (empty records all). Both apply to the CLI and to `bodega serve` alike — see [Audit Trail](#audit-trail) for what a filter that omits `denied` costs you.

Config files are written with mode `0600` (owner read/write only).

**Resolution priority:** CLI flags > environment variables > config file > built-in defaults. Every flag in the table above is registered with an empty default so it cannot shadow the env var and config key beneath it; `--log-level` is the one exception, where `0` is both a valid level and the zero value, so bodega asks whether the flag was typed rather than reading its value.

`manifest_dir` is where manifests live on the `local` backend. The built-in is `{storage_path}/manifests` and is always absolute: a relative path resolves against the process working directory, which under a systemd unit with no `WorkingDirectory=` is `/`. Nothing else is probed. A `manifests/` directory beside the binary or one level above it was reached first until an install at `/opt/bodega/bin/bodega` beside `/opt/bodega/manifests` turned that development convenience into a server reading a directory its config never named; either layout now names it with `manifest_dir`, `$BODEGA_MANIFEST_DIR` or `--manifest-dir`.

Manifests sit inside `storage_path` so that one directory holds the whole repository. Artifacts already lived there; a manifest tree outside it meant `tar` on `storage_path` produced a backup that restored every package's bytes and none of its metadata.

**Upgrading an install created before that default.** `--manifest-dir` used to be registered with a non-empty default, which made `manifest_dir` in the config file unreachable and sent manifests to `./manifests` relative to whatever directory bodega was started from; the executable-relative probe then claimed installs whose binary sat beside a `manifests/` tree. Check where yours are, then either move them or name them:

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

A `prefix` must be spelled canonically. A leading and a trailing `/` are stripped, so `cold/x`, `/cold/x` and `cold/x/` are one prefix and all three load. An empty segment or a `.` segment is refused, because they are a second spelling of a directory rather than a second directory:

```text
storage_backends["b"]: prefix "cold//x" is not canonical; write it as "cold/x". Two spellings of one prefix are two backend identities, and 'bodega pkg move' between them deletes the only copy
```

A `..` segment is refused separately, and for a different reason: it names a location outside the backend, and every key through such a backend already fails the traversal check, so the backend is unusable rather than ambiguous.

The two namespaces never mix, and `Load` enforces it. `storage_backend` is a **driver**. `storage_backends` keys and `storage_by_type` values are **names**. A name equal to `default` or to a driver is rejected, as is a `storage_by_type` value naming a backend nothing defines:

```text
storage_by_type["apt"] names undefined storage backend "archive" (defined: default, bulk)
```

Two entries resolving to one bucket or directory is neither rejected nor warned about. It is a supported way to stage a migration, and the identity that decides sameness is the backend's resolved label: comparing the configured strings at load would miss a symlink, a trailing slash or a relative path, and fire on a `path` two different drivers happen to share. `bodega pkg move` is the one command the collision can destroy anything through, and it refuses by label before the first copy.

The resolved label is resolved because the `local` driver is made to resolve it, not because a driver was ever guaranteed to. Until [#136](https://github.com/ravinald/bodega/issues/136), `storage_path` reached the label verbatim: a second backend pointing at a symlink of the first root produced two labels for one directory, the refusal did not fire, and `--delete-source` removed the only copy. `local` now resolves its root once at construction with `filepath.Abs` then `filepath.EvalSymlinks`, falling back to the absolute cleaned path for a root it is about to create. `s3://<bucket>` needs nothing: it is already one string per bucket.

The prefix is the other half of that label, and it was still concatenated verbatim after #136 fixed the root. Until [#189](https://github.com/ravinald/bodega/issues/189), two backends over one `storage_path` with prefixes `cold/x` and `cold//x` carried two labels for one directory, and `bodega pkg move --to b --delete-source` between them exited 0 reporting a move and left nothing on disk. The label now cleans the prefix, which is truthful only because the spellings that would need cleaning are refused at load: `s3` stores the key it is handed, so `cold//x/k` and `cold/x/k` are two distinct objects in one bucket and a cleaned label over an s3 backend would claim an identity the bucket does not have.

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

Each type can build under its own directory instead of `build_root`, which is what puts wheels on a large volume and binaries on fast SSD. One key per type, empty meaning `build_root`:

| Key | Type | Directory it roots |
|-----|------|--------------------|
| `apt_root` | apt | `<root>/apt-repo` |
| `git_root` | git | `<root>/bundles` |
| `pypi_root` | pypi | `<root>/wheels` |
| `binary_root` | binary | `<root>/binaries` |
| `gomod_root` | gomod | `<root>/gomod` |
| `helm_root` | helm | `<root>/charts` |
| `npm_root` | npm | `<root>/npm` |
| `cargo_root` | cargo | `<root>/cargo` |

Every command that reads or writes an artifact resolves through the same root: `bodega build run`, `fetch`, `package`, `upload`, `sync`, `repair` and the TUI. An upload that finds nothing names the directory it walked, so a root one command resolved differently from the build is visible in the skip line rather than reported as an empty build:

```
--- sync: apt ---
    No local apt artifacts found under /opt/bodega/apt-repo — skipping
```

**Upgrading an install that set one of the last four keys.** `gomod_root`, `helm_root` and `npm_root` used to reach `bodega build repair` alone, and `cargo_root` reached nothing at all, so the build wrote under `build_root` while the key said otherwise. All four now root the build, which points an install that set one at a directory holding none of the artifacts it already has. Nothing is lost: the files stay where they were written. `bodega build status` reports those entries absent, and `sync` and `upload` name the empty directory they walked. Move each tree once:

```bash
# Only for a key you actually set. /opt/bodega is the default build_root.
sudo mv /opt/bodega/gomod  "$GOMOD_ROOT/gomod"
sudo mv /opt/bodega/charts "$HELM_ROOT/charts"
sudo mv /opt/bodega/npm    "$NPM_ROOT/npm"
sudo mv /opt/bodega/cargo  "$CARGO_ROOT/cargo"
```

Or clear the key and keep everything under `build_root`. `apt_root`, `git_root`, `pypi_root` and `binary_root` need none of this: the build path already carried those four.

**Gap:** `custom_paths` gates none of this. The build path reads each root directly, so a root left in the config file stays in force after the flag is turned off. `config.RootForType` applies the gate and has no callers.

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

`build_env` is written by the build, never by the operator, and `bodega show pkg <type> <name> all` prints it:

| Key | Meaning |
|-----|---------|
| `bodega` | The bodega build that wrote the entry. `dev` for a binary built without `-ldflags`, which is what `go build` and a source checkout produce; `unknown` means nothing handed the builder a version, which no shipped path does |
| `platform` | `GOOS/GOARCH` of the build host, e.g. `linux/amd64` |
| `os_release` | `PRETTY_NAME` from the host's `/etc/os-release` |
| `python` | `python3 --version` on the build host |
| `go` | `go version` on the build host |
| `rust` | `rustc --version` on the build host |
| `built_at` | RFC-3339 UTC timestamp |

Every key but `platform` is omitted when empty, so an entry stamped on a host without a Go toolchain carries no `go` key rather than an empty one. The whole object is rewritten each time a fetch succeeds, so an entry built before `bodega` was wired carries no `bodega` key until something re-fetches it; nothing backfills it in place.

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
  "source_package": "amazon-efs-utils",
  "capture_suite": "noble",
  "url": "https://github.com/aws/efs-utils.git",
  "build_cmd": "make deb",
  "deb_glob": "build/*.deb",
  "suites": ["noble", "jammy"]
}
```

- **source_name**: upstream Debian package / source directory name. This is what `apt-get download` and a source build ask for, so it is the binary package name on every imported entry.
- **source_package**: the Debian source package this binary was built from, as `dpkg-query -W -f='${source:Package}'` reports it. Read by the OSV gate and by nothing else, because USN and DSA are keyed on it. Absent means no capture recorded one, which is not the same as equal to the name: see [apt](#apt) under the OSV gate for what the gate does with the difference.
- **capture_suite**: the release the host this version was captured on was running, from `bodega pkg convert apt --suite` or the converting machine's `/etc/os-release`. Read by the OSV gate, which keys a distro advisory on the release because Ubuntu and Debian backport a fix without moving the upstream version. Ignored by the index generator: **suites** below decides where the `.deb` is published, and on a server whose `apt_codename` is a name of your own the two fields hold different values.
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

A **mirrored codename** is configured differently, because something else signs it:

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

bodega rewrites every `dist.tarball` in a packument onto its own `/npm/` route before serving it. Relayed as upstream wrote them, those URLs name `registry.npmjs.org`, and npm's resolver replaces the origin while keeping the upstream path — so the client asks for `/<package>/-/<file>.tgz` with the `/npm` prefix dropped and gets a 404. On a deployment where that path happened to resolve it would get the tarball from a request bodega never sees, past the hidden-package and hidden-version checks, the version constraint, the audit row, the checksum and the cache.

The scheme and host it rewrites to come from [`public_url`](#configuration), or from the request when no `public_url` is set. The cached object is still the document the registry served: the rewrite happens on the way out, so a cache hit and a cache miss hand the client the same URLs and the stored copy remains evidence of what upstream published.

**git** (a `git_upstreams` namespace, clone URL ending in `.git`):
```bash
git clone https://bodega-host:8080/git/github/octocat/Hello-World.git
```

See [Git smart-HTTP](#git-smart-http) for what bodega does with that request.

#### Naming the host in the audit trail

None of the stanzas above carries a credential, and none needs one: every package route is open. A credential buys attribution. With one written, the `serve_fetch` row and the discovery observation name the host rather than the address it happened to hold, which is the difference between reading an audit trail and correlating one against DHCP leases.

```bash
bodega token generate devbox-3                                          # on the server
bodega identity bind token <id> devbox-3                                # on the server
bodega doctor --write-credentials --token bodega_ak_... --url https://bodega-host:8080
```

The last line runs on the client and writes the token into the file each of its package managers reads. See [`bodega doctor`](#bodega-doctor---write-credentials---token-token---url-url) for what lands where, and [`bodega identity`](#bodega-identity-bindunbindlist) for the CIDR binding that covers a whole subnet with no credential to distribute.

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

Signing happens once per snapshot rebuild, not per request. `InRelease` is the clearsigned form of `Release`, and `Release.gpg` is the armored detached signature. The clearsigned body is byte-identical to `Release`, so a verifying client and a `[trusted=yes]` client read the same index. Both use SHA-512: apt's `gpgv` rejects SHA-1 on current releases. Both armored blocks close with a CRC24 checksum line, which RFC 9580 makes optional and gpgv 2.4 still requires — without it that gpgv reports a good signature for every key and then exits 2.

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

**"apt accepts an `InRelease` when any one signature verifies" holds only up to the first signature whose key the client does not hold.** Re-measured 2026-09-04 against a dual-signed `InRelease`: gpgv 2.4.4 (`ubuntu:24.04`, `2.4.4-2ubuntu17.4`) walks the whole set and reports `GOODSIG` for whichever signature it can check, while gpgv 2.5.22 stops at the first `NO_PUBKEY` and emits no status at all for the second. Both exit 2 on a partial keyring, which is also what an unrelated keyring returns, so the exit code does not separate a client the window covers from one it rejects; apt reads gpgv's status-fd, and a `GOODSIG` arriving there is what the accept turns on. A keyring holding every signing key is the one case that exits 0, measured 2026-09-04 on gpgv 2.4.4 against a dual-signed `InRelease`: both keys 0, outgoing-only 2, incoming-only 2, unrelated 2. Before the armor carried its CRC24 checksum the full keyring exited 2 as well, so a rotation verified with `gpgv` by hand looked like a failure on 24.04 while apt accepted the same file. It is ordering, not algorithm: RSA-4096 and Ed25519 behave the same way in either position.

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

It carries no claim about upstream. `apt-get download` does verify against the distro's own keyring on the build host, but that result is recorded nowhere and does not reach the client; a source-built `.deb` never had an upstream signature at all. For a mirrored codename the upstream signature is forwarded unchanged instead, which is a stronger claim than bodega could make about the same bytes — see [Mirroring an upstream archive](#mirroring-an-upstream-archive). bodega's key signs generated suites and nothing else.

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

A codename listed in `apt_upstreams` is a **mirrored codename**: served from upstream rather than generated, the other of the two shapes a codename can take. A codename in `apt_suites` is a **generated suite**, built from bodega's own manifest entries and signed by bodega. bodega proxies `dists/<codename>/...` and the pool artifacts the index points at, caching each on the way through. This is what makes `apt update && apt install <anything>` work against bodega for packages nobody pre-built: apt reads the proxied `Packages`, resolves dependencies locally, then asks bodega for each `.deb` by its `Filename:`.

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

The upstream `InRelease` is forwarded byte-for-byte, signature intact, and apt verifies it against the distro keyring already installed on the host (`ubuntu-keyring`, `debian-archive-keyring`). Neither `[trusted=yes]` nor `Signed-By:` belongs on a source line naming a mirrored codename: the first discards a signature that is right there and valid, and the second points apt at bodega's key, which signed nothing in that tree. The startup banner, the TUI, the web UI and `GET /api/v1/status` all render a mirrored codename with neither option, and say why beside the line.

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

The proxy path streams: an upstream body is copied to a spool file, checksummed on the way through, then cached and served from there. Per-request memory is one copy buffer whatever the artifact's size, so process memory is not what bounds a proxied artifact. Disk is, and three keys say how much of it:

| Key | Default | What it bounds |
|-----|---------|----------------|
| `spool_dir` | `{build_root}/tmp` | Where the spool files are written |
| `spool_max_artifact_bytes` | `8589934592` (8 GiB) | The largest single artifact the proxy will copy |
| `spool_max_total_bytes` | `34359738368` (32 GiB) | The bytes every fetch in flight may hold between them |

Write `0` in either ceiling to remove it. An absent key takes the default; `0` is an operator turning the bound off, which is not the same thing.

A `spool_max_artifact_bytes` above a non-zero `spool_max_total_bytes` is refused at config load, by every bodega command and not just `serve`: no artifact that large could ever be admitted, so every fetch over the budget would be refused naming the wrong key. Lowering the budget alone is the way that bites. A host with a 4 GiB spool volume needs both keys moved, or the artifact ceiling set to `0`, which leaves the shared budget as the only bound.

**`spool_dir` is a startup condition.** `bodega serve` creates the directory and writes a probe file in it before it binds, and refuses to start naming the path if either fails. Left to the first large fetch, a misplaced spool surfaces as an `ENOSPC` or a permission error inside one proxy request — on the filesystem that by default also holds `audit_db` and the local store, which means the next thing to fail is something unrelated to the proxy.

**Upgrading:** the spool used to be `os.TempDir()`, so `$TMPDIR` was the only lever and it was a process environment variable. It is now `{build_root}/tmp`, matching where `bodega repair keys` already spools. An install whose `build_root` is the shipped `/opt/bodega` and whose serving user cannot create `/opt/bodega/tmp` will refuse to start rather than silently spool somewhere else: create the directory for that user, or set `spool_dir`.

**The per-artifact ceiling.** A `Content-Length` over `spool_max_artifact_bytes` is refused before a byte is read, which is the only way a client learns the artifact is too large without waiting for the whole transfer. A chunked or transparently-decompressed response declares no length, so that case is refused as the copy crosses the ceiling instead. Either way the spool file is removed, nothing is cached, and the error names the key. 8 GiB is roughly twice the largest thing a real archive publishes as one file — a CUDA `.deb` or a torch wheel runs 2-4 GB — and it refuses the runaway, which is otherwise bounded only by the 90-second upstream timeout times upstream bandwidth: about 11 GB at 1 Gbps, times however many fetches arrive at once.

**The shared budget.** `spool_max_total_bytes` is a byte budget rather than a count of concurrent fetches, because bytes are what runs the filesystem out: eight fetches in flight is 8 MB or 64 GB depending on what was requested, so a count tuned for one artifact size is the wrong bound for the next one. A fetch claims its declared length whole before the copy starts and is charged as it goes where the upstream declared none; the claim is returned when the response is served or the request fails.

**A request over the budget is refused, not queued.** It gets `503` with `Retry-After: 5` — unless bodega already holds a cached copy of that key, in which case it serves that, since the cached copy costs no spool at all. Queuing would turn a disk bound into a latency bound: a fleet running `apt-get update` off one cron minute would hold a goroutine and a connection each behind the 90-second upstream timeout, and the clients would time out anyway with nothing recorded about why.

**Reading the pressure.** Every refusal writes an `ERROR` log line naming the key, the bound and the bytes in flight, plus a `denied` audit row with `status` of `spool_artifact_too_large` or `spool_budget_exhausted` (see [Audit Trail](#audit-trail)). The `serve_start` and `serve_stop` rows carry `spool_dir` and both ceilings, so a run's refusals sit in the same table as the bounds that produced them. The live gauge is the `spool` block on `GET /api/v1/status`:

```json
"spool": {
  "dir": "/opt/bodega/tmp",
  "in_flight": 3,
  "used_bytes": 3221225472,
  "peak_bytes": 7516192768,
  "budget_bytes": 34359738368,
  "max_artifact_bytes": 8589934592,
  "refused_too_large": 0,
  "refused_budget": 12
}
```

`dir` is present only for a caller inside `admin_permit_cidr`. `GET /api/v1/status` answers any client that can reach the server, and a server filesystem path is a fact about the host rather than about what it serves; the counters stay visible, because a client acting on a `503` has to be able to see why it got one.

`peak_bytes` is the high-water mark since the process started, which is what sizes the volume: a `refused_budget` climbing while `peak_bytes` sits at the budget says the host is carrying more concurrent fetches than its spool was sized for, and a `refused_too_large` climbing says `spool_max_artifact_bytes` is below what this archive publishes. Those call for opposite fixes, which is why they are counted apart.

A cut transfer is still refused rather than cached: a body shorter than the `Content-Length` the upstream declared fails, the spool file is removed, and no checksum is recorded. Caching short bytes as authoritative is what made every later fetch of the real artifact fail verification against the truncated digest.

The npm packument and the PyPI simple index are the two responses bodega parses rather than relays. A miss on either is spooled and cached like any other object, so the ceilings above still decide what upstream may send; the parse runs on the way out, on a copy read back into memory. For the packument that read is capped at 256 MB on every path it takes — the cache hit, the spooled miss, and the direct fetch the hidden-version filter uses — and a document over the cap is refused with a `502` rather than served with its upstream `dist.tarball` URLs intact.

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

The TUI reaches none of that. Its freeze, delete and remove actions call the same work the verbs do without passing through cobra, so they signal from the run helpers themselves; a mutating action added there gets it by construction rather than by remembering. Which CLI verb signals is declared once per command where it is registered in `cmd/bodega/main.go`, and a group answers for its subtree; a leaf overrides its group, which is how `bodega policy osv rescan` signals from under a quiet `policy`. `TestEveryRunnableCommandIsClassified` fails the build on a command that declares neither, because a verb missing its signal looks exactly like a verb that never needed one: `pkg hide`, `freeze`, `refresh` and `remove` each shipped without it, and a hidden package stayed published until someone restarted the server. `bodega apt key` and `bodega acl` are in the quiet group on purpose: the rotation runbook above signals with `systemctl reload`, and the access lists carry their own 30s cache.

The retry interval matters because a snapshot that never built is a 503 on every apt request, and the ordinary way to land there is transient: expired credentials, or a network that was not up when systemd started the unit. Those clear in seconds and the first few attempts catch them. A wrong bucket, revoked credentials or a role that lost `s3:ListBucket` never clears at all, so the interval doubles up to the hourly one: 7 attempts in the first hour rather than 240, each of which is a manifest reload, a pool listing and an `ERROR` line against a dependency already failing. The first snapshot puts the loop straight back on the hourly interval however far the retry had walked.

A mutation-API rebuild runs on a background context rather than the request's. The write commits before the rebuild starts, so a client that hangs up in between would otherwise get its change persisted and the index left describing the state before it.

`Release` carries `Date` backdated 24 hours to tolerate client clock skew, and `Valid-Until` 14 days after that. The expiry is stamped when the snapshot is built and does not move on its own, which is why the refresh ticker is not an optimization: a server whose refresh loop stops eventually serves an expired `Release`, and every client fails `apt update` at once — including with `[trusted=yes]`, since `Acquire::Check-Valid-Until` is independent of trust. Within 24 hours of expiry the server logs at `WARN` on every `Release` fetch.

Five cases drop an entry from the index silently, and the client sees `Unable to locate package` for all five, which is also what a typo produces. Each is logged at `WARN` once per rebuild:

- The entry names suites, none of which is in `apt_suites`. This one also appears in `GET /api/v1/status` as `apt.unserved`, so an operator holding the API can tell a missing package from a misspelled one without reading the server's log. A suite name no configuration could ever serve (one containing `/`, which `apt_suites` rejects at load) is refused at the write instead, by both `POST /api/v1/packages/apt` and `bodega pkg import`.
- The entry has no `version`. No CLI verb can address a versionless entry, so publishing one hands clients a package nobody can withdraw. `POST /api/v1/packages/apt`, `bodega pkg import` and `bodega pkg edit` refuse to write one; `bodega repair` clears the ones already in a manifest.
- The entry has no `Architecture` in its metadata. deb822 has no default architecture, so there is nothing to substitute; set it with `bodega pkg edit` or re-run the build.
- The entry has no `_pool_path` and no `.deb` in the pool matches its name, version and architecture. Ordinarily this is the gap between `bodega pkg create` and the upload that follows.
- The entry matched a pool object by filename, carries no `SHA256`, and this instance's `pool/` has held upstream bytes — a checksum row records a mirrored fetch, or `apt_upstreams` is set. A filename match is not evidence of provenance there, and a stanza with no digest leaves the client nothing to check the substitution against. Record the digest with `bodega pkg edit`, or re-run `bodega build package` so the entry carries `_pool_path` and `_sha256` together. On an instance that has never mirrored, an out-of-band upload with no digest still publishes.

An entry that records `_pool_path` addresses its pool object directly, so an index whose entries all carry one is built without listing the pool at all. A listing is taken only for the entries that need the filename match, cached for `metadata_ttl`, and re-taken when the cached one leaves any of them unresolved — but no more often than every 15 seconds. The two bounds answer opposite failures. Without the re-take, a `.deb` uploaded out of band stays out of the index for the whole `metadata_ttl` and stays out silently. Without the floor under it, an entry staged before its `.deb` is uploaded holds the index in the unresolved state indefinitely, and every apt write then pays for a full walk of the pool on every configured backend: one listing per write for the length of a bulk import.

The filename match is exact — `<package>_<version>_<architecture>.deb` and nothing looser — and objects the mirror cached are excluded from it. Both matter on any instance that has ever mirrored: `pool/` then holds `.deb`s bodega did not build, an entry without `_pool_path` publishes no `SHA256` (that field comes from the same metadata `_pool_path` does), and a client has nothing to check the substitution against. Bodega tells the two apart by the audit checksum table, which holds a row per mirrored fetch, and consults it on every rebuild that has an entry to resolve by filename. **Removing `apt_upstreams` does not make the exclusion unnecessary.** Retiring mirroring leaves every cached upstream `.deb` in `pool/` and every checksum row in the database; an index built from the config alone would republish those bytes under bodega's own signature the next time the snapshot was rebuilt. `bodega pkg checksum clear apt <name>` blanks the digest and leaves the row for exactly this reason: the row is what keeps the artifact out of the index, and it outlives the digest an operator clears to escape a 502. On a mirroring instance whose audit database cannot be read, no entry without `_pool_path` reaches the index at all and the rebuild says so at `WARN`; entries that carry `_pool_path` are unaffected, so the repository keeps serving.

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

bodega has no ACME client. `tls_autocert` and `tls_domain` were config keys that nothing implemented, and they are gone. Both halves say so rather than disappearing: a file that still carries `tls_autocert: true` logs at startup that nothing reads it, and `--tls-autocert`/`--tls-domain` still parse — hidden and deprecated, off `--help` — so an upgraded unit file starts and gets the same message instead of `unknown flag: --tls-autocert` and exit 1 on every `Restart=always` cycle. Get a certificate from `certbot` or your CA, or terminate TLS at a proxy in front and set `public_url`.

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

#### Caching in front of a profile-enforced bodega

Leave the proxy cache off for `/pypi/`, `/npm/`, `/go/`, `/cargo/`, `/helm/`, `/git/` and `/binaries/`, or let it obey the headers bodega sends and nothing more.

A profile decides what those routes return, so one URL answers two hosts with two documents. A shared cache cannot evaluate a profile: it stores the first answer and hands it to the next host, with no denial row written and no error anywhere. bodega closes this from its side — artifacts go out `private`, indexes go out `no-cache, no-store, must-revalidate` — but a proxy configured to cache past the response headers reopens it. In nginx that means not setting `proxy_ignore_headers Cache-Control` and not forcing `proxy_cache_valid` on these locations.

`/apt/` is the exception and may be cached normally: apt is not profile-enforced, so every host gets the same `.deb` and the pool still ships `public, max-age=31536000, immutable`.

To check what a deployment is sending:

```bash
curl -sI -H "Authorization: Bearer $BODEGA_TOKEN" \
  https://bodega.example.com/pypi/wheels/requests-2.31.0-py3-none-any.whl | grep -i cache-control
# cache-control: private, max-age=31536000, immutable
```

A `public` on any route but `/apt/` means the request did not reach this version of bodega.

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
| GET | `/api/v1/packages/{type}/{name}/{version}` | One version, as a manifest scoped to it. Carries the `vetting.osv.*` keys on `metadata` |
| GET | `/api/v1/status` | Health check with entry counts, S3 probe, and the apt client state |
| GET | `/api/v1/config` | Non-sensitive config (bucket, region, manifest_dir) |
| GET | `/api/v1/audit` | Query audit events (supports filters) |
| GET | `/api/v1/profiles/{name}/pins` | One profile's pins, with their reason, review date and OSV state. `?stale=true` narrows to the overdue ones. Admin-gated. See [Pins as recorded decisions](#pins-as-recorded-decisions) |
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
- **`?merge=true`**: adds versions to packages that already exist, matching `pkg import --merge`. A recorded version is never overwritten, which keeps a `hosted` entry from being downgraded to `proxy` by a re-import. The `_origin` metadata key is the exception: a merge unions it, so a version reported by `db01` and then by `db02` records both. This route and `bodega pkg import` share one merge, `admit.MergeVersions`, so the answer cannot depend on which of the two wrote it. `POST /api/v1/packages/{type}` does not merge at all: it answers `409 Conflict` on a package that already exists. All three share `admit.Admit`.
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
| `pypi_upstream` | `https://pypi.org` | The PEP 503 index root. bodega reads `/simple/{dist}/` under it and fetches the artifact URL that page lists, which is on `files.pythonhosted.org` under a content-hash path. A wheel URL cannot be composed from a filename, so a request for a file the index does not list is a 404 naming the index that was read. What bodega serves at its own `/pypi/simple/{dist}/` is that document republished, not relayed: see [Republishing a proxied index](#republishing-a-proxied-index) |
| `cargo_upstream` | `https://index.crates.io` | The sparse index, and nothing else. A crate tarball request to this host is a 404 |
| `cargo_dl_upstream` | `https://static.crates.io/crates` | Crate tarballs. bodega appends `/{crate}/{version}/download` |

crates.io names its own download root in `https://index.crates.io/config.json`, and bodega does not read it. Fetching that document at startup would make `bodega serve` fail to bind because a registry was unreachable, and an operator mirroring the index is not thereby mirroring the tarballs: point the two keys wherever each actually lives.

#### Republishing a proxied index

A pypi simple index names its files by absolute URL, every one of them on `files.pythonhosted.org`. Relayed as it arrives, it points `pip` past bodega: the client resolves through the proxy and downloads around it, so nothing lands in the cache, the allow-list never sees the artifact request, no discovery or audit row records the bytes that got installed, and the checksum verification never runs.

bodega rewrites each `href` onto its own `/pypi/wheels/{filename}` before serving. The cached object is still the upstream document byte for byte: the rewrite happens on the way out, so a cache hit and a cache miss republish identically and the stored copy remains evidence of what pypi published.

A proxy-mode distribution is republished on every request, whether or not the cache already holds one of its wheels. Only a hosted distribution gets the listing bodega generates from its own storage, which names the files it holds and nothing else. Serving that listing for a proxy-mode distribution would pin it to the first wheel anybody fetched, so `pip install six==1.16.0` would leave every other version of `six` invisible to the next client. Nothing is lost by republishing: `/pypi/wheels/` answers from storage before it resolves anything upstream, so a cached wheel still serves from the cache.

Two attributes decide the client's behavior and are treated differently:

- The `#sha256=` fragment survives. It is `pip`'s integrity check on the artifact, and dropping it would have clients install bytes they cannot verify.
- `data-dist-info-metadata` and `data-core-metadata` (PEP 658, PEP 714) are dropped. Both promise that `<href>.metadata` is fetchable, and only `files.pythonhosted.org` publishes that file; bodega resolves a wheel by matching its filename against the index, which lists no `.whl.metadata` entry. Carried forward, `pip` 26.2.1 fails the install outright rather than falling back — `ERROR: 404 Client Error: Not Found for url: .../six-1.16.0-py2.py3-none-any.whl.metadata`. Dropped, the same client downloads the whole wheel through the proxy, which costs one metadata round trip per install and is the fetch that fills the cache and reaches the allow-list.

Everything else on the anchor, `data-requires-python` included, passes through untouched.

The allow-list checks the package name for `pypi`, `npm` and `gomod`, so `bodega policy add pypi <dist>` keeps working across the two pypi hosts. `cargo` is name-scoped the same way, and a rule constrains the crate rather than the host either key names.

---

## Checksum Verification

Checksums protect against upstream tampering and bit-rot.

**Builder path** (hosted entries):
- First `bodega build fetch`: computes SHA-256, stores on the manifest entry
- Subsequent fetches: verifies against stored checksum; fails on mismatch

**Proxy path** (cached entries):
- First proxy fetch: computes SHA-256, stores in audit DB under the artifact's type, name and version, all three read back out of the object key
- Subsequent proxy fetches: verifies against stored; returns **502 Bad Gateway** on mismatch

When an upstream republishes different bytes under a version it already served, every subsequent fetch answers 502 with `checksum verification failed — upstream content may be tampered`. Clearing the stored digest is the way out, and it is why the row carries package identity: `clear` matches by type and name, and rows recorded without them could only be reached by editing the database. A row with no digest reads as one never fetched, so the next fetch stores what it computed rather than answering 502 forever. Stores mirrored before this release have their identity re-derived from `s3_key` once, on the first open after upgrade; the log line names the row count.

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
| 500/s | `sqlite` | 803 | 0% | 1.27 s |
| | `postgres` | 989 | 0% | 24 ms |
| | `syslog` | 1,000 | 0% | 3.1 ms |
| | `jsonl` | 1,000 | 0% | 2.2 ms |
| 1,000/s | `sqlite` | 1,772 | 0% | 951 ms |
| | `postgres` | 1,997 | 0% | 17 ms |
| | `syslog` | 1,998 | 0% | 3.4 ms |
| | `jsonl` | 1,999 | 0% | 2.0 ms |
| 2,000/s | `sqlite` | 3,608 | 0% | 638 ms |
| | `postgres` | 3,993 | 0% | 15 ms |
| | `syslog` | 3,998 | 0% | 3.2 ms |
| | `jsonl` | 3,997 | 0% | 2.6 ms |
| 8,000/s | `sqlite` | 8,941 | 64.4% | 180 ms |
| | `postgres` | 15,979 | 0% | 15 ms |
| | `syslog` | 15,990 | 0% | 3.0 ms |
| | `jsonl` | 15,992 | 0% | 2.6 ms |

Unthrottled, the same harness sustains 8,639 hot-path writes/s on `sqlite` (7 of 92,267 lost to the 5 s busy timeout, p99 57 ms), 11,720/s on `postgres` (none lost, p99 21 ms), 132,055/s on `syslog` and 199,655/s on `jsonl`.

Convert a fleet to a request rate with `hosts x updates-per-hour x requests-per-update / 3600`. A thousand hosts running `apt update` twice an hour over a dozen index paths is about 7 requests/s; a CI fleet installing packages per build is one to two orders of magnitude above that.

- **Up to ~2,000 requests/s: `sqlite`.** Nothing drops, and the store you already have needs no daemon. Its hot-path p99 is the worst of the four even at 500 requests/s (over a second, because the request goroutine waits on the write lock the discovery batch holds), but that latency is off the response path.
- **Above ~2,000 requests/s, or more than one bodega: `postgres`.** It dropped no observations at any rate measured here and lost no hot-path write to a timeout, and its p99 stays under 25 ms across the whole range. It is also the only way to report across instances: each host keeps its own `audit_db` for ACLs and tokens, and their events land in one place.
- **When the SIEM already exists, at any rate: `syslog` or `jsonl`.** Neither dropped a row at any rate measured, and both have the cheapest hot-path latency of the four. You are trading `bodega discover promote` and `GET /api/v1/audit` for that; if you need them back, run one instance on `postgres`.

**What `sqlite` drops at 8,000 requests/s is the write lock, not the drain.** `DiscoveryRecorder` accumulates up to 128 observations or 50 ms, whichever comes first, and writes the batch as one statement. Serially it was one write latency per row, which held the drain to about 2,700 rows/s on `sqlite` and about 900/s on `postgres` (each upsert there costs a network round trip) however wide the pool underneath was, and made `postgres` drop more observations than `sqlite` at 2,000 requests/s while absorbing 40% more hot-path writes. Batched, `postgres` drains 11,700 rows/s and takes everything offered at 8,000 requests/s. `sqlite` takes everything up to 2,000 and drops 64% at 8,000, because its batch contends with 64 request goroutines for the one write lock, which is a property of the store rather than of how the queue is drained.

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
| `push_refused` | A git smart-HTTP push against a read-only mirror, on the `info/refs?service=git-receive-pack` probe or the `git-receive-pack` POST. `pkg_name` is the namespace, `details` the repository path. The POST reaches this only from inside `admin_permit_cidr`; from anywhere else `ip_not_permitted` refuses it first |
| `spool_artifact_too_large` | A proxied artifact over `spool_max_artifact_bytes`. See [Large artifacts and the spool directory](#large-artifacts-and-the-spool-directory) |
| `spool_budget_exhausted` | A proxy fetch arriving while `spool_max_total_bytes` is already held by the fetches in flight. `details` carries the bytes held and the number of fetches holding them |

The first eight gates run in the middleware chain, before any handler; the last five are decided by the handler itself. Both write the same row, because an operator asking "who was turned away" is asking one question.

The two `spool_*` statuses are refusals about this host rather than about the client, and they are in the same table on purpose: the operator's question is "why did that fetch not happen", and an answer split across two channels is one nobody correlates.

The row is written on a context detached from the request. `net/http` cancels the request context the moment a client closes the connection, so a caller that fires a request and hangs up without reading the response — ordinary scanner behavior — got its 403 and left no row, which made the rows least reliable exactly where they matter most.

The row carries the client IP, the User-Agent, and a `details` JSON blob with the method and path. It carries **no credential**: `token_expired` records the token id, `token_invalid` records the first 12 hex of the peppered hash — enough to tell two rejected callers apart, useless without the pepper — and no header is ever copied in. Client-controlled strings are capped at 256 bytes each, so an unauthenticated stranger does not choose how much disk a 403 costs.

The lifecycle rows bracket everything else. Without them a quiet database is ambiguous: nobody was turned away, or the server was not running. Their `details` carry the bound address, the PID, and the proxy spool's directory and both ceilings, so a `spool_budget_exhausted` row can be read against the budget the run it happened in was configured with.

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
- **Request and response headers or bodies.** Those are a `log_level: 3` (debug) and `log_level: 4` (trace) concern in the journal, not an audit record, and a header dump would carry the very credentials the denial rows are careful not to hold. The journal dump redacts them for the same reason: `Authorization`, `Proxy-Authorization`, `Cookie` and `Set-Cookie` log their name and `[redacted]` in place of the value, so a debug log still answers whether a client sent a credential and holds nothing that can be replayed. Read-path identity is what made that pressing — before it the only `Authorization` headers arriving were operator mutations, and now every package GET can carry one that `bodega doctor --write-credentials` put on the client host.
- **Successful admin reads.** Only the refusals are rows; a permitted `GET /api/v1/audit` is journal-only.

Denials record at every gate in the middleware chain, at the admin-read gate, and at the five refusals a handler decides for itself: a `DELETE` on a frozen entry (`entry_frozen`), a version outside an entry's `version_constraint` (`version_constraint`), a git push against a read-only mirror (`push_refused`, on both the `info/refs?service=git-receive-pack` probe and the `git-receive-pack` POST), and the two proxy spool bounds (`spool_artifact_too_large`, `spool_budget_exhausted`). The `status` column names which gate refused.

**What a refusal costs.** The denial row is the only database write an anonymous caller controls, and it is synchronous. Sixty-four concurrent 403s were sixty-four goroutines contending for SQLite's single write lock: the refusal rate fell from 6,100/s to 800/s and the slowest single 403 took 1.6 seconds. bodega admits one denial writer at a time. Removing the contention restores the serial rate, at 8,500 refusals/s with the slowest single 403 under 20ms at that same 64-way concurrency. There is no tuning knob for the limit, because every larger value measured worse.

Callers past the first wait in arrival order, and none is discarded: a `denied` row is the record of who was turned away and has no second source. That is the difference between this path and `discover_mode`, whose queue drops an observation rather than delay a request. The wait shares the 10-second ceiling the write already had, so a database wedged for that long still loses the row, as it did before this bound existed.

An allow-list refusal is a `cache` event with `status=policy_violation` rather than a `denied` row, and it is written wherever the refusal is decided: on the proxy path, and on the apt pool probe, which refuses a `.deb` before any fetch exists to record one.

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
│ cargo/             │                            │
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
| `/` | Filter sources (Sources pane), find text (Log pane) |
| `?` | Show help |
| `q` | Quit |
| `C` | Open config editor |
| `E` | Edit the selected entry as raw JSON |
| `L` | Query the audit log |
| `T` | Open token manager |

With the Log pane focused:

| Key | Action |
|-----|--------|
| `/` | Find text; the view jumps to the first match |
| `f` | Filter the pane to matching lines only |
| `n` / `N` | Next / previous match |
| `Esc` | Clear the query; a second press returns focus to Sources |

Both queries are case-insensitive substring matches, applied on every keystroke, and they match the text a line prints rather than the escape sequences that color it. The pane title carries the query and the match position, `/apt (2/17)` for a find and `filter:apt (17)` for a filter. `n` and `N` wrap at the ends. The current match is highlighted, which is also how you spot a query with no hits: the count reads `(0/0)` and nothing is marked.

The `?` help lays its sections into as many columns as the terminal is wide enough to hold, fewest first, because the full list is 55 rows and a popup cannot scroll. Sections are never split across a column break, and the reading order runs down a column then across. A terminal too narrow for two columns gets the single-column list back, taller than the screen.

### Config editor

Press `C` to open the config form. `Ctrl+S` saves, `Ctrl+T` loads defaults into the fields, `Ctrl+R` removes those fields' keys from the config file. Changes take effect immediately.

A save writes the keys you edited, plus any key whose value differs from what the running process resolved. Fields are prefilled with that resolved config — what is in force, flags and environment included — so pressing save without touching a field records nothing, and the log line says the file is unchanged rather than claiming a save. Editing a field pins its key even when you type back the value already shown: `bodega --manifest-dir /srv/m shell` prefills `/srv/m`, and retyping it is how you make it stick. The log line names the keys that reached the file.

`Ctrl+R` reaches the eleven fields on the form and nothing else. Every other key in the file survives it: `token`, `deny_list`, `admin_permit_cidr`, `audit_db`, `discover_mode`, `apt_codename`, the upstream keys and the TLS pair. Its log line names the keys it removed. Clearing an `admin_permit_cidr` you no longer want is `bodega acl admin`, not a reset.

The reset deletes those eleven keys rather than writing the built-in defaults into them, and the difference shows the moment a flag is in play. A save writes only what differs from the resolved config, so under `bodega --region us-west-2 shell`, where `us-west-2` is also the built-in default, assigning the default back is a difference of nothing: the file went on naming `us-east-1` and the log line said the fields were already at their defaults. An absent key already means "use the built-in default" everywhere else, it keeps meaning that if a later release changes what the default is, and it is the one form the diff cannot skip.

The form edits no ACL. `deny_list`, `admin_permit_cidr` and `trusted_proxies` are seeded from the config file on first start and inert afterwards, so a field writing them to `config.json` would accept a value, save it, report success and change nothing about who the server refuses. Edit them with `bodega acl deny`, `bodega acl admin` and `bodega acl proxies`; the form says so under its title.

### Details pane

The last field of an entry is the client instruction, and its label names the shape rather than assuming a URL: **Sources line** for apt, **Registry stanza** for cargo, **Package URL** for the other six. All three carry the base URL `public_url` and the TLS pair resolve to, so a pane behind a terminating proxy prints what a client outside it reaches.

cargo is the one type whose instruction is a file rather than a command. A client reaches the sparse index only once `.cargo/config.toml` names it as a registry, so the field carries the stanza and the command that uses it as one value:

```toml
[registries.bodega]
index = "sparse+https://bodega.example.com/cargo/"
# cargo add --registry bodega <crate>
```

The command is a TOML comment because the web dashboard's copy affordance copies the field verbatim and its destination is that config file: a bare shell line pasted there fails the parse. Uncomment it, or retype it at a prompt.

In the TUI the stanza's three lines are rendered one per row and never reflowed, so a pane too narrow to hold `index = "..."` cuts the line at the right edge instead of wrapping it. The pane offers nothing to copy, so what an operator reads is what they retype: a wrapped `index =` is a TOML parse error, and cargo reports it against their config file rather than against the pane. Widening the terminal is the fix, and the floor is around 85 columns for a loopback base, rising with the length of `public_url`: `https://bodega.example.com` needs 92. Do not count on the cut announcing itself. At 84 columns with bodega's default port it takes the closing quote and nothing else, leaving a line that reads as finished and parses as an unterminated string, so the row to check is the one ending `/cargo/"`.

The **Sources line** field for an apt entry is a command an operator pastes into `/etc/apt/sources.list.d/`, so it is rendered by the server-side renderer every other emitter uses ([Client configuration](#client-configuration)) rather than composed in the pane. Two things it does that are not obvious:

- **The suite is intersected against the served set.** The pane names the first suite the entry is published to that `apt_suites` (or `apt_codename`) also answers for. An entry naming a suite outside that set reaches no index, and a line pointing at it 404s the whole `dists/` path, which apt reports as "Unable to locate package" — the message a misspelled name produces. The fallback is the first served suite. `GET /api/v1/status` lists such entries under `apt.unserved`.
- **The signing state comes from the key file, not the running server.** The pane applies the same acceptance test `bodega serve` does — the key must load, and both its armored and dearmored public forms must render — but it reads the file. A server that already loaded a key keeps signing after the file is deleted, because a reload never takes signing away (see [Rotation](#rotation)), so the two disagree until a restart. A note beside the line says so and points at `GET /api/v1/status`, which reports what the server is actually doing.

### Audit log

`L` opens a query form over the audit trail (event type, package type, package name, client IP, limit). Results open in a scrollable table: `Up`/`Down` move, `Esc` or `q` closes it, and the Log pane keeps a line recording how many events the query returned.

The table sizes its columns from the rows it is showing, not from a fixed width, because the values that overflow a guessed width are the common case rather than the exception: `serve_fetch` is 11 characters and `dists/jammy-backports/InRelease` is 31. Two things follow from that:

- **A column no event filled in is dropped.** Served requests carry no `DURATION`, so querying them gives that width back to `NAME` instead of printing a column of nothing.
- **`NAME` is the column that gives up width first, and it loses its head.** A package name is a path whose identifying part is at the end, so a truncated one reads `…orts/InRelease`. Every other column is short enough to print whole; widen the terminal to see a name in full.

`bodega audit events` prints the same data as fixed-width text for a pipeline.

### Build stages

The build menu dispatches all eight entry types. Only `apt` and `pypi` have a build step and only `apt`, `git`, `pypi`, `helm` and `npm` have a package step; the rest say which stage does not apply to them rather than reporting an empty success. `helm` and `npm` package across the whole type — `index.yaml` and the packuments are repository metadata, not per-entry archives — so those two stages ignore the selected entry and regenerate everything.

---

## Web Dashboard

Access the dashboard at `https://bodega-host:8080/` when the server is running.

**Features:**
- **Live metrics**: package counts by type, total artifact size, version statistics
- **Status view**: per-package build and upload status
- **Copy utilities**: one-click copy for the client instruction (Package URL, Sources line or Registry stanza, per type) and Package JSON Config
- **Browser-based browsing**: explore packages by type and version

The type list is the server's, not the page's. The tree, the per-type bars and both expand-all loops render one group per key in the `/api/v1/packages` envelope, which carries every ecosystem the server knows with an empty array for the ones holding nothing. The page keeps a preferred order (apt first, then git, pypi, binary, gomod, helm, npm) and anything outside it renders after, sorted. So an ecosystem added to the server shows up in a browser with no change to the page, and a stored package can never be missing from the tree while the header counts it.

The header states two counts, not one: `2 packages, 4 versions`. The first is the package total the server reports in `entry_count`; the second is summed from the same function the tree renders each group from, so it equals the group counts below it by construction rather than by coincidence. Both are the served totals and neither follows the filter box.

A permalink naming a type the server does not serve is refused by name: `#<type>/<name>/<version>` is checked against those same keys, and a stale bookmark gets a message naming the type it asked for and the types this instance answers for.

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
