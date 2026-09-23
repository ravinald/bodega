# Usage

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
- [Storage Layout](#storage-layout)
- [Development](#development)

---

## Commands

### `bodega init`

Creates the S3 bucket with server-side encryption (AES-256), versioning enabled, and all public access blocked. Idempotent. Only needed when `storage_backend` is `"s3"`. Local storage requires no initialization.

### `bodega build fetch [TYPE...] [NAME]`

Downloads raw sources without building or packaging. If no types are given, all nine are fetched in dependency order: `binary, git, apt, pypi, gomod, helm, npm, cargo, freebsd`.

When a name is given after the type, only that entry is fetched.

```bash
bodega build fetch                 # fetch all types
bodega build fetch git             # fetch git sources only
bodega build fetch git widget      # fetch only widget
```

#### How a pypi version is resolved

A pypi fetch resolves each manifest entry to one concrete version and records it in `<build-root>/combined-requirements.txt`. Resolution happens here, at fetch, rather than in pip: a bare requirement line means "newest that satisfies the closure", and pip has no notion of an approved version to weigh that against. The fetch then downloads the closure that file resolves to into `<build-root>/wheelhouse/` and writes `<build-root>/resolved-requirements.txt`, which pins every distribution in it with a SHA-256. See [What reaches pip](#what-reaches-pip).

Versions are read, ordered and compared as [PEP 440](https://packaging.python.org/en/latest/specifications/version-specifiers/), which is the scheme PyPI publishes and semver cannot read. `1.16.0.post1`, `2.0.0rc1`, `1!2.0` and `0.6.dev1` are ordinary releases on an index; under semver every one of them is unparseable and drops out of the candidate list, which reads exactly like the release not existing. `pytz` is the live example: its newest release is `2026.3.post1`, and a semver filter resolves `any` to the release before it.

What each `version_constraint` resolves to:

| `version_constraint` | Resolves to                                                                                                                                                                |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `exact`, or absent   | The version named, compared under PEP 440 rather than as a string, so `1.16` matches `1.16.0` and `2.0.0-rc-1` matches `2.0.0rc1`. Fails when the index does not offer it. |
| `patch`              | The newest release sharing the named version's epoch and major.minor.                                                                                                      |
| `compatible`         | The newest release sharing the named version's epoch and major.                                                                                                            |
| `any`                | The newest release the index offers. This is how to say "latest".                                                                                                          |

The resolved version is written as `six===1.16.0`, in PEP 440's canonical spelling. Arbitrary equality (`===`) rather than `==`, because `==` ignores a candidate's local label when the specifier carries none: against an index offering both `1.16.0` and `1.16.0+vendor.1`, `six==1.16.0` downloads the vendored build. Measured on pip 26.2.1. An entry naming `1.16.0+vendor.1` still gets that build — the label is part of the version, and local labels order by PEP 440 segment rules, so `+vendor.10` is newer than `+vendor.9` and `+9` is newer than either.

The canonical spelling is not cosmetic: pip compares `===` by string equality against a candidate's normalized version, so an index listing `1.0-1` serves a wheel pip reads as `1.0.post1` and the raw spelling matches nothing.

The floating constraints (`patch`, `compatible`, `any`) take a pre-release or dev release only when the version the entry names is itself one. A project publishing `2.0.0rc1` would otherwise move every `any` entry onto a release candidate nobody approved. A post release is not a pre-release: `1.16.0.post1` ships after `1.16.0` and qualifies everywhere.

An entry whose `version` is empty or `*` resolves to nothing and keeps a bare, unpinned requirement line, whatever its constraint says. That is the form an auto-imported dependency arrives in, and pinning it would over-constrain a closure the base `-r` requirements already decide.

A version outside PEP 440 still resolves under `exact`, by literal match. `pytz` shipped `2011k`, which no parser will order but an index plainly offers.

##### Which index

Every entry resolves against one index for the whole type, and the same index serves the download. It is read from `url` on whichever entries name one, and is `https://pypi.org` when none do.

One index rather than one per entry, because a fetch writes a single requirements file and pip honors one `--index-url` across all of it. Resolving each entry against its own origin and then letting pip download from its default is how a version gets approved on one index and its bytes arrive from another. So the selected index is written into the requirements file as `--index-url <url>/simple/` and passed to `pip wheel` as an argument, and two entries naming different origins fail the fetch:

```text
pypi entries name 2 different indexes and one fetch can use one: https://a.example (six); https://b.example (attrs)
```

The default index is written out like any other. A deployment that wants its own mirror names it on the manifest entry; pointing pip at one through `pip.conf` no longer reaches the build, because the build runs pip with `--isolated` and an environment holding no `PIP_*` variable. pip reads those as configuration at a precedence above the requirements file, so an index named in either moves acquisition without appearing in any file this could examine, and an index nothing states is an index nothing enforces.

##### What reaches pip

The build reaches no index. The fetch downloads the closure; the build turns bytes already on disk into wheels:

```bash
pip wheel --isolated --no-index --find-links <build-root>/wheelhouse --require-hashes \
    --wheel-dir <build-root>/wheels -r <build-root>/resolved-requirements.txt
```

`--no-index` is the one index control a requirements file cannot undo. pip lets a file's `--index-url` replace a command-line one outright, so pointing the build at the approved index was always the weaker half of that pair. `opts.no_index` can only be set, and every index option in `pip/_internal/req/req_file.py` is guarded by `and not no_index`, so an `--index-url`, `--extra-index-url` or `-f` at any include depth changes nothing about where bytes come from. `--find-links` appends unconditionally, which is why `--require-hashes` is there too: a link reaching pip by some other route still cannot produce bytes the fetch did not record.

`resolved-requirements.txt` is the closure, one pinned line per distribution carrying a `--hash=sha256:` for every file the fetch stored:

```text
attrs==24.2.0 \
    --hash=sha256:81921eb96de3191c8258c705618104dcb9a1c1a70e57e239745cb0dbbc9d6d4c
six==1.16.0 \
    --hash=sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254
```

Each of those digests is also a row in `bodega pkg checksum list`, keyed `pypi/wheels/<filename>` — the key the server serves that wheel under. A second fetch producing different bytes for a version already on record is refused, and the wheelhouse it wrote into is discarded with it. Before pip runs, the build re-digests the wheelhouse against the lock, so a file edited between the two stages fails naming the distribution and both digests rather than reporting whichever candidate pip reached first:

```text
pypi six==1.16.0: six-1.16.0-py3-none-any.whl no longer matches the digest recorded at fetch: recorded=8abb2f1d… received=63df92ac…
```

Both stages run pip out of one virtualenv under `<build-root>/build-venv`, which the fetch creates and the build reuses. It needs a `python3` whose `ensurepip` works — `python3-venv` on Debian and Ubuntu, `python3.<minor>-venv` where the distribution splits it per minor version. A host without it fails the stage naming that package rather than bootstrapping pip by piping `bootstrap.pypa.io/get-pip.py` into the interpreter, which is an origin outside every control here. Nothing upgrades that pip, so it is whatever the platform's `ensurepip` bundles.

A source distribution in the closure is built at build time, and pip assembles its build environment through the same finder, so the backend has to be in the wheelhouse. `setuptools` and `wheel` are downloaded alongside the closure whenever it holds an sdist; a distribution needing another backend (`hatchling`, `flit_core`, `poetry-core`) is named as a pypi manifest entry, which puts it in the closure like anything else.

The applications' own requirements files are read at fetch and written out again, not handed to pip by reference. The generated `combined-requirements.txt` holds the selected index, the lines read from each application's file with `-r` and `-c` includes resolved in place, and one pin per manifest entry. It is what the closure is resolved from; it never reaches the build. `-c` includes land in a generated `combined-constraints.txt` instead, reached by a single `-c`, because a constraint restricts a version without requesting the package and flattening one into the requirements installs what an application only meant to bound.

Inlining rather than including, because an `-r` pointing back at the application's file leaves two parsers over one set of bytes: this one at fetch, pip's at build. Every difference between them is an acquisition instruction approved against one index and carried out against another, and five of them were found one at a time. What this reads is now what pip reads, so a construct read wrongly produces a wrong requirement rather than a silent change of origin.

Lines are read the way pip reads them: backslash continuations joined, comments stripped, the requirement and option halves of a line split on a literal space before any quote is removed, the option half tokenized by the same POSIX `shlex` rules pip uses, and `-r` and `-c` followed to any depth. Every option is classified before the file is accepted:

| Option                                                                                                                                                 | What the fetch does                                                  |
| ------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------- |
| `-i`, `--index-url`                                                                                                                                    | Passes when it names the selected index, fails when it names another |
| `--extra-index-url`, `-f`/`--find-links`, `--no-index`, `--trusted-host`                                                                               | Fails: each one acquires outside the approved index                  |
| `-r`/`--requirement`, `-c`/`--constraint`                                                                                                              | Followed, and the included file is read under these same rules       |
| `-e`/`--editable` naming a URL, or a requirement carrying its own download (`six @ https://host/six.whl`)                                              | Fails: pip downloads it without asking any index                     |
| `--pre`, `--prefer-binary`, `--require-hashes`, `--no-binary`, `--only-binary`, `--hash`, `-C`/`--config-settings`, `--global-option`, `--use-feature` | Accepted: none of them decides an origin                             |
| anything else                                                                                                                                          | Fails as uninterpreted                                               |

An include is resolved by replacing its line with the file it names, so it has to be the only thing on that line. An include beside a requirement is one pip ignores outright, because a requirement line's options are scoped to that requirement; an include beside another option would drop that option when the line is replaced. Both fail rather than guess.

Failing on an option nobody classified is deliberate. pip hands the line to optparse, which reads `-iURL`, `--index-url=URL`, `--index-url URL` and the unambiguous abbreviation `--index-ur URL` as the same option, and joins `--index-` and `url URL` across a backslash continuation into one before any of that. A checker matching exact tokens against physical lines reads none of those four, and an option it cannot read may be an index it never saw:

```text
pypi base requirements for widget@v4.5.5: /var/lib/bodega/git/sources/widget/widget-v4.5.5/requirements.txt names --extra-index-url https://b.example/simple/, which acquires outside the https://a.example the manifest approved
```

Quoting and escaping are part of that grammar, not decoration around it. pip runs `shlex.split` over the option half before optparse sees it, so `--pre "--index-url" https://b.example/simple/` and `--pre \--index-url https://b.example/simple/` are both an index option to pip while a reader comparing whole whitespace-separated tokens sees one inert option and two fragments naming nothing. A line neither reader can tokenize, such as an unclosed quotation, fails here for the same reason pip fails it:

```text
pypi base requirements for widget@v4.5.5: /var/lib/bodega/git/sources/widget/widget-v4.5.5/requirements.txt: --index-url "https://b.example/simple/ closes no " quotation; pip splits options the same way and fails the file, so fix the quoting
```

A quoted value is ordinary and passes on its own terms: `--index-url "<selected>/simple/"` names the selected index, and `-r "app extras.txt"` includes a path with a space in it.

Naming the selected index is agreement rather than conflict, and passes. Rejecting rather than rewriting: the file belongs to the application, and editing an origin out of it hides the disagreement instead of settling it.

##### What the file may not contain

pip decodes a requirements file and splits it into lines before it reads a single option, and both stages sit above tokenization. An option either of them produces is one no tokenizer can be taught to see: a UTF-16 file holds no `://` bytes at all, and a carriage return starts a line for pip that a reader splitting on newlines never finds. These constructs are refused rather than reproduced, because matching Python's decoding and line-breaking tables is a standing obligation and not a fix.

| Input                                                                                 | Why it fails                                                                                 |
| ------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| A byte-order mark, or a `# -*- coding: ... -*-` declaration naming anything but UTF-8 | pip decodes the whole file by it; this reads UTF-8                                           |
| Bytes that are not valid UTF-8                                                        | pip falls back to the locale encoding and reads different text                               |
| A carriage return anywhere but the end of a line                                      | `str.splitlines` starts a line there and this does not                                       |
| `\v`, `\f`, `\x1c`, `\x1d`, `\x1e`, `\u0085`, `\u2028`, `\u2029`                      | the same, for the seven other separators `str.splitlines` breaks on                          |
| `${NAME}`                                                                             | pip replaces it from its own environment; there is no escape, so the only safe reading is no |

Each failure names the file, the line and what to do:

```text
pypi base requirements for widget@v4.5.5: /var/lib/bodega/.../requirements.txt: line 12 expands ${PIP_OPTS}, which pip replaces from its own environment and this cannot see; write the value, or name the index in the manifest
```

##### When resolution fails

A version that resolves to nothing fails the whole fetch, names the entry, the version asked for and what the index offered, and writes no requirements file at all:

```text
pypi six: version_constraint "exact" on 1.99.0 resolves to nothing; the index at https://pypi.org offers 1.13.0, 1.14.0, 1.15.0, 1.16.0, 1.17.0 (34 versions in all)
```

A partial file would build cleanly and store a closure nobody approved, so there is no half-written one to find. A failure also discards the file a previous successful fetch wrote. Its existence is what `build run` reads as "fetch is done", so leaving it in place after a failed re-resolve lets the next build store the closure of a pin the manifest no longer names — the ordinary sequence being fetch, edit the version, re-fetch, build.

A release PyPI has emptied counts as not offered. Deleting a release leaves its key in the JSON document with an empty file list, and accepting the key resolves a pin to something pip cannot download, so the failure would surface inside the wheel build minutes later instead of here. `requests` `2.15.0` is the live example.

A response larger than 64 MiB fails by size rather than as malformed JSON — `pypi <name> response exceeds 67108864 bytes`. The document is read as a stream, so memory does not track the response; the cap bounds only how long a single index answer will be read. `examplesdk` measures 2,117 releases through this path.

##### What the build checks

`build run pypi` reads the pins back out of the generated file and compares them against the wheels pip stored. A pinned distribution present at a version no pin names fails the build:

```text
pypi six: the manifest names 1.16.0 and the wheels directory holds 1.16.0+vendor.1 — pip stored a version nobody approved
```

A specifier is a filter rather than a fact. An index that answers it with another build, a pip resolving it out of a cache, or a hand-edited requirements file all end with bytes on disk the manifest does not describe, and the wheels directory is what gets published. A pin with no wheel at all passes this check: pip exiting 0 having stored nothing for a requirement is a different defect, and failing it here would report it as a substitution.

#### Gaps

- **Transitive dependencies are pip's to resolve.** Only the versions the manifest names are pinned. The wheels pip pulls in behind them are whatever the closure resolves to, and the manifest does not record them until `build package` scans the wheel metadata into `dep-graph.json`.
- **An orphaned wheel already in object storage stays there.** `bodega build build pypi` removes a pinned distribution's wheels at versions no pin names before pip writes beside them, and the generated simple index publishes only versions an entry names, so a re-pin no longer leaves the old version installable. Neither reaches a wheel a previous run already uploaded: `Client.SyncDir` is upload-only. Delete the object to retire it.
- **The build toolchain is not pinned.** `pip install --upgrade pip wheel setuptools` reaches the selected index like the wheel build does, but takes whatever version that index offers, so a fixed bodega release is paired with whatever pip installed today. A selected index carrying no pip fails the build there rather than reaching past itself.
- **Controlling the requirements language does not prove the origin of every byte.** A build installs build dependencies, obtains dynamically reported build requirements and runs build backends, and a build requirement can carry a direct reference of its own. What the generated file names is checked; what a `setup.py` reaches for while it runs is not. See [Threat model](threat-model.md).
- **`bodega refresh` still orders pypi candidates as semver.** It proposes new manifest entries rather than resolving a fetch, so a `patch`-constrained entry will not see a post release offered to it.

### `bodega build run [TYPE...] [NAME]`

Compiles or prepares sources. Auto-fetches if sources are not already present (stage cascading). Types without a build step (binary, gomod, helm, npm) are skipped for the build phase.

```bash
bodega build run                   # build all types
bodega build run apt               # build apt sources only
bodega build run apt python3
```

### `bodega build sync [TYPE...] [NAME[@VERSION]]`

Pushes whatever local artifacts exist to S3 **without** running any pipeline stages. Useful when artifacts were built on a different machine.

```bash
bodega build sync                             # push all local artifacts
bodega build sync pypi helm                   # push pypi and helm only
bodega build sync binary example-tool-v2            # push one package
bodega build sync binary example-tool-v2@2.15.0 --storage bulk
```

Every type but `pypi` uploads one object per manifest version, to the backend that version records: a git bundle to `repos/<name>/`, a `.deb` to the pool path its entry carries, a binary to `binaries/<name>/<version>/`. `pypi` wheels have no per-version object key, so they sync as a directory to `pypi/wheels/` on the backend `storage_by_type.pypi` names. A version whose artifact is not on disk is skipped, and so is a type with none.

A name after the types narrows the push to one package. An argument that is neither a known type nor a package in the catalog is an error, so `bodega build sync gitt` still fails on the typo instead of filtering for a package nothing is called and exiting 0 having pushed nothing. `pypi` is skipped when a name is given, because one package of it cannot reach storage apart from the rest.

See [`--storage`](#placing-one-version-at-write-time) for directing a single version at a named backend.

### `bodega build upload [TYPE...] [NAME[@VERSION]]`

Runs the full pipeline (fetch → build) then uploads artifacts to S3. This is the most common command for end-to-end operation.

```bash
bodega build upload                # fetch, build, and upload all types
bodega build upload git            # fetch, build, and upload git only
bodega build upload git widget
bodega build upload binary example-tool-v2@2.15.0 --storage bulk
```

A name narrows the **upload**, not the cascade: `fetch`, `build` and `package` still run across the whole type, because the stage that would need the filter takes none. `bodega build sync` is the push with nothing in front of it. `pypi` is skipped when a name is given, since one package of it cannot reach storage apart from the rest.

#### Placing one version at write time

`--storage <backend>` writes one version's bytes to the backend you name, whatever the [placement hierarchy](#the-placement-hierarchy) resolves to. It is the surface for the one artifact that is too large, too sensitive or too slow to sit where the rest of its type sits, and which no rule can single out.

```bash
bodega build upload binary example-tool-v2@2.15.0 --storage bulk
bodega build sync   binary example-tool-v2@2.15.0 --storage bulk
```

It **records** the name on the version entry rather than adding a fourth rule. The next upload of that package writes to `bulk` again without the flag, because a recorded name already wins over the rule — the same lifetime `bodega pkg move` gives a version. That is the difference from `--replace-placement`, which re-applies the current rule and keeps doing so every time it is passed.

Four refusals, each because the alternative is silent:

- **One type, named.** Across every type the flag would place whatever package of that name each one happens to hold.
- **`NAME@VERSION`, not `NAME`.** Without the version it would be a package-level placement, which is `storage_policy` and already exists as `bodega pkg create --storage`.
- **A configured backend.** A name nothing answers to would be recorded on the entry and fail every later read rather than this command.
- **Not `pypi`.** A `pypi` version has no object of its own to place; set `storage_by_type.pypi` and re-upload with `--replace-placement`.

A run whose `--storage` version was never reached fails rather than reporting the uploads it did do. One digit wrong in the version and the artifact goes where the rule says with nothing on the backend the operator named:

```text
--storage bulk named example-tool-v2@2.15.1, which this run never uploaded: nothing was written to "bulk". Check the version against 'bodega show pkg binary example-tool-v2'; a frozen version is skipped by every upload, and so is one whose artifact is not on disk
```

The copy at the previous placement is left where it is and named on the way past, the same warning `pkg move` prints without `--delete-source`:

```text
    warning: example-tool-v2@2.15.0 moves to "bulk"; the copy in "default" is left behind
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

Walks every manifest in the store — one `<type>/<name>/manifest.json` per package, plus `index.json`, `graph.json` and `metrics.json` at the root — and compares each against its `.md5` sidecar. Use this to detect out-of-band modifications.

One row per manifest: `OK`, `FAIL` when the sidecar disagrees, `UNVERIFIABLE` when there is no sidecar to compare against, `ERROR` when the object could not be read. `UNVERIFIABLE` is not a pass, and the command exits non-zero when anything failed or could not be verified.

A store where no manifest carries a sidecar predates sidecars being written on every write; re-stamp it once with `bodega --break-glass-update-md5 all`. A store where some carry one and some do not has a writer that skipped a sidecar, which re-stamping hides rather than fixes. `pkg verify` says which of the two it is found.

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

Phase 4 is the only way to clear a version-less apt entry. `bodega pkg create apt` in package-name mode stages one before the upstream version is known and fills it once the lookup returns; one left over is addressable by nothing, because `pkg remove`, `pkg delete`, `hide` and `freeze` all name a version. A package whose entries are _all_ version-less is reported and left alone — that is a staging record, not a leftover.

Phase 5 corrects what `bodega discover promote --as manifest` wrote while the wheel handler composed `<index>/packages/<filename>`, a path pypi.org has never served. Nothing reads the field today, so the stored URL breaks no fetch; it is rewritten because promotion never revisits a version it already wrote, and the entry would otherwise carry a URL nothing can fetch for as long as it exists. The match is on the pattern, `<scheme>://<host>/packages/<file>`, on any host — an operator's own index that serves that path is rewritten to its root too, which is what the field means there as well. Entries of any other form are left untouched. See [Upstream hosts](#upstream-hosts) for how a wheel is resolved now.

### `bodega repair keys [--dry-run] [--delete-source] [--type TYPE]`

Moves artifacts sitting at an object key no current code path reads to the key the uploader and the server now agree on. Each object is copied, verified at its destination, and only then is the source considered — the ordering `bodega pkg move` uses, for the same reason: a backend answers a missing object with "not found" rather than an error, so an artifact lost mid-repair would look exactly like one that was never uploaded.

Source and destination are the same backend. Nothing in the manifest changes, because the key is derived rather than recorded, and re-running after an interruption is safe.

One superseded layout exists. Go modules were uploaded under the filesystem-safe name (`gomod/example.com--example-corp--widget-sdk/@v/...`) while a Go client asks for the module path with its slashes intact, so **no module uploaded before this release could be served**. Any install that ever uploaded a gomod artifact has data at the old key and needs one run of this command.

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
bodega show repo git widget        # versions of widget
bodega show repo git widget v4.5.7 # version details
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
bodega pkg freeze git widget       # freeze
bodega pkg freeze git widget       # unfreeze (toggle)
```

### `bodega pkg create <type> [name]`

Adds a new entry to a manifest interactively. The name can be given as a positional argument or prompted. All other fields (URL, version, etc.) are prompted.

For automation, use `bodega pkg import` with a JSON manifest file instead.

```bash
bodega pkg create git widget                  # prompts for url and ref
bodega pkg create apt python3                 # prompts for apt-specific fields
bodega pkg create gomod example.com/example-corp/widget-sdk   # prompts for version
bodega pkg create apt                         # fully interactive (prompts for name too)
bodega pkg create git widget --storage archive   # pin this package's writes
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

```bash
apt: recording release "jammy" on every entry (VERSION_CODENAME in /etc/os-release)
```

A host that names no codename resolves none: converting a capture on a Mac, or on a distro that publishes no `VERSION_CODENAME`, records no release and says so. The gate warns on such an entry rather than guessing a release for it, so the flag is the fix:

```bash
apt: no release recorded on these entries: no --suite, and /etc/os-release names no VERSION_CODENAME.
  The OSV gate answers an apt version from the advisories published for its own release, and warns rather than
  guessing one. Re-run with --suite <codename> to record it.
```

| Type    | Source command                                                                                                          |
| ------- | ----------------------------------------------------------------------------------------------------------------------- |
| `apt`   | `dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\t${source:Package}\n'`, or `apt list --installed` |
| `pypi`  | `pip list --format=json`                                                                                                |
| `npm`   | `npm ls --global --json --depth=0`                                                                                      |
| `gomod` | `go list -m all`, or `go version -m <binary>`                                                                           |
| `cargo` | `cargo install --list`                                                                                                  |
| `helm`  | `helm list -o json`                                                                                                     |

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

For apt specifically, `bodega build fetch apt` shells out to `apt-get download <name>=<version>` on the bodega host, so a catalog entry's version decides which `.deb` arrives and not only the storage key it lands under. The pin is checked three times: against the `Version table:` block of `apt-cache policy` before the download, by apt itself on the argv, and against the filename of what landed before it moves into the pool. A pin the local cache does not offer fails the entry naming the versions that are installable, rather than falling back to the candidate. The host can still only resolve releases its own apt sources carry: a bodega on noble cannot fetch a jammy catalog that way, and mirroring is what serves another release.

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
$ bodega pkg storage binary example-tool-v2
binary/example-tool-v2 -> bulk     (package policy)
$ bodega pkg storage apt nginx
apt/nginx  -> cold     (group rule: storage_by_group.mirror-set, from storage_groups on the package)
$ bodega pkg storage npm lodash
npm/lodash -> bulk     (type rule: storage_by_type.npm)
$ bodega pkg storage git widget
git/widget -> default  (global default; no type, group or package rule)
```

The group reason names both edits that could change the answer — the config key and the manifest field — because a line reading only `group rule` leaves an operator hunting for which of the two files to open. [`bodega pkg group`](#bodega-pkg-group-name) lists the other packages the same group holds.

`pypi` uploads a whole directory at a time, so neither the package level nor the group level is consulted for it. A `storage_policy` or a group membership on a `pypi` package is reported as skipped rather than as the level that won:

```bash
$ bodega pkg storage pypi examplesdk
pypi/examplesdk -> default  (global default; no type, group or package rule; storage_policy "bulk" is not consulted for pypi; storage_by_group.mirror-set is not consulted for pypi)
  warning: storage_policy "bulk" has no effect for pypi: pypi wheels upload as a directory with no per-version object key, so one package cannot be placed apart from the rest of its type. Set storage_by_type.pypi to place the whole type; 'bodega pkg move' refuses pypi for the same reason.
  warning: storage group "mirror-set" has no effect for pypi: pypi wheels upload as a directory with no per-version object key, so one package cannot be placed apart from the rest of its type. Set storage_by_type.pypi to place the whole type; 'bodega pkg move' refuses pypi for the same reason.
```

An operator reads this command to find out why a package landed where it did, so a level the write path will not use is worse than no level at all.

This is the write side. It says where the _next_ version goes and nothing about where versions already uploaded live; each of those records its own backend in `storage`, and the `STORED` column of `bodega show pkg <type> <name> --admin` prints it. A version that records nothing reads `default`, which is the backend the global `storage_backend` / `storage_path` / `bucket` / `region` keys describe and the one every artifact uploaded before backends were named lives on.

### `bodega pkg group [NAME]`

Lists the storage groups this install defines, or the packages one holds.

```bash
$ bodega pkg group
GROUP          BACKEND  PACKAGES  DECIDING
customer-acme  bulk     12        12
mirror-set     cold     41        39

'bodega pkg group NAME' lists one group's packages; 'bodega pkg storage TYPE NAME' resolves one package.
```

`PACKAGES` is how many manifests name the group. `DECIDING` is how many it actually places. The two columns are separate because membership is not placement, and a listing showing only the first reports forty-one packages held by a group that places thirty-nine of them:

```bash
$ bodega pkg group mirror-set
mirror-set -> cold (storage_by_group.mirror-set)

TYPE    PACKAGE    DECIDES
apt     nginx      yes
binary  kubectl    no — storage_policy "bulk" outranks it
npm     left-pad   no — group "customer-acme" wins by name
pypi    examplesdk      no — not consulted for pypi
```

A group with no packages is still listed: staging the set in the config before the manifests join it is a normal order, and omitting the row would read as a config that did not load.

This is the write side, like `bodega pkg storage`. It says nothing about where already-uploaded versions live; each records its own backend, and `bodega pkg drift` is what reports the two disagreeing.

### `bodega pkg move <type> <name>[@<version>] --to <backend>`

Copies the objects backing a package's versions to another named backend and repoints the manifest at the copy.

```bash
bodega pkg move binary example-tool-v2 --to bulk
bodega pkg move npm @example-corp/widget-cli@1.5.0 --to archive
bodega pkg move git widget@v4.5.5 --to bulk
bodega pkg move gomod example.com/example-corp/widget-sdk@v1.30.0 --to archive --delete-source
```

Movable types: `binary`, `npm`, `cargo`, `gomod`, `helm`, `apt`, `git`, `freebsd`. See [pypi is not movable](#pypi-is-not-movable) for the one that is not, and [a freebsd move is a republication](#a-freebsd-move-is-a-republication) for the one that does not follow the order above.

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
binary/example-tool-v2: backends "default" and "mirror" are the same location (file:///mnt/bulk/bodega) — every object would be copied onto itself, and --delete-source would then remove the only copy. Name a different --to, or point one of the two at another path or bucket
```

Both names are in the message because the configuration is deliberate: two names for one place is a documented way to stage a migration, so the operator needs to know which half to repoint. `Load` rejects a colliding name but not a colliding path, and does not warn about one either — see [Named backends](#named-backends-and-per-type-placement). Each object would be read and written at the same key, the verify would re-read what it had just overwritten and pass, and `--delete-source` would then remove the artifact the manifest points at. Both backends answer a missing object with "not found", so nothing afterwards could tell it had ever existed.

#### a freebsd move is a republication

A `freebsd` version is a whole mirrored repository, so the order above does not describe it. Every other type moves one artifact that stands on its own; a repository is two archives and everything they name, and a client reads the archives to find the rest. So the move copies the three repository-root files out of the source into `build_root` first, reads the object set out of **those copies**, writes and verifies every `repopath` they name at the destination, and publishes the root files last — `meta.conf`, `data.pkg`, `packagesite.pkg`, in the order a client reads them.

It does not list the source prefix. A listing answers "what is under this prefix right now", which is the right question for `bodega build status` and for `pkg delete` and is not the set a document names. A `bodega build upload freebsd` landing between the listing and the copy gives the move one generation's object list and another generation's catalogue bytes, and nothing downstream can tell: a `freebsd` entry carries no `checksum`, two generations of one repository routinely have identical archive sizes, and both commands exit 0. Copies of the archives, taken before anything is enumerated, are the only version of them no concurrent writer can replace.

Everything that can refuse runs before the first byte reaches the destination's repository root, including the `artifact_size` and `checksum` check against the copied `packagesite.pkg`. A refused move leaves the destination serving whatever generation it was already serving and the manifest still pointing at the source:

```text
latest@FreeBSD:14:amd64: the archives on "default" name All/Hashed/zogftw-2025.02.23_1~2$snxfrbid.pkg, which is not there. Publishing it on "bulk" would hand a client a repository that resolves that package and then 404s, so nothing was written to "bulk" and the manifest still points at "default". Re-run `bodega build fetch freebsd latest force` and `bodega build upload freebsd`, then move again
```

Objects on the source that neither archive names are not copied, for the same reason the upload does not upload them: no client can ask for them. `--delete-source` therefore removes what the move wrote and leaves those behind, and it removes `packagesite.pkg` first, so the window it opens on the source is a client told there is no such repository rather than one that resolves a package out of a live catalogue and cannot fetch it.

#### a generated freebsd repository moves its packages

A repository bodega generates the catalogue for stores no root files: `meta.conf`, `data.pkg` and `packagesite.pkg` are built per request from whichever backend the manifest names. The republication above has nothing to pin and nothing to publish last, so the move copies the packages alone, verifies each at the destination, and writes the manifest after them.

The listing is the document here, which reverses one rule and adds one check. A mirror refuses to enumerate by listing the prefix, because a listing is not the set a catalogue names; a generated repository has nothing else that names anything, and its catalogue is built from the listing after the move lands. The destination is therefore asked first whether it holds objects under the repository that the source does not, since those would be served as packages nobody uploaded:

```text
latest@FreeBSD:14:amd64: "bulk" already holds 1 object(s) under freebsd/FreeBSD:14:amd64/latest/ that "default" does not, the first being freebsd/FreeBSD:14:amd64/latest/All/leftover-9.9.pkg. A generated catalogue is built from whatever is under the prefix, so the moved repository would publish them as packages nobody uploaded. Nothing was written to "bulk" and the manifest still points at "default": remove them, or move to a backend that is not already serving this repository
```

An upload landing while the move is copying is refused the same way, between the last copy and the manifest write. Committing would point the manifest at the destination while the packages that landed in between sit on the backend it is about to stop naming, and the catalogue is built from whichever one the manifest names.

Every package is also checked by its bytes rather than by its length, which the republication above does not do and this cannot do without. A mirror publishes archives naming a `sum` for every package they carry, so a copy that arrived wrong is refused by the client that downloads it. A generated catalogue takes every `sum` from whatever is in the store when it builds, so the same fault is written into the catalogue as the truth: pkg fetches the corrupted package, checks it against the sum computed from the corrupted package, and installs it. `--delete-source` runs only after the manifest write, so the copy that was right is still there to move again.

```text
latest@FreeBSD:14:amd64: verify the bytes of freebsd/FreeBSD:14:amd64/latest/All/tool-3.1.pkg on "bulk": sha256 c1ccc03b… at the destination, 9aaef7cb… at the source, so the copy changed in transit. Nothing was committed and the manifest still points at "default"
```

#### pypi is not movable

`pypi` wheels upload as one local directory to one key prefix, and the PEP 503 index is generated from a listing over that whole tree. A package placed on another backend drops out of the index that finds it, so there is no per-version object to move:

```text
pypi is not movable: pypi wheels upload as a directory with no per-version object key, so one package cannot be placed apart from the rest of its type; repoint storage_by_type.pypi and re-upload instead
```

Point `storage_by_type.pypi` at the backend you want and re-upload.

`apt` and `git` were here until their uploaders learned to walk manifest entries. A `.deb` is addressed by the pool path its version entry records, a bundle by its ref, and both routes resolve a read through `storage` on the version entry, so either type moves one package at a time like the rest.

### `bodega pkg drift [TYPE...]`

Lists every version whose recorded backend is not the one the placement hierarchy resolves to today, across the whole catalog.

```bash
bodega pkg drift                   # every type
bodega pkg drift binary npm        # two of them
```

```text
TYPE    PACKAGE         VERSION           ON       RULE
binary  example-tool-v2       2.15.0            default  bulk
git     widget          v4.5.5 (frozen)   archive  default
pypi    examplesdk           1.26.0            default  archive

3 version(s) drifted. To discharge each:
  bodega pkg move binary example-tool-v2@2.15.0 --to bulk
  bodega pkg freeze git widget   # unfreeze first, then: bodega pkg move git widget@v4.5.5 --to default
  set storage_by_type.pypi to "archive" and re-run 'bodega build upload pypi --replace-placement' — pypi moves as a whole type or not at all
```

A rule change moves nothing, which is the design: everything already uploaded stays where it is and stays readable. The cost is that the change is invisible afterwards. `upload` and `sync` keep writing to the backend each version records, and only `pypi` refuses, because only `pypi` uploads a whole directory and can be split by a rule. The other eight types wrote on and reported nothing. This is where they answer.

`bodega pkg move` is what discharges a row, and the command is printed with its arguments so the line can be copied. A frozen version names the unfreeze first, because `pkg move` refuses the whole command when any selected version is frozen.

`pypi` gets a sentence rather than a command. Its wheels have no per-version object key and `pkg move` [refuses the type outright](#pypi-is-not-movable), so the only thing that moves them is `storage_by_type.pypi` plus a re-upload with `--replace-placement`. The remedy is printed once for the type, not once per drifted version, because one re-upload moves all of them. A `storage_policy` on a drifted `pypi` package is reported beside it: the package level is not consulted for `pypi`, so repointing the type rule leaves the inert policy behind.

Nothing is written and no backend is asked where anything lives. This reads the config hierarchy on one side and the manifest record on the other and reports the pair — it is deliberately not a second resolver, because [placement and resolution share no code path](#placement-is-recorded-not-recomputed). `bodega build status` is the command that probes whether the object is actually there; `bodega pkg storage` answers the write side for one package.

### `bodega serve [flags]`

Starts the HTTP(S) package server.

| Flag                | Default | Purpose                                                         |
| ------------------- | ------- | --------------------------------------------------------------- |
| `--addr`            | `:8080` | TCP address to listen on                                        |
| `--tls-cert`        |         | Path to TLS certificate PEM file                                |
| `--tls-key`         |         | Path to TLS private key PEM file                                |
| `--allow-plaintext` | `false` | Serve without TLS; required when `tls_cert`/`tls_key` are unset |

The server handles graceful shutdown on SIGTERM/SIGINT, giving in-flight requests up to 30 seconds to complete.

### `bodega shell`

Launches the interactive TUI. See [TUI](#tui) section for keybindings.

### `bodega audit events [flags]`

Queries the configured audit sink. Under `audit_sink: "syslog"` or `"jsonl"` it refuses by name: those sinks ship events out and keep nothing to read back. See [Audit Trail](#audit-trail).

| Flag         | Default | Purpose                                                                    |
| ------------ | ------- | -------------------------------------------------------------------------- |
| `--type`     |         | Event type: fetch, build, create, delete, cache                            |
| `--pkg-type` |         | Package type filter                                                        |
| `--name`     |         | Package name filter                                                        |
| `--client`   |         | Client IP filter                                                           |
| `--identity` |         | Identity filter: the host name an identity binding resolved the request to |
| `--actor`    |         | Actor filter (CLI and TUI events, matched against the OS user)             |
| `--since`    |         | Show events after this time (RFC3339 or YYYY-MM-DD)                        |
| `--limit`    | `20`    | Max events to show                                                         |

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

On first run, a pepper file is auto-generated at `/etc/bodega/pepper` (or `~/.config/bodega/pepper`), mode `0640` owned by root in the group the service runs in, or `0600` where the host names no service account. This pepper is combined with the token before hashing, so the stored hash alone cannot be used to forge tokens.

### `bodega token list`

Lists all API tokens with their ID, label, creation date, expiry, last use, and comment. Expired tokens are marked.

### `bodega token revoke <id|label>`

Revokes a token by its short ID or label, removing it from the database.

### `bodega acl <admin|deny|proxies> <add|remove|list> [cidr]`

Manages the three CIDR access lists. They live in the audit database, not in `config.json`, so a change lands on a running server with no restart: within 30 seconds on its own, or at once on `systemctl reload bodega`.

The list names are the config keys they replace:

| Name      | Config key          | What it holds                              |
| --------- | ------------------- | ------------------------------------------ |
| `admin`   | `admin_permit_cidr` | CIDRs allowed to reach the admin surface   |
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

| Kind    | Key                   | Right for                               | Bootstrap                           |
| ------- | --------------------- | --------------------------------------- | ----------------------------------- |
| `token` | an `api_tokens` id    | naming one host precisely               | the host needs the credential first |
| `cidr`  | a CIDR, stored masked | "everything on this subnet is a devbox" | none; the address is the claim      |

```bash
bodega identity bind cidr 10.20.0.0/16 devbox
bodega identity bind token 4f3c9a... build-07 --comment "CI runner"
bodega identity list
bodega identity unbind cidr 10.20.0.0/16
```

`bind token` refuses an id no token has, because a binding to a mistyped id is inert and looks identical to one that works: every request from that host resolves through the CIDR fallback, or to nothing, and the rows read as a host that never authenticated. `bodega token list` prints the ids.

This table decides what an audit row says, never what may be fetched: a request carrying no credential is served exactly as it was before any binding existed. **Which kinds resolve and in what order** is below.

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

#### Which kinds resolve, and in what order

Both kinds resolve on every request, in one fixed order:

| Order | Kind      | Resolves when                                                              |
| ----- | --------- | -------------------------------------------------------------------------- |
| 1     | `token`   | the request carries a credential matching an unexpired token that is bound |
| 2     | `cidr`    | the request's address falls inside a bound prefix; the longest prefix wins |
| 3     | _nothing_ | neither matched, and the row records the address alone                     |

The order is fixed rather than incidental, so the same credential from the same address always resolves to the same name. A token beats a CIDR that disagrees because the credential is the more specific statement: an operator who issued one to a host said more about that host than the subnet it sits in. A credential that matches no token, matches an expired one, or matches a token nothing is bound to falls through to the CIDR rather than refusing.

The address a CIDR binding matches on is the one `trusted_proxies` resolved, not the socket's peer. So a client behind a proxy resolves to the client, and two clients behind the same proxy resolve to different identities rather than both to the proxy.

#### A forwarded address needs `trusted_proxies` answered

Where that address came from decides whether it may name a host:

| The address came from                             | Names a host                              |
| ------------------------------------------------- | ----------------------------------------- |
| the connection, with no forwarded header believed | always                                    |
| `X-Real-IP` or `X-Forwarded-For`                  | only once `trusted_proxies` has an answer |

An address read off the connection is whatever completed a TCP handshake, and nothing a client writes changes it. A header is whatever the peer chose to write. The built-in default trusts loopback plus RFC 1918, and bodega returns `X-Real-IP` verbatim from any peer in that set, so on a default-configured instance any RFC 1918 peer could claim an address inside a bound network and collect that identity. That forgery is what the gate refuses, and it refuses it per request rather than refusing the whole binding.

A request is judged against the list in force when its header was read, not the list in force when the identity is resolved. So an `acl proxies add` or a SIGHUP landing mid-request neither grants nor retracts an identity for a request already in flight; the change applies from the next one.

So a bodega that clients reach directly needs nothing configured: `bodega identity bind cidr` works the moment it returns. One behind a proxy needs `trusted_proxies` answered, either way:

- `bodega acl proxies add <cidr>` names the proxy that terminates for your clients and claims the list for the database, which is what ends the built-in default. It is picked up within the cache TTL, with no restart.
- `"trusted_proxies": []` in the config file claims it empty on the next start, so bodega answers to the peer address alone.

There is no `acl proxies remove` path out of the default, on purpose: `remove` refuses a CIDR the list does not hold rather than claiming the list as a side effect, so a typo cannot silently move an instance from the default to trusting nobody.

`bodega identity bind cidr` says which of the two you are in at bind time, so a proxied deployment learns it from the command that wrote the binding rather than from an audit row that names nobody:

```text
Bound cidr 10.20.0.0/16 to devbox.

Note: trusted_proxies is still the built-in default (loopback + RFC 1918), so every peer
in that range has its X-Real-IP believed verbatim and an address read out of a forwarded
header names nobody. A client that connects to bodega directly resolves through this
binding now; one behind a proxy needs the answer:
  bodega acl proxies add <proxy-cidr>   name the proxy that terminates for clients
  "trusted_proxies": [] in /etc/bodega/config.json
                                        trust no forwarded header from anyone
```

A token binding is unaffected either way, because the credential is the claim and no header can assert it.

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

The read path enforces this for pypi, npm, gomod, cargo, helm, git and binary. apt is the deliberate exception: the index a profiled host reads is the control and the fetch is only the backstop behind it; see [What is enforced, and where](#what-is-enforced-and-where). `bodega pin` is the host-side half of the same idea and is a different thing: it emits apt preferences for a host to apply, where a profile decides what bodega will answer.

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

| Flag                | Value      | Meaning                                                                         |
| ------------------- | ---------- | ------------------------------------------------------------------------------- |
| `--membership`      | `closed`   | only the packages this profile lists                                            |
| `--membership`      | `open`     | every package of this type in the catalog                                       |
| `--version-default` | `pinned`   | only the version each entry names                                               |
| `--version-default` | `floating` | any version                                                                     |
| `--expansion`       | `warn`     | serve it, and record the reach outside the class                                |
| `--expansion`       | `block`    | refuse it with 403                                                              |
| `--expansion`       | `ignore`   | serve it and record nothing                                                     |
| `--base`            | codename   | apt only: the mirrored codename this profile's filtered index is generated from |

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

`unpin` drops the constraint and keeps the entry, so the package stays a member. The version the pin named stays on the entry as its base, because that is what a pinned type default reads: an entry with a version and no constraint of its own is held at that version, and one with neither is a pin with nothing to pin to, which permits no version at all. A floating default ignores the base and takes any version. `unpin` says which of the three it left you in:

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

`BY` is who made that decision, and it moves with `PINNED` rather than with the last write. A colleague correcting a typo in your reason does not take the byline, because the row would then name them beside your date. Every other profile command reports the last writer, which is what those commands mean by it. A row written before the column existed falls back to the last writer, since that is the only name the table has ever held for it.

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

`HELD AT` comes from the relation the dependency was declared with, not from what happens to be installed. `libpq5 (= 14.9)` holds a release still and reads `14.9`; `libssl3 (>= 3.0.0)` is a floor that may move upward whatever postgresql-14 is pinned at, so it reads `-` and `--strict-closure` has nothing to pin it to. The language discoverers record the version on every edge they write, so a closure that reaches a pypi or gomod package resolves to a version rather than a dash.

**Which packages have a closure at all is a narrower question.** Only two code paths write an edge, and both write the parent as an `apt` or a `git` package: `discover_apt.go` writes `apt/<parent>` to `apt/<child>`, and `ImportDeps` writes `git/<repo>@<ref>` to the language packages that repo requires. No path writes an edge whose parent is a pypi, gomod, npm or cargo package, so pinning one of those reports no closure — not because it holds nothing still, but because nothing recorded what it depends on. `bodega profile pin` says which of the two it is rather than printing nothing, and `bodega profile check` is the gate that would otherwise pass silently.

Recording language-to-language edges is a larger change: `ImportDeps` fixes one parent ref per scanned repository, and a transitive graph needs a parent ref per dependency. Nothing schedules it.

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

`--from-file` reads the whole document before it writes anything, through the same checks `add` and `set` make: a package type bodega does not know, an entry with no name and a constraint with no version are each refused with the offending line named. A key named twice is refused the same way, naming both lines: one type carries one marker and one package carries one entry, so the later row would replace the earlier and take its constraint, reason and review date with it. The profile, its markers and its entries then land in one transaction. A document rejected halfway would otherwise leave a bindable profile holding a subset of what was authored, which is not a failed create but a working access control permitting less than anyone wrote.

The round trip through a file is the review step, and `--out -` and `--from-file -` are both refused. A host's inventory holds its accidents alongside its requirements, and locking membership to it enshrines whatever was installed by hand at 03:00; a baseline piped straight from the command that produced it was never read by anyone.

For the same reason `--out` refuses a path that already holds something. On every run after the first that file is the one the operator edited, and a silent overwrite discards the review while reporting a successful write. `--overwrite` replaces it:

```text
$ bodega profile create db --from-origin db01 --out db.json
db.json already exists, and a baseline is written to be edited before it is used.
  Read what is there:  bodega profile create <name> --from-file db.json
  Write somewhere else:  --out <other path>
  Replace it, losing whatever it holds:  --overwrite
```

**apt entries are written under the source package.** A host running `nginx`, `nginx-common` and `libexpat1` catalogs three binaries; the baseline lists `nginx` and `expat`, because that is the identity a filtered codename and the pool predicate both close over. Every collapse is named in the success line, so an operator reading the file recognizes a name they never installed:

```text
$ bodega profile create web --from-origin web01 --out web.json
Wrote a baseline for web01 to web.json: 2 package(s) across 1 type(s), 0 pinned.
2 apt binaries are listed under the source package they were built from, which is what a filtered codename closes over:
  libexpat1 -> expat
  nginx-common -> nginx
Nothing was created. Read it, edit it, then:
  bodega profile create web --from-file web.json
```

`--pin libexpat1` still names the binary the host reports and lands on the `expat` entry it was collapsed onto. A capture taken before `bodega pkg convert apt` recorded the source package has no source to use and falls back to the binary name.

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

A slash is read as the qualifier only when what precedes it names one of the package types, none of which carries a slash. So `--pin @babel/core` and `--pin github.com/lib/pq` each name one npm or gomod package, and the qualified spellings for them are `npm/@babel/core` and `gomod/github.com/lib/pq`.

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

**apt inverts the two.** For apt the filtered index is the control and the request predicate is the backstop, because refusing an apt fetch at the pool is worse than having no control at all: apt has already resolved the transaction by then, takes the 403 mid-run and aborts everything, including the security updates in the same invocation. Filtered out of the index instead, apt reports the package kept back and upgrades the rest. See [apt under a profile](#apt-under-a-profile).

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

#### apt under a profile

apt is the one type where a profile changes what bodega **serves** rather than what it refuses. Give the apt rule a base and bodega generates a second codename holding a filtered view of it:

```bash
bodega profile add web apt nginx
bodega profile add web apt curl
bodega profile set web apt --membership closed --expansion block --base noble
```

```text
web apt: membership=closed version_default=floating expansion=block
  filtered codename: noble-web (from noble), served after the next index rebuild
```

`--base` names a codename in `apt_upstreams`, and the derived codename is always `<base>-<profile>`. It must not collide with anything in `apt_suites` or `apt_upstreams`; `set` and `create --from-file` both refuse at the write rather than leaving one ERROR line an hour later in the server's log, and a refused document writes no profile row. Two profiles over different bases can still derive one codename (`security-web` over `noble` and `web` over `noble-security` both give `noble-security-web`), which `set` cannot see because it holds one profile at a time. The rebuild serves neither and names both profiles in the log. `--base` needs `--membership closed` **and** `--expansion block`, and both refusals are the same one reached from opposite directions. Each names both ways out, since an operator opening a profile asked for the opposite of keeping the base: close it or block it to keep the codename, or `--base ""` to drop it. An open set admits everything the archive publishes; `warn` and `ignore` are closed sets that serve what they do not list, so the filter keeps every paragraph either way. What bodega would publish is the archive's own index, byte for byte, under bodega's signature instead of the archive's: the host stops verifying against the distro keyring it already has, `/apt/pool/` drops from `public` to `private`, and nothing is filtered in return. `warn` remains the default for the seven other types, where the index is not what enforces and an unlisted package is served and reported. apt is the one type whose unfiltered outcome costs a signature, so it is the one type where the posture is stated rather than inherited. A profile with an open apt rule, or a closed one with no base, reads the mirrored codename unchanged. The base keeps its value like every other flag on `set`: an edit naming `--version-default` alone leaves the codename standing, and `--base ""` is how you drop one. Dropping it retires the codename across the fleet, so `set` prints `no base` and the audit row carries `apt_base=""` rather than letting an operator learn it from a host whose `apt update` 404s.

```text
$ bodega profile set web apt --membership closed --base noble
--base needs --expansion block; this rule takes warn, which permits a package the profile does not list, so every upstream paragraph survives the filter and noble-web would serve the archive's own index under bodega's signature instead of the archive's: a host that stops verifying against the distro keyring, for no filtering.
  Filter it:  bodega profile set web apt --membership closed --expansion block --base noble
  Or drop the base:  bodega profile set web apt --expansion warn --base ""
    the profile then reads the mirrored codename noble unchanged, verified against the distro keyring
```

**A profile with no base still governs apt.** `--base` buys a filtered view of a _mirrored_ codename. A suite bodega serves from its own catalog — an `apt_suites` codename holding the entries an operator put in it — is filtered in place instead: the host reads the suite it was always pointed at and bodega answers with that profile's view of it, generated and signed at the same rebuild. Either way `/apt/pool/` refuses a `.deb` the profile does not entitle. What no base costs is the mirrored codename: that document is the archive's own, so a host reading one is offered the archive whole and meets the refusal at the fetch, which is the mid-transaction 403 the arrangement above avoids. Add `--base` to buy back the legible half.

**Membership closes over the source package.** `bodega profile add web apt nginx` covers `nginx-common`, `nginx-core` and every other binary that source builds. Ubuntu renames and splits binaries within a stable source as routine maintenance, and a set closed on binary names would fire on each one. `--from-origin` writes source names for the same reason, and `bodega profile check` reports an apt entry naming a binary whose source differs — an entry that matches no paragraph in the index it governs, so the host is told the package does not exist:

```text
$ bodega profile check web
PROFILE  TYPE  PACKAGE    REASON
web      apt   libexpat1  this profile serves a filtered apt codename, which closes on the source package; libexpat1 is a binary built from source expat, so it matches no paragraph in the index. List expat instead
```

**A pin is real for apt through the index.** An entry pinned to a version drops every other version's paragraph from the filtered `Packages`, which apt reads as "no candidate" rather than as a refusal. The name is the source and the version is each paragraph's own `Version:`, so that the pool predicate behind the index compares the same version off the `.deb` filename. A binNMU is where the two spellings of one release diverge: source `nginx` at `1.24.0-2ubuntu7.1` ships `nginx-common` at `+b1`, so an exact pin holds the binaries at the version you wrote and drops that source's rebuilt ones, and apt reports the group as kept back. `bodega profile check` names the binary and version a pin drops without failing the gate, since the repair is to widen the constraint to `any` and that discards the reason the pin records. A profile that lists apt packages and whose pins match no paragraph at all serves no codename: `apt update` fails on the source line rather than the host being told its installed set no longer exists.

The filtered codename is a generated suite: bodega signs its `Release`, so the client's stanza carries `Signed-By:` and needs no `[trusted=yes]`. `bodega doctor --write-apt-sources` installs both:

```bash
bodega doctor --write-apt-sources --url https://bodega.internal
```

```text
wrote /etc/apt/keyrings/bodega-archive-keyring.gpg
wrote /etc/apt/sources.list.d/bodega.sources

Profile "web": this host reads noble-web, a filtered view of what bodega mirrors.
```

```text
Types: deb
URIs: https://bodega.internal/apt/
Suites: noble-web
Components: main
Signed-By: /etc/apt/keyrings/bodega-archive-keyring.gpg
```

The server composes that stanza, because which codename a host reads is a fact only the running instance holds. Pass `--token` for a host identified by a token; a host bound with `bodega identity bind cidr` is identified by its address and needs none. A host bodega cannot identify is told which codenames exist rather than handed one, and `--suite` is how it is configured anyway.

What the client then sees when a dependency is outside the baseline:

```text
The following packages have been kept back:
  demo-app
The following packages will be upgraded:
  demo-tool
1 upgraded, 0 newly installed, 0 to remove and 1 not upgraded.
```

That is the whole point of the design. The same policy enforced at fetch time gives `403` mid-transaction and `E: Failed to fetch`, with nothing upgraded.

Three limits, stated rather than left to be found:

- **The `sources.list` is a scoping boundary, not an authorization one.** The host can edit it and read the unfiltered mirrored codename; the codename's name is not a secret either. What refuses the artifacts behind it is the request predicate at `/apt/pool/`, which runs on identity:

  ```text
  membership: profile "web" does not list apt/demo-extra at 1.0.
    Add it:      bodega profile add web apt demo-extra
    Or open it:  bodega profile set web apt --membership open
  ```

- **bodega re-signs an index it did not verify a signature on.** It checks the archive's TLS certificate and the SHA256 the archive's own `Release` publishes for the `Packages` beside it, and it holds no distro keyring to check `InRelease` against. A mirrored codename forwards the archive's signature intact; a filtered one does not. See [Threat model](threat-model.md).
- **One component, `main`**, matching every other generated suite. A base publishing more is named in the server log, and packages outside `main` are not served under the profile.

Filtered codenames appear in the startup banner and in `GET /api/v1/status` under `apt.filtered`, with a rendered stanza each in `apt.sources`. Nothing in the config file names them, so those are the two places to read them off. They are regenerated on the hourly index rebuild and on every `bodega profile` write, and the upstream indexes they are built from are cached behind `metadata_ttl`. A rebuild that cannot read or parse the upstream `Packages` withdraws the codename rather than serving the part of it that arrived, so `apt update` fails on a source line naming the instance; a truncated index would instead report every package past the break as kept back. An architecture the base's `Release` names and the archive answers 404 for is the exception: it is dropped from the filtered `Release` and the rest is served, because `archive.ubuntu.com` declares all seven and carries two, and the codename is withdrawn only when none survives.

### `bodega doctor [--write-credentials --token TOKEN [--url URL]] [--write-apt-sources [--suite CODENAME]] [--write-pkg-repo [--abi ABI] [--release N]]`

Without flags, `doctor` reports and changes nothing. It has three writes, and they run one at a time.

It exits 0 when every check is clean, 2 when one or more produced a finding, and 3 when one or more could not run at all. A check reports `SKIPPED` rather than `N/A` when the file or store it reads would not open, and the `Could not run:` block names what it needed: an unprivileged run against the root-owned `/etc/bodega/config.json` the service unit prescribes measures no policy posture, and three `N/A` rows beside the checks that passed said nothing about that. `N/A` keeps its meaning, which is a measurement: the subject is absent on this host.

`--write-apt-sources` asks the server which apt suite this host should read and installs the keyring and the stanza; see [apt under a profile](#apt-under-a-profile).

`--suite` names the codename when the server will not. An instance that mirrors serves a codename per upstream beside the one it generates, so several codenames is its ordinary state rather than a misconfiguration, and with no profile to choose between them the server names none:

```bash
bodega doctor --write-apt-sources --suite noble --url https://bodega.internal
```

The stanza is still the server's rendering of that codename, so this flag decides which block is installed and nothing about its contents. A mirrored codename installs the sources file alone, with no keyring and no trust line: bodega does not sign what it proxies, the archive's own signature reaches the client intact, and apt verifies it against the distro keyring the host already has. `Signed-By:` naming bodega's key there would fail every `apt update` on the signature, and `[trusted=yes]` would discard a signature that is present and valid, so the write refuses a stanza carrying either. A host whose profile scopes apt is refused too, and told to change the profile's base: the filtered codename is that profile's answer, and the unfiltered base it was built from is in the same list.

`--write-pkg-repo` is the FreeBSD half. It asks the server which pkg repository answers for this host's ABI and writes `/usr/local/etc/pkg/repos/bodega.conf`, which carries two things rather than one: bodega's repository, and the overrides that disable the repository `/etc/pkg/FreeBSD.conf` defines. A file with only the first leaves the host fetching from `pkg.FreeBSD.org` beside bodega, and `pkg update` says nothing about it, so the write refuses a document that disables nothing.

```bash
bodega doctor --write-pkg-repo --url https://bodega.internal
```

The ABI comes from `pkg config abi` on a FreeBSD host and from `--abi` anywhere else; nothing composes one from `runtime.GOARCH`, because the two spellings differ. The overrides follow the major release that ABI carries, and `--release` says otherwise for a host whose release is not the one the repository is named for. `signature_type` is the server's answer rather than a flag. A server serving several repositories for one ABI refuses and names them: which one a host reads is a decision, and a file naming one reads as authoritative. See [Client configuration](#client-configuration) for what lands in the file and why each line is there.

With `--write-credentials` it writes one token into the file each of the eight clients reads its credential from, because a feature that costs eight hand edits does not get adopted:

```bash
bodega token generate devbox-3
bodega identity bind token <id> devbox-3
bodega doctor --write-credentials --token bodega_ak_... --url https://bodega.internal
```

`--url` defaults to `public_url` from the config file. Five files serve the eight clients:

| Client   | File                               | Form                                  |
| -------- | ---------------------------------- | ------------------------------------- |
| `apt`    | `/etc/apt/auth.conf.d/bodega.conf` | netrc, `machine <scheme>://<host>`    |
| `pip`    | `~/.netrc`                         | read through requests                 |
| `npm`    | `~/.npmrc`                         | `//host/npm/:_authToken=`             |
| `gomod`  | `~/.netrc`                         | read for the `GOPROXY` host           |
| `cargo`  | `~/.cargo/credentials.toml`        | `[registries.bodega] token`           |
| `helm`   | helm's own config path (see below) | `username` / `password` on the repo   |
| `git`    | `~/.netrc`                         | read through libcurl                  |
| `binary` | `~/.netrc`                         | `curl --netrc`; wget reads it already |

pip, go, git and curl/wget all read `~/.netrc`, so one host-scoped entry serves four clients and there is one secret to rotate rather than four. The table `doctor` prints reports `current` for the three that find the entry the first already wrote.

apt gets a file to itself because its `machine` line carries the scheme, which plain netrc does not understand. Bare, apt matches the host and then declines: `Credentials for <host> match, but the protocol is not encrypted. Annotate with http:// to use.` — so an unannotated entry is inert on every plaintext deployment. `doctor` writes the scheme from `--url`, which also keeps the credential to the scheme bodega told clients to use rather than offering it on both. Verified against apt 2.8.3 on noble over `http` and `https`; the `#` fence is a comment to apt's parser and is skipped.

A second run replaces bodega's own entry rather than stacking another beside it, and nothing else in those files is touched. Where the format allows a comment anywhere, the entry is fenced by a marker; the fence is never the anchor, because bodega does not own these files. `cargo login`, `helm repo add` and `npm config set` each re-serialize the file and drop comments doing it, which takes the fence with them. So `doctor` finds its own entry by the key that entry carries: cargo's `[registries.bodega]` table, the repository named `bodega`, the `//<host>/npm/:_authToken=` line. `~/.netrc` gets no fence at all. Python's `netrc` module refuses a `#` line preceded by a blank one, and refuses the whole file rather than the entry, so a marker appended after the blank line that idiomatically separates stanzas costs pip every credential in the file, and silently: `requests` catches the parse error and sends no credential, while libcurl reads the same file without complaint, so git and curl keep working while pip stops. There the `machine <host>` stanza is the whole anchor, which is what it already had to be. No client rewrites that file, but an operator who configured bodega by hand before this command existed left a stanza in it, and appending beside it would put two credentials for one host in a file its four readers disagree about. libcurl takes the first match and Python's `netrc` module the last, so git, curl and wget would keep presenting the pre-rotation secret while pip presented the new one, and the table would report four successes. What the second run guarantees is one bodega entry holding the new token, in a file its client still parses. Stacking a second entry is not cosmetic: cargo rejects a duplicate key and stops reading the file at all, taking the operator's crates.io token with it, and helm resolves a chart through the first matching entry, which would be the pre-rotation one. The apt file needs root and the other four do not; a run as a normal user configures seven clients, names the one it could not, and exits 2.

helm's path is the one that is not the same everywhere: `doctor` resolves it the way helm does, `$HELM_REPOSITORY_CONFIG` first, then `$XDG_CONFIG_HOME/helm/repositories.yaml`, then the platform default, which is `~/Library/Preferences/helm/repositories.yaml` on macOS and `~/.config/helm/repositories.yaml` elsewhere. The table prints the path it resolved. `repositories.yaml` is also the one target where appending is not always legal. A file whose `repositories:` list is not last would take an appended entry into whatever key followed, and a `repositories: []`, which is what `helm repo remove` leaves when it removes the last repository, has no list to append under at all: a block sequence written there is a second value for one key, and helm rejects the whole file. `helm repo list` reports no repositories and exits 0 over that, so the damage would surface at the next `helm repo add` with nothing connecting it to the doctor run. Both cases are refused, with the `helm repo add bodega <url> --username bodega --password <token>` line to run instead.

Writing a credential changes what an audit row says, never what the host may fetch. It does change what the host may **write**, which is why `doctor` prints this before it touches a file:

```text
Before writing: bodega tokens carry no scope, so this same token is the
credential half of the mutation gate. A host that holds it and whose address
is inside admin_permit_cidr can POST and DELETE against this bodega.
  Keep admin_permit_cidr at loopback (bodega acl admin list), or treat every
  host you write a credential to as admin-capable.
```

`bodega token generate` takes a label and nothing else: a token is a token. The mutation gate accepts any unexpired one of them once `admin_permit_cidr` reaches past loopback, so the credential in a build host's `~/.netrc` is also the credential that authorizes `POST /api/v1/...` from that host. Keeping `admin_permit_cidr` at loopback makes the gate ignore tokens entirely and is the remedy that costs nothing; otherwise every host you write a credential to is admin-capable and should be treated that way. Scoped tokens would sever the two and do not exist yet. See [Threat model](threat-model.md).

### `bodega policy list [--type TYPE]`

Lists configured upstream allow-list rules. Without `--type`, shows every rule grouped by registry type.

### `bodega policy add <type> <pattern> [comment]`

Adds an allow-list rule. The rule kind is determined by type:

| Type   | Kind         | Pattern example                               |
| ------ | ------------ | --------------------------------------------- |
| apt    | host         | `archive.ubuntu.com`                          |
| git    | org (prefix) | `example.com/example-corp/`                   |
| pypi   | package      | `django`                                      |
| npm    | package      | `lodash` or `@example-cloud/*`                |
| gomod  | prefix       | `example.com/example-corp/`                   |
| helm   | prefix       | `https://kubernetes.github.io/ingress-nginx/` |
| binary | prefix       | `https://downloads.example.com/`              |

```bash
bodega policy add pypi django
bodega policy add git example.com/example-corp/ "widget maintainers"
bodega policy add npm @example-cloud/*
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

| Key                | Default              | Meaning                                                                          |
| ------------------ | -------------------- | -------------------------------------------------------------------------------- |
| `osv_db_dir`       | `{storage_path}/osv` | Directory holding one archive and one metadata file per ecosystem                |
| `osv_api_fallback` | `false`              | Authorize a live `api.osv.dev` query when the local copy cannot answer           |
| `osv_db_max_age`   | `168h`               | How old a synced ecosystem may be before a clean answer warns instead of passing |

The fallback is off by default because the deployment this gate exists for cannot reach `api.osv.dev`: with it on, every version stalls for the 15-second client timeout against a host that never answers, once per version, which a 635-package import pays 635 times.

#### Sync

```bash
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

```bash
$ bodega pkg import lodash.json
npm/lodash: 4 versions (4.17.4, 4.17.5, 4.17.6, ...): osv: no local OSV database for npm in /var/lib/bodega/osv; run `bodega policy osv sync`; osv_api_fallback is off, so nothing was queried
Imported npm/lodash (4 version(s))

$ bodega pkg import lodash.json     # database synced in March
npm/lodash: 4 versions (4.17.4, 4.17.5, 4.17.6, ...): osv: local OSV database for npm is 178d old (synced 2026-03-14T01:53:43Z); run `bodega policy osv sync`
```

Every version of a package hits the same degraded gate, so the reason is stated once and names the versions it covered rather than repeating per version. The mutation API returns the same lines in the `warnings` array of each import result, and the audit trail records the version-level detail under `policy_warn` either way.

A stale database still blocks on what it does hold — old data names old vulnerabilities correctly — and the age rides along in the reason. With `osv_api_fallback` on, a stale or missing ecosystem is answered from `api.osv.dev` instead, and only a failed query falls back to the stale copy.

`bodega policy osv list` reports the state per ecosystem, so a gate that is current is distinguishable from one that stopped syncing in March:

```bash
$ bodega policy osv list
ECOSYSTEM  ACTION  UPDATED     DB SYNCED             DB AGE
gomod      block   2026-09-08  never                 -
npm        block   2026-09-08  2026-09-08T01:53:43Z  47s
pypi       warn    2026-09-08  2026-09-08T01:53:27Z  1m4s

Local OSV database: /var/lib/bodega/osv (api.osv.dev fallback: off)
```

The `apt` row spans one index per release, over the same set `sync` resolves: the served suites plus the releases the manifests record on `capture_suite`. It reports the oldest of them and `never` if any one is absent, so a captured-only release nothing has fetched shows up here and not only when `rescan` answers `unanswered` for it.

Coverage is the set of registry types the gate can query, which is also the set of exports `sync` fetches:

| Type  | OSV ecosystem                                                      |
| ----- | ------------------------------------------------------------------ |
| npm   | `npm`                                                              |
| pypi  | `PyPI`                                                             |
| gomod | `Go`                                                               |
| cargo | `crates.io`                                                        |
| apt   | one per release (`Ubuntu:22.04:LTS`, `Debian:12`); see [apt](#apt) |

`binary`, `git` and `helm` have no OSV identifier. `set` refuses them:

```bash
$ bodega policy osv set helm block
Error: the OSV gate does not cover ecosystem "helm": the row would be stored and never read, leaving the gate silently off; set one of apt, cargo, gomod, npm, pypi instead
```

Earlier versions wrote that row, printed `Set helm OSV policy: block`, and then passed every helm version, because the checker short-circuits on any type outside the table above. Nothing reported the gap. The refusal replaces a gate the operator believed was on. It does not remove the rows already written: `bodega policy osv list` names them under the table and `bodega doctor` reports them, in the form shown under [`bodega policy age`](#bodega-policy-age-setlistremove).

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

```bash
apt/libexpat1: 2.6.1-2build1: osv: apt entry libexpat1 names no release and this bodega serves 2 releases (Ubuntu:22.04:LTS, Ubuntu:24.04:LTS), so nothing identifies which release's advisories cover its version; set capture_suite on the version entry, or re-capture the host with 'bodega pkg convert apt --suite <codename>' and re-import
```

Pockets are not releases: `jammy`, `jammy-security` and `jammy-updates` are one set of advisories, so serving all three keeps the fallback unambiguous. A served suite OSV publishes no export for does count as another release, because it is another release an entry could have come from and this gate cannot place it either way.

**One release is two OSV ecosystem strings.** `Ubuntu:22.04:LTS` carries main and `Ubuntu:Pro:22.04:LTS` carries universe, and on the ESM releases very nearly everything. The two sets are disjoint. Measured 2026-09-11, a stock jammy `imagemagick 8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3` answers with 4 records under the first and 179 under the second, and a xenial `expat 2.1.0-7ubuntu0.16.04.5+esm8` answers with none under the first and 37 under the second. Both halves are about the same host and both name stock revisions as their fixed versions, so `sync` folds them into one index per release: the `queried` stamp names `Ubuntu:22.04:LTS` and the answer covers both.

The FIPS, Realtime and Nvidia-BlueField strings are not folded: the fold matches `Ubuntu:Pro:<rel>` as an exact pair, so `Ubuntu:Pro:FIPS-preview:22.04:LTS`, `Ubuntu:Pro:FIPS-updates:22.04:LTS`, `Ubuntu:Pro:Realtime:22.04:LTS` and `Ubuntu:Nvidia-BlueField:22.04:LTS` all fall outside it. Each carries revisions of a build the stock host never installed, so folding one in reports against a version that was never there: `UBUNTU-CVE-2022-40735` fixes jammy `openssl` at `3.0.2-0ubuntu1.16` and the FIPS build at `3.0.2-0ubuntu1.16+Fips1`, and a patched stock host sorts below the second.

**The source package is queried, and it is a different field from `source_name`.** Advisories are issued against the source package, and one source builds many binaries: `expat` builds `libexpat1`, `libexpat1-dev` and `expat` itself. OSV's `Ubuntu` and `Debian` ecosystems are keyed on the source alone, so a lookup for `libexpat1` returns nothing at all while `expat` returns 51 records. The gate reads `source_package`, which `bodega pkg convert apt` fills from dpkg's `${source:Package}` and the builder fills from `apt show`'s `Source:` line. `source_name` is not that field and never was: every importer sets it to the binary name, because `apt-get download` needs the binary name to resolve a `.deb`.

**An entry recording no source package is queried under its binary name, and an empty answer from that query warns rather than passing.** The two cases are indistinguishable from the string alone: `libssl3` matching nothing and a patched `bash` matching nothing look the same. A match is self-validating, so the 28 of 101 packages whose source and binary names agree still report normally; only the empty answer is ambiguous, and B34's rule applies to it. The stamp says which name was used either way, so a finding on `libexpat1` traces back to the `expat` advisory that produced it.

```bash
apt/libssl3: 3.0.2-0ubuntu1.26: osv: apt entry libssl3 was queried under its binary name in Ubuntu:22.04:LTS and matched nothing, but Ubuntu and Debian advisories are issued against the source package, so an empty answer here is not a clean one; re-capture the host with dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\t${source:Package}\n' and re-import, or set source_package on the version entry
```

**Versions compare under dpkg's ordering, revision included.** Epoch, upstream version and revision compare separately, `~` sorts below the end of the string, and leading zeros carry no weight, so `3.0.2-0ubuntu1.15` is newer than `3.0.2-0ubuntu1.2`. semver gets `2.5.0-1+deb12u1` wrong in the expensive direction: it reads `+deb12u1` as build metadata and discards it, so an unpatched `2.5.0-1` compares equal to the revision carrying the fix and reports clean.

```bash
$ bodega pkg import expat.json      # jammy, one revision short of the fix
apt/libexpat1: 2.4.7-1ubuntu0.2: osv: libexpat1@2.4.7-1ubuntu0.2 has 2 OSV record(s): USN-6694-1, USN-7000-2, queried as source package expat in Ubuntu:22.04:LTS
```

An entry the gate cannot place warns and never passes, the same rule the missing database follows: a suite OSV publishes no records for (an interim Ubuntu release, or a suite name of your own), an entry whose own suites and `apt_codename` are both unmapped, or an entry whose version is not yet resolved.

```bash
apt/libexpat1: 2.6.3-2: osv: apt entry libexpat1 names suite(s) plucky, which OSV publishes no Ubuntu or Debian export for
apt/nginx: osv: apt entry nginx carries no version, so no advisory can be evaluated against it
```

An entry published to several suites is queried against each of them and the records are unioned: the same `.deb` is offered to every suite it lists, so a record against any of those releases is a finding on that version. If one of those suites has no export, the entry warns rather than reporting the other suite's answer as the whole answer.

**Sync fetches the aggregate archive, not the per-release one.** OSV publishes `Ubuntu:22.04:LTS/all.zip` and stopped rebuilding it in October 2024: measured 2026-09-11, that archive was last written 2024-10-09 and its newest advisory was from 2024-10-08, while `Ubuntu/all.zip` had been rebuilt that morning. The abandoned copy is also an id scheme behind, carrying Debian records as `CVE-2023-52425` where every other surface calls them `DEBIAN-CVE-2023-52425`. So `sync` pulls the aggregate and distills one index per release out of it, which is also why serving four Ubuntu suites is one download rather than four. Fetching the per-release archive would have shipped a gate reporting `DB SYNCED` two minutes ago over two-year-old advisories, and nothing would have caught it: the age is measured on the fetch, not on the contents.

#### Matching

The local matcher implements OSV's own evaluation: an enumerated `versions` list matches exactly, and a range is walked event by event in version order, under semver for npm, Go and crates.io, PEP 440 for PyPI, and dpkg's ordering for the Ubuntu and Debian releases. Measured against `api.osv.dev` over 240 range-boundary `(package, version)` pairs drawn across the four language ecosystems, it agrees on all 240.

An ecosystem is decompressed on the first version checked against it and held until `sync` replaces the archive, so a bulk import pays one decompression rather than one round trip per version. One process shares that copy across every package it admits: importing 100 npm packages at 4 versions each against the 2026-09 export takes 0.5s. What it holds, measured on the 2026-09-13 exports: npm 58 MB, PyPI 9 MB, gomod 6 MB, cargo 1.5 MB. An ecosystem with no policy row is never loaded.

The Ubuntu and Debian releases cost more than the language ones, though far less than they did before the enumerated version lists were trimmed and the decoded records shared: measured the same day, `Ubuntu:22.04:LTS` holds 43 MB once loaded, `Ubuntu:24.04:LTS` 32 MB and `Debian:12` 12 MB, and a release is loaded on the first apt version checked against it.

**What a distro index keeps and what it drops.** A distro advisory both enumerates every published version it covers and bounds the same span with a range, so `sync` drops each enumerated string the entry's own ranges already place and keeps every string they do not, which for these three releases is the whole list: `Ubuntu:22.04:LTS` arrived carrying 16,984,763 version strings and holds none. What remains on disk is one copy of each advisory per binary package its source builds, and what the load holds is one copy per distinct record: jammy's archive carries 772,549 record entries and the index reads them out of 175,514 allocations, because an advisory that names 40 packages identically is decoded once. Unlike the trim, that happens at load rather than at sync, so an archive already on disk gets it on the next start with nothing to re-sync.

Decoding one costs between six and sixteen times what it keeps, and the transient is the figure that gets a host OOM-killed rather than the one it settles at: the decoder allocates every duplicate before the sharing collapses it, so the peak moves far less than the retained figure does. Measured the same day, one process checking a single version against `Ubuntu:22.04:LTS`: 700 MB maximum resident, settling to the 43 MB above. `Ubuntu:24.04:LTS` peaks at 363 MB for the 32 MB it keeps, `Debian:12` at 77 MB for 12 MB. Releases decode one at a time, so provision for the largest release's peak plus what the others retain: 744 MB for a host serving all three, against 2653 MB for the same host reading pre-trim archives. Adding the retained figures alone sizes that host at 87 MB and it dies on the first apt version checked. Or keep the apt gate on a machine that imports rather than on the one that serves.

**An archive synced by an earlier version keeps the old cost until it is re-synced**, because the trim happens at sync and nothing rewrites an archive already on disk: read by the shipped decode, a pre-trim `Ubuntu:22.04:LTS` holds 154 MB and peaks at 2562 MB, `Ubuntu:24.04:LTS` holds 76 MB and `Debian:12` 15 MB, which is the 2653 MB above. The untrimmed layout has next to nothing to share, because an enumerated list is per package and two packages' records are then never equal: 772,514 distinct records out of 772,549 entries, against 175,514 trimmed. `bodega policy osv list` names those ecosystems under its table and `bodega policy osv sync apt` replaces them. Their advisories are current, so the gate answers from them correctly in the meantime.

A running server picks up a sync without a restart: it checks the archive it loaded from on each match and reloads when the file changes. `sync` is a separate process from the server enforcing the gate, so without that check the server would report the fresh fetch time under `bodega policy osv list` while still matching against the copy it loaded before the sync.

Two classes of record it does not answer the way `api.osv.dev` does.

**Withdrawn advisories are dropped at sync.** The API still returns some of them (PYSEC-2024-115, retracted in July 2026, comes back on a `langchain-community` query while other withdrawn records do not). A retracted advisory blocking an import is a false positive the operator has no way to clear.

**A range bound no ordering can place leaves that range unevaluated.** OSV carries 46 of them across the four exports as of 2026-09-08, in 15 packages: `4.1.0-NA` bounding `pywidget`, `2.6.0-cu124` bounding `torch`, `0.8.3ubuntu7.5` bounding `python-apt`, `9.6.0b1` bounding `github.com/redis/go-redis/v9`. Such a record neither matches nor clears. The gate names it instead, so a version never reports clean on a record nobody could read:

```bash
$ bodega pkg import pywidget.json
pypi/pywidget: 4.1.0: osv: 1 OSV record(s) for pywidget were not evaluated against 4.1.0: PYSEC-2024-325 (bound "4.1.0-NA")
Imported pypi/pywidget (1 version(s))
```

A version matching other records blocks on those and carries the unevaluated ids in the same reason, capped at five ids plus a count. Matching one record settles nothing about the one nobody read, so such a version is stamped with its ids and no check date, the same treatment the identical version with zero matches beside that record already gets. `api.osv.dev` is not consistent on this population: over 130 probes at published versions across those 15 packages it agreed 123 times, returning nothing for the record exactly as the local matcher does. The other 7 are the API failing open on a bound it also cannot place, returning GHSA-jqqh-999x-w26w, fixed in `buildbot` 0.7.11p3 in 2007, for `buildbot@4.3.0`. Reproducing that would mean shipping a block no operator can clear, so the matcher reports the record and declines to guess. Turn `osv_api_fallback` on to see what the API says about one.

A version with OSV records is stamped on its `VersionEntry.Metadata`, so the finding follows the version into the manifest rather than living only in the audit event:

| Key                      | Value                                                                                                                                     |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `vetting.osv.vulns`      | comma-separated OSV ids, sorted                                                                                                           |
| `vetting.osv.severity`   | JSON object keyed by OSV id, each value the record's `severity` array as OSV returned it                                                  |
| `vetting.osv.checked_at` | RFC 3339 timestamp of the last check that reached a verdict                                                                               |
| `vetting.osv.queried`    | what the lookup actually asked, on the ecosystems where that is not the package name and type: `source package expat in Ubuntu:22.04:LTS` |

`vetting.osv.severity` is present only when at least one record carried a score, and ids OSV scored nothing for are absent from it; `vetting.osv.vulns` is the full list either way. A version matching several records at different severities keeps them apart by id, so a reader ranking findings parses the stamp instead of querying OSV a second time.

`vetting.osv.checked_at` is what makes the other two readable. Without it a version with no findings and a version nobody ever queried both carry an absent `vetting.osv.vulns`, so "no known vulnerabilities" and "nobody looked" print the same. The date is written on a clean result and a flagged one alike, and only when the gate reached a verdict: a check answered out of a database too old to be trusted names the records it found and drops the date rather than keeping the one already there, an entry whose `version_constraint` is not exact is never dated at all, because the range it names is not the version that was queried, and a record naming the package that nobody could evaluate withholds the date whether or not some other record matched. A date left in place would then sit beside findings the check that wrote it never saw, and `show pkg` would render a fresh flag under the day the version last read clean.

Versions imported before this key existed cannot be backfilled. Nothing on disk records when they were checked, and dating them from the manifest's timestamp would invent the fact the field carries, so they read as `unchecked` until a rescan answers for them.

```json
{
  "GHSA-xxxx-yyyy-zzzz": [
    { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }
  ]
}
```

#### Rescan

Admission checks a version once, on the day somebody imported it. That answer never gets revisited, so a version admitted clean fourteen months ago is still recorded as clean, and CVEs published against versions already in the field are the normal case rather than the exception. **Admission-time checking alone does not tell you what is vulnerable today.** It tells you what was vulnerable on the day of the import, and nothing in the output distinguishes those two sentences.

`rescan` closes that gap. It walks the manifests, re-runs the lookup against the local database, and re-stamps every version it can answer for.

```bash
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

```bash
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

```bash
$ bodega show pkg npm minimist
Package: minimist

VERSION      PLATFORM        STORED     FROZEN   HIDDEN   CONSTRAINT OSV         CHECKED
1.2.0        any             default    no       no       exact      2 vuln(s)   2026-09-08
1.2.8        any             bulk       no       no       exact      clean       2026-09-08

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

`min-age` takes the Go duration formats plus a plain `<N>d` for days. The action is `warn`, `block` or `ignore`. One rule per ecosystem; `set` overwrites.

Coverage is the set of registry types with an upstream endpoint that carries a publish timestamp:

| Type  | Source                                                             |
| ----- | ------------------------------------------------------------------ |
| npm   | packument `time[<version>]` on `registry.npmjs.org`                |
| pypi  | earliest `urls[].upload_time_iso_8601` on `pypi.org`               |
| gomod | `Time` in the proxy's `@v/<version>.info`                          |
| cargo | `version.created_at` on `crates.io/api/v1/crates/<name>/<version>` |

`apt`, `binary`, `git` and `helm` have no such source. `set` refuses them:

```bash
$ bodega policy age set apt 7d warn
Error: the age gate does not cover ecosystem "apt": there is no upstream publish timestamp to date a version against, so every version would warn; set one of cargo, gomod, npm, pypi instead
```

The two gates failed differently before they refused. OSV passed silently. Age never did: a missing timestamp is a `warn` with the ecosystem named, so an apt policy made every apt version noisy rather than invisible. Refusing the row up front is a usability fix on that side and a security fix on the OSV side.

`set` grew that refusal after the fact, so a row written before it is still stored and still read by nothing. Both `list` commands mark the row's action and name it again under the table, and `bodega doctor` reports it as `policy-ecosystem`:

```bash
$ bodega policy age list
ECOSYSTEM  MIN AGE  ACTION                UPDATED
helm       7d       block (not enforced)  2026-03-11
npm        7d       warn                  2026-09-06

Not enforced: the age gate cannot evaluate helm, so that row is stored and never read.
Remove with 'bodega policy age remove <ecosystem>'.
```

The marker is on the row because the row is what an operator scans. A footnote alone left `block` reading as a block in the column where every other row's action is real, and the two rows above are the whole difference between a gate that runs and one that does not.

Nothing else counts such a row as enforcement. The `bodega serve` startup banner names only ecosystems the age gate can date, so an install carrying the `helm` row above with `npm` and `pypi` on `ignore` reports `minimum publish age: none enforced` rather than the block that never runs.

An upstream that is reachable but has no timestamp for the version warns rather than blocking, on the same reasoning: a registry outage should not fail an import closed.

### `bodega discover ...`

Discovery records what clients reached for that bodega could not serve from its own manifests, so an operator can turn a real installation run into allow-list rules or manifest entries instead of writing them from memory.

**It is a record of upstream reaches, not of installs.** A row means bodega went to an upstream, would have, or once did and is now answering from the copy it kept — a proxy cache hit bumps the row the fetch that filled it wrote, so a proxied artifact keeps counting long after the last upstream request for it. What writes nothing is a **hosted** entry: bodega built or fetched those on its own schedule and serves them out of storage with no upstream in the request at all. So the discovery log never answers "what did this host install", and it gets quieter as the catalog gets better. The answer to that question is the audit trail: `bodega audit events --client <ip> --type serve_fetch` carries one row per artifact bodega handed that client, hosted and proxied alike, which is the complete record discovery is not.

The mode is server-side. Set `discover_mode` in config.json and restart:

| Value          | What gets logged                                                            |
| -------------- | --------------------------------------------------------------------------- |
| `""` (default) | nothing; the hook is off                                                    |
| `"observe"`    | every upstream attempt and every pre-fetch miss, with the decision each got |

`discover_mode` decides whether a row is written. It decides nothing else. The allow-list, `catalog` mode on `git_upstreams` and `binary_upstreams`, hidden versions, version constraints, the CIDR access lists and the mutation gate all behave identically at both values, and a request the allow-list rejects gets its 403 either way. `observe` is safe to leave on permanently, and there is no mode that turns enforcement off.

For most types it is also not the way to bootstrap a catalog. Discovery only sees what clients ask for, so a host that has been stable for six months produces nothing, and `catalog` mode 404s a path before any policy check runs, so an empty store stays empty however long you watch it. pypi is the partial exception: an uncataloged `/pypi/simple/<dist>/` records a `no_manifest` row carrying the index URL, so a `pip install` against an empty store leaves a row per distribution it asked for. Every one of those requests 404s on an empty store, and pip reads no dependencies out of a 404, so one round records the requirements the client named and not the closure below them. Each round is three commands — `bodega discover generate-manifests pypi -o catalog.json`, `bodega pkg import catalog.json`, then the same `pip install` again — and the next layer of the closure appears in the log because the layer above it now resolves. `generate-manifests` writes JSON and nothing else; nothing is served until the import runs. Everywhere else, read the host's own inventory: [`bodega pkg convert`](#bodega-pkg-convert-type-file-) turns `dpkg-query`, `pip list`, `npm ls -g`, `go list -m all`, `cargo install --list` or `helm list` into a manifest set in one run. What discovery is for is the residue: once a catalog exists, `observe` names what the fleet reaches for that the catalog does not cover, including the two types `pkg convert` has no importer for (git and binary).

Each observation is one row keyed by `(type, pattern, package, version, decision)`, with a request count, the last client IP, and the upstream URL bodega fetched or would have fetched. The count is a count of **requests**, not of cache misses: a request the cache answers bumps the same row the fetch that filled it wrote, so `request_count` ranks by demand and `last_client` names the last host to ask. That holds for a stale copy served because no upstream is configured, and for one served because the upstream could not be reached — an outage is the window these columns are read in, and they keep moving through it.

`decision` describes the allow-list's verdict on the upstream candidate, not what happened to the request. A cache hit contacts no upstream, and it is recorded under the verdict that applies to the candidate now — which is what keeps it on the same row as the miss before it. The `decision` column carries one of:

| Decision       | Meaning                                                                                                                                                                                                                 |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `allowed`      | an allow-list rule matched the upstream                                                                                                                                                                                 |
| `denied`       | the allow-list rejected it; the client got a 403                                                                                                                                                                        |
| `no_policy`    | no allow-list rules exist for the type, so nothing was checked                                                                                                                                                          |
| `no_manifest`  | the request named a package no manifest entry holds. The client got a 404, except on `/pypi/simple/<dist>/`, which lists whatever wheels storage still holds for the distribution — `pkg delete pypi` leaves them there |
| `no_namespace` | the request named a namespace no upstream is configured for                                                                                                                                                             |

An audit database written under the retired `discover_mode: "learn"` also holds `would_deny` rows: an upstream the allow-list rejected while learn mode let the fetch proceed. Upgrading relabels them `denied`, merging counts where a `denied` row for the same package already existed. Nothing is deleted, and nothing writes `would_deny` again.

#### What is observed

| Type   | Route                                                                  | Recorded                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ------ | ---------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| apt    | `/apt/dists/{codename}/...`, `/apt/pool/...` under a mirrored codename | every request. Metadata rows carry `<codename>/<path>` as the package and no version, except by-hash entries, which collapse to `<codename>/by-hash` — the path is a digest naming no package, and left whole it sizes the `PACKAGE` column in `discover show` past the width of the terminal. The digest is still on the row, in the upstream URL; pool rows carry the package name and version parsed from the `.deb` filename, and together they are the dependency closure of what the fleet installed                                                                                                                                                                                                            |
| cargo  | sparse index, crate download                                           | every request                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| npm    | packument, tarball                                                     | every request; `no_manifest` on a tarball for an unknown package                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| pypi   | simple index, wheel                                                    | every request bodega proxies, cache hit or miss, including the read of the upstream simple index a wheel is resolved through. `no_manifest` twice: on a wheel for an unknown distribution, and on `/pypi/simple/<dist>/` for a distribution no manifest entry names. The second is the one an observe window runs on: pip meets an uncataloged distribution at the index and never composes a wheel URL, so the wheel route is never reached. Both carry the upstream simple index URL, which is what `generate-manifests` turns into a proxy-mode entry naming the distribution and no version                                                                                                                       |
| gomod  | `/go/...`                                                              | every request; `no_manifest` on a module with no entry                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| helm   | `/helm/charts/*.tgz`                                                   | every request; `no_manifest` on a chart with no entry, with an empty upstream URL (a chart repo is named per version entry, so with no entry there is no URL to record). A `no_manifest` row takes both halves from the chart key, so `cert-manager-1.14.0-rc.1.tgz` is recorded as `cert-manager` at `1.14.0-rc.1` and a promote names a chart that exists. Every other decision still takes its version from a split at the last `-`, recording the same file at `rc.1`, so a chart observed before its entry existed and fetched after it appears in `discover list` at two versions. `promote --as manifest` and `generate-manifests` read `no_manifest` rows only, so the split version never reaches a manifest |
| git    | `/git/{namespace}/...`                                                 | one row per clone under an `open` namespace, with an empty version. A clone is two requests, an `info/refs` GET and a `git-upload-pack` POST, and both pass the allow-list; only the `info/refs` leg is recorded, so a git count means the same thing as every other type's. `no_manifest` on an uncataloged repository under a `catalog` one; `no_namespace` on a first segment naming no `git_upstreams` entry, with the namespace as both the package and the pattern                                                                                                                                                                                                                                              |
| binary | `/binaries/{namespace}/...`                                            | every request under an `open` namespace; `no_manifest` on an uncataloged path under a `catalog` one; `no_namespace` on a first segment naming no `binary_upstreams` entry, once any entry exists                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |

#### Gaps

These are not observed yet. A quiet discovery log for one of them means the hook does not reach it, not that no client asked:

- **apt with no `apt_upstreams`**: `/apt/pool/...` reads storage directly with nothing upstream to fetch, so neither a hit nor a miss is recorded. A pool path a manifest entry owns behaves the same way even on a mirroring instance: it is served from storage and never proxied.
- **anything bodega already hosts**: a hosted entry is served out of storage with no upstream leg, so neither a hit nor a miss is recorded. That holds for every type. It runs against intuition (the better the catalog, the less discovery sees), and it is why a `pip list` on the client and `bodega discover list` on the server do not agree: one widget install had 100 distributions in its venv and one of them, `six`, in no discovery row, because bodega already held its wheel. The record of that install exists, in the audit trail rather than here: `bodega audit events --client <ip> --type serve_fetch`.
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
gomod  example.com/example-corp/   proxy.golang.org    18     no_manifest  2026-09-01 14:22
npm    lodash            registry.npmjs.org  4      no_policy    2026-09-01 14:21

# 4. Turn the packages into manifest entries, and the patterns into rules.
bodega discover promote-all gomod --as manifest
bodega discover promote-all gomod
```

Nothing here needs enforcement relaxed, so nothing has to be switched back afterwards. The `denied` rows are the report worth reading twice: each one is a package a client wanted and the allow-list refused, which is either a rule to add or a client to fix.

#### `bodega discover generate-manifests [type]`

Reads the `no_manifest` rows and writes the package manifests they describe to stdout, as a JSON array. Nothing reaches the manifest store and no discovery row is touched: this command only reads.

The output is the same format [`bodega pkg convert`](#bodega-pkg-convert-type-file-) emits, so `bodega pkg import` takes it with no editing in between — the review step is what the format is for, not a conversion step.

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
WARN skipped a versionless observation of (gomod, example.com/example-corp/widget-sdk): gomod composes the version into the fetch URL, so an open entry would 404 — the versioned rows for this package are unaffected

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

Dumps the raw rows to stdout for offline analysis. `json` emits an array whether or not the table holds rows, so `jq '.[]'` over an export of nothing iterates nothing rather than erroring on `null`; `csv` emits its header row on the same empty table.

### `bodega --break-glass-update-md5 <type|all>`

Recomputes the `.md5` sidecar for every manifest of one package type, or for the whole store with `all`. It stamps whatever the manifest now says without asking why the two disagreed, which is why it is a break-glass flag rather than a verb.

`all` is the only form that reaches `index.json`, `graph.json` and `metrics.json`: those sit at the store root and belong to no type.

---

## Global Flags

| Flag             | Env Var                | Default                    | Purpose                                                       |
| ---------------- | ---------------------- | -------------------------- | ------------------------------------------------------------- |
| `--bucket`       | `REPO_BUCKET`          |                            | S3 bucket name                                                |
| `--region`       | `AWS_REGION`           | `us-west-2`                | AWS region                                                    |
| `--build-root`   | `BOOTSTRAP_BUILD_ROOT` | `/opt/bodega`              | Local build directory                                         |
| `--manifest-dir` | `BODEGA_MANIFEST_DIR`  | `{storage_path}/manifests` | Path to manifests/ directory                                  |
| `--local-config` |                        | `false`                    | Use local filesystem instead of S3 for manifests              |
| `-v, --verbose`  |                        | `false`                    | Verbose output (equivalent to `--log-level 2`)                |
| `--log-level`    | `BODEGA_LOG_LEVEL`     | `0`                        | Logging verbosity: 0=errors, 1=warn, 2=info, 3=debug, 4=trace |
| `-V, --version`  |                        |                            | Print version and exit                                        |

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

| State                                                                                                       | Message                                                                                                      |
| ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| A file where the directory belongs                                                                          | `Error: manifest_dir /var/lib/bodega/manifests is not a directory (config: /etc/bodega/config.json)`         |
| Absent and uncreatable: `/manifests` under `ProtectSystem=strict`, a parent owned by another user           | `Error: manifest_dir … does not exist and cannot be created: mkdir /nope: read-only file system (config: …)` |
| Present but unopenable, which is what a root owned by another user does: it stats fine and reads back empty | `Error: manifest_dir … cannot be opened: permission denied (config: …)`                                      |

Each names the path and the config file the path came from, so the next move is `ls -ld` on the one and an edit to the other.

**An absent root that can be created is created, and the start continues.** On a fresh host neither `storage_path` nor its `manifests/` exists yet, and `systemctl enable --now bodega` has to survive that. The empty repository that follows is the legitimate one, and the `no packages loaded` line above is what marks it in the journal. That carve-out is also why a typo in `manifest_dir` under a writable parent is not caught here: it is created, and the `ERROR` line naming the root it read is the only thing that separates it from a fresh install.

### Storage backends

bodega supports two storage backends:

- **`local`** (default): Stores artifacts on the local filesystem. Set `storage_path` to change the root directory (default: `/var/lib/bodega`). No initialization needed, and no bucket: every command that touches storage runs without one.
  It is the only backend that carries per-object access state, and the only one on which a `chmod`, a `chgrp` or a `setfacl` you applied to a single artifact survives the next refill. See [Publication and access](#publication-and-access).
- **`s3`**: Stores artifacts in an S3 bucket. Set `bucket` and `region`, then run `bodega init` to create the bucket with encryption and versioning.

Manifests follow the backend. On `s3` they live under the `manifests/` prefix in the bucket; on `local` they live in `manifest_dir` on disk, which is also what `--local-config` selects against any backend.

A backend that fails to construct is not fatal for `bodega serve`. The server starts, `/healthz` and the `/api/v1/` routes answer, and every package route returns 503 naming no driver — the driver in the config is rarely the thing that broke. The reason is logged once at `ERROR` on startup, so it prints at the default `log_level` of 0:

```text
ERROR storage backend unavailable — package routes will answer 503; the API and /healthz still serve
  backend=local config=/etc/bodega/config.json error=create storage root /dev/null/nope: mkdir /dev/null: not a directory
```

### Publication and access

Every backend publishes rather than overwrites. A key names the object it named before a write or the object the write stores, never something in between, whichever backend placement sent it to:

- **A refill is all or nothing.** No client is served a half-written body, a truncated one or an empty one.
- **A download in flight finishes on the object it started.** A replacement landing mid-transfer does not reach a client already reading, and the next request gets the new object.
- **An interrupted write publishes nothing.** The key keeps what it held.

What differs per backend is access, and it differs in the direction that matters:

|                                                  | `local`        | `s3`                    |
| ------------------------------------------------ | -------------- | ----------------------- |
| Refill preserves mode, owner, group, ACL, xattrs | yes            | nothing to preserve     |
| A restriction survives the next refill           | yes            | no                      |
| Bytes on disk when the write returns             | not guaranteed | the service's guarantee |

**On `local`, a restriction is a decision and a refill is not.** Refilling an object restates everything it carried that decides who can reach it: its mode, its owner and group, its access ACL and its extended attributes, applied to the staging file before the mode that makes it readable. So a reader the artifact denied stays denied. Where the server cannot restate one of them, the refill fails, names which one, and leaves the previous object exactly as it was: handing an artifact to a group it was kept from is not something a cache fill gets to decide. Giving an artifact a group the server does not belong to is the case that reaches this, and it needs `CAP_CHOWN` or a server running as a member of that group. A new object has nothing to carry and lands at the mode the server's umask allows.

**On `s3`, it is not.** The backend reads and writes no per-object mode, owner or ACL, so there is nothing a refill can widen and equally nothing it preserves. An object ACL or a bucket policy applied outside bodega is not carried across a refill: the next write is a plain `PUT`. An artifact whose restriction has to survive refills belongs on a `local` backend, which per-package placement can arrange.

**Durability.** On `local`, a write returns after the rename with no `fsync`, so a host that loses power moments later can come up holding either object. The guarantees above survive that; the bytes may not. Every artifact the store holds is refetchable from an upstream or rebuildable from source, and the alternative is an `fsync` on every proxy cache fill. Mount the storage tree with your filesystem's own barrier settings if you need the other trade.

**Staging entries.** A `local` write fills a `.bodega-tmp-*` entry and renames it into place. A replacement gets a `.bodega-tmp-*` _directory_ of its own, holding one staging file, because for the length of the write that file holds a whole artifact under the server's access state rather than the object's, and a directory nothing else may enter is what keeps it unreadable until the rename. A fresh object is a `.bodega-tmp-*` file beside its destination. Listings skip both. A crash mid-write leaves one behind: it is safe to delete, and nothing reads it.

### Named backends and per-type placement

`storage_backend`, `storage_path`, `bucket` and `region` describe one backend, whose reserved name is `default`. `storage_backends` adds more, by name. `storage_by_type` says which name the _next_ write of each package type goes to, and `storage_by_group` does the same for a named set of packages that is not a whole type.

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

Four levels decide where the next write goes, most specific first — two for `pypi`, which reaches neither the package level nor the group level:

| Level   | Where it lives                                                                       | Reason                                                                                                                                 |
| ------- | ------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------- |
| Package | `storage_policy` on the package manifest                                             | One package whose bytes must live in a specific bucket, under a specific KMS key, while its type is shared with packages that must not |
| Group   | `storage_by_group.<group>` in the config, joined by `storage_groups` on the manifest | A set of packages that belong together and are not a whole type: forty `apt` packages a customer entitles, an air-gapped mirror set    |
| Type    | `storage_by_type.<type>` in the config                                               | A whole ecosystem on a separate volume                                                                                                 |
| Global  | `storage_backend`/`storage_path`/`bucket`/`region`                                   | Everything else                                                                                                                        |

One version can be directed past all four at write time with [`--storage`](#placing-one-version-at-write-time) on `upload` or `sync`. That is not a fifth level: it records a name on the version entry and stops deciding, where a level would re-decide at every future upload. `pypi` cannot take it, for the same reason it never reaches the package level.

The most specific rule wins. A package policy that lost to a type rule would be a trap: it is set precisely for the package that must not go where the rest of its type goes, and adding a type rule later would silently move it. The group level sits above the type rule for the same reason at set scale, and below the package policy so that the one package singled out by name still wins.

`bodega pkg storage <type> <name>` prints the resolved backend and which level decided it. Naming the winning level is what makes a four-level hierarchy debuggable — `bulk` on its own does not say whether a package policy took effect, a group the package joined, or a forgotten type rule.

`pypi` is the one type neither the package level nor the group level is consulted for. Its wheels upload as one directory to one prefix and the PEP 503 index is a listing over that tree, so honoring a rule for some packages and not others would split it with no listing to reunite it. A group is worse than a policy here rather than better: it holds packages across types, so one group serving a mirror set would place its `pypi` members apart from the rest of the tree. `bodega pkg move` refuses `pypi` for the same reason, and setting `storage_policy` or `storage_groups` on a `pypi` package warns rather than taking effect. Set `storage_by_type.pypi` to place the whole type.

#### Storage groups

A group is a name in `storage_by_group` pointing at a backend, and a package joins it by naming it in `storage_groups`:

```json
{
  "storage_by_group": { "mirror-set": "cold", "customer-acme": "bulk" }
}
```

```json
{
  "name": "nginx",
  "type": "apt",
  "storage_groups": ["mirror-set"]
}
```

The mapping is in the config and the membership is in the manifest, on purpose. Moving a whole set is then one config edit instead of one manifest edit per package, and a package still declares what it belongs to beside everything else it declares. Setting either moves nothing already uploaded; `bodega pkg drift` reports the versions a group rule now disagrees with and `bodega pkg move` moves them.

A package may name more than one group, because operators group by more than one axis and the sets overlap. Resolution is by **group name in sort order, first with a rule winning** — not by the order the manifest lists them, which a re-serialization could change under you. Two groups pointing at two different backends is refused at the edit that creates it, by `bodega pkg edit`, `bodega pkg import` and `POST /api/v1/packages` alike:

```text
storage_groups: groups resolve to more than one backend (alpha -> "bulk"; omega -> "cold"); a package is written to one backend, and "alpha" would win by group name — drop a group, or point them at the same backend in storage_by_group
```

Two groups naming one backend is not ambiguous and passes. A group name no `storage_by_group` key defines is refused outright, on the same grounds as a backend name nothing defines: it decides nothing, so the package falls through to its type rule and the typo surfaces at an upload with no obvious path back to the edit.

#### `storage_policy` and `storage` are different fields on purpose

`PackageManifest.storage_policy` is future tense: put new versions here. `VersionEntry.storage` is past tense: this version's bytes are here. Setting a policy moves nothing; `bodega pkg move` does that. One name for both would mislead every future reader of a manifest.

`bodega pkg create --storage`, `bodega pkg edit` and `bodega pkg import` all record a `storage_policy` on a `pypi` package and warn that it will not be read. The field is recorded rather than rejected so that an existing manifest stays importable and the value survives a round trip through `pkg edit`.

Editing `storage` is checked against the backends, not only against the config. A name that resolves to a configured backend passes validation and still strands the artifact, because reads resolve by the recorded name alone: the bytes stay where they were and the version becomes a 404 for content that exists. So `bodega pkg edit` asks the backend whether the object is there, and refuses an edit that points a version at a backend the object is not on while the one it names today holds it:

```text
storage was repointed at a backend the object is not on:
  example-tool-v2@2.15.0: binaries/example-tool-v2/2.15.0/example-tool.zip is on "default", not "bulk"; use 'bodega pkg move binary example-tool-v2@2.15.0 --to bulk', which copies the bytes and then repoints the record
```

An operator relabeling a record is either correcting a wrong one or stranding an artifact, and the manifest alone cannot tell which. The object on the backend being named is the correction, and it passes. A version with no object at either end strands nothing and passes too, which is what keeps `pkg create` then `pkg edit` working on an entry not yet uploaded. A backend that will not answer is refused rather than waved through: it has not said the object is there. A `pypi` version is probed against the wheel-tree sentinel, `pypi/wheels/MANIFEST.sha256`, since it has no object of its own, and the refusal names `storage_by_type.pypi` rather than `pkg move`.

The probe opens no backend at all when an edit leaves every `storage` field alone, which is almost every edit.

#### Placement is recorded, not recomputed

Each version records the backend it was written to, in `storage` on its manifest entry. Reads use that recorded name and never the config. Change a rule and everything already uploaded stays exactly where it is and stays readable; only the next write moves.

An entry with no `storage` key is on `default`. That is not "resolve it now" — it is the answer, and it is the correct one for every artifact uploaded before named backends existed.

A name no backend answers to is an error rather than a search of the others. Serving bytes from a second backend under a digest recorded against the first is indistinguishable from tampering, which is what the checksum machinery exists to catch.

#### Changing a rule

`upload` and `sync` honor a name a version already records. Change `storage_by_type` and they keep writing where the manifest says, so two runs either side of the change cannot produce divergent copies.

`--replace-placement` is the deliberate move. It applies the current rule to versions already placed elsewhere, repoints the manifest, and warns for every object it leaves behind — nothing copies the old bytes. `bodega pkg move` is the one that copies.

`bodega pkg drift` is how you find out that a rule change left anything behind. Without it the disagreement between the rule and the record is visible on `pypi` alone, where the refusal below fires; every other type writes to the backend its entry records and says nothing.

`pypi` uploads a whole directory with no per-version granularity, so a changed rule refuses outright rather than splitting a tree across backends. `apt` and `git` used to refuse here too and no longer do: both resolve one key per version now, and a rule change repoints only what has not been written yet.

```text
storage_by_type["pypi"] now resolves to "bulk", but 2 pypi version(s) are recorded elsewhere:
  examplesdk@1.35.0 (on "default")
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

`/api/v1/status` does the opposite: one row per backend under `backend_entries`, each with its own `healthy`, and the response-wide `healthy: false` when any row failed. A diagnostic exists to say which backend is broken. A row's `healthy` is true when its probe answered, an empty pool included, so `present: false` beside `healthy: true` is a backend holding nothing rather than a broken one. The failing row's `error` carries the failure verbatim for a caller inside `admin_permit_cidr` alone, because a `local` backend's failure names a directory under `storage_path` and an `s3` backend's names the bucket; from any other host every row reads `"error": ""`, and `healthy` and `backend` still say which one failed. An empty `error` on an unhealthy row means the caller was not an admin, not that the probe never ran: read it from an admin host or from the server log, which records every probe failure as `object store probe failed`. `bodega build status` and the `bodega status` dashboard follow the same policy — the dashboard's `By Backend` table exists because one volume filling up is invisible in a combined byte count.

Every row names its backend in `backend` and reports the probe under `key` and `present`. Nothing in the row names a driver: the same backend name is a local directory on one install and a bucket on the next, and a client acting on this endpoint acts on whether the objects are there and on which backend failed. The fields were `s3_key` and `in_s3` through v1; a client reading either has to move to `key` and `present`, and `s3_entries` to `backend_entries`.

#### Object size

S3 uploads go through the multipart uploader, so an artifact larger than 5 GB reaches an S3 backend. The part size is 16 MiB against S3's 10,000-part cap, which puts the ceiling at 160 GiB.

### Per-type build roots

Each type can build under its own directory instead of `build_root`, which is what puts wheels on a large volume and binaries on fast SSD. One key per type, empty meaning `build_root`:

| Key           | Type   | Directory it roots |
| ------------- | ------ | ------------------ |
| `apt_root`    | apt    | `<root>/apt-repo`  |
| `git_root`    | git    | `<root>/bundles`   |
| `pypi_root`   | pypi   | `<root>/wheels`    |
| `binary_root` | binary | `<root>/binaries`  |
| `gomod_root`  | gomod  | `<root>/gomod`     |
| `helm_root`   | helm   | `<root>/charts`    |
| `npm_root`    | npm    | `<root>/npm`       |
| `cargo_root`  | cargo  | `<root>/cargo`     |

Every command that reads or writes an artifact resolves through the same root: `bodega build run`, `fetch`, `package`, `upload`, `sync`, `repair` and the TUI. An upload that finds nothing names the directory it walked, so a root one command resolved differently from the build is visible in the skip line rather than reported as an empty build:

```text
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

`custom_paths` used to sit in front of all of this and gated nothing: the build path reads each root directly through `builder.rootFor`, so a root left in the file stayed in force after the flag was turned off, and the TUI stopped showing the value that was still deciding where artifacts land. The key is gone. Nothing moves as a result, because the behavior it claimed to gate is the behavior that was already running; a file that still carries it loads unchanged and `bodega doctor` names it under `retired-config-keys`.

**Gap:** the TUI's config form shows four of the nine roots — `apt_root`, `git_root`, `pypi_root`, `binary_root` — so `gomod_root`, `helm_root`, `npm_root`, `cargo_root` and `freebsd_root` can only be set by editing the file. Ctrl+R clears the same four. Tracked as #227.

### Audit database

The audit DB path defaults to `{log_dir}/audit.db`, and its parent directory and the file are created on first use. It holds the served fetches, the mutations, the cache events, every refused request and the server's own start and stop — unless `audit_sink` sends that stream elsewhere, in which case the file still holds the ACLs, the API tokens, the cached checksums and the policy tables. See [Audit Trail](#audit-trail) for the sinks, the event types and what is deliberately left out.

### Environment variables

Settings resolve in priority order: CLI flags, then environment variables, then the config file, then defaults.

| Environment variable  | Purpose                                                                                                                                               |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `REPO_BUCKET`         | S3 bucket name, when the backend is S3                                                                                                                |
| `AWS_REGION`          | AWS region (default: us-west-2)                                                                                                                       |
| `BODEGA_MANIFEST_DIR` | Manifest directory (default: `{storage_path}/manifests`). Overridden by `--manifest-dir`.                                                             |
| `BODEGA_LOG_LEVEL`    | Logging verbosity 0-4                                                                                                                                 |
| `BODEGA_CONFIG_FILE`  | Use this exact path as the config file, whether or not it exists. A generated default is written there too, so nothing touches `/etc` or `~/.config`. |
| `BODEGA_LISTEN_ADDR`  | HTTP listen address for `bodega serve` (default `:8080`). Overridden by `--addr`.                                                                     |

---

## Running under systemd

A sample unit ships at [bodega.service](bodega.service). It is `Type=notify` and uses bodega's sd_notify support to signal readiness rather than having systemd guess.

### Installing the unit

Copy the unit into place, edit `User` and the paths to match the install, then enable it:

```bash
sudo cp docs/bodega.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now bodega
```

The unit's own header carries the steps around it: the service account, the two writable directories, and the ownership pass that has to follow any bodega command run as root. Those leave `config.json` and `audit.db` owned by root, and the service will not start on either.

### Reloading and reading logs

Manifests reload without a restart, and the journal carries everything the process writes:

```bash
sudo systemctl reload bodega        # SIGHUP; rereads manifests in place
journalctl -u bodega -f
```

For an interactive background run without systemd, `nohup bodega serve > /tmp/bodega.log 2>&1 &` works. Bodega does not self-daemonize: systemd, launchd, and supervisord all want the server in the foreground, and a process that forks out from under its supervisor reports its own readiness wrong.

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

| Field            | Type   | Purpose                                                                                                                                                                           |
| ---------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `name`           | string | Canonical package name. `/` is written as `--` in the path, so a name always occupies exactly one directory level. `.` and `..` are refused: see [Package names](#package-names)  |
| `type`           | string | Package ecosystem                                                                                                                                                                 |
| `description`    | string | Short human-readable summary                                                                                                                                                      |
| `dep_policy`     | string | `none`, `direct`, or `transitive`                                                                                                                                                 |
| `storage_policy` | string | Backend this package's _next_ version is written to, overriding `storage_by_type`. Absent means the type rule decides; see [the placement hierarchy](#the-placement-hierarchy)    |
| `storage_groups` | array  | Storage groups this package belongs to, resolved to a backend by `storage_by_group`. Outranks `storage_by_type`, loses to `storage_policy`; see [Storage groups](#storage-groups) |

#### Package names

A name is stored as one path segment, with `/` written as `--`, so `@example-corp/widget-cli` becomes `@example-corp--widget-cli` and no name can add a directory level.

`.` and `..` are refused, by `bodega pkg create`, `bodega pkg import`, `POST /api/v1/packages/{type}` and `POST /api/v1/packages/import` alike:

```text
invalid package name "..": it is path syntax, not a name — ".." resolves to a manifest path outside its own type directory
```

They are the two names the `/` rule does not neutralize, because they are resolved as path syntax rather than stored as text. `apt/../manifest.json` cleans to `manifest.json` at the manifest root, which is also where `npm/../manifest.json` lands, so two packages of different types would share one file and the second write would replace the first. `apt/./manifest.json` lands at `apt/manifest.json`, inside the type directory where no package belongs. Nothing escapes the manifest root in either case ([#160](https://github.com/ravinald/bodega/issues/160)).

### Common fields on VersionEntry

All version entries support:

| Field                | Type   | Purpose                                                                                                                               |
| -------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| `version`            | string | Version identifier (semver, git ref, chart version, etc.)                                                                             |
| `url`                | string | Download, repository, or registry URL (labeled "Source URL" in UI)                                                                    |
| `mode`               | string | `hosted` (default when absent) or `proxy`: whether bodega serves stored bytes or fetches from `url` on demand and caches what it gets |
| `version_constraint` | string | One of: exact, compatible, patch, any                                                                                                 |
| `checksum`           | object | `{"algorithm": "sha256", "value": "hex..."}`                                                                                          |
| `checksum_verified`  | bool   | Whether checksum matches upstream publisher                                                                                           |
| `artifact_size`      | int64  | Size in bytes (set at fetch time)                                                                                                     |
| `hidden`             | bool   | Excludes from client view but keeps in manifest                                                                                       |
| `frozen`             | bool   | Prevents building, editing, or deletion                                                                                               |
| `storage`            | string | Backend holding this version's bytes. Absent means `default`; see [Named backends](#named-backends-and-per-type-placement)            |
| `metadata`           | object | Ecosystem-specific key-value pairs                                                                                                    |
| `build_env`          | object | Build server's environment at artifact creation time                                                                                  |

`build_env` is written by the build, never by the operator, and `bodega show pkg <type> <name> all` prints it:

| Key          | Meaning                                                                                                                                                                                                                      |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `bodega`     | The bodega build that wrote the entry. `dev` for a binary built without `-ldflags`, which is what `go build` and a source checkout produce; `unknown` means nothing handed the builder a version, which no shipped path does |
| `platform`   | `GOOS/GOARCH` of the build host, e.g. `linux/amd64`                                                                                                                                                                          |
| `os_release` | `PRETTY_NAME` from the host's `/etc/os-release`                                                                                                                                                                              |
| `python`     | `python3 --version` on the build host                                                                                                                                                                                        |
| `go`         | `go version` on the build host                                                                                                                                                                                               |
| `rust`       | `rustc --version` on the build host                                                                                                                                                                                          |
| `built_at`   | RFC-3339 UTC timestamp                                                                                                                                                                                                       |

Every key but `platform` is omitted when empty, so an entry stamped on a host without a Go toolchain carries no `go` key rather than an empty one. The whole object is rewritten each time a fetch succeeds, so an entry built before `bodega` was wired carries no `bodega` key until something re-fetches it; nothing backfills it in place.

### Git-specific fields

```json
{
  "version": "v4.5.7",
  "url": "https://example.com/example-corp/widget",
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
  "url": "https://example.com/example-corp/widget-utils.git",
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
  "url": "https://downloads.example.com/example-tool-exe-linux-x86_64.zip",
  "filename": "example-tool-exe-linux-x86_64.zip",
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

The fetch opens the `.tgz` and reads `version:` from the `Chart.yaml` at its root. An archive declaring a release other than the entry's `version` fails the fetch and is deleted rather than stored, because the archive filename, the `index.yaml` entry and the `/helm/charts/` object key are all rendered from the entry: a `version` and a `url` naming different releases would otherwise publish a chart that looks right by every name bodega prints and holds another release's templates. An entry naming no version pins nothing and is not checked. `appVersion` is still the manifest's word and is not read back from the chart.

### Pypi-specific fields

```json
{
  "version": "1.35.0",
  "required_by": ["widget"]
}
```

- **required_by**: list of packages that depend on this version

### FreeBSD-specific fields

```json
{
  "version": "FreeBSD:14:amd64",
  "url": "https://pkg.freebsd.org/FreeBSD:14:amd64/latest",
  "mode": "hosted"
}
```

A `freebsd` entry is a **repository**, not a package. The name is the repository directory a pkg client asks under (`latest`, `quarterly`, `base_latest`) and the version is the ABI above it, which is the string pkg substitutes for `${ABI}` in the URL it was configured with. One entry per ABI, several versions per repository.

- **version**: the ABI directory, e.g. `FreeBSD:14:amd64`. Required; nothing else says which tree of the repository an entry stands for.
- **url**: the repository root with `${ABI}` already substituted. Required unless `generated` is set, and not composed from the other two fields: a private repository need not nest its ABIs the way `pkg.freebsd.org` does, and nothing in a URL says which convention it follows.
- **mode**: `hosted` holds the repository in storage; `proxy` fetches from upstream on a cache miss and holds no snapshot.
- **generated**: `true` for a repository whose packages you built and whose catalogue bodega produces and signs. Refused together with `url` or with `mode: proxy`, and the refusal names the field: a mirror's client trusts FreeBSD's fingerprint and a generated repository's trusts bodega's key, so an entry claiming both says nothing about which signature a client should expect. An entry setting neither is refused by the client-configuration renderer for the same reason from the other side, and goes on being served. See [Hosting your own pkg repository](#hosting-your-own-pkg-repository).

```json
{
  "version": "FreeBSD:14:amd64",
  "generated": true
}
```

No checksum field. A mirrored catalogue carries FreeBSD's own signature and publishes a digest for every package, so the integrity claim is upstream's; a generated one publishes a digest bodega took of the object it stored. See [Mirroring a FreeBSD pkg repository](#mirroring-a-freebsd-pkg-repository).

---

## Pipeline

The build pipeline has four operations, processed in dependency order:

```text
fetch → build → sync → (upload to S3)
```

Actually, the operations are more granular: fetch, build/run, sync, upload.

**Stage cascading:** Each stage automatically runs its prerequisites if outputs are missing. Running `bodega build upload` on a fresh system will cascade through fetch and build stages first.

**Build order:** `binary, git, apt, pypi, gomod, helm, npm, cargo, freebsd`. This order reflects dependencies (e.g., pypi may reference git-cloned repos for its base requirements). It is `manifest.AllTypes`, and the three build subcommands render their help from it rather than restating it.

**Per-entry failures** are logged but do not abort the run. A non-zero exit code is returned if any entry failed.

---

## HTTP Server

`bodega serve` starts a package server that clients use directly.

### Client configuration

**APT** (`/etc/apt/sources.list.d/bodega.sources`), against a signed repository:

```text
Types: deb
URIs: https://bodega-host:8080/apt/
Suites: noble
Components: main
Signed-By: /etc/apt/keyrings/bodega-archive-keyring.gpg
```

The stanza above is the template, not the values. Your instance prints its own on the `bodega serve` startup banner and serves it on `GET /api/v1/status`, filled in from what the running process holds: the suites it answers for, the URL from `public_url`, and `Signed-By:` or the `[trusted=yes]` fallback according to whether a signing key is loaded. Copy that one. The web UI shows the block it read from this endpoint, so it cannot disagree with the server. The TUI renders through the same renderer but supplies the signing state from the key file rather than the process, which is the one axis where the two can differ — see [Details pane](#details-pane).

Install the keyring first. The `.gpg` route serves the dearmored form `Signed-By:` takes directly, so the client needs no `gpg` binary:

```bash
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSL https://bodega-host:8080/apt/bodega-archive-keyring.gpg \
  -o /etc/apt/keyrings/bodega-archive-keyring.gpg
```

The deb822 `.sources` form is preferred over the one-line `.list` form because `Signed-By:` there is a path rather than a bracket option, and one stanza can carry several suites. The one-line equivalent is `deb [signed-by=/etc/apt/keyrings/bodega-archive-keyring.gpg] https://bodega-host:8080/apt/ noble main`.

The suite (`noble` above) is any entry in `apt_suites`. One instance serves several: list them on the `Suites:` line, or give each its own sources line in the one-line format. A `.deb` listed in two suites is stored once in the shared `pool/` and appears in both `Packages` indexes with the same `Filename:`.

A **mirrored codename** is configured differently, because something else signs it:

```text
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

`/pypi/simple/<name>/` lists the wheels in storage, filtered to the versions the manifest entry names under its `version_constraint`. A distribution with no entry of its own is listed unfiltered: it arrives as somebody else's transitive dependency and the resolved closure is what pins it.

**Go modules**:

```bash
export GOPROXY=https://bodega-host:8080/go
go get example.com/example-corp/widget-sdk@v1.30.0
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

A package an entry names is answered from the manifest instead, with no upstream in the path: every version the entry records, each `dist.tarball` on this server's `/npm/` route, `dist.integrity` wherever a sha256 was recorded, and `dist-tags.latest` naming the highest version left after the hidden-version, constraint and profile filters have run. So `npm install --registry` works with `proxy_cache_enabled` false and no route to `registry.npmjs.org`. The entry decides this, not the mode it records: a `proxy`-mode entry is answered from the versions it lists too, so a release nobody pinned is absent from the packument while the tarball route still fetches it on request. Only a package no entry names is proxied.

Each version's `dependencies` come from `package/package.json` inside the tarball, read once when `bodega build fetch` downloaded it and recorded on the version entry. A packument lists every version, so reading each stored tarball to answer one metadata request would be O(versions x size) on the route every `npm install` starts with. An entry fetched before bodega recorded any omits the key rather than publishing an empty object: npm reads `{}` as "needs nothing", and only the absent key is honest about a version nobody has re-fetched. Only runtime dependencies are recorded — `devDependencies` are the author's build inputs and npm does not install them for a consumer, and `peerDependencies` are the consumer's to satisfy.

`dist.integrity` is the sha256 of the bytes the fetch stage stored, which is what npm verifies the download against. The digest an entry's `checksum` declares answers a different question — what upstream or the operator said the version should be — so where the two records disagree the key is omitted and both are logged at error. The version stays resolvable and installable: npm installs one carrying no `integrity`, and that is the difference between an operator reading a log line and a user meeting `EINTEGRITY` on a download that was not corrupt.

**cargo** (`.cargo/config.toml`, since a sparse registry is named in a file rather than on the command line):

```toml
[source.crates-io]
replace-with = "bodega"

[source.bodega]
registry = "sparse+https://bodega-host:8080/cargo/"
```

A crate an entry names gets the same treatment as npm, on the same terms: the sparse-index document is generated from the manifest, one JSON object per line, filtered the same three ways. `cksum` is the digest of the crate as stored, read per request; the sha256 `bodega build fetch` recorded answers only where this server holds no bytes for the version, which is the case for a `proxy`-mode entry whose download route goes upstream. A version is left out of the index rather than published with a checksum the bytes contradict: no digest can be established for it at all, or the recorded one disagrees with the stored crate, which happens when the crate is rebuilt or replaced under a manifest that keeps the old value. cargo reports a `cksum` mismatch as a corrupt download, which sends whoever hits it to their disk rather than to this registry, so a 404 on the crate is the better failure. The mismatch is logged at error with both digests.

`deps` is the dependency list `bodega build fetch` recorded from the upstream sparse index for that version, and `[]` where it recorded none: cargo refuses to deserialize a line missing the member, before it reaches the crate the line describes. The record comes from the index rather than from the `Cargo.toml` inside the `.crate`, because a registry dependency carries `name`, `req`, `features`, `optional`, `default_features`, `target` and `kind`, and `Cargo.toml`'s workspace inheritance, `path` dependencies and `git` dependencies map onto none of that. The registry resolved them when the crate was published, and the index line is where that resolution is written down. An index host that cannot be reached during a fetch logs a warning and records nothing; the crate's own bytes are unaffected and a later `--force` fetch fills the record in.

**Gap:** a generated index line declares `features: {}`. bodega records no cargo feature table, so a crate whose dependency needs a named feature resolves and downloads but may not compile. Recording the feature map is the same mechanism as `deps` and waits on nothing but the work.

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

The last line runs on the client and writes the token into the file each of its package managers reads. See [`bodega doctor`](#bodega-doctor---write-credentials---token-token---url-url---write-apt-sources---suite-codename---write-pkg-repo---abi-abi---release-n) for what lands where, and [`bodega identity`](#bodega-identity-bindunbindlist) for the CIDR binding that covers a whole subnet with no credential to distribute.

**FreeBSD pkg** (`/usr/local/etc/pkg/repos/bodega.conf`). Do not hand-write this one; ask the server:

```bash
bodega doctor --write-pkg-repo --url https://bodega-host:8080
```

The server renders it, because two of the three things it has to get right are facts only the running instance holds. `GET /api/v1/status` carries the same document under `freebsd.repos[].conf` for a host with no bodega binary on it, and the TUI and web UI show it per entry. On a FreeBSD 15 host mirroring `latest` it comes out as:

```text
FreeBSD-ports: { enabled: no }
FreeBSD-ports-kmods: { enabled: no }
FreeBSD-base: { enabled: no }

bodega-latest: {
  url: "https://bodega-host:8080/freebsd/${ABI}/latest",
  mirror_type: "none",
  signature_type: "fingerprints",
  fingerprints: "/usr/share/keys/pkg",
  enabled: yes
}
```

Four things in it are not obvious and each has a failure behind it.

**The overrides name the tags the target release defines, and the release moved.** FreeBSD 13 and 14 ship one repository, tagged `FreeBSD`. FreeBSD 15 split it into `FreeBSD-ports`, `FreeBSD-ports-kmods` and `FreeBSD-base`. pkg merges repository definitions by tag across `/etc/pkg/` and `/usr/local/etc/pkg/repos/`, so an override naming the wrong tag disables nothing: the upstream repository stays enabled beside bodega's and the host keeps fetching from the internet while the operator believes it is isolated. Nothing in `pkg update` output reports that; `pkg -vv` is where you see it. The release comes off the entry's own ABI, and `--release` overrides it for a host that is not the one the repository is named for.

**`pkg+https` is not a spelling of `https`.** `/etc/pkg/FreeBSD.conf` uses it and the next reader of this file will wonder. The `pkg+` scheme means SRV mirror discovery: the client resolves `_https._tcp.<host>` and expects a record set. bodega is one host and publishes none, so the URL is plain and `mirror_type: none` says there is nothing to discover.

**`${ABI}` stays literal.** pkg substitutes the running host's own ABI, so one file is correct across every architecture bodega mirrors.

**`signature_type` follows what the repository is, and the three answers are not interchangeable.** A mirror is copied byte for byte precisely so FreeBSD's own signature reaches the client inside `packagesite.pkg`. Which key signed it depends on who built the repository: the package builders sign ports and the base snapshots with the key in `/usr/share/keys/pkg`, release engineering signs `base_release_<n>` with the key set in `/usr/share/keys/pkgbase-${VERSION_MAJOR}`, and both directories ship on a FreeBSD 15 host. `/etc/pkg/FreeBSD.conf` says the same: `FreeBSD-ports` and `FreeBSD-ports-kmods` name the first, `FreeBSD-base` names the second. bodega reads two things to tell them apart, the entry's upstream URL and the release the repository was built for: the repository name is the operator's and says nothing about who signed what is under it, and 15 is the first release whose base system installs the pkgbase store at all, so a mirror of `base_release_<n>` for 13 or 14 verifies against the ports store like ports. Measured with pkg 2.7.5: `FreeBSD:14:amd64/base_release_1` verifies under `/usr/share/keys/pkg` and not under `/usr/share/keys/pkgbase-15`. The emitted comment names whichever of the two terms excused a repository from the pkgbase store, because a file that told a `base_release_1` mirror it was not a `base_release_<n>` repository would send its operator to move `fingerprints` onto a directory their host does not have:

```text
bodega-base: {
  url: "https://bodega-host:8080/freebsd/${ABI}/base",
  mirror_type: "none",
  signature_type: "fingerprints",
  fingerprints: "/usr/share/keys/pkgbase-${VERSION_MAJOR}",
  enabled: yes
}
```

A repository bodega generated is signed with bodega's key and verifies against `/usr/local/etc/pkg/fingerprints/bodega`:

```text
bodega-house: {
  url: "https://bodega-host:8080/freebsd/${ABI}/house",
  mirror_type: "none",
  signature_type: "fingerprints",
  fingerprints: "/usr/local/etc/pkg/fingerprints/bodega",
  enabled: yes
}
```

Point a mirror at bodega's fingerprints and every `pkg update` fails on a signature it cannot check; point a generated repository at FreeBSD's and the same. Mixing up FreeBSD's two stores is quieter and worse: measured against `FreeBSD:15:aarch64/base_release_1` on 15.1-RELEASE with pkg 2.7.5, the ports store fetches the catalogue, prints `No trusted public keys found`, processes 0 entries and exits 0, and the next `pkg install` reports the package as missing rather than as unverifiable. The same catalogue against `/usr/share/keys/pkgbase-15` processes 502. bodega derives it rather than taking a flag, and refuses to render at all for an entry that names both of the fields it derives from or neither. Both `generated` and a `url` is two right answers; neither is none, because a catalogue bodega did not copy and did not build is one nobody here knows the signer of, and the mirrored answer would point `fingerprints` at a store that checks whatever was uploaded only by luck. That refusal is the emitter's alone: the route serves such an entry from the store, so it gets a row in `freebsd.refused[]` and goes on answering. To stop re-fetching a mirror while keeping the answer, set `frozen` rather than clearing the `url`. A generated repository on a server holding no signing key renders `signature_type: none`, and its emitted comment says the catalogue carries no signature rather than that bodega signed it. See [Hosting your own pkg repository](#hosting-your-own-pkg-repository) for what installs the fingerprint file, and [Mirroring a FreeBSD pkg repository](#mirroring-a-freebsd-pkg-repository) for the mirror.

**How much of this repository leaves the host is two facts, and the file answers with both.** Whether _any_ path falls through to upstream is the three terms above: the entry records a `url`, and either its mode is `proxy` or the server's `proxy_cache_enabled` is on. How much falls through is the serving mode alone. A proxied repository fetches its catalogue from upstream with everything else and holds nothing of its own; a hosted mirror serves the catalogue that was published to it and answers a miss on `meta.conf`, `packagesite.pkg` or `data.pkg` with 404 rather than fetching it, because upstream's catalogue names packages the mirror has never held. Those three names are what the route recognizes, and the emitted comment names them for that reason. Both facts reach the client configuration, and neither is enough on its own. Measured on 2026-09-21 against two `FreeBSD:15:aarch64` entries recording the same `pkg.FreeBSD.org/FreeBSD:15:aarch64/quarterly` URL on a server with `proxy_cache_enabled: true` and nothing uploaded to either, differing only in the mode:

| Path                | `mode: proxy` | hosted |
| ------------------- | ------------- | ------ |
| `meta.conf`         | 200           | 404    |
| `packagesite.pkg`   | 200           | 404    |
| `data.pkg`          | 200           | 404    |
| `All/pv-1.9.31.pkg` | 200           | 200    |
| `Latest/pkg.pkg`    | 200           | 200    |

Every 200 came off `pkg.FreeBSD.org` and `cache_origins` names the upstream URL for each. So the emitted comment says one of four things rather than the one it used to: every request may reach the internet including the catalogue, or the catalogue is served here and every other path falls through on a miss, or nothing falls through because there is no `url` to resolve a miss against, or nothing falls through because this repository is hosted and `proxy_cache_enabled` is off. The second is the one an operator is most likely to be wrong about, because a hosted mirror is what you reach for when you want a finished local copy, and an install against it can succeed on a package nobody mirrored.

**The isolation claim names the term that would make it false, and the last two cases above do not have the same term.** A generated repository records no upstream, so no setting on the server can make a miss leave the host. A hosted mirror is isolated only while `proxy_cache_enabled` is off, and the file is installed on a client that never hears about that toggle again: turn it on and the stanza on disk goes on asserting isolation while `All/*.pkg` misses are fetched from `pkg.FreeBSD.org` and served under bodega's name. So the mirror's paragraph names both terms that put it there and says what flips them, and `bodega doctor --write-pkg-repo` is what re-reads the file after either changes. `upstream_fallthrough` on `GET /api/v1/status` answers the same question in one bit and cannot tell the two apart; the `conf` beside it can.

**`pkg bootstrap` is the one thing this may not give you, and the mode is not what decides it.** pkg's bootstrapper fetches `<repo>/Latest/pkg.pkg` and `<repo>/Latest/pkg.pkg.sig` and nothing else, and a mirror publishes only the repopaths its catalogue names, which never include that pair. What decides the answer is whether bodega fetches a path outside the catalogue from upstream, and that is three terms rather than the mode alone: the entry records a `url`, and either its mode is `proxy` or the server's `proxy_cache_enabled` is on. So a hosted mirror on a server with the cache on resolves both paths against upstream exactly as a proxied one does, and only a repository where none of the three holds is isolated. Upstream publishes a pkg package under the ports repositories and nowhere else. Measured with `fetch` against `pkg.FreeBSD.org` on 2026-09-21, both paths per repository: `latest` and `quarterly` answer 200 on `FreeBSD:15:aarch64` and `FreeBSD:14:amd64`; every `base_*` and `kmods_*` repository answers 403 or 404 on both, including `base_release_0`, which serves `pkg.pkg` and 403s the signature the bootstrapper checks it against; `release_0` and `release_1` answer 200 on 15 and 404 on 14. What the client sees is not always what upstream said: bodega passes a 404 through and turns any other upstream refusal into a 502 whose body names nothing, with the refusing URL in the server log. So bodega renders three answers rather than two, and a repository nobody measured gets the hedge: the emitted comment says which case this file is, the `bootstrap` field on `GET /api/v1/status` says the same in one word, and `upstream_fallthrough` beside it answers the question a reader means by "is this repository proxied". Install pkg from upstream, or from a ports repository through bodega, before switching a host over.

Verified against FreeBSD 15.1-RELEASE with pkg 2.7.5: the file above installs, `pkg -vv` reports all three upstream tags `enabled: no` and `mirror_type` absent from bodega's definition (pkg prints it only when it is not `NONE`), and `pkg update` followed by `pkg install` resolves from `[bodega-<repo>]`. The `base_release_<n>` form was proven the same way against a proxied `FreeBSD:15:aarch64/base_release_1`: `pkg -vv` resolves `${VERSION_MAJOR}` to `/usr/share/keys/pkgbase-15`, `pkg update` processes 502 packages and `pkg fetch FreeBSD-telnet` pulls the package through bodega.

### Git smart-HTTP

`git clone` against bodega speaks the same protocol it speaks against a forge. A `git_upstreams` namespace (see [Git upstreams](design.md#git-upstreams) for the config structure) maps onto an upstream, and bodega keeps a bare mirror of every repository a client has asked for.

```text
GET  /git/{namespace}/{org}/{repo}.git/info/refs?service=git-upload-pack
POST /git/{namespace}/{org}/{repo}.git/git-upload-pack
```

Those two suffixes are the whole served surface. Every other path under a namespace is a 404, including `HEAD` and `objects/info/packs`: bodega does not serve the dumb-HTTP protocol. The clone URL must end in `.git`, which is what a client types anyway.

On the first request bodega runs `git clone --mirror` into `{storage_path}/git/{namespace}/{org}/{repo}.git` and serves from that mirror afterwards. Concurrent first requests for one repository collapse into one clone. A clone that fails takes its directory with it — a partial mirror would answer later requests with a truncated history — and the client gets a 502 that names no path; the git error is in the server log.

What is on disk is inspected rather than counted. `git clone --mirror` creates the destination at the start of the transfer, so a restart, an OOM kill, or a removal that lost to a permission error leaves a directory holding `config`, `description`, `hooks/` and `info/` and nothing else. bodega treats a directory with neither `HEAD` nor its own `.bodega-fetched` stamp as an interrupted clone: it is removed and cloned again on the next request, and both legs of the protocol do it, so the `git-upload-pack` POST that arrives while the `info/refs` clone is still running blocks on the same lock rather than answering 404 with an empty body. A removal that fails is a 502 naming the reason in the log, not a mirror that 404s forever with nothing retrying.

**Repointing `git_upstreams[ns].url` re-clones.** Every mirror records the URL its own clone used, and bodega compares it against the configured upstream before serving. A mismatch is a forge migration, a host swap or a typo correction, so the mirror is discarded and cloned from the new URL, with both URLs in a `WARN`. Budget for the transfer: repointing a namespace with fifty mirrors under it re-clones all fifty, one per first request after the change.

`open` and `catalog` behave here as they do everywhere: a `catalog` namespace never clones a repository no manifest entry names, and answers 404 instead. With `discover_mode` set to `"observe"` the 404 also records a `no_manifest` discovery row, and `bodega discover promote git <pattern> --as manifest` turns that row into the entry, after which the same clone succeeds. With discovery off the 404 records nothing. The pattern is the upstream host and the first segment of its path (`github.com/freebsd/` for a namespace pointing there), not the `<org>/<repo>` the entry is named for; `bodega discover list git` prints it. The allow-list runs before the clone, so a denied upstream is a 403 with nothing written to disk.

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

```bash
curl -O https://bodega-host:8080/git/widget/widget-v4.5.7.bundle
git clone widget-v4.5.7.bundle widget
```

No `--branch` is needed: the packaging stage points the bundle's HEAD at the commit the entry's ref names, and refuses to write a bundle without one. A tag clones detached, a branch clones onto that branch, because git names a branch only when the bundle carries a `refs/heads/*` at HEAD's commit. A bundle written before HEAD was packaged has only its ref and clones into an empty repository whose error names the client's own branch; `bodega package git` rewrites it from the bare repo and the next `bodega sync` replaces the stored object at the same key.

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

| Order | Path                                     | Notes                                                     |
| ----- | ---------------------------------------- | --------------------------------------------------------- |
| 1     | `$CREDENTIALS_DIRECTORY/apt-signing.key` | systemd `LoadCredential=`; a per-service tmpfs, mode 0400 |
| 2     | `/etc/bodega/apt-signing.key`            | packaged location                                         |
| 3     | `<storage_path>/apt-signing.key`         | beside the artifacts                                      |

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

```text
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

A codename listed in `apt_upstreams` is a **mirrored codename**: served from upstream rather than generated, the other of the two modes a codename can take. A codename in `apt_suites` is a **generated suite**, built from bodega's own manifest entries and signed by bodega. bodega proxies `dists/<codename>/...` and the pool artifacts the index points at, caching each on the way through. This is what makes `apt update && apt install <anything>` work against bodega for packages nobody pre-built: apt reads the proxied `Packages`, resolves dependencies locally, then asks bodega for each `.deb` by its `Filename:`.

```json
"apt_upstreams": {
  "noble":          [{"url": "https://archive.ubuntu.com/ubuntu"}],
  "noble-updates":  [{"url": "https://archive.ubuntu.com/ubuntu"}],
  "noble-security": [{"url": "https://security.ubuntu.com/ubuntu"}]
}
```

```text
Types: deb
URIs: https://bodega-host:8080/apt/
Suites: noble noble-updates noble-security
Components: main restricted universe multiverse
```

bodega parses no index. The upstream `Release` names the components, architectures and `by-hash` digests, apt reads them, and the next request arrives with the path already composed, so any component the upstream publishes resolves, not only `main`.

#### `components`

The `Components:` line above is what bodega prints for a mirrored codename with nothing configured: Ubuntu's four. bodega cannot read the upstream `Release` to find out what a codename really publishes without fetching it at startup, which would make every client's availability depend on a host bodega only proxies. So the line is configured, per upstream, beside the URL:

```json
"apt_upstreams": {
  "bookworm": [{"url": "https://deb.debian.org/debian",
                "components": ["main", "contrib", "non-free", "non-free-firmware"]}]
}
```

Several upstreams for one codename contribute a union, in config order, each component once: apt reads one `Components:` line for the whole suite, and a component any of them publishes is one apt may request.

Set it whenever the upstream is not Ubuntu, and check the printed line against the archive before pasting it. The two ways to be wrong are not symmetric. A component the upstream does not publish fails at `apt update`, loudly, naming the component and the URL that 404d. A component left off the line fails much later, at `apt-get install`, after `apt update` reported success, as a package apt cannot locate: `redis-server` is in `universe`, and a stanza naming only `main` installs everything up to the moment it does not.

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

| Key                        | Default                | What it bounds                                        |
| -------------------------- | ---------------------- | ----------------------------------------------------- |
| `spool_dir`                | `{build_root}/tmp`     | Where the spool files are written                     |
| `spool_max_artifact_bytes` | `8589934592` (8 GiB)   | The largest single artifact the proxy will copy       |
| `spool_max_total_bytes`    | `34359738368` (32 GiB) | The bytes every fetch in flight may hold between them |

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

### Mirroring a FreeBSD pkg repository

A `freebsd` entry does one of two jobs, and which one decides everything a client has to be configured for. It mirrors an upstream repository, which is this section; or it hosts packages you built, which is [the next one](#hosting-your-own-pkg-repository). An entry naming a `url` mirrors, an entry marked `generated` hosts, and an entry claiming both is refused rather than resolved.

A mirror copies the repository **byte for byte**, and that constraint decides the whole design of the type. `packagesite.pkg` and `data.pkg` are zstd tarballs, and each carries three members: a 256-byte signature, a 451-byte public key and the document itself. The catalogue spells them `packagesite.yaml.sig`, `packagesite.yaml.pub` and `packagesite.yaml`; `data.pkg` spells them `data.sig`, `data.pub` and `data`. There is no `.sig` sidecar on the wire. So a byte-exact copy of those archives carries FreeBSD's own signature with it and validates against the key that signed the repository upstream, with no key of bodega's and no client-side signature configuration: `/usr/share/keys/pkg/trusted/pkg.freebsd.org.2013102301` for ports and for the base snapshots, and `/usr/share/keys/pkgbase-15/trusted/` for the `base_release_<n>` repositories release engineering signs. Regenerating the catalogue with `pkg repo` would discard that attestation permanently and force a fingerprint onto every client.

This is the opposite of what apt needs. bodega generates and re-signs Debian metadata for a generated suite because it has to; a mirrored pkg catalogue is never regenerated, because doing so would throw away the only thing that makes it worth mirroring exactly.

```bash
bodega pkg create freebsd          # prompts for the repository, the ABI and the URL
bodega build fetch freebsd         # mirror every repository the manifest names
bodega build upload freebsd        # place what was mirrored
```

The client stanza is under [Client configuration](#client-configuration).

#### The catalogue is the only authority on where packages live

`packagesite.yaml` is newline-delimited compact JSON despite the name, and each record carries `repopath`. The two repositories on `pkg.freebsd.org` spell it differently, and neither form is derivable from a package name and version:

| Repository    | Records | Bytes    | A repopath                                                     |
| ------------- | ------- | -------- | -------------------------------------------------------------- |
| `latest`      | 38,325  | 182.8 GB | `All/Hashed/zogftw-2025.02.23_1~2$snxfrbid.pkg`                |
| `base_latest` | 535     | 1.2 GB   | `./Hashed/FreeBSD-telnet-14.snap20260920075547~2$ea5o6tyi.pkg` |

There is no directory listing to crawl either: `All/` answers 403 upstream. So the mirrored object set is read out of the published archives and from nothing else.

Both of them, not `packagesite.pkg` alone. `data.pkg` carries the same record per package in one JSON document, which `pkg_repo_fetch_data_fd` reads out of the member `meta.conf` names under `data`, and the two are fetched a moment apart from a repository that rebuilds continuously, so they can describe different generations. bodega mirrors the union of what they name, because it publishes both unchanged and cannot rewrite either. A `data.pkg` whose member cannot be read fails the mirror with the member named: publishing an archive whose object set is unknown is the one thing the ordering rule below cannot protect a client from.

A leading `./` is dropped, because every HTTP client normalizes it out before the request leaves and keeping it would key an object under a path no request can spell. A `..` is refused rather than cleaned: the catalogue decides both the URL fetched and the path written, so a record resolving outside the repository is one this mirror must not touch.

A record that resolves onto a repository-root file is refused as well: `meta.conf`, `data.pkg` and `packagesite.pkg`, and the legacy names `digests.pkg`, `digests.txz`, `packagesite.txz` and `repo.txz` that the route answers 404 by. The repository root is bodega's own namespace, and a package keyed there would land on the metadata a client reads to find every other package — during the mirror's object phase, in the object half of an upload, inside a move's object loop, each of them before the ordering rule below applies. The first path segment decides it, after `./` is dropped and with case folded, because the build tree and a local backend are filesystems: one name is a file or a directory and not both, and APFS answers `Data.pkg` with `data.pkg`. A package at the repository root is an ordinary layout and stays mirrored; only these names are not its to take.

#### `packing_format`, not the extension

`meta.conf` is plain unsigned UCL, 168 bytes upstream, and it is the first request every `pkg update` makes. The codec of `packagesite.pkg` is read from its `packing_format` key rather than inferred from the `.pkg` extension, which names the archive and not the codec: a repository built by pkg 1.16 serves `packing_format = "txz"` under files spelled `.pkg`.

`tzst`, `tgz`, `tbz` and `tar` are read. `txz` is refused by name — Go ships no xz decoder — with the way out in the message: mirror a repository built by pkg 1.17 or later, or serve that one in proxy mode, where the catalogue is never parsed.

#### Objects first, catalogue last

A catalogue that lands ahead of the objects it names is a repository where `pkg install` resolves a package and then 404s partway through fetching it, and the upstream repositories rebuild continuously, so the window is not theoretical. The ordering holds at three layers:

- The mirror stages `meta.conf`, `data.pkg` and `packagesite.pkg` outside the tree, fetches every object either archive names, and only then moves the three into place. The staging directory belongs to that one run: a scheduled mirror and a manual one overlap often enough, and a shared staging path had the first to finish publish whichever archives were there — the other run's catalogue, naming a package still in flight. Each run publishes the archives it fetched and parsed, and nothing else.
- Every object lands through a temporary sibling and an atomic rename, and a body short of its declared `Content-Length` is discarded. A partial file left where a package belongs is indistinguishable from a mirrored one on the next run, which is how a catalogue gets published over 3 bytes of a 100-byte package; a forced refresh that fails keeps the copy that was already good.
- `bodega build upload` copies the three repository-root files out of the tree first and uploads those copies, reading the object list out of them rather than off a directory walk. Enumerating the upload set and opening its files are separated by however long the objects take to write, and a mirror landing in that window replaces the catalogue under a path the upload is still holding: the bytes published would then be a generation whose new objects are in nobody's upload list, with the ordering below satisfied and the repository still broken.
- Within that upload every object lands before any repository-root file, and `packagesite.pkg` last of all. An object the pinned catalogue names that is not on disk fails the enumeration with the entry, the object and the consequence in the message, and nothing is uploaded for that entry — the previously published generation stays the one clients read. Objects in the tree that the catalogue does not name are not uploaded: no client can ask for them.
- That upload resolves its storage backend once per repository and ABI, and writes every object and all three root files there. Every other type resolves placement per artifact, which is right where an artifact stands alone; a pkg catalogue does not, so an operator repointing the entry with `--storage` or a manifest edit while an upload of it runs sees that upload finish where it started and the next one honor the new name. A catalogue published into a backend holding another run's objects is a repository whose every `repopath` resolves to a 404.
- `bodega pkg move` republishes the repository rather than copying a key list: it copies the three root files out of the source backend first, enumerates the object set from those copies, writes every object to the destination, and publishes the root files last. See [a freebsd move is a republication](#a-freebsd-move-is-a-republication).
- A **hosted** entry's catalogue is never fetched from upstream on a miss. Upstream's catalogue is by construction newer than this mirror's objects and names packages the store has never held, so a miss answers 404 and `pkg` reports the repository as unavailable rather than installing half a transaction. Objects on a hosted entry may still be proxied: an object arriving late can only complete an install, never break one.

A **proxy**-mode entry holds no snapshot, so both halves come from upstream per request and are self-consistent; there is no skew for the ordering rule to prevent.

#### One entry per ABI, and it answers for its own requests

A `freebsd` package is a repository and its version entries are the ABI directories under it, each with its own mode, URL, storage backend and `hidden` flag. A request names the ABI in its path, so every one of those is read off the entry that ABI names: `FreeBSD:13:amd64` in proxy mode beside a mirrored `FreeBSD:14:amd64` serves each the way it was configured, and `bodega pkg hide` on one ABI stops it being served whatever the ABI beside it is doing.

#### Identity bytes on the wire

Every upstream fetch bodega makes for this type, the mirror's and the proxy's alike, asks for `Accept-Encoding: identity`, and a response that carries a `Content-Encoding` anyway is refused rather than decoded. Go's HTTP transport asks for gzip on its own and decodes the answer transparently, so a fetch that says nothing stores what the transport produced rather than what the repository signed. A refusal names the encoding and the URL: the usual cause is an entry pointed at a rewriting proxy rather than at an origin.

#### What is deliberately not served

`digests.pkg`, `digests.txz`, `packagesite.txz` and `repo.txz` all 404 on every current FreeBSD repository, and bodega refuses them by name rather than proxying them: a proxy would spend a round trip per client per update to cache somebody else's 404. `digests` was a `meta.conf` key whose own source comment at pkg 1.12 reads "Leave digests here so pkg will not complain", and it is gone from pkg 2.x.

#### `mirror_type` and the allow-list

`freebsd` is host-scoped in the upstream allow-list, the same as `apt`: `bodega policy add freebsd pkg.freebsd.org` names the archive host, because a request that reaches upstream carries a repopath and no package identity at all.

### Hosting your own pkg repository

An operator serving packages they built — out of poudriere, or by hand with `pkg create` — has no upstream catalogue to copy. bodega produces one for them: `meta.conf`, `packagesite.pkg` and `data.pkg`, built from the packages stored under the repository and served at the same paths a mirror serves them at.

```bash
bodega freebsd key generate        # RSA-4096, mode 0600, where the server searches
bodega pkg create freebsd          # repository and ABI; leave the URL blank
bodega build upload freebsd        # place the .pkg files you put in the build tree
```

Put the packages under `<build_root>/freebsd/<ABI>/<repository>/`, in whatever layout you like — `All/`, hashed, or flat at the root. The upload takes every `.pkg` beneath that directory and nothing else; `meta.conf`, `data.pkg` and `packagesite.pkg` are bodega's own names there, and a file left under one of them is skipped with a line saying so.

Each file in that tree uploads under one name. poudriere publishes most of a tree twice, `Latest/pkg.pkg` and an ordinary name beside every hashed one, and the two names are one package: uploading both stores that package under two keys, and the catalogue then carries two records pkg hashes alike. `pkg repo` drops the extra names for the same reason. The name kept is the real file where one of the names is a real file, and otherwise the first in lexical order, so the `repopath` a client downloads does not move when an alias appears or disappears beside the package.

The rule is over the file rather than over the link, which matters in two trees. A link whose target the upload does not itself publish — a `.txz` beside it from before pkg 1.17 spelled them `.pkg`, a staging name, a target under one of the three reserved roots — is the only name those bytes have, so it uploads. And two links at one file outside the tree are two names for one package even though neither resolves inside anything, so one of them uploads.

#### What a bodega signature proves

**That the catalogue came from this mirror. Nothing more.**

It says the records were served by the bodega instance holding that key, and that they have not been altered since. It says nothing about FreeBSD, about the ports tree a package was built from, or about the machine that built it. A mirrored repository carries a different claim entirely — FreeBSD signed that catalogue, and copying it byte for byte is what delivers the signature intact — and generating a catalogue is precisely the act that discards it. There is no configuration in which bodega re-attaches an upstream attestation to a document it produced, because a signature over bytes nobody upstream ever saw is not upstream's signature.

So the two repository kinds carry two different trust stories to two differently configured clients, and the failure mode of confusing them is quiet: pkg reports a repository it will not read and names the signature, never the configuration that asked for the wrong one.

#### One package, one record

pkg loads a catalogue into SQLite and then creates a unique index over `manifestdigest`, so two records it hashes alike fail the whole repository rather than the duplicate. `pkg update` reports the entries processed, fails with `UNIQUE constraint failed: packages.manifestdigest`, and the client keeps the catalogue it already had.

That digest is over a fixed field set: name, origin, version, arch, the vital flag, options, required and provided shlibs, users, groups, dependencies, provides and requires. The comment, the description, the sizes, the checksum and the key an object is stored under reach none of it.

So bodega publishes one record per package pkg would index, and decides between two objects claiming to be one package by their bytes:

- **Same package, same bytes.** One record, naming the lexicographically first key. That is an alias, and the document does not change when one appears or disappears beside the package, so no client refetches the catalogue over it.
- **Same package, different bytes.** Nothing is generated, and the error names both objects. Two builds of one version are a repository pkg refuses to load whichever of them bodega published, and choosing would decide on a sort order which one every client installs.

```text
freebsd house@FreeBSD:14:amd64: freebsd/FreeBSD:14:amd64/house/All/Hashed/widget-1.2.0~2$abcdefgh.pkg and freebsd/FreeBSD:14:amd64/house/All/widget-1.2.0.pkg are two builds of one package (widget-1.2.0) and differ in their bytes (sha256 4f21… against 9ba0…). pkg indexes both under one manifestdigest and refuses a catalogue holding the pair, so nothing was generated and the repository serves the catalogue it was serving before. Remove the object that should not be published, or give one of the two a version of its own
```

Two versions of one package are two packages to that index, and so are two option builds of one version. Both are published.

#### The signature is a member of the archive

`packagesite.pkg` carries exactly three members when a key is installed — `packagesite.yaml.sig`, `packagesite.yaml.pub` and `packagesite.yaml` — and `data.pkg` carries `data.sig`, `data.pub` and `data`. That is the shape upstream publishes, and there is no `.sig` sidecar on the wire for a client to fetch. With no key installed each archive carries the document alone, which is a supported configuration: pkg's own `signature_type` defaults to `NONE`.

Both members carry a `$PKGSIGN:<signer>$` frame ahead of their contents for an Ed25519 key, and neither does for RSA. pkg records the signer per member and keeps the last one it read, so an unframed `.pub` behind a framed `.sig` resets the choice to RSA and hands an Ed25519 key to the OpenSSL verifier; the client then reports `error reading public key` and never names the member that caused it. The frame is not part of the key, and a client strips it before hashing, so the fingerprint is taken over the bare key either way.

The construction follows the key rather than the caller, and it is two hashes deep in both cases. pkg digests the catalogue to SHA-256 and renders that as 64 lowercase hex characters; an RSA key then signs the SHA-256 of those characters with PKCS#1 v1.5 and the SHA-256 DigestInfo, and an Ed25519 key signs the characters themselves. Pairing a key with the wrong construction produces a signature the client rejects without saying why, so the pairing is not a knob.

**These archives are read by `signature_type: fingerprints`, and by nothing else.** The client reads the `.pub` member out of the archive, checks its SHA-256 against a trusted fingerprint file, and verifies the signature with that key. `pubkey` is a different archive layout — pkg looks for one member literally named `signature` and reads the public key off the local filesystem instead — and it finds no such member here, so a client configured that way fails `pkg update` however good the key is. Install the fingerprint file:

```bash
bodega freebsd key export --fingerprint \
  > /usr/local/etc/pkg/fingerprints/bodega/trusted/bodega
```

Publish that fingerprint out of band — a configuration-management repository, an image build, a USB stick. A client's first fetch of a public key is authenticated by TLS alone, and the fingerprint is what turns that into a check somebody can actually make. `bodega freebsd key export` prints the public key itself, which is for inspecting or delivering the key rather than for any client setting.

#### Key management

The vocabulary is `bodega apt key`'s, deliberately: two commands managing keys two different ways is one more thing to get wrong at 03:00.

```bash
bodega freebsd key generate            # RSA-4096 by default
bodega freebsd key generate --eddsa    # Ed25519; needs pkg 1.20 or later, where pkg's ecc signer arrived
bodega freebsd key show                # algorithm, fingerprint, and the file it was read from
bodega freebsd key export              # the public key, in the form its signer reads
```

`export` emits the key as the archive carries it: a PEM `SubjectPublicKeyInfo` for RSA, and pkg's own DER structure for Ed25519, which is what libecc parses and what `pkg key --public` writes. There is no PEM form of an Ed25519 pkg key for the same reason there is no OpenSSL verifier for one.

The server only ever loads a key — it searches `$CREDENTIALS_DIRECTORY`, then `/etc/bodega/pkg-signing.key`, then `<storage_path>/pkg-signing.key` — and refuses one readable beyond its owner. A server that could create its own key would be a server that could mint one after being compromised.

There is no `--rotate`, and that is a difference in the format rather than a missing feature. An apt `InRelease` carries as many signatures as you like, so a rotation window signs with both keys at once; a pkg archive carries exactly one `.sig` and one `.pub`. A pkg rotation happens on the client, which trusts two fingerprint files for as long as the window is open: install the new fingerprint everywhere first, then replace the key and reload bodega.

#### What generation reads, and what it costs

The catalogue is built from the objects stored under the repository, one record per `.pkg`. Each record is that package's own `+COMPACT_MANIFEST` — the same JSON `pkg repo` reads — with four fields added that only the repository knows: `repopath` and `path` from the key the object is stored under, `sum` from a SHA-256 of the whole archive, and `pkgsize` from its length. Copying the manifest through rather than re-deriving it is what keeps a field pkg reads and bodega has never heard of from being dropped on the way.

`repopath` comes from the key and from nothing else, because that is what bodega's serving path reads to find an object. A catalogue whose `repopath` disagreed with the key would resolve an install and then 404, after `pkg update` had already reported success.

Building reads every package in the repository, so the result is held until the object set changes or `metadata_ttl` expires, whichever comes first. A package that cannot be read fails the whole build with the object named, rather than being left out of the catalogue: a package silently missing answers `pkg install` with the message a typo produces, and nothing anywhere would name the file.

The ordering rule the mirror spends most of its design on does not apply here. A generated catalogue is derived from the objects rather than fetched alongside them, so it can only name bytes the store already holds.

### Serving the FreeBSD ports tree

A FreeBSD host gets its ports tree in one of two ways, and bodega serves both with types it already has. There is no `ports` type.

| Source      | How a host gets it                                                               | bodega serves it through                | Updates by                                     |
| ----------- | -------------------------------------------------------------------------------- | --------------------------------------- | ---------------------------------------------- |
| `ports.txz` | `bsdinstall` extracts it from the release distribution set                       | a `binary` entry                        | a newer tarball, or converting the tree to git |
| git         | `git clone https://git.FreeBSD.org/ports.git /usr/ports`, as the Handbook prints | a `git_upstreams` namespace, smart-HTTP | `git pull`                                     |

Find out which one a host has before telling it how to update: `test -d /usr/ports/.git`. A host installed from the boot media with the ports component selected has the tarball, and that is the common case rather than the exception.

portsnap was the third way. It was removed in FreeBSD 14.0 and its servers went away at the end of 13, and bodega does not serve it.

#### The tarball

`ports.txz` is a plain file, so it is one `binary` entry. Take the digest from the release's own `MANIFEST`, which publishes a SHA-256 for every distribution set:

```bash
fetch -qo - https://download.freebsd.org/releases/amd64/amd64/15.1-RELEASE/MANIFEST | grep '^ports.txz'
```

```json
{
  "config_version": 1,
  "name": "freebsd-ports",
  "type": "binary",
  "description": "FreeBSD ports tree, the release distribution set",
  "versions": [
    {
      "version": "15.1-RELEASE",
      "url": "https://download.freebsd.org/releases/amd64/amd64/15.1-RELEASE/ports.txz",
      "filename": "ports.txz",
      "sha256": "0429c42e496576596bad6826308c9e876b3e0e7bb98fb0d55966f827601c20c5"
    }
  ]
}
```

```bash
bodega pkg import freebsd-ports.json
bodega build upload binary freebsd-ports
```

One entry serves every architecture. The tree is architecture-independent, and `amd64/amd64` and `arm64/aarch64` publish the same digest for 15.1-RELEASE: the per-architecture path repeats the file in the URL layout, not in the bytes. Add a version per release you serve.

On the client, fetch it and extract at `/`, because the members are rooted at `usr/ports/`:

```bash
fetch -o /tmp/ports.txz https://bodega-host:8080/binaries/freebsd-ports/15.1-RELEASE/ports.txz
sha256 /tmp/ports.txz        # compare against the entry's sha256
tar -xf /tmp/ports.txz -C /
```

The 15.1-RELEASE file is 64,419,752 bytes. Extracted, it is about 530 MB of content across 215,208 files and directories (the third column of its `MANIFEST` line), so what it takes on disk depends on the filesystem's block size: 1.3 GB on the ext4 test guest.

#### Updating a tarball tree

**A tarball tree has no `.git`, and `git pull` inside it fails** with an error that names neither cause:

```text
fatal: not a git repository (or any of the parent directories): .git
```

The tree is pinned to the ports snapshot its release shipped, and nothing in it knows where it came from. There are two ways forward:

- **A newer tarball.** Add the next release's `ports.txz` as a new version and extract it into an empty `/usr/ports`. Extracting over the old tree leaves every port the new one removed in place, and `make` will build them.
- **Converting to git.** Move the tree aside and clone into the empty path, as below. `git clone` refuses a directory that is not empty (`fatal: destination path '/usr/ports' already exists and is not an empty directory.`), so a clone over the tarball tree fails rather than merging. `DISTDIR` defaults to `/usr/ports/distfiles`, so move that back afterwards if the host has fetched anything.

```bash
mv /usr/ports /usr/ports.txz-tree
git clone --depth 1 --branch 2026Q3 https://bodega-host:8080/git/freebsd/freebsd-ports.git /usr/ports
mv /usr/ports.txz-tree/distfiles /usr/ports/ 2>/dev/null
```

#### The git tree

Map a namespace onto FreeBSD's GitHub mirror in `config.json`, not onto `git.FreeBSD.org`:

```json
"git_upstreams": {
  "freebsd": { "url": "https://github.com/freebsd/", "mode": "open" }
}
```

The two carry the same commits under the same branch names; `git ls-remote` against both returned identical heads for `main` and `2026Q3`. What differs is whether a full clone completes. bodega's mirror is `git clone --mirror`, which asks for the whole history, and `git.FreeBSD.org` answered that with `HTTP 504` after five minutes, twice, from two different networks, before sending any pack data:

```text
error: RPC failed; HTTP 504 curl 22 The requested URL returned error: 504
fatal: expected 'packfile'
```

The same clone from `github.com/freebsd/freebsd-ports` finished in 6m30s at 3.2 GB. A depth-1 clone straight from `git.FreeBSD.org` completed in 1m07s on the same guest, so the Handbook's own command does not meet this; only the full-history request did. The route composes the upstream as `url` plus the path after the namespace, so the clone URL is `/git/freebsd/freebsd-ports.git`.

In `catalog` mode, which is the default, the repository also needs a manifest entry named `freebsd/freebsd-ports`, and until it has one every request answers 404. Discovery writes that entry from a refused request, but only a request that arrives while `discover_mode` is `"observe"`: with discovery off, which is the default, the 404 records nothing and there is nothing to promote. Set it in `config.json` and restart bodega before the refused request, not after.

`discover promote` takes the discovery pattern, not the manifest name. A `git_upstreams` row is filed under the upstream host and the first segment of its path, `github.com/freebsd/` here, while the entry it writes is named for the request path, `freebsd/freebsd-ports`. Passing the manifest name fails with `no no_manifest observations for git "freebsd/freebsd-ports"`. The pattern covers every repository clients asked for under it, so read `discover show` first; anything else listed there is admitted by the same promote.

```bash
# discover_mode is "observe" and bodega has been restarted
git ls-remote https://bodega-host:8080/git/freebsd/freebsd-ports.git   # 404, records a no_manifest row
bodega discover list git                                               # PATTERN github.com/freebsd/
bodega discover show git github.com/freebsd/
bodega discover promote git github.com/freebsd/ --as manifest          # + git freebsd/freebsd-ports@any
```

The running server picks up the entry without a reload, so the next request starts the mirror clone; see **Prime the mirror** below for what that request sees.

```bash
git clone --depth 1 --branch 2026Q3 https://bodega-host:8080/git/freebsd/freebsd-ports.git /usr/ports
```

**Every branch is served, and `--branch` selects one.** The mirror carries every ref upstream has, so the quarterly branches (`2026Q3` and its siblings) are served beside `main`. A host tracking the release its packages came from wants the quarterly branch matching its `pkg` repository's `quarterly` URL; `main` is what `latest` packages are built from. Without `--branch` the clone takes upstream's `HEAD`, which is `main`.

**`--depth 1` works through smart-HTTP.** `git-upload-pack` makes the shallow cut against bodega's full mirror, so the client receives one commit whatever sits behind it: 131 MB of `.git` in 16 seconds on the test guests, against 2.9 GB in 7m33s for a full clone of the same repository through the same bodega.

**A full clone has five minutes to transfer.** `git-http-backend` runs under a five-minute bound and the server's write timeout is the same five minutes, so the pack has to reach the client inside that window. The full ports history is 2.9 GB, which needs about 10 MB/s sustained. On the test guests' LAN it arrived in time; shaped to 40 Mbit/s, the same clone was cut off at exactly 5m00s:

```text
error: RPC failed; curl 18 transfer closed with outstanding read data remaining
fatal: early EOF
fatal: fetch-pack: invalid index-pack output
```

Use `--depth 1` on anything slower than that. The error names neither bodega nor a timeout.

**`--depth 1` does not work against a bundle.** A `git` manifest entry with `"source": "clone"` produces a `.bundle` on the [legacy bundle route](#legacy-bundle-route), and `git clone --depth 1` against a bundle ignores the depth with no warning and exit status 0: the client receives the ref's full history. A bundle also carries one ref, so each quarterly branch would be its own entry and its own rebuild. Serve ports through `git_upstreams`, not through a bundle.

**Prime the mirror before pointing hosts at it.** bodega clones upstream on the first request for the repository, bounded at 15 minutes. The clone runs detached from the request, but the request waits on it, and the ports mirror takes longer than the five-minute write timeout: when the clone finished, the waiting client got `curl: (52) Empty reply from server` rather than refs. The mirror is complete by then, and the next request is served from it. Trigger it yourself so no host is the one that waits:

```bash
curl -sS -o /dev/null --max-time 1000 'https://bodega-host:8080/git/freebsd/freebsd-ports.git/info/refs?service=git-upload-pack'
```

That curl ending in an empty reply is expected on a first run. `{storage_path}/git/freebsd/freebsd-ports.git/.bodega-fetched` appears when the mirror is complete.

#### Updating a git tree

```bash
git -C /usr/ports pull
```

A shallow clone stays shallow across `pull`. Moving to the next quarterly branch on a shallow, single-branch clone needs the branch added to what the clone fetches:

```bash
git -C /usr/ports remote set-branches --add origin 2026Q4
git -C /usr/ports fetch --depth 1 origin 2026Q4
git -C /usr/ports switch 2026Q4
```

bodega refreshes its mirror from upstream at most once per `metadata_ttl` (default `1h`), and only when a client asks, so a `pull` can trail upstream by up to that interval. See [Refresh](#refresh).

#### Distfiles

The tree is half of a build. `make fetch` reaches the sites each port's `Makefile` names, and a ports tree from bodega does nothing to stop that. bodega does not mirror distfiles: a host building ports with no route to the internet has the recipes and none of the sources.

### APT index generation

`dists/<suite>/Release` and the `Packages` bodies under it are generated together into one snapshot and served from memory until the next rebuild. Nothing is written to storage: the only stored part of the apt repository is `pool/`.

They are generated together because `Release` records the SHA256 and byte length of each `Packages` body, and apt fetches the two in separate requests. Regenerating per request lets a write land between them, and the client rejects the result as `Hash Sum mismatch`.

A rebuild happens on:

| Trigger                              | Notes                                                                                                                                                                                                                             |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Server start                         | Before the listener binds, so no request ever sees an empty index                                                                                                                                                                 |
| `SIGHUP`                             | After the manifest reload and the signing-key reload. Sent by every CLI verb that changes what is served, from one hook on the root command rather than from each verb's own code. The same signal re-reads the CIDR access lists |
| A mutation-API write to an apt entry | `POST`, `DELETE`, and the hide and freeze toggles                                                                                                                                                                                 |
| A ticker                             | Hourly once an index exists; 15s, 30s, 60s and on up to hourly until one does                                                                                                                                                     |

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

```text
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

bodega has no ACME client. `tls_autocert` and `tls_domain` were config keys that nothing implemented, and they are gone. Both halves say so rather than disappearing: a file that still carries either key logs at startup that nothing reads it, and `--tls-autocert`/`--tls-domain` still parse — hidden and deprecated, off `--help` — so an upgraded unit file starts and gets the same message instead of `unknown flag: --tls-autocert` and exit 1 on every `Restart=always` cycle. Get a certificate from `certbot` or your CA, or terminate TLS at a proxy in front and set `public_url`.

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

Leave the proxy cache off for `/pypi/`, `/npm/`, `/go/`, `/cargo/`, `/helm/`, `/git/`, `/binaries/` and `/apt/`, or let it obey the headers bodega sends and nothing more.

A profile decides what those routes return, so one URL answers two hosts with two documents. A shared cache cannot evaluate a profile: it stores the first answer and hands it to the next host, with no denial row written and no error anywhere. bodega closes this from its side — artifacts go out `private`, indexes go out `no-cache, no-store, must-revalidate` — but a proxy configured to cache past the response headers reopens it. In nginx that means not setting `proxy_ignore_headers Cache-Control` and not forcing `proxy_cache_valid` on these locations.

`/apt/` used to be the exception and no longer is. The `dists/` tree has always shipped `no-cache, no-store, must-revalidate`, and the pool now ships `public, max-age=31536000, immutable` only while the requesting host's profile does not scope apt; a host whose profile does gets `private`. The bytes are the same for everyone — a filtered index decides what a host is told exists, not what it receives — but a cached `public` copy would answer a refused host out of a permitted host's fetch, and the request would never reach the predicate that refuses it.

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

| Method | Path                                       | Description                                                                                                                                                                             |
| ------ | ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/api/v1/packages`                         | All entries across all types                                                                                                                                                            |
| GET    | `/api/v1/packages/{type}`                  | Entries for one type                                                                                                                                                                    |
| GET    | `/api/v1/packages/{type}/{name}`           | Single entry details                                                                                                                                                                    |
| GET    | `/api/v1/packages/{type}/{name}/{version}` | One version, as a manifest scoped to it. Carries the `vetting.osv.*` keys on `metadata`                                                                                                 |
| GET    | `/api/v1/status`                           | Health check with entry counts, one storage probe row per backend, and the apt client state                                                                                             |
| GET    | `/api/v1/config`                           | Non-sensitive config (bucket, region, manifest_dir)                                                                                                                                     |
| GET    | `/api/v1/audit`                            | Query audit events (supports filters)                                                                                                                                                   |
| GET    | `/api/v1/profiles/{name}/pins`             | One profile's pins, with their reason, review date and OSV state. `?stale=true` narrows to the overdue ones. Admin-gated. See [Pins as recorded decisions](#pins-as-recorded-decisions) |
| GET    | `/healthz`                                 | Health probe (returns `ok`)                                                                                                                                                             |

#### `version` on `/api/v1/status`

`version` is the build stamp of the running server, the same string `bodega --version` prints first: `git describe --tags --always --dirty` of the tree it was built from, or `dev` for a binary built without the Makefile's flags.

```json
"version": "07c79c3"
```

It is present only for a caller inside `admin_permit_cidr` (see `bodega acl`), and every other caller gets the response without the key. A package repository answers a whole fleet, so its build number is a public statement of which advisories apply to it; the gate is the one `spool.dir` sits behind. An empty `admin_permit_cidr` permits nobody, so on such a server no caller sees `version` at all. Behind a reverse proxy the address tested is the one resolved through `trusted_proxies`: a forwarded header from a proxy outside that list is not believed, and the address tested is the proxy's own.

An absent `version` therefore means one of two things, and the response cannot tell you which: the caller is outside `admin_permit_cidr`, or the server predates the field. Run `bodega --version` on the server host rather than reading the absence as either one.

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
      "components": "main",
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
- `mirrored` names the codenames proxied from an upstream archive rather than generated here, and it is what separates the two. Upstream's signature authenticates a mirrored codename, so `signed` says nothing about it and the `sources` block beside it renders differently.
- `filtered` names the codenames generated from a profile's view of a mirrored codename. A client treats them as generated suites (bodega's key signs them and `Signed-By:` goes on the line); they are separate from `suites` because no `apt_suites` entry produced them.
- `host` is the one stanza the host that asked should install, so a client installs it rather than picking a block out of `sources`. `profile` names the profile that scoped apt for that host, and is absent when none does — an instance serving a single codename answers `host` for every caller, profile or not. Both are absent when the answer is the operator's: no profile scopes apt and this instance serves more than one codename, and a guess there points a host at the wrong suite with nothing reporting it. `bodega doctor --write-apt-sources --suite <codename>` is the operator giving that answer, and it installs the block `sources` carries for that codename.
- `public_url` is the configured value when there is one. With none set it is the origin of the request that asked, resolved through `X-Forwarded-Proto` when the peer is trusted.
- `notes` are the consequences of the form above them: the permanence of `[trusted=yes]`, or the fact that the first keyring fetch is authenticated by TLS alone.

### Mutation endpoints

| Method | Path                                              | Description                                                  |
| ------ | ------------------------------------------------- | ------------------------------------------------------------ |
| POST   | `/api/v1/packages/{type}`                         | Create a new entry (JSON body)                               |
| POST   | `/api/v1/packages/import[?merge=true]`            | Import many entries across types (JSON array or NDJSON body) |
| DELETE | `/api/v1/packages/{type}/{name}`                  | Delete an entry                                              |
| PATCH  | `/api/v1/packages/{type}/{name}/hide`             | Toggle hidden (all versions)                                 |
| PATCH  | `/api/v1/packages/{type}/{name}/hide/{version}`   | Toggle hidden (specific version)                             |
| PATCH  | `/api/v1/packages/{type}/{name}/freeze`           | Toggle frozen (all versions)                                 |
| PATCH  | `/api/v1/packages/{type}/{name}/freeze/{version}` | Toggle frozen (specific version)                             |

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
    { "type": "apt", "name": "curl", "outcome": "imported" },
    {
      "type": "apt",
      "name": "bash",
      "outcome": "conflict",
      "reason": "package already exists (retry with merge=true to add versions)"
    },
    {
      "type": "apt",
      "name": "blank",
      "outcome": "invalid",
      "reason": "apt/blank has a version entry with no version; give one, or \"*\" to resolve the current upstream"
    }
  ]
}
```

`outcome` is one of `imported`, `merged`, `conflict`, `invalid`, `policy_blocked` or `failed`. Every manifest passes the same allow-list, age and OSV checks as `bodega pkg import` and `POST /api/v1/packages/{type}`.

### Token endpoints

| Method | Path                  | Description                                                |
| ------ | --------------------- | ---------------------------------------------------------- |
| GET    | `/api/v1/tokens`      | List all tokens                                            |
| POST   | `/api/v1/tokens`      | Create a new token (JSON body: `{label, expiry, comment}`) |
| DELETE | `/api/v1/tokens/{id}` | Revoke a token                                             |

### Policy endpoints

| Method | Path                           | Description                                                    |
| ------ | ------------------------------ | -------------------------------------------------------------- |
| GET    | `/api/v1/policies[?type=TYPE]` | List allow-list rules (optionally scoped to one registry type) |
| POST   | `/api/v1/policies`             | Add a rule (JSON body: `{registry_type, pattern, comment}`)    |
| DELETE | `/api/v1/policies/{id}`        | Remove a rule by ID                                            |

Policy mutations invalidate the in-memory cache, so changes take effect on the next request without a restart.

Mutation endpoints and the four admin reads (`/api/v1/audit`, `/api/v1/tokens`, `/api/v1/policies`, `/api/v1/config`) are restricted by `admin_permit_cidr`, which defaults to localhost only (`127.0.0.0/8`, `::1/128`). Requests from IPs outside the permit list get a 403, and an empty list permits nobody.

That list lives in the audit database and is read per request, so `bodega acl admin add|remove` takes effect on a running server without a restart. `config.json` seeds it on first start and is ignored afterwards; see **Configuration**.

The address compared against that list is the one `trusted_proxies` resolved, not the TCP peer. Behind a proxy the two differ by design; on a shared private network with the default trusted set they differ because a stranger said so.

When `admin_permit_cidr` includes non-localhost addresses, a Bearer token is also required. Generate tokens with `bodega token generate` and pass them in the `Authorization` header. Widening the list is what turns that requirement on, which is why `bodega acl admin add` refuses to widen past localhost while no token exists.

**Create example (from localhost):**

```bash
curl -X POST http://localhost:8080/api/v1/packages/gomod \
  -H 'Content-Type: application/json' \
  -d '{"name": "example.com/example-corp/widget-sdk", "version": "v1.30.0"}'
```

**Create example (from a remote host):**

```bash
curl -X POST https://bodega-host:8080/api/v1/packages/gomod \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer bodega_ak_7f3a...' \
  -d '{"name": "example.com/example-corp/widget-sdk", "version": "v1.30.0"}'
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

Enforcement happens in four places:

- **Server proxy** (`bodega serve`) — cache-miss fetches check policy before leaving the box. Blocked fetches return 403.
- **Builder** — each fetch stage validates entries before any network I/O, on every surface that runs one: `bodega build fetch`, `bodega build run`, `bodega build package`, `bodega build upload`, and the interactive `bodega shell`. A refusal prints against the entry and lands in the shell's log pane like any other stage output. `bodega build sync` and `bodega repair` reach no fetcher and check nothing.
- **Create API + import** (`POST /api/v1/packages/...`, `bodega pkg import`) — manifests referencing blocked upstreams are rejected at creation time. Fail early, not at first fetch.
- **Interactive create** (`bodega pkg create`) — warns the operator and asks y/N to proceed. The only path that allows override, and the override writes a `policy_override` audit event.

Every mutation (`policy add`, `policy remove`) and every violation (fetch, import, server) writes an event to the audit trail with `pkg_type="policy"` or `status="policy_violation"`.

```bash
# Turn on enforcement for git by pinning allowed orgs
bodega policy add git example.com/example-corp/
bodega policy add git example.com/example-corp/

# Scope pypi to a curated list
bodega policy add pypi django
bodega policy add pypi requests

# Audit existing manifests for any violations
bodega policy check
```

Enforcement needs the audit database, which is where the rules live. An install that configures no `audit_db` has no allow-list to apply, and every upstream is permitted. That state is announced rather than assumed: each run that reaches a fetch without one prints a single line before the first entry, on the same output the fetch reports to.

```text
  policy: no upstream allow-list loaded, so every upstream is permitted. Set audit_db and add rules with `bodega policy add` to enforce one.
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

| Resource  | TTL            | Examples                                    |
| --------- | -------------- | ------------------------------------------- |
| Immutable | Forever        | `.zip`, `.mod`, `.info`, `.tgz` (versioned) |
| Mutable   | `metadata_ttl` | `@v/list`, `index.yaml`, packument          |

Configure the TTL:

```json
{ "metadata_ttl": "1h" }
```

**A name no manifest holds still proxies.** `gomod`, `npm` and `cargo` answer a package with no entry from upstream and cache what they get, which is what makes a clean host able to bootstrap through bodega. For `gomod` that covers the whole module protocol — `@v/list`, `.info`, `.mod` and `.zip` — because `go get` reads all four and a listing served alone fails the resolution one step later. For `npm` it covers the packument and the tarball together, for the same reason at one remove: the proxied packument has every `dist.tarball` rewritten onto this server's own `/npm/{pkg}/-/{tarball}`, so a tarball route that refused what the packument published would fail `npm install` on a URL bodega itself named.

**`pypi` wheels and `helm` charts stay catalog-only, for different reasons.** A wheel URL is read out of the simple index rather than composed from a filename, and nothing publishes one for a distribution no entry names: `/pypi/simple/{dist}/` republishes the upstream index for a `proxy`-mode distribution only and lists stored wheels otherwise. Opening the wheel route would pay a simple-index fetch per request for addresses only a guess produces. A chart repository URL is recorded per version entry rather than in config, so an uncatalogued chart names no host to reach at all, and composing one from the chart name is the guess [`pkg import`](#bodega-pkg-import-file-file) already refuses. Both routes answer the missing entry rather than a bare 404: the response names the distribution or chart, what bodega would have needed to fetch it, and the `bodega pkg create` line that supplies it. A `no_manifest` discovery row is written either way, as before.

Which upstreams may be reached at all is the allow-list's decision, not this switch's: with rules configured for a type, a candidate that matches none is refused with a `cache` row at `status=policy_violation`. See [Supply Chain Management](#supply-chain-management).

### Upstream hosts

Five flat keys name the registries a proxying instance fetches from. They are not interchangeable, and two ecosystems need two keys each because the registry that answers "which versions exist" is not the one that serves the bytes.

| Key                 | Default                           | What that host serves                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ------------------- | --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `gomod_upstream`    | `https://proxy.golang.org`        | The whole module proxy protocol: `@v/list`, `@v/{version}.info`, `.mod` and `.zip`, all on one host                                                                                                                                                                                                                                                                                                                                                                                      |
| `npm_upstream`      | `https://registry.npmjs.org`      | Packuments and tarballs, both on one host                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `pypi_upstream`     | `https://pypi.org`                | The PEP 503 index root. bodega reads `/simple/{dist}/` under it and fetches the artifact URL that page lists, which is on `files.pythonhosted.org` under a content-hash path. A wheel URL cannot be composed from a filename, so a request for a file the index does not list is a 404 naming the index that was read. What bodega serves at its own `/pypi/simple/{dist}/` is that document republished, not relayed: see [Republishing a proxied index](#republishing-a-proxied-index) |
| `cargo_upstream`    | `https://index.crates.io`         | The sparse index, and nothing else. A crate tarball request to this host is a 404                                                                                                                                                                                                                                                                                                                                                                                                        |
| `cargo_dl_upstream` | `https://static.crates.io/crates` | Crate tarballs. bodega appends `/{crate}/{version}/download`                                                                                                                                                                                                                                                                                                                                                                                                                             |

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

- First `bodega build fetch`: computes SHA-256, stores it on the manifest entry and pins it in the audit DB under the artifact's object key
- Subsequent fetches: verifies against both; fails the entry on mismatch, naming the pinned digest and the fetched one

**Proxy path** (cached entries):

- First proxy fetch: computes SHA-256, stores in audit DB under the artifact's type, name and version, all three read back out of the object key
- Subsequent proxy fetches: verifies against stored; returns **502 Bad Gateway** on mismatch

Both paths write the same row, keyed by the object key, so a version pinned by the pipeline is the one the proxy enforces on serve and `bodega pkg checksum list` shows. Neither path overwrites a digest already on record: a disagreement is refused, not stored. The row's `SOURCE` column says which wrote it — `computed` for the proxy, `manifest` for the pipeline — and under the apt prefix that word is the only thing separating a `.deb` mirrored from an archive from one bodega built, so an index that publishes under bodega's own signature reads it.

Two artifacts have no per-version object key to pin against. **pypi** wheels upload as a directory holding a resolved dependency closure rather than one object per version. **Clone-mode git** ships a bundle generated locally at package time, so there are no upstream bytes to attest to and `git bundle create` is not reproducible byte-for-byte; a git entry fetched as a release tarball pins normally. Neither is an error: the fetch records the digest on the manifest entry and skips the cache row.

When an upstream republishes different bytes under a version it already served, every subsequent fetch answers 502 with `checksum verification failed — upstream content may be tampered`. Clearing the stored digest is the way out, and it is why the row carries package identity: `clear` matches by type and name, and rows recorded without them could only be reached by editing the database. A row with no digest reads as one never fetched, so the next fetch stores what it computed rather than answering 502 forever. Stores mirrored before this release have their identity re-derived from their object key once, on the first open after upgrade; the log line names the row count.

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

| `audit_sink` | For                                                            | `audit_sink_dsn`                                                | Queryable |
| ------------ | -------------------------------------------------------------- | --------------------------------------------------------------- | --------- |
| `sqlite`     | One host. The default, and no new dependency                   | not accepted                                                    | yes       |
| `postgres`   | A fleet writing at once, and reporting across instances        | libpq connection string                                         | yes       |
| `syslog`     | Shipping into a SIEM you already run                           | `tcp://`, `udp://`, `unix://` address; empty = the local daemon | no        |
| `jsonl`      | A file another collector tails; no daemon, no schema migration | absolute path                                                   | no        |

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

| Condition                                     | `bodega serve`                                                    | CLI                                                                                    |
| --------------------------------------------- | ----------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `postgres` will not connect (5s ping timeout) | refuses to start, naming `audit_db` and `audit_sink`              | read commands exit non-zero; a one-shot write warns on stderr and continues            |
| syslog socket is gone at startup              | refuses to start                                                  | same                                                                                   |
| jsonl path is unwritable                      | refuses to start                                                  | same                                                                                   |
| `audit_db` file exists but is not writable    | refuses to start                                                  | read commands keep working; this is the documented non-root `bodega audit events` path |
| `audit_db` is unset                           | starts with no audit trail, token auth and policy enforcement off | unchanged                                                                              |

An unset `audit_db` is an install that asked for no audit trail, so it is not a failure. Everything else is: an audit store that fails open silently is what this design exists to prevent. The parent directory of `audit_db` (and of a `jsonl` path) is created on first use, so a fresh install is not a startup failure.

A destination that goes away **after** startup does not stop the server. The write error is logged at `Error`, which the shipped default `log_level` prints, and bodega keeps serving packages: killing a package proxy because syslog restarted is the worse outcome.

### Choosing a sink

Measured on an Apple M1 Ultra (Mac13,2), macOS 26.7, internal NVMe over Apple Fabric, APFS; `postgres:17-alpine` in Docker Desktop on the same host over loopback. 64 concurrent writers, 10 s per run, at a fixed offered request rate. Each request takes the post-B16 path: one event row on the hot path plus one discovery observation through the recorder's queue.

| Offered | Sink       | Events/s landed | Discovery dropped | Hot-path write p99 |
| ------- | ---------- | --------------- | ----------------- | ------------------ |
| 500/s   | `sqlite`   | 803             | 0%                | 1.27 s             |
|         | `postgres` | 989             | 0%                | 24 ms              |
|         | `syslog`   | 1,000           | 0%                | 3.1 ms             |
|         | `jsonl`    | 1,000           | 0%                | 2.2 ms             |
| 1,000/s | `sqlite`   | 1,772           | 0%                | 951 ms             |
|         | `postgres` | 1,997           | 0%                | 17 ms              |
|         | `syslog`   | 1,998           | 0%                | 3.4 ms             |
|         | `jsonl`    | 1,999           | 0%                | 2.0 ms             |
| 2,000/s | `sqlite`   | 3,608           | 0%                | 638 ms             |
|         | `postgres` | 3,993           | 0%                | 15 ms              |
|         | `syslog`   | 3,998           | 0%                | 3.2 ms             |
|         | `jsonl`    | 3,997           | 0%                | 2.6 ms             |
| 8,000/s | `sqlite`   | 8,941           | 64.4%             | 180 ms             |
|         | `postgres` | 15,979          | 0%                | 15 ms              |
|         | `syslog`   | 15,990          | 0%                | 3.0 ms             |
|         | `jsonl`    | 15,992          | 0%                | 2.6 ms             |

Unthrottled, the same harness sustains 8,639 hot-path writes/s on `sqlite` (7 of 92,267 lost to the 5 s busy timeout, p99 57 ms), 11,720/s on `postgres` (none lost, p99 21 ms), 132,055/s on `syslog` and 199,655/s on `jsonl`.

Convert a fleet to a request rate with `hosts x updates-per-hour x requests-per-update / 3600`. A thousand hosts running `apt update` twice an hour over a dozen index paths is about 7 requests/s; a CI fleet installing packages per build is one to two orders of magnitude above that.

- **Up to ~2,000 requests/s: `sqlite`.** Nothing drops, and the store you already have needs no daemon. Its hot-path p99 is the worst of the four even at 500 requests/s (over a second, because the request goroutine waits on the write lock the discovery batch holds), but that latency is off the response path.
- **Above ~2,000 requests/s, or more than one bodega: `postgres`.** It dropped no observations at any rate measured here and lost no hot-path write to a timeout, and its p99 stays under 25 ms across the whole range. It is also the only way to report across instances: each host keeps its own `audit_db` for ACLs and tokens, and their events land in one place.
- **When the SIEM already exists, at any rate: `syslog` or `jsonl`.** Neither dropped a row at any rate measured, and both have the cheapest hot-path latency of the four. You are trading `bodega discover promote` and `GET /api/v1/audit` for that; if you need them back, run one instance on `postgres`.

**What `sqlite` drops at 8,000 requests/s is the write lock, not the drain.** `DiscoveryRecorder` accumulates up to 128 observations or 50 ms, whichever comes first, and writes the batch as one statement. Serially it was one write latency per row, which held the drain to about 2,700 rows/s on `sqlite` and about 900/s on `postgres` (each upsert there costs a network round trip) however wide the pool underneath was, and made `postgres` drop more observations than `sqlite` at 2,000 requests/s while absorbing 40% more hot-path writes. Batched, `postgres` drains 11,700 rows/s and takes everything offered at 8,000 requests/s. `sqlite` takes everything up to 2,000 and drops 64% at 8,000, because its batch contends with 64 request goroutines for the one write lock, which is a property of the store rather than of how the queue is drained.

**Event types:**

| Type                                                              | Trigger                                                                                                                    |
| ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `serve_fetch`                                                     | Client downloaded a package over HTTP                                                                                      |
| `fetch`, `build`, `package`, `upload`, `sync`                     | Build pipeline stage completed for an entry                                                                                |
| `create`, `delete`, `hide`, `freeze`, `edit`, `refresh`, `repair` | Manifest mutation (CLI, TUI or API)                                                                                        |
| `init`, `reset`, `status`, `show`                                 | Operator command                                                                                                           |
| `cache`                                                           | Every proxy outcome: an artifact served from the cache, one fetched from upstream, and the two refusals decided on the way |
| `denied`                                                          | A request the server refused                                                                                               |
| `serve_start`, `serve_stop`                                       | `bodega serve` bound its listener / shut down                                                                              |

That table is the whole set. A type absent from a trail is a gap to chase rather than a type the server was never going to write: `cache` was defined and reachable only through its two refusals for several releases, so an install proxying npm and cargo all day recorded nothing saying which artifacts had come from upstream, and nothing in the trail read as missing.

**Cache outcomes.** A `cache` row's `status` names which of the four happened. The first two are written on the serving path, one per request, and carry the package type, name and version off the object key with the upstream that answered in `details`:

| Status              | Outcome                                                                                                                                                                                                     |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cache_miss`        | Fetched from upstream, verified and stored. `details` names the URL that answered, which is the last hop of any redirect chain rather than the address bodega composed                                      |
| `cache_hit`         | Served from storage with no upstream contact. A stale copy served because the upstream could not be reached, or because the spool refused the refetch, records this too: the request is what the row counts |
| `checksum_mismatch` | Upstream bytes disagreed with the digest pinned on first fetch. The artifact was neither served nor cached                                                                                                  |
| `policy_violation`  | The upstream allow-list refused the candidate. Written wherever the refusal is decided, including the apt pool probe, which refuses a `.deb` before there is a fetch to record                              |

One row per request on both serving outcomes, so counting `cache_miss` over a window sizes what an upstream actually served. Every response the cache answers is counted, including the apt pool shortcut that serves a cached `.deb` without resolving which archive it came from, and including a stale copy served during an outage. A request the spool refuses with nothing cached to fall back on writes its `denied` row and no `cache` row: nothing came from upstream and nothing was served, so a row either way would be wrong. Where a stale copy does answer, both rows are written — the `denied` row names the bound that fired, the `cache_hit` names the bytes the client got.

**Provenance on a hit.** `details` on a `cache_hit` names the upstream that supplied those bytes, recorded when they were fetched and read back from the store — not the candidate `gomod_upstream` or `apt_upstreams` points at now. The two diverge routinely: the pypi wheel route holds no URL on a hit at all, because composing one costs a read of the simple index that a hit exists to avoid, and a restart or a configuration edit leaves the fetched URL nowhere in memory. The lookup is local either way, so a hit still contacts nothing.

A recorded origin belongs to the bytes, not to the key they sit under. A fetch reads its cached object back before recording anything and records nothing unless those bytes hash to what it fetched, so an upload that landed at the key while the fetch was in flight takes the row with it rather than inheriting it. A hit then compares what the backend reports — the object's location, its length, and its entity tag or its timestamp — against the handle it is about to serve from, not against an earlier lookup. So an artifact replaced under a key it already occupied is not credited to the archive that supplied the previous tenant, whether it was replaced by `bodega pkg upload`, by a delete and a refill, or by a move to another bucket, and whether the replacement is the same length as what it displaced or not.

A response already in flight is unaffected by the replacement: it serves the object it opened, under that object's origin, and the next request serves the new one. That holds because every backend publishes rather than overwrites (see [Publication and access](#publication-and-access)), and it is what lets the row be written from the same open that supplies the body.

Provenance a fetch is still in the middle of publishing is answered from that fetch. Bytes become readable partway through the write to storage and the origin lands after it, and a client arriving in between gets the upstream of the fill it is reading rather than a blank — once the object it is serving is confirmed to be the one that fill fetched, which costs a read of it and happens only inside that window.

An object cached before bodega kept origins, filled by a path that fetches nothing, or written over since by one, carries `"upstream": ""` and `"upstream_origin": "unrecorded"` instead of a guess: a row naming a host that answered nothing reads as evidence and is not.

**Denials.** A `denied` row's `status` column names the gate that turned the request away, so an address that was never permitted reads differently from a token that simply aged out:

| Status                     | Gate                                                                                                                                                                                                                                                                                                               |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `deny_list`                | Client IP matched `deny_list`                                                                                                                                                                                                                                                                                      |
| `client_ip_unparsable`     | Mutation whose resolved client IP is not an address                                                                                                                                                                                                                                                                |
| `ip_not_permitted`         | Mutation from outside `admin_permit_cidr`                                                                                                                                                                                                                                                                          |
| `no_tokens_configured`     | Remote mutation while no API token exists                                                                                                                                                                                                                                                                          |
| `token_missing`            | Mutation with no Bearer credential                                                                                                                                                                                                                                                                                 |
| `token_invalid`            | Bearer presented, matched no stored hash                                                                                                                                                                                                                                                                           |
| `token_expired`            | Bearer matched a token past its `expires_at`                                                                                                                                                                                                                                                                       |
| `admin_only`               | Admin-gated read (`/api/v1/config`, `/api/v1/audit`, tokens, policies) from outside `admin_permit_cidr`                                                                                                                                                                                                            |
| `entry_frozen`             | `DELETE` on a package whose every version is frozen. The caller cleared the admin gate, which is what makes the attempt worth a row                                                                                                                                                                                |
| `version_constraint`       | A gomod or npm request for a version outside the entry's `version_constraint`. `pkg_version` carries the version that was refused, `details` the constraint and the entry's own version                                                                                                                            |
| `push_refused`             | A git smart-HTTP push against a read-only mirror, on the `info/refs?service=git-receive-pack` probe or the `git-receive-pack` POST. `pkg_name` is the namespace, `details` the repository path. The POST reaches this only from inside `admin_permit_cidr`; from anywhere else `ip_not_permitted` refuses it first |
| `spool_artifact_too_large` | A proxied artifact over `spool_max_artifact_bytes`. See [Large artifacts and the spool directory](#large-artifacts-and-the-spool-directory)                                                                                                                                                                        |
| `spool_budget_exhausted`   | A proxy fetch arriving while `spool_max_total_bytes` is already held by the fetches in flight. `details` carries the bytes held and the number of fetches holding them                                                                                                                                             |

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

  The body capture at `log_level: 4` carries the same secret by the other route. `POST /api/v1/tokens` returns the plaintext token in its response body, because that is the one moment it can be read, so the trace log wrote it down. Bodies now redact by JSON key the way headers redact by name: `token`, `access_token`, `refresh_token`, `secret`, `password`, `private_key`, `signing_key` and `session` log `[redacted]` in place of the value at any depth, and the rest of the document is untouched. The key travels with the value rather than with the route, so a later endpoint returning a signing key is covered without anyone remembering to extend a list. A body that claims JSON and does not parse is scrubbed against the same key set textually rather than withheld: `maxBodyCapture` truncates at 64KB and a handler can answer with a JSON content type over something that is not JSON, and both are cases trace level exists to show. The key is still present ahead of the value it names even on a document the capture cut short, so the scrub reaches the credential while the rest of the body stays readable.

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

```text
┌─ Sources ──────────┬─ Details ──────────────────┐
│ apt/               │ Name:    widget            │
│ git/               │ Ref:     v4.5.7            │
│   widget@v4.5.7    │ Source URL: https://git... │
│ pypi/              │ Frozen:  no                │
│ binary/            │ Stored:  yes (backend      │
│                    │          default)          │
│ gomod/             │                            │
│ helm/              │                            │
│ npm/               │                            │
│ cargo/             │                            │
│ freebsd/           │                            │
├─ Log ──────────────┴────────────────────────────┤
│ [gomod] example.com/example-corp/sdk: fetching...         │
│ [gomod] example.com/example-corp/sdk: checksum verified   │
└─────────────────────────────────────────────────┘
```

### Keybindings

| Key                    | Action                                              |
| ---------------------- | --------------------------------------------------- |
| `Tab`                  | Switch focus between Sources and Log pane           |
| `Up`/`Down` or `j`/`k` | Navigate                                            |
| `Enter`                | Expand/collapse group                               |
| `/`                    | Filter sources (Sources pane), find text (Log pane) |
| `?`                    | Show help                                           |
| `q`                    | Quit                                                |
| `C`                    | Open config editor                                  |
| `E`                    | Edit the selected entry as raw JSON                 |
| `L`                    | Query the audit log                                 |
| `T`                    | Open token manager                                  |

With the Log pane focused:

| Key       | Action                                                   |
| --------- | -------------------------------------------------------- |
| `/`       | Find text; the view jumps to the first match             |
| `f`       | Filter the pane to matching lines only                   |
| `n` / `N` | Next / previous match                                    |
| `Esc`     | Clear the query; a second press returns focus to Sources |

Both queries are case-insensitive substring matches, applied on every keystroke, and they match the text a line prints rather than the escape sequences that color it. The pane title carries the query and the match position, `/apt (2/17)` for a find and `filter:apt (17)` for a filter. `n` and `N` wrap at the ends. The current match is highlighted, which is also how you spot a query with no hits: the count reads `(0/0)` and nothing is marked.

The `?` help lays its sections into as many columns as the terminal is wide enough to hold, fewest first, because the full list is 55 rows and a popup cannot scroll. Sections are never split across a column break, and the reading order runs down a column then across. A terminal too narrow for two columns gets the single-column list back, taller than the screen.

### Config editor

Press `C` to open the config form. `Ctrl+S` saves, `Ctrl+T` loads defaults into the fields, `Ctrl+R` removes those fields' keys from the config file. Changes take effect immediately.

A save writes the keys you edited, plus any key whose value differs from what the running process resolved. Fields are prefilled with that resolved config — what is in force, flags and environment included — so pressing save without touching a field records nothing, and the log line says the file is unchanged rather than claiming a save. Editing a field pins its key even when you type back the value already shown: `bodega --manifest-dir /srv/m shell` prefills `/srv/m`, and retyping it is how you make it stick. The log line names the keys that reached the file.

`Ctrl+R` reaches the eleven fields on the form and nothing else. Every other key in the file survives it: `token`, `deny_list`, `admin_permit_cidr`, `audit_db`, `discover_mode`, `apt_codename`, the upstream keys and the TLS pair. Its log line names the keys it removed. Clearing an `admin_permit_cidr` you no longer want is `bodega acl admin`, not a reset.

The reset deletes those eleven keys rather than writing the built-in defaults into them, and the difference shows the moment a flag is in play. A save writes only what differs from the resolved config, so under `bodega --region us-west-2 shell`, where `us-west-2` is also the built-in default, assigning the default back is a difference of nothing: the file went on naming `us-east-1` and the log line said the fields were already at their defaults. An absent key already means "use the built-in default" everywhere else, it keeps meaning that if a later release changes what the default is, and it is the one form the diff cannot skip.

The form edits no ACL. `deny_list`, `admin_permit_cidr` and `trusted_proxies` are seeded from the config file on first start and inert afterwards, so a field writing them to `config.json` would accept a value, save it, report success and change nothing about who the server refuses. Edit them with `bodega acl deny`, `bodega acl admin` and `bodega acl proxies`; the form says so under its title.

### Details pane

Two fields report where an entry's bytes are. **Stored** answers whether the probe found the primary artifact and names the backend it looked on (`yes (backend default)`); **Object** prints that object's URI, prefixed with the backend's own label — `file://<storage_path>` for a local backend, `s3://<bucket>` for an s3 one. Both read the backend the manifest entry records, so a local-only install reports its own disk rather than a bucket it never configured. Neither field is derived from `bucket`: an install carrying a leftover `bucket` key alongside `"storage_backend": "local"` printed an `s3://` URI over bytes on its own disk through v1.

The last field of an entry is the client instruction, and its label names the format rather than assuming a URL: **Sources line** for apt, **Registry stanza** for cargo, **Package URL** for the other six. All three carry the base URL `public_url` and the TLS pair resolve to, so a pane behind a terminating proxy prints what a client outside it reaches.

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

The build menu dispatches every entry type. Only `apt` and `pypi` have a build step and only `apt`, `git`, `pypi` and `helm` have a package step; the rest say which stage does not apply to them rather than reporting an empty success. `helm` packages across the whole type — `index.yaml` is repository metadata, not a per-entry archive — so that stage ignores the selected entry and regenerates everything.

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

```text
manifests/
  apt/python3/manifest.json
  apt/python3/manifest.json.md5
  git/widget/manifest.json
  git/widget/manifest.json.md5
  ...
```

Every manifest write emits its `.md5` sidecar in the same operation, through one helper that all four writers (`SavePackage`, `SaveIndex`, `SaveGraph`, `SaveMetrics`) go through. Reads do not verify; `bodega pkg verify` is what compares a manifest against its sidecar, and `bodega --break-glass-update-md5 <type|all>` recomputes one after a deliberate manual edit.

---

## Storage Layout

The key layout is the same regardless of backend (local filesystem or S3). Every key is derived in one place, `manifest.ArtifactKeys` and its per-type helpers, which the uploader, every server handler, `bodega build status`, `bodega pkg move` and the delete path all resolve through.

A name containing a slash is encoded to `--` for every type **except gomod**, which keeps its slashes: a Go client requests `GET /<module>/@v/<version>.zip` with the module path verbatim, and nothing on the wire can rewrite it back. So `@example-corp/widget-cli` stores as `npm/@example-corp--widget-cli/@example-corp--widget-cli-1.5.0.tgz` while `example.com/example-corp/widget` stores as `gomod/example.com/example-corp/widget/@v/...`.

`freebsd` keeps everything literal as well, for a different reason: the key is the path the upstream repository serves the object at, so an ABI's colons and a hashed filename's `~` and `$` all survive into it. S3 accepts all three in a key and every POSIX filesystem accepts them in a path, and encoding them would buy nothing while costing a decoder at four call sites — where a wrong decode serves the wrong bytes under a signature that still verifies.

| Type      | S3 prefix       | Example key                                                                     |
| --------- | --------------- | ------------------------------------------------------------------------------- |
| apt       | `packages/apt/` | `packages/apt/pool/main/h/hello/hello_2.10-3build1_amd64.deb`                   |
| git       | `repos/`        | `repos/widget/widget-v4.5.7.bundle`                                             |
| pypi      | `pypi/wheels/`  | `pypi/wheels/examplesdk-1.35.0-py3-none-any.whl`                                |
| binary    | `binaries/`     | `binaries/example-tool-v2/2.34.24/example-tool-exe-linux-x86_64.zip`            |
| gomod     | `gomod/`        | `gomod/example.com/example-corp/sdk/@v/v1.30.0.zip`                             |
| helm      | `charts/`       | `charts/ingress-nginx-4.11.0.tgz`                                               |
| npm       | `npm/`          | `npm/lodash/lodash-4.17.21.tgz`                                                 |
| cargo     | `cargo/crates/` | `cargo/crates/serde-1.0.200.crate`                                              |
| freebsd   | `freebsd/`      | `freebsd/FreeBSD:14:amd64/latest/All/Hashed/zogftw-2025.02.23_1~2$snxfrbid.pkg` |
| manifests | `manifests/`    | `manifests/apt/python3/manifest.json`                                           |
| index     | `index.json`    | Fast startup without loading every manifest                                     |
| graph     | `graph.json`    | Dependency graph with typed edges                                               |
| metrics   | `metrics.json`  | Dashboard metrics                                                               |

Git smart-HTTP mirrors are the one tree that is not a storage key. They are bare repositories under `{storage_path}/git/{namespace}/{org}/{repo}.git` on the local filesystem, never in a named backend and never in S3: `git-http-backend` reads a real directory, and `bodega pkg move` has nothing to move. Placement rules do not reach them.

---

## Development

### Build targets

```bash
make check          # every job CI blocks on, cheapest leg first
make build          # compile to ./dist/bodega
make cross          # cross-compile for every pair in CROSS_TARGETS (linux/amd64, linux/arm64)
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

```text
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
