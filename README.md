# bodega

<img src="assets/bodega-256.png" alt="A warehouse with a b on its sign band and three loading bays" width="120" align="right">

[![CI](https://github.com/ravinald/bodega/actions/workflows/ci.yml/badge.svg)](https://github.com/ravinald/bodega/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/ravinald/bodega.svg)](https://pkg.go.dev/github.com/ravinald/bodega)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A self-hosted package repository manager backed by pluggable object storage. It fetches, builds, and serves ten package types to their native clients without leaving your network, so `apt-get`, `pip`, `npm`, and FreeBSD's `pkg` keep working when the upstream registry is unreachable, compromised, or simply not where your hosts are allowed to go.

Every package is a manifest: a name, a type, and a list of version entries. An entry carries where the bytes came from, the checksum pinned on first fetch, and the lifecycle flags the server enforces at request time. Artifacts live in local storage, S3, or several named backends at once; the audit database records every fetch, mutation, and refusal.

| Type      | Client         | Protocol                                    |
| --------- | -------------- | ------------------------------------------- |
| apt       | `apt-get`      | Debian repository                           |
| git       | `git clone`    | Git bundles                                 |
| pypi      | `pip install`  | PEP 503 simple index                        |
| binary    | `curl`         | Direct download                             |
| gomod     | `go get`       | GOPROXY                                     |
| helm      | `helm install` | Chart repository                            |
| npm       | `npm install`  | npm registry                                |
| cargo     | `cargo`        | Sparse registry index                       |
| freebsd   | `pkg`          | pkg repository, mirrored or generated       |
| distfiles | `make fetch`   | Ports distfiles, checked against `distinfo` |

## Install

Build from source with Go at the version `go.mod` names:

```bash
git clone https://github.com/ravinald/bodega.git
cd bodega
make build          # ./dist/bodega
```

There are no published releases yet, and `go install github.com/ravinald/bodega/cmd/bodega@latest` resolves to a cached `v0.1.0` that predates this tree. Build from source until a tagged release lands.

The server runs on Linux and FreeBSD, and `make build` works the same on both. FreeBSD does not yet get release archives or an rc.d script beside the systemd unit; [Platforms](docs/usage.md#platforms) tracks each gap.

Storage defaults to the local filesystem at `/var/lib/bodega`. For S3, set `storage_backend` to `"s3"` in the config file and run `bodega init` to create the bucket with encryption, versioning, lifecycle rules, and public access blocked. Credentials come from the AWS default chain. `bodega init --print-policy` prints the IAM policies for setup and for the running service, and `bodega init check` confirms the current credentials hold the runtime one. [S3 setup](docs/usage.md#s3-setup) has the details.

## Quick start

Add a package, fetch it, and serve it to a client:

```bash
bodega pkg create git widget     # add a git entry, with interactive prompts
bodega build fetch               # download sources
bodega build upload              # build and upload to storage
bodega serve --allow-plaintext   # HTTP server on :8080
```

The client then points at the mirror instead of upstream, and nothing else about its workflow changes.

To catalog a host that already exists rather than adding packages one at a time, read its installed set and push the result. Neither step needs a manifest store on the host:

```bash
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\t${source:Package}\n' \
  | bodega pkg convert apt > catalog.json
bodega pkg import --server https://bodega.example.com catalog.json
```

[Quick start](docs/quickstart.md) walks the same ground with a client install at the end.

## Commands

| Command    | Purpose                                                                                       |
| ---------- | --------------------------------------------------------------------------------------------- |
| `acl`      | Manage the CIDR access lists in the audit database                                            |
| `apt`      | APT repository operations, including signing key management                                   |
| `audit`    | Audit trail and dependency checking                                                           |
| `build`    | Build pipeline: fetch, run, package, upload, sync, status                                     |
| `discover` | Inspect upstream-fetch observations and promote them to allow-list rules                      |
| `doctor`   | Inspect the host and this install's policy posture for gaps in bodega's controls              |
| `freebsd`  | Manage the signing key for a generated pkg repository                                         |
| `identity` | Bind tokens and networks to the host names the audit trail records                            |
| `init`     | Create an S3 backend's bucket, print its IAM policies, and check them                         |
| `pin`      | Pin a host to the versions bodega serves                                                      |
| `pkg`      | Package management: create, edit, import, export, convert, delete, freeze, hide, move, verify |
| `policy`   | Manage the upstream source allow-list                                                         |
| `profile`  | Declare what one class of host may fetch                                                      |
| `repair`   | Detect and fix inconsistencies in the manifest store                                          |
| `reset`    | Clear all manifests and local artifacts, keeping app config                                   |
| `serve`    | Start the HTTP(S) package server                                                              |
| `shell`    | Launch the interactive TUI                                                                    |
| `show`     | Display repository and package information                                                    |
| `status`   | Show the repository status dashboard                                                          |
| `token`    | Manage API tokens for the mutation API                                                        |

## Documentation

- [Quick start](docs/quickstart.md) takes one package from nothing to a client install.
- [Usage](docs/usage.md) is the operational reference: every command, the config file, the policy surface, the audit trail, and running under systemd.
- [Design](docs/design.md) explains the architecture and why the proxy and cache sit where they do.
- [Threat model](docs/threat-model.md) states what bodega protects against, what it does not, and which distribution formats are out of scope on purpose.
- [Quarantining a compromised release](docs/quarantine/) covers tombstoning a bad version, pinning a known-good replacement, and relaxing back to normal tracking without losing the tombstone. The same three scenarios run through [the shell](docs/quarantine/cli.md), [the TUI](docs/quarantine/tui.md), and [HTTP](docs/quarantine/api.md).
- [Contributing](CONTRIBUTING.md) covers the build, the merge gate, and the end-to-end suite.
- [Security](SECURITY.md) has the vulnerability disclosure address.

## Status

Pre-1.0. The CLI surface, the manifest schema, and the config format still move, and nothing here promises otherwise yet. All ten package types serve their native clients today, and the end-to-end suite drives every one of them against a running server.

Two checksum gaps are known and stated rather than implied: pypi and clone-mode git have no per-version object key, so neither pins a digest on first fetch. [Threat model](docs/threat-model.md) covers both. That suite runs by hand against four hosts, a Linux pair and a FreeBSD pair, rather than in CI, so the automated gate is unit tests and linters.

## License

Apache 2.0. See [LICENSE](LICENSE).
