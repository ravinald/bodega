# Fixtures

Captured from real package managers, not written by hand. A parser tested only
against input its author invented is tested in a world where the parse bug
cannot occur.

| File | Source | Captured from |
| --- | --- | --- |
| `apt-dpkg-query-ns0.txt` | `dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\n'` | Ubuntu 22.04.5 LTS server, x86_64 |
| `apt-list-installed-ns0.txt` | `apt list --installed` | the same host, same moment |
| `apt-dpkg-query-ubuntu2404.txt` | `dpkg-query -W` | `ubuntu:24.04` container, arm64, after `apt-get install curl jq` then `apt-get remove jq` |
| `apt-list-installed-ubuntu2404.txt` | `apt list --installed` | the same container, same moment |
| `pypi-pip-list.json` | `pip list --format=json` | macOS, Homebrew python |
| `npm-ls-global.json` | `npm ls --global --json --depth=0` | macOS, Homebrew node |
| `cargo-install-list.txt` | `cargo install --list` | macOS |
| `gomod-go-version-m.txt` | `go version -m ~/go/bin/drover` | macOS, go1.26.6 |
| `gomod-go-list-m-all.txt` | `go list -m all` | this repository |
| `helm-repo-list.json` | `helm repo list -o json` | `alpine/helm:3.16.3` container, two public repos added |
| `helm-list.json` | `helm list -o json` | **synthesized**, see below |

## The two apt hosts earn their places separately

The ns0 capture is the scale and the correctness case in one. `dpkg-query -W`
returns 774 rows there; only 635 are `install ok installed`. The other 139 are
`deinstall ok config-files`, mostly superseded kernel images, and a parser that
skips the status filter mirrors 139 packages the host does not have. The
matching `apt list --installed` capture lists exactly those 635, so the two
formats cross-check each other and neither is graded against its own parser.

The container capture covers what a long-lived server does not show: a package
installed from a repo carries a real suite (`noble-updates,noble-security,now`)
rather than `now`, and the `[installed,automatic]` and `[installed,auto-removable]`
markers appear. A base image alone shows `[installed,local]` for everything,
which would let a marker-parsing bug pass.

## The synthesized one

`helm-list.json` is written from helm's documented `-o json` schema, because
`helm list` reaches a Kubernetes cluster and there is none in this repo's test
environment. Its shape is asserted, its content is invented. Replace it with a
real capture when a cluster is available. `helm-repo-list.json` beside it is a
real capture and needs no such caveat.
