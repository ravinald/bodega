# Contributing

Bodega is a package repository that other machines trust to hand them software. Every change is a security change, so the gate is not a formality and the review reads the diff against what it lets through.

## Building

The build needs Go at the version `go.mod` names and nothing else:

```bash
make build      # ./dist/bodega for this host
make cross      # linux/amd64, linux/arm64, freebsd/amd64 and freebsd/arm64
```

`make install` puts the binary on `PATH`; `make uninstall` takes it off again.

Release archives come from GoReleaser at tag time, not from the Makefile: `.goreleaser.yaml` builds `tar.gz` archives for `linux`, `darwin` and `freebsd` on `amd64` and `arm64`, with the same ldflags `make build` stamps, and the `.deb` and `.rpm` packages for Linux. `goreleaser release --snapshot --clean --skip=sign` reproduces them in `dist/` without a tag; the signing stage signs keyless through GitHub's OIDC issuer and only completes in CI.

## The gate

`make check` is what CI blocks on, and the one command to run before opening a pull request:

```bash
make check
```

It runs a leg per CI job, cheapest first, so a gofmt slip costs two seconds rather than a full race test:

| Leg          | What it runs                                                                |
| ------------ | --------------------------------------------------------------------------- |
| `ci-drift`   | asserts the CI job list, the leg each job maps to, and `ci.yml` still agree |
| `fmt-check`  | fails on gofmt or goimports drift                                           |
| `tidy-check` | fails on `go.mod` or `go.sum` drift, restoring both either way              |
| `harness`    | shellcheck and shfmt over the e2e suites, then their own tests              |
| `vet`        | `go vet`                                                                    |
| `build`      | compiles every package                                                      |
| `lint`       | golangci-lint                                                               |
| `test`       | `go test -race -count=1`                                                    |

Run a leg on its own with `make test`, `make lint`, `make vet`, `make fmt`, or `make tidy`.

**One gate job has no leg: `test-freebsd`.** It runs `go test ./...` on a FreeBSD 15.1 kernel in a VM, which no workstation or Linux runner can boot, so `make check` passing says nothing about it. The Makefile lists it in `CI_ONLY_GATE_JOBS`, and `make ci-drift` accepts it in the gate without a leg on that basis alone. A FreeBSD failure shows up in the pull request's checks; reproduce it on a FreeBSD host as an unprivileged user with `TMPDIR` set to a directory that user's own group owns, the way the job runs it.

**Tool versions differ between this gate and CI.** `shfmt` is pinned in `.github/workflows/ci.yml`; `shellcheck` comes from the GitHub runner image and is not. A shell change that passes `make harness` locally can still fail in CI on a rule your build does not carry, so read the job log rather than assuming the local run settled it.

## End-to-end tests

`make check` is unit tests and linters. `test/e2e/` is the other half: it ships a build to four hosts, a Linux pair and a FreeBSD pair, and drives `apt-get`, `pip`, `helm`, `npm`, `cargo`, `go`, `git`, `curl`, `pkg`, and `make fetch` against a running server, then writes a findings file. The FreeBSD server guest is the only place the storage layer's extattr and ACL calls run on both ZFS and UFS with ACLs, as root and unprivileged; the `test-freebsd` CI job runs them once, unprivileged, on whatever filesystem its VM image carries.

It needs four scratch guests and several minutes, so it runs by hand rather than in CI:

```bash
make e2e
```

[`test/e2e/README.md`](test/e2e/README.md) covers the host requirements, what the run measures, and how to read the result. The guests are named in an uncommitted `test/e2e/hosts.env`; copy `test/e2e/hosts.env.example` to create it. The suites are destructive by design, so name nothing you care about.

## Pull requests

Keep the subject terse and let the diff carry the rest. A commit body earns its place when it answers something the diff cannot show: the alternative that lost, the constraint that forced this design, a failure that arrives with no error, or the commit it corrects.

Examples in documentation and help text use fictional names. A real package, company, or host appears only when something on the wire has to resolve to it: registry hosts, tool names, and actual `go.mod` dependencies. `cmd/bodega/example_names_test.go` enforces that, and also resolves every relative link in the Markdown, because nothing else does.

## Reporting a vulnerability

Do not open an issue. [`SECURITY.md`](SECURITY.md) has the disclosure address and the response commitment.
