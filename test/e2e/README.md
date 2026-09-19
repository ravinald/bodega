# End-to-end harness

## What this is for

Everything that gates a merge in this repository is a unit test. `make check`
runs seven legs, CI runs six jobs, and every one of them is `go test` or a
linter. bodega serves eight package types to eight real clients, and until this
harness existed nothing automated had ever pointed `apt-get`, `pip`, `helm`,
`npm`, `cargo`, `go`, `git` or `curl` at a running server and checked what came
back.

This harness answers one question: **does a bodega built from this commit serve
its eight package types to their native clients, enforce its access controls
against a request that is not from loopback, and record what it did?**

It runs from the workstation against the two UTM guests described in
[`docs-internal/DEV_HOSTS.md`](../../docs-internal/DEV_HOSTS.md). It does not run
in CI and never will: it needs two hosts, a real network between them, and
several minutes.

## Running it

```bash
./test/e2e/run.sh --validate     # every script parses. <1s, touches nothing
./test/e2e/run.sh --dry-run      # walk every suite, contact no guest, list
                                 # every command it would issue
./test/e2e/run.sh --preflight    # the foundation only, for real, ~15s
./test/e2e/run.sh                # the full pass
./test/e2e/run.sh --deadline 480 # stop at 8h with a report rather than hang
```

Run the first three before an unattended pass. `--validate` catches a typo in a
late suite in under a second; `--dry-run` proves every suite reaches its last
check and writes `dry-run-plan.txt`, which is every command the real run will
issue, in order.

Other flags: `--suite <prefix>` runs a subset (00-preflight always runs
regardless, because it sets the reachability flags the others read),
`--no-ship` reuses whatever is installed on the guests, `--allow-dirty` permits
an uncommitted tree, `--self-test` runs the harness's own tests with no guest
needed.

`make harness` runs the lint and the self-test, and is a leg of `make check`.
`make e2e` runs the full pass.

## Measuring success

**The run exits 0 when nothing FAILed and nothing was BLOCKED.** That is the
one-line answer. Below it:

| Verdict | Means | What to do |
|---|---|---|
| `PASS` | The check measured what it expected. | Nothing. |
| `FAIL` | A defect, or a harness bug. | Triage. Every FAIL is a candidate issue. |
| `XFAIL` | Failed, and `known-issues.tsv` maps it to an open issue. | Nothing. It is already filed. |
| `XPASS` | Passed, and it maps to an open issue. | **Close the issue and delete the row.** |
| `SKIP` | A precondition is absent by design (no container runtime, no TLS). | Read the reason; some skips are themselves findings. |
| `BLOCKED` | A prerequisite failed, so this never ran. | Fix the prerequisite. A blocked check is neither a pass nor a failure. |
| `DRY` | `--dry-run`. Nothing was measured. | Nothing. A dry run never reports PASS. |

Each run writes `results/<run-id>/`:

- `report.md` — verdict counts, a per-suite table, then one section per failure
  with the exact command, expected against actual, and a source reference.
- `findings.jsonl` — one JSON object per check. This is the machine-readable
  record; `report.md` is rendered from it and can be re-rendered with
  `--report <run-id>`.
- `logs/<suite>.log` — the full transcript of every command, with stdout,
  stderr and exit code. The findings carry an excerpt; this carries everything.
- `dry-run-plan.txt` — on a dry run, every command that would have been issued.

`results/` is gitignored. A run is evidence, not an artifact of the repository.

### Triaging a failure

Ask whether the harness or the product is wrong, and prefer the harness. Three
of the first four failures this harness reported were its own:

- A `| tail -5` made the pipeline report `tail`'s exit code, so npm 404ing and
  npm succeeding were both rc 0. `e2e_on` now forces `set -o pipefail` on the
  guest.
- The admin-gated read checks ran *after* the admin list was widened, so they
  measured an admin asking itself whether it is an admin.
- A token was extracted by taking the longest string in the output, which is
  the token ID, printed two lines below the token.

The log directory settles it: read the transcript before filing anything.

### Filing

```bash
./test/e2e/run.sh --file-dry-run <run-id>   # what it would file
./test/e2e/run.sh --file <run-id>           # one issue per unmapped FAIL
```

Filing is a separate invocation on purpose. A broken guest or a stale binary
would otherwise open a dozen bogus issues in one run. Each issue carries the
check id, so the next run's XFAIL mapping is a one-line append to
`known-issues.tsv`.

## How it is put together

```
run.sh                  orchestrator: guards, run state, suite loop, report
known-issues.tsv        check-id -> issue number. FAIL becomes XFAIL, PASS becomes XPASS
lib/assert.sh           every verdict goes through e2e_record, the only writer of findings.jsonl
lib/remote.sh           ssh/scp; e2e_on runs one command string on "server" or "client"
lib/bodega.sh           bodega CLI, config, restart, HTTP helpers
lib/fixtures.sh         the shared package set: one hosted PackageManifest per
                        type, plus npm-proxy/cargo-proxy/gomod-proxy in proxy mode
lib/report.sh           findings.jsonl -> report.md, and issue filing
lib/selftest.sh         the harness's own tests. Runs with no guest reachable
suites/*.sh             sourced in filename order
```

A suite is sourced, not executed, so it shares the counters and the run state.
It runs under `set -euo pipefail` inherited from `run.sh`: a suite that dies
takes its own remaining checks down but not the run, and the aborted suite is
recorded as a failure rather than as silence.

### Guards worth knowing about

**The host allowlist is a constant, not a flag.** The suites call
`bodega reset`, `pkg delete --remove-artifacts` and `userdel bodega`, and the
production host is `bodega.cow.org`, one label away from the server guest.
`e2e_host_for` resolves only the aliases `server` and `client`; no suite can
name a host however it is edited.

**The commit under test is stamped and asserted.** `run.sh` refuses a dirty
tree without `--allow-dirty`, builds through `make cross` so the ldflags land,
and asserts `bodega --version` contains the HEAD short commit on both guests. A
run that cannot prove which commit it measured produces findings nobody can act
on. Both guests were 35 commits behind when this harness was written, running a
binary stamped `bodega unit-test` from a bare `go build`.

**Ownership is repaired after every root-run command.** `e2e_bodega` chowns
`/var/lib/bodega` and `/var/log/bodega` back to the service user. A cache write
the service cannot make logs `permission denied` at WARN and still answers the
request from upstream, so an install serves correctly for weeks while caching
nothing.

## Writing a suite

Filename is `NN-name.sh`, and `NN` is the order it runs in. Read-only suites go
before mutating ones; anything destructive goes at the end.

```bash
# shellcheck shell=bash
# shellcheck source-path=SCRIPTDIR

# shellcheck source=../lib/assert.sh
. "${E2E_DIR:?run.sh sets E2E_DIR}/lib/assert.sh"
# shellcheck source=../lib/remote.sh
. "${E2E_DIR:?}/lib/remote.sh"

if [ "${E2E_DRY_RUN:-no}" != yes ] && [ "${E2E_SERVER_UP:-no}" != yes ]; then
	E2E_HOST=local
	e2e_block XYZ-BLOCK "what this suite covers" "the server guest is unreachable"
	return 0
fi

E2E_HOST=server
e2e_on server "bodega something" || true
check_eq XYZ-01 "what must be true" "expected" "$E2E_OUT" "internal/path.go:12" "bodega something"
```

Rules the harness enforces or depends on:

- **Check ids are unique across every suite.** `run.sh` fails the run on a
  duplicate: two suites sharing an id make the known-issue map ambiguous.
- **Prefix ids by area** (`PRE-`, `SHIP-`, `PIPE-`, `SRV-`, `CLI-`, `POL-`,
  `PROF-`, `ACC-`, `PXY-`, `AUD-`, `INT-`, `SYS-`, `GAT-`, `UI-`, `DST-`,
  `JSON-`) and keep them stable. A filed issue cites one.
- **Never let a suite exit on a failed command.** `|| true` after every
  `e2e_on`; the check reads `$E2E_RC`.
- **A suite that needs a value another suite produced must tolerate its
  absence**, because `--suite` can filter the producer away. `run.sh` declares
  the shared ones empty for this reason.
- **Restore what you changed, and check the restore.** `60-access` puts the
  admin list back to loopback; `65-proxy` puts the proxy back off, empties both
  `git_upstreams` and `binary_upstreams`, and deletes the three proxy-mode
  entries it imported, each with a check of its own. A suite that left the proxy
  on would let a later "hosted" check pass on an upstream fetch, one that left
  an upstream namespace configured would answer a later hosted check out of a
  namespace it invented, and one that left a proxy-mode entry catalogued would
  do the same for that one package name.
- **Restarts are rate-limited.** systemd allows 5 starts per 10 seconds by
  default, and a suite walking several postures reaches that on a healthy
  service. `e2e_restart` clears the counter before every restart; a suite that
  restarts by hand will report a refused start as a server that will not come
  up.
- **Assert the thing, not a proxy for it.** `PIPE-VERSION` reads the artifact on
  disk rather than asking `show pkg` what version it holds: the manifest-side
  form compares the manifest with itself and passed a store holding a 1.17.0
  wheel against an entry pinning 1.16.0.
- **A ref carries the source location, and what was measured when the check's
  meaning depends on a comparison.** `PXY-MODE-04` records that a proxy-mode
  gomod fetch answers 200 with the cache switch off where an uncatalogued
  module 404s. A location on its own leaves that comparison in a shell comment,
  and a comment reaches no reader of `findings.jsonl`, `report.md` or a filed
  issue. Keep it to one line and free of backticks: `report.md` and the issue
  body both render the ref inline.

Available assertions: `check_eq`, `check_ne`, `check_contains`, `check_lacks`,
`check_matches`, `e2e_skip`, `e2e_block`, and `e2e_record` for anything with a
verdict those do not express.

`make harness` must pass before a suite lands: `shellcheck -x`, `shfmt -d` and
the self-test are a leg of `make check`.

## What this run does not cover

- **TLS.** This harness runs against a plaintext listener, which is why the pip
  checks pass `--trusted-host`. `docs-internal/DEV_HOSTS.md` lists TLS as a gap:
  the unit has only ever run with `allow_plaintext` on loopback. The base URL is
  a variable, so turning it on is a config change rather than a rewrite.
- **The S3 storage backend**, and the `TimeoutStartSec=180` the unit carries for
  it. Needs a real bucket or a local S3 on the server guest.
- **The postgres audit sink** (`BODEGA_TEST_POSTGRES_DSN`).
- **`gomod` from the client guest.** `go get` needs a toolchain and the client
  carries none on purpose, so `CLI-GOMOD-01` runs on the server. It crosses the
  network stack; it does not exercise the client.
- **A scripted guest reset.** Restoring is a manual UTM clone-and-rename, which
  caps how often the destructive suite can run.
