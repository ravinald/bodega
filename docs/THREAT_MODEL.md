# Bodega Threat Model

This document defines what bodega protects against, what it does not, and the
distribution channels that bodega intentionally treats as out of scope. It is
the reference point for operator decisions about how to lock down a host that
is supposed to fetch software exclusively through bodega.

## What bodega protects against

Bodega is built around a single chokepoint: every fetch from upstream traverses
the server's proxy/cache layer, where it is matched against the operator's
allow-list, verified against a stored checksum, and recorded in the audit DB.
That gives operators leverage against the following classes of supply-chain
risk:

- **Typosquatting and namespace confusion.** Allow-list rules are exact-match
  by registry type (package name for pypi/npm/cargo, prefix for gomod/git,
  hostname for apt). A request for `reqeusts` does not match an allow rule for
  `requests`, and the fetch is rejected before any bytes leave the network.
- **Silent version drift.** Manifest entries pin a concrete version. Subsequent
  fetches must produce the same SHA-256, or the cached artifact wins. Tuesday's
  build produces the same bytes as last Tuesday's build.
- **A malicious release inside its own withdrawal window.** A fresh install is
  seeded with a minimum publish age of `7d` on `npm` and `pypi`, action `warn`,
  and `bodega serve` names it at startup. The npm and PyPI campaigns of
  2025-2026 were caught and the versions pulled within days of publication, so
  an import that waits a week gets the withdrawal rather than the payload.
  Checksum pinning is the wrong tool for this one: it guarantees today's fetch
  matches the first one, so a compromised *first* fetch is served faithfully
  and forever with `checksum_verified` beside it. The cooldown is what makes
  the first fetch late enough to be safe.
- **Compromised upstream releases.** When an upstream package is replaced with
  a malicious version (the canonical example being the npm or PyPI account
  takeovers of recent years), bodega's `pkg hide` and `pkg freeze` operations
  let an operator quarantine the bad version and pin a known-good replacement
  in seconds. The case studies under `docs/case-study/` walk through one such
  incident end to end.
- **Transitive dependency poisoning.** When a top-level package (e.g. a git
  repo with `dep_policy: "direct"` or `"transitive"`) is fetched, bodega
  records every dependency it discovers and creates manifest entries for
  them. Subsequent builds resolve dependencies against those pinned entries
  rather than re-querying public registries.
- **Opaque CI fetches.** A `bodega serve` instance is the single place to look
  when answering "what did our build pull from the internet?" The audit DB
  records every fetch event with client IP, package name, version, and
  outcome.

## What bodega does not protect against

The chokepoint only protects what flows through it. Bodega makes no claim of
defence against:

- **Host-level compromise.** A root-owned process on a CI host can edit
  `/etc/hosts`, replace `/usr/bin/pip`, or simply ignore bodega entirely.
  Bodega's controls assume the host itself is trustworthy.
- **Bodega-server compromise.** A compromised bodega instance can serve any
  artifact it likes. Operate the server like any other piece of internal
  infrastructure: principle of least privilege on the bucket IAM role,
  short-lived credentials, audit-log forwarding off-box.
- **Anything inside an opaque distribution bundle.** When a package format
  bundles its own dependencies in a way bodega cannot inspect (see below),
  the contents of that bundle are outside bodega's allow-list. Bodega may
  see the request for the outer artifact and may even cache it, but it has
  no visibility into the libraries linked or interpreted inside.
- **Anything the shipped defaults do not reach.** The seeded cooldown covers
  `npm` and `pypi` and reports rather than refuses. It says nothing about
  `gomod` or `cargo`, which can be dated and get no seed; it cannot cover
  `apt`, `binary`, `git` or `helm` at all, because those have no upstream
  publish timestamp to date a version against. Every other control is off on a
  new install: the upstream allow-list is empty, which accepts every
  candidate, and the OSV gate has no rows until an operator adds one. An
  install created before the seed shipped gains nothing on upgrade, by
  design: a new default must not change what a running fleet enforces.
- **Build-time code execution by trusted packages.** A `setup.py` that
  `os.system`s out, an `npm install` lifecycle script, a `cargo build` script
  — all of these run with the build user's privileges and can do anything
  that user can. Bodega controls *which* packages run; it does not sandbox
  what they do once they run.

## Out-of-scope distribution formats

Three properties make a distribution format incompatible with bodega's
controls. Any one of them is enough; the formats below have all three.

1. **Auto-refresh.** The runtime fetches and applies updates on its own
   schedule, independent of any operator action. Version pinning is impossible
   without per-package opt-out gymnastics.
2. **Opaque bundling.** The on-disk artifact is a closed container that
   includes its own copies of libraries, language runtimes, or other
   dependencies. Bodega's per-type proxies (apt, pypi, gomod, …) never see
   those nested dependencies.
3. **Third-party trust root.** The cryptographic signatures that the runtime
   verifies are anchored in keys held by an external vendor. Even a perfect
   mirror cannot change *what* the vendor signs — only *whether* you cache it.

The following formats are intentionally not supported by bodega. The intent
is not a value judgement; these are products that exist for good reasons in
contexts where bodega's threat model does not apply.

### Snap

Snaps (`.snap` files served by `snapd`) hit all three failure modes.
Installed snaps refresh automatically on a daemon-managed schedule unless
explicitly held per-snap. Each snap is a squashfs image with its own bundled
libraries, runtimes, and interpreters. Assertions are signed by Canonical;
even Canonical's commercial Snap Store Proxy mirrors but does not gatekeep
what publishers ship.

### Flatpak

Same shape as snap. Flatpak runtimes are bundled, remotes (flathub etc.)
are configured per-host rather than through bodega's allow-list, and updates
happen on a user- or system-triggered cadence that bodega does not see.

### AppImage (with auto-update enabled)

A bare AppImage downloaded once and never updated is fine — bodega's `binary`
type handles that case cleanly. An AppImage with `AppImageUpdate` enabled
self-modifies from a URL embedded in the image, which both bypasses bodega
and produces a different artifact than the one originally vetted.

### Homebrew casks (and `brew` without `HOMEBREW_NO_AUTO_UPDATE`)

`brew install` runs `brew update` first by default, fetching tap metadata
from upstream before resolving the requested package. Casks additionally
download closed-source binaries from vendor URLs that change without notice.
Setting `HOMEBREW_NO_AUTO_UPDATE=1` partially mitigates the metadata fetch,
but the cask download URLs are still vendor-controlled.

### Container base images with floating tags

`FROM ubuntu:latest` resolves to a different image digest over time. Bodega
does not currently operate a container registry, but the same principle
applies if you stand one up: only digest-pinned references
(`FROM ubuntu@sha256:...`) give the version-pinning guarantee that bodega's
manifest entries provide for non-container types.

## Operator guidance

For a host that is supposed to fetch software exclusively through a bodega
instance, the recommended posture is:

- **Remove snapd entirely.**
  `sudo systemctl disable --now snapd snapd.socket && sudo apt purge snapd`.
  Replace the `snap` binary with a stub that exits 1 if you cannot remove
  the package outright.
- **Do not install flatpak.** `sudo apt purge flatpak` if it is present from
  an upstream image.
- **If Homebrew is required, set `HOMEBREW_NO_AUTO_UPDATE=1`** in the system
  profile (`/etc/environment` or `/etc/profile.d/`). Audit casks separately
  — they are not covered by this flag.
- **Configure each package manager to talk to bodega exclusively.**
  `bodega doctor` enumerates every file that needs editing and the bodega
  endpoint each should point at. Re-run `bodega doctor` after rewriting to
  confirm exit 0.
- **Set `GOPROXY` to `http://<bodega>/gomod,off`** — never `,direct`. The
  `,off` form makes cache misses fail loudly; `,direct` silently falls
  through to public VCS, defeating the chokepoint.
- **Run `bodega doctor` in CI** as a gate step. Exit 2 is a finding; exit 0
  is clean. The output is tab-aligned and tabwriter-stable, so a pipeline
  can both gate on the exit code and surface the per-check detail in the
  build log. The checks themselves write nothing, but every bodega command
  bootstraps a config file on first run, so a runner holding neither
  `/etc/bodega/config.json` nor `~/.config/bodega/config.json` gains the
  second one (the first, as root) before the first check executes. That file
  and the log directory it names are all a doctor run creates. The posture
  checks open the audit database read-only, so a run against an install one
  release behind neither brings a database into existence nor migrates the
  one it finds: an upgrade is something you schedule, not something a report
  does to you. A host with no install reads `N/A` rather than gaining one.
- **Harden the seeded cooldown and add an allow-list.** `bodega policy age
  set npm 7d block` turns the shipped `warn` into a refusal once you have
  watched it for a release cycle; `bodega policy add <type> <pattern>`
  constrains what may be fetched at all. Run them on the server, not on the
  clients: they are the install's own posture, and they take effect without a
  restart.

On the bodega host itself, `doctor` adds three checks that read the audit
database rather than the machine. They report `N/A` on a client host with no
install:

- `policy-coverage`: no allow-list rule and no publish-age or OSV gate, so
  every upstream fetch is admitted. It counts both gates because
  `admit.checkVersions` runs both, so an install carrying either one already
  refuses fetches and reporting it as wide open is a claim its own
  `policy_violation` records disprove.
- `policy-ignored`: a gate set to `ignore` on every ecosystem it covers.
  That is where an install lands when somebody silences an alert during an
  incident and nobody puts it back.
- `policy-ecosystem`: a stored row whose gate cannot evaluate it, written
  before `policy set` learned to refuse one. It lists as active policy and is
  read by nothing.

## See also

- `docs/DESIGN.md` — overall architecture; the proxy/cache chokepoint at the
  centre of the security story.
- `docs/USAGE.md` — operational reference for `pkg hide`, `pkg freeze`, and
  the allow-list policy commands referenced above.
- `docs/case-study/bitwarden-supply-chain.md` — worked example of using
  bodega's controls during an active upstream compromise.
- `README.md` — the supported package types whose fetches flow through
  bodega's chokepoint.
