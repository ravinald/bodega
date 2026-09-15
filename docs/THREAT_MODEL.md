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
- **Silent version drift.** Manifest entries pin a concrete version, an npm
  dist-tag being the exception named below. The first
  fetch records that version's SHA-256 in the audit database, keyed by the
  object key the server serves it under, and a later fetch producing different
  bytes is refused rather than stored. Both halves of the pipeline write that
  one record: `build fetch` pins what it downloads, and the proxy pins what it
  caches on behalf of a client. `build upload` reaches upstream through that
  same fetch when a stage is missing, so the one-command install pins as it
  cascades rather than uploading artifacts nothing is pinned against.
  Tuesday's build produces the same bytes as last Tuesday's build, and
  `bodega pkg checksum list` is the record of which versions are pinned.

  Two artifacts are not covered, and the gap is in the shape of the artifact
  rather than in the check. **pypi** wheels upload as a directory holding the
  resolved dependency closure, so no per-version object key exists to pin one
  against; the closure is pinned by the requirements set instead.
  **Clone-mode git** ships a bundle this instance generates locally at package
  time, so there are no upstream bytes for a digest to attest to, and `git
  bundle create` is not reproducible byte-for-byte — a pin would fail the next
  repackage rather than catch anything. A git entry fetched as a release
  tarball is covered normally.

  An **npm dist-tag** (`latest`, or an entry left without a version) pins per
  resolved version rather than per manifest entry. The tag is meant to move, so
  a digest written onto the entry would refuse the next legitimate release; the
  digest goes on the resolved version's own object key instead. Every concrete
  version the tag has ever resolved to is on record and shows as its own row in
  `bodega pkg checksum list`, and a later resolution to one of them is refused
  if the bytes changed. The tag advancing to a new release is not a mismatch;
  an existing version being republished under it is.

  An **apt** entry pins at whichever stage first holds the `.deb`. A direct URL
  or an `apt-get download` produces the artifact during fetch, so the digest and
  the pool key the server will publish it under are both recorded there, and a
  later fetch returning different bytes under the same filename is refused
  rather than stored. An entry carrying a `build_cmd` has no `.deb` until the
  build runs: its digest is recorded at package time off what this instance
  compiled, because no upstream download happened for an earlier stage to
  attest to.

  Nothing else is exempt: binary, apt, gomod, helm, npm and cargo all pin.
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
- **An out-of-band edit to a manifest.** The manifest is the record of what was
  approved, and it is a JSON file an operator can open in an editor. Every
  manifest write emits an MD5 sidecar in the same operation, and
  `bodega pkg verify` compares each manifest against its own and exits non-zero
  on a mismatch. A manifest carrying no sidecar is reported `UNVERIFIABLE`
  rather than passed: nothing was compared, and a run that counted that as a
  pass would answer yes to every edited manifest in the store. The limit is
  worth stating plainly — MD5 and a sidecar in the same directory detect an
  edit, not an attacker, because whoever can rewrite the manifest can rewrite
  the sidecar beside it. It catches a hand-edit, a partial restore and a
  half-finished write; it is not a signature.
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
- **A read-path credential being read-only.** `bodega token generate` takes a
  label and nothing else; the rows in `api_tokens` carry no scope. The
  mutation gate accepts any unexpired one of them as its credential half
  whenever `admin_permit_cidr` reaches past loopback, so a token written to a
  client host by `bodega doctor --write-credentials` authorizes `POST` and
  `DELETE` from that host too, if its address is inside `admin_permit_cidr`.
  Read-path identity did not introduce this; it is what unscoped tokens have
  always meant, and it matters now because the read path is the first place
  those tokens live on machines other than an operator's. Two remedies exist
  today, and `--write-credentials` prints them before it writes: keep
  `admin_permit_cidr` at loopback, which makes the gate ignore tokens
  entirely, or treat every host holding a written credential as
  admin-capable. Scoped tokens would sever the two and are not shipped.
- **A profile's apt codename being an authorization boundary.** It is a
  scoping one. A profile that scopes apt is served a filtered `Packages` under
  a codename of its own, and the host reads that codename because its
  `sources.list` names it — a file the host can edit. Nothing stops a host from
  writing the unfiltered mirrored codename into that file and reading the
  archive whole, and nothing about the filtered codename's name is a secret:
  it is `<base>-<profile>`, it appears in the startup banner and in
  `GET /api/v1/status`, and it is served to whoever asks for it. What the
  filtered index buys is that a *correctly configured* host is never offered a
  package outside its class, which is what turns a refusal into `kept back`
  instead of an aborted transaction. What refuses the artifacts behind it is
  the request predicate at `/apt/pool/`, which runs on identity rather than on
  what the client's sources say. Read the two together: the index decides what
  a host is told exists, the predicate decides what it may fetch. The gap
  closes when the token that identifies a host also gates the codename, which
  is not shipped.
- **The chain of trust behind a filtered apt codename.** bodega re-signs it
  with bodega's own key, and what bodega verified before signing is the
  archive's TLS certificate and the SHA256 that the archive's own `Release`
  publishes for the `Packages` beside it. It does not verify the archive's
  `InRelease` signature, because it holds no distro keyring to check one
  against. So a filtered codename's trust ends at the archive's certificate,
  where a *mirrored* codename forwards the archive's signature untouched and
  the client checks it against the distro keyring already on the host. That is
  a real difference and it is the price of filtering: one URL serves one
  `Release`, and an index bodega narrowed cannot carry a signature over the
  index it narrowed. An operator who wants the upstream signature end to end
  points the host at the mirrored codename and accepts that it is unfiltered.
  Which is why a filtered codename that would filter nothing is refused rather
  than served: an apt rule with a base needs closed membership *and* `block`
  expansion, because `warn` and `ignore` permit every package the profile does
  not list and the filter then copies the upstream index through verbatim. That
  document is the trust downgrade above paid for no filtering, and it is the
  one shape where a control the operator believes they set makes the host
  strictly less safe than having written no profile at all.
- **An apt entry naming a binary package.** Membership for apt closes on the
  source, so an entry spelled `nginx-common` or `libexpat1` matches no
  paragraph in the index it governs and the host is told the package does not
  exist. The failure is availability rather than disclosure — nothing outside
  the class is offered — but it is silent, arrives as `kept back` on a package
  the operator listed themselves, and is the shape most likely to get a control
  turned off. `--from-origin` writes source names and `bodega profile check`
  reports the divergence; neither is a runtime gate, so an entry hand-written
  under a binary name is caught at `check` time or not at all.

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
