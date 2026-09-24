# Threat model

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

  One artifact is not covered, and the gap is in the nature of the artifact
  rather than in the check. **Clone-mode git** ships a bundle this instance
  generates locally at package time, so there are no upstream bytes for a
  digest to attest to, and `git bundle create` is not reproducible
  byte-for-byte: a pin would fail the next repackage rather than catch
  anything. A git entry fetched as a release tarball is covered normally.

  A **pypi** entry pins per closure artifact rather than per manifest entry.
  One approved version installs everything it depends on, and those transitive
  bytes answer to no entry, so the fetch resolves the whole closure, downloads
  it into a wheelhouse of its own, and records a digest per file keyed by
  `pypi/wheels/<filename>` — the key the server serves that wheel under. Every
  file of the closure shows as its own row in `bodega pkg checksum list`, and a
  later fetch producing different bytes for a version already on record is
  refused. The build then reaches no index at all: pip runs with `--no-index`
  and a `--find-links` naming that wheelhouse, under `--require-hashes` against
  the digests the fetch recorded. Redirecting it needs bytes that already hash
  to what was approved.

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

- **A mirrored FreeBSD pkg repository, which pins nothing of bodega's.** A
  `freebsd` entry copies a repository byte for byte, and the attestation it
  carries is FreeBSD's rather than this instance's: `packagesite.pkg` holds
  `packagesite.yaml.sig` and `packagesite.yaml.pub` as tar members, so the
  client verifies the catalogue against the fingerprint of whoever signed it
  upstream — `/usr/share/keys/pkg/trusted/pkg.freebsd.org.2013102301` for
  ports, `/usr/share/keys/pkgbase-15/trusted/` for a `base_release_<n>`
  repository — and every package against the digest that catalogue publishes. bodega records a digest for the
  catalogue archive it fetched and none for the packages under it. That is a
  stronger claim than bodega could make about the same bytes and a narrower
  one than pinning: it says the repository is FreeBSD's, and it says nothing
  about which point in time this mirror is holding.

- **A generated FreeBSD pkg repository, whose attestation is this instance's.**
  A `freebsd` entry marked `generated` holds packages the operator built, so
  there is no upstream catalogue to copy and bodega produces one. It carries
  bodega's signature or none, and the claim shrinks accordingly: the catalogue
  came from this mirror and has not been altered since, and nothing at all is
  said about who built the packages or from what. Generating the catalogue is
  the act that discards FreeBSD's attestation, and no configuration puts it
  back. The per-package digest in a generated catalogue is bodega's own, taken
  over the object as it was stored.

- **A malicious release inside its own withdrawal window.** A fresh install is
  seeded with a minimum publish age of `7d` on `npm` and `pypi`, action `warn`,
  and `bodega serve` names it at startup. The npm and PyPI campaigns of
  2025-2026 were caught and the versions pulled within days of publication, so
  an import that waits a week gets the withdrawal rather than the payload.
  Checksum pinning is the wrong tool for this one: it guarantees today's fetch
  matches the first one, so a compromised _first_ fetch is served faithfully
  and forever with `checksum_verified` beside it. The cooldown is what makes
  the first fetch late enough to be safe.
- **A poisoned first fetch of a ports distfile.** The `distfiles` type does
  not pin what it first fetched. Every distfile's SHA-256 and size are already
  in the ports tree's `distinfo`, which bodega did not write, and a fetch is
  admitted only when both match; a name no `distinfo` lists is refused rather
  than pinned. That is why its default upstream can be plain `http`: an
  attacker on the path can make a fetch fail the check and cannot make one
  pass it. The trust anchor moves to the ports tree the server reads, so a
  tampered tree on the server is served faithfully. Keep it at the revision
  the clients build from, from the same source they take it from.
- **A restricted distfile served on a guess about the client.** A port's
  redistribution terms, and the `distinfo` its fetch checks against, can
  depend on files and variables on the client host rather than in the ports
  tree: the aspell dictionaries include `${LOCALBASE}/etc/aspell.ver`, and
  base `make` lets that file move `DISTINFO_FILE` to another port's `distinfo`
  and set `NO_CDROM`. bodega reads every port against the environment the
  operator declares in `distfiles_environment_variables` and
  `distfiles_environment_files`, and against nothing else. A port that reads a
  path or a variable the declaration does not cover is refused, and when its
  `distinfo` then cannot be placed, every distfile is refused. The server's
  own filesystem never stands in for a client's, and a path missing on the
  server is not evidence that it is missing on a client. A request carries
  only a distinfo name, so what a client's `make` computes never reaches
  admission and cannot widen what bodega releases. The snapshots are held to
  the digest bodega started with; one that changes or cannot be read refuses
  every distfile until its bytes are back or bodega restarts. See [The client
  environment](usage.md#the-client-environment).
- **Compromised upstream releases.** When an upstream package is replaced with
  a malicious version (the canonical example being the npm or PyPI account
  takeovers of recent years), bodega's `pkg hide` and `pkg freeze` operations
  let an operator quarantine the bad version and pin a known-good replacement
  in seconds. The walkthroughs under `docs/quarantine/` cover one such
  compromise end to end.
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
  worth stating plainly: MD5 and a sidecar in the same directory detect an
  edit, not an attacker, because whoever can rewrite the manifest can rewrite
  the sidecar beside it. It catches a hand-edit, a partial restore and a
  half-finished write; it is not a signature.
- **Operator detail in an error body on an unauthenticated route.** The
  package routes a client reads without a token answer a failure with a fixed
  body and write the reason to the log. The reason is written for an operator,
  so it names what an operator needs: the pkg signing key's path and the mode
  that leaves it readable, the `storage_path` root, the s3 bucket and prefix,
  or an upstream URL a manifest may have written with credentials in it. A
  generated FreeBSD catalogue's 500 and a proxied artifact's "upstream does
  not publish this" 404 both follow this rule. `GET /api/v1/status` draws the
  same line with a gate instead: `spool.dir`, `version`, `freebsd.key_error`
  and `backend_entries[].error` are withheld from a caller outside
  `admin_permit_cidr` (see [usage.md](usage.md)). A package route has no admin
  caller to gate for, so its body is fixed for everyone. Three items have
  needed this fix separately, which makes it a class: any handler writing
  `err.Error()` into a response on a route that takes no token reopens it.
  Two bodies still carry error text. A spool refusal's 503 quotes byte counts
  and the config key that bounds them, all of which `/api/v1/status` already
  publishes to every caller. A FreeBSD entry marked both `generated` and
  mirrored answers with a 500 quoting its `url`, which is not yet fixed.
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
- **A ports build reaching the internet through `MASTER_SITE_OVERRIDE`.**
  Serving distfiles over HTTP preempts a port's own sites; it does not replace
  them. `do-fetch.sh` falls through to the port's `MASTER_SITES` on any answer
  other than the bytes, including bodega's refusals, and no `bsd.port.mk`
  setting stops it. Only a `DISTDIR` bodega wrote isolates a build, because
  `do-fetch.sh` skips a file already present before it consults any site. See
  [Mirroring ports distfiles](usage.md#mirroring-ports-distfiles).
- **A ports client that differs from the declared environment.** bodega has no
  view of a client host. It answers every distfiles request as it would answer
  a client in the declared environment, so a client whose `make.conf`,
  environment or files outside the ports tree differ is outside what bodega
  vouches for. That client's own `make` may attribute a file bodega admitted
  to a port whose terms, as its host defines them, forbid redistribution, and
  bodega does not learn of it. Keeping clients inside the declaration is the
  job of configuration management. The declaration covers the fleet only if
  the operator makes it: a value or an alternative left out is one bodega
  never reads. The scan does not evaluate conditions, so where it errs it
  refuses a file a client could have had, not the reverse.
- **Build-time code execution by trusted packages.** A `setup.py` that
  `os.system`s out, an `npm install` lifecycle script, a `cargo build` script
  — all of these run with the build user's privileges and can do anything
  that user can. Bodega controls _which_ packages run; it does not sandbox
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
  filtered index buys is that a _correctly configured_ host is never offered a
  package outside its class, which is what turns a refusal into `kept back`
  instead of an aborted transaction. What refuses the artifacts behind it is
  the request predicate at `/apt/pool/`, which runs on identity rather than on
  what the client's sources say. Read the two together: the index decides what
  a host is told exists, the predicate decides what it may fetch. A suite
  bodega generates from its own catalog is the narrower case: its filtered view
  is served under the suite's own name and picked on identity, so editing the
  file does not reach around it, and what a host reaches by editing is the
  mirrored codename, which is the archive's document and is filtered for
  nobody. The gap
  closes when the token that identifies a host also gates the codename, which
  is not shipped.
- **The chain of trust behind a filtered apt codename.** bodega re-signs it
  with bodega's own key, and what bodega verified before signing is the
  archive's TLS certificate and the SHA256 that the archive's own `Release`
  publishes for the `Packages` beside it. It does not verify the archive's
  `InRelease` signature, because it holds no distro keyring to check one
  against. So a filtered codename's trust ends at the archive's certificate,
  where a _mirrored_ codename forwards the archive's signature untouched and
  the client checks it against the distro keyring already on the host. That is
  a real difference and it is the price of filtering: one URL serves one
  `Release`, and an index bodega narrowed cannot carry a signature over the
  index it narrowed. An operator who wants the upstream signature end to end
  points the host at the mirrored codename and accepts that it is unfiltered.
  Which is why a filtered codename that would filter nothing is refused rather
  than served: an apt rule with a base needs closed membership _and_ `block`
  expansion, because `warn` and `ignore` permit every package the profile does
  not list and the filter then copies the upstream index through verbatim. That
  document is the trust downgrade above paid for no filtering, and it is the
  one case where a control the operator believes they set makes the host
  strictly less safe than having written no profile at all.
- **An apt entry naming a binary package.** Membership for apt closes on the
  source, so an entry spelled `nginx-common` or `libexpat1` matches no
  paragraph in the index it governs and the host is told the package does not
  exist. The failure is availability rather than disclosure, since nothing outside
  the class is offered, but it is silent, arrives as `kept back` on a package
  the operator listed themselves, and is the case most likely to get a control
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
   mirror cannot change _what_ the vendor signs, only _whether_ you cache it.

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

Same reasoning as snap. Flatpak runtimes are bundled, remotes (flathub etc.)
are configured per-host rather than through bodega's allow-list, and updates
happen on a user- or system-triggered cadence that bodega does not see.

### AppImage (with auto-update enabled)

A bare AppImage downloaded once and never updated is fine, because bodega's `binary`
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
- **Set `GOPROXY` to `http://<bodega>/gomod,off`**, never `,direct`. The
  `,off` form makes cache misses fail loudly; `,direct` silently falls
  through to public VCS, defeating the chokepoint.
- **Run `bodega doctor` in CI** as a gate step. Exit 0 is clean, exit 2 is a
  finding, and exit 3 is a run that could not finish: a check whose config or
  audit store would not open reports `SKIPPED` and measured nothing, so
  answering 2 would let "fix these three and we are clean" stand on a posture
  nobody read. 3 outranks 2 when a run produces both. The output is
  tab-aligned and tabwriter-stable, so a pipeline
  can both gate on the exit code and surface the per-check detail in the
  build log. The checks themselves write nothing, but every bodega command
  bootstraps a config file on first run, so a runner holding neither
  `/etc/bodega/config.json` nor `~/.config/bodega/config.json` gains the
  second one (the first, as root) before the first check executes. That file
  and the log directory it names are all a doctor run creates. The posture
  checks open the audit database read-only, so a run against an install one
  release behind neither brings a database into existence nor migrates the
  one it finds: an upgrade is something you schedule, not something a report
  does to you. A host with no install reads `N/A` rather than gaining one, and
  an account that cannot read `/etc/bodega/config.json` or `/var/lib/bodega`
  reads `SKIPPED` with the privilege it needs, rather than `N/A` beside the
  checks that genuinely passed.
- **Declare the environment your ports clients build in** before serving
  distfiles from a stock tree; the empty declaration refuses all of them.
  Start from it, read the unplaced ports bodega logs, confirm each named value
  on a client with base `make -V`, and declare every value and every
  alternative your clients hold. Revisit it when a client's `make.conf`
  changes, an architecture is added, or a package installs a file a port
  includes, such as aspell's `etc/aspell.ver`.
- **Harden the seeded cooldown and add an allow-list.** `bodega policy age
set npm 7d block` turns the shipped `warn` into a refusal once you have
  watched it for a release cycle; `bodega policy add <type> <pattern>`
  constrains what may be fetched at all. Run them on the server, not on the
  clients: they are the install's own posture, and they take effect without a
  restart.

On the bodega host itself, `doctor` adds three checks that read the audit
database rather than the machine. They report `N/A` on a client host with no
install, and `SKIPPED` where this account cannot read what they read:

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

- `docs/design.md` — overall architecture; the proxy and cache chokepoint at the
  center of the security story.
- `docs/usage.md` — operational reference for `pkg hide`, `pkg freeze`, and
  the allow-list policy commands referenced above.
- `docs/quarantine/` — worked example of using
  bodega's controls during an active upstream compromise, across the CLI, the
  TUI and the API.
- `README.md` — the supported package types whose fetches flow through
  bodega's chokepoint.
