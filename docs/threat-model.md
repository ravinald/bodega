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

- **FreeBSD distfiles, which carry neither attestation.** The digest that
  protects a distfile is pinned in the client's own ports tree: a port's
  `distinfo` records a SHA-256 and a size for each distfile, and `make checksum`
  refuses bytes that disagree, wherever they came from. bodega has no distfiles
  type. A distfile proxied through a `binary_upstreams` namespace is pinned on
  first fetch like any other binary, which says only that later fetches match
  the first. What the check is worth is what the tree is worth: `ports.txz`
  served as a `binary` entry is pinned to the digest the release `MANIFEST`
  publishes, and a tree cloned through a `git_upstreams` mirror is as
  trustworthy as the forge it mirrors.

  That makes three trust stories for one operating system, and a reader should
  not assume one covers another. A mirrored pkg repository carries FreeBSD's
  signature and bodega adds nothing to it. A generated repository carries
  bodega's and nothing of FreeBSD's. Distfiles carry no signature from either:
  they rest on the `distinfo` digest in the client's ports tree, and are as
  sound as the route that tree arrived by.

- **A malicious release inside its own withdrawal window.** A fresh install is
  seeded with a minimum publish age of `7d` on `npm` and `pypi`, action `warn`,
  and `bodega serve` names it at startup. The npm and PyPI campaigns of
  2025-2026 were caught and the versions pulled within days of publication, so
  an import that waits a week gets the withdrawal rather than the payload.
  Checksum pinning is the wrong tool for this one: it guarantees today's fetch
  matches the first one, so a compromised _first_ fetch is served faithfully
  and forever with `checksum_verified` beside it. The cooldown is what makes
  the first fetch late enough to be safe.
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
- **A manifest field that becomes a path.** A manifest is written by an
  operator, through `pkg create`, `pkg edit`, `pkg import` or the mutation API
  behind its token, or by hand in the store. No anonymous route writes one.
  It is trusted to name what to fetch and where to serve it from, and not
  trusted to choose where on disk or in storage a write lands. A binary
  entry's `filename` override is joined into the build root and the object
  key, so it must be a clean relative path: every manifest write refuses one
  with a `..` or `.` segment, an empty segment, a leading `/`, a `\` or a
  NUL, and the fetch, the upload, the download alias and the key a delete or
  move derives refuse it again for a manifest written before the check. The
  fetch also refuses a version that is not one directory, a package name that
  is not a clean relative path, and a destination that resolves through a
  symlink to outside the configured build root, a link at `binaries/` included. Unchecked, a `filename` of
  `../../../../escaped` writes outside the build root and reports success, and
  planting one takes manifest-write access: an operator's token, or write
  access to the store itself. See [usage.md](usage.md#binary-specific-fields)
  for what an upgrade does with a manifest that already carries one.
- **A secret an operator writes into a manifest.** The rule, in every field:

  - **`url` is the one field bodega holds a credential in.** bodega has no
    other place to configure one per upstream, so a `url` may carry userinfo
    or a query-string token, and the builder and the proxy routes fetch with
    it as written. The store keeps it as written. Every response a caller
    with no token can reach carries it through `manifest.PublicURL`, which
    removes the userinfo, username included, and the whole query and
    fragment. The query goes whole because no parameter name says whether
    its value is a secret. Where URL readers disagree about where the
    authority ends (a scheme-relative `//user@host`, a browser reading
    `https:\\user@host`, curl reading past a `\`, git handing ssh
    everything before the host of `ssh://a#b@host/` or `a?b@host:repo`,
    and decoding `%40` first), it cuts at the widest reading.
  - **`metadata` is public by contract.** bodega never fetches with a
    metadata value. Every value is published, except that a value written
    as a URL (a scheme followed by `/` or `\`, `http:` or `https:`, or
    `//host`) goes through the same cut as `url`, whatever its key, except
    the five apt keys below, which are refused rather than cut. The test is
    on the whole value: a URL inside longer text (`see
    https://user:secret@host/`), a schemeless `user:secret@host/x` and a
    secret that is not part of a URL are published as written.
  - **`metadata.attestation_uri` takes no credential.** Its endpoint answers
    an `http(s)` uri with a 302 whose `Location` the client follows, so the
    uri cannot be cut without breaking the fetch. Admission refuses one
    carrying userinfo, a query or a fragment, and the endpoint answers one
    already stored with a 502 rather than a redirect. An `s3://` uri is read
    by bodega with its own backend credentials and never reaches the client.
  - **An apt entry's `Architecture`, `_pool_path`, `_md5`, `_sha1` and
    `_sha256` take no credential.** The apt index publishes them as what
    they are: `Architecture` names the index paths and the `Architectures`
    line in `Release` and the signed `InRelease`, `_pool_path` is the
    `Filename` apt fetches, and the digests are what apt checks the bytes
    against. Cutting a credential out of one would rename an index or
    publish a checksum nothing matches, so admission refuses a URL with
    userinfo, a query or a fragment in any of them, and an entry already
    stored with one reaches no index. Each rebuild logs it by key, never by
    value.
  - **Every other field is public by contract**: names, versions,
    descriptions, dependencies (an npm `git+https://token@host/` spec
    included), checksums, suites, storage names, metadata keys,
    `build_cmd` and `build_env`. The read routes return each as written,
    and the npm packument, the cargo index, `index.yaml`, the apt stanza
    and `/api/v1/status` carry the names, versions, descriptions and
    dependencies among them. A token in a `build_cmd` is published to
    every caller.

  The rule is enforced where each response is built, not where the manifest
  is loaded, so a manifest stored before the rule existed is covered without
  being rewritten. A handler writing `err.Error()` into a public response
  is a new instance of this class, because a manifest check quotes fields
  verbatim for the operator; a test for one asserts the secret is absent
  from the body, and a test of a redirect asserts it on the `Location`
  header separately, since that is a different code path carrying the same
  string.
- **A secret an operator writes into configuration.** `gomod_upstream`,
  `npm_upstream`, `pypi_upstream`, `cargo_upstream`, `cargo_dl_upstream`
  and each `apt_upstreams` `url` accept userinfo, so a private index can be
  configured as `https://user:secret@pypi.internal`, and bodega fetches with
  it as written. `git_upstreams` and `binary_upstreams` refuse userinfo, a
  query and a fragment when the config loads. The manifest `url` rule
  applies unchanged: a response a caller with no token can reach names a
  configured upstream only through `manifest.PublicURL`. One route quotes
  one today: a pypi wheel no manifest names answers 404 naming the simple
  index bodega would have read, cut, and logs the refusal with the index
  through `url.Redacted`, which masks the password and keeps the username.
  Every other configured upstream reaches the operator log (the fetch
  failure lines carry it as written), the discovery row and the audit
  record, and no response body. `/api/v1/audit` and `/api/v1/config`
  answer inside `admin_permit_cidr` only, so the stored URL is behind the
  same boundary as a stored manifest `url`.

  What a caller sees depends on which of four boundaries the response sits
  behind, and a bearer token decides only the last of them:

  - **Anonymous: every caller.** The four `/api/v1/packages` read routes and
    the web UI that reads them; the attestation route; the apt `Packages`
    stanza, which copies every metadata key, and `Release` and `InRelease`,
    which name every architecture; `/api/v1/status`, which blanks
    `freebsd.refused[].error` (it quotes the url), `spool.dir`, `version`,
    `freebsd.key_error` and `backend_entries[].error` outside
    `admin_permit_cidr` (see [usage.md](usage.md)); and the package routes
    (`/apt/`, `/freebsd/`, `/binaries/` and the rest), which answer a
    failure with a fixed body and put the reason, url included, in the log.
    npm, cargo and helm indexes are built from bodega's own base URL and
    carry no manifest `url` or metadata. One anonymous body quotes a
    config value rather than a manifest one: the pypi 404 for a
    distribution no manifest names prints `pypi_upstream` as written, which
    is open as B95.
  - **Admin range: no token needed.** Inside `admin_permit_cidr` the
    `/api/v1/status` fields above are returned in full with no
    `Authorization` header. `/api/v1/audit` is gated the same way and
    returns the before and after manifest JSON a mutation recorded, as
    written; `/api/v1/config`, `/api/v1/tokens`, `/api/v1/policies` and
    `/api/v1/profiles/{name}/pins` share the gate and emit no version
    `url`. `admin_permit_cidr` is therefore the boundary for the stored
    credential on reads, not the token.
  - **Mutations: the existing CIDR and token rules.** Create and the hide and
    freeze toggles return the whole manifest as stored. A mutation needs an
    address in `admin_permit_cidr`, and a bearer token only once that range
    reaches past loopback; a loopback-only server takes mutations from
    localhost with no token.
  - **Operator host and backend.** `bodega show pkg`, `pkg export`,
    `pkg edit`, the TUI, the builder's output, repair and validation
    diagnostics and the server log print or serialize the manifest as
    written. They read the store or the log directly, so filesystem and
    backend permissions are the boundary. A binary entry with no `filename`
    is stored under its url's last segment, so for a url with no path, or a
    query-string token, the object key carries the credential and anyone who
    can list that bucket or directory reads it. The read routes publish
    every binary entry with a download alias of its own, `~/<tag>/<display>`,
    since a stored name is served from whichever entry of its version comes
    first and so does not stay with one entry. The display part comes from
    the published url and the tag is an HMAC of the version, the recorded
    backend and the stored name keyed by the server's token pepper, and
    `/binaries/` maps it back to that entry's key on that entry's backend
    without publishing the key. The key is there so that the published name
    cannot be used to confirm a guessed credential offline. An alias spans
    three path segments and a stored name is one, so the route never reads
    either as the other: an alias whose entry is gone or has moved backend,
    or whose pepper has been rotated away, is a 404, never a request for an
    object stored under that spelling or for another entry holding the same
    key on another backend. A server with no pepper publishes no binary
    download link: every entry gets the all-zero withheld alias, which is a
    404, because a stored name would follow the order of the manifest rather
    than the entry. The TUI links by the same alias, so it reads the pepper
    file as well as the manifest store; where it cannot, it links a stored
    name only when the route serves that name from the entry's own backend,
    and otherwise shows no link.

  A manifest read from the API and pushed back through an import arrives
  without the userinfo, query and fragment of its `url`.
- **A replacement read while it is being written.** On a `local` backend a
  replacement is written to a staging file inside a directory of its own, and
  both are reduced to their mode bits before the first byte lands: every ACL
  entry the storage root handed down is taken away, so the body is readable by
  the server's own user and nobody else until the rename publishes it under
  the object's own access state. On ZFS a `chmod` alone does that only at some
  settings of the dataset's `aclmode`, which bodega's config does not set and
  no error reports: `discard`, the default, drops the inherited entries,
  `restricted` refuses the `chmod`, and `passthrough` keeps them, which would
  let `www` read a replacement mid-write from a root carrying
  `user:www:rx:fd:allow`, including one whose object denies `www`. Bodega
  therefore sets the trivial NFSv4 ACL itself and reads it back, whatever the
  property says, and a staging inode that still carries a named or inheritable
  entry fails the write and leaves the previous object as it was.
  `zfs get aclmode,aclinherit <dataset>` shows what a dataset has. The
  property still decides what a published object carries: under
  `aclinherit=passthrough` a fresh object keeps what its directory hands down,
  as a file created there by hand would. On FreeBSD a filesystem that keeps
  no ACL at all, a UFS mounted without `acls` or `nfsv4acls`, gives that
  read-back nothing to confirm, so every replacement there fails before its
  body is written and leaves the previous object in place; a fresh object
  still lands. Keep a FreeBSD storage root on ZFS or on a UFS mounted with
  either option.
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
- **What a cache miss tells the upstream.** `proxy_cache_enabled: true` makes
  bodega a cache, and a miss is a request from bodega's egress address to the
  entry's `url` with the missing path appended. Whoever runs that host learns
  what this instance asked for and when. For `freebsd` the `url` is a
  repository root with the ABI already in it, so a miss on
  `https://pkg.FreeBSD.org/FreeBSD:15:aarch64/base_release_1` discloses this
  instance's ABI, the repository name and the package path. What reaches
  upstream depends on the entry's mode:
  - A `proxy` entry fetches every miss, with or without
    `proxy_cache_enabled`: the catalogue on every `pkg update` once
    `metadata_ttl` lapses, and each package on first install.
  - A hosted `freebsd` entry, mirrored or generated, never fetches the
    repository-root names pkg asks for by default. `meta.conf`, `data.pkg`
    and `packagesite.pkg` come from the store, or from the build for a
    generated entry, or answer 404, and so do the names pkg falls back to when
    they are missing (`meta.txz`, and `data` or `packagesite` under a
    `packing_format` extension). A `pkg update` that asks only for those
    names sends nothing upstream, finished mirror or not. A package the store
    does not hold is still fetched on a miss when `proxy_cache_enabled` is
    `true`, which sends the ABI, the repository and that package's path.
  - The names are pkg's defaults, not fixed. pkg asks for its catalogue
    archives by the `data` and `manifests` keys of the `meta.conf` it read,
    as `<name>.pkg` then `<name>.<packing_format>`. A generated entry writes
    the defaults, so its clients ask for nothing else. A mirrored entry serves
    upstream's `meta.conf` as stored, so a mirror of a repository whose
    `meta.conf` renames either archive sends its clients to names bodega does
    not guard. With `proxy_cache_enabled: true` each of those is a cache miss:
    it discloses the ABI and repository on every `pkg update`, and if
    upstream serves the name, the client reads upstream's catalogue rather
    than the mirror's. No `pkg.FreeBSD.org` repository renames either
    archive; a private one might.
  - With `proxy_cache_enabled: false`, a hosted entry sends nothing upstream
    at request time. The mirror run that fills it (`bodega build fetch`) still
    fetches the catalogue and every object it names, on the operator's
    schedule rather than a client's.

  An operator who wants a mirror no client request can make phone home sets
  `proxy_cache_enabled: false` and accepts that a package the mirror lacks is
  a 404.

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
