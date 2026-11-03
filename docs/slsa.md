# SLSA

bodega is built against two tracks of [SLSA](https://slsa.dev), and sits at a different level on each:

| Track                                                            | What it covers                                    | Where bodega stands                                                                       |
| ---------------------------------------------------------------- | ------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| [Dependency track](https://slsa.dev/spec/draft/dependency-track) | the third-party packages bodega admits and serves | Level 2 is the target, met with the gaps listed below. Level 3 is out of scope by design. |
| [Build track](https://slsa.dev/spec/v1.2/build-track-basics)     | the release binaries of bodega itself             | Level 2 by construction. Level 3 is the aim and is not yet proven.                        |

The Dependency track is a working draft: the page says "This document may be modified, replaced, or discarded at any time", and it is not part of SLSA 1.2. bodega tracks it at [`4d3f9d44`](https://github.com/slsa-framework/slsa/blob/4d3f9d44a803aaa52eef08fdafd04a7409c263e7/spec/dependency-provenance.md) of slsa-framework/slsa, read on November 2, 2026 (`DraftRevision` in `internal/attest/attest.go`); [Spec drift](#spec-drift) says how bodega follows the draft as it changes.

## Dependency track Level 2

Level 2 asks for a controlled ingestion path: every dependency enters through one platform, which checks it and signs a record of the decision. bodega is that platform. The following table maps each Level 1 and Level 2 requirement to what meets it.

| Requirement                                                                                      | How bodega meets it                                                                                                                                                                                                                                                                                                     |
| ------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| L1: a provenance for every admitted dependency, by name, version and digest                      | One signed in-toto statement per artifact, emitted when its digest is pinned, on a hosted fetch and on a proxy fill (`internal/attest/emit.go`). See [Attestations](usage.md#attestations).                                                                                                                             |
| L2: the platform is the ingestion path, and its identity is in every provenance                  | Clients fetch through bodega's routes in hosted or proxy mode. `bodega doctor` reports client configuration that reaches around it. Each statement carries `ingestionPlatform.id`, from `attestation_platform_id` or the public URL.                                                                                    |
| L2: integrity verified at ingestion; a failure is refused                                        | SHA-256 is pinned on first fetch and checked on every later one; a mismatch answers 502 with reason `checksum` and is not served.                                                                                                                                                                                       |
| L2: a publisher signature, when one is published, verified against the publisher's identity      | npm Sigstore bundles and GitHub release attestations are verified against the Sigstore trusted root ([Upstream provenance](usage.md#bodega-policy-provenance-setlist)). The outcome is recorded in `publisherSignature` and `upstreamProvenance`, and an upstream that publishes nothing is recorded as `unavailable`.  |
| L2: admission policy recorded, with its identity, version, time and verdict, bound to the digest | Every decision writes an [admission row](usage.md#admission-decisions) with each check's outcome and a `policy_digest` over the rules in force. The statement copies them into `policyEvaluations`, and the signer re-reads the row before signing, refusing to sign a version whose newest decision is not `admitted`. |
| L2: transitive dependencies admitted through the same controls                                   | A proxy fill of a versioned artifact runs the same checks as a direct fetch and writes the same admission row.                                                                                                                                                                                                          |
| L2: the provenance is signed                                                                     | DSSE envelopes signed with an [attestation key](usage.md#attestation-signing-key) used for nothing else, so a stolen key cannot sign an apt `InRelease` or a pkg catalog.                                                                                                                                               |

### Gaps

These are where bodega falls short of Level 2 as the draft reads today. Each one is either tracked by an open issue or a boundary bodega keeps by design:

- **Unsigned when the key or the table is missing.** With no attestation key installed, or with `audit_sink` set to `syslog` or `jsonl`, nothing is signed. The server says so once at startup, and the artifact is still served. By design: installing the key and choosing the audit store are the operator's decisions.
- **Clone-mode git carries no upstream digest.** bodega builds the bundle locally at package time, so there are no upstream bytes to pin, and `git bundle create` is not byte-for-byte reproducible. A git entry fetched as a release archive is pinned normally. By design; [Threat model](threat-model.md) explains the boundary.
- **Publisher signatures are verified for npm and GitHub releases only.** PyPI attestations (PEP 740), the Go checksum database and Helm `.prov` files are not checked at admission, so those types always record `unavailable`. The go command still verifies modules against the checksum database bodega relays. Tracked in [#273](https://github.com/ravinald/bodega/issues/273) (PyPI), [#274](https://github.com/ravinald/bodega/issues/274) (Go) and [#275](https://github.com/ravinald/bodega/issues/275) (Helm).
- **`resolvedFrom` is absent where bodega cannot establish the parent's digest.** The draft requires it for a transitive dependency at L2. bodega leaves it out of a proxy fill of a version with no manifest entry, whose parent the server never sees; of a child signed before its parent had a SHA-256 pinned, because the envelope is not re-signed and `bodega attest backfill` skips an object that already has one; of a reference whose type and name hold more than one distinct pinned SHA-256; of a pypi closure member whose only parents are source distributions or marker-conditioned requirements; and of every statement signed before parent digests were recorded. `requiredBy` names each such parent with the reason. [Attestations](usage.md#attestations) lists the cases.
- **The build side is the operator's.** Level 2 also requires the consuming build to resolve only through the platform, with versions pinned. `bodega doctor --configure` and the [setup script](usage.md#setup-script) write that configuration, and `bodega pin` pins a host, but bodega cannot see a build it is not asked to serve. By design: the requirement falls on the ingestor, not the platform.

## Beyond Level 2: bypass detection

Level 2 concedes that "a determined developer or build can still bypass the configured path". bodega goes past it with [host inventory reconciliation](usage.md#inventory): osquery reports what each host installed, and bodega compares that with its own record of what it served the host and what it refused. A component bodega refused, never served, or served to a different identity is a finding, and a host that stops reporting is a finding too.

This is the control [S2C2F](https://github.com/ossf/s2c2f/blob/main/specification/framework.md) names as AUD-2, "Audit that developers are consuming OSS through the approved ingestion method". The path to Level 3 is egress control, and reconciliation supports it in two ways:

- It shows where bypass happens, so an operator knows which hosts and package managers an egress rule has to cover.
- Once egress is restricted, it is the evidence that the restriction holds: a host that installed something bodega never served got it some other way.

It is not Level 3 and does not stand in for it. Level 3 requires that bypass be prevented, "not just detect[ed] after the fact", and the draft says the detect-only signal is "subsumed at L3 by structural enforcement". osquery runs as root on the host it reports on, so it catches drift and process bypass, not an attacker with root. [Host inventory reconciliation](threat-model.md#host-inventory-reconciliation) states the full limits.

## What Level 3 requires that bodega does not provide

Level 3 is out of scope because each remaining requirement needs something outside one bodega process:

| Level 3 requirement                                                | Why bodega does not meet it                                                                                                                                                   |
| ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Bypass blocked by network policy, not detected                     | Egress control belongs to the network. Restrict hosts to bodega with a firewall or an endpoint product's firewall policy; reconciliation then reports what still got through. |
| Signing key unreachable from any process that runs dependency code | `bodega build run` executes upstream build steps on the same host that holds the attestation key. Meeting this takes a separate signer process.                               |
| Each dependency's ingestion isolated from every other's            | Builds share one host and one filesystem; there is no per-dependency sandbox.                                                                                                 |
| Signatures recorded in a transparency log                          | Not implemented.                                                                                                                                                              |
| At least one upstream-attestation verdict per provenance           | Met in form: `upstreamProvenance` is always recorded, with `availability: unavailable` when nothing was published.                                                            |

A compromised bodega host is out of scope in the [threat model](threat-model.md), and Level 3's isolation requirements are the ones that would matter there. [What an attestation proves](threat-model.md#what-an-attestation-proves) states what a verified statement says and what it cannot.

## bodega's own releases

Releases build on GitHub-hosted runners in a reusable workflow, `.github/workflows/release-build.yml`, which `release.yml` calls only after `ci.yml`'s gate has passed on the tagged commit. The workflow signs `checksums-sha256.txt` with cosign keyless and attests every file it lists with `actions/attest`, so each archive, package and SBOM carries build provenance signed by the platform rather than by a key a maintainer holds. GitHub describes that as Build Level 2; the reusable workflow, which isolates signing from the caller, is the step toward Level 3.

What is not yet proven, tracked in [#278](https://github.com/ravinald/bodega/issues/278):

- **No release has been cut,** so the provenance has never been produced or verified outside a snapshot build.
- **The `release` environment carries no protection rule yet.** The build job names it, and GitHub creates an environment with no required reviewer the first time a job does.

[Verifying a release](../SECURITY.md#verifying-a-release) shows the commands.

## Spec drift

The draft changed after bodega's predicate was written. Each change is tracked in [#277](https://github.com/ravinald/bodega/issues/277), and at the revision `DraftRevision` names, every field bodega emits under the draft's name follows the draft. `requiredBy` is bodega's own addition beside them.

The predicate type, `https://slsa.dev/dependency/v1`, is one constant in `internal/attest/attest.go`, so a rename costs one line. Field changes need a re-emit, which the [decision to track the draft](design.md#attestations) accepted as the price of using it before approval.
