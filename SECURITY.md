# Security policy

## Reporting a vulnerability

Email **ravi@cow.org** with details. Acknowledgement within 72 hours, with an
estimated remediation timeline to follow. Please do not file public issues for
security problems.

If you'd prefer encrypted reporting, request a PGP key over email and one will
be provided.

## Supported versions

The latest tagged release on `main`. Older releases receive fixes only for
critical (CVSS 9.0+) issues.

## Verifying a release

Each release signs `checksums-sha256.txt` with cosign keyless and attests
every file it lists (archives, packages and SBOMs) with SLSA build
provenance, which GitHub describes as Build Level 2; [SLSA](docs/slsa.md)
states what is and is not yet proven. Both are issued to the reusable workflow
`.github/workflows/release-build.yml`, which `release.yml` calls only after
`ci.yml`'s gate has passed on the tagged commit. The release stays a draft
until `scripts/verify-release.sh` passes against it, and `release.yml`
publishes it only then. `release-verify.yml` re-checks the newest published
release daily.

From a clone checked out at the release tag, the script checks every asset:
both signature formats on the checksum file, the SHA-256 of every file it
lists, and the attestation of each one.

```bash
VERSION=v0.2.0
git checkout "$VERSION"
scripts/verify-release.sh "$VERSION"
```

It needs `gh`, `cosign`, and `sha256sum` or `shasum`. `--dir <path>` checks
files already downloaded instead, and `--latest` checks the newest published
release. Exit codes: `0` every check passed, `1` a check failed, `2` a usage
or input error or a missing tool, `3` `--latest` found no published release.

Without a clone, check the signature, then the checksums, then the
provenance by hand:

```bash
VERSION=v0.2.0
gh release download "$VERSION" --repo ravinald/bodega
cosign verify-blob \
  --bundle checksums-sha256.txt.sigstore.json \
  --certificate-identity "https://github.com/ravinald/bodega/.github/workflows/release-build.yml@refs/tags/$VERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums-sha256.txt
```

A cosign release that cannot read a Sigstore bundle checks the detached
signature and certificate instead:

```bash
cosign verify-blob \
  --certificate checksums-sha256.txt.pem \
  --signature checksums-sha256.txt.sig \
  --certificate-identity "https://github.com/ravinald/bodega/.github/workflows/release-build.yml@refs/tags/$VERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums-sha256.txt
```

Then check the checksums and the provenance of each file you install:

```bash
sha256sum --ignore-missing -c checksums-sha256.txt
gh attestation verify "bodega_${VERSION#v}_linux_amd64.tar.gz" \
  --repo ravinald/bodega \
  --signer-workflow ravinald/bodega/.github/workflows/release-build.yml \
  --source-ref "refs/tags/$VERSION"
```

A failure from any of these means the file did not come from this
repository's release workflow at that tag. Do not install it, and report it
as above.

## Scope

In scope:

- The `bodega` binary and its HTTP server
- Build/fetch pipelines (`bodega build fetch|run|upload|sync`)
- Handling of upstream artifacts (proxy/cache, manifest integrity, GPG flow,
  TLS, allow-list enforcement, discovery log)
- Audit / token / policy storage layer
- Release artifacts published from this repository

Out of scope:

- Bugs in third-party clients (apt, pip, cargo, go, npm, helm, git)
- Bugs in upstream package registries that bodega proxies
- The host operating system or container runtime that bodega runs on
- Misuse of operator-controlled config (e.g. an allow-list that's too broad,
  or an `open` upstream namespace pointed at a public forge)
