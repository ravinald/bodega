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
provenance. Both are issued to the reusable workflow
`.github/workflows/release-build.yml`, which `release.yml` calls only after
`ci.yml`'s gate has passed on the tagged commit. Check the signature, then the
checksums, then the provenance:

```bash
VERSION=v0.2.0
gh release download "$VERSION" --repo ravinald/bodega
cosign verify-blob \
  --certificate checksums-sha256.txt.pem \
  --signature checksums-sha256.txt.sig \
  --certificate-identity "https://github.com/ravinald/bodega/.github/workflows/release-build.yml@refs/tags/$VERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums-sha256.txt
sha256sum --ignore-missing -c checksums-sha256.txt
gh attestation verify "bodega_${VERSION#v}_linux_amd64.tar.gz" \
  --repo ravinald/bodega \
  --signer-workflow ravinald/bodega/.github/workflows/release-build.yml \
  --source-ref "refs/tags/$VERSION"
```

A failure from any of the three means the file did not come from this
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
