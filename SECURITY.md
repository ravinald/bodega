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
  a `discover_mode: "learn"` window left on indefinitely)
