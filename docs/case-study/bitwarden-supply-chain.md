# Case study: the @bitwarden/cli supply-chain compromise

On April 22, 2026 between 5:57 PM and 7:30 PM ET, a malicious build of `@bitwarden/cli@2026.4.0` shipped to the public npm registry. Bitwarden's security team detected it, revoked access, and deprecated the release inside that 93-minute window; `2026.4.1` landed the next day as a clean replacement. The compromise arrived through a hijacked GitHub Action — part of the broader "Shai-Hulud" Checkmarx supply-chain campaign, which is its third known iteration as of this writing.

The published analyses — Socket, OX Security, JFrog — agree on the payload shape: a postinstall hook (`bw1.js`) harvested GitHub tokens, npm tokens, SSH keys, shell history, environment variables, and cloud credentials, then exfiltrated them to an attacker-controlled C2 host. Any developer who ran `npm install` against the public registry during the 93-minute window became an entry point for broader compromise of whatever CI/CD systems their tokens could reach. End-user vault data was not affected; this attack targeted the developer tool, not the password-manager service.

This document is about the response side: how a bodega operator, already running a mirror for their organization, would have quarantined the bad version, pinned a known-good one, and reopened the faucet when the fix landed. See [References](#references) at the end for the upstream analysis.

## What bodega gives you

Bodega stores every package as a `PackageManifest` — a JSON object that lists one or more `VersionEntry` records. Each version carries lifecycle flags the mirror actually enforces at request time:

- **`hidden`** — the version is tombstoned. The server 404s on tarball requests and scrubs the entry from the packument it hands to clients. Useful for "this specific build is poisoned; do not serve it."
- **`frozen`** — the build pipeline won't touch the entry. `bodega build fetch` skips it, `bodega pkg delete` refuses it, `bodega pkg edit` rejects metadata changes. Useful for "I've decided this is the version; don't let anyone's automation nudge it."
- **`version_constraint`** — a package-level gate. Combined with a baseline version (e.g. `2026.4.1` with `compatible`), the server 403s on tarball requests below the baseline and strips below-baseline versions from packuments. Useful for "allow anything at or after this version but explicitly reject anything earlier."

Those three flags, applied to the right entries in the right order, let you step through the full incident-response arc: **quarantine the bad version, pin a known-good one, then relax back to normal tracking without forgetting what you quarantined**.

## Three ways to do it

You can operate a bodega mirror through any of three administrative surfaces. They're not equivalents — they're different tools for different moments.

| Surface | When it fits | Walkthrough |
|---|---|---|
| **CLI** | Runbooks, automation, the fastest path when you're on the box | [bitwarden-cli.md](bitwarden-cli.md) |
| **TUI** | Interactive triage, when you want to see the tree and the details panel side by side | [bitwarden-tui.md](bitwarden-tui.md) |
| **API** | When bodega is one link in a bigger pipeline — a ticketing system kicking an action, a GitOps agent reconciling config | [bitwarden-api.md](bitwarden-api.md) |

Each walkthrough covers the same three scenarios:

1. **Quarantine + pin known-good.** Add a `hidden+frozen` tombstone for `2026.4.0`, pin to `2026.3.0`.
2. **Relax to `latest` tracking.** Point the active entry back at the `latest` dist-tag so fresh releases are picked up automatically, while keeping the `2026.4.0` tombstone.
3. **Constrain `>= 2026.4.1`.** Express the policy directly on the manifest: reject anything earlier, allow anything from the fix forward.

The starting state is the same in every walkthrough: a single manifest entry for `@bitwarden/cli` pinned to `latest`, which was fetched (for the sake of the narrative) right before the compromise landed upstream. The ending state, by the end of the third scenario, is a manifest that explicitly allows `>= 2026.4.1` and explicitly denies `2026.4.0` forever.

## What bodega does not do

A few things worth being honest about up front:

- **Bodega is not a vulnerability scanner.** It doesn't know that `@bitwarden/cli@2026.4.0` is compromised on its own. The operator has to tell it. Hook your advisory feed (Socket, GitHub, Snyk, your organization's security team) into whatever process decides what to `hide` or `freeze`.
- **Bodega does not rotate credentials.** If the bad version actually ran on any machine before you quarantined it, the credentials it touched are cooked. Run a host IoC scanner on every machine that could have seen the payload (see [References](#references)). Rotate GitHub, npm, AWS, SSH, and any other tokens that were reachable from those hosts. That's a separate task bodega can't help with.
- **Bodega does not retroactively unpoison.** If a tarball is already in your S3 cache, the quarantine manifest alone does not remove it. The `hidden` flag stops it from being served; deleting the cache key in S3 removes it from existence. For the Bitwarden incident specifically, the npm security team unpublished the bad version before most mirrors pulled it — but that's not something you can rely on.

## Start here

- New to the incident itself: read one of the analyses in [References](#references) below, then pick a walkthrough.
- Running bodega already and need to act right now: go to the [CLI walkthrough](bitwarden-cli.md).
- Building automation around bodega: go to the [API walkthrough](bitwarden-api.md).
- Want to drive this from a terminal with a real cursor: go to the [TUI walkthrough](bitwarden-tui.md).

## References

### Primary

- **Bitwarden** — [official statement on the Checkmarx supply-chain incident](https://community.bitwarden.com/t/bitwarden-statement-on-checkmarx-supply-chain-incident/96127), April 23, 2026. Source of record for the 5:57–7:30 PM ET attack window, the remediation timeline, and Bitwarden's scope assessment (vault data unaffected, developer credentials at risk for anyone who installed the package during the window).
- **CVE** — a CVE was being issued at the time of Bitwarden's statement; check [nvd.nist.gov](https://nvd.nist.gov/) for the assigned identifier under `@bitwarden/cli@2026.4.0`.

### Independent analyses

- **Socket** — [Bitwarden CLI Compromised in Ongoing Checkmarx Supply Chain Campaign](https://socket.dev/blog/bitwarden-cli-compromised). Payload disassembly, C2 infrastructure, IoC list. The most detailed technical writeup.
- **OX Security** — [Shai-Hulud: The Third Coming — Bitwarden CLI Backdoored in Latest Supply Chain Campaign](https://www.ox.security/blog/shai-hulud-bitwarden-cli-supply-chain-attack/). Campaign context and attribution; ties this incident to prior Shai-Hulud iterations.
- **The Hacker News** — [Bitwarden CLI Compromised in Ongoing Checkmarx Supply Chain Campaign](https://thehackernews.com/2026/04/bitwarden-cli-compromised-in-ongoing.html). General-audience summary with a clear timeline.

### Host-level IoC scanning

A host scanner script (`scan.sh`) built against the IoCs from Socket's analysis — payload filename, C2 IP, mutex lock location, exfiltration marker — is useful on any machine that might have installed the bad version during the attack window, regardless of whether bodega caught it at the mirror. Build it from Socket's IoC list or adapt one of the public variants.
