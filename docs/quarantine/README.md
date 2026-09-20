# Quarantining a compromised release

A version you already mirror turns out to be malicious. Upstream pulls it, an advisory lands, and until you act every client pointed at your mirror is one `install` away from the payload.

The window is short and you will usually miss it. In the shape these walkthroughs use, the bad build was live for a little under two hours before upstream revoked it, and the fix shipped the next day. A mirror that resolved a dist-tag during those two hours is now serving the payload from your own cache, on your own network, with your name on it.

The package is fictional: `@example-corp/widget-cli`, a scoped npm CLI mirrored on a single entry tracking the `latest` dist-tag. Nothing else is. Every flag, endpoint, and keystroke here is what bodega ships.

The response has three steps, and each is a scenario in all three walkthroughs:

1. **Quarantine the bad version, pin a known-good one.** Tombstone `1.5.0` with `hidden` and `frozen`, and point the active entry at `1.4.2`.
2. **Relax back to `latest`, keep the tombstone.** `1.5.1` is out. New releases should flow again without babysitting, and `1.5.0` should stay gone regardless of what upstream does next.
3. **Constrain to `>= 1.5.1`.** Stop trusting upstream's `latest` pointer and put the policy on the manifest, where an auditor can read it.

Every walkthrough starts from the same state: one entry for `@example-corp/widget-cli` tracking `latest`, fetched just before the bad build shipped. All three end with a manifest that allows `1.5.1` and up and denies `1.5.0` forever.

## What bodega gives you

Bodega stores every package as a `PackageManifest`, a JSON object listing one or more `VersionEntry` records. Each version carries lifecycle flags the mirror enforces at request time:

- **`hidden`** — the version is tombstoned. The server 404s on tarball requests and scrubs the entry from the packument it hands to clients. Use it for "this specific build is poisoned; do not serve it."
- **`frozen`** — the build pipeline won't touch the entry. `bodega build fetch` skips it, `bodega pkg delete` refuses it, and `bodega pkg edit` rejects metadata changes. Use it for "I've decided this is the version; don't let anyone's automation nudge it."
- **`version_constraint`** — a package-level gate. Combined with a baseline version (`1.5.1` with `compatible`, for example), the server 403s on tarball requests below the baseline and strips below-baseline versions from packuments. Use it for "allow anything at or after this version, reject anything earlier."

Those three flags, applied to the right entries in the right order, walk the whole arc: quarantine the bad version, pin a known-good one, then relax back to normal tracking without forgetting what you quarantined.

## Three ways to do it

You can operate a bodega mirror through any of three administrative surfaces. They are not equivalents; they are different tools for different moments.

| Surface | When it fits                                                                                                          | Walkthrough                           |
| ------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| **CLI** | Runbooks, automation, the fastest path when you're on the box                                                         | [Quarantining from the shell](cli.md) |
| **TUI** | Interactive triage, when you want the tree and the details panel side by side                                         | [Quarantining from the TUI](tui.md)   |
| **API** | When bodega is one link in a bigger pipeline: a ticketing system kicking an action, a GitOps agent reconciling config | [Quarantining over HTTP](api.md)      |

## What bodega does not do

Three limits decide what else has to happen while you work:

- **Bodega is not a vulnerability scanner.** It does not know `1.5.0` is compromised. You tell it. Your advisory feed and the gates in [Where the signal comes from](#where-the-signal-comes-from) decide; bodega enforces the decision.
- **Bodega does not rotate credentials.** If the bad version ran anywhere before you quarantined it, everything it could read is compromised. Scan every host that could have installed it and rotate every token reachable from those hosts. That is a separate job and a separate tool.
- **Bodega does not retroactively unpoison.** A tombstone stops the bytes being served; it does not remove them. If the tarball is already in your cache, delete the object as well. Upstream unpublishing the bad version is luck, not a control.

## Where the signal comes from

None of this starts until something tells you `1.5.0` is bad. Three things shorten that gap, and all three ship in the box:

- **`bodega policy age`** sets a minimum publish age. A fresh install enforces a seven-day cooldown on npm and pypi in `warn` mode. Malicious versions are usually withdrawn within days, so a fetch that waits a week gets the withdrawal instead of the payload. `bodega policy age set npm 7d block` makes it refuse rather than report.
- **`bodega policy osv`** matches advisories against what you mirror. It is empty on a fresh install; `bodega policy osv set npm warn` starts it.
- **Your own feed** is whatever your organization already subscribes to. Wire its output into whichever process decides what to `hide` and what to `freeze`.

Neither gate would have caught a two-hour window on its own. The cooldown would have kept `1.5.0` out of the mirror entirely, which is the point: the control that works here runs before you know anything.
