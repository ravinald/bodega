# Bitwarden case study: CLI walkthrough

This walks through three scenarios on the `@bitwarden/cli` compromise using `bodega` from a shell. Start with [bitwarden-supply-chain.md](bitwarden-supply-chain.md) if you want the incident background.

## Starting state

Assume the mirror was initialized with a single floating-ref entry for `@bitwarden/cli`:

```bash
bodega pkg create npm @bitwarden/cli
#   Package name: @bitwarden/cli
#   Version: latest
#   Registry URL: (blank → registry.npmjs.org)
```

Which produced this manifest on disk:

```json
{
  "config_version": 1,
  "name": "@bitwarden/cli",
  "type": "npm",
  "versions": [
    {"version": "latest"}
  ]
}
```

Tracking `latest` is fine in normal operation — bodega's builder resolves the dist-tag on every `build fetch` and pulls whatever the registry has today. The trouble with this shape during a supply-chain incident is that it offers no policy knobs: there's nothing to deny, nothing to constrain, no tombstone.

Every scenario below replaces this entry with something more deliberate.

## Scenario 1: quarantine 2026.4.0, pin to 2026.3.0

Objective: refuse to serve `2026.4.0` forever, and while you figure out what you actually want to track long-term, pin to the last pre-incident release.

```bash
bodega pkg edit npm @bitwarden/cli
```

That opens the manifest in `$EDITOR`. Replace it with:

```json
{
  "config_version": 1,
  "name": "@bitwarden/cli",
  "type": "npm",
  "description": "Bitwarden CLI — quarantined 2026.4.0 per socket.dev advisory",
  "versions": [
    {"version": "2026.3.0", "mode": "hosted", "frozen": true},
    {
      "version": "2026.4.0",
      "mode": "hosted",
      "hidden": true,
      "frozen": true,
      "description": "Supply-chain compromise; unpublished from npm 2026-04-23"
    }
  ]
}
```

Save. Bodega runs validation and the upstream allow-list check before persisting; any failure leaves the temp buffer on disk so you can retry without re-typing.

What each piece does:

- `2026.3.0` entry pins the version that clients will actually resolve. `frozen: true` prevents the builder from fetching a different version of this entry; `mode: hosted` means "serve from local cache, don't proxy upstream."
- `2026.4.0` entry is a tombstone. `hidden: true` makes the server 404 this specific version on both tarball and packument requests. `frozen: true` is belt-and-suspenders: it prevents another operator (or a well-meaning script) from flipping the hidden flag back off.

Fetch the known-good tarball into the cache if you haven't already:

```bash
bodega build fetch npm @bitwarden/cli
bodega build upload npm
```

Verify the audit trail:

```bash
bodega audit events --type edit --actor $USER
```

You should see two rows for `@bitwarden/cli` with a JSON diff in the details column showing the version changes.

Test from a client. Any npm client pointing at your bodega instance should:

- `npm install @bitwarden/cli@2026.3.0` → succeeds.
- `npm install @bitwarden/cli@2026.4.0` → 404.
- `npm install @bitwarden/cli` (no version) → resolves via the packument, which doesn't list `2026.4.0` at all, so client picks `2026.3.0`.

## Scenario 2: relax to latest tracking, keep the tombstone

Objective: the incident has stabilized, `2026.4.1` is out, you want fresh releases to flow in again without babysitting. But `2026.4.0` is still a tombstone — it doesn't come back.

```bash
bodega pkg edit npm @bitwarden/cli
```

Replace with:

```json
{
  "config_version": 1,
  "name": "@bitwarden/cli",
  "type": "npm",
  "description": "Bitwarden CLI — tracking latest, 2026.4.0 quarantined",
  "versions": [
    {"version": "latest"},
    {
      "version": "2026.4.0",
      "mode": "hosted",
      "hidden": true,
      "frozen": true,
      "description": "Supply-chain compromise; unpublished from npm 2026-04-23"
    }
  ]
}
```

The first entry is back to the floating dist-tag — on next `build fetch` it resolves to whatever `@bitwarden/cli@latest` points at upstream (currently `2026.4.1`). The second entry is the same tombstone as before.

Two things to notice:

- `2026.4.0`'s tombstone survives because the manifest still carries it. If `latest` ever pointed back at `2026.4.0` for whatever reason (attacker got access again, mirror glitch, whatever), the hidden flag would still 404 the tarball.
- Ordering matters for `packageMode`. Bodega derives the package-level mode from the first version entry. `{version: "latest"}` with no explicit `mode` defaults to `hosted`, which is what we want — `hosted` is a policy boundary, not a policy statement.

Fetch the new latest:

```bash
bodega build fetch npm @bitwarden/cli
bodega build upload npm
```

Client behavior now:

- `npm install @bitwarden/cli` → packument (with `2026.4.0` stripped) resolves `latest` to `2026.4.1`. Tarball request succeeds.
- `npm install @bitwarden/cli@2026.4.0` → 404 (tombstone still in effect).

## Scenario 3: constrain to `>= 2026.4.1`

Objective: express the policy directly on the manifest instead of relying on the upstream registry's `latest` pointer. Useful when you want bodega to reject below-baseline versions even if someone explicitly requests them, and useful for compliance audits that ask "prove you're blocking everything before the fix."

This uses `version_constraint` — the same mechanism the gomod handler has used for a while, extended to npm in v0.2.0.

```bash
bodega pkg edit npm @bitwarden/cli
```

Replace with:

```json
{
  "config_version": 1,
  "name": "@bitwarden/cli",
  "type": "npm",
  "description": "Bitwarden CLI — pinned to >= 2026.4.1",
  "versions": [
    {
      "version": "2026.4.1",
      "mode": "hosted",
      "version_constraint": "compatible"
    },
    {
      "version": "2026.4.0",
      "mode": "hosted",
      "hidden": true,
      "frozen": true,
      "description": "Supply-chain compromise; unpublished from npm 2026-04-23"
    }
  ]
}
```

The first entry is the constraint-bearer. `version_constraint: "compatible"` combined with the baseline `2026.4.1` tells the handler: "accept this version or anything higher; reject anything lower." The second entry keeps the tombstone.

Save. Client behavior:

- `npm install @bitwarden/cli@2026.4.1` → succeeds.
- `npm install @bitwarden/cli@2026.5.0` (when Bitwarden eventually ships it) → succeeds without any manifest change.
- `npm install @bitwarden/cli@2026.4.0` → 404 (tombstone wins over constraint).
- `npm install @bitwarden/cli@2026.3.0` → **403** (below constraint — this is the new behavior compared to Scenario 2).
- `npm install @bitwarden/cli` (no version) → packument has everything below `2026.4.1` and the `2026.4.0` tombstone stripped. Client resolves to the newest available version ≥ `2026.4.1`.

The difference between Scenario 2 and Scenario 3 is subtle but load-bearing. In Scenario 2, bodega trusts the upstream's `latest` pointer plus your tombstone list. In Scenario 3, bodega enforces your policy directly on the wire — no matter what `latest` says, no matter what specific version the client asks for, anything below `2026.4.1` is rejected.

## Auditing

Every edit in every scenario above records an `edit` event in the audit database with actor attribution (your OS username, or the user behind a `sudo` invocation). Query it any time:

```bash
# Everything touching @bitwarden/cli.
bodega audit events --name '@bitwarden/cli'

# Just my edits.
bodega audit events --type edit --actor $USER

# Everything in the last hour.
bodega audit events --since $(date -u -d '1 hour ago' +%FT%TZ)
```

The audit trail is append-only. The details column holds a JSON diff of the manifest before and after, so an investigator can reconstruct exactly what policy was in effect at any point in time.

## Rollback

If any edit goes sideways, the temp buffer from the last `bodega pkg edit` is preserved on disk — bodega prints the path when the save fails. For a planned rollback of a successful save, export the current state before you edit:

```bash
bodega pkg export npm @bitwarden/cli > ~/bitwarden-pre-change.json
# ... edit and save ...
# decide to undo:
bodega pkg delete npm @bitwarden/cli
bodega pkg import ~/bitwarden-pre-change.json
```

`pkg export` writes a valid `PackageManifest`; `pkg import` accepts that same shape. They round-trip cleanly.
