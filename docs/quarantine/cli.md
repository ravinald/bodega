# Quarantining from the shell

Three scenarios against a compromised `@example-corp/widget-cli`, driven with `bodega` from a shell. [Quarantining a compromised release](README.md) sets up the situation and the flags these scenarios use.

## Starting state

Assume the mirror was initialized with a single floating-ref entry for `@example-corp/widget-cli`:

```bash
bodega pkg create npm @example-corp/widget-cli
#   Package name: @example-corp/widget-cli
#   Version: latest
#   Registry URL: (blank defaults to registry.npmjs.org)
```

Which produced this manifest on disk:

```json
{
  "config_version": 1,
  "name": "@example-corp/widget-cli",
  "type": "npm",
  "versions": [{ "version": "latest" }]
}
```

Tracking `latest` is fine in normal operation: bodega's builder resolves the dist-tag on every `build fetch` and pulls whatever the registry has today. The trouble with this setup during a supply-chain incident is that it offers no policy knobs: there's nothing to deny, nothing to constrain, no tombstone.

Each scenario replaces this entry with something more deliberate.

## Scenario 1: quarantine 1.5.0, pin to 1.4.2

Objective: refuse to serve `1.5.0` forever, and while you figure out what you actually want to track long-term, pin to the last pre-incident release.

```bash
bodega pkg edit npm @example-corp/widget-cli
```

That opens the manifest in `$EDITOR`. Replace it with:

```json
{
  "config_version": 1,
  "name": "@example-corp/widget-cli",
  "type": "npm",
  "description": "widget-cli: quarantined 1.5.0 on advisory",
  "versions": [
    { "version": "1.4.2", "mode": "hosted", "frozen": true },
    {
      "version": "1.5.0",
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

- `1.4.2` entry pins the version that clients will actually resolve. `frozen: true` prevents the builder from fetching a different version of this entry; `mode: hosted` means "serve from local cache, don't proxy upstream."
- `1.5.0` entry is a tombstone. `hidden: true` makes the server 404 this specific version on both tarball and packument requests. `frozen: true` is belt-and-suspenders: it prevents another operator (or a well-meaning script) from flipping the hidden flag back off.

Fetch the known-good tarball into the cache if you haven't already:

```bash
bodega build fetch npm @example-corp/widget-cli
bodega build upload npm
```

Verify the audit trail:

```bash
bodega audit events --type edit --actor $USER
```

You should see two rows for `@example-corp/widget-cli` with a JSON diff in the details column showing the version changes.

Test from a client. Any npm client pointing at your bodega instance should:

- `npm install @example-corp/widget-cli@1.4.2` > succeeds.
- `npm install @example-corp/widget-cli@1.5.0` > 404.
- `npm install @example-corp/widget-cli` (no version) > resolves via the packument, which doesn't list `1.5.0` at all, so client picks `1.4.2`.

## Scenario 2: relax to latest tracking, keep the tombstone

Objective: the incident has stabilized, `1.5.1` is out, you want fresh releases to flow in again without babysitting. But `1.5.0` is still a tombstone, and it does not come back.

```bash
bodega pkg edit npm @example-corp/widget-cli
```

Replace with:

```json
{
  "config_version": 1,
  "name": "@example-corp/widget-cli",
  "type": "npm",
  "description": "widget-cli: tracking latest, 1.5.0 quarantined",
  "versions": [
    { "version": "latest" },
    {
      "version": "1.5.0",
      "mode": "hosted",
      "hidden": true,
      "frozen": true,
      "description": "Supply-chain compromise; unpublished from npm 2026-04-23"
    }
  ]
}
```

The first entry is back to the floating dist-tag, so on the next `build fetch` it resolves to whatever `@example-corp/widget-cli@latest` points at upstream (currently `1.5.1`). The second entry is the same tombstone as before.

Two things to notice:

- `1.5.0`'s tombstone survives because the manifest still carries it. If `latest` ever pointed back at `1.5.0` for whatever reason (attacker got access again, mirror glitch, whatever), the hidden flag would still 404 the tarball.
- Ordering matters for `packageMode`. Bodega derives the package-level mode from the first version entry. `{version: "latest"}` with no explicit `mode` defaults to `hosted`, which is what we want, because `hosted` is a policy boundary rather than a policy statement.

Fetch the new latest:

```bash
bodega build fetch npm @example-corp/widget-cli
bodega build upload npm
```

Client behavior now:

- `npm install @example-corp/widget-cli` > packument (with `1.5.0` stripped) resolves `latest` to `1.5.1`. Tarball request succeeds.
- `npm install @example-corp/widget-cli@1.5.0` > 404 (tombstone still in effect).

## Scenario 3: constrain to `>= 1.5.1`

Objective: express the policy directly on the manifest instead of relying on the upstream registry's `latest` pointer. Useful when you want bodega to reject below-baseline versions even if someone explicitly requests them, and useful for compliance audits that ask "prove you're blocking everything before the fix."

This uses `version_constraint`, the same mechanism the gomod handler already had, extended to npm in v0.2.0.

```bash
bodega pkg edit npm @example-corp/widget-cli
```

Replace with:

```json
{
  "config_version": 1,
  "name": "@example-corp/widget-cli",
  "type": "npm",
  "description": "widget-cli: pinned to >= 1.5.1",
  "versions": [
    {
      "version": "1.5.1",
      "mode": "hosted",
      "version_constraint": "compatible"
    },
    {
      "version": "1.5.0",
      "mode": "hosted",
      "hidden": true,
      "frozen": true,
      "description": "Supply-chain compromise; unpublished from npm 2026-04-23"
    }
  ]
}
```

The first entry is the constraint-bearer. `version_constraint: "compatible"` combined with the baseline `1.5.1` tells the handler: "accept this version or anything higher; reject anything lower." The second entry keeps the tombstone.

Save. Client behavior:

- `npm install @example-corp/widget-cli@1.5.1` > succeeds.
- `npm install @example-corp/widget-cli@1.6.0` (when upstream eventually ships it) > succeeds without any manifest change.
- `npm install @example-corp/widget-cli@1.5.0` > 404 (tombstone wins over constraint).
- `npm install @example-corp/widget-cli@1.4.2` > **403** (below constraint, which is the new behavior compared to Scenario 2).
- `npm install @example-corp/widget-cli` (no version) > packument has everything below `1.5.1` and the `1.5.0` tombstone stripped. Client resolves to the newest available version >= `1.5.1`.

The difference between Scenario 2 and Scenario 3 is small and decides what a client can reach. Scenario 2 trusts the upstream's `latest` pointer plus your tombstone list. Scenario 3 enforces your policy on the wire: whatever `latest` says, whatever version the client asks for by name, anything below `1.5.1` is rejected.

## Auditing

Every edit in every scenario records an `edit` event in the audit database with actor attribution (your OS username, or the user behind a `sudo` invocation). Query it any time:

```bash
# Everything touching @example-corp/widget-cli.
bodega audit events --name '@example-corp/widget-cli'

# Just my edits.
bodega audit events --type edit --actor $USER

# Everything in the last hour.
bodega audit events --since $(date -u -d '1 hour ago' +%FT%TZ)
```

The audit trail is append-only. The details column holds a JSON diff of the manifest before and after, so an investigator can reconstruct exactly what policy was in effect at any point in time.

## Rollback

If any edit goes sideways, the temp buffer from the last `bodega pkg edit` is preserved on disk, and bodega prints the path when the save fails. For a planned rollback of a successful save, export the current state before you edit:

```bash
bodega pkg export npm @example-corp/widget-cli > ~/widget-cli-pre-change.json
# ... edit and save ...
# decide to undo:
bodega pkg delete npm @example-corp/widget-cli
bodega pkg import ~/widget-cli-pre-change.json
```

`pkg export` writes a valid `PackageManifest`; `pkg import` accepts that same structure. They round-trip cleanly.
