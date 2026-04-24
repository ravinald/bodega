# Bitwarden case study: TUI walkthrough

Same three scenarios as the [CLI walkthrough](bitwarden-cli.md), driven from bodega's interactive TUI. Start with [bitwarden-supply-chain.md](bitwarden-supply-chain.md) for the incident background.

## Why use the TUI for this

The TUI earns its keep during triage. You can see the full tree on the left, the selected package's details on the right, and the audit log at the bottom — all at once. When you're trying to answer "what state is this package actually in right now, on this mirror" without losing your place, a live tree beats a shell history.

Everything in the CLI walkthrough works here; this is just the keyboard-driven equivalent.

## Launching

```bash
bodega shell
```

Three panes come up: **Sources** (tree, top-left), **Details** (right), **Log** (bottom-left). Everything that follows happens in Sources unless noted.

Useful keys you'll need throughout:

| Key | Action |
|---|---|
| `↑`/`↓` or `j`/`k` | Move cursor |
| `→`/`l` or `Enter` | Expand node |
| `←`/`h` | Collapse node |
| `/` | Filter the tree |
| `E` | Edit the selected entry (opens raw-JSON editor) |
| `H` | Toggle hidden on selected version |
| `F` | Toggle frozen on selected entry |
| `Ctrl+S` | Save (inside the JSON editor) |
| `Esc` | Discard / dismiss |
| `?` | Help overlay |
| `q` | Quit |

## Starting state

Navigate: expand `npm/`, expand `@bitwarden/cli`. You should see a single version leaf labelled `latest`:

```
▼ npm/
  ▼ @bitwarden/cli (1)
      latest
```

Cursor on the `latest` leaf shows the version entry in the Details pane. The JSON blob on the right shows the full manifest.

## Scenario 1: quarantine 2026.4.0, pin to 2026.3.0

1. Cursor on the `@bitwarden/cli` package header (not on the `latest` leaf — one level up).
2. Press `E`. A raw-JSON editor opens, seeded with the full `PackageManifest`.
3. Replace the buffer with:

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

4. `Ctrl+S` to save. The editor closes; the tree rebuilds. `@bitwarden/cli` now shows two version leaves: `2026.3.0` and `2026.4.0`. The tombstoned version renders with the Hidden indicator in Details.

If the save fails (validation, policy, permissions), the error shows at the bottom of the editor popup and the buffer stays open. Correct and retry, or `Esc` to discard.

Verification:

- Cursor on `2026.4.0` leaf. Details pane shows `Hidden: true, Frozen: true`. JSON panel shows a scoped one-entry `PackageManifest` — exactly the shape that `bodega pkg export npm @bitwarden/cli 2026.4.0` produces, and exactly the shape the web UI delivers for `/api/v1/packages/npm/@bitwarden/cli/2026.4.0`. All three surfaces speak the same JSON.
- Cursor on `2026.3.0`. Details shows `Frozen: true`, no Hidden. This is the version that will serve.

## Scenario 2: relax to latest tracking, keep the tombstone

1. Cursor on the `@bitwarden/cli` package header.
2. `E`.
3. Buffer now has the Scenario 1 shape. Replace with:

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

4. `Ctrl+S`.

Tree now shows `latest` and `2026.4.0` leaves. Tombstone remains visible (and hidden); the active version floats.

### Alternative: per-version edit

If you want to change only the tombstone entry — say, to update its description — and leave the `latest` entry alone, you can scope the edit to a single version:

1. Cursor on the `2026.4.0` leaf.
2. `E`.
3. Buffer opens with a one-version `PackageManifest`:

```json
{
  "config_version": 1,
  "name": "@bitwarden/cli",
  "type": "npm",
  "versions": [
    {"version": "2026.4.0", "hidden": true, "frozen": true, ...}
  ]
}
```

4. Edit, `Ctrl+S`.

Bodega merges the single edited version back into the stored manifest in place — the `latest` entry in the other slot is untouched. Same shape the CLI uses for `bodega pkg edit npm @bitwarden/cli 2026.4.0`.

## Scenario 3: constrain to `>= 2026.4.1`

1. Cursor on the `@bitwarden/cli` package header.
2. `E`.
3. Replace with:

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

4. `Ctrl+S`.

Tree now shows `2026.4.1` (the constraint-bearer) and `2026.4.0` (the tombstone). Details on the `2026.4.1` leaf shows `Constraint: compatible`, which matches the manifest semantics: accept this version or anything higher.

After this save, the server enforces the constraint on the wire. You can watch the effect from a client terminal with `curl` or an `npm install --dry-run` against a specific below-baseline version — it'll come back as HTTP 403.

## Quick toggles (when you don't need the full editor)

For the routine "hide this version / freeze this entry" operations, you don't have to open the JSON editor at all:

- Cursor on a version leaf, press `H` → toggles Hidden on that specific version.
- Cursor anywhere on a package, press `F` → toggles Frozen on every version of that package.

Both operations record audit events with actor attribution the same way the JSON editor does. The JSON editor earns its keep when you're doing anything more surgical than a flag flip — adding a constraint, changing version order, editing description text.

## Watching the audit log

The TUI has a dedicated audit-query view. Press `L` to open it, fill in the filter (event type, package name, actor), submit, and the results stream into the Log pane at the bottom. For the Bitwarden scenarios above, filter `type=edit`, `name=@bitwarden/cli` and you'll see every save with its JSON diff.

You can also keep `bodega audit events --type edit -f` running in a separate terminal if you prefer a follow-style tail.

## What the TUI doesn't do (yet)

- **No per-version `version_constraint` toggle keybinding.** The constraint field requires the JSON editor — there's no `Ctrl+K compat` equivalent. That's deliberate; constraints are policy decisions with more knobs than a single keypress can capture.
- **No bulk quarantine.** If you need to tombstone the same version across multiple packages (a transitive-dependency advisory, say), the TUI drives one package at a time. Scripted `bodega pkg edit` loops are the right tool for fleet-wide updates; see the [CLI walkthrough](bitwarden-cli.md).
