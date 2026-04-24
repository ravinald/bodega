# Bitwarden case study: API walkthrough

Same three scenarios as the [CLI](bitwarden-cli.md) and [TUI](bitwarden-tui.md) walkthroughs, driven via HTTP. Start with [bitwarden-supply-chain.md](bitwarden-supply-chain.md) for the incident background.

## When to use the API

The API earns its keep when bodega is one node in a bigger graph — a ticketing system that needs to quarantine a version as part of closing an incident ticket, a GitOps reconciler keeping manifest state in line with a git repo, a scanner that opens a PR to add a tombstone when it finds a new advisory. If you're operating bodega interactively, the TUI or CLI are faster. If you're operating it from code, this is the surface to target.

## Endpoints

Reads are open (no auth). Mutations go through an IP allow-list + Bearer token gate — see [Auth](#auth) below.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/packages` | All packages grouped by type |
| `GET` | `/api/v1/packages/{type}` | All packages of a type |
| `GET` | `/api/v1/packages/{type}/{name}` | Full `PackageManifest` |
| `GET` | `/api/v1/packages/{type}/{name}/{version}` | `PackageManifest` scoped to one version |
| `POST` | `/api/v1/packages/{type}` | Create an entry (body: `PackageManifest`) |
| `DELETE` | `/api/v1/packages/{type}/{name}` | Delete an entry |
| `PATCH` | `/api/v1/packages/{type}/{name}/hide[/{version}]` | Toggle hidden on the package or one version |
| `PATCH` | `/api/v1/packages/{type}/{name}/freeze[/{version}]` | Toggle frozen on the package or one version |
| `GET` | `/api/v1/audit` | Query the audit log |

No PUT to replace a full manifest. For complex edits — adding a `version_constraint`, restructuring the versions array, changing description text — the idiom is `DELETE` then `POST` with the new body. The gap here is honest: a crash or network blip between the two calls leaves the entry gone. For critical state, take a `GET` snapshot first and keep it on disk until the `POST` succeeds.

For flag-only changes — toggling hide or freeze — the `PATCH` endpoints are safe, atomic, and don't need the DELETE+POST dance.

## Auth

Under the default configuration, mutations from `127.0.0.0/8` are unauthenticated — convenient for operator shells on the bodega host itself. Any client outside the localhost range needs:

1. Its source IP in `admin_permit_cidr` (set in `config.json`).
2. A valid Bearer token, created via:

```bash
bodega token create my-automation \
  --comment "ticketing integration" \
  --expires 2026-07-01
```

That command prints the token once. Keep it; you can't retrieve it again. Then pass it on every mutating call:

```
Authorization: Bearer <token>
```

A missing or invalid token on a non-localhost client produces HTTP 401. An allowed IP without a token (when `admin_permit_cidr` is wider than localhost) also produces 401. A denied IP produces 403 regardless of token. Tune the two controls to your trust model.

All examples below assume the mutating caller is either on localhost or has `$BODEGA_TOKEN` set and `-H "Authorization: Bearer $BODEGA_TOKEN"` added to every mutating `curl`.

## Starting state

A single entry pinned to the `latest` dist-tag:

```bash
curl -s http://bodega.internal:8080/api/v1/packages/npm/%40bitwarden%2Fcli
```

```json
{
  "config_version": 1,
  "name": "@bitwarden/cli",
  "type": "npm",
  "versions": [{"version": "latest"}]
}
```

Note the URL-encoded scope: `@bitwarden/cli` becomes `%40bitwarden%2Fcli`. Go's `ServeMux` treats each path segment as a single var; a literal `/` would split the name across two segments and miss the route.

## Scenario 1: quarantine 2026.4.0, pin to 2026.3.0

Full-manifest edit. DELETE + POST.

```bash
# 1. Snapshot the current state (rollback insurance).
curl -s http://bodega.internal:8080/api/v1/packages/npm/%40bitwarden%2Fcli \
  > /tmp/bitwarden-pre.json

# 2. Delete the existing entry.
curl -X DELETE http://bodega.internal:8080/api/v1/packages/npm/%40bitwarden%2Fcli

# 3. Create the new entry.
curl -X POST http://bodega.internal:8080/api/v1/packages/npm \
  -H "Content-Type: application/json" \
  -d '{
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
  }'
```

Verify:

```bash
# Full manifest round-trip.
curl -s http://bodega.internal:8080/api/v1/packages/npm/%40bitwarden%2Fcli | jq .

# Version-scoped read — confirms the tombstone flags.
curl -s http://bodega.internal:8080/api/v1/packages/npm/%40bitwarden%2Fcli/2026.4.0 | jq '.versions[0]'
# Expected: {"version": "2026.4.0", "mode": "hosted", "hidden": true, "frozen": true, "description": "..."}
```

Client-side enforcement kicks in immediately on the npm routes (no need to restart the server):

```bash
# 2026.3.0 tarball: 200 (assuming it's been fetched + uploaded).
curl -I http://bodega.internal:8080/npm/@bitwarden/cli/-/cli-2026.3.0.tgz

# 2026.4.0 tarball: 404 (tombstone).
curl -I http://bodega.internal:8080/npm/@bitwarden/cli/-/cli-2026.4.0.tgz

# Packument: 2026.4.0 stripped from versions[] and dist-tags.
curl -s http://bodega.internal:8080/npm/@bitwarden/cli | jq '.versions | keys'
```

Fetch the known-good tarball into storage if you haven't already. That's a builder operation, not API:

```bash
# On the bodega host.
bodega build fetch npm @bitwarden/cli
bodega build upload npm
```

## Quick alternative: PATCH for flag toggles only

If the only change you need is "hide version X" — say, you've already created the tombstone entry some other way and you just want to toggle its state — skip DELETE+POST entirely:

```bash
# Toggle hidden on a specific version.
curl -X PATCH http://bodega.internal:8080/api/v1/packages/npm/%40bitwarden%2Fcli/hide/2026.4.0

# Toggle frozen on the whole package.
curl -X PATCH http://bodega.internal:8080/api/v1/packages/npm/%40bitwarden%2Fcli/freeze
```

These are toggles, not sets — the endpoint flips whatever state the flag was in. The response body contains the updated manifest. For idempotent set-or-leave semantics, fetch the current state first and only PATCH if the flag doesn't match what you want.

## Scenario 2: relax to latest tracking, keep the tombstone

Same DELETE + POST pattern with a different body:

```bash
curl -X DELETE http://bodega.internal:8080/api/v1/packages/npm/%40bitwarden%2Fcli

curl -X POST http://bodega.internal:8080/api/v1/packages/npm \
  -H "Content-Type: application/json" \
  -d '{
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
  }'
```

The `latest` dist-tag resolves on the next `bodega build fetch`. The tombstone carries over identically.

## Scenario 3: constrain to `>= 2026.4.1`

```bash
curl -X DELETE http://bodega.internal:8080/api/v1/packages/npm/%40bitwarden%2Fcli

curl -X POST http://bodega.internal:8080/api/v1/packages/npm \
  -H "Content-Type: application/json" \
  -d '{
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
  }'
```

After this POST, client-side behavior:

```bash
# 2026.4.1 (at constraint): 200.
curl -I http://bodega.internal:8080/npm/@bitwarden/cli/-/cli-2026.4.1.tgz

# 2026.4.0 (hidden): 404.
curl -I http://bodega.internal:8080/npm/@bitwarden/cli/-/cli-2026.4.0.tgz

# 2026.3.0 (below constraint): 403.
curl -I http://bodega.internal:8080/npm/@bitwarden/cli/-/cli-2026.3.0.tgz

# Packument: everything below 2026.4.1 and the 2026.4.0 tombstone are stripped.
curl -s http://bodega.internal:8080/npm/@bitwarden/cli \
  | jq '{dist_tags: ."dist-tags", versions: (.versions | keys)}'
```

The 403 vs 404 distinction is deliberate. 404 says "this version doesn't exist here" — appropriate for the tombstone since we've decided it's gone. 403 says "this version exists upstream but we won't serve it by policy" — appropriate for below-constraint requests.

## Auditing

```bash
# Everything the API did today.
curl -s "http://bodega.internal:8080/api/v1/audit?since=$(date +%F)&limit=200" | jq .

# Events tied to @bitwarden/cli only.
curl -s "http://bodega.internal:8080/api/v1/audit?name=%40bitwarden%2Fcli" | jq .
```

Mutations through the API are attributed by `client_ip` rather than `actor` — `actor` is reserved for OS-user attribution on CLI/TUI operations. If you need human-level attribution for API calls, put it in the request path: issue a dedicated token per automation identity (`bodega token create ticketing`, `bodega token create gitops-reconciler`) and query the audit log by the client IP those tokens are used from.

## Rollback

The snapshot from Scenario 1 step 1 is your escape hatch:

```bash
curl -X DELETE http://bodega.internal:8080/api/v1/packages/npm/%40bitwarden%2Fcli
curl -X POST http://bodega.internal:8080/api/v1/packages/npm \
  -H "Content-Type: application/json" \
  --data-binary @/tmp/bitwarden-pre.json
```

The API accepts the exact shape that `GET /api/v1/packages/{type}/{name}` emits, which is why the round-trip works.

## Integration notes

- **Idempotency.** `POST /api/v1/packages/{type}` rejects with 409 if the entry already exists. Automation pipelines should either DELETE first (full replace) or detect the 409 and fall back to PATCH + targeted manipulation.
- **Policy enforcement.** `POST` and `PATCH` both run the upstream allow-list check (`policy add` rules). A POST that references a URL outside the allow-list returns HTTP 403 with the offending candidate in the error body. Pre-seed policy rules before any bulk import.
- **Concurrent writes.** Mutations acquire a package-level mutex, so two overlapping DELETE+POSTs on the same entry are serialized. Cross-package writes are parallel.
- **Rate limits.** Not implemented. If your automation can fan out 10k mutation calls in a minute, so can anything else; put a proxy in front if that's a concern.
