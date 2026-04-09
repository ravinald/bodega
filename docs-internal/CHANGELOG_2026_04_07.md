# Changelog — 2026-04-07

## Full migration to new Store API (internal/builder, internal/server, internal/tui, cmd/bodega)

Completed the codebase-wide migration to the new unified `manifest.PackageManifest` + `manifest.VersionEntry` API. All packages now use `store.ListPackages`, `store.GetPackage`, `store.SavePackage`, `store.AddVersion`, `store.DeletePackage`, and `store.SaveIndex`. The old per-type structs and Store field/method accessors are gone everywhere.

### Packages modified

**`internal/builder/`** (`apt.go`, `binary.go`, `git.go`, `gomod.go`, `helm.go`, `npm.go`, `pypi.go`, `pypi_deps.go`, `buildenv.go`, `checksum.go`, `discover.go`, `describe.go`, `stage_test.go`): All functions now accept `(name string, ve manifest.VersionEntry)`. Iteration pattern: `store.ListPackages(typ)` → `store.GetPackage(ctx, typ, name)` → `pm.Versions`. SHA256 field changed from `*string` to `string`.

**`internal/server/server_test.go`**: `newTestServer` builds store via `manifest.NewLocalStore(t.TempDir())` + `store.AddVersion` instead of old struct literal.

**`internal/tui/sources.go`**: `BuildTree` uses `store.ListPackages` + `store.GetPackage` via a shared `collectEntries` helper. Requires `context` import.

**`internal/tui/details.go`**: `discoverGitDeps` takes `(name, ref string)`. `dependentsOf` queries `VersionEntry.RequiredBy`. All `store.FindXxx` calls replaced with `store.GetPackage`. `s3Path`/`clientURL`/`rawJSON`/`packageDescription` rewritten. `SHA256` access updated to `string` field.

**`internal/tui/app.go`**: Store reload blocks use `manifest.NewLocalStore`/`manifest.NewStore` + `store.LoadIndex`. `buildEditFields`, `saveCreateEntry`, `makeJSONApplyFn`, `toggleHidden` rewritten. `buildCreatePopup.validate` uses `store.GetPackage`.

**`internal/tui/executor.go`**: `runDelete`/`runFreeze`/`isFrozenEntry`/`s3KeyForEntry` rewritten. `runVerify` simplified.

**`internal/tui/tui_test.go`**: All `manifest.Store{Apt: ...}` struct literals replaced with `manifest.NewLocalStore(t.TempDir())` + `store.AddVersion`.

**`cmd/bodega/main.go`**: `loadStore` uses `manifest.NewLocalStore`/`manifest.NewStore` + `store.LoadIndex`.

**`cmd/bodega/cmd_create.go`**: `collectXxxEntry` helpers return `(name string, ve manifest.VersionEntry)`. Creates entries via `store.AddVersion` + `store.SaveIndex`.

**`cmd/bodega/cmd_delete.go`**: `isFrozen`/`s3KeyFor` take `context.Context`. Deletion via `store.DeletePackage` + `store.SaveIndex`.

**`cmd/bodega/cmd_freeze.go`**: Toggle frozen state on all VersionEntry items via `store.GetPackage` → mutate → `store.SavePackage`.

**`cmd/bodega/cmd_refresh.go`**: Iteration uses `store.ListPackages` + `store.GetPackage`. New versions via `store.AddVersion` + `store.SaveIndex`. Old `pypiVersionExists`/`gomodVersionExists` etc. helpers replaced with `store.FindVersion` checks.

**`cmd/bodega/cmd_remove.go`**: `s3KeyFor` call updated to pass `context.Context`.

**`cmd/bodega/pipeline.go`**: All `ensureFetchedXxx`/`ensureBuiltXxx`/`ensurePackagedXxx` helpers rewritten to iterate `store.ListPackages` + `store.GetPackage`.

### Result

`go build ./...` — clean.
`go test ./...` — all packages pass (builder, manifest, server, tui, audit, config, logging).

---


## manifest package rebuild (internal/manifest/)

Replaced the flat per-type manifest architecture with a per-package file layout
and a unified VersionEntry type. The manifest package now has no internal
dependencies beyond the Go standard library.

### Files replaced / deleted

| File | Action |
|------|--------|
| `internal/manifest/types.go` | Replaced — old per-type structs removed; unified PackageManifest + VersionEntry added |
| `internal/manifest/backend.go` | Replaced — Backend interface extended with Delete and List; ReadMD5 removed from interface |
| `internal/manifest/loader.go` | Deleted — superseded by store.go |
| `internal/manifest/loader_test.go` | Rewritten for new Store API |

### Files added

| File | Purpose |
|------|---------|
| `internal/manifest/store.go` | New Store with lazy per-package loading, index management, mutex safety |
| `internal/manifest/graph.go` | Internal helpers for DependencyGraph load/save/query |

### Key type changes

- `CurrentConfigVersion` bumped from 1 to 2.
- Removed all per-type structs (AptManifest, GitEntry, BinaryEntry, etc.).
- Added `PackageManifest` (one JSON per package at `{type}/{safeName}/manifest.json`).
- Added `VersionEntry` — unified across all 7 ecosystems.
- Added `Index` (index.json), `DependencyGraph` / `DepEdge` (graph.json).
- `SafeName()` replaces `/` with `--` for filesystem-safe path components.

### Backend changes

- `Delete(ctx, name string) error` added to Backend interface.
- `List(ctx, prefix string) ([]string, error)` added to Backend interface.
- `S3Backend`: new `DeleteFn` and `ListFn` fields; `List` strips backend Prefix from returned keys.
- `LocalBackend`: `Delete` via `os.Remove`; `List` via `filepath.WalkDir`; `Write` creates intermediate dirs.
- `ReadMD5` removed from Backend interface (MD5 remains a local filesystem concern in integrity.go).

### Store API

- `NewStore(backend Backend) *Store` / `NewLocalStore(dir string) *Store`
- `LoadIndex` / `SaveIndex` — manage index.json
- `GetPackage` — lazy-load with in-memory cache; `SavePackage` / `DeletePackage`
- `FindVersion` / `AddVersion` / `RemoveVersion`
- `ListPackages(typ)` / `AllPackages()`
- `LoadGraph` / `SaveGraph` / `AddEdge` / `RemoveEdge` / `ParentsOf` / `ChildrenOf` / `Orphans`

### Test results

24 tests pass (5 integrity + 19 store/graph tests), 0 failures.

---


## bodega HTTP server (`tools/bodega/internal/server/`)

Added an HTTP package server that proxies S3-backed artifacts to standard
package manager clients (apt, pip, curl) and exposes a REST API.

*Note: This section was written in a prior session and is preserved for history.*

---

## Leveled logging system + HTTPS + graceful shutdown

Added structured leveled logging, HTTPS support, and graceful shutdown.
See CHANGELOG_2026_04_06.md for details.

---

## Go module, Helm chart, and npm package support

Added three new source types with full manifest, builder, CLI, TUI, and HTTP
serving support. Added proxy/cache-on-demand, CRUD API, and SQLite audit trail.

### New source types

**Go modules (`gomod`)**
- Manifest: `GomodEntry` with `Name` (module path), `Version`, `URL` (upstream proxy)
- Builder: `FetchGomod` downloads `.info`, `.mod`, `.zip` from upstream GOPROXY
- Server: `GET /go/{path...}` with GOPROXY protocol (splits on `/@v/`)
- Proxy/cache: immutable version artifacts cached forever, `@v/list` refreshed by TTL
- S3 layout: `gomod/{module}/@v/{version}.{info,mod,zip}`, `gomod/{module}/@v/list`

**Helm charts (`helm`)**
- Manifest: `HelmEntry` with `Name`, `Version`, `URL`, `AppVersion`
- Builder: `FetchHelm` downloads `.tgz`; `PackageHelm` generates `index.yaml`
- Server: `GET /helm/index.yaml`, `GET /helm/charts/{file}`
- S3 layout: `charts/{name}-{version}.tgz`, `charts/index.yaml`

**npm packages (`npm`)**
- Manifest: `NpmEntry` with `Name` (supports @scoped), `Version`, `URL` (registry)
- Builder: `FetchNpm` downloads tarballs; `PackageNpm` generates packument JSON
  from tarball package.json metadata
- Server: `GET /npm/{path...}` — distinguishes packument (path only) from tarball
  (`/-/` in path)
- S3 layout: `npm/{name}/{name}-{version}.tgz`, `npm/{name}/packument.json`

### Proxy/cache layer

**New file: `internal/server/proxy.go`**
- `proxyOrCache(w, r, s3Key, upstreamURL, immutable)` — checks S3 first, fetches
  upstream on miss, caches in S3, serves response
- TTL-based refresh for mutable resources (configurable via `metadata_ttl`)
- Immutable versioned artifacts cached permanently
- `s3Writer` interface extends `s3Getter` with `PutBytes` for cache writes
- `fetchUpstream` downloads from upstream with 256MB cap
- Falls back to stale cache on upstream failure

### CRUD API

**Routes added to `internal/server/server.go`:**
- `POST /api/v1/packages/{type}` — create entry (JSON body, validates uniqueness)
- `DELETE /api/v1/packages/{type}/{name}` — delete entry (checks frozen, returns 403)
- Returns 201 Created, 409 Conflict, 403 Forbidden, 400 Bad Request as appropriate
- All 7 types supported (pypi returns 400 with edit-directly message)
- Mutex-protected for concurrent safety

### SQLite audit trail

**New package: `internal/audit/audit.go`**
- Pure-Go SQLite via `modernc.org/sqlite` (no CGo)
- 5 event types: `fetch`, `build`, `create`, `delete`, `cache`
- Schema: `events` table with timestamp, event_type, pkg_type, pkg_name,
  pkg_version, client_ip, user_agent, status, duration_ms, details
- Indexed on event_type, (pkg_type, pkg_name), timestamp, client_ip
- WAL mode for concurrent read/write performance
- `Record(ctx, Event)` — insert event
- `Query(ctx, Filter)` — filtered, ordered, limited queries
- `Count(ctx, Filter)` — aggregate counts

**Audit middleware** (`internal/server/middleware.go`):
- `AuditMiddleware(db)` records fetch events for package-serving routes
- `parsePackagePath` extracts type/name/version from URL paths for all 7 types
- Skips `/healthz` and `/api/v1/*` routes

**CLI query** (`cmd/bodega/cmd_audit.go`):
- `bodega audit [--type TYPE] [--pkg-type TYPE] [--name NAME] [--client IP] [--since TIME] [--limit N]`
- Prints table with timestamp, event, type, name, status, client, duration

### Manifest changes

**`internal/manifest/types.go`:**
- Added `TypeGomod`, `TypeHelm`, `TypeNpm` constants
- Updated `AllTypes` to 7 types (build order: binary, git, apt, pypi, gomod, helm, npm)
- Added `GomodEntry`, `HelmEntry`, `NpmEntry` structs with `VersionedName()` methods
- Added `GomodManifest`, `HelmManifest`, `NpmManifest` envelopes

**`internal/manifest/loader.go`:**
- Added `Gomod`, `Helm`, `Npm` fields to `Store`
- Added `FindGomod/Helm/Npm`, `RemoveGomod/Helm/Npm`, `SaveGomod/Helm/Npm` methods
- Updated `LoadAll`, `LoadAllFromBackend` to load gomod.json, helm.json, npm.json
- Updated `AllNames()` to include new types

### Config changes

**`internal/config/config.go`:**
- Added `ProxyCacheEnabled`, `MetadataTTL`, `GomodUpstream`, `NpmUpstream`
- Added `GomodRoot`, `HelmRoot`, `NpmRoot` per-type build root overrides
- Added `AuditDB` path (default: `{log_dir}/audit.db`)
- Updated `RootForType`, `Load`, `Save`, `defaultConfigContent`

### Builder changes

**`internal/builder/runner.go`:**
- Added `gomod`, `charts`, `npm` to `dirs` struct
- Added `GomodRoot`, `HelmRoot`, `NpmRoot` to `Config`
- Updated `rootFor` and `buildDirs`

**New files:**
- `internal/builder/gomod.go` — FetchGomod, CheckGomodStage, GomodArtifactPaths
- `internal/builder/helm.go` — FetchHelm, PackageHelm, CheckHelmStage, HelmArtifactPaths
- `internal/builder/npm.go` — FetchNpm, PackageNpm, CheckNpmStage, NpmArtifactPaths

### CLI changes

- `cmd/bodega/cmd_create.go` — added gomod/helm/npm cases with collect functions
- `cmd/bodega/cmd_delete.go` — added gomod/helm/npm cases in remove, isFrozen, s3KeyFor
- `cmd/bodega/cmd_fetch.go` — added gomod/helm/npm cases
- `cmd/bodega/cmd_audit.go` — new `bodega audit` command
- `cmd/bodega/main.go` — registered audit command

### TUI changes

- `internal/tui/sources.go` — added gomod/, helm/, npm/ group nodes in BuildTree
- `internal/tui/details.go` — added entry detail rendering and rawJSON for new types

### Server changes

- Updated `packagesResponse` to include gomod/helm/npm
- Updated `handleAPIPackagesByType`, `handleAPIPackage`, `handleAPIStatus` for 7 types
- Added `.tgz`, `.yaml`, `.mod`, `.info` to content types map
- Added `.tgz` to immutable cache headers
- Added `mu sync.Mutex` and `auditDB *audit.DB` to Server struct

### New schemas

- `schemas/gomod.schema.json` — name + version required, optional url + frozen
- `schemas/helm.schema.json` — name + version + url required, optional app_version + frozen
- `schemas/npm.schema.json` — name + version required, optional url + frozen

### Tests

- All existing tests pass (91 tests across 7 packages)
- 13 new audit tests (Record, Query by type/pkg/client/since, limit, ordering, count)
- Updated TUI tests for 7 types

### New dependency

- `modernc.org/sqlite v1.48.1` — pure-Go SQLite driver (no CGo)
