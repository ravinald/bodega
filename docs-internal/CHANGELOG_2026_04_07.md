# Changelog — 2026-04-07

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
