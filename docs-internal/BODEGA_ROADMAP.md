# bodega Roadmap — Toward Universal Repository Management

## Current State (v0.1)

bodega is a manifest-driven package build system + S3 repository with a TUI.
It builds from source, manages 4 artifact types (apt, git, pypi, binary),
and uploads to S3. Unique features: build-from-source, git release bundling,
three-pane TUI, S3-native storage.

## Architecture Principle

**We don't reinvent dependency resolution.** Native package managers (apt, pip,
npm, etc.) handle resolution at install time. bodega stores packages with
correct metadata so native tools work natively. The TUI visualizes dependencies
by reading package metadata — same approach as Nexus IQ.

## Priority Roadmap

### P0 — Fix Current Issues (immediate)

- [x] Log interleaving fix (tea.Sequence, syncWriter)
- [x] Git release mode (tarball instead of clone)
- [x] Tar extraction path creation
- [x] Bundle lock cleanup
- [x] Venv ensurepip fallback
- [ ] Verify clean build end-to-end on admin1
- [ ] Ensure Sources tree survives build operations (S3 backend reload)

### P1 — Proxy/Cache (next)

**Goal:** Mirror upstream repos so instances don't need internet at install time.

**What Nexus does:** "Proxy repository" — caches upstream packages on first
request. Subsequent requests served from cache. Transparent to clients.

**For bodega:**

1. **APT proxy** — Mirror specific packages from Ubuntu repos into our APT
   repository. Not a full mirror (that's TB of data) — selective mirroring
   based on a package list. `aptly mirror` does this well.

2. **PyPI proxy** — Cache wheels from PyPI on first download. A simple
   HTTP proxy that sits between pip and pypi.org, caching to S3.
   `devpi` or `bandersnatch` do this, or we build a minimal one.

3. **Implementation approach:** Rather than building proxy functionality
   into bodega itself, integrate with existing tools:
   - Use `aptly` for APT mirroring (it's a mature, focused tool)
   - Use `devpi-server` or a simple S3-caching proxy for PyPI
   - bodega orchestrates these tools via its manifest system

### P2 — Web API

**Goal:** Non-TUI clients can query the repo programmatically.

**Endpoints:**
```
GET  /api/v1/packages              — list all packages
GET  /api/v1/packages/{type}       — list by type
GET  /api/v1/packages/{type}/{name} — package details + deps
GET  /api/v1/status                — repo health
POST /api/v1/packages              — create entry
DELETE /api/v1/packages/{type}/{name} — delete entry
POST /api/v1/build/{type}/{name}   — trigger build
GET  /api/v1/build/status          — build queue status
```

**Implementation:** Add an HTTP server mode to bodega (`bodega serve`).
Use standard library `net/http` or a lightweight router. Serves the
same data the TUI shows. Could also serve the APT repo and wheel
cache directly (replacing the need for apt-transport-s3 on clients).

### P3 — Docker/OCI Registry

**Goal:** Host container images alongside packages.

**Implementation:** This is complex — OCI registries have a specific API
(Docker Registry HTTP API V2). Options:
- Integrate with `distribution` (the reference Go implementation)
- Use a lightweight Go library like `go-containerregistry`
- Or: just proxy to ECR (since we're on AWS) and not self-host

### P4 — RBAC / Authentication

**Goal:** Multi-team access control.

**Implementation:**
- API keys for programmatic access
- Read/write permissions per package type
- Admin role for configuration changes
- Integration with existing IAM (AWS, Okta)

### P5 — Vulnerability Scanning

**Goal:** Check packages against CVE databases.

**Implementation:**
- Integrate with `grype` or `trivy` (both are Go tools)
- Scan .deb packages, wheels, and container images
- Show vulnerability status in the TUI Details pane
- Block upload of packages with critical CVEs (configurable)

### P6 — Additional Format Support

Based on what Nexus supports, in priority order:
1. **RPM/Yum** — for RHEL/CentOS-based instances
2. **npm** — if any Node.js services are deployed
3. **Go modules** — proxy for `GOPROXY`
4. **Helm** — if Kubernetes is adopted
5. **Maven/Gradle** — if JVM services are deployed

## Format-Specific Notes

### APT (current)
- reprepro manages metadata correctly
- Clients use standard `apt-get` with `apt-transport-s3`
- Dependencies declared in `.deb` control files, resolved by apt client
- bodega: no changes needed for deps; already correct

### PyPI (current)
- Wheels contain METADATA with Requires-Dist
- pip resolves deps using `resolvelib` backtracking algorithm
- `--find-links` works for offline install
- bodega: dep visualization via METADATA scanning is correct approach

### Docker/OCI (future)
- Registry API V2 is well-specified
- Images have manifests with layer dependencies
- Docker/containerd resolve layers themselves
- bodega: would serve manifests + layers, not resolve deps

### RPM/Yum (future)
- `repodata/` directory with `primary.xml.gz` contains dep metadata
- `createrepo` generates this from `.rpm` files (like reprepro for deb)
- `yum`/`dnf` client resolves deps
- bodega: would use `createrepo` tool, same pattern as reprepro

## Technical Decisions

### Proxy: build into bodega vs. external tools?

**Recommendation: Hybrid.** For simple proxying (PyPI wheel cache, APT
package cache), build it into bodega's web server. For full mirroring
with snapshot support, delegate to specialized tools (aptly, bandersnatch)
and have bodega orchestrate them.

### Web server: embedded vs. separate service?

**Recommendation: Embedded.** `bodega serve` starts an HTTP server that:
1. Serves the API endpoints
2. Serves the APT repo (replaces apt-transport-s3)
3. Serves the PyPI wheel index (replaces --find-links)
4. Optionally proxies to upstream for cache misses

This means instances point to `http://bodega-host:8080/apt/` instead of
`s3://bucket/packages/apt/`. Simpler for clients, no S3 auth needed.
