# Changelog — 2026-04-07 — Rename reman → bodega

## Summary

Renamed the tool from `reman` (repo-manager) to `bodega` across the entire codebase.

## Changes

### Go module
- `go.mod` module path: `github.com/scaleapi/core-infrastructure/tools/repo-manager` → `github.com/scaleapi/bodega`
- All import paths updated across every `.go` file

### Directory structure
- `cmd/reman/` → `cmd/bodega/`

### Binary and build
- `Makefile`: binary name `reman` → `bodega`, cmd package path updated
- Build output: `dist/reman` → `dist/bodega`

### Configuration paths
- System config: `/etc/reman/` → `/etc/bodega/`
- User config: `~/.config/reman/` → `~/.config/bodega/`
- Log directory: `/var/log/reman/` → `/var/log/bodega/`
- Build root: `/opt/repo-manager` → `/opt/bodega`
- Environment variable: `REMAN_LOG_LEVEL` → `BODEGA_LOG_LEVEL`

### CLI
- Root command `Use` field: `reman` → `bodega`
- All example strings in every subcommand updated
- Version output: `reman <version>` → `bodega <version>`

### Server
- Example hostnames: `reman-host` → `bodega-host`
- TLS domain example: `reman.example.com` → `bodega.example.com`
- Log messages: "reman server listening" → "bodega server listening"

### TUI
- Quit confirmation: "Quit reman?" → "Quit bodega?"
- Config dialog title updated

### Schema files
- `$id` URIs in all JSON schemas updated from `repo-manager` to `bodega`

### Documentation
- `README.md`, `docs/QUICKSTART.md`, `docs/USAGE.md` — all references updated
- `docs-internal/REMAN_ROADMAP.md` → `docs-internal/BODEGA_ROADMAP.md`
- All internal changelogs and session docs updated

### Not changed
- S3 bucket names (these are infrastructure resources, not tool names)
- Git remote URL (already updated by user)
