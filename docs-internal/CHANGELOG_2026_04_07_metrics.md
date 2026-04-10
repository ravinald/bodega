# Changelog — 2026-04-07 (metrics pipeline)

## Fix: metrics not updating after fetch/build/upload/sync

The web UI dashboard showed no storage totals because `metrics.json` was never
written after pipeline operations. `SaveIndex` (which calls `SaveMetrics`) was
only wired into create/delete/repair/refresh commands.

### Changes

- `cmd/bodega/cmd_fetch.go`: Added `"context"` import. Call `store.SaveIndex(ctx)`
  and `notifyServer(gf)` after all fetches complete.
- `cmd/bodega/cmd_build.go`: Added `"context"` import. Call `store.SaveIndex(ctx)`
  and `notifyServer(gf)` after all builds complete.
- `cmd/bodega/cmd_upload.go`: Call `store.SaveIndex(ctx)` and `notifyServer(gf)`
  after all uploads complete.
- `cmd/bodega/cmd_sync.go`: Call `store.SaveIndex(ctx)` and `notifyServer(gf)`
  after all syncs complete.

### Result

After any pipeline command (fetch, build, upload, sync), `metrics.json` is now
written with up-to-date `ArtifactSize` totals. The running server is notified
via SIGHUP to reload, so the web dashboard reflects current storage.

`go build ./...` — clean.
