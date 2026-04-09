# Changelog 2026-04-03

## bootstrap CLI tool (`tools/bootstrap-builder/`)

Built a Go CLI tool that replaces the existing `build.sh` + `lib/` bash scripts
with a structured, testable, manifest-driven program.

### New files

**Go module**
- `go.mod` — module `github.com/scaleapi/bootstrap-builder`, Go 1.26

**Command layer** (`cmd/bootstrap/`)
- `main.go` — root cobra command, persistent flags, `--break-glass-update-md5`
- `cmd_init.go` — `bootstrap init`: create S3 bucket with encryption + versioning
- `cmd_build.go` — `bootstrap build [TYPE...] [--entry NAME]`
- `cmd_sync.go` — `bootstrap sync [TYPE...]`
- `cmd_status.go` — `bootstrap status [TYPE...]`
- `cmd_verify.go` — `bootstrap verify`
- `cmd_create.go` — `bootstrap create <type>` (interactive prompts for missing flags)
- `cmd_delete.go` — `bootstrap delete <type> <name> [--remove-from-s3]`
- `cmd_remove.go` — `bootstrap remove <type> <name>`
- `cmd_freeze.go` — `bootstrap freeze <type> <name>`
- `cmd_shell.go` — `bootstrap shell` (interactive REPL)

**Internal packages**
- `internal/config/config.go` — configuration resolution: flags > env > config.json > defaults
- `internal/manifest/types.go` — `AptEntry`, `GitEntry`, `PypiManifest`, `BinaryEntry` structs; backward-compatible with existing JSON
- `internal/manifest/integrity.go` — MD5 companion file read/write/verify/force-update
- `internal/manifest/loader.go` — `Store` type: load all four manifests with integrity checks; save methods that update MD5
- `internal/builder/runner.go` — shared `Config`, `Result`, `Summary` types; `runCmd`, `runCmdCapture` helpers
- `internal/builder/binary.go` — download via curl, optional SHA-256 verification
- `internal/builder/git.go` — bare clone + `git bundle create` + worktree helper for pypi
- `internal/builder/apt.go` — GPG key setup, reprepro configuration, source build or apt-get download
- `internal/builder/pypi.go` — combined requirements resolution, virtualenv creation, `pip wheel`, MANIFEST.sha256
- `internal/s3/init.go` — `InitBucket`: create bucket, public access block, versioning, AES-256 encryption
- `internal/s3/client.go` — `Client` wrapping AWS SDK v2: HeadObject, UploadFile, DeleteObject, ListPrefix, SyncDir
- `internal/s3/status.go` — `CheckStatus`, `PrintStatus` comparing manifest entries to S3
- `internal/shell/shell.go` — readline REPL with tab completion and history

**Tests**
- `internal/manifest/integrity_test.go`
- `internal/manifest/loader_test.go`
- `internal/builder/binary_test.go`
- `internal/builder/apt_test.go`
- `internal/config/config_test.go`
- `internal/shell/shell_test.go`

**Tooling**
- `Makefile` — `build`, `install`, `test`, `vet`, `fmt`, `lint`, `tidy`, `clean`
- `README.md` — full usage documentation

## bootstrap-builder lint and formatting fixes (tools/bootstrap-builder/)

Resolved all compilation warnings, lint violations, and formatting drift in the
`bootstrap-builder` Go project.

### Changes

**`go.mod`**
- Changed `go 1.26` directive to `go 1.24` (the minimum required by the
  dependency versions present in `go.sum`; the toolchain enforced this floor
  when `go 1.23` was written).

**`.golangci.yml`** (new file)
- Added golangci-lint v2 configuration that explicitly enables `errcheck`,
  `govet`, `gosec`, `staticcheck`, and `unused`.
- Excluded gosec rules that are intentional false positives for a build-runner
  tool: G204/G702 (subprocess via variable), G301 (dir perms 0755), G304 (file
  path via variable), G306 (file write perms 0644), G703 (path traversal on
  temp file).

**`internal/builder/runner.go`**
- Removed unused `indent` helper function.
- Added `_, _ =` discard for `fmt.Fprintf`/`fmt.Fprintln` calls in `Print` and
  `logf` where write errors are not actionable (output goes to stdout/buffer).
- Fixed struct field alignment to satisfy `gofmt`.

**`internal/builder/apt.go`**
- Added `_, _ =` discard on all unchecked `fmt.Fprintf` output calls.
- Changed `defer os.Remove(...)` to `defer func() { _ = os.Remove(...) }()`.
- Replaced bare `tmpFile.Close()` with checked `if err := tmpFile.Close()`.

**`internal/builder/binary.go`**
- Changed `defer f.Close()` to `defer func() { _ = f.Close() }()` in
  `fileSHA256`.
- Added `_, _ =` discard on all output `fmt.Fprintf` calls in `BuildBinaries`.

**`internal/builder/git.go`**
- Added `_, _ =` discard on all unchecked `fmt.Fprintf` output calls.

**`internal/builder/pypi.go`**
- Added `_, _ =` discard on all unchecked `fmt.Fprintf` output calls.

**`internal/s3/client.go`**
- Changed `defer f.Close()` to `defer func() { _ = f.Close() }()` in
  `UploadFile`.
- Added `_, _ =` discard on the `fmt.Fprintf` call in `SyncDir`.

**`internal/s3/status.go`**
- Added `_, _ =` discard on all `fmt.Fprintf` calls in `PrintStatus`.
- Fixed struct field alignment to satisfy `gofmt`.

**`internal/config/config.go`**
- Fixed struct field alignment to satisfy `gofmt`.

**`internal/config/config_test.go`**
- Replaced bare `os.Unsetenv`/`os.Setenv` calls with checked versions that
  call `t.Fatalf`/`t.Errorf` on failure.

**`cmd/bootstrap/cmd_shell.go`**
- Removed trailing blank line to satisfy `gofmt`.

### Key design decisions

- All `fmt.Fprintf` / `fmt.Fprintln` calls that write to a terminal-bound or
  in-memory `io.Writer` use `_, _ =` discard rather than `//nolint` pragmas.
  This is idiomatic Go: the standard library itself does not check these in
  analogous code, but the explicit discard makes the intent clear.
- gosec false positives are suppressed at the config layer, not at the call
  site, keeping production code free of nolint annotations.

### Key design decisions

- Manifest schema is backward-compatible with the existing JSON files; no changes to `manifests/*.json`.
- Build order matches the original shell script: `binary → git → apt → pypi`.
- Build failures per-entry are non-fatal; run continues and failures are reported in a summary.
- MD5 integrity is enforced on every manifest read; `--break-glass-update-md5` is the explicit escape hatch for out-of-band edits.
- Frozen entries are rejected at build/create/delete; toggled with `bootstrap freeze`.
- All S3 operations use the AWS SDK v2 default credential chain (respects `AWS_PROFILE`, IAM roles, etc.).

## bodega pipeline refactor (`tools/bodega/`)

Split the monolithic `build` command into four explicit pipeline stages:
`fetch`, `build`, `package`, and `upload`.

### internal/builder/

**binary.go**
- Renamed `BuildBinaries` to `FetchBinaries`; retained the old name as a
  backward-compatible alias.
- Binary has no separate build or package stage: the download is the artifact.

**git.go**
- Split `BuildGit` into `FetchGit` (bare `git clone`) and `PackageGit`
  (`git bundle create` + verify).
- `PackageGit` checks that the bare repo exists before proceeding.
- Retained `BuildGit` as a compatibility wrapper calling both stages.
- Added `mergeSummaries` private helper used by all wrappers.

**apt.go**
- Split into three exported stage functions:
  - `FetchApt` — `git clone --depth 1` (URL entries) or `apt-get download`
    (non-URL entries) into `sources/`.
  - `BuildApt` — runs `build_cmd` inside the clone dir; no-op for apt-get
    entries. Pre-checks that the source directory exists.
  - `PackageApt` — locates the `.deb` and runs `reprepro includedeb`. Calls
    `setupAptRepo` internally (only this stage requires GPG / reprepro conf).
- Added `locateDebFile` private helper to resolve the `.deb` path for both
  entry variants (URL source-build vs. apt-get download).
- Added `RunApt` as a convenience wrapper calling all three stages.

**pypi.go**
- Split `BuildPypi` into three stage functions:
  - `FetchPypi` — resolves git worktrees, writes `combined-requirements.txt`.
  - `BuildPypi` — creates venv, upgrades pip/wheel/setuptools, runs `pip wheel`.
    Pre-checks that `combined-requirements.txt` exists.
  - `PackagePypi` — generates `MANIFEST.sha256`. Pre-checks that `.whl` files
    exist.
- Added `RunPypi` as a convenience wrapper.

### cmd/bootstrap/

- `cmd_build.go` — rewritten to call stage functions in sequence per type
  (fetch → build → package). Each stage is skipped if the previous one failed.
- `cmd_fetch.go` — new file; `bootstrap fetch [TYPE...] [--entry NAME]`.
- `cmd_package.go` — new file; `bootstrap package [TYPE...] [--entry NAME]`.
- `cmd_upload.go` — new file replacing `cmd_sync.go`; command name changed
  from `sync` to `upload`; S3 logic unchanged.
- `cmd_sync.go` — deleted.
- `cmd_shell.go` — added `shellFetch`, `shellPackage`, `shellUpload`; updated
  `shellBuild` to use staged functions; replaced `sync` with `upload`.
- `main.go` — registered `newFetchCmd`, `newPackageCmd`, `newUploadCmd`;
  replaced `newSyncCmd`.

### internal/shell/shell.go

- Added `fetch`, `package`, `upload` to the readline autocomplete tree.
- Replaced `sync` with `upload` in tab completion and help text.

## bodega stage cascading, sync command, and versioned paths (`tools/bodega/`)

Added three new features to the bootstrap CLI tool.

### Feature 1 — Stage cascading

Pipeline commands now automatically run prerequisite stages when their outputs
are absent on disk, rather than failing with "run X first" errors.

**`internal/builder/runner.go`**
- Added `StageStatus` struct (`Fetched`, `Built`, `Packaged` booleans).
- Added `ArtifactPath` struct pairing a local filesystem path with its S3 key.
- Added exported `MergeSummaries(...*Summary) *Summary` for command-layer use.

**`internal/builder/apt.go`**
- Added `aptSourceDir(dirs, AptEntry) string` — returns versioned source dir.
- Added `CheckAptStage(cfg, AptEntry) StageStatus` — filesystem inspection only.
- Updated `FetchApt`, `BuildApt`, `PackageApt` to use `aptSourceDir`.
- Updated `locateDebFile` signature to take `dirs` instead of `srcDir, sourceName` strings.

**`internal/builder/git.go`**
- Added `gitBareDir(dirs, GitEntry) string` — returns `repos/<name>-<ref>.git`.
- Added `CheckGitStage(cfg, GitEntry) StageStatus`.
- Updated `FetchGit`, `PackageGit`, `packageGitBundle`, `GitWorktreePath` to use `gitBareDir`.

**`internal/builder/binary.go`**
- Added `binaryFilename`, `binaryDestPath`, `binaryS3Key` helpers with versioning support.
- Added `CheckBinaryStage(cfg, BinaryEntry) StageStatus`.
- Updated `FetchBinaries` to use `binaryDestPath` (creates versioned sub-directory when needed).
- Added `BinaryArtifactPaths(cfg, store, entryFilter) []ArtifactPath` for upload/sync use.

**`internal/builder/pypi.go`**
- Added `pypiWheelsDir(dirs, PypiManifest) string` and `pypiS3Prefix(PypiManifest) string`.
- Added `CheckPypiStage(cfg, store) StageStatus`.
- Added `PypiArtifactDir(cfg, store) (localDir, s3Prefix string)`.
- Updated `BuildPypi` and `PackagePypi` to use `pypiWheelsDir`.

**`cmd/bootstrap/pipeline.go`** (new file)
- Reusable cascade helpers used by build, package, and upload commands:
  `ensureFetchedBinaries`, `ensureFetchedGit`, `ensureFetchedApt`, `ensureFetchedPypi`,
  `ensureBuiltApt`, `ensureBuiltPypi`, `ensurePackagedGit`, `ensurePackagedApt`, `ensurePackagedPypi`.

**`cmd/bootstrap/cmd_build.go`**
- Rewritten: `build` now runs fetch cascade then the build stage only (not package).
  - `binary` / `git`: ensure fetched.
  - `apt`: ensure fetched, then `BuildApt`.
  - `pypi`: ensure fetched, then `BuildPypi`.

**`cmd/bootstrap/cmd_package.go`**
- Rewritten: `package` now cascades through all prerequisite stages automatically.
  - `git`: ensure fetched, then package.
  - `apt` / `pypi`: cascade fetch → build → package as needed.

**`cmd/bootstrap/cmd_upload.go`**
- Rewritten: `upload` runs the full cascade (fetch → build → package) before uploading.
- Binary upload now uses `BinaryArtifactPaths` for per-entry, versioned S3 keys.
- PyPI upload uses `PypiArtifactDir` for the versioned S3 prefix.

### Feature 2 — `sync` command

**`cmd/bootstrap/cmd_sync.go`** (new file)
- `bootstrap sync [TYPE...]` — dumb push: uploads whatever local artifacts exist
  to S3 without running any pipeline stages.
- Binary: per-entry upload via `BinaryArtifactPaths`.
- Git: `SyncDir bundles/ → repos/`.
- APT: `SyncDir apt-repo/ → packages/apt/`.
- PyPI: `SyncDir wheels[/<version>]/ → pypi/wheels[/<version>]/`.

**`cmd/bootstrap/main.go`**
- Registered `newSyncCmd`.

**`internal/shell/shell.go`**
- Added `sync` to the readline autocomplete tree and help text.

### Feature 3 — Versioned paths

Local paths and S3 keys now include version information when the `version` field
is set in a manifest entry, allowing multiple versions to coexist.

| Type   | Local path                              | S3 key                                          |
|--------|-----------------------------------------|-------------------------------------------------|
| binary | `binaries/<version>/<filename>`         | `binaries/<name>/<version>/<filename>`          |
| binary (unversioned) | `binaries/<filename>`     | `binaries/<filename>`                           |
| git    | `repos/<name>-<ref>.git` (bare)         | `repos/<name>/<name>-<ref>.bundle`              |
| apt    | `sources/<sourceName>-<version>/`       | (reprepro manages S3 sync; no path change)      |
| pypi   | `wheels/<version>/`                     | `pypi/wheels/<version>/`                        |
| pypi (unversioned) | `wheels/`                 | `pypi/wheels/`                                  |

Git bare repos changed from `repos/<name>.git` to `repos/<name>-<ref>.git`
since `Ref` is always non-empty and serves as the version identifier.

### Tests

**`internal/builder/stage_test.go`** (new file)
- `TestCheckBinaryStage_*` — not fetched, fetched, versioned vs. unversioned path.
- `TestBinaryDestPath_*` — no version, versioned, filename override.
- `TestBinaryS3Key_*` — no version, versioned.
- `TestCheckGitStage_*` — empty, fetched only, fetched+packaged.
- `TestGitBareDir` — verifies `<name>-<ref>.git` naming.
- `TestAptSourceDir_*` — no version, versioned, source_name override.
- `TestCheckAptStage_*` — empty, source-build fetched/built, apt-get fetched.
- `TestPypiWheelsDir_*`, `TestPypiS3Prefix_*` — no version, versioned.
- `TestCheckPypiStage_*` — empty, fetched, built, packaged.
- `TestMergeSummaries_*` — nil inputs, combined totals.
- `TestBinaryArtifactPaths` — only returns entries with files on disk; correct S3 keys.

## bodega: Replace readline shell with bubbletea TUI (`tools/bodega/`)

Replaced the `chzyer/readline`-based interactive REPL with a three-pane bubbletea TUI
launched by `bodega shell`.

### New files

| File | Purpose |
|---|---|
| `internal/tui/app.go` | Root bubbletea model; layout, focus, resize |
| `internal/tui/sources.go` | Sources pane: tree view with expand/collapse/filter |
| `internal/tui/details.go` | Details pane: per-entry metadata display |
| `internal/tui/shell_pane.go` | Shell pane: text input, scrolling viewport, command dispatch |
| `internal/tui/commands.go` | Shared helpers: `splitArgs`, `extractFlag` |
| `internal/tui/popup.go` | Help and confirm overlay popups |
| `internal/tui/styles.go` | Lipgloss styles, colours, status icons |
| `internal/tui/tui_test.go` | 14 unit tests |

### Modified files

| File | Change |
|---|---|
| `cmd/bootstrap/cmd_shell.go` | Replaced readline REPL launch with `tui.Run()` |
| `go.mod` | Added `bubbletea v1.3.10`, `bubbles v1.0.0`, `lipgloss v1.1.0`; removed `chzyer/readline` |

### Deleted files

- `internal/shell/shell.go`
- `internal/shell/shell_test.go`

### Keybindings

Sources pane: `Tab` focus switch, `Up`/`Down` navigate, `Enter` expand/collapse, `B` build, `U` upload, `D` delete (confirm), `F` freeze, `R` remove from S3, `/` filter, `?` help, `q` quit.
Shell pane: `Tab` focus switch, `Up`/`Down` history, `Enter` execute.

### Command execution

All commands (`build`, `fetch`, `package`, `upload`, `sync`, `status`, `verify`, `init`, `delete`, `remove`, `freeze`) call Go functions directly — no subprocess fork to the bodega binary. Output streams into the viewport. Commands that modify state trigger a manifest reload and S3 re-check automatically.

## bodega: cross-type cascade, build logging, and PyPI tree expansion (`tools/bodega/`)

Three features added to the bodega tool.

### Feature 1 — Cross-type cascade for PyPI

`FetchPypi` now auto-fetches and auto-packages any git repos referenced in
`base_requirements` before resolving requirements. Previously, running
`fetch pypi` would fail with "git repo not found" when the corresponding git
entries had not been cloned first.

**`internal/builder/pypi.go`**
- Added a cascade loop before the base requirements resolution loop in
  `FetchPypi`. For each repo in `base_requirements`, the function calls
  `CheckGitStage`, then conditionally calls `FetchGit` and/or `PackageGit`.
- When a repo is referenced in `base_requirements` but absent from the git
  manifest, a `WARNING` is logged and the entry is skipped rather than failing.

### Feature 2 — Build logging

Structured, per-session and per-package logging for both the TUI and CLI.

**`internal/logging/logger.go`** (new package)
- `BuildLogger` struct with `logDir`, `sessionLog`, `auditLog`, `timestamp`,
  and a `sync.Mutex` for safe concurrent access (TUI goroutines).
- `NewBuildLogger(logDir string) (*BuildLogger, error)` — opens
  `<logDir>/build-<timestamp>.log` (session log) and `<logDir>/audit.log`
  (append-only). Non-fatal: returns a no-op logger on directory creation
  failure.
- `StartPackage(typ, name string) io.Writer` — creates
  `<logDir>/packages/<typ>/<name>/<timestamp>.log` and returns an
  `io.MultiWriter` writing to both the package log and the session log.
- `SessionWriter() io.Writer` — returns the session log for output that is not
  package-specific.
- `Audit(format string, args ...interface{})` — appends a timestamped line to
  `audit.log`.
- `Close()` — closes all file handles.

**`internal/builder/runner.go`**
- Added `Logger *logging.BuildLogger` field to `Config`.
- Added `entryWriter(typ, name string) io.Writer` method: returns
  `Logger.StartPackage(typ, name)` when a logger is set, otherwise falls
  through to `stdout()`.

**`internal/builder/apt.go`, `git.go`, `binary.go`**
- Each per-entry loop now assigns `out := cfg.entryWriter(type, entry.Name)`
  rather than using the function-level `out := cfg.stdout()`.
- Each entry completes with a `cfg.Logger.Audit(...)` call recording success or
  failure with elapsed time.
- Frozen-entry log messages routed through `cfg.logf` so they go to the session
  log rather than a stale per-function `out`.

**`internal/builder/pypi.go`**
- `FetchPypi` and `PackagePypi` each emit a single `cfg.Logger.Audit()` call
  on completion.

**`internal/tui/executor.go`**
- `builderCfg` now creates a `BuildLogger` when `cfg.LogDir` is non-empty.
  Sets `bc.Stdout = io.MultiWriter(buf, logger.SessionWriter())` so TUI log
  pane and session file both receive all output.

**`cmd/bodega/cmd_build.go`**
- Creates a `BuildLogger` at the start of `RunE` when `cfg.LogDir` is set.
- Sets `bcfg.Stdout = io.MultiWriter(os.Stdout, logger.SessionWriter())` so
  CLI output and session log file both receive all output.
- Summary `.Print()` calls use `buildOut` so the session log captures the
  build summary as well.

### Feature 3 — PyPI individual packages in sources tree

**`internal/tui/sources.go`**
- `TreeNode` gained a `BaseApp bool` field to distinguish `base_requirements`
  entries from explicit package entries.
- `BuildTree` now expands the `pypi/` group into individual child nodes:
  one per entry in `base_requirements` (labeled `<repo>@<ref> (base app)`)
  and one per entry in `packages`.
- Added `sortedStringKeys` helper for deterministic ordering of the
  `BaseRequirements` map.

**`internal/builder/pypi_deps.go`** (new file)
- `PypiDepGraph` and `PypiPackageInfo` structs for the serialised dependency
  graph.
- `ScanWheelMetadata(wheelDir, store)` — opens each `.whl` file as a ZIP
  archive, reads `*.dist-info/METADATA`, parses `Name`, `Version`, and
  `Requires-Dist` headers. Tags entries as `Explicit` or `BaseApp` from
  `store.Pypi`. Builds a reverse `UsedBy` index.
- `LoadDepGraph(path)` — reads cached JSON; returns `(nil, nil)` when absent.
- `SaveDepGraph(path, graph)` — writes indented JSON.
- Helper functions: `normalisePkgName` (PEP 503), `pkgBaseName` (strips
  version specifiers, extras, markers), `appendUniq`, `readWheelMetadata`,
  `parseWheelMetadata`.

**`internal/builder/pypi.go`**
- `PackagePypi` calls `ScanWheelMetadata` and `SaveDepGraph` after generating
  `MANIFEST.sha256`. Failures are logged as warnings, not build failures.

**`internal/tui/details.go`**
- `detailsModel` gained a `buildRoot string` field.
- `newDetailsModel` now takes `(store, buildRoot)`.
- The `TypePypi` case in `renderEntryDetails` now distinguishes `BaseApp` nodes
  (shows Name, Type, Ref, and dep graph summary when available) from explicit
  package nodes (shows Name, Type, Version, Used-by from dep graph).
- Loads the dep graph lazily from `<buildRoot>/wheels[/<version>]/dep-graph.json`.

**`internal/tui/app.go`**
- `newDetailsModel` call updated to pass `cfg.BuildRoot`.

**`internal/tui/tui_test.go`**
- Updated two `newDetailsModel` call sites to pass the new `buildRoot` argument.

## bodega: Enhanced create form TUI (`tools/bodega/`)

### manifest/types.go

- Added `Checksum` struct: `Algorithm string` (md5/sha1/sha256/sha512) and `Value string` (lowercase hex).
- Added `Checksum *Checksum` field to `AptEntry`, `BinaryEntry`, and `PypiPackage`.

### internal/tui/popup.go

- Extended `formField` with: `Select bool`, `Options []string`, `Disabled bool`, `Hint string`.
- Extended `popupModel` with: `prevCursor int`, `onChange func(*popupModel)`, `validate func([]formField) string`, `validationError string`, `selectOpen bool`, `selectCursor int`, `jsonInput bool`, `jsonBuffer string`, `jsonError string`.
- `HandleFormKey`: Select fields open inline submenu on Enter or Space; tab navigation skips Disabled fields; disabled fields block keypresses; `onChange` hook invoked after every navigation, checkbox toggle, and backspace.
- Added `openSelectMenu`, `handleSelectMenuKey`: Up/Down navigate submenu, Enter selects and closes, Esc discards selection.
- Added `HandleJSONOverlayKey`: Enter appends newline, Ctrl+S calls caller-provided apply function, Esc discards, backspace and runes edit the buffer.
- `HandleFormRune`: skips Checkbox, Select, and Disabled fields; calls `onChange` after every rune.
- `renderForm`: Select fields show `▾` after value; Disabled fields render in dim style; Hint renders below field in dim style; inline submenu box renders below focused Select field when open; validation error shown above footer.
- Added `renderSelectMenu`: inline bordered box with cursor-highlighted current option.
- `View`: delegates to new `renderJSONOverlay` when `jsonInput` is true.
- Added `renderJSONOverlay(screenWidth, screenHeight)`: centered box at ~80% screen width containing the buffer, a trailing cursor, and an error line when validation failed.

### internal/tui/app.go

- Added `encoding/json` import for JSON overlay parsing.
- `handlePopupKey` for `popupForm`: routes all input to `HandleJSONOverlayKey` when `jsonInput` is true; intercepts `j` key (before printable-rune handling) to open the JSON overlay; treats Space as a control key on Select fields.
- Replaced stub `"c"` create form with `buildCreatePopup()`.
- `buildCreatePopup()`: constructs a `popupModel` starting with the full apt field set; wires `onChange`, `validate`, and `onFormSave` closures.
- `rebuildCreateFields(entryType, prev)`: builds type-appropriate field slices (apt, git, pypi, binary), carrying over values already entered for matching labels.
- `updateChecksumHint(fields)`: updates Checksum Hint; implements Latest↔Version coupling for binary entries; auto-fills Name from URL when Name is empty and URL is non-empty.
- `validateCreateFields(fields) string`: enforces required fields per type; blocks save when Checksum is present but invalid.
- `saveCreateEntry(store, fields) error`: marshals form values into the appropriate manifest struct and persists via store Save methods.
- `makeJSONApplyFn()`: closure that parses the JSON overlay buffer into the appropriate entry type and populates form fields.
- `detectChecksumAlgorithm(hex) string`: returns md5/sha1/sha256/sha512 based on hex string length; returns "" for invalid input.
- `checksumHint(val) string`: "(optional — auto-generated on build)" / "detected: <algo>" / "invalid checksum".
- `extractNameFromURL(url, entryType) string`: strips .git suffix for git, archive extensions (.tar.gz/.tgz/.zip/.deb/.rpm) for binary/apt.
- Added `fieldValueFromSlice`, `setFieldValue` field helpers.

### internal/tui/tui_test.go

Added 25 new test functions:
- `TestDetectChecksumAlgorithm`: all four algorithms, non-hex input, wrong lengths, uppercase.
- `TestChecksumHint`: empty/valid/invalid values.
- `TestExtractNameFromURL`: git, binary, apt URL patterns.
- `TestRebuildCreateFieldsPreservesValues`: value carry-over across type switch.
- `TestRebuildCreateFieldsGit`, `TestRebuildCreateFieldsBinary`: required label presence.
- `TestValidateCreateFields`: table-driven; missing name, missing URL/Ref for git, invalid/valid checksum.
- `TestSelectFieldOpenClose`: Space opens, Down navigates, Enter selects and closes.
- `TestSelectFieldEscDiscards`: Esc discards navigation and leaves popup active.
- `TestDisabledFieldsSkippedByTab`: Tab skips disabled field in sequence.
- `TestDisabledFieldIgnoresRune`: rune input does not mutate disabled field.
- `TestUpdateChecksumHintLatestCoupling`: Latest=yes disables Version and sets it to "latest".
- `TestUpdateChecksumHintLatestOff`: Latest=no re-enables Version and clears "latest".
- `TestJSONOverlayOpenClose`, `TestJSONOverlayApply`, `TestJSONOverlayApplyError`, `TestJSONOverlayBufferEditing`.
- `TestSetFieldValue`, `TestFieldValueFromSlice`.
