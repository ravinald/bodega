package tui

import (
	"bytes"
	"context"
	"fmt"
	"io"

	tea "github.com/charmbracelet/bubbletea"

	"encoding/json"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/inventory"
	"github.com/ravinald/bodega/internal/logging"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/placement"
	bos3 "github.com/ravinald/bodega/internal/s3"
	"github.com/ravinald/bodega/internal/server"
	"github.com/ravinald/bodega/internal/storage"
)

// cmdOutputMsg carries the text result of an executed command back to the
// bubbletea event loop. The refresh flag indicates that the store changed and
// the sources pane should be rebuilt.
type cmdOutputMsg struct {
	output  string
	refresh bool
	err     error
}

// errQuit is a sentinel error that signals the TUI to exit cleanly.
var errQuit = fmt.Errorf("quit")

// BuildStage identifies which pipeline stage to execute for a given entry.
type BuildStage int

const (
	// StageFetch downloads the source (clone / apt download / binary fetch).
	StageFetch BuildStage = iota
	// StageBuild compiles or prepares sources (apt build, pypi wheel build).
	StageBuild
	// StagePackage creates a distributable artifact from built sources.
	StagePackage
	// StageDeploy uploads the packaged artifact to S3.
	StageDeploy
	// StageAll runs the full pipeline: fetch → build → package → deploy.
	StageAll
)

// builderCfg converts a config.Config into a builder.Config with output
// directed to buf. When cfg.LogDir is set and accessible, a BuildLogger is
// created and its session writer is teed into the buffer so that all output
// lands in both the TUI log pane and the on-disk session log.
func builderCfg(buf *bytes.Buffer, cfg *config.Config) *builder.Config {
	bc := &builder.Config{
		BuildRoot:      cfg.BuildRoot,
		ManifestDir:    cfg.ManifestDir,
		Bucket:         cfg.Bucket,
		Region:         cfg.Region,
		Verbose:        cfg.Verbose,
		AptRoot:        cfg.AptRoot,
		GitRoot:        cfg.GitRoot,
		PypiRoot:       cfg.PypiRoot,
		BinaryRoot:     cfg.BinaryRoot,
		AutoImportDeps: true, // default: auto-import discovered deps
		Stdout:         buf,
	}

	if cfg.LogDir != "" {
		logger, err := logging.NewBuildLogger(cfg.LogDir)
		if err == nil {
			// Tee builder output to both the in-memory buffer (for the TUI log
			// pane) and the on-disk session log.
			bc.Stdout = io.MultiWriter(buf, logger.SessionWriter())
			bc.Logger = logger
			// Log the session file path so the viewport shows which file output goes to.
			fmt.Fprintf(buf, "--- log: %s ---\n", logger.SessionLogPath())
		}
	}

	return bc
}

// executeStage runs a specific build pipeline stage for a single entry and
// returns a tea.Cmd that delivers the result as a cmdOutputMsg.
func executeStage(stage BuildStage, entryType, entryName string, cfg *config.Config, store *manifest.Store, stores storage.Resolver, force ...bool) tea.Cmd {
	return func() tea.Msg {
		var buf bytes.Buffer
		var err error
		refresh := false

		bc := builderCfg(&buf, cfg)
		if len(force) > 0 && force[0] {
			bc.Force = true
		}

		switch stage {
		case StageFetch:
			err = runFetch(&buf, cfg, store, []string{entryType, "--entry", entryName})
		case StageBuild:
			err = runBuildStage(&buf, bc, store, entryType, entryName)
		case StagePackage:
			err = runPackageStage(&buf, bc, store, entryType, entryName)
		case StageDeploy:
			if stores == nil {
				err = fmt.Errorf("deploy requires a configured storage backend")
			} else {
				err = runUpload(&buf, cfg, store, stores, []string{entryType})
				if err == nil {
					refresh = true
				}
			}
		case StageAll:
			err = runFullPipeline(&buf, cfg, bc, store, stores, entryType, entryName)
			if err == nil {
				refresh = true
			}
		}

		return cmdOutputMsg{output: buf.String(), refresh: refresh, err: err}
	}
}

// runBuildStage runs only the build step (no fetch, no package) for a single
// entry type/name pair.
func runBuildStage(buf *bytes.Buffer, bc *builder.Config, store *manifest.Store, entryType, entryName string) error {
	totalFail := 0
	switch entryType {
	case manifest.TypeApt:
		s := builder.BuildApt(bc, store, entryName)
		s.Print(buf)
		totalFail += s.Failures
	case manifest.TypePypi:
		s := builder.BuildPypi(bc, store)
		s.Print(buf)
		totalFail += s.Failures
	case manifest.TypeGit, manifest.TypeBinary:
		fmt.Fprintf(buf, "No separate build step for %s — use fetch or package.\n", entryType)
	}
	if totalFail > 0 {
		return fmt.Errorf("%d build(s) failed", totalFail)
	}
	return nil
}

// runPackageStage runs only the package step for a single entry type/name.
func runPackageStage(buf *bytes.Buffer, bc *builder.Config, store *manifest.Store, entryType, entryName string) error {
	totalFail := 0
	switch entryType {
	case manifest.TypeGit:
		s := builder.PackageGit(bc, store, entryName)
		s.Print(buf)
		totalFail += s.Failures
	case manifest.TypeApt:
		s := builder.PackageApt(bc, store, entryName)
		s.Print(buf)
		totalFail += s.Failures
	case manifest.TypePypi:
		s := builder.PackagePypi(bc, store)
		s.Print(buf)
		totalFail += s.Failures
	case manifest.TypeBinary:
		fmt.Fprintf(buf, "No separate package step for binary — binaries are uploaded directly.\n")
	}
	if totalFail > 0 {
		return fmt.Errorf("%d package(s) failed", totalFail)
	}
	return nil
}

// runFullPipeline runs fetch → build → package → upload for a single entry.
func runFullPipeline(buf *bytes.Buffer, cfg *config.Config, bc *builder.Config, store *manifest.Store, stores storage.Resolver, entryType, entryName string) error {
	// Fetch
	if err := runFetch(buf, cfg, store, []string{entryType, "--entry", entryName}); err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	// Build
	if err := runBuildStage(buf, bc, store, entryType, entryName); err != nil {
		return fmt.Errorf("build: %w", err)
	}
	// Package
	if err := runPackageStage(buf, bc, store, entryType, entryName); err != nil {
		return fmt.Errorf("package: %w", err)
	}
	// Deploy
	if stores == nil {
		fmt.Fprintf(buf, "Skipping deploy: no storage backend configured.\n")
		return nil
	}
	return runUpload(buf, cfg, store, stores, []string{entryType})
}

// executeSyncAll uploads all artifact types to S3 and returns a tea.Cmd.
func executeSyncAll(types []string, cfg *config.Config, store *manifest.Store, stores storage.Resolver) tea.Cmd {
	return func() tea.Msg {
		var buf bytes.Buffer
		err := runUpload(&buf, cfg, store, stores, types)
		return cmdOutputMsg{output: buf.String(), refresh: err == nil, err: err}
	}
}

// executeInit initialises the S3 bucket structure and returns a tea.Cmd.
func executeInit(cfg *config.Config, s3client *bos3.Client) tea.Cmd {
	return func() tea.Msg {
		var buf bytes.Buffer
		err := runInit(&buf, cfg, s3client)
		return cmdOutputMsg{output: buf.String(), refresh: false, err: err}
	}
}

// executeVerify checks manifest MD5 checksums and returns a tea.Cmd.
func executeVerify(cfg *config.Config, store *manifest.Store) tea.Cmd {
	return func() tea.Msg {
		var buf bytes.Buffer
		err := runVerify(&buf, cfg)
		return cmdOutputMsg{output: buf.String(), refresh: false, err: err}
	}
}

// executeFreeze toggles the frozen flag for the given entry and returns a
// tea.Cmd. The store is mutated and saved; refresh=true so the tree rebuilds.
func executeFreeze(entryType, entryName string, cfg *config.Config, store *manifest.Store, auditDB *audit.DB) tea.Cmd {
	return func() tea.Msg {
		var buf bytes.Buffer
		err := runFreeze(&buf, cfg, store, entryType, entryName, auditDB)
		return cmdOutputMsg{output: buf.String(), refresh: err == nil, err: err}
	}
}

// executeDelete removes the named entry from the manifest and returns a
// tea.Cmd. refresh=true causes the sources tree to rebuild.
func executeDelete(entryType, entryName string, cfg *config.Config, store *manifest.Store, auditDB *audit.DB) tea.Cmd {
	return func() tea.Msg {
		var buf bytes.Buffer
		err := runDelete(&buf, cfg, store, entryType, entryName, auditDB)
		return cmdOutputMsg{output: buf.String(), refresh: err == nil, err: err}
	}
}

// executeRemoveFromS3 deletes the artifact from S3 without touching the
// manifest and returns a tea.Cmd. refresh=true re-checks S3 status.
func executeRemoveFromS3(entryType, entryName string, cfg *config.Config, store *manifest.Store, stores storage.Resolver) tea.Cmd {
	return func() tea.Msg {
		var buf bytes.Buffer
		err := runRemove(&buf, cfg, store, stores, entryType, entryName)
		return cmdOutputMsg{output: buf.String(), refresh: err == nil, err: err}
	}
}

// --- lower-level run helpers ---

// signalServer tells a running bodega serve that what it publishes changed.
//
// The CLI classifies each verb where it is registered and one cobra hook sends
// the signal; nothing in the TUI passes through cobra, so a freeze or a delete
// here left the entry published until the hourly tick swept it up — the same
// defect B6 fixed for the CLI, arriving by a second route. The signal lives in
// these run helpers rather than in the tea.Cmd wrappers above them so a future
// caller reaching a mutating verb directly gets it too, which is how the first
// route came to be missed.
//
// A failure is reported and never fatal: the mutation has already committed by
// the time this runs, and the tick is the floor under a signal that did not
// land.
func signalServer(buf *bytes.Buffer, cfg *config.Config) {
	if cfg == nil {
		return
	}
	if err := server.NotifyReload(cfg.LogDir); err != nil {
		fmt.Fprintf(buf, "warning: could not notify server: %v\n", err)
	}
}

func runFetch(buf *bytes.Buffer, cfg *config.Config, store *manifest.Store, args []string) error {
	entryFilter, remaining := extractFlag(args, "--entry")
	types, err := resolveTypes(remaining)
	if err != nil {
		return err
	}
	bc := builderCfg(buf, cfg)
	totalFail := 0
	for _, t := range types {
		var sum *builder.Summary
		switch t {
		case manifest.TypeBinary:
			sum = builder.FetchBinaries(bc, store, entryFilter)
		case manifest.TypeGit:
			sum = builder.FetchGit(bc, store, entryFilter)
		case manifest.TypeApt:
			sum = builder.FetchApt(bc, store, entryFilter)
		case manifest.TypePypi:
			sum = builder.FetchPypi(bc, store)
		}
		if sum != nil {
			sum.Print(buf)
			totalFail += sum.Failures
		}
	}
	if totalFail > 0 {
		return fmt.Errorf("%d fetch(es) failed", totalFail)
	}
	return nil
}

// runUpload writes each type's local artifacts through the placement hierarchy,
// to the backend the manifest records for each version.
//
// It resolves through storage.Resolver rather than a bare S3 client, and
// through internal/placement rather than its own switch. The switch it replaced
// knew four of the eight types and reported the other four as "No artifacts",
// carried its own copies of the key prefixes, and synced whole directories to
// the default bucket whatever storage_by_type said.
func runUpload(buf *bytes.Buffer, cfg *config.Config, store *manifest.Store, stores storage.Resolver, args []string) error {
	if stores == nil {
		return fmt.Errorf("upload requires a configured storage backend")
	}
	types, err := resolveTypes(args)
	if err != nil {
		return err
	}
	pl := placement.NewWith(stores, store, buf, false)
	bc := builderCfg(buf, cfg)
	ctx := context.Background()
	for _, t := range types {
		fmt.Fprintf(buf, "\n--- upload: %s ---\n", t)
		if _, err := pl.UploadType(ctx, bc, t); err != nil {
			return err
		}
	}
	return nil
}

func runVerify(buf *bytes.Buffer, cfg *config.Config) error {
	_ = cfg // verification now done via store; legacy .md5 check for backward compat
	fmt.Fprintf(buf, "  Manifest integrity: using store backend validation\n")
	return nil
}

func runInit(buf *bytes.Buffer, cfg *config.Config, s3client *bos3.Client) error {
	if s3client == nil {
		return fmt.Errorf("init requires a configured S3 bucket")
	}
	fmt.Fprintf(buf, "Initialising bucket s3://%s ...\n", cfg.Bucket)
	return bos3.InitBucket(context.Background(), s3client.S3Client(), cfg.Bucket, cfg.Region)
}

func runDelete(buf *bytes.Buffer, cfg *config.Config, store *manifest.Store, entryType, name string, auditDB *audit.DB) error {
	if !isValidType(entryType) {
		return fmt.Errorf("unknown type %q", entryType)
	}
	ctx := context.Background()
	frozen, err := isFrozenEntry(store, ctx, entryType, name)
	if err != nil {
		return err
	}
	if frozen {
		return fmt.Errorf("entry %s/%s is frozen — unfreeze first", entryType, name)
	}

	// Capture before state for audit.
	var beforeJSON []byte
	if auditDB != nil {
		if pm, err := store.GetPackage(ctx, entryType, name); err == nil && pm != nil {
			beforeJSON, _ = json.MarshalIndent(pm, "", "  ")
		}
	}

	if err := store.DeletePackage(ctx, entryType, name); err != nil {
		return err
	}
	if err := store.SaveIndex(ctx); err != nil {
		fmt.Fprintf(buf, "WARNING: could not save index: %v\n", err)
	}
	fmt.Fprintf(buf, "Removed %s/%s from manifest.\n", entryType, name)

	if auditDB != nil {
		_ = auditDB.Record(ctx, audit.Event{
			EventType: audit.EventDelete,
			PkgType:   entryType,
			PkgName:   name,
			Actor:     audit.CurrentActor(),
			Status:    "success",
			Details:   audit.FormatDiff(beforeJSON, nil),
		})
	}
	signalServer(buf, cfg)
	return nil
}

// runRemove deletes every object backing an entry, keyed through
// inventory.ArtifactKeys so the TUI removes what the uploader wrote, on the
// backend each version records.
//
// Resolving no key is an error rather than a quiet success. Every Delete in
// bodega is idempotent, so a delete aimed at a key nothing wrote reports the
// same "Deleted." as one that worked, and this is the last place the two can
// still be told apart.
func runRemove(buf *bytes.Buffer, cfg *config.Config, store *manifest.Store, stores storage.Resolver, entryType, name string) error {
	if stores == nil {
		return fmt.Errorf("remove requires a configured storage backend")
	}
	if !isValidType(entryType) {
		return fmt.Errorf("unknown type %q", entryType)
	}
	ctx := context.Background()
	pm, err := store.GetPackage(ctx, entryType, name)
	if err != nil {
		return fmt.Errorf("get %s/%s: %w", entryType, name, err)
	}
	if pm == nil {
		return fmt.Errorf("%s entry %q not found", entryType, name)
	}
	if len(pm.Versions) == 0 {
		return fmt.Errorf("%s/%s has no versions, so no artifact key resolves for it", entryType, name)
	}

	removed := 0
	for _, ve := range pm.Versions {
		label := pm.Name + "@" + versionLabel(ve)
		backend := placement.EffectiveStorage(ve.Storage)
		objStore, err := stores.ByName(ve.Storage)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		keys, err := inventory.ArtifactKeys(ctx, objStore, pm, ve)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if len(keys) == 0 {
			return fmt.Errorf("%s: no object key resolves on %q; refusing to report a delete that looked nowhere",
				label, backend)
		}
		for _, key := range keys {
			status, err := objStore.Head(ctx, key)
			if err != nil {
				return fmt.Errorf("%s: head %s on %q: %w", label, key, backend, err)
			}
			if !status.Exists {
				fmt.Fprintf(buf, "  %s: %s/%s already absent\n", label, objStore.Label(), key)
				continue
			}
			if err := objStore.Delete(ctx, key); err != nil {
				return fmt.Errorf("%s: delete %s from %q: %w", label, key, backend, err)
			}
			fmt.Fprintf(buf, "  %s: deleted %s/%s\n", label, objStore.Label(), key)
			removed++
		}
	}
	fmt.Fprintf(buf, "Deleted %d object(s).\n", removed)
	signalServer(buf, cfg)
	return nil
}

// versionLabel names an entry for an operator: Version, else Ref, else "?".
func versionLabel(ve manifest.VersionEntry) string {
	if ve.Version != "" {
		return ve.Version
	}
	if ve.Ref != "" {
		return ve.Ref
	}
	return "?"
}

func runFreeze(buf *bytes.Buffer, cfg *config.Config, store *manifest.Store, entryType, name string, auditDB *audit.DB) error {
	if !isValidType(entryType) {
		return fmt.Errorf("unknown type %q", entryType)
	}
	ctx := context.Background()
	pm, err := store.GetPackage(ctx, entryType, name)
	if err != nil {
		return fmt.Errorf("get %s/%s: %w", entryType, name, err)
	}
	if pm == nil {
		return fmt.Errorf("%s entry %q not found", entryType, name)
	}

	beforeJSON, _ := json.MarshalIndent(pm, "", "  ")

	// Toggle Frozen on all versions.
	allFrozen := true
	for _, ve := range pm.Versions {
		if !ve.Frozen {
			allFrozen = false
			break
		}
	}
	newState := !allFrozen
	for i := range pm.Versions {
		pm.Versions[i].Frozen = newState
	}
	if err := store.SavePackage(ctx, pm); err != nil {
		return err
	}
	printFreezeResult(buf, entryType, name, newState)

	if auditDB != nil {
		afterJSON, _ := json.MarshalIndent(pm, "", "  ")
		_ = auditDB.Record(ctx, audit.Event{
			EventType: audit.EventFreeze,
			PkgType:   entryType,
			PkgName:   name,
			Actor:     audit.CurrentActor(),
			Status:    "success",
			Details:   audit.FormatDiff(beforeJSON, afterJSON),
		})
	}
	signalServer(buf, cfg)
	return nil
}

func printFreezeResult(buf *bytes.Buffer, t, name string, frozen bool) {
	state := "frozen"
	if !frozen {
		state = "unfrozen"
	}
	fmt.Fprintf(buf, "%s/%s is now %s.\n", t, name, state)
}

// isFrozenEntry reports whether the given entry has all versions frozen.
func isFrozenEntry(store *manifest.Store, ctx context.Context, t, name string) (bool, error) {
	pm, err := store.GetPackage(ctx, t, name)
	if err != nil {
		return false, fmt.Errorf("get %s/%s: %w", t, name, err)
	}
	if pm == nil {
		return false, fmt.Errorf("%s entry %q not found", t, name)
	}
	if len(pm.Versions) == 0 {
		return false, nil
	}
	for _, ve := range pm.Versions {
		if !ve.Frozen {
			return false, nil
		}
	}
	return true, nil
}

// lastURLSegment returns the portion of a URL after the final '/'.
func lastURLSegment(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return s[i+1:]
		}
	}
	return s
}

// resolveTypes expands an empty slice to AllTypes and validates each element.
func resolveTypes(args []string) ([]string, error) {
	if len(args) == 0 {
		return manifest.AllTypes, nil
	}
	for _, t := range args {
		if !isValidType(t) {
			return nil, fmt.Errorf("unknown type %q — must be one of: apt, git, pypi, binary", t)
		}
	}
	return args, nil
}

// isValidType returns true when t is one of the four known manifest types.
func isValidType(t string) bool {
	for _, known := range manifest.AllTypes {
		if t == known {
			return true
		}
	}
	return false
}
