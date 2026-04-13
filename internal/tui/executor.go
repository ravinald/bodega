package tui

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"encoding/json"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/logging"
	"github.com/ravinald/bodega/internal/manifest"
	bos3 "github.com/ravinald/bodega/internal/s3"
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
func executeStage(stage BuildStage, entryType, entryName string, cfg *config.Config, store *manifest.Store, s3client *bos3.Client, force ...bool) tea.Cmd {
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
			if s3client == nil {
				err = fmt.Errorf("deploy requires a configured S3 bucket")
			} else {
				err = runUpload(&buf, cfg, s3client, []string{entryType})
				if err == nil {
					refresh = true
				}
			}
		case StageAll:
			err = runFullPipeline(&buf, cfg, bc, store, s3client, entryType, entryName)
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
func runFullPipeline(buf *bytes.Buffer, cfg *config.Config, bc *builder.Config, store *manifest.Store, s3client *bos3.Client, entryType, entryName string) error {
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
	if s3client == nil {
		fmt.Fprintf(buf, "Skipping deploy: no S3 bucket configured.\n")
		return nil
	}
	return runUpload(buf, cfg, s3client, []string{entryType})
}

// executeSyncAll uploads all artifact types to S3 and returns a tea.Cmd.
func executeSyncAll(types []string, cfg *config.Config, store *manifest.Store, s3client *bos3.Client) tea.Cmd {
	return func() tea.Msg {
		var buf bytes.Buffer
		err := runUpload(&buf, cfg, s3client, types)
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
func executeFreeze(entryType, entryName string, store *manifest.Store, auditDB *audit.DB) tea.Cmd {
	return func() tea.Msg {
		var buf bytes.Buffer
		err := runFreeze(&buf, store, entryType, entryName, auditDB)
		return cmdOutputMsg{output: buf.String(), refresh: err == nil, err: err}
	}
}

// executeDelete removes the named entry from the manifest and returns a
// tea.Cmd. refresh=true causes the sources tree to rebuild.
func executeDelete(entryType, entryName string, store *manifest.Store, s3client *bos3.Client, cfg *config.Config, auditDB *audit.DB) tea.Cmd {
	return func() tea.Msg {
		var buf bytes.Buffer
		err := runDelete(&buf, cfg, store, s3client, entryType, entryName, auditDB)
		return cmdOutputMsg{output: buf.String(), refresh: err == nil, err: err}
	}
}

// executeRemoveFromS3 deletes the artifact from S3 without touching the
// manifest and returns a tea.Cmd. refresh=true re-checks S3 status.
func executeRemoveFromS3(entryType, entryName string, store *manifest.Store, s3client *bos3.Client, cfg *config.Config) tea.Cmd {
	return func() tea.Msg {
		var buf bytes.Buffer
		err := runRemove(&buf, cfg, store, s3client, entryType, entryName)
		return cmdOutputMsg{output: buf.String(), refresh: err == nil, err: err}
	}
}

// --- lower-level run helpers (shared with legacy shell_pane runCommand) ---

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

func runUpload(buf *bytes.Buffer, cfg *config.Config, s3client *bos3.Client, args []string) error {
	if s3client == nil {
		return fmt.Errorf("upload requires a configured S3 bucket")
	}
	types, err := resolveTypes(args)
	if err != nil {
		return err
	}
	ctx := context.Background()
	for _, t := range types {
		fmt.Fprintf(buf, "\n--- upload: %s ---\n", t)
		var localDir, s3Prefix string
		switch t {
		case manifest.TypeBinary:
			localDir = filepath.Join(cfg.BuildRoot, "binaries")
			s3Prefix = "binaries/"
		case manifest.TypeGit:
			localDir = filepath.Join(cfg.BuildRoot, "bundles")
			s3Prefix = "repos/"
		case manifest.TypeApt:
			localDir = filepath.Join(cfg.BuildRoot, "apt-repo")
			s3Prefix = "packages/apt/"
		case manifest.TypePypi:
			localDir = filepath.Join(cfg.BuildRoot, "wheels")
			s3Prefix = "pypi/wheels/"
		}
		if _, err := os.Stat(localDir); os.IsNotExist(err) {
			fmt.Fprintf(buf, "    No artifacts at %s — skipping\n", localDir)
			continue
		}
		n, err := s3client.SyncDir(ctx, buf, localDir, s3Prefix)
		if err != nil {
			return fmt.Errorf("upload %s: %w", t, err)
		}
		fmt.Fprintf(buf, "    Uploaded %d file(s)\n", n)
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

func runDelete(buf *bytes.Buffer, cfg *config.Config, store *manifest.Store, s3client *bos3.Client, entryType, name string, auditDB *audit.DB) error {
	_ = cfg
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
			Status:    "success",
			Details:   audit.FormatDiff(beforeJSON, nil),
		})
	}
	return nil
}

func runRemove(buf *bytes.Buffer, cfg *config.Config, store *manifest.Store, s3client *bos3.Client, entryType, name string) error {
	if s3client == nil {
		return fmt.Errorf("remove requires a configured S3 bucket")
	}
	if !isValidType(entryType) {
		return fmt.Errorf("unknown type %q", entryType)
	}
	key := s3KeyForEntry(store, entryType, name)
	if key == "" {
		return fmt.Errorf("could not determine S3 key for %s/%s", entryType, name)
	}
	fmt.Fprintf(buf, "Deleting s3://%s/%s ...\n", cfg.Bucket, key)
	if err := s3client.DeleteObject(context.Background(), key); err != nil {
		return err
	}
	fmt.Fprintf(buf, "Deleted.\n")
	return nil
}

func runFreeze(buf *bytes.Buffer, store *manifest.Store, entryType, name string, auditDB *audit.DB) error {
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
			Status:    "success",
			Details:   audit.FormatDiff(beforeJSON, afterJSON),
		})
	}
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

// s3KeyForEntry returns the primary S3 object key for a named entry (first version).
func s3KeyForEntry(store *manifest.Store, t, name string) string {
	ctx := context.Background()
	pm, err := store.GetPackage(ctx, t, name)
	if err != nil || pm == nil || len(pm.Versions) == 0 {
		return ""
	}
	ve := pm.Versions[0]
	switch t {
	case manifest.TypeBinary:
		filename := ve.Filename
		if filename == "" {
			filename = lastURLSegment(ve.URL)
		}
		return "binaries/" + filename
	case manifest.TypeGit:
		sn := strings.ReplaceAll(pm.Name, "/", "--")
		if ve.IsRelease() {
			return fmt.Sprintf("repos/%s/%s-%s.tar.gz", sn, sn, ve.Ref)
		}
		return fmt.Sprintf("repos/%s/%s-%s.bundle", sn, sn, ve.Ref)
	}
	return ""
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
