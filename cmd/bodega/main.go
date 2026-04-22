// Bootstrap is a CLI tool for managing a centralized S3 bodega package
// repository. It supports four artifact types: apt, git, pypi, and binary.
//
// Usage:
//
//	bootstrap [command] [flags]
//	bodega shell   # interactive REPL
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	bos3 "github.com/ravinald/bodega/internal/s3"
	"github.com/ravinald/bodega/internal/server"
	"github.com/ravinald/bodega/internal/storage"
)

// version is set at build time via -ldflags "-X main.version=..."
var version = "dev"

// globalFlags holds values bound to the persistent root flags.
type globalFlags struct {
	bucket      string
	region      string
	buildRoot   string
	manifestDir string
	localConfig bool
	verbose     bool
	logLevel    int
}

func main() {
	// Ensure config file and log directory exist on first run.
	path, err := config.EnsureConfigAndLogDir()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Warning: could not initialise config: %v\n", err)
	} else if path != "" {
		fc, _ := os.ReadFile(path)
		if len(fc) > 0 {
			var check struct {
				Bucket string `json:"bucket"`
			}
			if json.Unmarshal(fc, &check) == nil && check.Bucket == "" {
				_, _ = fmt.Fprintf(os.Stderr, "Config file created: %s\n", path)
				_, _ = fmt.Fprintf(os.Stderr, "Edit it to set your bucket and region.\n\n")
			}
		}
	}

	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

// newRootCmd constructs the root cobra.Command and attaches all sub-commands.
func newRootCmd() *cobra.Command {
	gf := &globalFlags{}

	root := &cobra.Command{
		Use:   "bodega",
		Short: "Manage a centralized S3 package repository",
		Long: `bodega manages a centralized S3 repository of package artifacts:
  apt     Debian packages built from source or downloaded from apt
  git     Git repositories bundled at a specific ref
  pypi    Python wheels built from a requirements set
  binary  Files downloaded directly from a URL

Configuration priority: flags > env vars (REPO_BUCKET, AWS_REGION) > config.json > defaults.`,
		SilenceUsage: true,
	}

	// Persistent flags apply to every sub-command.
	pf := root.PersistentFlags()
	pf.StringVar(&gf.bucket, "bucket", "", "S3 bucket name (env: REPO_BUCKET)")
	pf.StringVar(&gf.region, "region", "", "AWS region (env: AWS_REGION)")
	pf.StringVar(&gf.buildRoot, "build-root", "", "Local build directory (default: /opt/bodega)")
	pf.StringVar(&gf.manifestDir, "manifest-dir", defaultManifestDir(), "Path to manifests/ directory")
	pf.BoolVar(&gf.localConfig, "local-config", false, "Read/write manifests from local filesystem instead of S3")
	pf.BoolVarP(&gf.verbose, "verbose", "v", false, "Show verbose output")
	pf.IntVar(&gf.logLevel, "log-level", 0, "Logging verbosity: 0=errors, 1=warn, 2=info, 3=debug, 4=trace")

	// -V / --version prints the version and exits.
	var showVersion bool
	root.Flags().BoolVarP(&showVersion, "version", "V", false, "Print version and exit")

	// --break-glass-update-md5 is a top-level flag, not a sub-command.
	var breakGlassType string
	root.Flags().StringVar(&breakGlassType, "break-glass-update-md5", "", "Recompute MD5 for the named manifest type and exit")
	root.RunE = func(cmd *cobra.Command, args []string) error {
		if showVersion {
			fmt.Printf("bodega %s\n", version)
			return nil
		}
		if breakGlassType == "" {
			return cmd.Help()
		}
		if !isValidType(breakGlassType) {
			return fmt.Errorf("unknown type %q — must be one of: apt, git, pypi, binary", breakGlassType)
		}
		cfg, err := loadConfig(gf)
		if err != nil {
			return err
		}
		return manifest.ForceUpdateMD5(cfg.ManifestDir, breakGlassType)
	}

	// Build pipeline commands: bodega build {fetch,run,upload,sync,status}
	buildParent := &cobra.Command{
		Use:   "build",
		Short: "Build pipeline operations (fetch, run, upload, sync, status)",
	}
	buildParent.AddCommand(
		newFetchCmd(gf),
		newBuildRunCmd(gf),
		newUploadCmd(gf),
		newSyncCmd(gf),
		newStatusCmd(gf),
		newPackageCmd(gf),
	)

	// Package management commands: bodega pkg {create,delete,freeze,hide,refresh,verify,checksum}
	pkgParent := &cobra.Command{
		Use:     "pkg",
		Aliases: []string{"package"},
		Short:   "Package management (create, delete, freeze, hide, refresh, verify)",
	}
	pkgParent.AddCommand(
		newCreateCmd(gf),
		newImportCmd(gf),
		newExportCmd(gf),
		newDeleteCmd(gf),
		newRemoveCmd(gf),
		newFreezeCmd(gf),
		newHideCmd(gf),
		newRefreshCmd(gf),
		newVerifyCmd(gf),
		newChecksumCmd(gf),
	)

	// Audit commands: bodega audit {events,check}
	auditParent := &cobra.Command{
		Use:   "audit",
		Short: "Audit trail and dependency checking",
	}
	auditParent.AddCommand(
		newAuditEventsCmd(gf),
		newAuditCheckCmd(gf),
	)

	// Top-level commands.
	root.AddCommand(
		buildParent,
		pkgParent,
		auditParent,
		newTokenCmd(gf),
		newPolicyCmd(gf),
		newShowCmd(gf),
		newDashboardCmd(gf),
		newInitCmd(gf),
		newShellCmd(gf),
		newServeCmd(gf),
		newRepairCmd(gf),
		newResetCmd(gf),
	)

	return root
}

// loadConfig resolves the runtime Config from the global flags.
func loadConfig(gf *globalFlags) (*config.Config, error) {
	cfg, err := config.Load(gf.manifestDir, gf.bucket, gf.region, gf.buildRoot, gf.localConfig, gf.verbose)
	if err != nil {
		return nil, err
	}

	// Resolve log level: flag > env > config file.
	if gf.logLevel > 0 {
		cfg.LogLevel = gf.logLevel
	} else if env := os.Getenv(config.EnvLogLevel); env != "" {
		if v, err := strconv.Atoi(env); err == nil {
			cfg.LogLevel = v
		}
	}
	// --verbose is equivalent to --log-level 2 when log-level is not set.
	if cfg.Verbose && cfg.LogLevel == 0 {
		cfg.LogLevel = 2
	}

	return cfg, nil
}

// loadStore returns a manifest Store loaded from the appropriate backend
// (S3 by default, local filesystem with --local-config).
func loadStore(gf *globalFlags) (*manifest.Store, error) {
	cfg, err := loadConfig(gf)
	if err != nil {
		return nil, err
	}

	ctx := backgroundCtx()

	var store *manifest.Store
	if cfg.LocalConfig {
		store = manifest.NewLocalStore(cfg.ManifestDir)
	} else {
		// Object storage backend — need bucket for S3
		if err := requireBucket(cfg); err != nil {
			return nil, err
		}
		objStore, err := newObjStore(cfg)
		if err != nil {
			return nil, err
		}
		backend := &manifest.S3Backend{
			Prefix:   "manifests/",
			GetFn:    objStore.Get,
			PutFn:    objStore.Put,
			DeleteFn: objStore.Delete,
			ListFn:   objStore.List,
			Label_:   fmt.Sprintf("s3://%s/manifests/", cfg.Bucket),
		}
		store = manifest.NewStore(backend)
	}

	if err := store.LoadIndex(ctx); err != nil {
		return nil, fmt.Errorf("load index: %w", err)
	}
	return store, nil
}

// openAuditDB opens the audit database from config, configures timezone and
// event filtering, and returns it. Returns nil (not an error) if the audit DB
// path is empty or the DB cannot be opened -- audit is best-effort.
func openAuditDB(gf *globalFlags) *audit.DB {
	cfg, err := loadConfig(gf)
	if err != nil {
		return nil
	}
	dbPath := cfg.AuditDB
	if dbPath == "" {
		if cfg.LogDir != "" {
			dbPath = filepath.Join(cfg.LogDir, "audit.db")
		} else {
			return nil
		}
	}
	db, err := audit.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not open audit db: %v\n", err)
		return nil
	}
	if cfg.Timezone != "" {
		db.SetTimezone(cfg.Timezone)
	}
	if len(cfg.AuditEvents) > 0 {
		db.SetEventFilter(cfg.AuditEvents)
	}
	return db
}

// notifyServer sends SIGHUP to the running bodega serve process (if any)
// so it reloads manifests after CLI changes.
func notifyServer(gf *globalFlags) {
	cfg, err := loadConfig(gf)
	if err != nil {
		return
	}
	if err := server.NotifyReload(cfg.LogDir); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not notify server: %v\n", err)
	}
}

// requireBucket returns an error when cfg.Bucket is empty.
func requireBucket(cfg *config.Config) error {
	if cfg.Bucket == "" {
		return fmt.Errorf(
			"S3 bucket is required: set --bucket, the BOOTSTRAP_BUCKET env var, or add \"bucket\" to config.json",
		)
	}
	return nil
}

// defaultManifestDir returns the manifests/ directory relative to the
// binary's location, falling back to ./manifests.
func defaultManifestDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "manifests"
	}
	// Walk up from the executable to find manifests/.
	// In development, the binary lives in tools/bodega/ after
	// go build, so check the parent directories.
	candidates := []string{
		exe + "/../manifests",
		exe + "/../../manifests",
		"manifests",
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && fi.IsDir() {
			return c
		}
	}
	return "manifests"
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

// resolveTypes expands an empty slice to AllTypes and validates each entry.
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

// backgroundCtx returns a context bound to the process lifetime.
func backgroundCtx() context.Context {
	return context.Background()
}

// newObjStore creates an ObjectStore from the resolved config.
func newObjStore(cfg *config.Config) (storage.ObjectStore, error) {
	ctx := backgroundCtx()
	objStore, err := storage.New(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect to storage: %w", err)
	}
	return objStore, nil
}

// newS3Client creates a direct S3 client from the resolved config. This is
// retained for callers that require the concrete *bos3.Client type (e.g.
// the TUI, which has not yet been migrated to the storage abstraction).
func newS3Client(cfg *config.Config) (*bos3.Client, error) {
	ctx := backgroundCtx()
	client, err := bos3.NewClient(ctx, cfg.Bucket, cfg.Region)
	if err != nil {
		return nil, fmt.Errorf("connect to AWS: %w", err)
	}
	return client, nil
}
