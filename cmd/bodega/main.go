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
	"strconv"

	"github.com/spf13/cobra"

	"github.com/scaleapi/bodega/internal/config"
	"github.com/scaleapi/bodega/internal/manifest"
	bos3 "github.com/scaleapi/bodega/internal/s3"
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
			var check struct{ Bucket string `json:"bucket"` }
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

	// Register sub-commands.
	root.AddCommand(
		newInitCmd(gf),
		newFetchCmd(gf),
		newBuildCmd(gf),
		newPackageCmd(gf),
		newUploadCmd(gf),
		newSyncCmd(gf),
		newStatusCmd(gf),
		newVerifyCmd(gf),
		newCreateCmd(gf),
		newDeleteCmd(gf),
		newRemoveCmd(gf),
		newFreezeCmd(gf),
		newShellCmd(gf),
		newServeCmd(gf),
		newAuditCmd(gf),
		newChecksumCmd(gf),
		newResetCmd(gf),
		newRefreshCmd(gf),
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

	if cfg.LocalConfig {
		backend := &manifest.LocalBackend{Dir: cfg.ManifestDir}
		return manifest.LoadAllFromBackend(ctx, backend)
	}

	// S3 backend — need bucket
	if err := requireBucket(cfg); err != nil {
		return nil, err
	}

	s3client, err := newS3Client(cfg)
	if err != nil {
		return nil, err
	}

	backend := &manifest.S3Backend{
		Prefix: "manifests/",
		GetFn:  s3client.GetObject,
		PutFn:  s3client.PutBytes,
		Label_: fmt.Sprintf("s3://%s/manifests/", cfg.Bucket),
	}
	return manifest.LoadAllFromBackend(ctx, backend)
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

// newS3Client creates an S3 client from the resolved config.
func newS3Client(cfg *config.Config) (*bos3.Client, error) {
	ctx := backgroundCtx()
	client, err := bos3.NewClient(ctx, cfg.Bucket, cfg.Region)
	if err != nil {
		return nil, fmt.Errorf("connect to AWS: %w", err)
	}
	return client, nil
}
