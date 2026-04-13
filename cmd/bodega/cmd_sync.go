package main

// cmd_sync.go implements the 'sync' command: a dumb push that uploads whatever
// build artifacts already exist locally to S3 without running any pipeline
// stages. Use 'upload' instead when you want the full cascade.

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

func newSyncCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "sync [TYPE...]",
		Short: "Push local artifacts to S3 without running any pipeline stages",
		Long: `sync is the dumb push command. It uploads whatever build artifacts already
exist on disk to S3 without fetching, building, or packaging anything.

This is useful when artifacts have been built on a separate machine or in a
prior session and you simply want to (re-)upload them.

  binary  Upload per-entry to binaries/<name>/<version>/<filename> (or
          binaries/<filename> when unversioned)
  git     Sync bundles/ directory to repos/ in S3
  apt     Sync apt-repo/ directory to packages/apt/ in S3
  pypi    Sync wheels[/<version>]/ directory to pypi/wheels[/<version>]/ in S3

If a local artifact directory does not exist the type is silently skipped.

If no types are given all four are synced.

For the smart variant that runs missing pipeline stages before uploading,
use 'upload' instead.`,
		Example: `  bodega sync
  bodega sync apt
  bodega sync git pypi`,
		RunE: func(cmd *cobra.Command, args []string) error {
			types, err := resolveTypes(args)
			if err != nil {
				return err
			}

			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
			if err := requireBucket(cfg); err != nil {
				return err
			}

			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}

			bcfg := &builder.Config{
				AutoImportDeps: true,
				BuildRoot:      cfg.BuildRoot,
				ManifestDir:    cfg.ManifestDir,
				Bucket:         cfg.Bucket,
				Region:         cfg.Region,
				Verbose:        cfg.Verbose,
			}

			ctx := backgroundCtx()
			objStore, err := storage.New(ctx, cfg)
			if err != nil {
				return fmt.Errorf("connect to storage: %w", err)
			}

			buildRoot := cfg.BuildRoot
			totalUploaded := 0

			for _, t := range types {
				fmt.Printf("\n--- sync: %s ---\n", t)

				switch t {
				case manifest.TypeBinary:
					// Upload per-entry to the correct versioned S3 key.
					paths := builder.BinaryArtifactPaths(bcfg, store, "")
					if len(paths) == 0 {
						fmt.Printf("    No local binary artifacts found — skipping\n")
						continue
					}
					for _, ap := range paths {
						fmt.Printf("    upload: s3://%s/%s\n", cfg.Bucket, ap.S3Key)
						if err := objStore.PutFile(ctx, ap.Local, ap.S3Key); err != nil {
							return fmt.Errorf("sync binary %s: %w", ap.Local, err)
						}
						totalUploaded++
					}

				case manifest.TypeGit:
					localDir := filepath.Join(buildRoot, "bundles")
					if _, err := os.Stat(localDir); os.IsNotExist(err) {
						fmt.Printf("    No bundles directory at %s — skipping\n", localDir)
						continue
					}
					n, err := objStore.SyncDir(ctx, os.Stdout, localDir, "repos/")
					if err != nil {
						return fmt.Errorf("sync git: %w", err)
					}
					fmt.Printf("    Uploaded %d file(s) to s3://%s/repos/\n", n, cfg.Bucket)
					totalUploaded += n

				case manifest.TypeApt:
					localDir := filepath.Join(buildRoot, "apt-repo")
					if _, err := os.Stat(localDir); os.IsNotExist(err) {
						fmt.Printf("    No apt-repo directory at %s — skipping\n", localDir)
						continue
					}
					n, err := objStore.SyncDir(ctx, os.Stdout, localDir, "packages/apt/")
					if err != nil {
						return fmt.Errorf("sync apt: %w", err)
					}
					fmt.Printf("    Uploaded %d file(s) to s3://%s/packages/apt/\n", n, cfg.Bucket)
					totalUploaded += n

				case manifest.TypePypi:
					localDir, s3Prefix := builder.PypiArtifactDir(bcfg, store)
					if _, err := os.Stat(localDir); os.IsNotExist(err) {
						fmt.Printf("    No wheels directory at %s — skipping\n", localDir)
						continue
					}
					n, err := objStore.SyncDir(ctx, os.Stdout, localDir, s3Prefix)
					if err != nil {
						return fmt.Errorf("sync pypi: %w", err)
					}
					fmt.Printf("    Uploaded %d file(s) to s3://%s/%s\n", n, cfg.Bucket, s3Prefix)
					totalUploaded += n
				}
			}

			fmt.Printf("\nSync complete. Total files uploaded: %d\n", totalUploaded)

			// Update metrics after sync.
			if err := store.SaveIndex(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not update metrics: %v\n", err)
			}
			notifyServer(gf)

			return nil
		},
	}
}
