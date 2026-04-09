package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/scaleapi/bodega/internal/builder"
	"github.com/scaleapi/bodega/internal/manifest"
	bos3 "github.com/scaleapi/bodega/internal/s3"
)

func newUploadCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "upload [TYPE...]",
		Short: "Upload built artifacts to S3 (cascades through full pipeline if needed)",
		Long: `upload ensures all pipeline stages are complete and then syncs the local
build artifacts to S3 for the specified types.

Before uploading each type, upload checks whether the package stage has been
completed. If any stage is missing it runs the full cascade:
  fetch → build → package → upload

For the "dumb push" variant that uploads only what already exists locally
without running any pipeline stages, use 'sync' instead.

If no types are given all four are uploaded.`,
		Example: `  bodega upload
  bodega upload apt
  bodega upload git pypi`,
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
				BuildRoot:   cfg.BuildRoot,
				ManifestDir: cfg.ManifestDir,
				Bucket:      cfg.Bucket,
				Region:      cfg.Region,
				Verbose:     cfg.Verbose,
			}

			ctx := backgroundCtx()
			client, err := bos3.NewClient(ctx, cfg.Bucket, cfg.Region)
			if err != nil {
				return fmt.Errorf("connect to AWS: %w", err)
			}

			buildRoot := cfg.BuildRoot
			totalUploaded := 0

			for _, t := range types {
				fmt.Printf("\n--- upload: %s ---\n", t)

				switch t {
				case manifest.TypeBinary:
					// Cascade: ensure all binary entries are fetched.
					if s := ensureFetchedBinaries(bcfg, store, ""); s.HasFailures() {
						return fmt.Errorf("cascade fetch for binary failed")
					}
					// Upload per-entry to the versioned S3 path.
					paths := builder.BinaryArtifactPaths(bcfg, store, "")
					for _, ap := range paths {
						fmt.Printf("    upload: s3://%s/%s\n", cfg.Bucket, ap.S3Key)
						if err := client.UploadFile(ctx, ap.Local, ap.S3Key); err != nil {
							return fmt.Errorf("upload binary %s: %w", ap.Local, err)
						}
						totalUploaded++
					}

				case manifest.TypeGit:
					// Cascade: ensure all git entries are packaged.
					if s := ensurePackagedGit(bcfg, store, ""); s.HasFailures() {
						return fmt.Errorf("cascade package for git failed")
					}
					localDir := filepath.Join(buildRoot, "bundles")
					if _, err := os.Stat(localDir); os.IsNotExist(err) {
						fmt.Printf("    No bundles directory at %s — skipping\n", localDir)
						continue
					}
					n, err := client.SyncDir(ctx, os.Stdout, localDir, "repos/")
					if err != nil {
						return fmt.Errorf("upload git: %w", err)
					}
					fmt.Printf("    Uploaded %d file(s) to s3://%s/repos/\n", n, cfg.Bucket)
					totalUploaded += n

				case manifest.TypeApt:
					// Cascade: ensure all apt entries are packaged.
					if s := ensurePackagedApt(bcfg, store, ""); s.HasFailures() {
						return fmt.Errorf("cascade package for apt failed")
					}
					localDir := filepath.Join(buildRoot, "apt-repo")
					if _, err := os.Stat(localDir); os.IsNotExist(err) {
						fmt.Printf("    No apt-repo directory at %s — skipping\n", localDir)
						continue
					}
					n, err := client.SyncDir(ctx, os.Stdout, localDir, "packages/apt/")
					if err != nil {
						return fmt.Errorf("upload apt: %w", err)
					}
					fmt.Printf("    Uploaded %d file(s) to s3://%s/packages/apt/\n", n, cfg.Bucket)
					totalUploaded += n

				case manifest.TypePypi:
					// Cascade: ensure pypi is packaged.
					if s := ensurePackagedPypi(bcfg, store); s.HasFailures() {
						return fmt.Errorf("cascade package for pypi failed")
					}
					localDir, s3Prefix := builder.PypiArtifactDir(bcfg, store)
					if _, err := os.Stat(localDir); os.IsNotExist(err) {
						fmt.Printf("    No wheels directory at %s — skipping\n", localDir)
						continue
					}
					n, err := client.SyncDir(ctx, os.Stdout, localDir, s3Prefix)
					if err != nil {
						return fmt.Errorf("upload pypi: %w", err)
					}
					fmt.Printf("    Uploaded %d file(s) to s3://%s/%s\n", n, cfg.Bucket, s3Prefix)
					totalUploaded += n
				}
			}

			fmt.Printf("\nUpload complete. Total files uploaded: %d\n", totalUploaded)
			return nil
		},
	}
}
