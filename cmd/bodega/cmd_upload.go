package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
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
						if err := objStore.PutFile(ctx, ap.Local, ap.S3Key); err != nil {
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
					n, err := objStore.SyncDir(ctx, os.Stdout, localDir, "repos/")
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
					n, err := objStore.SyncDir(ctx, os.Stdout, localDir, "packages/apt/")
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
					n, err := objStore.SyncDir(ctx, os.Stdout, localDir, s3Prefix)
					if err != nil {
						return fmt.Errorf("upload pypi: %w", err)
					}
					fmt.Printf("    Uploaded %d file(s) to s3://%s/%s\n", n, cfg.Bucket, s3Prefix)
					totalUploaded += n

				case manifest.TypeGomod:
					// Cascade: ensure every gomod entry has its .info/.mod/.zip triplet.
					if s := ensureFetchedGomod(bcfg, store, ""); s.HasFailures() {
						return fmt.Errorf("cascade fetch for gomod failed")
					}
					paths := builder.GomodArtifactPaths(bcfg, store, "")
					if len(paths) == 0 {
						fmt.Println("    No gomod artifacts to upload — skipping")
						continue
					}
					for _, ap := range paths {
						fmt.Printf("    upload: s3://%s/%s\n", cfg.Bucket, ap.S3Key)
						if err := objStore.PutFile(ctx, ap.Local, ap.S3Key); err != nil {
							return fmt.Errorf("upload gomod %s: %w", ap.Local, err)
						}
						totalUploaded++
					}

				case manifest.TypeHelm:
					// Cascade: ensure charts are fetched and index.yaml is regenerated.
					if s := ensurePackagedHelm(bcfg, store, ""); s.HasFailures() {
						return fmt.Errorf("cascade package for helm failed")
					}
					paths := builder.HelmArtifactPaths(bcfg, store, "")
					if len(paths) == 0 {
						fmt.Println("    No helm artifacts to upload — skipping")
						continue
					}
					for _, ap := range paths {
						fmt.Printf("    upload: s3://%s/%s\n", cfg.Bucket, ap.S3Key)
						if err := objStore.PutFile(ctx, ap.Local, ap.S3Key); err != nil {
							return fmt.Errorf("upload helm %s: %w", ap.Local, err)
						}
						totalUploaded++
					}

				case manifest.TypeNpm:
					// Cascade: ensure tarballs are fetched and packuments regenerated.
					if s := ensurePackagedNpm(bcfg, store, ""); s.HasFailures() {
						return fmt.Errorf("cascade package for npm failed")
					}
					paths := builder.NpmArtifactPaths(bcfg, store, "")
					if len(paths) == 0 {
						fmt.Println("    No npm artifacts to upload — skipping")
						continue
					}
					for _, ap := range paths {
						fmt.Printf("    upload: s3://%s/%s\n", cfg.Bucket, ap.S3Key)
						if err := objStore.PutFile(ctx, ap.Local, ap.S3Key); err != nil {
							return fmt.Errorf("upload npm %s: %w", ap.Local, err)
						}
						totalUploaded++
					}

				case manifest.TypeCargo:
					// Cascade: ensure .crate tarballs are fetched. Cargo has no
					// per-package packument equivalent — clients consume the
					// upstream sparse index proxied through bodega.
					if s := ensureFetchedCargo(bcfg, store, ""); s.HasFailures() {
						return fmt.Errorf("cascade fetch for cargo failed")
					}
					paths := builder.CargoArtifactPaths(bcfg, store, "")
					if len(paths) == 0 {
						fmt.Println("    No cargo artifacts to upload — skipping")
						continue
					}
					for _, ap := range paths {
						fmt.Printf("    upload: s3://%s/%s\n", cfg.Bucket, ap.S3Key)
						if err := objStore.PutFile(ctx, ap.Local, ap.S3Key); err != nil {
							return fmt.Errorf("upload cargo %s: %w", ap.Local, err)
						}
						totalUploaded++
					}
				}
			}

			fmt.Printf("\nUpload complete. Total files uploaded: %d\n", totalUploaded)

			// Update metrics after upload.
			if err := store.SaveIndex(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not update metrics: %v\n", err)
			}
			notifyServer(gf)

			return nil
		},
	}
}
