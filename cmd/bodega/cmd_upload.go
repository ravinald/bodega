package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/builder"
)

func newUploadCmd(gf *globalFlags) *cobra.Command {
	var replacePlacement bool
	cmd := &cobra.Command{
		Use:   "upload [TYPE...]",
		Short: "Upload built artifacts to S3 (cascades through full pipeline if needed)",
		Long: `upload ensures all pipeline stages are complete and then syncs the local
build artifacts to S3 for the specified types.

Before uploading each type, upload checks whether the package stage has been
completed. If any stage is missing it runs the full cascade:
  fetch → build → package → upload

For the "dumb push" variant that uploads only what already exists locally
without running any pipeline stages, use 'sync' instead.

Every type but pypi uploads one object per manifest version, to the backend
that version records. pypi's wheels have no per-version object key, so they
sync as a directory to the backend its type rule names.

If no types are given all of them are uploaded.`,
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
			pl, err := newPlacer(ctx, cfg, store, os.Stdout, replacePlacement)
			if err != nil {
				return err
			}

			totalUploaded := 0
			for _, t := range types {
				fmt.Printf("\n--- upload: %s ---\n", t)
				if err := ensureUploadable(t, bcfg, store); err != nil {
					return err
				}
				n, err := pl.UploadType(ctx, bcfg, t)
				totalUploaded += n
				if err != nil {
					return err
				}
			}

			fmt.Printf("\nUpload complete. Total files uploaded: %d\n", totalUploaded)

			// Update metrics after upload.
			if err := store.SaveIndex(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not update metrics: %v\n", err)
			}

			return nil
		},
	}
	cmd.Flags().BoolVar(&replacePlacement, "replace-placement", false,
		"Apply the current storage_by_type rule to versions already recorded on another backend (leaves the old objects behind)")
	return cmd
}
