package main

// cmd_sync.go implements the 'sync' command: a dumb push that uploads whatever
// build artifacts already exist locally to S3 without running any pipeline
// stages. Use 'upload' instead when you want the full cascade.

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/builder"
)

func newSyncCmd(gf *globalFlags) *cobra.Command {
	var replacePlacement bool
	cmd := &cobra.Command{
		Use:   "sync [TYPE...]",
		Short: "Push local artifacts to S3 without running any pipeline stages",
		Long: `sync is the dumb push command. It uploads whatever build artifacts already
exist on disk to S3 without fetching, building, or packaging anything.

This is useful when artifacts have been built on a separate machine or in a
prior session and you simply want to (re-)upload them.

Every type but pypi uploads one object per manifest version, to the backend
that version records: a git bundle to repos/<name>/, a .deb to the pool path
its entry carries, a binary to binaries/<name>/<version>/. pypi's wheels have
no per-version object key, so they sync as a directory to pypi/wheels/ on the
backend its type rule names.

A version whose artifact is not on disk is skipped, and so is a type with none.

If no types are given all of them are synced.

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
				fmt.Printf("\n--- sync: %s ---\n", t)
				n, err := pl.UploadType(ctx, bcfg, t)
				totalUploaded += n
				if err != nil {
					return err
				}
			}

			fmt.Printf("\nSync complete. Total files uploaded: %d\n", totalUploaded)

			// Update metrics after sync.
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
