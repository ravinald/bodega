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
	var storageBackend string
	cmd := &cobra.Command{
		Use:   "sync [TYPE...] [NAME[@VERSION]]",
		Short: "Push local artifacts to the storage backend without running any pipeline stages",
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

If no types are given all of them are synced. A name after the types narrows
the push to one package. pypi is skipped when a name is given: its wheels reach
storage as one directory, so one package cannot be pushed apart from the rest.

--storage names the backend one version's bytes go to, whatever the placement
hierarchy resolves to. It records that name on the version entry, so the next
push of the same package writes there again without the flag — the same
lifetime 'bodega pkg move' gives a version, and a different thing from
--replace-placement, which re-applies the current rule. It needs one type and
one NAME@VERSION, and pypi cannot take it.

For the smart variant that runs missing pipeline stages before uploading,
use 'upload' instead.`,
		Example: `  bodega build sync
  bodega build sync apt
  bodega build sync git pypi
  bodega build sync binary example-tool-v2
  bodega build sync binary example-tool-v2@2.15.0 --storage bulk`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}

			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}

			types, selector, err := parseUploadArgs(args, store)
			if err != nil {
				return err
			}

			bcfg := builder.NewConfig(cfg, nil)

			ctx := backgroundCtx()
			pl, err := newPlacer(ctx, cfg, store, os.Stdout, replacePlacement)
			if err != nil {
				return err
			}
			if err := applyUploadScope(cfg, pl, types, selector, storageBackend); err != nil {
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

			if storageBackend != "" {
				if err := confirmPlaced(pl, types[0], selector, storageBackend); err != nil {
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
	cmd.Flags().StringVar(&storageBackend, "storage", "",
		"Backend one version's bytes are written to, overriding the placement hierarchy; needs one type and NAME@VERSION")
	return cmd
}
