package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/policy"
)

func newUploadCmd(gf *globalFlags) *cobra.Command {
	var replacePlacement bool
	var storageBackend string
	cmd := &cobra.Command{
		Use:   "upload [TYPE...] [NAME[@VERSION]]",
		Short: "Upload built artifacts to the storage backend (cascades through full pipeline if needed)",
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

If no types are given all of them are uploaded. A name after the types narrows
the upload to one package; it narrows the upload alone, not the cascade, so the
stages that run first still cover the whole type. Use 'sync' for the push with
nothing in front of it. pypi is skipped when a name is given: its wheels reach
storage as one directory, so one package cannot be pushed apart from the rest.

--storage names the backend one version's bytes go to, whatever the placement
hierarchy resolves to. It records that name on the version entry, so the next
upload of the same package writes there again without the flag — the same
lifetime 'bodega pkg move' gives a version, and a different thing from
--replace-placement, which re-applies the current rule. It needs one type and
one NAME@VERSION, and pypi cannot take it.`,
		Example: `  bodega build upload
  bodega build upload apt
  bodega build upload git pypi
  bodega build upload binary awscli-v2
  bodega build upload binary awscli-v2@2.15.0 --storage bulk`,
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

			auditDB := openAuditDB(gf)
			if auditDB != nil {
				defer auditDB.Close()
			}

			bcfg := builder.NewConfig(cfg, policy.CheckerFor(auditDB))
			// upload is the only advertised command that reaches a hosted
			// artifact without naming a stage: ensureUploadable runs fetch,
			// build and package under this config. Left nil, every digest
			// those stages compute stops at pinChecksum's nil guard, so a
			// first install driven entirely by `build upload` uploads
			// artifacts nothing is pinned against.
			bcfg.AuditDB = auditDB

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

			if storageBackend != "" {
				if err := confirmPlaced(pl, types[0], selector, storageBackend); err != nil {
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
	cmd.Flags().StringVar(&storageBackend, "storage", "",
		"Backend one version's bytes are written to, overriding the placement hierarchy; needs one type and NAME@VERSION")
	return cmd
}
