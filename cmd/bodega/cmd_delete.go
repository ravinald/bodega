package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/inventory"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

func newDeleteCmd(gf *globalFlags) *cobra.Command {
	var removeFromS3 bool

	cmd := &cobra.Command{
		Use:   "delete <type> <name>",
		Short: "Remove an entry from the manifest",
		Long: `delete removes the named entry from a manifest and writes the updated file.

Use --remove-from-s3 to also delete the corresponding artifact from S3.
Frozen entries cannot be deleted; unfreeze them first with 'bodega freeze'.`,
		Example: `  bodega delete git netbox
  bodega delete binary awscli-v2 --remove-from-s3`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, name := args[0], args[1]
			if !isValidType(t) {
				return fmt.Errorf("unknown type %q", t)
			}

			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
			if err := ensureMutable(cfg); err != nil {
				return err
			}

			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}

			ctx := context.Background()

			// Check frozen status before deletion.
			if frozen, err := isFrozen(store, ctx, t, name); err != nil {
				return err
			} else if frozen {
				return fmt.Errorf("entry %s/%s is frozen — unfreeze it first with 'bodega freeze %s %s'", t, name, t, name)
			}

			// Remove the objects before the manifest entry. A failure here
			// stops the command with the entry intact: the entry is the only
			// record of which bytes to clean up, so dropping it after a delete
			// that resolved nothing would orphan them with nothing left to
			// name them.
			if removeFromS3 {
				stores, err := storage.NewResolver(ctx, cfg)
				if err != nil {
					return fmt.Errorf("connect to storage: %w", err)
				}
				removed, err := deleteEntryObjects(ctx, stores, store, t, name, os.Stdout)
				if err != nil {
					return err
				}
				fmt.Printf("Deleted %d object(s).\n", len(removed))
			}

			// Capture before state for audit.
			var beforeJSON []byte
			if pm, err := store.GetPackage(ctx, t, name); err == nil && pm != nil {
				beforeJSON, _ = json.MarshalIndent(pm, "", "  ")
			}

			// Remove from manifest.
			if err := store.DeletePackage(ctx, t, name); err != nil {
				return err
			}
			if err := store.SaveIndex(ctx); err != nil {
				return fmt.Errorf("save index: %w", err)
			}

			fmt.Printf("Removed %s/%s from manifest.\n", t, name)

			if adb := openAuditDB(gf); adb != nil {
				_ = adb.Record(ctx, audit.Event{
					EventType: audit.EventDelete,
					PkgType:   t,
					PkgName:   name,
					Actor:     audit.CurrentActor(),
					Status:    "success",
					Details:   audit.FormatDiff(beforeJSON, nil),
				})
				adb.Close()
			}

			notifyServer(gf)
			return nil
		},
	}

	cmd.Flags().BoolVar(&removeFromS3, "remove-from-s3", false, "Also delete the artifact from S3")
	return cmd
}

// deleteEntryObjects removes every object backing a named entry and returns
// the keys it actually removed.
//
// Every version is walked, not just the first: 'pkg delete' drops the whole
// entry, so a key left behind is a key nothing will ever name again. Each
// version resolves on the backend its own record names, because a version
// moved with 'pkg move' does not live where its siblings do.
//
// Resolving no key at all is an error. Local.Get and the S3 client both answer
// a missing object with (nil, nil) and both Deletes are idempotent, so a delete
// aimed at the wrong key reports the same success as one that worked; the only
// place that difference can still be caught is here, before the delete runs.
func deleteEntryObjects(ctx context.Context, stores storage.Resolver, store *manifest.Store, t, name string, out io.Writer) ([]string, error) {
	pm, err := store.GetPackage(ctx, t, name)
	if err != nil {
		return nil, fmt.Errorf("get %s/%s: %w", t, name, err)
	}
	if pm == nil {
		return nil, fmt.Errorf("%s entry %q not found", t, name)
	}
	if len(pm.Versions) == 0 {
		return nil, fmt.Errorf("%s/%s has no versions, so no artifact key resolves for it", t, name)
	}

	var removed []string
	for _, ve := range pm.Versions {
		label := pm.Name + "@" + versionLabel(ve)
		objStore, err := stores.ByName(ve.Storage)
		if err != nil {
			return removed, fmt.Errorf("%s: %w", label, err)
		}
		keys, err := inventory.ArtifactKeys(ctx, objStore, pm, ve)
		if err != nil {
			return removed, fmt.Errorf("%s: %w", label, err)
		}
		if len(keys) == 0 {
			return removed, fmt.Errorf("%s: no object key resolves on %q; refusing to report a delete that looked nowhere",
				label, effectiveStorage(ve.Storage))
		}
		for _, key := range keys {
			info, err := objStore.Head(ctx, key)
			if err != nil {
				return removed, fmt.Errorf("%s: head %s on %q: %w", label, key, effectiveStorage(ve.Storage), err)
			}
			if !info.Exists {
				fmt.Fprintf(out, "  %s: %s/%s already absent\n", label, objStore.Label(), key)
				continue
			}
			if err := objStore.Delete(ctx, key); err != nil {
				return removed, fmt.Errorf("%s: delete %s from %q: %w", label, key, effectiveStorage(ve.Storage), err)
			}
			fmt.Fprintf(out, "  %s: deleted %s/%s\n", label, objStore.Label(), key)
			removed = append(removed, key)
		}
	}
	return removed, nil
}

// isFrozen returns whether all versions of the named entry are frozen, or an error if not found.
func isFrozen(store *manifest.Store, ctx context.Context, t, name string) (bool, error) {
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
