package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
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

			// Remove from object store first if requested.
			if removeFromS3 {
				if err := requireBucket(cfg); err != nil {
					return err
				}
				objStore, err := storage.New(ctx, cfg)
				if err != nil {
					return fmt.Errorf("connect to storage: %w", err)
				}
				key := s3KeyFor(store, ctx, t, name)
				if key != "" {
					fmt.Printf("Deleting s3://%s/%s ...\n", cfg.Bucket, key)
					if err := objStore.Delete(ctx, key); err != nil {
						return err
					}
					fmt.Println("  Deleted from S3.")
				}
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

// s3KeyFor returns the primary S3 key for a named entry (first version).
func s3KeyFor(store *manifest.Store, ctx context.Context, t, name string) string {
	pm, err := store.GetPackage(ctx, t, name)
	if err != nil || pm == nil || len(pm.Versions) == 0 {
		return ""
	}
	ve := pm.Versions[0]
	switch t {
	case manifest.TypeBinary:
		filename := ve.Filename
		if filename == "" {
			filename = lastS3Segment(ve.URL)
		}
		return "binaries/" + filename
	case manifest.TypeGit:
		sn := strings.ReplaceAll(pm.Name, "/", "--")
		return fmt.Sprintf("repos/%s/%s-%s.bundle", sn, sn, ve.Ref)
	}
	return ""
}

// lastS3Segment returns the basename portion of a URL path.
func lastS3Segment(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return s[i+1:]
		}
	}
	return s
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
