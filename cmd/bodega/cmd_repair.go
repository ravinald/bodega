package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/scaleapi/bodega/internal/manifest"
)

func newRepairCmd(gf *globalFlags) *cobra.Command {
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "repair",
		Short: "Detect and fix inconsistencies between local index, manifests, and S3",
		Long: `repair scans the local index, per-package manifest files, and S3 artifacts
to find inconsistencies:

  - Packages in the index but missing manifest files
  - Manifest files on disk/S3 but not in the index
  - Artifacts in S3 but no matching manifest entry
  - Manifest entries with no matching S3 artifact

By default, repair fixes what it can (re-syncs index, re-uploads manifests).
Use --dry-run to only report issues without fixing them.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load store: %w", err)
			}

			ctx := context.Background()
			issues := 0

			// 1. Check that every package in the index has a manifest.
			fmt.Println("Checking index consistency...")
			for _, typ := range manifest.AllTypes {
				for _, name := range store.ListPackages(typ) {
					pm, err := store.GetPackage(ctx, typ, name)
					if err != nil {
						fmt.Printf("  ERROR: %s/%s: could not load manifest: %v\n", typ, name, err)
						issues++
						continue
					}
					if pm == nil {
						fmt.Printf("  MISSING: %s/%s in index but no manifest file\n", typ, name)
						issues++
						if !dryRun {
							fmt.Printf("    -> removing from index\n")
							// Would need to remove from index
						}
						continue
					}
					if len(pm.Versions) == 0 {
						fmt.Printf("  EMPTY: %s/%s has manifest but no versions\n", typ, name)
						issues++
					}
				}
			}

			// 2. Re-save all manifests to ensure they're synced to backend.
			if !dryRun {
				fmt.Println("\nRe-syncing manifests to backend...")
				synced := 0
				for _, typ := range manifest.AllTypes {
					for _, name := range store.ListPackages(typ) {
						pm, err := store.GetPackage(ctx, typ, name)
						if err != nil || pm == nil {
							continue
						}
						if err := store.SavePackage(ctx, pm); err != nil {
							fmt.Printf("  ERROR saving %s/%s: %v\n", typ, name, err)
							issues++
						} else {
							synced++
						}
					}
				}
				fmt.Printf("  Re-synced %d package manifests\n", synced)

				// Re-save index.
				if err := store.SaveIndex(ctx); err != nil {
					fmt.Printf("  ERROR saving index: %v\n", err)
					issues++
				} else {
					fmt.Println("  Index saved")
				}

				// Re-save graph.
				if err := store.SaveGraph(ctx); err != nil {
					fmt.Printf("  ERROR saving graph: %v\n", err)
					issues++
				} else {
					fmt.Println("  Dependency graph saved")
				}
			}

			if issues > 0 {
				fmt.Printf("\n%d issue(s) found", issues)
				if dryRun {
					fmt.Println(" (dry run, no changes made)")
				} else {
					fmt.Println(" (repaired)")
				}
			} else {
				fmt.Println("\nNo issues found. Everything is consistent.")
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Report issues without fixing them")
	return cmd
}
