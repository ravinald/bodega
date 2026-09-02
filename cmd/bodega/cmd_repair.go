package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/manifest"
)

func newRepairCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "repair [check]",
		Short: "Detect and fix inconsistencies in the manifest store",
		Long: `repair performs several consistency checks and fixes:

  1. Index consistency: packages in the index must have manifest files
  2. Dependency linking: git entries with fetched sources should have
     their dependencies discovered and linked
  3. Artifact sizes: backfill ArtifactSize from local files
  4. Apt placeholders: version-less apt entries left beside a resolved one
  5. Manifest sync: all manifests are re-saved to the backend (S3)
  6. Graph rebuild: dependency edges are rebuilt from RequiredBy fields

  bodega repair                          # detect and fix
  bodega repair check                    # detect only, no changes`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dryRun := len(args) > 0 && args[0] == "check"
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load store: %w", err)
			}

			ctx := context.Background()

			// Load the dependency graph so ChildrenOf checks work.
			if err := store.LoadGraph(ctx); err != nil {
				fmt.Printf("  WARNING: could not load dependency graph: %v\n", err)
			}

			issues := 0

			// Phase 1: Index consistency.
			fmt.Println("Phase 1: Checking index consistency...")
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
						continue
					}
					if len(pm.Versions) == 0 {
						fmt.Printf("  EMPTY: %s/%s has manifest but no versions\n", typ, name)
						issues++
					}
				}
			}

			// Phase 2: Dependency discovery.
			fmt.Println("\nPhase 2: Checking dependency links...")
			bcfg := &builder.Config{
				BuildRoot:      cfg.BuildRoot,
				ManifestDir:    cfg.ManifestDir,
				AutoImportDeps: true,
			}
			for _, name := range store.ListPackages(manifest.TypeGit) {
				pm, err := store.GetPackage(ctx, manifest.TypeGit, name)
				if err != nil || pm == nil {
					continue
				}
				for _, ve := range pm.Versions {
					parentRef := fmt.Sprintf("git/%s@%s", name, ve.Ref)
					children := store.ChildrenOf(parentRef)
					if len(children) > 0 {
						fmt.Printf("  OK: %s has %d dependency edges\n", parentRef, len(children))
						continue
					}

					// No edges -- check if the source exists on disk.
					worktree, wtErr := builder.GitWorktreePath(cfg.BuildRoot, name, ve.Ref)
					if wtErr != nil || worktree == "" {
						fmt.Printf("  SKIP: %s source not on disk (fetch first)\n", parentRef)
						continue
					}

					fmt.Printf("  UNLINKED: %s has source but no dependency edges\n", parentRef)
					issues++

					if !dryRun {
						fmt.Printf("    -> re-running dependency discovery...\n")
						var buf bytes.Buffer
						result := builder.ScanDeps(bcfg, store, name, ve, io.Writer(&buf))
						if len(result.Deps) > 0 {
							builder.ImportDeps(ctx, store, name, ve, result.Deps, io.Writer(&buf))
							fmt.Printf("    -> discovered %d dependencies\n", len(result.Deps))
						}
						// Also discover descriptions.
						builder.DiscoverDescriptions(store, io.Writer(&buf))
					}
				}
			}

			// Phase 3: Backfill artifact sizes.
			fmt.Println("\nPhase 3: Backfilling artifact sizes...")
			if !dryRun {
				bcfgSizes := &builder.Config{
					BuildRoot:   cfg.BuildRoot,
					ManifestDir: cfg.ManifestDir,
					BinaryRoot:  cfg.BinaryRoot,
					GitRoot:     cfg.GitRoot,
					GomodRoot:   cfg.GomodRoot,
					HelmRoot:    cfg.HelmRoot,
					NpmRoot:     cfg.NpmRoot,
				}
				n := builder.BackfillArtifactSizes(bcfgSizes, store, cmd.OutOrStdout())
				fmt.Printf("  Backfilled %d package(s)\n", n)
			} else {
				fmt.Println("  (skipped in check mode)")
			}

			// Phase 4: Version-less apt entries.
			fmt.Println("\nPhase 4: Checking apt entries for version-less placeholders...")
			issues += repairAptPlaceholders(ctx, store, dryRun, os.Stdout)

			// Phase 5: Re-sync manifests to backend.
			if !dryRun {
				fmt.Println("\nPhase 5: Re-syncing manifests to backend...")
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

				if err := store.SaveIndex(ctx); err != nil {
					fmt.Printf("  ERROR saving index: %v\n", err)
					issues++
				} else {
					fmt.Println("  Index saved")
				}

				if err := store.SaveGraph(ctx); err != nil {
					fmt.Printf("  ERROR saving graph: %v\n", err)
					issues++
				} else {
					fmt.Println("  Dependency graph saved")
				}
			}

			fmt.Println()
			if issues > 0 {
				fmt.Printf("%d issue(s) found", issues)
				if dryRun {
					fmt.Println(" (dry run, no changes made)")
				} else {
					fmt.Println(" (repaired)")
				}
			} else {
				fmt.Println("No issues found. Everything is consistent.")
			}
			if dryRun {
				suppressReload(cmd)
			}
			return nil
		},
	}

	cmd.AddCommand(newRepairKeysCmd(gf))
	return cmd
}

// repairAptPlaceholders drops version-less apt entries that sit beside a
// resolved one, and reports how many it found. 'pkg create apt' in
// package-name mode stages one before the upstream version is known and the
// resolve that follows fills it; one left over is reachable from nowhere
// else, because every other verb addresses a version by name. A sweep is the
// only thing that can clear it, which is why it lives in repair.
//
// A package whose entries are all version-less is reported and left alone:
// that one is still a staging record its operator can resolve.
func repairAptPlaceholders(ctx context.Context, store *manifest.Store, dryRun bool, out io.Writer) int {
	issues := 0
	for _, name := range store.ListPackages(manifest.TypeApt) {
		pm, err := store.GetPackage(ctx, manifest.TypeApt, name)
		if err != nil || pm == nil {
			continue
		}
		blank, resolved := 0, 0
		for _, ve := range pm.Versions {
			if ve.Version == "" {
				blank++
			} else {
				resolved++
			}
		}
		if blank == 0 {
			continue
		}
		issues += blank
		if resolved == 0 {
			fmt.Fprintf(out, "  UNRESOLVED: apt/%s has only version-less entries; resolve or delete the package\n", name)
			continue
		}
		fmt.Fprintf(out, "  PLACEHOLDER: apt/%s has %d version-less entry(s) beside %d resolved\n", name, blank, resolved)
		if dryRun {
			continue
		}
		dropped, err := builder.DropVersionlessAptEntries(ctx, store, name)
		if err != nil {
			fmt.Fprintf(out, "    ERROR: could not drop them: %v\n", err)
			continue
		}
		fmt.Fprintf(out, "    -> dropped %d\n", dropped)
	}
	return issues
}
