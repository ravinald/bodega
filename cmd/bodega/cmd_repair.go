package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"

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
  5. Pypi URLs: entries carrying the retired pypi.org/packages/ wheel URL
  6. Pypi names: manifests stored under a name PEP 503 does not canonicalize to
  7. Manifest sync: all manifests are re-saved to the backend (S3)
  8. Graph rebuild: dependency edges are rebuilt from RequiredBy fields

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
					if manifest.CanonicalName(typ, name) != name {
						// Phase 6 owns this one. The manifest is on disk under
						// the name the index spells and every read composes the
						// canonical path, so the load below reports MISSING for
						// a file that is right there; counting it here as well
						// reports one defect twice.
						continue
					}
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
			bcfg := builder.NewConfig(cfg, nil)
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
				n := builder.BackfillArtifactSizes(builder.NewConfig(cfg, nil), store, cmd.OutOrStdout())
				fmt.Printf("  Backfilled %d package(s)\n", n)
			} else {
				fmt.Println("  (skipped in check mode)")
			}

			// Phase 4: Version-less apt entries.
			fmt.Println("\nPhase 4: Checking apt entries for version-less placeholders...")
			issues += repairAptPlaceholders(ctx, store, dryRun, os.Stdout)

			// Phase 5: Retired pypi wheel URLs.
			fmt.Println("\nPhase 5: Checking pypi entries for the retired wheel URL...")
			issues += repairPypiWheelURLs(ctx, store, dryRun, os.Stdout)

			// Phase 6: Manifests stored under a non-canonical name.
			fmt.Println("\nPhase 6: Checking pypi manifests for non-canonical names...")
			found, unresolved := repairPypiNames(ctx, store, dryRun, os.Stdout)
			issues += found

			// Phase 7: Re-sync manifests to backend.
			if !dryRun {
				fmt.Println("\nPhase 7: Re-syncing manifests to backend...")
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
			switch {
			case issues == 0:
				fmt.Println("No issues found. Everything is consistent.")
			case dryRun:
				fmt.Printf("%d issue(s) found (dry run, no changes made)\n", issues)
			case unresolved > 0:
				fmt.Printf("%d issue(s) found, %d not repaired\n", issues, unresolved)
			default:
				fmt.Printf("%d issue(s) found (repaired)\n", issues)
			}
			if dryRun {
				suppressReload(cmd)
			}
			if unresolved > 0 {
				return fmt.Errorf("%d non-canonical pypi manifest(s) are still stored where no read composes their path; the lines above name each one and what blocked the rename. Nothing was moved, so merge the two manifests by hand and re-run", unresolved)
			}
			return nil
		},
	}

	cmd.AddCommand(newRepairKeysCmd(gf))
	return cmd
}

// repairPypiNames moves a pypi manifest stored under a non-canonical name onto
// its PEP 503 name, and reports how many it found.
//
// An install that predates canonicalization holds whatever `pip list` reported —
// `Django`, `zope.interface`, `ruamel.yaml` — and every route now composes the
// canonical path, so each of those manifests is unreachable by the client the
// inventory came from. The rename is here rather than at server start because it
// moves a manifest out from under a running process: `repair check` names them
// and changes nothing, and the operator picks the moment.
//
// A collision is reported and counted as unresolved rather than skipped
// quietly. Two manifests for one distribution hold two sets of version entries,
// choosing which pins survive is not a sweep's decision to make, and the
// distribution stays unreachable until somebody makes it — which is a failing
// repair, not a repaired one.
//
// found counts every non-canonical manifest; unresolved counts the ones still
// where they were when this returned.
func repairPypiNames(ctx context.Context, store *manifest.Store, dryRun bool, out io.Writer) (found, unresolved int) {
	misnamed, err := store.MisnamedPackages(ctx)
	if err != nil {
		fmt.Fprintf(out, "  ERROR: could not list stored manifests: %v\n", err)
		return 1, 1
	}
	for _, m := range misnamed {
		found++
		fmt.Fprintf(out, "  NON-CANONICAL: %s/%s is stored where every read composes %s/%s\n",
			m.Type, m.Stored, m.Type, m.Canonical)
		if dryRun {
			continue
		}
		if err := store.RenameToCanonical(ctx, m); err != nil {
			fmt.Fprintf(out, "    ERROR: could not rename it: %v\n", err)
			unresolved++
			continue
		}
		fmt.Fprintf(out, "    -> renamed to %s/%s\n", m.Type, m.Canonical)
	}
	return found, unresolved
}

// pypiWheelURLPattern matches the wheel URL bodega composed before wheels were
// resolved through the simple index.
var pypiWheelURLPattern = regexp.MustCompile(`^(https?://[^/]+)/packages/[^/]+$`)

// repairPypiWheelURLs rewrites a pypi entry's URL from the retired
// <index>/packages/<filename> shape to the registry root, and reports how many
// it found.
//
// pypi.org has never served /packages/, so every entry `discover promote --as
// manifest` wrote under the old handler records a fetch that 404s. Nothing
// reads the field today — internal/builder/pypi.go resolves wheels through pip
// and the server resolves them through the simple index — so the stored value
// is inert rather than dangerous, and that is exactly why it would otherwise
// sit there uncorrected until someone taught the builder to trust it. The
// registry root is what the field means for pypi now, matching gomod and npm.
//
// The pattern is host-agnostic and the report says only what it checked. An
// operator's own index that serves /packages/<file> matches too, and the
// rewrite is right for it as well: the field means a registry root whoever
// wrote the entry. Naming pypi in the line would state a fact about a host the
// sweep never looked at, leaving the operator unable to tell whether their own
// mirror is broken.
func repairPypiWheelURLs(ctx context.Context, store *manifest.Store, dryRun bool, out io.Writer) int {
	issues := 0
	for _, name := range store.ListPackages(manifest.TypePypi) {
		pm, err := store.GetPackage(ctx, manifest.TypePypi, name)
		if err != nil || pm == nil {
			continue
		}
		changed := 0
		for i, ve := range pm.Versions {
			m := pypiWheelURLPattern.FindStringSubmatch(ve.URL)
			if m == nil {
				continue
			}
			issues++
			fmt.Fprintf(out, "  WRONG SHAPE: pypi/%s@%s records %s, a wheel URL where the field means a registry root\n", name, ve.Version, ve.URL)
			if dryRun {
				continue
			}
			pm.Versions[i].URL = m[1]
			changed++
		}
		if changed == 0 {
			continue
		}
		if err := store.SavePackage(ctx, pm); err != nil {
			fmt.Fprintf(out, "    ERROR: could not rewrite them: %v\n", err)
			continue
		}
		fmt.Fprintf(out, "    -> rewrote %d to the registry root\n", changed)
	}
	return issues
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
