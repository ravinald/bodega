package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scaleapi/bodega/internal/builder"
	"github.com/scaleapi/bodega/internal/manifest"
)

func newAuditCheckCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check that all dependency requirements are satisfied",
		Long: `check scans the manifest store and dependency graph for issues:

  - Git entries with source trees but no dependency links
  - Graph edges pointing to packages that don't exist
  - Packages with no parent (orphans)
  - Empty packages (no versions)`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load store: %w", err)
			}

			ctx := context.Background()
			if err := store.LoadGraph(ctx); err != nil {
				fmt.Println("WARNING: could not load dependency graph:", err)
			}

			issues := 0

			// 1. Check git entries have dependency links.
			fmt.Println("Checking git dependency links...")
			for _, name := range store.ListPackages(manifest.TypeGit) {
				pm, err := store.GetPackage(ctx, manifest.TypeGit, name)
				if err != nil || pm == nil {
					continue
				}
				for _, ve := range pm.Versions {
					ref := ve.Ref
					if ref == "" {
						ref = ve.Version
					}
					parentRef := fmt.Sprintf("git/%s@%s", name, ref)
					children := store.ChildrenOf(parentRef)

					// Check if source exists on disk.
					worktree, _ := builder.GitWorktreePath(cfg.BuildRoot, name, ref)
					hasSource := worktree != ""

					if len(children) == 0 && hasSource {
						fmt.Printf("  UNLINKED: %s has source on disk but no dependency edges\n", parentRef)
						fmt.Printf("           run 'bodega repair' to re-discover dependencies\n")
						issues++
					} else if len(children) == 0 && !hasSource {
						fmt.Printf("  INFO: %s has no source on disk (not fetched yet)\n", parentRef)
					} else {
						fmt.Printf("  OK: %s -> %d dependencies\n", parentRef, len(children))
					}
				}
			}

			// 2. Check all graph edges point to existing packages.
			fmt.Println("\nChecking graph edge targets...")
			allEdges := store.AllEdges()
			if len(allEdges) == 0 {
				fmt.Println("  (no edges in dependency graph)")
			}
			for _, edge := range allEdges {
				typ, name, version := parseEdgeRef(edge.Child)
				if typ == "" {
					continue
				}
				pm, err := store.GetPackage(ctx, typ, name)
				if err != nil || pm == nil {
					fmt.Printf("  MISSING: %s requires %s (package not in manifest)\n", edge.Parent, edge.Child)
					issues++
					continue
				}
				if version != "" {
					found := false
					for _, ve := range pm.Versions {
						if ve.Version == version || ve.Ref == version {
							found = true
							break
						}
					}
					if !found {
						fmt.Printf("  VERSION: %s requires %s@%s (version not found)\n", edge.Parent, name, version)
						issues++
					}
				}
			}

			// 3. Check for empty packages.
			fmt.Println("\nChecking for empty packages...")
			for _, typ := range manifest.AllTypes {
				for _, name := range store.ListPackages(typ) {
					pm, err := store.GetPackage(ctx, typ, name)
					if err != nil || pm == nil {
						fmt.Printf("  ERROR: %s/%s could not be loaded\n", typ, name)
						issues++
						continue
					}
					if len(pm.Versions) == 0 {
						fmt.Printf("  EMPTY: %s/%s has no versions\n", typ, name)
						issues++
					}
				}
			}

			// 4. Check for orphaned packages.
			fmt.Println("\nChecking for orphaned packages...")
			childSet := make(map[string]bool)
			for _, e := range allEdges {
				childSet[e.Child] = true
			}
			for _, typ := range manifest.AllTypes {
				// Git and binary entries are typically top-level (not children).
				if typ == manifest.TypeGit || typ == manifest.TypeBinary || typ == manifest.TypeApt {
					continue
				}
				for _, name := range store.ListPackages(typ) {
					pm, err := store.GetPackage(ctx, typ, name)
					if err != nil || pm == nil {
						continue
					}
					for _, ve := range pm.Versions {
						v := ve.Version
						if v == "" {
							v = ve.Ref
						}
						ref := fmt.Sprintf("%s/%s@%s", typ, name, v)
						hasParent := childSet[ref] || len(ve.RequiredBy) > 0
						if !hasParent {
							fmt.Printf("  ORPHAN: %s (not required by any package)\n", ref)
						}
					}
				}
			}

			fmt.Println()
			if issues > 0 {
				fmt.Printf("%d issue(s) found. Run 'bodega repair' to fix.\n", issues)
			} else {
				fmt.Println("All dependencies satisfied.")
			}
			return nil
		},
	}
	return cmd
}

// parseEdgeRef splits "type/name@version" into its parts.
func parseEdgeRef(ref string) (typ, name, version string) {
	for _, t := range manifest.AllTypes {
		prefix := t + "/"
		if strings.HasPrefix(ref, prefix) {
			rest := ref[len(prefix):]
			if idx := strings.LastIndex(rest, "@"); idx >= 0 {
				return t, rest[:idx], rest[idx+1:]
			}
			return t, rest, ""
		}
	}
	return "", "", ""
}
