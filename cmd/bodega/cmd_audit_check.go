package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/scaleapi/bodega/internal/manifest"
)

func newAuditCheckCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check [TYPE] [NAME]",
		Short: "Check that all dependency requirements are satisfied",
		Long: `check scans the dependency graph and verifies that every child package
referenced by a parent exists in the manifest with a matching version.

Reports:
  - Missing children (parent requires a package that doesn't exist)
  - Version mismatches (parent requires version X but only Y exists)
  - Orphaned packages (exist in manifest but nothing requires them)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load store: %w", err)
			}

			ctx := context.Background()
			if err := store.LoadGraph(ctx); err != nil {
				fmt.Println("WARNING: could not load dependency graph:", err)
			}

			issues := 0

			// Check that every edge's child exists.
			fmt.Println("Checking dependency graph...")
			for _, edge := range store.ChildrenOf("") {
				// Parse child reference: "type/name@version"
				// This is a simplification; we check that the package exists.
				child := edge.Child
				// Find the type prefix.
				for _, typ := range manifest.AllTypes {
					prefix := typ + "/"
					if len(child) > len(prefix) && child[:len(prefix)] == prefix {
						rest := child[len(prefix):]
						// Split on @ for name and version.
						name := rest
						version := ""
						for i := len(rest) - 1; i >= 0; i-- {
							if rest[i] == '@' {
								name = rest[:i]
								version = rest[i+1:]
								break
							}
						}
						pm, err := store.GetPackage(ctx, typ, name)
						if err != nil || pm == nil {
							fmt.Printf("  MISSING: %s requires %s (not in manifest)\n", edge.Parent, child)
							issues++
						} else if version != "" {
							found := false
							for _, ve := range pm.Versions {
								if ve.Version == version || ve.Ref == version {
									found = true
									break
								}
							}
							if !found {
								fmt.Printf("  VERSION: %s requires %s@%s but only other versions exist\n", edge.Parent, name, version)
								issues++
							}
						}
						break
					}
				}
			}

			// Find orphaned packages (no parent references them).
			fmt.Println("\nChecking for orphaned packages...")
			allEdges := store.ChildrenOf("")
			childSet := make(map[string]bool)
			for _, e := range allEdges {
				childSet[e.Child] = true
			}

			for _, typ := range manifest.AllTypes {
				for _, name := range store.ListPackages(typ) {
					pm, err := store.GetPackage(ctx, typ, name)
					if err != nil || pm == nil {
						continue
					}
					for _, ve := range pm.Versions {
						ref := fmt.Sprintf("%s/%s@%s", typ, name, ve.Version)
						if ve.Version == "" {
							ref = fmt.Sprintf("%s/%s@%s", typ, name, ve.Ref)
						}
						hasParent := false
						if len(ve.RequiredBy) > 0 {
							hasParent = true
						}
						if childSet[ref] {
							hasParent = true
						}
						// Top-level entries (git repos, manually added packages) are expected to have no parent.
						if !hasParent && typ != manifest.TypeGit && typ != manifest.TypeBinary {
							fmt.Printf("  ORPHAN: %s (not required by any package)\n", ref)
						}
					}
				}
			}

			if issues > 0 {
				fmt.Printf("\n%d dependency issue(s) found.\n", issues)
			} else {
				fmt.Println("\nAll dependencies satisfied.")
			}
			return nil
		},
	}
	return cmd
}
