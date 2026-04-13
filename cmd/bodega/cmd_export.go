package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/manifest"
)

func newExportCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export [type] [name]",
		Short: "Export package manifests as JSON",
		Long: `export writes package manifests to stdout as JSON.

With no arguments, exports all packages. With a type, exports all packages of
that type. With a type and name, exports a single package.

Examples:
  bodega pkg export                    # all packages, all types
  bodega pkg export apt                # all apt packages
  bodega pkg export apt python3        # single package
  bodega pkg export apt python3 > python3.json`,
		Args: cobra.RangeArgs(0, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}
			ctx := context.Background()

			var packages []*manifest.PackageManifest

			switch len(args) {
			case 0:
				// Export all types.
				for _, t := range manifest.AllTypes {
					for _, name := range store.ListPackages(t) {
						pm, err := store.GetPackage(ctx, t, name)
						if err != nil {
							return fmt.Errorf("load %s/%s: %w", t, name, err)
						}
						if pm != nil {
							packages = append(packages, pm)
						}
					}
				}
			case 1:
				// Export all packages of a type.
				t := args[0]
				if !isValidType(t) {
					return fmt.Errorf("unknown type %q — must be one of: %s", t, strings.Join(manifest.AllTypes, ", "))
				}
				for _, name := range store.ListPackages(t) {
					pm, err := store.GetPackage(ctx, t, name)
					if err != nil {
						return fmt.Errorf("load %s/%s: %w", t, name, err)
					}
					if pm != nil {
						packages = append(packages, pm)
					}
				}
			case 2:
				// Export a single package.
				t, name := args[0], args[1]
				if !isValidType(t) {
					return fmt.Errorf("unknown type %q — must be one of: %s", t, strings.Join(manifest.AllTypes, ", "))
				}
				pm, err := store.GetPackage(ctx, t, name)
				if err != nil {
					return fmt.Errorf("load %s/%s: %w", t, name, err)
				}
				if pm == nil {
					return fmt.Errorf("%s/%s not found", t, name)
				}
				packages = append(packages, pm)
			}

			if len(packages) == 0 {
				fmt.Fprintln(os.Stderr, "No packages found.")
				return nil
			}

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")

			// Single package: output the manifest directly.
			// Multiple: output as a JSON array.
			if len(packages) == 1 {
				return enc.Encode(packages[0])
			}
			return enc.Encode(packages)
		},
	}

	return cmd
}
