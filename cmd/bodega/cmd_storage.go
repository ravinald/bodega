package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

func newStorageCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "storage <type> <name>",
		Short: "Show which backend this package's next version will be written to",
		Long: `storage resolves the placement hierarchy for one package and names the level
that decided the answer.

Three levels are consulted, most specific first: the package's own
storage_policy, then storage_by_type for its type, then the default backend.
Naming the winning level is the point — "bulk" on its own does not say whether
a package policy took effect or a forgotten type rule did.

This is the WRITE side. It says nothing about where versions already uploaded
live; each of those records its own backend, and 'bodega show pkg' prints it.`,
		Example: `  bodega pkg storage git netbox
  bodega pkg storage apt nginx`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, name := args[0], args[1]
			if !isValidType(t) {
				return fmt.Errorf("unknown type %q — must be one of: %s", t, strings.Join(manifest.AllTypes, ", "))
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
			pm, err := store.GetPackage(ctx, t, name)
			if err != nil {
				return fmt.Errorf("get %s/%s: %w", t, name, err)
			}
			if pm == nil {
				return fmt.Errorf("%s entry %q not found", t, name)
			}

			stores, err := storage.NewResolver(ctx, cfg)
			if err != nil {
				return fmt.Errorf("connect to storage: %w", err)
			}
			d := stores.Placement(t, pm.StoragePolicy)

			fmt.Printf("%s -> %-8s (%s)\n", t+"/"+name, d.Name, d.Reason(t))
			return nil
		},
	}
}
