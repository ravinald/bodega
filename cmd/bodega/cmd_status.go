package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/inventory"
	"github.com/ravinald/bodega/internal/storage"
)

func newStatusCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "status [TYPE...]",
		Short: "Compare local manifests against the backends holding their artifacts",
		Long: `status probes each manifest entry against the storage backend its version
entry records, and reports what is present or missing. If no types are given,
every type is checked.

Every configured backend is reachable, local and s3 alike, and the BACKEND
column names the one each row was probed on. A backend that fails to answer
marks its own rows ERROR and the command exits non-zero; the rows belonging to
backends that did answer are still printed, because a diagnostic exists to say
which backend is broken.`,
		Example: `  bodega build status
  bodega build status apt git`,
		RunE: func(cmd *cobra.Command, args []string) error {
			types, err := resolveTypes(args)
			if err != nil {
				return err
			}

			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}

			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}

			ctx := backgroundCtx()
			stores, err := storage.NewResolver(ctx, cfg)
			if err != nil {
				return fmt.Errorf("connect to storage: %w", err)
			}

			for _, ns := range stores.All() {
				fmt.Printf("Checking %s (%s) ...\n", ns.Name, ns.Store.Label())
			}
			statuses, err := inventory.CheckStatus(ctx, stores, store, types)
			if err != nil {
				return fmt.Errorf("status check: %w", err)
			}

			inventory.PrintStatus(os.Stdout, statuses)
			if n := inventory.Failures(statuses); n > 0 {
				return fmt.Errorf("%d entr(ies) could not be probed", n)
			}
			return nil
		},
	}
}
