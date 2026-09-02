package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/storage"
)

func newRemoveCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <type> <name>",
		Short: "Remove artifacts from S3 without touching the manifest",
		Long: `remove deletes the artifact(s) for the named entry from S3. The manifest
file is not modified.

Every version of the entry is removed, each from the backend its own record
names. An entry no object key resolves for is an error, not a no-op: both
backends delete idempotently, so a key nobody wrote reports the same success
as one that held the artifact.`,
		Example: `  bodega pkg remove binary awscli-v2
  bodega pkg remove git netbox`,
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

			ctx := backgroundCtx()
			stores, err := storage.NewResolver(ctx, cfg)
			if err != nil {
				return fmt.Errorf("connect to storage: %w", err)
			}
			removed, err := deleteEntryObjects(ctx, stores, store, t, name, os.Stdout)
			if err != nil {
				return err
			}
			fmt.Printf("Deleted %d object(s).\n", len(removed))
			return nil
		},
	}
}
