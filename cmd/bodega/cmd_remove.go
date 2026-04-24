package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/storage"
)

func newRemoveCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <type> <name>",
		Short: "Remove artifacts from S3 without touching the manifest",
		Long: `remove deletes the artifact(s) for the named entry from S3. The manifest
file is not modified.`,
		Example: `  bodega remove binary awscli-v2
  bodega remove git netbox`,
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
			if err := requireBucket(cfg); err != nil {
				return err
			}

			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}

			ctx := backgroundCtx()
			key := s3KeyFor(store, ctx, t, name)
			if key == "" {
				return fmt.Errorf("could not determine S3 key for %s/%s", t, name)
			}
			objStore, err := storage.New(ctx, cfg)
			if err != nil {
				return fmt.Errorf("connect to storage: %w", err)
			}

			fmt.Printf("Deleting s3://%s/%s ...\n", cfg.Bucket, key)
			if err := objStore.Delete(ctx, key); err != nil {
				return err
			}
			fmt.Println("Deleted.")
			return nil
		},
	}
}
