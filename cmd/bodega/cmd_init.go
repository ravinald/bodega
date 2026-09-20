package main

import (
	"fmt"

	"github.com/spf13/cobra"

	bos3 "github.com/ravinald/bodega/internal/s3"
)

func newInitCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create the bucket an s3 storage backend needs (encryption, versioning, public access block)",
		Long: `init is for the s3 storage backend only. An install whose backend is
"local" stores artifacts in a directory and needs nothing from this command.

It creates the bucket named by --bucket / REPO_BUCKET and configures it with:
  - Server-side encryption (AES-256 / SSE-S3)
  - Versioning enabled
  - All public access blocked

The command is idempotent: running it against an existing bucket is safe.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
			if err := requireBucket(cfg); err != nil {
				return err
			}

			ctx := backgroundCtx()
			client, err := bos3.NewClient(ctx, cfg.Bucket, cfg.Region)
			if err != nil {
				return fmt.Errorf("connect to AWS: %w", err)
			}

			fmt.Printf("Initializing bucket s3://%s in %s...\n", cfg.Bucket, cfg.Region)
			if err := bos3.InitBucket(ctx, client.S3Client(), cfg.Bucket, cfg.Region); err != nil {
				return err
			}
			fmt.Printf("\nBucket s3://%s is ready.\n", cfg.Bucket)
			return nil
		},
	}
}
