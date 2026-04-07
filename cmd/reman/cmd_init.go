package main

import (
	"fmt"

	"github.com/spf13/cobra"

	bos3 "github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/s3"
)

func newInitCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create the S3 bucket with encryption, versioning, and public access block",
		Long: `init creates the bootstrap S3 bucket and configures it with:
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
