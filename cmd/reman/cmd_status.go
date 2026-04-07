package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	bos3 "github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/s3"
)

func newStatusCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "status [TYPE...]",
		Short: "Compare local manifests against S3",
		Long: `status checks each manifest entry against S3 and reports what is present,
missing, or uploaded. If no types are given, all four are checked.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			types, err := resolveTypes(args)
			if err != nil {
				return err
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
			client, err := bos3.NewClient(ctx, cfg.Bucket, cfg.Region)
			if err != nil {
				return fmt.Errorf("connect to AWS: %w", err)
			}

			fmt.Printf("Checking s3://%s ...\n", cfg.Bucket)
			statuses, err := bos3.CheckStatus(ctx, client, store, types)
			if err != nil {
				return fmt.Errorf("status check: %w", err)
			}

			bos3.PrintStatus(os.Stdout, statuses)
			return nil
		},
	}
}
