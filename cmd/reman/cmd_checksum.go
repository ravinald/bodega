package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/audit"
)

func newChecksumCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "checksum",
		Short: "Manage cached package checksums",
		Long: `checksum manages the cached SHA-256 checksums stored in the audit database.

Checksums are auto-computed on first fetch and verified on subsequent fetches.
Use 'list' to view cached checksums and 'clear' to reset them.`,
	}

	cmd.AddCommand(
		newChecksumListCmd(gf),
		newChecksumClearCmd(gf),
	)
	return cmd
}

func newChecksumListCmd(gf *globalFlags) *cobra.Command {
	var (
		pkgType string
		pkgName string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List cached checksums",
		Example: `  reman checksum list
  reman checksum list --type gomod
  reman checksum list --type npm --name lodash`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}

			db, err := audit.Open(cfg.AuditDB)
			if err != nil {
				return fmt.Errorf("open audit db: %w", err)
			}
			defer db.Close()

			ctx := backgroundCtx()
			checksums, err := db.ListChecksums(ctx, pkgType, pkgName)
			if err != nil {
				return fmt.Errorf("list checksums: %w", err)
			}

			if len(checksums) == 0 {
				fmt.Println("No cached checksums.")
				return nil
			}

			fmt.Printf("%-8s %-40s %-10s %-8s %-64s %s\n",
				"TYPE", "NAME", "VERSION", "ALGO", "CHECKSUM", "SOURCE")
			fmt.Println("---")

			for _, cs := range checksums {
				fmt.Printf("%-8s %-40s %-10s %-8s %-64s %s\n",
					cs.PkgType,
					truncate(cs.PkgName, 40),
					cs.PkgVersion,
					cs.Algorithm,
					cs.Value,
					cs.Source,
				)
			}

			fmt.Printf("\n%d checksum(s)\n", len(checksums))
			return nil
		},
	}

	cmd.Flags().StringVar(&pkgType, "type", "", "Filter by package type")
	cmd.Flags().StringVar(&pkgName, "name", "", "Filter by package name")
	return cmd
}

func newChecksumClearCmd(gf *globalFlags) *cobra.Command {
	var version string

	cmd := &cobra.Command{
		Use:   "clear <type> <name>",
		Short: "Clear cached checksums for a package",
		Long: `clear removes cached checksums for the specified package.
The next fetch will re-compute and store a fresh checksum.`,
		Example: `  reman checksum clear gomod github.com/aws/aws-sdk-go-v2
  reman checksum clear npm lodash`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			pkgType, pkgName := args[0], args[1]

			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}

			db, err := audit.Open(cfg.AuditDB)
			if err != nil {
				return fmt.Errorf("open audit db: %w", err)
			}
			defer db.Close()

			ctx := backgroundCtx()

			if version != "" {
				// Clear specific version — need to find the S3 key.
				checksums, err := db.ListChecksums(ctx, pkgType, pkgName)
				if err != nil {
					return err
				}
				found := false
				for _, cs := range checksums {
					if cs.PkgVersion == version {
						if err := db.ClearChecksum(ctx, cs.S3Key); err != nil {
							return err
						}
						fmt.Printf("Cleared checksum for %s/%s@%s\n", pkgType, pkgName, version)
						found = true
					}
				}
				if !found {
					return fmt.Errorf("no checksum found for %s/%s@%s", pkgType, pkgName, version)
				}
			} else {
				// Clear all versions.
				if err := db.ClearChecksumsByPackage(ctx, pkgType, pkgName); err != nil {
					return err
				}
				fmt.Printf("Cleared all checksums for %s/%s\n", pkgType, pkgName)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&version, "version", "", "Clear only this version")
	return cmd
}
