package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
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
		Example: `  bodega pkg checksum list
  bodega pkg checksum list --type gomod
  bodega pkg checksum list --type npm --name lodash`,
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
				// A cleared row keeps its identity and loses its digest. An
				// empty column reads as a display bug; the word says the row is
				// doing its other job, holding the artifact's provenance.
				value := cs.Value
				if value == "" {
					value = "(cleared)"
				}
				fmt.Printf("%-8s %-40s %-10s %-8s %-64s %s\n",
					cs.PkgType,
					truncate(cs.PkgName, 40),
					cs.PkgVersion,
					cs.Algorithm,
					value,
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
		Long: `clear blanks the cached digests for the specified package.
The next fetch re-computes and stores a fresh checksum.

The row itself is kept. For apt it is also the record that tells a .deb the
mirror cached from one bodega built, and deleting it would republish the
archive's bytes under bodega's own signature.`,
		Example: `  bodega pkg checksum clear gomod github.com/aws/aws-sdk-go-v2
  bodega pkg checksum clear npm lodash`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			pkgType, pkgName := args[0], args[1]

			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}

			db, err := audit.Open(cfg.AuditDB)
			if err != nil {
				return fmt.Errorf("open audit db %s: %w; the digest lives there, so clear it on the host that serves this instance", cfg.AuditDB, err)
			}
			defer db.Close()

			ctx := backgroundCtx()

			if pkgType == manifest.TypeApt {
				fmt.Fprintln(cmd.OutOrStdout(),
					"apt: the digest goes, the row stays. Cached upstream .debs stay out of the index; the next fetch stores a fresh digest.")
			}

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
						fmt.Fprintf(cmd.OutOrStdout(), "Cleared checksum for %s/%s@%s; the next fetch recomputes it.\n", pkgType, pkgName, version)
						found = true
					}
				}
				if !found {
					return fmt.Errorf("no checksum found for %s/%s@%s: nothing was cleared, and the 502 you are chasing is not a stale digest for this version; run `bodega pkg checksum list --type %s --name %s` for the versions that do have one",
						pkgType, pkgName, version, pkgType, pkgName)
				}
			} else {
				// Clear all versions.
				cleared, matched, err := db.ClearChecksumsByPackage(ctx, pkgType, pkgName)
				if err != nil {
					return fmt.Errorf("clear checksums for %s/%s: %w; the digests are unchanged, so a re-fetch still answers 502", pkgType, pkgName, err)
				}
				switch {
				case matched == 0:
					fmt.Fprintf(cmd.OutOrStdout(), "No cached checksums matched %s/%s; nothing was cleared. Run `bodega pkg checksum list --type %s` for the names this instance recorded.\n", pkgType, pkgName, pkgType)
				case cleared == 0:
					fmt.Fprintf(cmd.OutOrStdout(), "%d row(s) for %s/%s already carry no digest; nothing was cleared. A 502 that survives this is not a stale checksum.\n", matched, pkgType, pkgName)
				default:
					fmt.Fprintf(cmd.OutOrStdout(), "Cleared %d checksum(s) for %s/%s; the next fetch recomputes them.\n", cleared, pkgType, pkgName)
				}
				return nil
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&version, "version", "", "Clear only this version")
	return cmd
}
