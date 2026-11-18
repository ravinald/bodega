package main

import (
	"context"
	"fmt"
	"sort"
	"strings"

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

			out := cmd.OutOrStdout()
			if len(checksums) == 0 {
				fmt.Fprintln(out, "No cached checksums.")
				return nil
			}

			fmt.Fprintf(out, "%-8s %-40s %-10s %-8s %-64s %-10s %s\n",
				"TYPE", "NAME", "VERSION", "ALGO", "CHECKSUM", "SOURCE", "ARCHIVE")
			fmt.Fprintln(out, "---")

			for _, cs := range checksums {
				// A cleared row keeps its identity and loses its digest. An
				// empty column reads as a display bug; the word says the row is
				// doing its other job, holding the artifact's provenance.
				value := cs.Value
				if value == "" {
					value = "(cleared)"
				}
				fmt.Fprintf(out, "%-8s %-40s %-10s %-8s %-64s %-10s %s\n",
					cs.PkgType,
					truncate(cs.PkgName, 40),
					cs.PkgVersion,
					cs.Algorithm,
					value,
					cs.Source,
					checksumArchive(cs.ObjectKey),
				)
			}

			fmt.Fprintf(out, "\n%d checksum(s)\n", len(checksums))
			return nil
		},
	}

	cmd.Flags().StringVar(&pkgType, "type", "", "Filter by package type")
	cmd.Flags().StringVar(&pkgName, "name", "", "Filter by package name")
	return cmd
}

func newChecksumClearCmd(gf *globalFlags) *cobra.Command {
	var version, archive string

	cmd := &cobra.Command{
		Use:   "clear <type> <name>",
		Short: "Clear cached checksums for a package",
		Long: `clear blanks the cached digests for the specified package.
The next fetch re-computes and stores a fresh checksum.

The row itself is kept. For apt it is also the record that tells a .deb the
mirror cached from one bodega built, and deleting it would republish the
archive's bytes under bodega's own signature.

One apt package can hold a digest per archive in apt_archives, since two
distributions publish different bytes at one pool path. --archive clears the
digest of that archive alone; without it every archive's digest goes, and the
output counts them per archive.`,
		Example: `  bodega pkg checksum clear gomod example.com/example-corp/widget-sdk
  bodega pkg checksum clear npm lodash
  bodega pkg checksum clear apt nginx --archive debian`,
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

			if archive != "" {
				return clearArchiveChecksums(ctx, cmd, db, pkgType, pkgName, version, archive)
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
						if err := db.ClearChecksum(ctx, cs.ObjectKey); err != nil {
							return err
						}
						fmt.Fprintf(cmd.OutOrStdout(), "Cleared checksum for %s/%s@%s%s; the next fetch recomputes it.\n", pkgType, pkgName, version, inArchive(cs.ObjectKey))
						found = true
					}
				}
				if !found {
					return fmt.Errorf("no checksum found for %s/%s@%s: nothing was cleared, and the 502 you are chasing is not a stale digest for this version; run `bodega pkg checksum list --type %s --name %s` for the versions that do have one",
						pkgType, pkgName, version, pkgType, pkgName)
				}
			} else {
				// Clear all versions. The per-archive count is read first,
				// off the rows the clear is about to blank.
				perArchive, err := pinnedPerArchive(ctx, db, pkgType, pkgName)
				if err != nil {
					return err
				}
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
					fmt.Fprint(cmd.OutOrStdout(), perArchive)
				}
				return nil
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&version, "version", "", "Clear only this version")
	cmd.Flags().StringVar(&archive, "archive", "", "Clear only the digest held for this apt_archives archive (apt only)")
	return cmd
}

// checksumArchive is the ARCHIVE column: the named apt archive a digest's
// object belongs to, and "-" for the default archive and every other type.
func checksumArchive(objectKey string) string {
	if archive, _, ok := manifest.SplitAptKey(objectKey); ok && archive != "" {
		return archive
	}
	return "-"
}

func inArchive(objectKey string) string {
	if archive := checksumArchive(objectKey); archive != "-" {
		return " in archive " + archive
	}
	return ""
}

// pinnedPerArchive renders how many digests a package holds in each archive,
// one line per archive, and nothing unless a named archive holds one: a
// server with no apt_archives has one archive and the total already says it.
func pinnedPerArchive(ctx context.Context, db *audit.DB, pkgType, pkgName string) (string, error) {
	if pkgType != manifest.TypeApt {
		return "", nil
	}
	rows, err := db.ListChecksums(ctx, pkgType, pkgName)
	if err != nil {
		return "", err
	}
	counts := map[string]int{}
	named := false
	for _, cs := range rows {
		if cs.Value == "" {
			continue
		}
		archive := checksumArchive(cs.ObjectKey)
		counts[archive]++
		named = named || archive != "-"
	}
	if !named {
		return "", nil
	}
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		label := "archive " + name
		if name == "-" {
			label = "default archive"
		}
		fmt.Fprintf(&b, "  %s: %d\n", label, counts[name])
	}
	return b.String(), nil
}

// clearArchiveChecksums blanks the digests one named archive holds for a
// package, leaving the same package's digests in every other archive alone.
func clearArchiveChecksums(ctx context.Context, cmd *cobra.Command, db *audit.DB, pkgType, pkgName, version, archive string) error {
	if pkgType != manifest.TypeApt {
		return fmt.Errorf("--archive applies to apt only: %s has no archives; drop the flag", pkgType)
	}
	rows, err := db.ListChecksums(ctx, pkgType, pkgName)
	if err != nil {
		return err
	}
	var cleared, blank int
	elsewhere := map[string]bool{}
	for _, cs := range rows {
		if version != "" && cs.PkgVersion != version {
			continue
		}
		switch got := checksumArchive(cs.ObjectKey); {
		case got != archive:
			elsewhere[got] = true
		case cs.Value == "":
			blank++
		default:
			if err := db.ClearChecksum(ctx, cs.ObjectKey); err != nil {
				return fmt.Errorf("clear checksum for %s: %w; digests cleared before it stay cleared", cs.ObjectKey, err)
			}
			cleared++
		}
	}
	what := pkgType + "/" + pkgName
	if version != "" {
		what += "@" + version
	}
	switch {
	case cleared > 0:
		fmt.Fprintf(cmd.OutOrStdout(), "Cleared %d checksum(s) for %s in archive %s; the next fetch recomputes them.\n", cleared, what, archive)
	case blank > 0:
		fmt.Fprintf(cmd.OutOrStdout(), "%d row(s) for %s in archive %s already carry no digest; nothing was cleared. A 502 that survives this is not a stale checksum.\n", blank, what, archive)
	default:
		held := make([]string, 0, len(elsewhere))
		for name := range elsewhere {
			if name == "-" {
				name = "the default archive (no --archive)"
			}
			held = append(held, name)
		}
		sort.Strings(held)
		where := "no archive holds one"
		if len(held) > 0 {
			where = "it has one in: " + strings.Join(held, ", ")
		}
		return fmt.Errorf("no checksum found for %s in archive %q: nothing was cleared; %s. Run `bodega pkg checksum list --type apt --name %s` for the ARCHIVE of each",
			what, archive, where, pkgName)
	}
	return nil
}
