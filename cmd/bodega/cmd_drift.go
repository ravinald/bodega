package main

import (
	"fmt"
	"io"
	"os"
	"slices"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/placement"
	"github.com/ravinald/bodega/internal/storage"
)

func newDriftCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "drift [TYPE...]",
		Short: "List versions whose recorded backend is not the one placement now resolves to",
		Long: `drift compares every version's recorded backend against the backend the
placement hierarchy resolves to today, across the whole catalog.

A rule change moves nothing. That is the design — everything already uploaded
stays where it is and stays readable — but it also means a storage_by_type
edit is invisible afterwards: the next upload writes to the backend the version
already records, and only pypi refuses, because only pypi uploads a whole
directory. This is where the other seven answer.

Each row names the type, the package, the version, the backend the bytes are
on, and the backend the rule names. 'bodega pkg move' is what discharges a row,
and the command with its arguments is printed below the table.

pypi has no per-version object key and 'pkg move' refuses it, so a pypi row
names the only thing that moves those wheels: repoint storage_by_type.pypi and
re-upload the type with --replace-placement.

Nothing is written and no backend is asked where anything lives. This reads the
config hierarchy on one side and the manifest record on the other; 'bodega
build status' is the command that probes whether the object is actually there.`,
		Example: `  bodega pkg drift
  bodega pkg drift binary npm`,
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

			rows, err := placement.Drift(ctx, stores, store, types)
			if err != nil {
				return err
			}
			printDrift(os.Stdout, rows)
			return nil
		},
	}
}

// printDrift writes the table, then one remedy per distinct command. Distinct
// rather than per row because a directory-placed type's remedy is type-wide:
// printing it once per drifted pypi version would suggest each needed its own
// re-upload, when one moves all of them.
func printDrift(out io.Writer, rows []placement.DriftRow) {
	if len(rows) == 0 {
		fmt.Fprintln(out, "No drift: every version is on the backend its rule names.")
		return
	}

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TYPE\tPACKAGE\tVERSION\tON\tRULE")
	for _, r := range rows {
		version := r.Version
		if r.Frozen {
			version += " (frozen)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.Type, r.Package, version, r.On, r.Rule)
	}
	_ = tw.Flush()

	var seen []string
	for _, r := range rows {
		remedy := r.Remedy()
		if !slices.Contains(seen, remedy) {
			seen = append(seen, remedy)
		}
	}
	fmt.Fprintf(out, "\n%d version(s) drifted. To discharge each:\n", len(rows))
	for _, remedy := range seen {
		fmt.Fprintf(out, "  %s\n", remedy)
	}

	// A row can carry both, and fixing one leaves the other: an operator who
	// clears an inert storage_policy on a pypi package still has it in a group
	// that places nothing.
	var inert []string
	for _, r := range rows {
		for _, w := range []string{
			storagePolicyWarning(r.Type, r.IgnoredPolicy),
			storageGroupWarning(r.Type, r.IgnoredGroup),
		} {
			if w == "" {
				continue
			}
			line := fmt.Sprintf("%s/%s: %s", r.Type, r.Package, w)
			if !slices.Contains(inert, line) {
				inert = append(inert, line)
			}
		}
	}
	for _, w := range inert {
		fmt.Fprintf(out, "\n  warning: %s\n", w)
	}
}
