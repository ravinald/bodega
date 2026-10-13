package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

func newPolicySimilarityCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "similarity",
		Short: "Name-similarity (typosquat) check per ecosystem",
		Long: `Compare every admitted npm, pypi and cargo package name with that
ecosystem's most-downloaded names. A name one or two edits (Damerau-
Levenshtein: insert, delete, substitute, swap two adjacent characters) from a
popular name it is not equal to fails, and the admission row names the
popular name and the distance. pypi names are compared after PEP 503
normalization; npm names are lowercased, with the scope and the bare name
compared separately; cargo treats - and _ as one character.

Exempt, so turning the check on breaks nothing already in use:
  - a name an exact allow-list rule names (not an npm @scope/* wildcard)
  - a name the manifest store held when the check first ran here

The action says what a near name does to the admission:

  warn    (default) the admission goes ahead and the row says warn
  block   the admission is refused
  ignore  the row records the near name and nothing fails

It catches a squat of a popular name only. A squat of a package outside the
list is not caught.

  bodega policy similarity set pypi block
  bodega policy similarity list
  bodega policy similarity load npm ./top-npm.txt`,
	}
	cmd.AddCommand(newPolicySimilaritySetCmd(gf), newPolicySimilarityListCmd(gf), newPolicySimilarityLoadCmd(gf))
	return cmd
}

func newPolicySimilaritySetCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "set <ecosystem> warn|block|ignore",
		Short: "Set the name similarity action for an ecosystem",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			eco, action := args[0], strings.ToLower(args[1])
			if err := requireEcosystem(eco, policy.SimilarityEcosystems(), "name similarity check",
				"it has no popular-name list"); err != nil {
				return err
			}
			if action != policy.ActionWarn && action != policy.ActionBlock && action != policy.ActionIgnore {
				return fmt.Errorf("action must be warn|block|ignore, got %q", action)
			}
			adb, done, err := openSimilarityDB(cmd.Context(), gf)
			if err != nil {
				return err
			}
			defer done()
			ctx := cmd.Context()
			actor := audit.CurrentActor()
			if err := adb.SetSimilarityPolicy(ctx, audit.SimilarityPolicy{Ecosystem: eco, Action: action, Actor: actor}); err != nil {
				return err
			}
			details, _ := json.Marshal(map[string]string{"gate": audit.CheckNameSimilarity, "action": action})
			if err := adb.Record(ctx, audit.Event{
				EventType: audit.EventPolicy, PkgType: eco, Actor: actor, Status: "success", Details: string(details),
			}); err != nil {
				return fmt.Errorf("set %s name similarity action to %s, but the audit event was not written: %w", eco, action, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Set %s name similarity policy: %s\n", eco, action)
			return nil
		},
	}
}

func newPolicySimilarityListCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the name similarity action and popular list for every ecosystem",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("audit DB unavailable")
			}
			defer adb.Close()
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ECOSYSTEM\tACTION\tLIST\tSOURCE")
			for _, eco := range policy.SimilarityEcosystems() {
				action := "warn (default)"
				if p, err := adb.GetSimilarityPolicy(ctx, eco); err == nil {
					action = p.Action
				}
				list, _, err := policy.LoadPopularNames(ctx, adb, eco)
				if err != nil {
					return err
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", eco, action, list.Label(), dash(list.Source))
			}
			if err := w.Flush(); err != nil {
				return err
			}
			baseline, err := adb.NameBaseline(ctx)
			if err != nil {
				return err
			}
			if baseline.Taken {
				fmt.Fprintf(cmd.OutOrStdout(), "\nExempt as in use before the check: %d package names from the manifest store and %d more with an admitted row, recorded %s.\n",
					baseline.Packages, baseline.Admitted, baseline.TakenAt.UTC().Format("2006-01-02"))
			}
			return nil
		},
	}
}

func newPolicySimilarityLoadCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "load <ecosystem> <file>",
		Short: "Replace an ecosystem's popular-name list",
		Long: `Replace the embedded popular-name list for one ecosystem with the names in
file: one per line, most popular first, with # comments. The header keys
"# source:" and "# date:" are recorded and shown by list, as the embedded
lists' are. The loaded list replaces the embedded one whole, and the policy
digest changes with it.`,
		Example: `  bodega policy similarity load npm ./top-npm.txt`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			eco, path := args[0], args[1]
			if err := requireEcosystem(eco, policy.SimilarityEcosystems(), "name similarity check",
				"it has no popular-name list"); err != nil {
				return err
			}
			data, err := os.ReadFile(path) //nolint:gosec // G304: the operator names the file.
			if err != nil {
				return err
			}
			list, err := policy.ParsePopularNames(eco, data)
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			ctx := cmd.Context()
			adb, done, err := openSimilarityDB(ctx, gf)
			if err != nil {
				return err
			}
			defer done()
			actor := audit.CurrentActor()
			source := list.Source
			if source == "" {
				source = path
			}
			if err := adb.SetPopularList(ctx, audit.PopularList{
				Ecosystem: eco, Names: string(data), NameCount: len(list.Names), SHA256: list.SHA256, Source: source, Actor: actor,
			}); err != nil {
				return err
			}
			details, _ := json.Marshal(map[string]any{"gate": audit.CheckNameSimilarity, "op": "load_list",
				"names": len(list.Names), "sha256": list.SHA256, "source": source})
			if err := adb.Record(ctx, audit.Event{
				EventType: audit.EventPolicy, PkgType: eco, Actor: actor, Status: "success", Details: string(details),
			}); err != nil {
				return fmt.Errorf("loaded %d %s names, but the audit event was not written: %w", len(list.Names), eco, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Loaded %d popular %s names from %s (%s)\n", len(list.Names), eco, path, list.SHA256)
			return nil
		},
	}
}

// openSimilarityDB opens the audit database for a similarity command that
// writes, refusing on a read-only install, and takes the name baseline first
// so that a block set before any admission ran still exempts what is in use.
func openSimilarityDB(ctx context.Context, gf *globalFlags) (*audit.DB, func(), error) {
	cfg, err := loadConfig(gf)
	if err != nil {
		return nil, nil, err
	}
	if err := ensureMutable(cfg); err != nil {
		return nil, nil, err
	}
	adb := openAuditDB(gf)
	if adb == nil {
		return nil, nil, fmt.Errorf("audit DB unavailable")
	}
	store, err := loadStore(gf)
	if err != nil {
		_ = adb.Close()
		return nil, nil, fmt.Errorf("load manifests: %w", err)
	}
	takeNameBaseline(ctx, adb, store)
	return adb, func() { _ = adb.Close() }, nil
}

// takeNameBaseline records the store's packages and the admitted names as
// exempt from the name similarity check, the first time any command holding both the store and the
// audit database runs. A failure is a warning: the check still runs, and the
// next command tries again.
func takeNameBaseline(ctx context.Context, adb *audit.DB, store *manifest.Store) {
	if adb == nil || store == nil {
		return
	}
	took, err := policy.TakeNameBaseline(ctx, adb, store.AllPackages())
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: the name similarity baseline was not recorded: %v\n", err)
		return
	}
	if took {
		if b, err := adb.NameBaseline(ctx); err == nil {
			fmt.Fprintf(os.Stderr, "Recorded %d package names from the manifest store and %d more with an admitted row as exempt from the name similarity check.\n",
				b.Packages, b.Admitted)
		}
	}
}
