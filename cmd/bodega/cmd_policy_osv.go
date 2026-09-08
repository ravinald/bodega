package main

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/policy"
)

// requireEcosystem refuses a policy row for an ecosystem the named gate cannot
// evaluate. The two gates fail differently on an uncovered ecosystem, so the
// caller supplies what actually happens: OSV short-circuits to pass and the
// operator believes a gate is on that has never run, while age warns on every
// version. consequence names which.
func requireEcosystem(eco string, covered []string, gate, consequence string) error {
	if slices.Contains(covered, eco) {
		return nil
	}
	return fmt.Errorf("the %s does not cover ecosystem %q: %s; set one of %s instead",
		gate, eco, consequence, strings.Join(covered, ", "))
}

func newPolicyOSVCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "osv",
		Short: "OSV vulnerability gate per ecosystem",
		Long: `Match every imported (ecosystem, name, version) against the local
OSV database and flag or block based on the per-ecosystem policy. OSV
coverage maps npm, pypi, gomod and cargo. Any other ecosystem has no OSV
identifier, so set refuses it rather than writing a row the gate never
reads.

sync is the only subcommand that reaches the network. Admission answers
from the directory sync wrote (osv_db_dir), and queries api.osv.dev only
when osv_api_fallback is on and the local copy cannot answer.

  bodega policy osv sync
  bodega policy osv set npm block
  bodega policy osv set pypi warn
  bodega policy osv list
  bodega policy osv remove npm`,
	}
	cmd.AddCommand(newPolicyOSVSetCmd(gf), newPolicyOSVListCmd(gf),
		newPolicyOSVRemoveCmd(gf), newPolicyOSVSyncCmd(gf))
	return cmd
}

func newPolicyOSVSetCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "set <ecosystem> <action>",
		Short: "Set the OSV policy action for an ecosystem",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			eco, action := args[0], strings.ToLower(args[1])
			if err := requireEcosystem(eco, policy.OSVEcosystems(), "OSV gate",
				"the row would be stored and never read, leaving the gate silently off"); err != nil {
				return err
			}
			if action != "warn" && action != "block" && action != "ignore" {
				return fmt.Errorf("action must be warn|block|ignore, got %q", action)
			}
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
			if err := ensureMutable(cfg); err != nil {
				return err
			}
			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("audit DB unavailable")
			}
			defer adb.Close()
			if err := adb.SetOSVPolicy(context.Background(), audit.OSVPolicy{
				Ecosystem: eco, Action: action,
			}); err != nil {
				return err
			}
			fmt.Printf("Set %s OSV policy: %s\n", eco, action)
			return nil
		},
	}
}

func newPolicyOSVListCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List OSV policies and the local database's per-ecosystem sync time",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
			db := policy.NewOSVDatabase(cfg.ResolveOSVDBDir())
			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("audit DB unavailable")
			}
			defer adb.Close()
			rows, err := adb.ListOSVPolicies(context.Background())
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				fmt.Printf("No OSV policies configured.\nLocal OSV database: %s (api.osv.dev fallback: %s)\n",
					db.Dir(), onOff(cfg.OSVAPIFallback))
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ECOSYSTEM\tACTION\tUPDATED\tDB SYNCED\tDB AGE")
			stored := make([]string, 0, len(rows))
			for _, p := range rows {
				synced, age := osvDBState(db, p.Ecosystem)
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					p.Ecosystem, p.Action, p.UpdatedAt.Format("2006-01-02"), synced, age)
				stored = append(stored, p.Ecosystem)
			}
			if err := w.Flush(); err != nil {
				return err
			}
			fmt.Printf("\nLocal OSV database: %s (api.osv.dev fallback: %s)\n",
				db.Dir(), onOff(cfg.OSVAPIFallback))
			reportUncovered("OSV gate", stored, policy.OSVEcosystems(), "bodega policy osv remove")
			return nil
		},
	}
}

func newPolicyOSVRemoveCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <ecosystem>",
		Short: "Remove the OSV policy for an ecosystem",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
			if err := ensureMutable(cfg); err != nil {
				return err
			}
			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("audit DB unavailable")
			}
			defer adb.Close()
			deleted, err := adb.DeleteOSVPolicy(context.Background(), args[0])
			if err != nil {
				return err
			}
			if !deleted {
				return fmt.Errorf("no OSV policy for %q", args[0])
			}
			fmt.Printf("Removed OSV policy for %s\n", args[0])
			return nil
		},
	}
}

func newPolicyOSVSyncCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "sync [ecosystem...]",
		Short: "Fetch or refresh the local OSV database",
		Long: `Download OSV's per-ecosystem export into osv_db_dir, one archive
per ecosystem, and record when each was fetched. With no arguments every
covered ecosystem is synced.

This is the only OSV subcommand that reaches the network. On an
air-gapped host, run it where the network is, copy the directory over,
and point osv_db_dir at the copy.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
			ecosystems := policy.OSVEcosystems()
			if len(args) > 0 {
				for _, eco := range args {
					if err := requireEcosystem(eco, policy.OSVEcosystems(), "OSV gate",
						"there is no export to fetch for it"); err != nil {
						return err
					}
				}
				ecosystems = args
			}
			db := policy.NewOSVDatabase(cfg.ResolveOSVDBDir())
			if db == nil {
				return fmt.Errorf("no OSV database directory: set osv_db_dir or storage_path")
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ECOSYSTEM\tOSV\tRECORDS\tPACKAGES\tSIZE\tFETCHED")
			var failed []string
			wrote := 0
			for _, eco := range ecosystems {
				osvEco := policy.OSVEcosystemFor(eco)
				meta, err := db.Sync(cmd.Context(), osvEco)
				if err != nil {
					failed = append(failed, fmt.Sprintf("%s: %v", eco, err))
					fmt.Fprintf(w, "%s\t%s\t-\t-\t-\tFAILED\n", eco, osvEco)
					continue
				}
				fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\t%s\n", eco, osvEco,
					meta.Records, meta.Packages, humanBytes(meta.Bytes),
					meta.FetchedAt.Format(time.RFC3339))
				wrote++
			}
			if err := w.Flush(); err != nil {
				return err
			}
			if wrote > 0 {
				fmt.Printf("\nWrote %s\n", db.Dir())
			}
			if len(failed) > 0 {
				return fmt.Errorf("sync failed for %d ecosystem(s): %s", len(failed), strings.Join(failed, "; "))
			}
			return nil
		},
	}
}

// osvDBState renders one ecosystem's sync time and age for the list table. An
// ecosystem that was never synced reads "never" rather than a blank column:
// the gate warns on it, and the operator has to see which one.
func osvDBState(db *policy.OSVDatabase, ecosystem string) (string, string) {
	osvEco := policy.OSVEcosystemFor(ecosystem)
	if osvEco == "" {
		return "n/a", "-"
	}
	meta, err := db.Meta(osvEco)
	if err != nil {
		return "never", "-"
	}
	return meta.FetchedAt.Format(time.RFC3339), policy.ShortDuration(meta.Age(time.Now()))
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGTPE"[exp])
}
