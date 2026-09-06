package main

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

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
		Long: `Query api.osv.dev for every imported (ecosystem, name, version)
and flag or block based on the per-ecosystem policy. OSV coverage maps
npm, pypi, gomod and cargo. Any other ecosystem has no OSV identifier,
so set refuses it rather than writing a row the gate never reads.

  bodega policy osv set npm block
  bodega policy osv set pypi warn
  bodega policy osv list
  bodega policy osv remove npm`,
	}
	cmd.AddCommand(newPolicyOSVSetCmd(gf), newPolicyOSVListCmd(gf), newPolicyOSVRemoveCmd(gf))
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
		Short: "List OSV policies",
		RunE: func(cmd *cobra.Command, args []string) error {
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
				fmt.Println("No OSV policies configured.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ECOSYSTEM\tACTION\tUPDATED")
			for _, p := range rows {
				fmt.Fprintf(w, "%s\t%s\t%s\n", p.Ecosystem, p.Action, p.UpdatedAt.Format("2006-01-02"))
			}
			return w.Flush()
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
