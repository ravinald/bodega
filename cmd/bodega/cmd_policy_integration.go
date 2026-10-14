package main

import (
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/integration"
	"github.com/ravinald/bodega/internal/policy"
)

func newPolicyIntegrationCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "integration",
		Short: "The action each external check instance takes per ecosystem",
		Long: `Set what a configured integration instance does when it flags a version,
or cannot answer, for one ecosystem: warn, block or ignore. An outage,
timeout, 5xx or rate limit is recorded as an error and takes the same
action, so under block an unreachable vendor refuses rather than admits.

With no row, the instance's type default applies; list shows which.

  bodega policy integration set aikido npm block
  bodega policy integration list`,
	}
	cmd.AddCommand(newPolicyIntegrationSetCmd(gf), newPolicyIntegrationListCmd(gf))
	return cmd
}

func newPolicyIntegrationSetCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "set <instance> <ecosystem> <warn|block|ignore>",
		Short: "Set an instance's action for an ecosystem",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, eco, action := args[0], args[1], strings.ToLower(args[2])
			if action != policy.ActionWarn && action != policy.ActionBlock && action != policy.ActionIgnore {
				return fmt.Errorf("action must be warn|block|ignore, got %q", action)
			}
			entry, err := fileEntry(name)
			if err != nil {
				return err
			}
			typ, _ := entry["type"].(string)
			d, ok := integration.Lookup(typ)
			if !ok {
				return fmt.Errorf("integrations.%s.type: unknown integration type %q", name, typ)
			}
			if err := requireEcosystem(eco, d.Ecosystems, d.DisplayName+" integration",
				"the row would be stored and never read, because the instance records every other ecosystem not evaluated"); err != nil {
				return err
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
				return errors.New("audit DB unavailable")
			}
			defer adb.Close()
			if err := adb.SetIntegrationPolicy(cmd.Context(), audit.IntegrationPolicy{
				Instance: name, Ecosystem: eco, Action: action, Actor: audit.CurrentActor(),
			}); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Set %s policy for %s: %s\n", name, eco, action)
			return nil
		},
	}
}

func newPolicyIntegrationListCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List each configured instance's action per ecosystem",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			entries, err := integration.FileEntries()
			if err != nil {
				return err
			}
			adb := openAuditDB(gf)
			if adb == nil {
				return errors.New("audit DB unavailable")
			}
			defer adb.Close()
			rows, err := adb.ListIntegrationPolicies(cmd.Context())
			if err != nil {
				return err
			}
			set := map[string]audit.IntegrationPolicy{}
			for _, p := range rows {
				set[p.Instance+"\x00"+p.Ecosystem] = p
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "INSTANCE\tECOSYSTEM\tACTION\tSOURCE")
			listed := map[string]bool{}
			for _, n := range integration.SortedNames(entries) {
				typ, _ := entries[n]["type"].(string)
				d, ok := integration.Lookup(typ)
				if !ok {
					continue
				}
				for _, eco := range d.Ecosystems {
					k := n + "\x00" + eco
					listed[k] = true
					if p, ok := set[k]; ok {
						fmt.Fprintf(w, "%s\t%s\t%s\tset by %s %s\n", n, eco, p.Action, p.Actor, p.UpdatedAt.UTC().Format("2006-01-02"))
						continue
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s default\n", n, eco, d.DefaultAction, d.Type)
				}
			}
			// A row whose instance is no longer configured is kept, so adding
			// the instance back restores it; it is shown so it is not a
			// surprise when that happens.
			for _, p := range rows {
				if !listed[p.Instance+"\x00"+p.Ecosystem] {
					fmt.Fprintf(w, "%s\t%s\t%s\tnot configured; applies if the instance is added back\n", p.Instance, p.Ecosystem, p.Action)
				}
			}
			return w.Flush()
		},
	}
}
