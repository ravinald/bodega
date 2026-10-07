package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/policy"
)

func newPolicyFilterCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "filter",
		Short: "Hide versions the age and OSV gates block from proxied indexes",
		Long: `With the filter on for an ecosystem, the proxied npm packument, pypi
simple page and gomod @v/list omit every version the age gate or the OSV gate
would block, so a client's resolver picks the newest version that passes
instead of the newest upstream and a refusal. A gate set to warn or ignore
withholds nothing. The artifact routes still refuse a withheld version
requested directly.

  bodega policy filter set npm on
  bodega policy filter set pypi off
  bodega policy filter list`,
	}
	cmd.AddCommand(newPolicyFilterSetCmd(gf), newPolicyFilterListCmd(gf))
	return cmd
}

func newPolicyFilterSetCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "set <ecosystem> <on|off>",
		Short: "Turn the index filter on or off for an ecosystem",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			eco, state := args[0], strings.ToLower(args[1])
			if err := requireEcosystem(eco, policy.IndexFilterEcosystems(), "index filter",
				"bodega rewrites no proxied index for it"); err != nil {
				return err
			}
			if state != "on" && state != "off" {
				return fmt.Errorf("state must be on or off, got %q", args[1])
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
			if err := adb.SetIndexFilter(context.Background(), audit.IndexFilter{
				Ecosystem: eco,
				Enabled:   state == "on",
			}); err != nil {
				return err
			}
			fmt.Printf("Set %s index filter: %s\n", eco, state)
			return nil
		},
	}
}

func newPolicyFilterListCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Show the index filter for every ecosystem it covers",
		RunE: func(cmd *cobra.Command, args []string) error {
			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("audit DB unavailable")
			}
			defer adb.Close()
			ctx := context.Background()
			rows, err := adb.ListIndexFilters(ctx)
			if err != nil {
				return err
			}
			stored := make(map[string]audit.IndexFilter, len(rows))
			for _, f := range rows {
				stored[f.Ecosystem] = f
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ECOSYSTEM\tFILTER\tWITHHOLDS\tUPDATED")
			for _, eco := range policy.IndexFilterEcosystems() {
				f, set := stored[eco]
				state, updated := "off", "-"
				if set {
					updated = f.UpdatedAt.Format("2006-01-02")
					if f.Enabled {
						state = "on"
					}
				}
				withholds, err := filterWithholds(ctx, adb, eco)
				if err != nil {
					return err
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", eco, state, withholds, updated)
			}
			return w.Flush()
		},
	}
}

// filterWithholds names what the filter would withhold for an ecosystem if it
// were on. Shown beside an off filter too, so an operator reads what turning
// it on would do before doing it.
func filterWithholds(ctx context.Context, adb *audit.DB, eco string) (string, error) {
	var parts []string
	age, err := adb.GetAgePolicy(ctx, eco)
	switch {
	case errors.Is(err, audit.ErrAgePolicyNotFound):
	case err != nil:
		return "", err
	case age.Action == policy.ActionBlock:
		parts = append(parts, "age < "+policy.ShortDuration(time.Duration(age.MinAgeSeconds)*time.Second))
	}
	osv, err := adb.GetOSVPolicy(ctx, eco)
	switch {
	case errors.Is(err, audit.ErrOSVPolicyNotFound):
	case err != nil:
		return "", err
	case osv.Action == policy.ActionBlock:
		parts = append(parts, "osv records")
	}
	if len(parts) == 0 {
		return "nothing (no gate blocks)", nil
	}
	return strings.Join(parts, ", "), nil
}
