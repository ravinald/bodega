package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
)

func newPolicyAgeCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "age",
		Short: "Minimum-publish-age gate per ecosystem",
		Long: `Configure a minimum-publish-age gate for each package ecosystem.

A version is rejected (or flagged) when its upstream publish timestamp is
newer than the ecosystem's minimum age. Ecosystems without a reliable
upstream timestamp (apt, binary, git, helm) are unaffected.

  bodega policy age set npm 7d warn
  bodega policy age set pypi 72h block
  bodega policy age list
  bodega policy age remove npm`,
	}
	cmd.AddCommand(newPolicyAgeSetCmd(gf), newPolicyAgeListCmd(gf), newPolicyAgeRemoveCmd(gf))
	return cmd
}

func newPolicyAgeSetCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "set <ecosystem> <min-age> <action>",
		Short: "Set the minimum-age policy for an ecosystem",
		Long: `min-age is a duration like 24h, 7d, or 168h. action is one of
warn, block, or ignore. The same ecosystem can only have one rule; set
overwrites the existing row.`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			eco, rawDur, action := args[0], args[1], strings.ToLower(args[2])
			dur, err := parseAgeDuration(rawDur)
			if err != nil {
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
			if err := adb.SetAgePolicy(context.Background(), audit.AgePolicy{
				Ecosystem:     eco,
				MinAgeSeconds: int64(dur.Seconds()),
				Action:        action,
			}); err != nil {
				return err
			}
			fmt.Printf("Set %s age policy: >= %s, %s\n", eco, dur, action)
			return nil
		},
	}
}

func newPolicyAgeListCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List age policies",
		RunE: func(cmd *cobra.Command, args []string) error {
			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("audit DB unavailable")
			}
			defer adb.Close()
			rows, err := adb.ListAgePolicies(context.Background())
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				fmt.Println("No age policies configured.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ECOSYSTEM\tMIN AGE\tACTION\tUPDATED")
			for _, p := range rows {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
					p.Ecosystem,
					(time.Duration(p.MinAgeSeconds) * time.Second).String(),
					p.Action,
					p.UpdatedAt.Format("2006-01-02"))
			}
			return w.Flush()
		},
	}
}

func newPolicyAgeRemoveCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <ecosystem>",
		Short: "Remove the age policy for an ecosystem",
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
			deleted, err := adb.DeleteAgePolicy(context.Background(), args[0])
			if err != nil {
				return err
			}
			if !deleted {
				return fmt.Errorf("no age policy for %q", args[0])
			}
			fmt.Printf("Removed age policy for %s\n", args[0])
			return nil
		},
	}
}

// parseAgeDuration accepts the stock Go duration shapes plus a plain <N>d
// shorthand for days, which time.ParseDuration doesn't understand.
func parseAgeDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		var days int
		if _, err := fmt.Sscanf(s, "%dd", &days); err != nil || days <= 0 {
			return 0, fmt.Errorf("bad duration %q (expected like 7d, 72h)", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
