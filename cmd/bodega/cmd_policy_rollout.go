package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// reportRowLimit bounds the admission rows `policy report` reads for its
// window. A window holding more says so rather than printing a floor as a
// count.
const reportRowLimit = 200000

func newPolicyModeCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mode",
		Short: "How each ecosystem decides which names it admits",
		Long: `An ecosystem admits names in one of two modes:

  listed  only a name an allow-list rule matches
  open    any name that passes every per-version gate (age, OSV, upstream
          provenance, name similarity)

An ecosystem nobody set a mode for follows its allow-list: listed when it
has rules, open when it has none, which is how bodega behaved before modes
existed. Open admission is admission by criteria: no person approves each
name, and the gates decide each version. unset returns an ecosystem to that
default; a mode set to open stays open after allow-list rules are added.

  bodega policy mode list
  bodega policy mode set npm open
  bodega policy mode set pypi listed
  bodega policy mode unset npm`,
	}
	cmd.AddCommand(newPolicyModeSetCmd(gf), newPolicyModeUnsetCmd(gf), newPolicyModeListCmd(gf))
	return cmd
}

func newPolicyModeSetCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "set <ecosystem> listed|open",
		Short: "Set an ecosystem's admission mode",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			eco, mode := args[0], strings.ToLower(args[1])
			if err := policy.ValidateType(eco); err != nil {
				return err
			}
			if mode != audit.ModeListed && mode != audit.ModeOpen {
				return fmt.Errorf("mode must be %s or %s, got %q", audit.ModeListed, audit.ModeOpen, args[1])
			}
			adb, err := openMutableAuditDB(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			ctx := context.Background()
			before, err := policy.NewChecker(adb).ModeFor(ctx, eco)
			if err != nil {
				return err
			}
			actor := audit.CurrentActor()
			if err := adb.SetAdmissionMode(ctx, audit.AdmissionMode{Ecosystem: eco, Mode: mode, Actor: actor}); err != nil {
				return err
			}
			details, _ := json.Marshal(map[string]any{"admission_mode": mode, "before": before.Mode, "before_set": before.Set})
			if err := adb.Record(ctx, audit.Event{EventType: audit.EventPolicy, PkgType: eco, Actor: actor,
				Status: "success", Details: string(details)}); err != nil {
				return fmt.Errorf("set %s to %s, but the audit event was not written: %w", eco, mode, err)
			}
			fmt.Printf("Set %s admission mode: %s (was %s)\n", eco, mode, before.Mode)
			if mode == audit.ModeListed && before.Rules == 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s has no allow-list rules, so listed mode admits no name until 'bodega policy add %s <pattern>' adds one\n", eco, eco)
			}
			return nil
		},
	}
}

func newPolicyModeUnsetCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "unset <ecosystem>",
		Short: "Return an ecosystem to the admission mode its allow-list implies",
		Long: `Delete the mode set for an ecosystem, so it follows its allow-list again:
listed when it has rules, open when it has none. An ecosystem with no mode
set is left as it is and nothing is recorded, so a restore script can run
this unconditionally.

  bodega policy mode unset npm`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			eco := args[0]
			if err := policy.ValidateType(eco); err != nil {
				return err
			}
			adb, err := openMutableAuditDB(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			ctx := context.Background()
			before, err := policy.NewChecker(adb).ModeFor(ctx, eco)
			if err != nil {
				return err
			}
			if !before.Set {
				fmt.Printf("%s has no admission mode set; it is %s by default\n", eco, before.Mode)
				return nil
			}
			if _, err := adb.ClearAdmissionMode(ctx, eco); err != nil {
				return err
			}
			after, err := policy.NewChecker(adb).ModeFor(ctx, eco)
			if err != nil {
				return fmt.Errorf("unset %s, but reading its default mode failed: %w", eco, err)
			}
			details, _ := json.Marshal(map[string]any{"admission_mode": "default", "before": before.Mode,
				"before_set": before.Set, "after": after.Mode})
			if err := adb.Record(ctx, audit.Event{EventType: audit.EventPolicy, PkgType: eco, Actor: audit.CurrentActor(),
				Status: "success", Details: string(details)}); err != nil {
				return fmt.Errorf("unset %s, but the audit event was not written: %w", eco, err)
			}
			fmt.Printf("Unset %s admission mode: now %s by default (was %s, set)\n", eco, after.Mode, before.Mode)
			return nil
		},
	}
}

func newPolicyModeListCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List every ecosystem's admission mode",
		RunE: func(cmd *cobra.Command, args []string) error {
			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("audit DB unavailable")
			}
			defer adb.Close()
			ctx := context.Background()
			set, err := adb.ListAdmissionModes(ctx)
			if err != nil {
				return err
			}
			byEco := map[string]audit.AdmissionMode{}
			for _, m := range set {
				byEco[m.Ecosystem] = m
			}
			checker := policy.NewChecker(adb)
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ECOSYSTEM\tMODE\tRULES\tSOURCE")
			for _, eco := range manifest.AllTypes {
				m, err := checker.ModeFor(ctx, eco)
				if err != nil {
					return fmt.Errorf("%s: %w", eco, err)
				}
				fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", eco, m.Mode, m.Rules, modeSource(m, byEco[eco]))
			}
			return w.Flush()
		},
	}
}

// modeSource says why an ecosystem is in its mode, which is what doctor and
// an operator reading the list both need: an open ecosystem nobody chose is
// a different finding from one somebody did.
func modeSource(m policy.Mode, row audit.AdmissionMode) string {
	switch {
	case m.Set:
		return fmt.Sprintf("set by %s on %s", row.Actor, row.UpdatedAt.Format("2006-01-02"))
	case m.Rules == 0:
		return "default: no allow-list rules"
	default:
		return "default: has allow-list rules"
	}
}

func newPolicyEnforceCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "enforce <ecosystem> report|enforce",
		Short: "Switch an ecosystem's gates between report-only and their configured actions",
		Long: `report sets every gate the ecosystem has a policy row for (age, OSV,
upstream provenance, name similarity) to warn, and saves the actions they had.
enforce writes each saved action back. Each switch writes one audit event
naming the actor and every gate's before and after.

In report mode a gate admits what it would have refused and records the
finding, so 'bodega policy report' can show what enforcing would block before
anything is blocked. Two things are deliberately left as they are: the OSV
malware action, because a known-malicious package is not one to admit while
reading a report, and the allow-list, which has no action and is opened with
'bodega policy mode set <ecosystem> open' instead.

  bodega policy enforce npm report
  bodega policy report --since 7d
  bodega policy enforce npm enforce`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			eco, state := args[0], strings.ToLower(args[1])
			if err := policy.ValidateType(eco); err != nil {
				return err
			}
			adb, err := openMutableAuditDB(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			switches, err := policy.SwitchRollout(context.Background(), adb, eco, state, audit.CurrentActor())
			if err != nil {
				return err
			}
			fmt.Printf("%s: %s\n", eco, state)
			if len(switches) == 0 {
				fmt.Println("  no gate has a policy row for this ecosystem, so nothing was switched")
				return nil
			}
			for _, s := range switches {
				fmt.Printf("  %-20s %s -> %s\n", s.Gate, s.Before, s.After)
			}
			return nil
		},
	}
}

func newPolicyReportCmd(gf *globalFlags) *cobra.Command {
	var since string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "report",
		Short: "What the gates flagged, and the baseline debt",
		Long: `List what the gates flagged in the window, grouped by ecosystem, check and
package, with the request count, the versions and the hosts (by identity)
that asked. ON ENFORCE is the action the check takes once the ecosystem is
enforced, so a warn row whose ON ENFORCE is block is what 'bodega policy
enforce <ecosystem> enforce' would start refusing.

Baseline debt lists versions imported with 'bodega pkg import --baseline'
that fail a gate and are admitted only because of the mark, whatever the
window. 'bodega policy baseline clear' removes the mark.

  bodega policy report
  bodega policy report --since 30d --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			window, err := config.ParseTTL(since)
			if err != nil {
				return fmt.Errorf("--since: %w", err)
			}
			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("audit DB unavailable")
			}
			defer adb.Close()
			ctx := context.Background()
			from := time.Now().Add(-window)
			flagged, err := adb.Admissions(ctx, audit.AdmissionFilter{Since: from, Limit: reportRowLimit})
			if err != nil {
				return err
			}
			var debt []audit.Admission
			store, err := loadStore(gf)
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: baseline debt not listed: load manifests: %v\n", err)
			} else if debt, err = baselineRows(ctx, adb, store); err != nil {
				return err
			}
			onEnforce, err := policy.EnforceActions(ctx, adb, manifest.AllTypes)
			if err != nil {
				return err
			}
			rep := policy.BuildReport(from, flagged, debt, onEnforce)
			rep.Truncated = len(flagged) == reportRowLimit
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(rep)
			}
			return printReport(cmd.OutOrStdout(), rep)
		},
	}
	cmd.Flags().StringVar(&since, "since", "7d", "Window to report on, like 7d or 72h")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print the report as JSON")
	return cmd
}

// baselineRows returns the newest admission row of every version the store
// still marks baseline.
func baselineRows(ctx context.Context, adb *audit.DB, store *manifest.Store) ([]audit.Admission, error) {
	var out []audit.Admission
	for _, t := range manifest.AllTypes {
		for _, name := range store.ListPackages(t) {
			pm, err := store.GetPackage(ctx, t, name)
			if err != nil {
				return nil, fmt.Errorf("load %s/%s: %w", t, name, err)
			}
			for _, ve := range pm.Versions {
				if !ve.Baseline {
					continue
				}
				version := ve.Version
				if version == "" {
					version = ve.Ref
				}
				rows, err := adb.Admissions(ctx, audit.AdmissionFilter{PkgType: t, PkgName: pm.Name, PkgVersion: version, Limit: 1})
				if err != nil {
					return nil, err
				}
				out = append(out, rows...)
			}
		}
	}
	return out, nil
}

func printReport(out io.Writer, rep policy.Report) error {
	fmt.Fprintf(out, "Flagged since %s\n", rep.Since.UTC().Format(time.RFC3339))
	if rep.Truncated {
		fmt.Fprintf(out, "(the window holds more than %d admission rows; counts are a floor, narrow --since)\n", reportRowLimit)
	}
	if len(rep.Flagged) == 0 {
		fmt.Fprintln(out, "  nothing flagged")
	} else {
		w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "ECOSYSTEM\tCHECK\tPACKAGE\tSTATUS\tON ENFORCE\tREQUESTS\tVERSIONS\tHOSTS")
		for _, e := range rep.Flagged {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n", e.Ecosystem, e.Check, e.Package, e.Status,
				orDash(e.OnEnforce), e.Requests, orDash(strings.Join(e.Versions, ",")), hostsCell(e))
		}
		if err := w.Flush(); err != nil {
			return err
		}
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Baseline debt")
	if len(rep.BaselineDebt) == 0 {
		fmt.Fprintln(out, "  none")
		return nil
	}
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ECOSYSTEM\tCHECK\tPACKAGE\tVERSIONS\tDETAIL")
	for _, e := range rep.BaselineDebt {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", e.Ecosystem, e.Check, e.Package, strings.Join(e.Versions, ","), e.Detail)
	}
	return w.Flush()
}

func hostsCell(e policy.ReportEntry) string {
	cell := strings.Join(e.Hosts, ",")
	if e.Unidentified > 0 {
		if cell != "" {
			cell += ","
		}
		cell += fmt.Sprintf("(%d unidentified)", e.Unidentified)
	}
	return orDash(cell)
}

func newPolicyBaselineCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Manage the baseline marks 'pkg import --baseline' set",
	}
	// Clearing rewrites manifests the server serves from its cache.
	cmd.AddCommand(signalsReload(newPolicyBaselineClearCmd(gf)))
	return cmd
}

func newPolicyBaselineClearCmd(gf *globalFlags) *cobra.Command {
	var olderThan string
	cmd := &cobra.Command{
		Use:   "clear <ecosystem>",
		Short: "Remove the baseline mark so the gates apply",
		Long: `Remove the baseline mark from every version of the ecosystem, or with
--older-than only from versions marked at least that long ago, then evaluate
each cleared version against the gates and report how many now fail.

The evaluation records nothing: the next fetch or re-vet of a failing version
is what refuses it.

  bodega policy baseline clear npm
  bodega policy baseline clear pypi --older-than 30d`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			eco := args[0]
			if err := policy.ValidateType(eco); err != nil {
				return err
			}
			var age time.Duration
			if olderThan != "" {
				d, err := config.ParseTTL(olderThan)
				if err != nil {
					return fmt.Errorf("--older-than: %w", err)
				}
				age = d
			}
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
			if err := ensureMutable(cfg); err != nil {
				return err
			}
			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}
			adb := openAuditDB(gf)
			if adb != nil {
				defer adb.Close()
			}
			ctx := context.Background()
			cleared, err := admit.ClearBaseline(ctx, store, policy.CheckerFor(adb), adb, cfg, eco, age, time.Now())
			if err != nil {
				return err
			}
			failing := 0
			for _, c := range cleared {
				if len(c.Failing) > 0 {
					failing++
				}
			}
			if adb != nil {
				details, _ := json.Marshal(map[string]any{"baseline_clear": len(cleared), "failing": failing, "older_than": olderThan})
				_ = adb.Record(ctx, audit.Event{EventType: audit.EventPolicy, PkgType: eco, Actor: audit.CurrentActor(),
					Status: "baseline_clear", Details: string(details)})
			}
			fmt.Printf("Cleared the baseline mark from %d %s version(s); %d now fail a gate.\n", len(cleared), eco, failing)
			for _, c := range cleared {
				for _, f := range c.Failing {
					fmt.Printf("  %s@%s: %s: %s\n", c.Name, c.Version, f.Check, f.Detail)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&olderThan, "older-than", "", "Clear only marks set at least this long ago, like 30d")
	return cmd
}

// openMutableAuditDB opens the audit database for a policy write, refusing
// on a read-only install.
func openMutableAuditDB(gf *globalFlags) (*audit.DB, error) {
	cfg, err := loadConfig(gf)
	if err != nil {
		return nil, err
	}
	if err := ensureMutable(cfg); err != nil {
		return nil, err
	}
	adb := openAuditDB(gf)
	if adb == nil {
		return nil, fmt.Errorf("audit DB unavailable")
	}
	return adb, nil
}
