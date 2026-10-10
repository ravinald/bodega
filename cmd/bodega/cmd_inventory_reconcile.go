package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/inventory"
	"github.com/ravinald/bodega/internal/inventory/reconcile"
)

// openReconciler opens the audit store and the configured source instances,
// which is everything the read side of reconciliation needs. It classifies
// nothing, so it needs no catalog.
func openReconciler(gf *globalFlags) (*reconcile.Reconciler, func(), error) {
	cfg, err := loadConfig(gf)
	if err != nil {
		return nil, nil, fmt.Errorf("load config: %w", err)
	}
	insts, err := inventory.Configure(cfg.InventorySources)
	if err != nil {
		return nil, nil, err
	}
	adb, err := openInventoryDB(gf)
	if err != nil {
		return nil, nil, err
	}
	return &reconcile.Reconciler{DB: adb, Instances: insts}, func() { _ = adb.Close() }, nil
}

func newInventoryReportCmd(gf *globalFlags) *cobra.Command {
	var (
		asJSON  bool
		classes []string
	)
	c := &cobra.Command{
		Use:   "report <identity>",
		Short: "Show what a host has installed, classified against what bodega served it",
		Long: `report prints a host's current installed set: the union of the latest report
from each inventory source mapped to it. Each component carries the class it
was given when its report arrived, worst first:

  refused       bodega refused this name@version at admission, or it is hidden
  unknown       not cataloged and never served by bodega, or served with
                different bytes; no baseline covers it
  unattributed  served or cataloged, but never served to this host
  served        bodega served it to this host
  baseline      an accepted baseline covers it

A component whose report nothing classified (the audit sink could not answer,
or the report predates reconciliation) reads unclassified.

Then each source instance with its last report, and whether it is stale, and
any component one source reports and another omits (source-disagreement).

Exits 1 when a component is refused, unknown or unclassified, or two sources
disagree, whatever --class shows, so a scheduled job can alert on it.

Examples:
  bodega inventory report web-01
  bodega inventory report web-01 --class refused,unknown
  bodega inventory report web-01 --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rc, done, err := openReconciler(gf)
			if err != nil {
				return err
			}
			defer done()
			alert, err := runInventoryReport(backgroundCtx(), os.Stdout, rc, args[0], classes, asJSON)
			if err != nil {
				return err
			}
			if alert {
				done()
				os.Exit(1) //nolint:revive // the alerting exit code a scheduled job reads
			}
			return nil
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "Print JSON")
	c.Flags().StringSliceVar(&classes, "class", nil, "Show only these classes (comma-separated): "+strings.Join(reconcile.Classes, ", "))
	return c
}

// runInventoryReport prints one host's report and returns whether it alerts.
func runInventoryReport(ctx context.Context, w io.Writer, rc *reconcile.Reconciler, identity string, classes []string, asJSON bool) (bool, error) {
	for _, cl := range classes {
		if !slices.Contains(reconcile.Classes, cl) {
			return false, fmt.Errorf("unknown class %q; choose from %s", cl, strings.Join(reconcile.Classes, ", "))
		}
	}
	rep, err := rc.Host(ctx, identity)
	if err != nil {
		return false, err
	}
	if len(classes) > 0 {
		kept := rep.Components[:0]
		for _, comp := range rep.Components {
			if slices.Contains(classes, comp.Class) {
				kept = append(kept, comp)
			}
		}
		rep.Components = kept
	}
	if asJSON {
		return rep.Alert, writeJSONTo(w, rep)
	}

	fmt.Fprintf(w, "%s: %s\n", rep.Identity, countLine(rep.Counts, len(rep.Disagreements)))
	current := ""
	for _, comp := range rep.Components {
		if comp.Class != current {
			current = comp.Class
			fmt.Fprintf(w, "\n%s (%d)\n", strings.ToUpper(current), rep.Counts[current])
		}
		fmt.Fprintf(w, "  %s %s %s  [%s]\n", comp.Ecosystem, comp.Name, dash(comp.Version), strings.Join(comp.Sources, ","))
		if len(comp.Paths) > 0 {
			fmt.Fprintf(w, "      path: %s\n", strings.Join(comp.Paths, ", "))
		}
		fmt.Fprintf(w, "      %s\n", comp.Reason)
	}

	if len(classes) == 0 || slices.Contains(classes, reconcile.ClassStale) {
		fmt.Fprintln(w, "\nSOURCES")
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  INSTANCE\tMODE\tINTERVAL\tLAST REPORT\tREPORT\tSTALE")
		for _, st := range rep.Sources {
			stale := "no"
			if st.Stale {
				stale = "yes: " + st.Reason
			}
			report := "-"
			if st.ReportID != 0 {
				report = strconv.FormatInt(st.ReportID, 10)
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n", st.Instance, dash(st.Mode), dash(st.Interval), fmtInvTimePtr(st.LastReport), report, stale)
		}
		_ = tw.Flush()
	}

	if len(rep.Disagreements) > 0 {
		fmt.Fprintf(w, "\nSOURCE-DISAGREEMENT (%d)\n", len(rep.Disagreements))
		for _, d := range rep.Disagreements {
			fmt.Fprintf(w, "  %s %s %s  reported by %s (report %d), absent from %s (report %d)\n",
				d.Ecosystem, d.Name, dash(d.Version), d.ReportedBy, d.ReportedIn, d.AbsentFrom, d.AbsentIn)
		}
	}
	return rep.Alert, nil
}

func countLine(counts map[string]int, disagreements int) string {
	parts := make([]string, 0, len(reconcile.Classes)+1)
	for _, cl := range reconcile.Classes {
		if n := counts[cl]; n > 0 || cl != reconcile.ClassUnclassified {
			parts = append(parts, fmt.Sprintf("%d %s", n, cl))
		}
	}
	parts = append(parts, fmt.Sprintf("%d source-disagreement", disagreements))
	return strings.Join(parts, ", ")
}

func newInventoryHostsCmd(gf *globalFlags) *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use:   "hosts",
		Short: "List every mapped host with its sources, staleness and class counts",
		Long: `hosts lists every identity the host mapping knows, including mapped hosts
that never reported. For each source instance mapped to it: the last report
(and for a pull source the last successful poll), the interval, and whether it
is stale, meaning no report within twice that interval. The counts are the
classes of the host's current set, as 'bodega inventory report' shows them.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			rc, done, err := openReconciler(gf)
			if err != nil {
				return err
			}
			defer done()
			return runInventoryHosts(backgroundCtx(), os.Stdout, rc, asJSON)
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "Print JSON")
	return c
}

func runInventoryHosts(ctx context.Context, w io.Writer, rc *reconcile.Reconciler, asJSON bool) error {
	hosts, err := rc.Hosts(ctx)
	if err != nil {
		return err
	}
	if asJSON {
		return writeJSONTo(w, hosts)
	}
	if len(hosts) == 0 {
		fmt.Fprintln(w, "No hosts are mapped. `bodega inventory unbound` lists the ids waiting for a binding.")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "IDENTITY\tSOURCE\tLAST REPORT\tLAST POLL\tINTERVAL\tSTALE\tREFUSED\tUNKNOWN\tUNATTRIBUTED\tSERVED\tBASELINE")
	for _, h := range hosts {
		for i, st := range h.Sources {
			stale := "no"
			if st.Stale {
				stale = "yes"
			}
			counts := "\t\t\t\t"
			if i == 0 {
				counts = fmt.Sprintf("%d\t%d\t%d\t%d\t%d", h.Counts[reconcile.ClassRefused], h.Counts[reconcile.ClassUnknown],
					h.Counts[reconcile.ClassUnattributed], h.Counts[reconcile.ClassServed], h.Counts[reconcile.ClassBaseline])
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", h.Identity, st.Instance, fmtInvTimePtr(st.LastReport),
				fmtInvTimePtr(st.LastPoll), dash(st.Interval), stale, counts)
		}
	}
	return tw.Flush()
}

func newInventoryAcceptCmd(gf *globalFlags) *cobra.Command {
	var (
		reportID int64
		comment  string
		profile  string
	)
	c := &cobra.Command{
		Use:   "accept <identity> [--report <id>] | accept --profile <name>",
		Short: "Accept a host's report, or a profile's entries, as its baseline",
		Long: `accept records what a host is expected to carry, so its image stops reading as
a bypass. With an identity it accepts that host's current set (the latest
report from each source), or the one report --report names. With --profile it
accepts the profile's entries for every identity bound to it: a pinned entry
covers its version, an unpinned one every version of the name.

Reports that arrive afterwards classify the accepted components as baseline,
unless bodega refused them: a baseline never hides a refused version. Reports
already stored keep the classes they were given. Accepting again replaces the
baseline in force; the earlier one stays on record.

Examples:
  bodega inventory accept web-01 --comment "golden image 2026-10"
  bodega inventory accept web-01 --report 412
  bodega inventory accept --profile web-tier`,
		Args: func(cmd *cobra.Command, args []string) error {
			switch {
			case profile != "" && len(args) > 0:
				return fmt.Errorf("--profile accepts for every identity bound to the profile; name no identity with it")
			case profile != "" && reportID != 0:
				return fmt.Errorf("--report names one host's report and --profile a profile's entries; use one")
			case profile == "" && len(args) != 1:
				return fmt.Errorf("accept takes one identity, or --profile <name>")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			_, adb, err := openACLStore(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			cfg, err := loadConfig(gf)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			insts, err := inventory.Configure(cfg.InventorySources)
			if err != nil {
				return err
			}
			rc := &reconcile.Reconciler{DB: adb, Instances: insts}
			identity := ""
			if len(args) == 1 {
				identity = args[0]
			}
			return runInventoryAccept(backgroundCtx(), os.Stdout, rc, identity, profile, reportID, audit.CurrentActor(), comment)
		},
	}
	c.Flags().Int64Var(&reportID, "report", 0, "Accept this report id instead of the host's current set")
	c.Flags().StringVar(&comment, "comment", "", "Why this is accepted, kept with the baseline")
	c.Flags().StringVar(&profile, "profile", "", "Accept this profile's entries for every identity bound to it")
	return c
}

func runInventoryAccept(ctx context.Context, w io.Writer, rc *reconcile.Reconciler, identity, profile string, reportID int64, actor, comment string) error {
	var (
		b   audit.InventoryBaseline
		err error
	)
	if profile != "" {
		b, err = rc.AcceptProfile(ctx, profile, actor, comment)
	} else {
		b, err = rc.AcceptReport(ctx, identity, reportID, actor, comment)
	}
	if err != nil {
		return err
	}
	subject, name := "identity="+b.Identity, b.Identity
	if b.Profile != "" {
		subject, name = "profile="+b.Profile, b.Profile
	}
	_ = rc.DB.Record(ctx, audit.Event{
		EventType: audit.EventCreate, PkgType: "inventory-baseline", PkgName: name,
		Actor: actor, Status: "success",
		Details: fmt.Sprintf("id=%d %s reports=%s components=%d", b.ID, subject, joinIDs(b.ReportIDs), len(b.Components)),
	})
	if b.Profile != "" {
		fmt.Fprintf(w, "Accepted %d entries of profile %s as the baseline of every identity bound to it (baseline %d).\n",
			len(b.Components), b.Profile, b.ID)
	} else {
		fmt.Fprintf(w, "Accepted %d components from report %s as the baseline of %s (baseline %d).\n",
			len(b.Components), joinIDs(b.ReportIDs), b.Identity, b.ID)
	}
	fmt.Fprintln(w, "Reports from now on classify these as baseline unless bodega refused them; stored reports keep their classes.")
	return nil
}

func newInventoryBaselineCmd(gf *globalFlags) *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use:   "baseline <identity>",
		Short: "Show what is accepted for a host, and when",
		Long: `baseline shows the baseline in force for an identity: its own, from
'bodega inventory accept <identity>', and the one its bound profile carries,
from 'bodega inventory accept --profile'. Each with who accepted it, when, why,
and the components it covers.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rc, done, err := openReconciler(gf)
			if err != nil {
				return err
			}
			defer done()
			return runInventoryBaseline(backgroundCtx(), os.Stdout, rc, args[0], asJSON)
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "Print JSON")
	return c
}

func runInventoryBaseline(ctx context.Context, w io.Writer, rc *reconcile.Reconciler, identity string, asJSON bool) error {
	bs, err := rc.BaselinesFor(ctx, identity)
	if err != nil {
		return err
	}
	if asJSON {
		return writeJSONTo(w, bs)
	}
	if bs.Own == nil && bs.ByProfile == nil {
		fmt.Fprintf(w, "Nothing is accepted for %s.", identity)
		if bs.Profile != "" {
			fmt.Fprintf(w, " Its profile %s has no accepted baseline either.", bs.Profile)
		}
		fmt.Fprintf(w, "\n  Accept its current set with: bodega inventory accept %s\n", identity)
		return nil
	}
	for _, b := range []*audit.InventoryBaseline{bs.Own, bs.ByProfile} {
		if b == nil {
			continue
		}
		if b.Profile != "" {
			fmt.Fprintf(w, "Profile %s baseline %d\n", b.Profile, b.ID)
		} else {
			fmt.Fprintf(w, "%s baseline %d, from report %s\n", b.Identity, b.ID, joinIDs(b.ReportIDs))
		}
		fmt.Fprintf(w, "  accepted %s by %s\n", fmtInvTime(b.CreatedAt), dash(b.Actor))
		if b.Comment != "" {
			fmt.Fprintf(w, "  comment: %s\n", b.Comment)
		}
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintf(tw, "  ECOSYSTEM\tNAME\tVERSION\n")
		for _, c := range b.Components {
			version := c.Version
			if version == "" {
				version = "any"
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\n", c.Ecosystem, c.Name, version)
		}
		_ = tw.Flush()
		fmt.Fprintln(w)
	}
	return nil
}

func joinIDs(ids []int64) string {
	if len(ids) == 0 {
		return "-"
	}
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = strconv.FormatInt(id, 10)
	}
	return strings.Join(out, ",")
}

func writeJSONTo(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
