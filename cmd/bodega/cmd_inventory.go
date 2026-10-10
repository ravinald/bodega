package main

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/inventory"
)

// newInventoryCmd manages the host mapping inventory sources resolve reports
// through, and reports on the configured sources.
func newInventoryCmd(gf *globalFlags) *cobra.Command {
	parent := &cobra.Command{
		Use:   "inventory <sources|bind|unbind|unbound|report|hosts|accept|baseline>",
		Short: "Inspect inventory sources, map their hosts, and reconcile what hosts installed",
		Long: `Inventory sources deliver each host's installed packages to bodega, either
pushed to a route the source registers or polled from a vendor API. Each
source names hosts its own way (a node key, a vendor host id, a token's
identity), and a report reaches an identity only through the host mapping
these commands manage. A report from an id nothing maps is kept as unbound.

Each report is classified against what bodega served, refused and cataloged
as it arrives. report, hosts, accept and baseline read and steer that.

Examples:
  bodega inventory sources
  bodega inventory unbound --json
  bodega inventory bind osquery-a 5f1c0e... web-01
  bodega inventory unbind osquery-a 5f1c0e...
  bodega inventory report web-01
  bodega inventory hosts
  bodega inventory accept web-01 --comment "golden image"
  bodega inventory baseline web-01`,
	}
	parent.AddCommand(
		newInventorySourcesCmd(gf),
		newInventoryBindCmd(gf),
		newInventoryUnbindCmd(gf),
		newInventoryUnboundCmd(gf),
		newInventoryReportCmd(gf),
		newInventoryHostsCmd(gf),
		newInventoryAcceptCmd(gf),
		newInventoryBaselineCmd(gf),
	)
	return parent
}

// inventoryInstance refuses a source name inventory_sources does not
// configure, so a bind to a misspelled source fails here rather than mapping
// a host nothing reports for.
func inventoryInstance(cfg *config.Config, name string) error {
	if _, ok := cfg.InventorySources[name]; ok {
		return nil
	}
	names := make([]string, 0, len(cfg.InventorySources))
	for n := range cfg.InventorySources {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return fmt.Errorf("no inventory source named %q: inventory_sources in %s is empty", name, config.ConfigPath())
	}
	return fmt.Errorf("no inventory source named %q (configured: %s)", name, strings.Join(names, ", "))
}

func newInventoryBindCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "bind <source> <external-id> <identity>",
		Short: "Map a source's host id to a bodega identity",
		Long: `bind maps the id a source instance uses for a host to the identity bodega
records for it. Reports already stored unbound stay as they were written;
reports from now on carry the identity.

An id already mapped to a different identity is refused. Unbind it first.`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			source, ext, identity := args[0], args[1], args[2]
			cfg, adb, err := openACLStore(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			if err := inventoryInstance(cfg, source); err != nil {
				return err
			}
			added, err := adb.BindInventoryHost(backgroundCtx(), source, ext, identity)
			if err != nil {
				return err
			}
			if !added {
				fmt.Printf("%s %s is already bound to %s.\n", source, ext, identity)
				return nil
			}
			fmt.Printf("Bound %s %s to %s.\n", source, ext, identity)
			return nil
		},
	}
}

func newInventoryUnbindCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "unbind <source> <external-id>",
		Short: "Remove a host mapping",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			source, ext := args[0], args[1]
			_, adb, err := openACLStore(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			removed, err := adb.UnbindInventoryHost(backgroundCtx(), source, ext)
			if err != nil {
				return err
			}
			if !removed {
				return fmt.Errorf("%s %s is not bound; bodega inventory unbound lists the ids waiting for one", source, ext)
			}
			fmt.Printf("Unbound %s %s.\n", source, ext)
			return nil
		},
	}
}

func newInventoryUnboundCmd(gf *globalFlags) *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use:   "unbound",
		Short: "List host ids that have reported and that no mapping names",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			adb, err := openInventoryDB(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			rows, err := adb.ListUnboundInventoryHosts(backgroundCtx())
			if err != nil {
				return err
			}
			if asJSON {
				if rows == nil {
					rows = []audit.UnboundInventoryHost{}
				}
				return printJSON(rows)
			}
			if len(rows) == 0 {
				fmt.Println("No unbound hosts.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "SOURCE\tEXTERNAL ID\tREPORTS\tFIRST\tLATEST")
			for _, u := range rows {
				fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n", u.Source, u.ExternalID, u.Reports,
					fmtInvTime(u.FirstReport), fmtInvTime(u.LatestReport))
			}
			return w.Flush()
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "Print JSON")
	return c
}

// inventorySourceRow is one line of `bodega inventory sources`.
type inventorySourceRow struct {
	Instance     string     `json:"instance"`
	Type         string     `json:"type"`
	Mode         string     `json:"mode"`
	Capabilities []string   `json:"capabilities"`
	Enabled      bool       `json:"enabled"`
	Interval     string     `json:"interval,omitempty"`
	LastReport   *time.Time `json:"last_report"`
	LastPoll     *time.Time `json:"last_poll,omitempty"`
	LastSuccess  *time.Time `json:"last_success,omitempty"`
	LastError    string     `json:"last_error,omitempty"`
	MappedHosts  int64      `json:"mapped_hosts"`
	UnboundHosts int64      `json:"unbound_hosts"`
}

func newInventorySourcesCmd(gf *globalFlags) *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use:   "sources",
		Short: "List configured inventory sources with their last report and host counts",
		Long: `sources lists every instance in inventory_sources: its type, mode,
capabilities and enabled state, when it last delivered a report (and for a
pull source when it last polled and last succeeded), and how many hosts it
maps and how many it has seen that nothing maps.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			insts, err := inventory.Configure(cfg.InventorySources)
			if err != nil {
				return err
			}
			adb, err := openInventoryDB(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			rows := make([]inventorySourceRow, 0, len(insts))
			for _, inst := range insts {
				st, err := adb.InventorySourceStats(backgroundCtx(), inst.Name)
				if err != nil {
					return fmt.Errorf("read %s: %w", inst.Name, err)
				}
				row := inventorySourceRow{
					Instance: inst.Name, Type: inst.Source.Type(), Mode: string(inst.Source.Mode()),
					Enabled: inst.Enabled, LastReport: timePtr(st.LastReport),
					MappedHosts: st.MappedHosts, UnboundHosts: st.UnboundHosts,
				}
				for _, c := range inst.Source.Capabilities() {
					row.Capabilities = append(row.Capabilities, string(c))
				}
				if inst.Source.Mode() == inventory.ModePull {
					row.Interval = inst.Interval.String()
					row.LastPoll, row.LastSuccess, row.LastError = timePtr(st.LastAttempt), timePtr(st.LastSuccess), st.LastError
				}
				rows = append(rows, row)
			}
			if asJSON {
				return printJSON(rows)
			}
			if len(rows) == 0 {
				fmt.Println("No inventory sources configured (inventory_sources in " + config.ConfigPath() + ").")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "INSTANCE\tTYPE\tMODE\tCAPABILITIES\tENABLED\tLAST REPORT\tLAST POLL\tMAPPED\tUNBOUND")
			for _, r := range rows {
				poll := "-"
				if r.Mode == string(inventory.ModePull) {
					poll = fmtInvTimePtr(r.LastPoll)
					if r.LastError != "" {
						poll += " (failed)"
					}
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%v\t%s\t%s\t%d\t%d\n", r.Instance, r.Type, r.Mode,
					strings.Join(r.Capabilities, ","), r.Enabled, fmtInvTimePtr(r.LastReport), poll,
					r.MappedHosts, r.UnboundHosts)
			}
			return w.Flush()
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "Print JSON")
	return c
}

// openInventoryDB opens the audit store for a read, keeping the reason when
// it cannot.
func openInventoryDB(gf *globalFlags) (*audit.DB, error) {
	adb, err := openAuditDBErr(gf)
	if err != nil {
		return nil, err
	}
	if adb == nil {
		return nil, errors.New("no audit database is configured, and the inventory store lives in it; set audit_db or log_dir")
	}
	return adb, nil
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func fmtInvTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04")
}

func fmtInvTimePtr(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return fmtInvTime(*t)
}
