package main

import (
	"context"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/policy"
)

// newDiscoverCmd returns the `bodega discover ...` subcommand tree. Discover
// mode is configured server-side via `discover_mode` in config.json; this CLI
// reads from and curates the resulting observation log.
func newDiscoverCmd(gf *globalFlags) *cobra.Command {
	parent := &cobra.Command{
		Use:   "discover",
		Short: "Inspect upstream-fetch observations and promote them to allow-list rules",
		Long: `Auto-discover mode is configured server-side. Set "discover_mode" in
config.json to one of:

  "observe"  log every upstream fetch + still enforce the allow-list (safe to leave on)
  "learn"    log + temporarily BYPASS the allow-list (loud WARN; for bootstrapping)

Use these subcommands to review what's been captured and turn observations
into policy rules.`,
	}
	parent.AddCommand(
		newDiscoverListCmd(gf),
		newDiscoverShowCmd(gf),
		newDiscoverPromoteCmd(gf),
		newDiscoverPromoteAllCmd(gf),
		newDiscoverClearCmd(gf),
		newDiscoverExportCmd(gf),
	)
	return parent
}

func newDiscoverListCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list [type]",
		Short: "List distinct (type, pattern) buckets seen by the discovery hook",
		Long: `Aggregate observations into one row per (registry_type, suggested-pattern).
The PATTERN column is exactly what 'bodega discover promote' would write.

Examples:
  bodega discover list                 # all types
  bodega discover list gomod           # filter to one type`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var regType string
			if len(args) > 0 {
				regType = args[0]
				if err := policy.ValidateType(regType); err != nil {
					return err
				}
			}

			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("could not open audit database")
			}
			defer adb.Close()

			ctx := context.Background()
			rows, err := adb.AggregateDiscovery(ctx, regType)
			if err != nil {
				return fmt.Errorf("aggregate discovery: %w", err)
			}
			if len(rows) == 0 {
				fmt.Println("No discovery observations yet.")
				fmt.Println("(Set \"discover_mode\" to \"observe\" or \"learn\" in config.json and restart bodega.)")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "TYPE\tPATTERN\tHOST\tCOUNT\tDECISIONS\tLAST SEEN")
			for _, a := range rows {
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\n",
					a.RegistryType, a.PatternHint, a.Host, a.RequestCount,
					a.Decisions, a.LastSeen.Format("2006-01-02 15:04"))
			}
			return w.Flush()
		},
	}
}

func newDiscoverShowCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "show <type> <pattern>",
		Short: "Show raw observation rows for one (type, pattern) bucket",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			regType := args[0]
			pattern := args[1]
			if err := policy.ValidateType(regType); err != nil {
				return err
			}

			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("could not open audit database")
			}
			defer adb.Close()

			ctx := context.Background()
			rows, err := adb.ListDiscovery(ctx, audit.DiscoveryFilter{
				RegistryType: regType,
				PatternHint:  pattern,
				Limit:        500,
			})
			if err != nil {
				return fmt.Errorf("list discovery: %w", err)
			}
			if len(rows) == 0 {
				fmt.Printf("No observations for %s %q.\n", regType, pattern)
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "PACKAGE\tVERSION\tDECISION\tCOUNT\tLAST CLIENT\tLAST SEEN\tUPSTREAM URL")
			for _, r := range rows {
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
					r.PkgName, r.PkgVersion, r.Decision, r.RequestCount,
					r.LastClient, r.LastSeen.Format("2006-01-02 15:04"),
					r.UpstreamURL)
			}
			return w.Flush()
		},
	}
}

func newDiscoverPromoteCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "promote <type> <pattern> [comment]",
		Short: "Promote one discovered pattern to an allow-list rule",
		Long: `Insert an allow-list rule with the type's natural rule kind and the
captured pattern. Same write path as 'bodega policy add'.

Examples:
  bodega discover promote gomod github.com/aws/
  bodega discover promote npm @aws-sdk/* "AWS SDK packages"`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			regType := args[0]
			pattern := args[1]
			comment := ""
			if len(args) > 2 {
				comment = strings.Join(args[2:], " ")
			}
			return promoteOne(gf, regType, pattern, comment)
		},
	}
}

func newDiscoverPromoteAllCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "promote-all <type>",
		Short: "Bulk-promote every captured pattern for a type",
		Long: `Insert an allow-list rule for every distinct pattern observed for the
given type. Already-existing rules are skipped (duplicate-key on
upstream_policies). Use this after a learn-mode window to bootstrap the
allow-list from real client traffic.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			regType := args[0]
			if err := policy.ValidateType(regType); err != nil {
				return err
			}

			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("could not open audit database")
			}
			defer adb.Close()

			ctx := context.Background()
			rows, err := adb.AggregateDiscovery(ctx, regType)
			if err != nil {
				return fmt.Errorf("aggregate discovery: %w", err)
			}
			if len(rows) == 0 {
				fmt.Printf("No observations for %s.\n", regType)
				return nil
			}

			cfg, err := loadConfig(gf)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			if err := ensureMutable(cfg); err != nil {
				return err
			}

			added, skipped := 0, 0
			for _, a := range rows {
				err := insertPolicyRule(ctx, adb, regType, a.PatternHint, "promoted from discovery")
				switch {
				case err == nil:
					added++
					fmt.Printf("+ %s %s\n", regType, a.PatternHint)
				case strings.Contains(strings.ToLower(err.Error()), "unique"):
					skipped++
				default:
					return fmt.Errorf("insert %q: %w", a.PatternHint, err)
				}
			}
			fmt.Printf("\nPromoted %d, skipped %d (already present).\n", added, skipped)
			return nil
		},
	}
}

func newDiscoverClearCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "clear [type]",
		Short: "Delete discovery rows for a type, or all types when omitted",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			if err := ensureMutable(cfg); err != nil {
				return err
			}

			var regType string
			if len(args) > 0 {
				regType = args[0]
				if err := policy.ValidateType(regType); err != nil {
					return err
				}
			}

			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("could not open audit database")
			}
			defer adb.Close()

			n, err := adb.ClearDiscovery(context.Background(), regType)
			if err != nil {
				return fmt.Errorf("clear discovery: %w", err)
			}
			if regType == "" {
				fmt.Printf("Deleted %d discovery rows (all types).\n", n)
			} else {
				fmt.Printf("Deleted %d discovery rows for %s.\n", n, regType)
			}
			return nil
		},
	}
}

func newDiscoverExportCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "export <json|csv> [type]",
		Short: "Dump discovery rows to stdout in JSON or CSV",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			format := args[0]
			if format != "json" && format != "csv" {
				return fmt.Errorf("format must be \"json\" or \"csv\", got %q", format)
			}
			var regType string
			if len(args) > 1 {
				regType = args[1]
				if err := policy.ValidateType(regType); err != nil {
					return err
				}
			}

			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("could not open audit database")
			}
			defer adb.Close()

			rows, err := adb.ListDiscovery(context.Background(), audit.DiscoveryFilter{
				RegistryType: regType,
				Limit:        100000,
			})
			if err != nil {
				return fmt.Errorf("list discovery: %w", err)
			}

			if format == "json" {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(rows)
			}
			// CSV
			cw := csv.NewWriter(os.Stdout)
			defer cw.Flush()
			_ = cw.Write([]string{
				"registry_type", "host", "pattern_hint", "pkg_name", "pkg_version",
				"decision", "upstream_url", "first_seen", "last_seen", "last_client", "request_count",
			})
			for _, r := range rows {
				_ = cw.Write([]string{
					r.RegistryType, r.Host, r.PatternHint, r.PkgName, r.PkgVersion,
					r.Decision, r.UpstreamURL,
					r.FirstSeen.Format("2006-01-02T15:04:05Z07:00"),
					r.LastSeen.Format("2006-01-02T15:04:05Z07:00"),
					r.LastClient,
					fmt.Sprintf("%d", r.RequestCount),
				})
			}
			return nil
		},
	}
}

// promoteOne is the single-rule path shared by `discover promote` and
// (internally) by `discover promote-all`'s per-row loop. Keeping this in
// one place ensures both commands write rules identically to `policy add`.
func promoteOne(gf *globalFlags, regType, pattern, comment string) error {
	if err := policy.ValidateType(regType); err != nil {
		return err
	}

	cfg, err := loadConfig(gf)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err := ensureMutable(cfg); err != nil {
		return err
	}

	adb := openAuditDB(gf)
	if adb == nil {
		return fmt.Errorf("could not open audit database")
	}
	defer adb.Close()

	ctx := context.Background()
	if err := insertPolicyRule(ctx, adb, regType, pattern, comment); err != nil {
		return err
	}
	fmt.Printf("Promoted %s %q\n", regType, pattern)
	return nil
}

func insertPolicyRule(ctx context.Context, adb *audit.DB, regType, pattern, comment string) error {
	kind := policy.RuleKindForType(regType)
	if kind == "" {
		return fmt.Errorf("no rule kind registered for type %q", regType)
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return fmt.Errorf("generate id: %w", err)
	}
	id := hex.EncodeToString(idBytes)
	return adb.InsertPolicy(ctx, audit.PolicyInfo{
		ID:           id,
		RegistryType: regType,
		RuleKind:     kind,
		Pattern:      pattern,
		Comment:      comment,
		CreatedBy:    "discover",
	})
}
