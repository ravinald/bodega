package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

func newPolicyCmd(gf *globalFlags) *cobra.Command {
	parent := &cobra.Command{
		Use:   "policy",
		Short: "Manage the upstream source allow-list",
		Long: `Declare which upstream sources bodega is allowed to fetch from.

Registry types map to rule kinds as follows:
  apt             host      — URL hostname (e.g. archive.ubuntu.com)
  git             org       — URL prefix after scheme (github.com/my-org/)
  pypi, npm       package   — exact package name (PyPI normalization applied)
  gomod, helm, binary  prefix   — full URL/path prefix

An empty allow-list means no enforcement — the feature is opt-in. Add at
least one rule for a registry type to switch enforcement on for that type.`,
	}
	parent.AddCommand(
		newPolicyListCmd(gf),
		newPolicyAddCmd(gf),
		newPolicyRemoveCmd(gf),
		newPolicyCheckCmd(gf),
		newPolicyAgeCmd(gf),
		newPolicyOSVCmd(gf),
	)
	return parent
}

func newPolicyListCmd(gf *globalFlags) *cobra.Command {
	var typeFlag string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List configured allow-list rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("could not open audit database")
			}
			defer adb.Close()

			ctx := context.Background()
			var rules []audit.PolicyInfo
			var err error
			if typeFlag != "" {
				if err := policy.ValidateType(typeFlag); err != nil {
					return err
				}
				rules, err = adb.GetPoliciesByType(ctx, typeFlag)
			} else {
				rules, err = adb.ListPolicies(ctx)
			}
			if err != nil {
				return fmt.Errorf("list policies: %w", err)
			}
			if len(rules) == 0 {
				fmt.Println("No allow-list rules configured.")
				fmt.Println("(Enforcement is disabled; all upstream sources are accepted.)")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "TYPE\tKIND\tPATTERN\tID\tADDED\tCOMMENT")
			for _, r := range rules {
				comment := r.Comment
				if len(comment) > 40 {
					comment = comment[:37] + "..."
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					r.RegistryType, r.RuleKind, r.Pattern, r.ID,
					r.CreatedAt.Format("2006-01-02"), comment)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&typeFlag, "type", "", "Filter to a single registry type")
	return cmd
}

func newPolicyAddCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "add <type> <pattern> [comment]",
		Short: "Add an upstream source to the allow-list",
		Long: `Add an allow-list rule for the given registry type.

Examples:
  bodega policy add apt archive.ubuntu.com
  bodega policy add git github.com/netbox-community/ "NetBox maintainers"
  bodega policy add pypi django
  bodega policy add npm @aws-sdk/*
  bodega policy add gomod github.com/aws/
  bodega policy add binary https://releases.hashicorp.com/`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			regType := args[0]
			pattern := args[1]
			comment := ""
			if len(args) > 2 {
				comment = strings.Join(args[2:], " ")
			}

			if err := policy.ValidateType(regType); err != nil {
				return err
			}
			kind := policy.RuleKindForType(regType)
			if kind == "" {
				return fmt.Errorf("no rule kind registered for type %q", regType)
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

			idBytes := make([]byte, 16)
			if _, err := rand.Read(idBytes); err != nil {
				return fmt.Errorf("generate id: %w", err)
			}
			id := hex.EncodeToString(idBytes)

			ctx := context.Background()
			rule := audit.PolicyInfo{
				ID:           id,
				RegistryType: regType,
				RuleKind:     kind,
				Pattern:      pattern,
				Comment:      comment,
				CreatedBy:    "cli",
			}
			if err := adb.InsertPolicy(ctx, rule); err != nil {
				return fmt.Errorf("insert policy: %w", err)
			}

			_ = adb.Record(ctx, audit.Event{
				EventType: audit.EventCreate,
				PkgType:   "policy",
				PkgName:   regType + ":" + pattern,
				Actor:     audit.CurrentActor(),
				Status:    "success",
				Details:   fmt.Sprintf("id=%s kind=%s", id, kind),
			})

			fmt.Printf("Added %s %s %q (id=%s)\n", regType, kind, pattern, id)
			return nil
		},
	}
}

func newPolicyRemoveCmd(gf *globalFlags) *cobra.Command {
	var typeFlag string
	cmd := &cobra.Command{
		Use:   "remove <id|pattern>",
		Short: "Remove an allow-list rule by ID or pattern",
		Long: `Remove an allow-list rule.

With a single positional argument, remove tries the ID first. If no row
matches, it falls back to deleting by pattern (scoped to --type when set).

Examples:
  bodega policy remove 5a3f...                     # by ID
  bodega policy remove django --type pypi          # by pattern, scoped
  bodega policy remove archive.ubuntu.com          # by pattern, any type`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]

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

			deleted, err := adb.DeletePolicyByID(ctx, target)
			if err != nil {
				return fmt.Errorf("remove by id: %w", err)
			}
			if !deleted {
				n, err := adb.DeletePolicyByPattern(ctx, typeFlag, target)
				if err != nil {
					return fmt.Errorf("remove by pattern: %w", err)
				}
				if n == 0 {
					return fmt.Errorf("no rule matched %q", target)
				}
				fmt.Printf("Removed %d rule(s) matching %q.\n", n, target)
			} else {
				fmt.Printf("Removed rule %s.\n", target)
			}

			_ = adb.Record(ctx, audit.Event{
				EventType: audit.EventDelete,
				PkgType:   "policy",
				PkgName:   target,
				Actor:     audit.CurrentActor(),
				Status:    "success",
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&typeFlag, "type", "", "Scope pattern deletion to a single registry type")
	return cmd
}

func newPolicyCheckCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Scan manifests for policy violations",
		Long: `Walk every manifest in the configured store and report entries whose
upstream URL or package name would be rejected by the current allow-list.

Exit code 1 if any violations are found — suitable for CI pipelines.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("could not open audit database")
			}
			defer adb.Close()

			checker := policy.NewChecker(adb)
			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}

			ctx := context.Background()
			var violations int
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)

			for _, t := range manifest.AllTypes {
				for _, name := range store.ListPackages(t) {
					pm, err := store.GetPackage(ctx, t, name)
					if err != nil {
						return fmt.Errorf("load %s/%s: %w", t, name, err)
					}
					for _, ve := range pm.Versions {
						candidate := policy.CandidateFor(t, pm.Name, ve.URL)
						if candidate == "" {
							continue
						}
						if err := checker.Check(ctx, t, candidate); err != nil {
							if violations == 0 {
								fmt.Fprintln(w, "TYPE\tPACKAGE\tVERSION\tREASON")
							}
							fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", t, pm.Name, ve.Version, err)
							violations++
						}
					}
				}
			}
			_ = w.Flush()

			if violations == 0 {
				fmt.Println("OK: no policy violations found.")
				return nil
			}
			return fmt.Errorf("%d policy violation(s) detected", violations)
		},
	}
}
