package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

func newAuditEventsCmd(gf *globalFlags) *cobra.Command {
	var (
		eventType string
		pkgType   string
		pkgName   string
		clientIP  string
		actor     string
		since     string
		limit     int
		identity  string
	)

	cmd := &cobra.Command{
		Use:   "events",
		Short: "Query the audit event trail",
		Long: `audit queries the configured audit sink and prints matching events.
Under audit_sink "syslog" or "jsonl" it refuses: those sinks ship events out
and keep nothing to read back.

Examples:
  bodega audit events                                    # last 20 events
  bodega audit events --type fetch --limit 50            # last 50 fetch events
  bodega audit events --pkg-type gomod --name example.com/example-corp/widget-sdk
  bodega audit events --client 10.0.0.5 --since 2026-04-07
  bodega audit events --identity build-07                # every request an identity binding attributed
  bodega audit events --type denied --limit 50           # requests the server refused

A "denied" event carries the gate that refused it in the STATUS column:
deny_list, client_ip_unparsable, ip_not_permitted, no_tokens_configured,
token_missing, token_invalid, token_expired, admin_only.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := openQueryableAuditDB(gf, "the audit events `audit events` queries")
			if err != nil {
				return err
			}
			defer db.Close()

			f := audit.Filter{
				EventType: audit.EventType(eventType),
				PkgType:   pkgType,
				PkgName:   pkgName,
				ClientIP:  clientIP,
				Actor:     actor,
				Identity:  identity,
				Limit:     limit,
			}

			if since != "" {
				t, err := time.Parse(time.RFC3339, since)
				if err != nil {
					// Try date-only format.
					t, err = time.Parse("2006-01-02", since)
					if err != nil {
						return fmt.Errorf("invalid --since format (use RFC3339 or YYYY-MM-DD): %w", err)
					}
				}
				f.Since = t
			}

			ctx := backgroundCtx()
			events, err := db.Query(ctx, f)
			if err != nil {
				return fmt.Errorf("query audit db: %w", err)
			}

			if len(events) == 0 {
				fmt.Println("No matching events.")
				return nil
			}

			// Print table header. CLIENT is the HTTP client IP; IDENTITY is
			// what an identity binding resolved that request to, blank when
			// nothing bound it; ACTOR is the CLI/TUI user. CLIENT and IDENTITY
			// are printed together on purpose — the deny list matched on the
			// address, and one identity holds several.
			fmt.Printf("%-20s %-12s %-8s %-40s %-20s %-15s %-14s %-12s %s\n",
				"TIMESTAMP", "EVENT", "TYPE", "NAME", "STATUS", "CLIENT", "IDENTITY", "ACTOR", "DURATION")
			fmt.Println("---")

			for _, ev := range events {
				dur := ""
				if ev.DurationMs > 0 {
					dur = fmt.Sprintf("%dms", ev.DurationMs)
				}
				fmt.Printf("%-20s %-12s %-8s %-40s %-20s %-15s %-14s %-12s %s\n",
					ev.Timestamp.Format("2006-01-02 15:04:05"),
					ev.EventType,
					ev.PkgType,
					truncate(ev.PkgName, 40),
					ev.Status,
					ev.ClientIP,
					ev.Identity,
					ev.Actor,
					dur,
				)
			}

			fmt.Printf("\n%d event(s)\n", len(events))
			return nil
		},
	}

	cmd.Flags().StringVar(&eventType, "type", "", "Event type filter (serve_fetch, denied, build, create, delete, cache, serve_start, serve_stop, ...)")
	cmd.Flags().StringVar(&pkgType, "pkg-type", "", "Package type filter (apt, git, pypi, binary, gomod, helm, npm)")
	cmd.Flags().StringVar(&pkgName, "name", "", "Package name filter")
	cmd.Flags().StringVar(&clientIP, "client", "", "Client IP filter (HTTP events)")
	cmd.Flags().StringVar(&actor, "actor", "", "Actor filter (CLI/TUI events — matches the OS user)")
	cmd.Flags().StringVar(&identity, "identity", "", "Identity filter (HTTP events — matches a bound host name)")
	cmd.Flags().StringVar(&since, "since", "", "Show events after this time (RFC3339 or YYYY-MM-DD)")
	cmd.Flags().IntVar(&limit, "limit", 20, "Maximum number of events to show")

	return cmd
}

func newAuditAdmissionsCmd(gf *globalFlags) *cobra.Command {
	var (
		asJSON bool
		limit  int
	)
	cmd := &cobra.Command{
		Use:   "admissions <type> <name> [version]",
		Short: "Show the admission decisions recorded for a package",
		Long: `admissions prints every admission decision recorded for a package, newest
first: the verdict, each check's result, the digest of the policy it was
decided under, and the object key once the artifact's digest was pinned.

A decision is written by pkg import, pkg edit, pkg create, POST
/api/v1/packages, POST /api/v1/packages/import, a build's fetch and a proxy
fill. A row whose checks all say not_evaluated was written by a digest pin
that found no decision for its version: those bytes reached the store with
nothing evaluated, and the row says so rather than recording a pass.

Under audit_sink "syslog" or "jsonl" it refuses: those sinks ship decisions
out as "admission" and "admission_pin" records and keep nothing to read back.

Examples:
  bodega audit admissions npm lodash
  bodega audit admissions npm lodash 4.17.21
  bodega audit admissions gomod example.com/example-corp/widget-sdk v1.30.0 --json`,
		Args: cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !isValidType(args[0]) {
				return fmt.Errorf("unknown type %q — must be one of: %s", args[0], strings.Join(manifest.AllTypes, ", "))
			}
			db, err := openQueryableAuditDB(gf, "the admission decisions `audit admissions` queries")
			if err != nil {
				return err
			}
			defer db.Close()

			f := audit.AdmissionFilter{PkgType: args[0], PkgName: args[1], Limit: limit}
			if len(args) == 3 {
				f.PkgVersion = args[2]
			}
			rows, err := db.Admissions(backgroundCtx(), f)
			if err != nil {
				return fmt.Errorf("query admissions: %w", err)
			}
			if asJSON {
				if rows == nil {
					rows = []audit.Admission{}
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(rows)
			}
			if len(rows) == 0 {
				fmt.Println("No admission decisions recorded.")
				return nil
			}
			printAdmissions(rows)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit the rows as a JSON array, with every check's detail")
	cmd.Flags().IntVar(&limit, "limit", 50, "Maximum number of decisions to show")
	return cmd
}

func newAuditServedCmd(gf *globalFlags) *cobra.Command {
	var (
		identity string
		since    string
		asJSON   bool
	)
	cmd := &cobra.Command{
		Use:   "served",
		Short: "List the distinct artifacts served to one identity",
		Long: `served prints each distinct (type, name, version, digest) bodega served to
one identity, read from its serve_fetch rows. Two builds of one version are
two lines, told apart by the digest.

Only rows naming the stored object they served count: a metadata response
(an index, a packument, InRelease) hands over no artifact, and a row written
before bodega recorded object keys cannot say which bytes it was. DIGEST is
empty where bodega holds no sha256 for the object.

Under audit_sink "syslog" or "jsonl" it refuses: those sinks keep nothing to
read back.

Examples:
  bodega audit served --identity build-07
  bodega audit served --identity build-07 --since 7d
  bodega audit served --identity build-07 --since 24h --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if identity == "" {
				return fmt.Errorf("--identity is required: the served set is per host (see 'bodega identity list')")
			}
			var from time.Time
			if since != "" {
				d, err := parseAgeDuration(since)
				if err != nil || d <= 0 {
					return fmt.Errorf("invalid --since %q (want a duration like 24h or 7d)", since)
				}
				from = time.Now().Add(-d)
			}
			db, err := openQueryableAuditDB(gf, "the serve_fetch rows `audit served` reads")
			if err != nil {
				return err
			}
			defer db.Close()

			rows, err := db.Served(backgroundCtx(), identity, from)
			if err != nil {
				return fmt.Errorf("query served artifacts: %w", err)
			}
			if asJSON {
				if rows == nil {
					rows = []audit.ServedArtifact{}
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(rows)
			}
			if len(rows) == 0 {
				fmt.Printf("No artifacts served to %s.\n", identity)
				return nil
			}
			fmt.Printf("%-8s %-40s %-24s %s\n", "TYPE", "NAME", "VERSION", "DIGEST")
			fmt.Println("---")
			for _, a := range rows {
				fmt.Printf("%-8s %-40s %-24s %s\n", a.PkgType, truncate(a.PkgName, 40), truncate(a.PkgVersion, 24), a.Digest)
			}
			fmt.Printf("\n%d artifact(s)\n", len(rows))
			return nil
		},
	}
	cmd.Flags().StringVar(&identity, "identity", "", "Identity whose served set to list (required)")
	cmd.Flags().StringVar(&since, "since", "", "Only rows newer than this duration ago (e.g. 24h, 7d); default all time")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit the rows as a JSON array")
	return cmd
}

// printAdmissions renders one line per decision, then the detail of every
// check that did not pass beneath it: the verdict an operator is looking for
// is usually the one exception, and a column cannot hold its reason.
func printAdmissions(rows []audit.Admission) {
	fmt.Printf("%-20s %-16s %-15s %-44s %-22s %-14s %s\n",
		"DECIDED", "VERSION", "DECISION", "CHECKS", "POLICY", "BY", "OBJECT KEY")
	fmt.Println("---")
	for _, a := range rows {
		var checks []string
		for _, c := range a.Checks {
			checks = append(checks, c.Check+"="+c.Status)
		}
		by := a.Actor
		if by == "" {
			by = a.Identity
		}
		policyDigest := a.PolicyDigest
		if policyDigest == "" {
			policyDigest = "(none)"
		}
		key := a.ObjectKey
		if key == "" {
			key = "(not pinned)"
		}
		fmt.Printf("%-20s %-16s %-15s %-44s %-22s %-14s %s\n",
			a.DecidedAt.Format("2006-01-02 15:04:05"),
			truncate(a.PkgVersion, 16),
			a.Decision,
			strings.Join(checks, " "),
			truncate(policyDigest, 22),
			truncate(by, 14),
			key,
		)
		for _, c := range a.Checks {
			if c.Status == audit.CheckPass || c.Detail == "" {
				continue
			}
			fmt.Printf("    %s (%s, action %s): %s\n", c.Check, c.Status, c.Action, c.Detail)
		}
	}
	fmt.Printf("\n%d decision(s)\n", len(rows))
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
