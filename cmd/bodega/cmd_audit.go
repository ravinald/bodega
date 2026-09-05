package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
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
	)

	cmd := &cobra.Command{
		Use:   "events",
		Short: "Query the audit event trail",
		Long: `audit queries the configured audit sink and prints matching events.
Under audit_sink "syslog" or "jsonl" it refuses: those sinks ship events out
and keep nothing to read back.

Examples:
  bodega audit                                    # last 20 events
  bodega audit --type fetch --limit 50            # last 50 fetch events
  bodega audit --pkg-type gomod --name github.com/aws/aws-sdk-go-v2
  bodega audit --client 10.0.0.5 --since 2026-04-07
  bodega audit --type denied --limit 50            # requests the server refused

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

			// Print table header. CLIENT is the HTTP client IP; ACTOR is the
			// CLI/TUI user. They're mutually exclusive per event in practice.
			fmt.Printf("%-20s %-12s %-8s %-40s %-20s %-15s %-12s %s\n",
				"TIMESTAMP", "EVENT", "TYPE", "NAME", "STATUS", "CLIENT", "ACTOR", "DURATION")
			fmt.Println("---")

			for _, ev := range events {
				dur := ""
				if ev.DurationMs > 0 {
					dur = fmt.Sprintf("%dms", ev.DurationMs)
				}
				fmt.Printf("%-20s %-12s %-8s %-40s %-20s %-15s %-12s %s\n",
					ev.Timestamp.Format("2006-01-02 15:04:05"),
					ev.EventType,
					ev.PkgType,
					truncate(ev.PkgName, 40),
					ev.Status,
					ev.ClientIP,
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
	cmd.Flags().StringVar(&since, "since", "", "Show events after this time (RFC3339 or YYYY-MM-DD)")
	cmd.Flags().IntVar(&limit, "limit", 20, "Maximum number of events to show")

	return cmd
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
