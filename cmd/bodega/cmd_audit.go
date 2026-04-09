package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/scaleapi/bodega/internal/audit"
)

func newAuditEventsCmd(gf *globalFlags) *cobra.Command {
	var (
		eventType string
		pkgType   string
		pkgName   string
		clientIP  string
		since     string
		limit     int
	)

	cmd := &cobra.Command{
		Use:   "events",
		Short: "Query the audit event trail",
		Long: `audit queries the SQLite audit database and prints matching events.

Examples:
  bodega audit                                    # last 20 events
  bodega audit --type fetch --limit 50            # last 50 fetch events
  bodega audit --pkg-type gomod --name github.com/aws/aws-sdk-go-v2
  bodega audit --client 10.0.0.5 --since 2026-04-07`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}

			db, err := audit.Open(cfg.AuditDB)
			if err != nil {
				return fmt.Errorf("open audit db: %w", err)
			}
			defer db.Close()

			f := audit.Filter{
				EventType: audit.EventType(eventType),
				PkgType:   pkgType,
				PkgName:   pkgName,
				ClientIP:  clientIP,
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

			// Print table header.
			fmt.Printf("%-20s %-8s %-8s %-40s %-12s %-15s %s\n",
				"TIMESTAMP", "EVENT", "TYPE", "NAME", "STATUS", "CLIENT", "DURATION")
			fmt.Println("---")

			for _, ev := range events {
				dur := ""
				if ev.DurationMs > 0 {
					dur = fmt.Sprintf("%dms", ev.DurationMs)
				}
				fmt.Printf("%-20s %-8s %-8s %-40s %-12s %-15s %s\n",
					ev.Timestamp.Format("2006-01-02 15:04:05"),
					ev.EventType,
					ev.PkgType,
					truncate(ev.PkgName, 40),
					ev.Status,
					ev.ClientIP,
					dur,
				)
			}

			fmt.Printf("\n%d event(s)\n", len(events))
			return nil
		},
	}

	cmd.Flags().StringVar(&eventType, "type", "", "Event type filter (fetch, build, create, delete, cache)")
	cmd.Flags().StringVar(&pkgType, "pkg-type", "", "Package type filter (apt, git, pypi, binary, gomod, helm, npm)")
	cmd.Flags().StringVar(&pkgName, "name", "", "Package name filter")
	cmd.Flags().StringVar(&clientIP, "client", "", "Client IP filter")
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
