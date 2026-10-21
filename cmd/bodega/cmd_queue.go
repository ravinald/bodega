package main

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// newQueueCmd is the review queue: every client request bodega refused, one
// row per (type, package, version, check), each resolved in one step.
func newQueueCmd(gf *globalFlags) *cobra.Command {
	parent := &cobra.Command{
		Use:   "queue <list|approve|dismiss>",
		Short: "Review what clients asked for and bodega refused, and admit or dismiss it",
		Long: `queue holds one row for every (type, package, version, check) a client was
refused, with the identities and addresses that asked. A row is written whatever
discover_mode says, for the allow-list, age, osv, malware, profile,
upstream_provenance and name_similarity checks and for each integration
(integration:<instance>).

  list    [--type <type>] [--check <check>] [--all] [--json]
  approve <id> --reason <text> [--expires <duration>]
  dismiss <id> --reason <text>

approve does what the row's check calls for:

  allow-list   adds an allow-list rule: the exact name for npm, pypi, cargo
               and gomod, the suggested host or URL prefix for the others
  profile      pins the version in every profile that refused it, as
               'bodega profile pin' does, with the reason on the entry
  other checks requests a two-person override for the version (bodega
               override), which applies once override_quorum identities
               approve it; --expires defaults to override_max_ttl

A row refused as known malware (an OSV MAL- record or a malware-list
integration hit), or for upstream provenance that failed to verify, is never
approved: dismiss it. A row that is refused again after it
was approved or dismissed reopens.

Examples:
  bodega queue list --check age
  bodega queue approve 12 --reason "INC-4411: vendor needs 1.3.0 today"
  bodega queue dismiss 14 --reason "typo of lodash"`,
	}
	parent.AddCommand(newQueueListCmd(gf), newQueueApproveCmd(gf), newQueueDismissCmd(gf))
	return parent
}

func newQueueListCmd(gf *globalFlags) *cobra.Command {
	var f audit.QueueFilter
	var all, asJSON bool
	c := &cobra.Command{
		Use:   "list [--type <type>] [--check <check>] [--all] [--json]",
		Short: "List open queue rows, most recently refused first",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.PkgType != "" {
				if err := requirePackageType(f.PkgType); err != nil {
					return err
				}
			}
			if f.Check != "" && !slices.Contains(admit.QueueChecks(), f.Check) {
				return fmt.Errorf("unknown check %q (want one of %s)", f.Check, strings.Join(admit.QueueChecks(), ", "))
			}
			if !all {
				f.State = audit.QueueOpen
			}
			adb := openAuditDB(gf)
			if adb == nil {
				return errors.New("could not open the audit database, which is where the queue lives.\n" +
					"  Check audit_db (or log_dir) in config.json, then: bodega status")
			}
			defer adb.Close()
			rows, err := adb.ListQueue(backgroundCtx(), f)
			if err != nil {
				return err
			}
			if asJSON {
				return printJSON(rows)
			}
			if len(rows) == 0 {
				fmt.Println("Nothing in the queue.")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tSTATE\tPACKAGE\tCHECK\tREQUESTS\tLAST SEEN\tASKED BY")
			for _, q := range rows {
				fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%d\t%s\t%s\n", q.ID, queueState(q), queueSubject(q), q.Check,
					q.RequestCount, q.LastSeen.Format(time.RFC3339), queueAskers(q.Requesters))
			}
			return tw.Flush()
		},
	}
	c.Flags().StringVar(&f.PkgType, "type", "", "only rows for this package type: "+strings.Join(manifest.AllTypes, ", "))
	c.Flags().StringVar(&f.Check, "check", "", "only rows refused by this check: "+strings.Join(admit.QueueChecks(), ", "))
	c.Flags().BoolVar(&all, "all", false, "include approved and dismissed rows")
	c.Flags().BoolVar(&asJSON, "json", false, "print as JSON")
	return c
}

func newQueueApproveCmd(gf *globalFlags) *cobra.Command {
	var a admit.QueueApproval
	var asJSON bool
	c := &cobra.Command{
		Use:   "approve <id> --reason <text> [--expires <duration>]",
		Short: "Admit what one queue row refused, by the action its check calls for",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseQueueID(args[0])
			if err != nil {
				return err
			}
			cfg, adb, err := openACLStore(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			res, err := admit.ApproveQueued(backgroundCtx(), adb, cfg, id, audit.CurrentActor(), a, time.Now())
			if err != nil {
				return queueError(id, err)
			}
			if asJSON {
				return printJSON(res)
			}
			q := res.Row
			switch {
			case res.Rule != nil:
				fmt.Printf("Approved %d: added allow-list rule %s %s %q (id=%s).\n",
					q.ID, res.Rule.RegistryType, res.Rule.RuleKind, res.Rule.Pattern, res.Rule.ID)
				fmt.Println("A running server applies it within 30s.")
			case len(res.Profiles) > 0:
				fmt.Printf("Approved %d: pinned %s in profile %s.\n", q.ID, queueSubject(q), strings.Join(res.Profiles, ", "))
			case res.Override != nil:
				o := res.Override
				if o.Status == audit.OverrideStatusActive {
					fmt.Printf("Approved %d: override %s already applies to %s until %s.\n",
						q.ID, o.ID, queueSubject(q), o.ExpiresAt.Format(time.RFC3339))
					break
				}
				fmt.Printf("Approved %d: requested override %s for %s past %s, expiring %s.\n",
					q.ID, o.ID, queueSubject(q), o.Check, o.ExpiresAt.Format(time.RFC3339))
				fmt.Printf("It applies once %d more identit(ies) other than %s approve it:\n  bodega override approve %s\n",
					o.ApprovalsNeeded, o.RequestedBy, o.ID)
			}
			if res.Warning != "" {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning: "+res.Warning)
			}
			return nil
		},
	}
	c.Flags().StringVar(&a.Reason, "reason", "", "why, for the audit trail (required)")
	c.Flags().StringVar(&a.Expires, "expires", "", "how long the override this requests applies, counted from the request rather than its approval, e.g. 7d; defaults to override_max_ttl")
	c.Flags().StringVar(&a.ConfirmNearPopular, "confirm-near-popular", "",
		"the popular package an allow-list row's exact name sits near, repeated to approve the rule anyway")
	c.Flags().BoolVar(&asJSON, "json", false, "print the resolution as JSON")
	_ = c.MarkFlagRequired("reason")
	return c
}

func newQueueDismissCmd(gf *globalFlags) *cobra.Command {
	var reason string
	var asJSON bool
	c := &cobra.Command{
		Use:   "dismiss <id> --reason <text>",
		Short: "Close one queue row without admitting anything",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseQueueID(args[0])
			if err != nil {
				return err
			}
			_, adb, err := openACLStore(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			q, err := admit.DismissQueued(backgroundCtx(), adb, id, audit.CurrentActor(), reason, time.Now())
			if err != nil {
				return queueError(id, err)
			}
			if asJSON {
				return printJSON(q)
			}
			fmt.Printf("Dismissed %d: %s stays refused by %s. It reopens if it is refused again.\n", q.ID, queueSubject(q), q.Check)
			return nil
		},
	}
	c.Flags().StringVar(&reason, "reason", "", "why, for the audit trail (required)")
	c.Flags().BoolVar(&asJSON, "json", false, "print the row as JSON")
	_ = c.MarkFlagRequired("reason")
	return c
}

func parseQueueID(s string) (int64, error) {
	id, err := strconv.ParseInt(s, 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("queue id %q is not a row number: bodega queue list shows the ids", s)
	}
	return id, nil
}

// queueError says what to do next about a refused resolution.
func queueError(id int64, err error) error {
	if errors.Is(err, audit.ErrQueueRowNotFound) {
		return fmt.Errorf("no queue row %d: bodega queue list shows the ids", id)
	}
	return err
}

func queueSubject(q audit.QueueRow) string {
	s := q.PkgType + "/" + q.PkgName
	if q.PkgVersion != "" {
		s += "@" + q.PkgVersion
	}
	return s
}

// queueState marks a row that reopened, so a resolution that did not take
// is visible in the listing rather than only in the audit trail.
func queueState(q audit.QueueRow) string {
	if q.State == audit.QueueOpen && q.Resolution != "" {
		return "open (was: " + q.Resolution + ")"
	}
	return q.State
}

func queueAskers(rs []audit.QueueRequester) string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		who := r.ClientIP
		if r.Identity != "" {
			who = r.Identity + "@" + r.ClientIP
		}
		out = append(out, who)
	}
	if len(out) > 3 {
		return strings.Join(out[:3], ", ") + fmt.Sprintf(" +%d", len(out)-3)
	}
	return strings.Join(out, ", ")
}
