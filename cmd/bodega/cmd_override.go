package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
)

// newOverrideCmd is the two-person exception process: one identity requests
// an override for one check on one version, and it applies only once enough
// other identities approve it.
func newOverrideCmd(gf *globalFlags) *cobra.Command {
	parent := &cobra.Command{
		Use:   "override <request|approve|reject|list>",
		Short: "Request and approve time-limited, two-person overrides of a blocked admission",
		Long: `override admits one version past one check's failure, once identities other
than the requester approve it, until it expires.

  request <type> <name> <version> --check <check> --reason <text> --expires <duration>
  approve <id>
  reject  <id>
  list    [--pending|--active|--expired] [--json]

An override needs override_quorum (default 2) identities holding approve. The
requester counts toward it only when they held approve at request time: on the
CLI they always do, so the default is the requester plus one other identity,
while a write-only API token (a CI pipeline) needs two approvers. The requester
can never approve their own request, and one identity voting twice counts once.
An approval from a token the requester minted, or through an identity binding
the requester made, is recorded but does not count. A rejection cancels it for
good, an approved one included. Rejecting needs approve like approving does, so
a requester holding only write (CI) withdraws a request from the host's CLI or
through someone holding approve, not with its own token.

Scopes on the API: write requests, approve approves and rejects, and listing
needs admin or approve. Approval sits outside admin on purpose: whoever sets
policy does not also approve exceptions to it. Give superadmin, which mints
tokens, to someone other than the approvers: a holder of both can mint a
second voter for a request someone else made.

Once approved, the next admission of that version records the check as
"overridden" with the override's id in its admission row. It stops applying
at its expiry with nobody acting. For an allowlist, age, osv or
upstream_provenance override the next re-vet refuses the version again and
acts under revet_on_block. Re-vet does not run name_similarity or integration
checks, so an expired override of either stops applying at the next admission
of that version (an import, a build's fetch or a proxy fill), and a version
already admitted stays served. An override never applies to known malware (an OSV MAL- record or a
malware-list integration hit) or to upstream provenance that failed to verify,
and a request naming a check the version's newest admission recorded as one of
those is refused.

On the CLI the identity is the operator (SUDO_USER under sudo); on the API it
is the identity the request's token is bound to (bodega identity bind token).

Examples:
  bodega override request npm left-pad 1.3.0 --check allowlist \
    --reason "vendor fork pending, INC-4411" --expires 7d
  bodega override approve 3f9a1c0e5b7d2a64
  bodega override list --pending`,
	}
	parent.AddCommand(newOverrideRequestCmd(gf), newOverrideVoteCmd(gf, true), newOverrideVoteCmd(gf, false),
		newOverrideListCmd(gf))
	return parent
}

func newOverrideRequestCmd(gf *globalFlags) *cobra.Command {
	var req admit.OverrideRequest
	var asJSON bool
	c := &cobra.Command{
		Use:   "request <type> <name> <version> --check <check> --reason <text> --expires <duration>",
		Short: "Request an override for one check on one version",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			req.Type, req.Name, req.Version = args[0], args[1], args[2]
			cfg, adb, err := openACLStore(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			o, err := admit.RequestOverride(backgroundCtx(), adb, cfg, req, audit.LocalOverrideCaller(audit.CurrentActor()), time.Now())
			if err != nil {
				return err
			}
			if asJSON {
				return printJSON(o)
			}
			fmt.Printf("Requested override %s: %s/%s@%s past %s, expires %s.\n",
				o.ID, o.PkgType, o.PkgName, o.PkgVersion, o.Check, o.ExpiresAt.Format(time.RFC3339))
			fmt.Printf("It needs %d more approval(s) from identities other than %s (%s):\n  bodega override approve %s\n",
				o.ApprovalsNeeded, o.RequestedBy, requesterCounted(o), o.ID)
			return nil
		},
	}
	c.Flags().StringVar(&req.Check, "check", "", "the check to admit past: "+strings.Join(admit.OverrideChecks(), ", ")+", or integration:<instance>")
	c.Flags().StringVar(&req.Reason, "reason", "", "why, for the approvers and the audit trail")
	c.Flags().StringVar(&req.Expires, "expires", "", "how long it applies, counted from the request rather than the approval, e.g. 7d or 72h; at most override_max_ttl")
	c.Flags().BoolVar(&asJSON, "json", false, "print the override as JSON")
	for _, f := range []string{"check", "reason", "expires"} {
		_ = c.MarkFlagRequired(f)
	}
	return c
}

func newOverrideVoteCmd(gf *globalFlags, approve bool) *cobra.Command {
	var comment string
	var asJSON bool
	use, short := "approve <id>", "Approve an override someone else requested"
	if !approve {
		use, short = "reject <id>", "Reject an override, cancelling it"
	}
	c := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, adb, err := openACLStore(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			voter := audit.LocalOverrideCaller(audit.CurrentActor())
			o, err := admit.VoteOverride(backgroundCtx(), adb, args[0], voter, approve, comment, time.Now())
			if err != nil {
				return overrideVoteError(args[0], err)
			}
			if asJSON {
				return printJSON(o)
			}
			if v, ok := admit.VoteBy(o, voter.Identity); ok && !v.Counted {
				fmt.Printf("Your approval is recorded but does not count: %s.\n", v.NotCounted)
			}
			switch o.Status {
			case audit.OverrideStatusActive:
				fmt.Printf("Override %s is approved by %s and applies until %s.\n",
					o.ID, strings.Join(o.Approvers(), ", "), o.ExpiresAt.Format(time.RFC3339))
			case audit.OverrideStatusRejected:
				fmt.Printf("Override %s is rejected and will never apply.\n", o.ID)
			default:
				fmt.Printf("Override %s has %d of %d approvals and needs %d more before it applies.\n",
					o.ID, len(o.Approvers()), o.Quorum, o.ApprovalsNeeded)
			}
			return nil
		},
	}
	c.Flags().StringVar(&comment, "comment", "", "a note recorded with the vote")
	c.Flags().BoolVar(&asJSON, "json", false, "print the override as JSON")
	return c
}

// requesterCounted says whether o's requester counts toward its quorum.
func requesterCounted(o audit.Override) string {
	if o.RequesterCounts {
		return "counted"
	}
	return "not counted"
}

// overrideVoteError says what to do next about a refused vote.
func overrideVoteError(id string, err error) error {
	switch {
	case errors.Is(err, audit.ErrOverrideNotFound):
		return fmt.Errorf("no override %s: bodega override list shows the ids", id)
	case errors.Is(err, audit.ErrSelfApproval):
		return fmt.Errorf("%w: %s needs approval from a different identity", err, id)
	}
	return err
}

func newOverrideListCmd(gf *globalFlags) *cobra.Command {
	var pending, active, expired, asJSON bool
	c := &cobra.Command{
		Use:   "list [--pending|--active|--expired]",
		Short: "List overrides, newest request first",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			want := ""
			for flag, status := range map[*bool]string{&pending: audit.OverrideStatusPending,
				&active: audit.OverrideStatusActive, &expired: audit.OverrideStatusExpired} {
				if *flag {
					want = status
				}
			}
			adb := openAuditDB(gf)
			if adb == nil {
				return errors.New("could not open the audit database, which is where overrides live.\n" +
					"  Check audit_db (or log_dir) in config.json, then: bodega status")
			}
			defer adb.Close()
			list, err := admit.ListOverrides(backgroundCtx(), adb, want, time.Now())
			if err != nil {
				return err
			}
			if asJSON {
				return printJSON(list)
			}
			if len(list) == 0 {
				fmt.Println("No overrides.")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tSTATUS\tPACKAGE\tCHECK\tAPPROVALS\tREQUESTED BY\tEXPIRES\tREASON")
			for _, o := range list {
				fmt.Fprintf(tw, "%s\t%s\t%s/%s@%s\t%s\t%d/%d\t%s\t%s\t%s\n", o.ID, o.Status,
					o.PkgType, o.PkgName, o.PkgVersion, o.Check, len(o.Approvers()), o.Quorum,
					o.RequestedBy+" ("+requesterCounted(o)+")", o.ExpiresAt.Format(time.RFC3339), o.Reason)
			}
			return tw.Flush()
		},
	}
	c.Flags().BoolVar(&pending, "pending", false, "only requests still waiting for approval")
	c.Flags().BoolVar(&active, "active", false, "only approved overrides that apply now")
	c.Flags().BoolVar(&expired, "expired", false, "only overrides past their expiry")
	c.Flags().BoolVar(&asJSON, "json", false, "print as JSON")
	c.MarkFlagsMutuallyExclusive("pending", "active", "expired")
	return c
}
