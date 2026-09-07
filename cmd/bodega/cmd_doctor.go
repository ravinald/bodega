package main

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/host"
	"github.com/ravinald/bodega/internal/policy"
)

// newDoctorCmd reports host-level configuration that would silently bypass
// bodega's supply-chain controls, and the server's own policy posture where
// this machine holds an install. The checks are read-only: doctor changes
// nothing it inspects and never creates the audit database it reports on.
// What a doctor run can leave behind is not a check's doing — main() writes a
// default config file, and the log directory it names, before any command runs.
// Exit code is 0 when all checks are clean (OK or N/A) and 2 when at least
// one check produced a finding (WARN or FAIL); this matches the convention
// used by other CI-gating linters.
//
// The threat model and rationale for each check is documented in
// docs/THREAT_MODEL.md.
func newDoctorCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Inspect the local host and this install's policy posture for gaps in bodega's controls",
		Long: `doctor scans the machine running this command for distribution channels
and package-manager configurations that would silently fetch software from
outside bodega's allow-list. Common findings:

  - snapd or flatpak installed (opaque, auto-refreshing bundles)
  - Homebrew with auto-update enabled
  - pip / cargo / npm / apt configured to talk to public registries directly
  - GOPROXY unset or falling through to proxy.golang.org

Where this machine holds a bodega install, doctor also reports the server's
own posture: an install with no allow-list rule and no publish-age or OSV
gate admits every upstream fetch, and one whose gates are all set to ignore
is configured but enforcing nothing. Those checks read the audit database
and report N/A on a client host that has none.

Reports only: the posture checks open the audit database read-only, so a
doctor run neither creates one nor migrates the one it finds. One caveat for
a CI runner. Every bodega command bootstraps a config file on first run,
doctor included, so a host with neither /etc/bodega/config.json nor
~/.config/bodega/config.json gains the second one (the first, as root), and
the log directory that config names, before the checks execute.

Exit code is 0 when clean and 2 when one or more findings are present, so
this command can gate CI pipelines for build hosts that are supposed to
route everything through bodega.

See docs/THREAT_MODEL.md for the rationale behind each check.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			findings := make([]host.Finding, 0, len(host.AllChecks())+len(postureChecks))
			for _, fn := range host.AllChecks() {
				findings = append(findings, fn())
			}
			findings = append(findings, serverPostureFindings(backgroundCtx(), gf)...)

			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "CHECK\tSTATUS\tDETAIL")
			actionable := 0
			for _, f := range findings {
				fmt.Fprintf(w, "%s\t%s\t%s\n", f.Check, f.Status, f.Detail)
				if f.IsFinding() {
					actionable++
				}
			}
			_ = w.Flush()

			if actionable > 0 {
				fmt.Println()
				fmt.Println("Remediation:")
				for _, f := range findings {
					if !f.IsFinding() || f.Remediation == "" {
						continue
					}
					fmt.Printf("  [%s] %s\n", f.Check, f.Remediation)
				}
				fmt.Printf("\n%d finding(s) — host is not fully aligned with bodega's threat model.\n", actionable)
				fmt.Println("See docs/THREAT_MODEL.md for context.")
				os.Exit(2) //nolint:revive // CI-gating exit code distinct from cobra's 1
			}

			fmt.Println()
			fmt.Println("OK: host configuration aligns with bodega's threat model.")
			return nil
		},
	}
}

// postureChecks names the server-posture rows in the order doctor prints them.
// The set is fixed so the table has the same shape on a host with an install
// and one without, which is what lets a pipeline diff the output.
var postureChecks = []string{"policy-coverage", "policy-ignored", "policy-ecosystem"}

// postureStore is the read surface the posture checks need. An interface so
// they can be driven against a store built by hand, without a config file or
// a serving instance in the way.
type postureStore interface {
	ListPolicies(ctx context.Context) ([]audit.PolicyInfo, error)
	ListAgePolicies(ctx context.Context) ([]audit.AgePolicy, error)
	ListOSVPolicies(ctx context.Context) ([]audit.OSVPolicy, error)
}

// serverPostureFindings resolves this machine's install and reports on it,
// or marks every posture check N/A with the reason there is nothing to read.
func serverPostureFindings(ctx context.Context, gf *globalFlags) []host.Finding {
	cfg, err := loadConfig(gf)
	if err != nil {
		return postureUnavailable("config unreadable: " + err.Error())
	}
	path := auditDBPath(cfg)
	if path == "" {
		return postureUnavailable("no audit database configured (audit_db and log_dir are both empty)")
	}
	// Stat before open: opening creates the file and seeds a fresh install's
	// default policy, and a report is not an installation.
	if _, err := os.Stat(path); err != nil {
		return postureUnavailable("no bodega install on this host (" + path + " does not exist)")
	}
	// Read-only for the same reason. The read-write opener migrates whatever
	// it finds, so a doctor run against an install that predates migration 012
	// would claim the seed marker on an operator who only asked what their
	// posture was.
	db, err := audit.OpenReadOnly(path)
	if err != nil {
		return postureUnavailable("could not read audit store at " + path + ": " + err.Error())
	}
	defer db.Close()
	return serverPosture(ctx, db)
}

func postureUnavailable(detail string) []host.Finding {
	out := make([]host.Finding, 0, len(postureChecks))
	for _, name := range postureChecks {
		out = append(out, host.Finding{Check: name, Status: host.StatusNA, Detail: detail})
	}
	return out
}

// serverPosture reports what this install actually enforces. The three checks
// are the three ways an install ends up enforcing nothing: never configured,
// configured and then silenced, and configured against an ecosystem the gate
// cannot evaluate.
func serverPosture(ctx context.Context, store postureStore) []host.Finding {
	rules, err := store.ListPolicies(ctx)
	if err != nil {
		return postureUnavailable("read allow-list: " + err.Error())
	}
	ages, err := store.ListAgePolicies(ctx)
	if err != nil {
		return postureUnavailable("read age policy: " + err.Error())
	}
	osvs, err := store.ListOSVPolicies(ctx)
	if err != nil {
		return postureUnavailable("read osv policy: " + err.Error())
	}
	return []host.Finding{
		policyCoverage(rules, ages, osvs),
		policyIgnored(ages, osvs),
		policyEcosystem(ages, osvs),
	}
}

// gateRow is a policy table flattened to what the posture checks read. Both
// tables answer the same two questions and neither check should care which
// one it is looking at.
type gateRow struct{ ecosystem, action string }

func ageRows(ages []audit.AgePolicy) []gateRow {
	out := make([]gateRow, 0, len(ages))
	for _, p := range ages {
		out = append(out, gateRow{p.Ecosystem, p.Action})
	}
	return out
}

func osvRows(osvs []audit.OSVPolicy) []gateRow {
	out := make([]gateRow, 0, len(osvs))
	for _, p := range osvs {
		out = append(out, gateRow{p.Ecosystem, p.Action})
	}
	return out
}

// enforcing keeps the rows that can change an admission decision. A row for an
// ecosystem outside covered is read by nothing, and counting it as enforcement
// is how an install with one dead row masks the fact that every live gate is
// off. That row has its own check, policy-ecosystem.
func enforcing(rows []gateRow, covered []string) []gateRow {
	out := make([]gateRow, 0, len(rows))
	for _, r := range rows {
		if slices.Contains(covered, r.ecosystem) {
			out = append(out, r)
		}
	}
	return out
}

// policyCoverage is the zero-policy install: a caching proxy with an audit
// trail. Every upstream fetch is admitted, and nothing in the request path
// would have refused the compromised release the audit trail then records.
// It reads every gate admit.checkVersions runs, age and OSV both: an install
// carrying one of them refuses fetches, so reporting it as wide open is a
// false statement the operator can disprove from their own logs.
func policyCoverage(rules []audit.PolicyInfo, ages []audit.AgePolicy, osvs []audit.OSVPolicy) host.Finding {
	f := host.Finding{Check: "policy-coverage", Status: host.StatusOK}
	aged := enforcing(ageRows(ages), policy.AgeEcosystems())
	scanned := enforcing(osvRows(osvs), policy.OSVEcosystems())
	gates := slices.Concat(aged, scanned)
	if len(rules) > 0 || len(gates) > 0 {
		f.Detail = fmt.Sprintf("%d allow-list rule(s), %d ecosystem(s) with a publish-age gate, %d with an OSV gate",
			len(rules), len(aged), len(scanned))
		// This check asks whether anybody ever configured a policy; whether it
		// runs is policy-ignored's question. Counting a silenced row as a gate
		// is the right answer to the first question and a false statement on
		// its own, so the count that matters at 03:00 goes on the same line.
		if inForce := len(gates) - ignoredCount(gates); inForce < len(gates) {
			f.Detail += fmt.Sprintf(" (%d in force; see policy-ignored)", inForce)
		}
		return f
	}
	f.Status = host.StatusWarn
	f.Detail = "no allow-list rule and no publish-age or OSV gate: every upstream fetch is admitted"
	f.Remediation = "bodega policy add npm <package> to constrain what may be fetched; " +
		"bodega policy age set npm 7d warn for a publish-age cooldown"
	return f
}

func ignoredCount(rows []gateRow) int {
	n := 0
	for _, r := range rows {
		if r.action == policy.ActionIgnore {
			n++
		}
	}
	return n
}

// policyIgnored is the install that had a gate and lost it. Silencing one
// ecosystem during an incident is routine; leaving every ecosystem on ignore
// is a gate that reports as configured and has never run since.
func policyIgnored(ages []audit.AgePolicy, osvs []audit.OSVPolicy) host.Finding {
	f := host.Finding{Check: "policy-ignored", Status: host.StatusOK}
	var silenced, fixes []string
	if ecos := silencedEcosystems(ageRows(ages), policy.AgeEcosystems()); len(ecos) > 0 {
		silenced = append(silenced, "age ("+strings.Join(ecos, ", ")+")")
		fixes = append(fixes, "bodega policy age set "+ecos[0]+" 7d warn")
	}
	if ecos := silencedEcosystems(osvRows(osvs), policy.OSVEcosystems()); len(ecos) > 0 {
		silenced = append(silenced, "osv ("+strings.Join(ecos, ", ")+")")
		fixes = append(fixes, "bodega policy osv set "+ecos[0]+" warn")
	}
	if len(silenced) == 0 {
		f.Detail = "no gate is set to ignore on every ecosystem it covers"
		return f
	}
	f.Status = host.StatusWarn
	f.Detail = strings.Join(silenced, ", ") + " set to ignore on every ecosystem: configured, enforcing nothing"
	f.Remediation = "restore an action on the silenced gate: " + strings.Join(fixes, "; ")
	return f
}

// silencedEcosystems names the rows a gate can read when every one of them is
// on ignore, and nothing when any of them still enforces or when the gate has
// no readable row at all.
func silencedEcosystems(rows []gateRow, covered []string) []string {
	live := enforcing(rows, covered)
	ecos := make([]string, 0, len(live))
	for _, r := range live {
		if r.action != policy.ActionIgnore {
			return nil
		}
		ecos = append(ecos, r.ecosystem)
	}
	return ecos
}

// policyEcosystem is the row the gate cannot read. `policy set` refuses one
// now, but a row written before that refusal survives and both `policy list`
// and this install's own inventory report it as an active gate.
func policyEcosystem(ages []audit.AgePolicy, osvs []audit.OSVPolicy) host.Finding {
	f := host.Finding{Check: "policy-ecosystem", Status: host.StatusOK}
	var stale, fixes []string
	for _, p := range ages {
		if !slices.Contains(policy.AgeEcosystems(), p.Ecosystem) {
			stale = append(stale, "age "+p.Ecosystem)
			fixes = append(fixes, "bodega policy age remove "+p.Ecosystem)
		}
	}
	for _, p := range osvs {
		if !slices.Contains(policy.OSVEcosystems(), p.Ecosystem) {
			stale = append(stale, "osv "+p.Ecosystem)
			fixes = append(fixes, "bodega policy osv remove "+p.Ecosystem)
		}
	}
	if len(stale) == 0 {
		f.Detail = "every stored policy row names an ecosystem its gate can evaluate"
		return f
	}
	f.Status = host.StatusWarn
	f.Detail = "stored policy rows no gate can evaluate: " + strings.Join(stale, ", ") + "; listed as active, never enforced"
	f.Remediation = strings.Join(fixes, "; ")
	return f
}
