package main

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// requireEcosystem refuses a policy row for an ecosystem the named gate cannot
// evaluate. The two gates fail differently on an uncovered ecosystem, so the
// caller supplies what actually happens: OSV short-circuits to pass and the
// operator believes a gate is on that has never run, while age warns on every
// version. consequence names which.
func requireEcosystem(eco string, covered []string, gate, consequence string) error {
	if slices.Contains(covered, eco) {
		return nil
	}
	return fmt.Errorf("the %s does not cover ecosystem %q: %s; set one of %s instead",
		gate, eco, consequence, strings.Join(covered, ", "))
}

func newPolicyOSVCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "osv",
		Short: "OSV vulnerability gate per ecosystem",
		Long: `Match every imported (ecosystem, name, version) against the local
OSV database and flag or block based on the per-ecosystem policy. OSV
coverage maps npm, pypi, gomod, cargo and apt. Any other ecosystem has no
OSV identifier, so set refuses it rather than writing a row the gate never
reads.

apt is keyed on the release rather than on one identifier. Ubuntu and
Debian backport a security fix into the revision without moving the
upstream version, so the records that settle a version live in the export
for the suite that version is published to, and the query carries the full
version string and the source package name.

sync is the only subcommand that reaches the network. Admission answers
from the directory sync wrote (osv_db_dir), and queries api.osv.dev only
when osv_api_fallback is on and the local copy cannot answer.

Admission checks a version once, on the day it was imported. rescan is
what turns that into an answer about today.

  bodega policy osv sync
  bodega policy osv set npm block
  bodega policy osv set apt block
  bodega policy osv list
  bodega policy osv rescan --type npm
  bodega policy osv remove npm`,
	}
	cmd.AddCommand(newPolicyOSVSetCmd(gf), newPolicyOSVListCmd(gf),
		newPolicyOSVRemoveCmd(gf), newPolicyOSVSyncCmd(gf),
		// The policy subtree is quiet, and rescan is the one verb under it
		// that rewrites manifests. Without this the server keeps serving the
		// pre-rescan stamp for the life of the process, because
		// manifest.Store answers from its cache after the first read.
		signalsReload(newPolicyOSVRescanCmd(gf)))
	return cmd
}

func newPolicyOSVSetCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "set <ecosystem> <action>",
		Short: "Set the OSV policy action for an ecosystem",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			eco, action := args[0], strings.ToLower(args[1])
			if err := requireEcosystem(eco, policy.OSVEcosystems(), "OSV gate",
				"the row would be stored and never read, leaving the gate silently off"); err != nil {
				return err
			}
			if action != "warn" && action != "block" && action != "ignore" {
				return fmt.Errorf("action must be warn|block|ignore, got %q", action)
			}
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
			if err := ensureMutable(cfg); err != nil {
				return err
			}
			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("audit DB unavailable")
			}
			defer adb.Close()
			if err := adb.SetOSVPolicy(context.Background(), audit.OSVPolicy{
				Ecosystem: eco, Action: action,
			}); err != nil {
				return err
			}
			fmt.Printf("Set %s OSV policy: %s\n", eco, action)
			return nil
		},
	}
}

func newPolicyOSVListCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List OSV policies and the local database's per-ecosystem sync time",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
			db := policy.NewOSVDatabase(cfg.ResolveOSVDBDir())
			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("audit DB unavailable")
			}
			defer adb.Close()
			rows, err := adb.ListOSVPolicies(context.Background())
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				fmt.Printf("No OSV policies configured.\nLocal OSV database: %s (api.osv.dev fallback: %s)\n",
					db.Dir(), onOff(cfg.OSVAPIFallback))
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ECOSYSTEM\tACTION\tUPDATED\tDB SYNCED\tDB AGE")
			stored := make([]string, 0, len(rows))
			for _, p := range rows {
				synced, age := osvDBState(db, p.Ecosystem, cfg.ServedAptSuites())
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					p.Ecosystem, p.Action, p.UpdatedAt.Format("2006-01-02"), synced, age)
				stored = append(stored, p.Ecosystem)
			}
			if err := w.Flush(); err != nil {
				return err
			}
			fmt.Printf("\nLocal OSV database: %s (api.osv.dev fallback: %s)\n",
				db.Dir(), onOff(cfg.OSVAPIFallback))
			reportUncovered("OSV gate", stored, policy.OSVEcosystems(), "bodega policy osv remove")
			return nil
		},
	}
}

func newPolicyOSVRemoveCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <ecosystem>",
		Short: "Remove the OSV policy for an ecosystem",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
			if err := ensureMutable(cfg); err != nil {
				return err
			}
			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("audit DB unavailable")
			}
			defer adb.Close()
			deleted, err := adb.DeleteOSVPolicy(context.Background(), args[0])
			if err != nil {
				return err
			}
			if !deleted {
				return fmt.Errorf("no OSV policy for %q", args[0])
			}
			fmt.Printf("Removed OSV policy for %s\n", args[0])
			return nil
		},
	}
}

func newPolicyOSVSyncCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "sync [ecosystem...]",
		Short: "Fetch or refresh the local OSV database",
		Long: `Download OSV's per-ecosystem export into osv_db_dir, one archive
per ecosystem, and record when each was fetched. With no arguments every
covered ecosystem is synced.

apt expands to one index per apt suite the server serves, because OSV keys
Ubuntu and Debian advisories on the release. Those releases are distilled
out of one archive each: OSV stopped rebuilding its per-release archives in
October 2024 and keeps the aggregate current. A suite OSV publishes no
records for is named on stderr and fetched for nothing; entries published
to it warn at admission rather than reporting clean.

This is the only OSV subcommand that reaches the network. On an
air-gapped host, run it where the network is, copy the directory over,
and point osv_db_dir at the copy.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
			ecosystems := policy.OSVEcosystems()
			if len(args) > 0 {
				for _, eco := range args {
					if err := requireEcosystem(eco, policy.OSVEcosystems(), "OSV gate",
						"there is no export to fetch for it"); err != nil {
						return err
					}
				}
				ecosystems = args
			}
			db := policy.NewOSVDatabase(cfg.ResolveOSVDBDir())

			// apt is one export per served suite: OSV keys Ubuntu and
			// Debian advisories on the release, because the revision that
			// carries a backported fix is a fact about one release. Resolve
			// every ecosystem first, then hand the whole list over at once:
			// several releases come out of one archive, and a fetch per
			// release would download it once each.
			var osvEcos, skipped []string
			owner := map[string]string{}
			var failed []string
			for _, eco := range ecosystems {
				exports, unmapped := policy.OSVExportsFor(eco, cfg.ServedAptSuites())
				for _, suite := range unmapped {
					skipped = append(skipped, fmt.Sprintf("%s: OSV publishes no Ubuntu or Debian export for suite %q", eco, suite))
				}
				if len(exports) == 0 {
					failed = append(failed, fmt.Sprintf("%s: no OSV export to fetch", eco))
					continue
				}
				for _, osvEco := range exports {
					osvEcos = append(osvEcos, osvEco)
					owner[osvEco] = eco
				}
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ECOSYSTEM\tOSV\tRECORDS\tPACKAGES\tSIZE\tFETCHED")
			wrote := 0
			for _, res := range db.SyncGroup(cmd.Context(), osvEcos) {
				eco := owner[res.Ecosystem]
				if res.Err != nil {
					failed = append(failed, fmt.Sprintf("%s: %v", eco, res.Err))
					fmt.Fprintf(w, "%s\t%s\t-\t-\t-\tFAILED\n", eco, res.Ecosystem)
					continue
				}
				fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\t%s\n", eco, res.Ecosystem,
					res.Meta.Records, res.Meta.Packages, humanSize(res.Meta.Bytes),
					res.Meta.FetchedAt.Format(time.RFC3339))
				wrote++
			}
			if err := w.Flush(); err != nil {
				return err
			}
			if wrote > 0 {
				fmt.Printf("\nWrote %s\n", db.Dir())
			}
			// Named, never silent: a suite nothing was fetched for is a suite
			// whose entries the gate will warn on, and the operator has to
			// learn that here rather than from every import.
			for _, s := range skipped {
				fmt.Fprintf(os.Stderr, "skipped %s\n", s)
			}
			if len(failed) > 0 {
				return fmt.Errorf("sync failed for %d ecosystem(s): %s", len(failed), strings.Join(failed, "; "))
			}
			return nil
		},
	}
}

// osvDBState renders one ecosystem's sync time and age for the list table. An
// ecosystem that was never synced reads "never" rather than a blank column:
// the gate warns on it, and the operator has to see which one.
//
// apt spans one export per served suite, and the row reports the oldest of
// them. A gate that stopped syncing jammy in March is a gate that stopped, and
// averaging it against a fresh noble would hide exactly that.
func osvDBState(db *policy.OSVDatabase, ecosystem string, aptSuites []string) (string, string) {
	osvEcos, _ := policy.OSVExportsFor(ecosystem, aptSuites)
	if len(osvEcos) == 0 {
		return "never", "-"
	}
	var oldest time.Time
	for _, osvEco := range osvEcos {
		meta, err := db.Meta(osvEco)
		if err != nil {
			return "never", "-"
		}
		if oldest.IsZero() || meta.FetchedAt.Before(oldest) {
			oldest = meta.FetchedAt
		}
	}
	return oldest.Format(time.RFC3339), policy.ShortDuration(time.Since(oldest))
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func newPolicyOSVRescanCmd(gf *globalFlags) *cobra.Command {
	var typeFlag, nameFlag string
	cmd := &cobra.Command{
		Use:   "rescan [--type TYPE] [--name NAME]",
		Short: "Re-check stored versions against the local OSV database",
		Long: `Walk the manifests, re-run the OSV lookup for every stored version in
an OSV-covered ecosystem, and re-stamp what the local database says
today. Admission checked each version once, on the day it was imported;
advisories published against versions already in the field are the normal
case, so that answer ages out.

rescan records and decides nothing. It never blocks, hides, freezes or
deletes: an OSV data refresh that flags a base image would otherwise take
a fleet offline with no operator in the loop. What it changes is the
stamp, and the summary on stderr is what an operator acts on.

Versions the database cannot answer for keep the stamp they had. A
version checked before the check date existed reads as unchecked rather
than gaining an invented date.

  bodega policy osv rescan
  bodega policy osv rescan --type npm
  bodega policy osv rescan --type pypi --name django`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
			if err := ensureMutable(cfg); err != nil {
				return err
			}
			types := policy.OSVEcosystems()
			if typeFlag != "" {
				if err := requireEcosystem(typeFlag, policy.OSVEcosystems(), "OSV gate",
					"there are no OSV records to re-check it against"); err != nil {
					return err
				}
				types = []string{typeFlag}
			}
			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}
			adb := openAuditDB(gf)
			if adb != nil {
				defer adb.Close()
			}
			ck := admit.OSVChecker(cfg, adb)

			// The index keys packages by manifest.SafeName, which collapses
			// "/" to "--". Comparing the operator's spelling against that
			// walks nothing for every scoped npm package and every gomod
			// module path.
			wantName := ""
			if nameFlag != "" {
				wantName = manifest.SafeName(nameFlag)
			}

			ctx := cmd.Context()
			var sum policy.OSVRescanSummary
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			rows := 0
			row := func(typ, pkg, version, state, detail string) {
				if rows == 0 {
					fmt.Fprintln(w, "TYPE\tPACKAGE\tVERSION\tSTATE\tDETAIL")
				}
				rows++
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", typ, pkg, version, state, detail)
			}
			// A manifest that will not load or will not save is one package
			// the run could not answer for, not grounds to discard the report
			// for every other package. The walk finishes and the summary says
			// what it missed.
			fail := func(typ, pkg, reason string) {
				sum.Add(policy.OSVRescanChange{Reason: reason})
				row(typ, pkg, "-", "unanswered", reason)
			}
			matched, failures, saved := 0, 0, 0
			for _, t := range types {
				for _, name := range store.ListPackages(t) {
					if wantName != "" && name != wantName {
						continue
					}
					matched++
					pm, err := store.GetPackage(ctx, t, name)
					if err != nil {
						failures++
						fail(t, name, fmt.Sprintf("load %s/%s: %v", t, name, err))
						continue
					}
					// An index entry whose manifest file is gone is a package
					// the run could not answer for, not one with nothing to
					// say. 'bodega repair' counts the same state as an issue;
					// skipping it silently here reports a fleet nobody looked
					// at as a fleet with no findings.
					if pm == nil {
						failures++
						fail(t, name, fmt.Sprintf("%s/%s is in the index with no manifest file", t, name))
						continue
					}
					changed := false
					for i := range pm.Versions {
						ve := &pm.Versions[i]
						ch := ck.Rescan(ctx, pm, ve)
						sum.Add(ch)
						if ch.Answered {
							changed = true
						}
						state, detail := rescanRow(ch)
						if state == "" {
							continue
						}
						row(t, pm.Name, ve.Version, state, detail)
					}
					// One write per package, and only when something was
					// answered: a walk that learned nothing must not rewrite
					// every manifest in the store.
					if changed {
						if err := store.SavePackage(ctx, pm); err != nil {
							failures++
							fail(t, name, fmt.Sprintf("save %s/%s: %v", t, name, err))
							continue
						}
						saved++
					}
				}
			}
			if err := w.Flush(); err != nil {
				return err
			}
			sum.Report(os.Stderr)
			if saved == 0 {
				suppressReload(cmd)
			}
			if wantName != "" && matched == 0 {
				as := ""
				if wantName != nameFlag {
					as = fmt.Sprintf(" (index key %q)", wantName)
				}
				return fmt.Errorf("no package named %q%s in %s: nothing was re-checked",
					nameFlag, as, strings.Join(types, ", "))
			}
			// Name the population, not a cause. A walk answers for nothing
			// when the mirror is missing, when the store failed, and when
			// every entry carries a range no point lookup settles; the
			// reasons printed above tell those apart, and asserting one of
			// them here sends the operator to the wrong subsystem.
			if sum.Answered == 0 && sum.Walked > 0 && failures == 0 {
				return fmt.Errorf("nothing was re-checked: none of %d version(s) could be answered for; the reasons are above", sum.Walked)
			}
			if failures > 0 {
				// The post-run hook fires only after a nil return, and a walk
				// that re-stamped eight packages before failing on the ninth
				// still changed what the server should be serving.
				if saved > 0 {
					signalReloadNow(cmd, gf)
				}
				return fmt.Errorf("%d package(s) could not be read or written; their stamps are unchanged", failures)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&typeFlag, "type", "", "Restrict the walk to one registry type")
	cmd.Flags().StringVar(&nameFlag, "name", "", "Restrict the walk to one package name")
	return cmd
}

// rescanRow renders the one line a version earns in the report, or "" for a
// version that stayed clean. A clean version is in the summary count and
// nowhere else: the table is the list an operator has to read, and padding it
// with every version that did not change is how the two flagged rows get
// missed.
func rescanRow(ch policy.OSVRescanChange) (state, detail string) {
	switch {
	case !ch.Answered:
		// Ids first: an operator scanning the column for advisory names has
		// to find one here too, or a matched record hides behind the prose
		// explaining why nothing was written.
		return "unanswered", withReason(strings.Join(ch.Vulns, ", "), ch.Reason)
	case ch.Flagged:
		return "flagged (new)", withReason(strings.Join(ch.Vulns, ", "), ch.Reason)
	case len(ch.Vulns) > 0:
		return "flagged", withReason(strings.Join(ch.Vulns, ", "), ch.Reason)
	case ch.Cleared:
		return "cleared", withReason("no OSV records match it today", ch.Reason)
	default:
		return "", ""
	}
}

// withReason appends what qualified an answer to the answer itself. The row is
// the only per-version surface an operator reads, so a caveat that reaches the
// stderr reason counts and not the row leaves one line claiming a complete
// verdict the run never had.
func withReason(detail, reason string) string {
	switch {
	case reason == "":
		return detail
	case detail == "":
		return reason
	default:
		return detail + "; " + reason
	}
}
