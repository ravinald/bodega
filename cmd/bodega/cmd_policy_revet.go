package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/attest"
	"github.com/ravinald/bodega/internal/attestsign"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/policy"
	"github.com/ravinald/bodega/internal/storage"
)

func newPolicyRevetCmd(gf *globalFlags) *cobra.Command {
	var f admit.RevetFilter
	var olderThan string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "revet [--type TYPE] [--name NAME] [--version VERSION] [--older-than DURATION]",
		Short: "Re-run admission over versions already admitted",
		Long: `revet re-runs every per-version check against admitted versions, those in
the catalog and those the proxy cache admitted on a fill: the upstream
allow-list, OSV and upstream provenance. The publish-age gate is
not re-run, because a version only gets older; its last recorded verdict
is carried into the new row with its date.

Each version gets a new admission row beside the old one, under the actor
revet, so 'bodega audit admissions' shows what bodega concluded at
admission and at every re-vet since. --older-than keeps only versions
whose newest decision is older than that.

A refused version is handled by revet_on_block. report (the default)
writes a revet audit event and prints a WARN; the version stays served.
hide hides it as 'bodega pkg hide' does, recorded under the actor revet
with the failing checks in the event. A frozen version is never hidden:
it is reported, and the run exits non-zero because it is still served.
Neither is a version served only from the proxy cache, which has no
catalog entry to hide: it is reported, and its envelope still revokes it.
Under hide, such a version, or one whose hide failed, also makes the run
exit non-zero, since it is still served; under report none does.

For a helm, binary or apt version the proxy cached, whose catalog entry
names no upstream, the allow-list is re-run against the upstream recorded
when the object was cached. With none recorded, the allow-list entry is
not_evaluated and the outcome notes that the upstream is unknown.

With an attestation key installed, each refusal of a pinned object signs
a new envelope whose policy evaluations record the block, and a pass that
overturns an earlier refusal signs one recording the pass. Run it as the
user the server runs as so it can read the key.

  bodega policy revet
  bodega policy revet --type npm --name minimist
  bodega policy revet --type pypi --name django --version 5.2.12
  bodega policy revet --older-than 7d`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
			if err := ensureMutable(cfg); err != nil {
				return err
			}
			if olderThan != "" {
				if f.OlderThan, err = parseAgeDuration(olderThan); err != nil || f.OlderThan <= 0 {
					return fmt.Errorf("--older-than %q: want a positive duration like 7d or 72h", olderThan)
				}
			}
			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}
			adb, err := openAuditDBErr(gf)
			if err != nil {
				return err
			}
			if adb == nil {
				return errors.New("no audit store configured; a re-vet writes admission rows, so set audit_db")
			}
			defer func() { _ = adb.Close() }()

			ctx := cmd.Context()
			rv := &admit.Revetter{
				Cfg: cfg, DB: adb, Store: store, Allow: policy.NewChecker(adb),
				OnBlock: cfg.ResolveRevetOnBlock(),
			}
			// The stores are opened whether or not this process can sign: the
			// allow-list of a proxy-cached helm, binary or apt version is
			// re-run against the upstream recorded for the object they hold.
			if rv.Stores, err = storage.NewResolver(ctx, cfg); err != nil {
				rv.Stores = nil
				fmt.Fprintf(os.Stderr, "note: object stores not opened, so no envelope is signed and a proxy-cached URL-keyed version's allow-list is not re-run: %v\n", err)
			}
			if note := revetSigner(cfg, adb, rv); note != "" {
				fmt.Fprintf(os.Stderr, "note: %s\n", note)
			}
			targets, err := rv.Targets(ctx, f)
			if err != nil {
				return err
			}

			var outcomes []admit.RevetOutcome
			sum := rv.Sweep(ctx, targets, audit.CurrentActor(), 0, func(o admit.RevetOutcome) {
				outcomes = append(outcomes, o)
			})
			if asJSON {
				if outcomes == nil {
					outcomes = []admit.RevetOutcome{}
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(outcomes); err != nil {
					return err
				}
			} else if err := printRevet(outcomes); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Re-vetted %d version(s): %d admitted, %d refused (%d hidden, %d frozen), %d error(s).\n",
				sum.Walked, sum.Admitted, sum.Blocked, sum.Hidden, sum.Frozen, sum.Errors)
			for _, o := range outcomes {
				if o.Blocked() && o.Action != admit.RevetHidden && o.Action != admit.RevetAlreadyHidden {
					fmt.Fprintf(os.Stderr, "WARN: %s/%s@%s is refused and still served (%s)\n", o.Type, o.Name, o.Version, o.Action)
				}
			}
			if sum.Hidden == 0 {
				suppressReload(cmd)
			}
			if sum.Errors > 0 {
				signalReloadNow(cmd, gf)
				return fmt.Errorf("%d version(s) could not be re-vetted; see the table", sum.Errors)
			}
			if sum.Frozen > 0 {
				signalReloadNow(cmd, gf)
				return fmt.Errorf("%d frozen version(s) are refused and still served; unfreeze and hide them with 'bodega pkg freeze' and 'bodega pkg hide'", sum.Frozen)
			}
			if n := unhidden(rv.OnBlock, outcomes); n > 0 {
				signalReloadNow(cmd, gf)
				return fmt.Errorf("revet_on_block is hide and %d refused version(s) are still served; see the table for why each was not hidden", n)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&f.Type, "type", "", "Restrict the walk to one registry type")
	cmd.Flags().StringVar(&f.Name, "name", "", "Restrict the walk to one package name")
	cmd.Flags().StringVar(&f.Version, "version", "", "Restrict the walk to one version (or git ref)")
	cmd.Flags().StringVar(&olderThan, "older-than", "", "Only versions whose newest decision is older than this (e.g. 7d, 72h)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print each outcome as JSON")
	return cmd
}

// revetSigner wires the attestation emitter into rv when this process can
// sign, and otherwise returns why it cannot. Not signing is a note rather
// than a failure: the refusal is still recorded and still acted on, and an
// operator without the key is the common case for a CLI run.
func revetSigner(cfg *config.Config, adb *audit.DB, rv *admit.Revetter) string {
	if adb.ReadOnly() || !adb.EventsQueryable() {
		return "audit_sink " + adb.SinkName() + " keeps no admissions table to re-read before signing; refusals are recorded and no envelope is signed"
	}
	kr, err := openAttestKey(cfg)
	if err != nil {
		return "no envelope is signed for a refusal: " + err.Error()
	}
	if rv.Stores == nil {
		return "no envelope is signed for a refusal: no object store is open"
	}
	signer := kr.Signer()
	rv.Emitter = &attest.Emitter{
		Signer:     func() attestsign.Signer { return signer },
		Admissions: adb,
		PlatformID: cfg.ResolveAttestationPlatformID(),
	}
	return ""
}

// unhidden counts the refusals revet_on_block: hide left served: a version
// only the proxy cache holds, or one whose hide failed. Under report every
// refusal is left served by design and none is counted.
func unhidden(onBlock string, outcomes []admit.RevetOutcome) int {
	if onBlock != config.RevetHide {
		return 0
	}
	n := 0
	for _, o := range outcomes {
		if o.Blocked() && o.Action == admit.RevetReported {
			n++
		}
	}
	return n
}

func printRevet(outcomes []admit.RevetOutcome) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "TYPE\tPACKAGE\tVERSION\tPREVIOUS\tDECISION\tACTION\tDETAIL")
	for _, o := range outcomes {
		var detail []string
		if o.Error != "" {
			detail = append(detail, "error: "+o.Error)
		}
		for _, c := range o.Failing {
			detail = append(detail, c.Check+": "+c.Detail)
		}
		detail = append(detail, o.Notes...)
		for _, e := range o.Envelopes {
			detail = append(detail, "signed "+e)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", o.Type, o.Name, o.Version,
			dash(o.Previous), dash(o.Decision), dash(o.Action), strings.Join(detail, "; "))
	}
	return w.Flush()
}
