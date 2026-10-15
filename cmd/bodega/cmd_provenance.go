package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
	"github.com/ravinald/bodega/internal/provenance"
)

func newPolicyProvenanceCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "provenance",
		Short: "Upstream provenance check per ecosystem",
		Long: `Verify the provenance a publisher signed for every admitted version: the
Sigstore bundles npm serves beside a version built in CI, and the GitHub
artifact attestations of a binary or git release asset. A verified bundle
names the source repository and builder; the first verified version of a
package pins both, and a later version verified from anything else is a
mismatch. So is an npm version with no provenance published after the
pinned version: the trace a publish from a stolen token leaves, and also
the one a maintainer publishing by hand leaves. The result names who
published each version; deciding which it was is the operator's call.
'bodega pkg trust' shows and clears the pin.

Each version gets one outcome:

  verified     the signature, certificate chain and subject digest checked out
  unavailable  the package publishes no provenance, or its ecosystem has no
               mechanism bodega reads (pypi, gomod, cargo, helm, apt, freebsd,
               distfiles)
  invalid      provenance was published and did not verify
  unknown      the evidence could not be read: a lookup failed or did not
               parse, or the registry no longer lists the version; nothing
               was verified, and an override may admit it
  mismatch     it verified, from a repository or builder other than the pin;
               or, on npm, it has no provenance and was published after the
               pinned version

The action says what each outcome does to the admission:

  warn    (default) invalid, unknown and mismatch warn; unavailable passes
  block   invalid, unknown, mismatch and unavailable all refuse
  ignore  every outcome is recorded and none refuses

The trusted root comes from Sigstore's TUF repository, or from the file the
sigstore_trusted_root config key names on a host that cannot reach it.

  bodega policy provenance set npm block
  bodega policy provenance list`,
	}
	cmd.AddCommand(newPolicyProvenanceSetCmd(gf), newPolicyProvenanceListCmd(gf))
	return cmd
}

func newPolicyProvenanceSetCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "set <ecosystem> warn|block|ignore",
		Short: "Set the upstream provenance action for an ecosystem",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			eco, action := args[0], strings.ToLower(args[1])
			if !manifest.IsKnownType(eco) {
				return fmt.Errorf("unknown ecosystem %q: must be one of %s", eco, strings.Join(manifest.AllTypes, ", "))
			}
			if action != policy.ActionWarn && action != policy.ActionBlock && action != policy.ActionIgnore {
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
			ctx := cmd.Context()
			actor := audit.CurrentActor()
			if err := adb.SetProvenancePolicy(ctx, audit.ProvenancePolicy{Ecosystem: eco, Action: action, Actor: actor}); err != nil {
				return err
			}
			details, _ := json.Marshal(map[string]string{"gate": audit.CheckUpstreamProvenance, "action": action})
			if err := adb.Record(ctx, audit.Event{
				EventType: audit.EventPolicy, PkgType: eco, Actor: actor, Status: "success", Details: string(details),
			}); err != nil {
				return fmt.Errorf("set %s upstream provenance action to %s, but the audit event was not written: %w", eco, action, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Set %s upstream provenance policy: %s\n", eco, action)
			if action == policy.ActionBlock && !provenance.IsCovered(eco) {
				fmt.Fprintf(cmd.OutOrStdout(), "note: every %s version records unavailable (%s), so block refuses all of them\n",
					eco, provenance.UncoveredReason(eco))
			}
			return nil
		},
	}
}

func newPolicyProvenanceListCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the upstream provenance action for every ecosystem",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("audit DB unavailable")
			}
			defer adb.Close()
			rows, err := adb.ListProvenancePolicies(cmd.Context())
			if err != nil {
				return err
			}
			set := make(map[string]audit.ProvenancePolicy, len(rows))
			for _, p := range rows {
				set[p.Ecosystem] = p
			}
			// Every ecosystem gets a row, because the unset ones still run
			// the check under warn.
			types := slices.Sorted(slices.Values(manifest.AllTypes))
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ECOSYSTEM\tACTION\tVERIFIES\tSET BY\tUPDATED")
			for _, eco := range types {
				covered := "no"
				if provenance.IsCovered(eco) {
					covered = "yes"
				}
				p, ok := set[eco]
				if !ok {
					fmt.Fprintf(w, "%s\twarn (default)\t%s\t-\t-\n", eco, covered)
					continue
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", eco, p.Action, covered, dash(p.Actor), p.UpdatedAt.Format("2006-01-02"))
			}
			return w.Flush()
		},
	}
}

func newTrustCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Show or clear a package's upstream provenance pin",
		Long: `The first version of a package whose upstream provenance verifies pins the
source repository it was built from and the builder that built it (the
builder with any @<ref> removed, since a release workflow runs at a new tag
each time). A later version verified from a different repository or builder
fails the upstream_provenance check as a mismatch.

reset deletes the pin, so the next verified version pins afresh. Use it when a
project moved repositories or CI systems on purpose; the reset is recorded as
an audit event naming who ran it and what the pin held.`,
	}
	cmd.AddCommand(newTrustShowCmd(gf), newTrustResetCmd(gf))
	return cmd
}

func newTrustShowCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:     "show <type> <name>",
		Short:   "Show the repository and builder a package is pinned to",
		Example: `  bodega pkg trust show npm sigstore`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			typ, name := args[0], args[1]
			adb := openAuditDB(gf)
			if adb == nil {
				return fmt.Errorf("audit DB unavailable")
			}
			defer adb.Close()
			pin, err := adb.GetProvenancePin(cmd.Context(), typ, name)
			if errors.Is(err, audit.ErrProvenancePinNotFound) {
				fmt.Fprintf(cmd.OutOrStdout(), "%s/%s has no pin: no version of it has verified yet, so the next one that does is pinned.\n", typ, name)
				return nil
			}
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintf(w, "package\t%s/%s\n", typ, name)
			fmt.Fprintf(w, "source repository\t%s\n", pin.SourceRepositoryURI)
			fmt.Fprintf(w, "builder\t%s\n", pin.BuilderID)
			fmt.Fprintf(w, "workflow\t%s\n", dash(pin.WorkflowRef))
			fmt.Fprintf(w, "pinned by version\t%s\n", dash(pin.PinnedVersion))
			fmt.Fprintf(w, "pinned at\t%s\n", pin.PinnedAt.UTC().Format("2006-01-02T15:04:05Z"))
			return w.Flush()
		},
	}
}

func newTrustResetCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:     "reset <type> <name>",
		Short:   "Clear a package's pin so the next verified version pins afresh",
		Example: `  bodega pkg trust reset npm sigstore`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			typ, name := args[0], args[1]
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
			ctx := cmd.Context()
			old, err := adb.ResetProvenancePin(ctx, typ, name)
			if errors.Is(err, audit.ErrProvenancePinNotFound) {
				fmt.Fprintf(cmd.OutOrStdout(), "%s/%s has no pin; nothing was cleared.\n", typ, name)
				return nil
			}
			if err != nil {
				return err
			}
			details, _ := json.Marshal(map[string]string{
				"gate": audit.CheckUpstreamProvenance, "op": "trust_reset",
				"source_repository_uri": old.SourceRepositoryURI, "builder_id": old.BuilderID,
				"pinned_version": old.PinnedVersion,
			})
			if err := adb.Record(ctx, audit.Event{
				EventType: audit.EventPolicy, PkgType: typ, PkgName: name,
				Actor: audit.CurrentActor(), Status: "success", Details: string(details),
			}); err != nil {
				return fmt.Errorf("cleared the pin for %s/%s, but the audit event was not written: %w", typ, name, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Cleared the pin for %s/%s (was %s from %s); the next verified version pins afresh.\n",
				typ, name, old.BuilderID, old.SourceRepositoryURI)
			return nil
		},
	}
}
