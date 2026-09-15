package main

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/manifest"
)

func newVerifyCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Verify every manifest against its .md5 sidecar",
		Long: `verify reads each manifest object in the store and checks that its companion
.md5 file contains the correct MD5 digest.

A manifest with no sidecar is UNVERIFIABLE, not a pass: nothing was compared,
so an edit to it would go unnoticed. verify exits non-zero when any manifest
fails or cannot be verified.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := loadStore(gf)
			if err != nil {
				return err
			}

			results, err := store.VerifyIntegrity(backgroundCtx())
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if len(results) == 0 {
				fmt.Fprintf(out, "No manifests in %s.\n", store.Label())
				return nil
			}

			return reportIntegrity(out, results)
		},
	}
}

// reportIntegrity prints one row per manifest and returns a non-nil error when
// any of them failed or could not be verified.
func reportIntegrity(out io.Writer, results []manifest.IntegrityResult) error {
	var failed, unverifiable int
	for _, r := range results {
		switch r.Status {
		case manifest.IntegrityOK:
			fmt.Fprintf(out, "  %-12s %s  (%s)\n", r.Status, r.Path, r.Digest)
		case manifest.IntegrityFail:
			failed++
			fmt.Fprintf(out, "  %-12s %s  (MD5 mismatch — run: bodega --break-glass-update-md5 %s)\n",
				r.Status, r.Path, restampArg(r.Type))
		case manifest.IntegrityUnverifiable:
			unverifiable++
			fmt.Fprintf(out, "  %-12s %s  (no .md5 sidecar)\n", r.Status, r.Path)
		default:
			failed++
			fmt.Fprintf(out, "  %-12s %s  (%v)\n", r.Status, r.Path, r.Err)
		}
	}

	if unverifiable > 0 {
		fmt.Fprintf(out, "\n%s\n", unverifiableCause(results, unverifiable))
	}
	if failed+unverifiable > 0 {
		return fmt.Errorf("%d manifest(s) failed and %d could not be verified", failed, unverifiable)
	}
	fmt.Fprintf(out, "\nAll %d manifest(s) passed integrity check.\n", len(results))
	return nil
}

// unverifiableCause names which of the two things a sidecar-less manifest is,
// because the remedy differs and neither is guessable from the row alone.
//
// Every write emits its sidecar, so a store written by this build has one per
// manifest. None at all means the store predates that and needs a single
// re-stamp. Some but not all means a writer stored a manifest and skipped the
// sidecar, which is a defect in that writer and re-stamping only hides it.
func unverifiableCause(results []manifest.IntegrityResult, unverifiable int) string {
	if unverifiable == len(results) {
		return "No manifest in this store carries a sidecar, so it was written before sidecars\n" +
			"were emitted on every write. Re-stamp the store once:\n" +
			"  bodega --break-glass-update-md5 all"
	}
	return fmt.Sprintf("%d of %d manifests carry a sidecar, so the store is not a pre-sidecar install:\n",
		len(results)-unverifiable, len(results)) +
		"something wrote those manifests without one. Re-stamping hides that; report it first."
}

// restampArg names what to hand --break-glass-update-md5 for a given manifest.
// The store-wide index.json, graph.json and metrics.json belong to no type.
func restampArg(typ string) string {
	if typ == "" {
		return breakGlassAll
	}
	return typ
}
