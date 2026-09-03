package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/host"
)

// newDoctorCmd reports host-level configuration that would silently bypass
// bodega's supply-chain controls. The checks are read-only — doctor never
// modifies the host. Exit code is 0 when all checks are clean (OK or N/A)
// and 2 when at least one check produced a finding (WARN or FAIL); this
// matches the convention used by other CI-gating linters.
//
// The threat model and rationale for each check is documented in
// docs/THREAT_MODEL.md.
func newDoctorCmd(gf *globalFlags) *cobra.Command {
	_ = gf // doctor inspects the host, not the bodega config
	return &cobra.Command{
		Use:   "doctor",
		Short: "Inspect the local host for configurations that bypass bodega's controls",
		Long: `doctor scans the machine running this command for distribution channels
and package-manager configurations that would silently fetch software from
outside bodega's allow-list. Common findings:

  - snapd or flatpak installed (opaque, auto-refreshing bundles)
  - Homebrew with auto-update enabled
  - pip / cargo / npm / apt configured to talk to public registries directly
  - GOPROXY unset or falling through to proxy.golang.org

Reports only. doctor never modifies the host. Exit code is 0 when clean
and 2 when one or more findings are present, so this command can gate CI
pipelines for build hosts that are supposed to route everything through
bodega.

See docs/THREAT_MODEL.md for the rationale behind each check.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			findings := make([]host.Finding, 0, len(host.AllChecks()))
			for _, fn := range host.AllChecks() {
				findings = append(findings, fn())
			}

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
