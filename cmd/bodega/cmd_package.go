package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

func newPackageCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "package [TYPE] [NAME]",
		Short: "Package built artifacts into distributable form",
		Long: `package creates the final distributable artifacts from built sources.
It automatically cascades through fetch and build if those stages have not
been completed yet.

  binary  No-op (the downloaded file is already the artifact)
  git     Create and verify a git bundle from the bare repo (fetches if needed)
  apt     Copy .deb into pool directory structure (fetches and builds if needed)
  pypi    Generate MANIFEST.sha256 for the wheels directory
          (fetches and builds if needed)
  helm    Generate index.yaml across every fetched chart
  npm     No-op (the server generates the packument from the manifest entry)
  gomod   No-op (the downloaded module zip is already the artifact)
  cargo   No-op (the downloaded crate tarball is already the artifact)
  freebsd No-op (fetch mirrors the repository; nothing here may touch its bytes)

helm packages across the whole type rather than per entry, because index.yaml
is repository metadata: naming one entry regenerates everything.

` + typeOrderSentence("packaged") + `

When a name is given after the type, only that entry is packaged.`,
		Example: `  bodega build package
  bodega build package git
  bodega build package apt python3`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var typeArgs []string
			var entryFilter string
			for _, a := range args {
				if isTypeArg(a) {
					typeArgs = append(typeArgs, a)
				} else {
					entryFilter = a
				}
			}
			types, err := resolveTypes(typeArgs)
			if err != nil {
				return err
			}

			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}

			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}

			auditDB := openAuditDB(gf)
			if auditDB != nil {
				defer auditDB.Close()
			}

			// The cargo arm cascades into ensureFetchedCargo, so this command
			// reaches a fetcher and needs the allow-list the fetch commands
			// carry; without it a rule that blocks a crate under
			// `bodega build fetch` did not block it here.
			bcfg := builder.NewConfig(cfg, policy.CheckerFor(auditDB))
			// The package stage records EventPackage and pins the apt digest,
			// and both went nowhere while this was nil: apt's _pool_path is
			// written here rather than at fetch, so the pool key a checksum row
			// is filed under does not exist until this stage runs.
			bcfg.AuditDB = auditDB

			var allSummaries []*builder.Summary

			for _, t := range types {
				switch t {
				case manifest.TypeBinary:
					// Binary has no package stage: the downloaded file is the artifact.
					// Emit an empty summary so aggregate output is consistent.
					allSummaries = append(allSummaries, &builder.Summary{})

				case manifest.TypeGit:
					// Cascade: fetch if not fetched, then package.
					allSummaries = append(allSummaries,
						ensurePackagedGit(bcfg, store, entryFilter),
					)

				case manifest.TypeApt:
					// Cascade: fetch → build → package as needed.
					allSummaries = append(allSummaries,
						ensurePackagedApt(bcfg, store, entryFilter),
					)

				case manifest.TypePypi:
					// Cascade: fetch → build → package as needed.
					allSummaries = append(allSummaries,
						ensurePackagedPypi(bcfg, store),
					)

				case manifest.TypeGomod:
					// gomod has no package stage: fetched artifacts are what ships.
					allSummaries = append(allSummaries, &builder.Summary{})

				case manifest.TypeHelm:
					// Cascade: fetch any missing charts, then regenerate index.yaml.
					allSummaries = append(allSummaries,
						ensurePackagedHelm(bcfg, store, entryFilter),
					)

				case manifest.TypeNpm:
					// npm has no package stage — the server generates the packument per request.
					allSummaries = append(allSummaries,
						ensureFetchedNpm(bcfg, store, entryFilter),
					)

				case manifest.TypeCargo:
					// Cargo has no package stage — proxied sparse index is the metadata.
					allSummaries = append(allSummaries,
						ensureFetchedCargo(bcfg, store, entryFilter),
					)

				case manifest.TypeFreeBSD:
					// freebsd has no package stage — the mirrored catalogue is
					// the metadata, and it is upstream's to produce.
					allSummaries = append(allSummaries,
						ensureMirroredFreeBSD(bcfg, store, entryFilter),
					)
				}
			}

			total, failures := 0, 0
			for _, s := range allSummaries {
				s.Print(os.Stdout)
				total += s.Total
				failures += s.Failures
			}

			fmt.Printf("\nTotal entries: %d  Failures: %d\n", total, failures)
			if failures > 0 {
				return fmt.Errorf("%d package(s) failed", failures)
			}
			return nil
		},
	}

	return cmd
}
