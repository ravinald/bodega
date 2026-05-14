package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/manifest"
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

If no types are given, all four are packaged in dependency order:
  binary → git → apt → pypi

When a name is given after the type, only that entry is packaged.`,
		Example: `  bodega build package
  bodega build package git
  bodega build package apt python3`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var typeArgs []string
			var entryFilter string
			for _, a := range args {
				if isValidType(a) {
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

			bcfg := &builder.Config{
				AutoImportDeps: true,
				BuildRoot:      cfg.BuildRoot,
				ManifestDir:    cfg.ManifestDir,
				Bucket:         cfg.Bucket,
				Region:         cfg.Region,
				Verbose:        cfg.Verbose,
			}

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
					// Cascade: fetch any missing tarballs, then regenerate packuments.
					allSummaries = append(allSummaries,
						ensurePackagedNpm(bcfg, store, entryFilter),
					)

				case manifest.TypeCargo:
					// Cargo has no package stage — proxied sparse index is the metadata.
					allSummaries = append(allSummaries,
						ensureFetchedCargo(bcfg, store, entryFilter),
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
