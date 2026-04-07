package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/builder"
	"github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/manifest"
)

func newPackageCmd(gf *globalFlags) *cobra.Command {
	var entryFilter string

	cmd := &cobra.Command{
		Use:   "package [TYPE...]",
		Short: "Package built artifacts into distributable form",
		Long: `package creates the final distributable artifacts from built sources.
It automatically cascades through fetch and build if those stages have not
been completed yet.

  binary  No-op (the downloaded file is already the artifact)
  git     Create and verify a git bundle from the bare repo (fetches if needed)
  apt     Run reprepro includedeb to add the .deb to the APT repository
          (fetches and builds if needed)
  pypi    Generate MANIFEST.sha256 for the wheels directory
          (fetches and builds if needed)

If no types are given, all four are packaged in dependency order:
  binary → git → apt → pypi

The --entry flag restricts the operation to a single named entry.`,
		Example: `  reman package
  reman package git
  reman package apt --entry amazon-efs-utils`,
		RunE: func(cmd *cobra.Command, args []string) error {
			types, err := resolveTypes(args)
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
				BuildRoot:   cfg.BuildRoot,
				ManifestDir: cfg.ManifestDir,
				Bucket:      cfg.Bucket,
				Region:      cfg.Region,
				Verbose:     cfg.Verbose,
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

	cmd.Flags().StringVar(&entryFilter, "entry", "", "Package only the named entry")
	return cmd
}
