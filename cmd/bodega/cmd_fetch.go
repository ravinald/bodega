package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/scaleapi/bodega/internal/builder"
	"github.com/scaleapi/bodega/internal/manifest"
)

func newFetchCmd(gf *globalFlags) *cobra.Command {
	var entryFilter string
	var force bool

	cmd := &cobra.Command{
		Use:   "fetch [TYPE...]",
		Short: "Download source artifacts for one or more manifest types",
		Long: `fetch downloads raw sources without compiling or packaging them:

  binary  Download file from URL to binaries/
  git     Clone bare repository to repos/
  apt     Clone source repo (or apt-get download .deb) to sources/
  pypi    Resolve requirements from cloned git repos, write combined-requirements.txt

If no types are given, all four are fetched in dependency order:
  binary → git → apt → pypi

The --entry flag restricts the operation to a single named entry.`,
		Example: `  bodega fetch
  bodega fetch git
  bodega fetch apt --entry amazon-efs-utils`,
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
				AutoImportDeps: true,
				Force:       force,
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
					allSummaries = append(allSummaries,
						builder.FetchBinaries(bcfg, store, entryFilter),
					)
				case manifest.TypeGit:
					allSummaries = append(allSummaries,
						builder.FetchGit(bcfg, store, entryFilter),
					)
				case manifest.TypeApt:
					allSummaries = append(allSummaries,
						builder.FetchApt(bcfg, store, entryFilter),
					)
				case manifest.TypePypi:
					allSummaries = append(allSummaries,
						builder.FetchPypi(bcfg, store),
					)
				case manifest.TypeGomod:
					allSummaries = append(allSummaries,
						builder.FetchGomod(bcfg, store, entryFilter),
					)
				case manifest.TypeHelm:
					allSummaries = append(allSummaries,
						builder.FetchHelm(bcfg, store, entryFilter),
					)
				case manifest.TypeNpm:
					allSummaries = append(allSummaries,
						builder.FetchNpm(bcfg, store, entryFilter),
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
				return fmt.Errorf("%d fetch(es) failed", failures)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&entryFilter, "entry", "", "Fetch only the named entry")
	cmd.Flags().BoolVar(&force, "force", false, "Re-fetch even if artifacts already exist")
	return cmd
}
