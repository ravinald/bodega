package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

func newFetchCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fetch [TYPE] [NAME] [force]",
		Short: "Download source artifacts for one or more manifest types",
		Long: `fetch downloads raw sources without compiling or packaging them:

  binary  Download file from URL to binaries/
  git     Clone bare repository to repos/
  apt     Clone source repo (or apt-get download .deb) to sources/
  pypi    Resolve requirements from cloned git repos, write combined-requirements.txt

If no types are given, all seven are fetched in dependency order:
  binary → git → apt → pypi → gomod → helm → npm

Append 'force' to re-fetch even if artifacts already exist.
When a name is given after the type, only that entry is fetched.`,
		Example: `  bodega build fetch
  bodega build fetch git
  bodega build fetch apt python3
  bodega build fetch force`,
		RunE: func(cmd *cobra.Command, args []string) error {
			force := false
			var typeArgs []string
			var entryFilter string
			for _, a := range args {
				if a == "force" {
					force = true
				} else if isValidType(a) {
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

			var policyChecker *policy.Checker
			if auditDB != nil {
				policyChecker = policy.NewChecker(auditDB)
			}

			bcfg := &builder.Config{
				AutoImportDeps: true,
				Force:          force,
				AuditDB:        auditDB,
				Policy:         policyChecker,
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

			// Update metrics after fetch.
			ctx := context.Background()
			if err := store.SaveIndex(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not update metrics: %v\n", err)
			}
			notifyServer(gf)

			if failures > 0 {
				return fmt.Errorf("%d fetch(es) failed", failures)
			}
			return nil
		},
	}

	return cmd
}
