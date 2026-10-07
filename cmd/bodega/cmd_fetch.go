package main

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

func newFetchCmd(gf *globalFlags) *cobra.Command {
	var backfillPublished bool
	cmd := &cobra.Command{
		Use:   "fetch [TYPE] [NAME] [force]",
		Short: "Download source artifacts for one or more manifest types",
		Long: `fetch downloads raw sources without compiling or packaging them:

  binary  Download file from URL to binaries/
  git     Clone bare repository to repos/
  apt     Clone source repo (or apt-get download .deb) to sources/
  pypi    Resolve requirements from cloned git repos, download the closure to wheelhouse/
  gomod   Download module zips to gomod/
  helm    Download chart archives to charts/
  npm     Download package tarballs to npm/
  cargo   Download crate tarballs to cargo/
  freebsd Mirror a pkg repository byte for byte to freebsd/
  distfiles Download ports distfiles matching the ports tree's distinfo to distfiles/

` + typeOrderSentence("fetched") + `

Append 'force' to re-fetch even if artifacts already exist.
When a name is given after the type, only that entry is fetched.

--backfill-published fetches nothing. It reads the upstream publish time of
every npm, pypi, gomod and cargo version that has none recorded, at most one
request every ` + builder.PublishedBackfillInterval.String() + `, and reports how many it filled and how
many it could not. Versions fetched before bodega recorded publish times need
it once before a hosted index can date them.`,
		Example: `  bodega build fetch
  bodega build fetch git
  bodega build fetch apt python3
  bodega build fetch force
  bodega build fetch --backfill-published
  bodega build fetch npm --backfill-published`,
		RunE: func(cmd *cobra.Command, args []string) error {
			force := false
			var positional []string
			for _, a := range args {
				if a == "force" {
					force = true
				} else {
					positional = append(positional, a)
				}
			}
			typeArgs, rest := splitTypeArgs(positional)
			var entryFilter string
			if len(rest) > 0 {
				entryFilter = rest[len(rest)-1]
			}
			types, err := resolveTypes(typeArgs)
			if err != nil {
				return err
			}
			if backfillPublished {
				if force {
					return fmt.Errorf("--backfill-published fetches nothing, so 'force' has nothing to re-fetch; run them separately")
				}
				if types, err = publishedTypes(types, len(typeArgs) > 0); err != nil {
					return err
				}
			}

			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}

			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}
			if err := refuseAliasCollision(typeArgs, store); err != nil {
				return err
			}

			auditDB := openAuditDB(gf)
			if auditDB != nil {
				defer auditDB.Close()
			}

			bcfg := builder.NewConfig(cfg, policy.CheckerFor(auditDB))
			bcfg.Force = force
			bcfg.AuditDB = auditDB

			if backfillPublished {
				res := builder.BackfillPublished(bcfg, store, types, entryFilter, builder.PublishedBackfillInterval)
				fmt.Printf("\nPublish times filled: %d  Could not fill: %d\n", res.Filled, res.Failed)
				if res.Failed > 0 {
					return fmt.Errorf("%d version(s) still have no publish time; each is named above with its reason", res.Failed)
				}
				return nil
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
				case manifest.TypeCargo:
					allSummaries = append(allSummaries,
						builder.FetchCargo(bcfg, store, entryFilter),
					)
				case manifest.TypeFreeBSD:
					allSummaries = append(allSummaries,
						builder.FetchFreeBSD(bcfg, store, entryFilter),
					)
				case manifest.TypeDistfiles:
					allSummaries = append(allSummaries,
						builder.FetchDistfiles(bcfg, store, entryFilter),
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

			if failures > 0 {
				return fmt.Errorf("%d fetch(es) failed", failures)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&backfillPublished, "backfill-published", false,
		"Record upstream publish times on versions that have none, instead of fetching")
	return cmd
}

// publishedTypes narrows types to the ones a publish time can be read for. A
// type the operator named that has no such source is refused rather than
// skipped, since skipping reports a clean run over something never examined.
func publishedTypes(types []string, named bool) ([]string, error) {
	dated := policy.AgeEcosystems()
	var out []string
	for _, t := range types {
		if slices.Contains(dated, t) {
			out = append(out, t)
		} else if named {
			return nil, fmt.Errorf("%s has no upstream publish time to backfill; --backfill-published covers %s",
				t, strings.Join(dated, ", "))
		}
	}
	return out, nil
}
