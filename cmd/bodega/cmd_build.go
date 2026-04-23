package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/logging"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

func newBuildRunCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run [TYPE] [NAME]",
		Short: "Compile/transform sources for one or more manifest types",
		Long: `build compiles or prepares sources for the specified types. It automatically
fetches sources first if they have not already been fetched.

  binary  Download the file (fetch is the final artifact; no compilation)
  git     Clone the bare repository if not already present
  apt     Fetch source (if needed), then run build_cmd to produce a .deb
  pypi    Resolve requirements (if needed), then run pip wheel

If no types are given, all four are processed in dependency order:
  binary → git → apt → pypi

When a name is given after the type, only that entry is built.`,
		Example: `  bodega build run
  bodega build run apt
  bodega build run apt python3`,
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

			// Set up the build logger. Output is teed to both stdout and the
			// session log; failures to open the log dir are non-fatal.
			var buildOut io.Writer = os.Stdout
			var buildLogger *logging.BuildLogger
			if cfg.LogDir != "" {
				if logger, err := logging.NewBuildLogger(cfg.LogDir); err == nil {
					buildLogger = logger
					defer logger.Close()
					buildOut = io.MultiWriter(os.Stdout, logger.SessionWriter())
				}
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
				BuildRoot:      cfg.BuildRoot,
				ManifestDir:    cfg.ManifestDir,
				Bucket:         cfg.Bucket,
				Region:         cfg.Region,
				Verbose:        cfg.Verbose,
				AptRoot:        cfg.AptRoot,
				GitRoot:        cfg.GitRoot,
				PypiRoot:       cfg.PypiRoot,
				BinaryRoot:     cfg.BinaryRoot,
				Stdout:         buildOut,
				Logger:         buildLogger,
				AuditDB:        auditDB,
				Policy:         policyChecker,
			}

			var allSummaries []*builder.Summary

			for _, t := range types {
				switch t {
				case manifest.TypeBinary:
					// Fetch is the only stage for binaries; cascade ensures it runs.
					allSummaries = append(allSummaries,
						ensureFetchedBinaries(bcfg, store, entryFilter),
					)

				case manifest.TypeGit:
					// Git has no compilation step; fetch is the only build action.
					allSummaries = append(allSummaries,
						ensureFetchedGit(bcfg, store, entryFilter),
					)

				case manifest.TypeApt:
					// Cascade: fetch if not fetched, then build.
					allSummaries = append(allSummaries,
						ensureFetchedApt(bcfg, store, entryFilter),
					)
					s := builder.BuildApt(bcfg, store, entryFilter)
					allSummaries = append(allSummaries, s)

				case manifest.TypePypi:
					// Cascade: fetch if not fetched, then build.
					allSummaries = append(allSummaries,
						ensureFetchedPypi(bcfg, store),
					)
					s := builder.BuildPypi(bcfg, store)
					allSummaries = append(allSummaries, s)

				case manifest.TypeGomod:
					// gomod has no build step; fetch is the only action.
					// FetchGomod skips already-fetched entries per-item.
					allSummaries = append(allSummaries,
						builder.FetchGomod(bcfg, store, entryFilter),
					)

				case manifest.TypeHelm:
					// helm has no build step; FetchHelm skips already-fetched.
					allSummaries = append(allSummaries,
						builder.FetchHelm(bcfg, store, entryFilter),
					)

				case manifest.TypeNpm:
					// npm has no build step; FetchNpm skips already-fetched.
					allSummaries = append(allSummaries,
						builder.FetchNpm(bcfg, store, entryFilter),
					)
				}
			}

			total, failures := 0, 0
			for _, s := range allSummaries {
				s.Print(buildOut)
				s.LogErrors(buildLogger, "build")
				total += s.Total
				failures += s.Failures
			}

			fmt.Fprintf(buildOut, "\nTotal entries: %d  Failures: %d\n", total, failures)

			// Update metrics after build.
			ctx := context.Background()
			if err := store.SaveIndex(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not update metrics: %v\n", err)
			}
			notifyServer(gf)

			if failures > 0 {
				return fmt.Errorf("%d build(s) failed", failures)
			}
			return nil
		},
	}

	return cmd
}
