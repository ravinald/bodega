package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

func newImportCmd(gf *globalFlags) *cobra.Command {
	var merge bool

	cmd := &cobra.Command{
		Use:   "import <file> [file...]",
		Short: "Import package manifests from JSON files",
		Long: `import reads one or more JSON files (or stdin with "-") and adds them to
the manifest store. Each file may contain either a single PackageManifest
object or a JSON array of PackageManifest objects (e.g. the output of
'bodega pkg export').

Use this for automation instead of the interactive 'create' command.

Examples:
  bodega pkg import nginx.json
  bodega pkg import packages/*.json
  bodega pkg import bundle.json             # array of many packages
  cat manifest.json | bodega pkg import -
  bodega pkg import --merge updated.json    # add versions to existing package`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			if err := ensureMutable(cfg); err != nil {
				return err
			}

			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}
			ctx := context.Background()

			// Open the audit DB once for both policy enforcement and audit logging.
			adb := openAuditDB(gf)
			if adb != nil {
				defer adb.Close()
			}
			var checker *policy.Checker
			if adb != nil {
				checker = policy.NewChecker(adb)
			}

			var imported int
			for _, path := range args {
				data, err := readInput(path)
				if err != nil {
					return fmt.Errorf("read %s: %w", path, err)
				}

				pms, err := decodeManifests(data)
				if err != nil {
					return fmt.Errorf("parse %s: %w", path, err)
				}

				for i := range pms {
					pm := &pms[i]
					res := admit.Admit(ctx, checker, adb, cfg, pm, audit.CurrentActor())
					for _, w := range res.Warnings {
						fmt.Fprintf(os.Stderr, "%s/%s: %s\n", pm.Type, pm.Name, w)
					}
					if !res.OK() {
						return fmt.Errorf("%s [%s/%s]: %s", path, pm.Type, pm.Name, res.Reason)
					}

					existing, _ := store.GetPackage(ctx, pm.Type, pm.Name)
					if existing != nil && !merge {
						return fmt.Errorf("%s/%s already exists (use --merge to add versions)", pm.Type, pm.Name)
					}

					if existing != nil && merge {
						// Merge new versions into existing package.
						for _, ve := range pm.Versions {
							found := false
							for _, ev := range existing.Versions {
								if ev.Version == ve.Version {
									found = true
									break
								}
							}
							if !found {
								existing.Versions = append(existing.Versions, ve)
							}
						}
						if err := store.SavePackage(ctx, existing); err != nil {
							return fmt.Errorf("save %s/%s: %w", pm.Type, pm.Name, err)
						}
						fmt.Printf("Merged %d version(s) into %s/%s\n", len(pm.Versions), pm.Type, pm.Name)
					} else {
						pm.ConfigVersion = manifest.CurrentConfigVersion
						if err := store.SavePackage(ctx, pm); err != nil {
							return fmt.Errorf("save %s/%s: %w", pm.Type, pm.Name, err)
						}
						fmt.Printf("Imported %s/%s (%d version(s))\n", pm.Type, pm.Name, len(pm.Versions))
					}

					if err := store.SaveIndex(ctx); err != nil {
						return fmt.Errorf("save index: %w", err)
					}
					imported++

					// Audit.
					if adb != nil {
						afterJSON, _ := json.MarshalIndent(pm, "", "  ")
						_ = adb.Record(ctx, audit.Event{
							EventType: audit.EventCreate,
							PkgType:   pm.Type,
							PkgName:   pm.Name,
							Actor:     audit.CurrentActor(),
							Status:    "success",
							Details:   audit.FormatDiff(nil, afterJSON),
						})
					}
				}
			}

			if imported > 1 {
				fmt.Printf("Imported %d packages\n", imported)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&merge, "merge", false, "Merge versions into existing package instead of rejecting duplicates")
	return cmd
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

// decodeManifests accepts either a single PackageManifest object or a JSON
// array of them. The array form lets one file import many packages at once.
func decodeManifests(data []byte) ([]manifest.PackageManifest, error) {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var pms []manifest.PackageManifest
		if err := json.Unmarshal(data, &pms); err != nil {
			return nil, err
		}
		return pms, nil
	}
	var pm manifest.PackageManifest
	if err := json.Unmarshal(data, &pm); err != nil {
		return nil, err
	}
	return []manifest.PackageManifest{pm}, nil
}

// validateManifest reports whether a manifest is structurally storable,
// writing any non-fatal warning to out. It is the structure half of
// admit.Admit, exposed for callers that have no policy checker to run.
func validateManifest(pm *manifest.PackageManifest, cfg *config.Config, out io.Writer) error {
	res := admit.Admit(context.Background(), nil, nil, cfg, pm, "")
	for _, w := range res.Warnings {
		fmt.Fprintf(out, "%s/%s: %s\n", pm.Type, pm.Name, w)
	}
	if !res.OK() {
		return errors.New(res.Reason)
	}
	return nil
}

// checkBackendName rejects a name no configured backend answers to.
func checkBackendName(cfg *config.Config, name string) error {
	return admit.CheckBackendName(cfg, name)
}
