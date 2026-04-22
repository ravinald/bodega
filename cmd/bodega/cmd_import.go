package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

func newImportCmd(gf *globalFlags) *cobra.Command {
	var merge bool

	cmd := &cobra.Command{
		Use:   "import <file> [file...]",
		Short: "Import package manifests from JSON files",
		Long: `import reads one or more JSON files (or stdin with "-") and adds them to
the manifest store. The JSON format is the same PackageManifest used internally.

Use this for automation instead of the interactive 'create' command.

Examples:
  bodega pkg import nginx.json
  bodega pkg import packages/*.json
  cat manifest.json | bodega pkg import -
  bodega pkg import --merge updated.json    # add versions to existing package`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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

				var pm manifest.PackageManifest
				if err := json.Unmarshal(data, &pm); err != nil {
					return fmt.Errorf("parse %s: %w", path, err)
				}

				if err := validateManifest(&pm); err != nil {
					return fmt.Errorf("validate %s: %w", path, err)
				}
				if err := enforceImportPolicy(ctx, checker, adb, &pm); err != nil {
					return fmt.Errorf("%s: %w", path, err)
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
					if err := store.SavePackage(ctx, &pm); err != nil {
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
					afterJSON, _ := json.MarshalIndent(&pm, "", "  ")
					_ = adb.Record(ctx, audit.Event{
						EventType: audit.EventCreate,
						PkgType:   pm.Type,
						PkgName:   pm.Name,
						Status:    "success",
						Details:   audit.FormatDiff(nil, afterJSON),
					})
				}
			}

			if imported > 1 {
				fmt.Printf("Imported %d packages\n", imported)
			}
			notifyServer(gf)
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

// enforceImportPolicy walks every version in pm and rejects the import if any
// upstream candidate is outside the configured allow-list. Nil checker means
// policy is disabled.
func enforceImportPolicy(ctx context.Context, checker *policy.Checker, adb *audit.DB, pm *manifest.PackageManifest) error {
	if checker == nil {
		return nil
	}
	for _, ve := range pm.Versions {
		candidate := policy.CandidateFor(pm.Type, pm.Name, ve.URL)
		if candidate == "" {
			continue
		}
		if err := checker.Check(ctx, pm.Type, candidate); err != nil {
			if adb != nil {
				_ = adb.Record(ctx, audit.Event{
					EventType:  audit.EventCreate,
					PkgType:    pm.Type,
					PkgName:    pm.Name,
					PkgVersion: ve.Version,
					Status:     "policy_violation",
					Details:    fmt.Sprintf("candidate=%s", candidate),
				})
			}
			return err
		}
	}
	return nil
}

func validateManifest(pm *manifest.PackageManifest) error {
	if pm.Name == "" {
		return fmt.Errorf("name is required")
	}
	if pm.Type == "" {
		return fmt.Errorf("type is required")
	}
	valid := false
	for _, t := range manifest.AllTypes {
		if pm.Type == t {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("unknown type %q — must be one of: %s", pm.Type, strings.Join(manifest.AllTypes, ", "))
	}
	return nil
}
