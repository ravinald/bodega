package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/server"
)

func newHideCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hide TYPE NAME [VERSION]",
		Short: "Toggle the hidden flag on a package or version",
		Long: `hide toggles the hidden flag on a package. Hidden packages are not served
to clients but remain in the manifest for record-keeping.

When VERSION is given, only that specific version is toggled.
Without VERSION, all versions of the package are toggled.

An apt package served only from a mirrored codename has no manifest entry.
For one of those, VERSION is required: hide checks that a mirrored codename's
Packages lists that version, then records a server-wide hide. Every apt index
bodega serves drops the version, the mirrored codename carrying it is rewritten
and re-signed with bodega's apt key, and /apt/pool/ refuses the .deb with 403.
Running it again removes the hide.`,
		Example: `  bodega pkg hide pypi django
  bodega pkg hide pypi django 5.2.12
  bodega pkg hide apt php8.5-fpm 8.5.4-0ubuntu1`,
		Args: cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			t := args[0]
			name := args[1]
			version := ""
			if len(args) == 3 {
				version = args[2]
			}

			if t == manifest.TypeGomod {
				if err := manifest.ValidateGomodName(name); err != nil {
					return err
				}
			}

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
			pm, err := store.GetPackage(ctx, t, name)
			if err != nil {
				return fmt.Errorf("get %s/%s: %w", t, name, err)
			}
			if t == manifest.TypeApt && version != "" && !hasVersion(pm, version) {
				return toggleMirroredAptHide(ctx, gf, cfg, name, version)
			}
			if pm == nil {
				return fmt.Errorf("%s/%s not found", t, name)
			}

			beforeJSON, _ := json.MarshalIndent(pm, "", "  ")

			toggled := 0
			for i := range pm.Versions {
				ve := &pm.Versions[i]
				if version != "" && ve.Version != version && ve.Ref != version {
					continue
				}
				ve.Hidden = !ve.Hidden
				state := "hidden"
				if !ve.Hidden {
					state = "visible"
				}
				v := ve.Version
				if v == "" {
					v = ve.Ref
				}
				fmt.Printf("%s/%s@%s is now %s\n", t, name, v, state)
				toggled++
			}

			if toggled == 0 {
				return fmt.Errorf("no matching version found for %s/%s@%s", t, name, version)
			}

			if err := store.SavePackage(ctx, pm); err != nil {
				return fmt.Errorf("save: %w", err)
			}

			if adb := openAuditDB(gf); adb != nil {
				afterJSON, _ := json.MarshalIndent(pm, "", "  ")
				_ = adb.Record(ctx, audit.Event{
					EventType: audit.EventHide,
					PkgType:   t,
					PkgName:   name,
					Actor:     audit.CurrentActor(),
					Status:    "success",
					Details:   audit.FormatDiff(beforeJSON, afterJSON),
				})
				adb.Close()
			}
			return nil
		},
	}
	return cmd
}

// hasVersion reports whether a manifest carries the version, by the match the
// manifest toggle uses.
func hasVersion(pm *manifest.PackageManifest, version string) bool {
	if pm == nil {
		return false
	}
	for _, ve := range pm.Versions {
		if ve.Version == version || ve.Ref == version {
			return true
		}
	}
	return false
}

// toggleMirroredAptHide hides or unhides one version of an apt package that no
// manifest entry describes. The record lives in the audit store, which the
// server reads at every index rebuild; the reload this verb signals is that
// rebuild.
func toggleMirroredAptHide(ctx context.Context, gf *globalFlags, cfg *config.Config, name, version string) error {
	adb, err := openAuditDBErr(gf)
	if err != nil {
		return err
	}
	if adb == nil {
		return fmt.Errorf("apt/%s %s is in no manifest, and a mirrored version's hide is recorded in the audit store, which this config does not name: set audit_db or log_dir", name, version)
	}
	defer adb.Close()

	existing, hidden, err := adb.GetAptMirrorHide(ctx, name, version)
	if err != nil {
		return err
	}
	if hidden {
		if _, err := adb.DeleteAptMirrorHide(ctx, name, version); err != nil {
			return fmt.Errorf("remove the hide on apt/%s %s: %w", name, version, err)
		}
		fmt.Printf("apt/%s@%s is now visible (mirrored; hidden by %s at %s)\n",
			name, version, existing.HiddenBy, existing.HiddenAt.UTC().Format(time.RFC3339))
		recordMirroredHide(ctx, adb, name, version, "visible", existing.Codenames)
		return nil
	}

	codenames, err := server.LocateMirroredAptVersion(ctx, cfg, adb, name, version)
	if err != nil {
		return err
	}
	if err := adb.InsertAptMirrorHide(ctx, audit.AptMirrorHide{
		Name: name, Version: version, Codenames: codenames, HiddenBy: audit.CurrentActor(),
	}); err != nil {
		return fmt.Errorf("record the hide on apt/%s %s: %w", name, version, err)
	}
	fmt.Printf("apt/%s@%s is now hidden (mirrored from %s)\n", name, version, strings.Join(codenames, " "))
	recordMirroredHide(ctx, adb, name, version, "hidden", codenames)
	return nil
}

func recordMirroredHide(ctx context.Context, adb *audit.DB, name, version, state string, codenames []string) {
	details, _ := json.Marshal(map[string]string{
		"mirrored":  "true",
		"state":     state,
		"codenames": strings.Join(codenames, " "),
	})
	_ = adb.Record(ctx, audit.Event{
		EventType:  audit.EventHide,
		PkgType:    manifest.TypeApt,
		PkgName:    name,
		PkgVersion: version,
		Actor:      audit.CurrentActor(),
		Status:     "success",
		Details:    string(details),
	})
}
