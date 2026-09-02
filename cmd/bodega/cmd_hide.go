package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
)

func newHideCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hide TYPE NAME [VERSION]",
		Short: "Toggle the hidden flag on a package or version",
		Long: `hide toggles the hidden flag on a package. Hidden packages are not served
to clients but remain in the manifest for record-keeping.

When VERSION is given, only that specific version is toggled.
Without VERSION, all versions of the package are toggled.`,
		Example: `  bodega pkg hide pypi django
  bodega pkg hide pypi django 5.2.12`,
		Args: cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			t := args[0]
			name := args[1]
			version := ""
			if len(args) == 3 {
				version = args[2]
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
