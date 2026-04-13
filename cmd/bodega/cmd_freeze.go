package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/audit"
)

func newFreezeCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "freeze <type> <name>",
		Short: "Toggle the frozen flag on a manifest entry",
		Long: `freeze toggles the frozen flag on the named entry.

A frozen entry cannot be built, edited, or deleted. Running freeze on an
already-frozen entry unfreezes it.`,
		Example: `  bodega freeze binary awscli-v2
  bodega freeze git netbox`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, name := args[0], args[1]
			if !isValidType(t) {
				return fmt.Errorf("unknown type %q", t)
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
				return fmt.Errorf("%s entry %q not found", t, name)
			}

			beforeJSON, _ := json.MarshalIndent(pm, "", "  ")

			// Toggle: if all versions are frozen, unfreeze; otherwise freeze all.
			allFrozen := len(pm.Versions) > 0
			for _, ve := range pm.Versions {
				if !ve.Frozen {
					allFrozen = false
					break
				}
			}
			newState := !allFrozen
			for i := range pm.Versions {
				pm.Versions[i].Frozen = newState
			}
			if err := store.SavePackage(ctx, pm); err != nil {
				return err
			}
			printFreezeStatus(t, name, newState)

			if adb := openAuditDB(gf); adb != nil {
				afterJSON, _ := json.MarshalIndent(pm, "", "  ")
				_ = adb.Record(ctx, audit.Event{
					EventType: audit.EventFreeze,
					PkgType:   t,
					PkgName:   name,
					Status:    "success",
					Details:   audit.FormatDiff(beforeJSON, afterJSON),
				})
				adb.Close()
			}
			return nil
		},
	}
}

func printFreezeStatus(t, name string, frozen bool) {
	state := "frozen"
	if !frozen {
		state = "unfrozen"
	}
	fmt.Printf("%s/%s is now %s.\n", t, name, state)
}
