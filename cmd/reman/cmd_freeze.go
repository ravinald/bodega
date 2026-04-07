package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/manifest"
)

func newFreezeCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "freeze <type> <name>",
		Short: "Toggle the frozen flag on a manifest entry",
		Long: `freeze toggles the frozen flag on the named entry.

A frozen entry cannot be built, edited, or deleted. Running freeze on an
already-frozen entry unfreezes it.`,
		Example: `  reman freeze binary awscli-v2
  reman freeze git netbox`,
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

			switch t {
			case manifest.TypeApt:
				e := store.FindApt(name)
				if e == nil {
					return fmt.Errorf("apt entry %q not found", name)
				}
				e.Frozen = !e.Frozen
				printFreezeStatus(t, name, e.Frozen)
				return store.SaveApt()

			case manifest.TypeGit:
				e := store.FindGit(name)
				if e == nil {
					return fmt.Errorf("git entry %q not found", name)
				}
				e.Frozen = !e.Frozen
				printFreezeStatus(t, name, e.Frozen)
				return store.SaveGit()

			case manifest.TypeBinary:
				e := store.FindBinary(name)
				if e == nil {
					return fmt.Errorf("binary entry %q not found", name)
				}
				e.Frozen = !e.Frozen
				printFreezeStatus(t, name, e.Frozen)
				return store.SaveBinary()

			case manifest.TypePypi:
				store.Pypi.Frozen = !store.Pypi.Frozen
				printFreezeStatus(t, "pypi", store.Pypi.Frozen)
				return store.SavePypi()
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
