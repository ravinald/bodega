package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/placement"
)

// groupMember is one package that names a group, and what the group does for
// it. Deciding is false when the group is outranked or dropped: a
// storage_policy beats it, and a directory-placed type never reaches it. A
// listing that showed membership alone would report forty packages held by a
// group that places thirty-eight of them.
type groupMember struct {
	Type     string
	Package  string
	Deciding bool
	Why      string // why the group does not decide, when it does not
}

func newGroupCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "group [NAME]",
		Short: "List storage groups, or the packages one holds",
		Long: `group lists the storage groups this install defines, or the packages in one.

A group is the level between the type rule and the package: storage_by_group
maps a group name to a backend, and a package joins one by naming it in
storage_groups. Moving a whole set is then one config edit rather than one
manifest edit per package.

With no argument, every group is listed with the backend it names and how many
packages name it. With a group name, every package in that group is listed.

Membership is not the same as placement, so each row says whether the group
actually decides for that package. A storage_policy on the package outranks
it, and pypi never reaches the group level at all — its wheels upload as one
directory, so a group holding pypi packages beside others would split the tree
the PEP 503 index is a listing over.

This is the WRITE side, like 'bodega pkg storage'. It says nothing about where
already-uploaded versions live; each records its own backend.`,
		Example: `  bodega pkg group
  bodega pkg group mirror-set`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}

			ctx := backgroundCtx()
			if len(args) == 0 {
				return printGroups(ctx, os.Stdout, cfg, store)
			}

			group := args[0]
			backend, ok := cfg.StorageByGroup[group]
			if !ok {
				return fmt.Errorf("unknown storage group %q — storage_by_group defines: %s",
					group, definedGroups(cfg))
			}
			members, err := groupMembers(ctx, cfg, store, group)
			if err != nil {
				return err
			}
			printGroupMembers(os.Stdout, group, backend, members)
			return nil
		},
	}
}

// printGroups writes one row per defined group. A group with no packages is
// still listed: an empty group is how a set is staged before the manifests
// join it, and omitting it would read as a config that did not load.
func printGroups(ctx context.Context, out io.Writer, cfg *config.Config, store *manifest.Store) error {
	if len(cfg.StorageByGroup) == 0 {
		fmt.Fprintln(out, "No storage groups: storage_by_group is empty.")
		return nil
	}

	names := make([]string, 0, len(cfg.StorageByGroup))
	for name := range cfg.StorageByGroup {
		names = append(names, name)
	}
	sort.Strings(names)

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "GROUP\tBACKEND\tPACKAGES\tDECIDING")
	for _, name := range names {
		members, err := groupMembers(ctx, cfg, store, name)
		if err != nil {
			return err
		}
		deciding := 0
		for _, m := range members {
			if m.Deciding {
				deciding++
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\n", name, cfg.StorageByGroup[name], len(members), deciding)
	}
	_ = tw.Flush()
	fmt.Fprintln(out, "\n'bodega pkg group NAME' lists one group's packages; 'bodega pkg storage TYPE NAME' resolves one package.")
	return nil
}

// groupMembers returns every package naming group, in catalog order.
func groupMembers(ctx context.Context, cfg *config.Config, store *manifest.Store, group string) ([]groupMember, error) {
	var out []groupMember
	for _, typ := range manifest.AllTypes {
		for _, pkg := range store.ListPackages(typ) {
			pm, err := store.GetPackage(ctx, typ, pkg)
			if err != nil {
				return out, fmt.Errorf("get %s/%s: %w", typ, pkg, err)
			}
			if pm == nil || !slices.Contains(pm.StorageGroups, group) {
				continue
			}
			m := groupMember{Type: typ, Package: pm.Name, Deciding: true}
			switch {
			case placement.DirectoryPlaced(typ):
				m.Deciding, m.Why = false, "not consulted for "+typ
			case pm.StoragePolicy != "":
				m.Deciding, m.Why = false, fmt.Sprintf("storage_policy %q outranks it", pm.StoragePolicy)
			case admit.GroupRule(cfg, pm.StorageGroups) != group:
				m.Deciding, m.Why = false, fmt.Sprintf("group %q wins by name", admit.GroupRule(cfg, pm.StorageGroups))
			}
			out = append(out, m)
		}
	}
	return out, nil
}

func printGroupMembers(out io.Writer, group, backend string, members []groupMember) {
	fmt.Fprintf(out, "%s -> %s (storage_by_group.%s)\n\n", group, backend, group)
	if len(members) == 0 {
		fmt.Fprintln(out, "No packages name this group in storage_groups.")
		return
	}

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TYPE\tPACKAGE\tDECIDES")
	for _, m := range members {
		decides := "yes"
		if !m.Deciding {
			decides = "no — " + m.Why
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", m.Type, m.Package, decides)
	}
	_ = tw.Flush()
}

// definedGroups lists the group names for an error message, sorted.
func definedGroups(cfg *config.Config) string {
	if len(cfg.StorageByGroup) == 0 {
		return "none"
	}
	names := make([]string, 0, len(cfg.StorageByGroup))
	for name := range cfg.StorageByGroup {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
