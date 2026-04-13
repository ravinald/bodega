package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/manifest"
)

func newShowCmd(gf *globalFlags) *cobra.Command {
	show := &cobra.Command{
		Use:   "show",
		Short: "Display repository and package information",
	}
	show.AddCommand(
		newShowRepoCmd(gf),
		newShowPkgCmd(gf),
	)
	return show
}

// ---------- show repo (client view, excludes hidden) ----------

func newShowRepoCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "repo [TYPE] [PACKAGE] [VERSION]",
		Short: "Show repository contents (client view, excludes hidden)",
		Long: `Display what clients can install from this repository.
Hidden packages and versions are excluded.

  bodega show repo                       # all types with counts
  bodega show repo git                   # packages in git
  bodega show repo git netbox            # versions of netbox
  bodega show repo git netbox v4.5.7     # version details
  bodega show repo git json              # JSON output`,
		Args:                  cobra.ArbitraryArgs,
		DisableFlagsInUseLine: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := loadStore(gf)
			if err != nil {
				return err
			}
			ctx := context.Background()
			args, jsonOut := stripJSON(args)
			return runShow(ctx, store, args, false, jsonOut)
		},
	}
}

// ---------- show pkg (admin view, shows everything) ----------

func newShowPkgCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:     "pkg [TYPE] [PACKAGE] [VERSION|all]",
		Aliases: []string{"package"},
		Short:   "Show package configuration (admin view, includes hidden/frozen)",
		Long: `Display full package configuration including hidden versions,
frozen flags, build environment, and raw JSON.

  bodega show pkg                        # all types with counts
  bodega show pkg pypi                   # all pypi packages
  bodega show pkg pypi django            # django versions
  bodega show pkg pypi django all        # verbose with build_env
  bodega show pkg pypi django 5.2.12     # specific version detail
  bodega show pkg pypi django json       # JSON output`,
		Args:                  cobra.ArbitraryArgs,
		DisableFlagsInUseLine: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := loadStore(gf)
			if err != nil {
				return err
			}
			ctx := context.Background()
			args, jsonOut := stripJSON(args)
			return runShow(ctx, store, args, true, jsonOut)
		},
	}
}

// stripJSON checks if the last positional arg is "json" and removes it.
func stripJSON(args []string) ([]string, bool) {
	if len(args) > 0 && args[len(args)-1] == "json" {
		return args[:len(args)-1], true
	}
	return args, false
}

// runShow dispatches based on arg depth. admin=true shows hidden/frozen/build_env.
func runShow(ctx context.Context, store *manifest.Store, args []string, admin, jsonOut bool) error {
	switch len(args) {
	case 0:
		return showTypeSummary(ctx, store, admin, jsonOut)
	case 1:
		return showPackageList(ctx, store, args[0], admin, jsonOut)
	case 2:
		return showVersionList(ctx, store, args[0], args[1], admin, jsonOut)
	case 3:
		return showVersionDetail(ctx, store, args[0], args[1], args[2], admin, jsonOut)
	default:
		return fmt.Errorf("too many arguments")
	}
}

// ---------- depth 0: type summary ----------

func showTypeSummary(ctx context.Context, store *manifest.Store, admin, jsonOut bool) error {
	type typeStat struct {
		Type     string `json:"type"`
		Packages int    `json:"packages"`
		Versions int    `json:"versions"`
		Hidden   int    `json:"hidden,omitempty"`
	}
	var stats []typeStat

	for _, typ := range manifest.AllTypes {
		names := store.ListPackages(typ)
		versions := 0
		hidden := 0
		for _, name := range names {
			pm, err := store.GetPackage(ctx, typ, name)
			if err != nil || pm == nil {
				continue
			}
			for _, ve := range pm.Versions {
				if ve.Hidden {
					hidden++
					if !admin {
						continue
					}
				}
				versions++
			}
		}
		stats = append(stats, typeStat{Type: typ, Packages: len(names), Versions: versions, Hidden: hidden})
	}

	if jsonOut {
		return printJSON(stats)
	}

	if admin {
		fmt.Printf("%-10s %-10s %-10s %-10s\n", "TYPE", "PACKAGES", "VERSIONS", "HIDDEN")
	} else {
		fmt.Printf("%-10s %-10s %-10s\n", "TYPE", "PACKAGES", "VERSIONS")
	}
	for _, s := range stats {
		if admin {
			fmt.Printf("%-10s %-10d %-10d %-10d\n", s.Type, s.Packages, s.Versions, s.Hidden)
		} else {
			fmt.Printf("%-10s %-10d %-10d\n", s.Type, s.Packages, s.Versions)
		}
	}
	return nil
}

// ---------- depth 1: package list ----------

func showPackageList(ctx context.Context, store *manifest.Store, typ string, admin, jsonOut bool) error {
	if !isValidType(typ) {
		return fmt.Errorf("unknown type %q — must be one of: %s", typ, strings.Join(manifest.AllTypes, ", "))
	}

	type pkgInfo struct {
		Name        string `json:"name"`
		Description string `json:"description,omitempty"`
		Versions    int    `json:"versions"`
		Latest      string `json:"latest,omitempty"`
		Mode        string `json:"mode,omitempty"`
		Hidden      int    `json:"hidden,omitempty"`
	}
	var pkgs []pkgInfo

	for _, name := range store.ListPackages(typ) {
		pm, err := store.GetPackage(ctx, typ, name)
		if err != nil || pm == nil {
			continue
		}
		visibleVersions := 0
		hiddenVersions := 0
		latest := ""
		mode := ""
		for _, ve := range pm.Versions {
			if ve.Hidden {
				hiddenVersions++
				if !admin {
					continue
				}
			}
			visibleVersions++
			v := ve.Version
			if v == "" {
				v = ve.Ref
			}
			latest = v
			if mode == "" {
				mode = ve.EffectiveMode()
			}
		}
		if visibleVersions == 0 && !admin {
			continue
		}
		pkgs = append(pkgs, pkgInfo{
			Name:        pm.Name,
			Description: pm.Description,
			Versions:    visibleVersions,
			Latest:      latest,
			Mode:        mode,
			Hidden:      hiddenVersions,
		})
	}

	if jsonOut {
		return printJSON(pkgs)
	}

	if admin {
		fmt.Printf("%-35s %-10s %-12s %-10s %-8s\n", "PACKAGE", "VERSIONS", "LATEST", "MODE", "HIDDEN")
	} else {
		fmt.Printf("%-35s %-10s %-12s %-10s\n", "PACKAGE", "VERSIONS", "LATEST", "MODE")
	}
	for _, p := range pkgs {
		if admin {
			fmt.Printf("%-35s %-10d %-12s %-10s %-8d\n", p.Name, p.Versions, p.Latest, p.Mode, p.Hidden)
		} else {
			fmt.Printf("%-35s %-10d %-12s %-10s\n", p.Name, p.Versions, p.Latest, p.Mode)
		}
	}
	return nil
}

// ---------- depth 2: version list ----------

func showVersionList(ctx context.Context, store *manifest.Store, typ, name string, admin, jsonOut bool) error {
	pm, err := store.GetPackage(ctx, typ, name)
	if err != nil || pm == nil {
		return fmt.Errorf("%s/%s not found", typ, name)
	}

	if jsonOut {
		if admin {
			return printJSON(pm)
		}
		// Filter hidden for repo view.
		filtered := *pm
		filtered.Versions = nil
		for _, ve := range pm.Versions {
			if !ve.Hidden {
				filtered.Versions = append(filtered.Versions, ve)
			}
		}
		return printJSON(filtered)
	}

	fmt.Printf("Package: %s\n", pm.Name)
	if pm.Description != "" {
		fmt.Printf("Description: %s\n", pm.Description)
	}
	fmt.Println()

	if admin {
		fmt.Printf("%-12s %-15s %-6s %-8s %-8s %-10s\n", "VERSION", "PLATFORM", "S3", "FROZEN", "HIDDEN", "CONSTRAINT")
	} else {
		fmt.Printf("%-12s %-15s %-10s\n", "VERSION", "PLATFORM", "CONSTRAINT")
	}
	for _, ve := range pm.Versions {
		if ve.Hidden && !admin {
			continue
		}
		v := ve.Version
		if v == "" {
			v = ve.Ref
		}
		platform := ve.Platform
		if platform == "" {
			platform = "any"
		}
		constraint := ve.VersionConstraint
		if constraint == "" {
			constraint = "exact"
		}
		if admin {
			frozen := "no"
			if ve.Frozen {
				frozen = "yes"
			}
			hidden := "no"
			if ve.Hidden {
				hidden = "yes"
			}
			fmt.Printf("%-12s %-15s %-6s %-8s %-8s %-10s\n", v, platform, "-", frozen, hidden, constraint)
		} else {
			fmt.Printf("%-12s %-15s %-10s\n", v, platform, constraint)
		}
	}
	return nil
}

// ---------- depth 3: version detail or "all" ----------

func showVersionDetail(ctx context.Context, store *manifest.Store, typ, name, versionOrAll string, admin, jsonOut bool) error {
	pm, err := store.GetPackage(ctx, typ, name)
	if err != nil || pm == nil {
		return fmt.Errorf("%s/%s not found", typ, name)
	}

	if versionOrAll == "all" {
		// Show all versions verbosely.
		if jsonOut {
			return printJSON(pm)
		}
		fmt.Printf("Package: %s (%s)\n", pm.Name, pm.Type)
		if pm.Description != "" {
			fmt.Printf("Description: %s\n", pm.Description)
		}
		fmt.Printf("Versions: %d\n\n", len(pm.Versions))
		for i, ve := range pm.Versions {
			if ve.Hidden && !admin {
				continue
			}
			printVersionDetail(pm, ve, admin)
			if i < len(pm.Versions)-1 {
				fmt.Println("---")
			}
		}
		return nil
	}

	// Find specific version.
	for _, ve := range pm.Versions {
		v := ve.Version
		if v == "" {
			v = ve.Ref
		}
		if v == versionOrAll {
			if jsonOut {
				return printJSON(ve)
			}
			printVersionDetail(pm, ve, admin)
			return nil
		}
	}
	return fmt.Errorf("version %q not found in %s/%s", versionOrAll, typ, name)
}

func printVersionDetail(pm *manifest.PackageManifest, ve manifest.VersionEntry, admin bool) {
	v := ve.Version
	if v == "" {
		v = ve.Ref
	}
	fmt.Printf("Package:     %s\n", pm.Name)
	fmt.Printf("Type:        %s\n", pm.Type)
	fmt.Printf("Version:     %s\n", v)
	if ve.URL != "" {
		fmt.Printf("Source URL:  %s\n", ve.URL)
	}
	if ve.Ref != "" && ve.Ref != v {
		fmt.Printf("Ref:         %s\n", ve.Ref)
	}
	if ve.Platform != "" {
		fmt.Printf("Platform:    %s\n", ve.Platform)
	}
	if ve.Checksum != nil {
		fmt.Printf("Checksum:    %s:%s\n", ve.Checksum.Algorithm, ve.Checksum.Value)
		if ve.ChecksumVerified {
			fmt.Printf("Verified:    yes\n")
		} else {
			fmt.Printf("Verified:    no\n")
		}
	}
	constraint := ve.VersionConstraint
	if constraint == "" {
		constraint = "exact"
	}
	fmt.Printf("Constraint:  %s\n", constraint)
	if ve.Mode != "" {
		fmt.Printf("Mode:        %s\n", ve.Mode)
	}

	if admin {
		fmt.Printf("Frozen:      %v\n", ve.Frozen)
		fmt.Printf("Hidden:      %v\n", ve.Hidden)
	}

	if len(ve.RequiredBy) > 0 {
		fmt.Printf("Required by: %s\n", strings.Join(ve.RequiredBy, ", "))
	}

	if admin && ve.BuildEnv != nil {
		fmt.Println("Build Environment:")
		if ve.BuildEnv.OSRelease != "" {
			fmt.Printf("  OS:        %s\n", ve.BuildEnv.OSRelease)
		}
		if ve.BuildEnv.Python != "" {
			fmt.Printf("  Python:    %s\n", ve.BuildEnv.Python)
		}
		if ve.BuildEnv.Go != "" {
			fmt.Printf("  Go:        %s\n", ve.BuildEnv.Go)
		}
		if ve.BuildEnv.Rust != "" {
			fmt.Printf("  Rust:      %s\n", ve.BuildEnv.Rust)
		}
		if ve.BuildEnv.Bodega != "" {
			fmt.Printf("  Bodega:    %s\n", ve.BuildEnv.Bodega)
		}
		if ve.BuildEnv.BuiltAt != "" {
			fmt.Printf("  Built at:  %s\n", ve.BuildEnv.BuiltAt)
		}
	}

	// Type-specific fields.
	if ve.SourceName != "" {
		fmt.Printf("Package Name: %s\n", ve.SourceName)
	}
	if ve.BuildCmd != "" {
		fmt.Printf("Build Cmd:   %s\n", ve.BuildCmd)
	}
	if ve.Filename != "" {
		fmt.Printf("Filename:    %s\n", ve.Filename)
	}
	if ve.AppVersion != "" {
		fmt.Printf("App Version: %s\n", ve.AppVersion)
	}
	if len(ve.Metadata) > 0 {
		fmt.Println("Metadata:")
		keys := make([]string, 0, len(ve.Metadata))
		for k := range ve.Metadata {
			if k != "Description-Full" {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  %-16s %s\n", k+":", ve.Metadata[k])
		}
	}
	fmt.Println()
}

func printJSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// isValidType is defined in main.go
