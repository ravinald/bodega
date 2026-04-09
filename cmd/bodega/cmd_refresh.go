package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scaleapi/bodega/internal/builder"
	"github.com/scaleapi/bodega/internal/manifest"
)

func newRefreshCmd(gf *globalFlags) *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "refresh [TYPE] [NAME]",
		Short: "Discover available versions from upstream registries",
		Long: `refresh queries upstream package registries for available versions matching
each entry's version constraint, and creates manifest records for new versions.

Without arguments, refreshes all entries across all types.
With a type argument, refreshes only entries of that type.
With type and name, refreshes only that specific package.

New versions are created as manifest records but not fetched until you run
'bodega fetch'. For proxy-mode entries, versions are served on demand.`,
		Example: `  bodega refresh
  bodega refresh pypi
  bodega refresh pypi django
  bodega refresh --force`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(gf)
			if err != nil {
				return err
			}
			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}

			typeFilter := ""
			nameFilter := ""
			if len(args) >= 1 {
				typeFilter = args[0]
			}
			if len(args) >= 2 {
				nameFilter = args[1]
			}

			_ = cfg // for future use

			return refreshEntries(store, typeFilter, nameFilter, force)
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Re-discover even if versions already exist")
	return cmd
}

func refreshEntries(store *manifest.Store, typeFilter, nameFilter string, force bool) error {
	ctx := context.Background()
	total := 0
	created := 0

	// PyPI
	if typeFilter == "" || typeFilter == manifest.TypePypi {
		pypiCreated := 0
		for _, safeName := range store.ListPackages(manifest.TypePypi) {
			pm, err := store.GetPackage(ctx, manifest.TypePypi, safeName)
			if err != nil || pm == nil {
				continue
			}
			if nameFilter != "" && !strings.EqualFold(pm.Name, nameFilter) {
				continue
			}
			for _, ve := range pm.Versions {
				if ve.VersionConstraint == "" || ve.VersionConstraint == manifest.ConstraintExact {
					continue
				}
				fmt.Printf("  [pypi] %s: querying upstream...\n", pm.Name)
				versions, err := builder.DiscoverPyPIVersions(pm.Name)
				if err != nil {
					fmt.Printf("  [pypi] %s: ERROR: %v\n", pm.Name, err)
					continue
				}
				filtered := builder.FilterVersions(versions, ve.VersionConstraint, ve.Version)
				for _, v := range filtered {
					newVE := manifest.VersionEntry{
						Version:           v,
						Mode:              ve.Mode,
						VersionConstraint: manifest.ConstraintExact,
						RequiredBy:        ve.RequiredBy,
					}
					if !force {
						existing, _ := store.FindVersion(ctx, manifest.TypePypi, pm.Name, v)
						if existing != nil {
							continue
						}
					}
					if err := store.AddVersion(ctx, manifest.TypePypi, pm.Name, newVE); err != nil {
						continue
					}
					fmt.Printf("  [pypi] %s: added version %s\n", pm.Name, v)
					pypiCreated++
				}
				total += len(filtered)
			}
		}
		if pypiCreated > 0 {
			if err := store.SaveIndex(ctx); err != nil {
				return fmt.Errorf("save pypi: %w", err)
			}
		}
		created += pypiCreated
	}

	// Gomod
	if typeFilter == "" || typeFilter == manifest.TypeGomod {
		gomodCreated := 0
		for _, safeName := range store.ListPackages(manifest.TypeGomod) {
			pm, err := store.GetPackage(ctx, manifest.TypeGomod, safeName)
			if err != nil || pm == nil {
				continue
			}
			if nameFilter != "" && pm.Name != nameFilter {
				continue
			}
			for _, ve := range pm.Versions {
				if ve.VersionConstraint == "" || ve.VersionConstraint == manifest.ConstraintExact {
					continue
				}
				fmt.Printf("  [gomod] %s: querying upstream...\n", pm.Name)
				versions, err := builder.DiscoverGomodVersions(pm.Name)
				if err != nil {
					fmt.Printf("  [gomod] %s: ERROR: %v\n", pm.Name, err)
					continue
				}
				filtered := builder.FilterVersions(versions, ve.VersionConstraint, ve.Version)
				for _, v := range filtered {
					newVE := manifest.VersionEntry{
						Version:           v,
						URL:               ve.URL,
						Mode:              ve.Mode,
						VersionConstraint: manifest.ConstraintExact,
					}
					if !force {
						existing, _ := store.FindVersion(ctx, manifest.TypeGomod, pm.Name, v)
						if existing != nil {
							continue
						}
					}
					if err := store.AddVersion(ctx, manifest.TypeGomod, pm.Name, newVE); err != nil {
						continue
					}
					fmt.Printf("  [gomod] %s: added version %s\n", pm.Name, v)
					gomodCreated++
				}
				total += len(filtered)
			}
		}
		if gomodCreated > 0 {
			if err := store.SaveIndex(ctx); err != nil {
				return fmt.Errorf("save gomod: %w", err)
			}
		}
		created += gomodCreated
	}

	// Npm
	if typeFilter == "" || typeFilter == manifest.TypeNpm {
		npmCreated := 0
		for _, safeName := range store.ListPackages(manifest.TypeNpm) {
			pm, err := store.GetPackage(ctx, manifest.TypeNpm, safeName)
			if err != nil || pm == nil {
				continue
			}
			if nameFilter != "" && pm.Name != nameFilter {
				continue
			}
			for _, ve := range pm.Versions {
				if ve.VersionConstraint == "" || ve.VersionConstraint == manifest.ConstraintExact {
					continue
				}
				fmt.Printf("  [npm] %s: querying upstream...\n", pm.Name)
				versions, err := builder.DiscoverNpmVersions(pm.Name)
				if err != nil {
					fmt.Printf("  [npm] %s: ERROR: %v\n", pm.Name, err)
					continue
				}
				filtered := builder.FilterVersions(versions, ve.VersionConstraint, ve.Version)
				for _, v := range filtered {
					newVE := manifest.VersionEntry{
						Version:           v,
						URL:               ve.URL,
						Mode:              ve.Mode,
						VersionConstraint: manifest.ConstraintExact,
					}
					if !force {
						existing, _ := store.FindVersion(ctx, manifest.TypeNpm, pm.Name, v)
						if existing != nil {
							continue
						}
					}
					if err := store.AddVersion(ctx, manifest.TypeNpm, pm.Name, newVE); err != nil {
						continue
					}
					fmt.Printf("  [npm] %s: added version %s\n", pm.Name, v)
					npmCreated++
				}
				total += len(filtered)
			}
		}
		if npmCreated > 0 {
			if err := store.SaveIndex(ctx); err != nil {
				return fmt.Errorf("save npm: %w", err)
			}
		}
		created += npmCreated
	}

	// Helm
	if typeFilter == "" || typeFilter == manifest.TypeHelm {
		helmCreated := 0
		for _, safeName := range store.ListPackages(manifest.TypeHelm) {
			pm, err := store.GetPackage(ctx, manifest.TypeHelm, safeName)
			if err != nil || pm == nil {
				continue
			}
			if nameFilter != "" && pm.Name != nameFilter {
				continue
			}
			for _, ve := range pm.Versions {
				if ve.VersionConstraint == "" || ve.VersionConstraint == manifest.ConstraintExact {
					continue
				}
				if ve.URL == "" {
					continue
				}
				fmt.Printf("  [helm] %s: querying upstream...\n", pm.Name)
				versions, err := builder.DiscoverHelmVersions(pm.Name, ve.URL)
				if err != nil {
					fmt.Printf("  [helm] %s: ERROR: %v\n", pm.Name, err)
					continue
				}
				filtered := builder.FilterVersions(versions, ve.VersionConstraint, ve.Version)
				for _, v := range filtered {
					newVE := manifest.VersionEntry{
						Version:           v,
						URL:               ve.URL,
						Mode:              ve.Mode,
						VersionConstraint: manifest.ConstraintExact,
					}
					if !force {
						existing, _ := store.FindVersion(ctx, manifest.TypeHelm, pm.Name, v)
						if existing != nil {
							continue
						}
					}
					if err := store.AddVersion(ctx, manifest.TypeHelm, pm.Name, newVE); err != nil {
						continue
					}
					fmt.Printf("  [helm] %s: added version %s\n", pm.Name, v)
					helmCreated++
				}
				total += len(filtered)
			}
		}
		if helmCreated > 0 {
			if err := store.SaveIndex(ctx); err != nil {
				return fmt.Errorf("save helm: %w", err)
			}
		}
		created += helmCreated
	}

	fmt.Printf("\nRefresh complete: %d versions discovered, %d new records created.\n", total, created)
	return nil
}
