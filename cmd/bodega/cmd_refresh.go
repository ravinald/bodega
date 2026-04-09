package main

import (
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
	total := 0
	created := 0

	// PyPI
	if typeFilter == "" || typeFilter == manifest.TypePypi {
		for _, pkg := range store.Pypi.Packages {
			if nameFilter != "" && !strings.EqualFold(pkg.Name, nameFilter) {
				continue
			}
			if pkg.VersionConstraint == "" || pkg.VersionConstraint == manifest.ConstraintExact {
				continue // exact constraint: nothing to discover
			}
			fmt.Printf("  [pypi] %s: querying upstream...\n", pkg.Name)
			versions, err := builder.DiscoverPyPIVersions(pkg.Name)
			if err != nil {
				fmt.Printf("  [pypi] %s: ERROR: %v\n", pkg.Name, err)
				continue
			}
			filtered := builder.FilterVersions(versions, pkg.VersionConstraint, pkg.Version)
			for _, v := range filtered {
				if !force && pypiVersionExists(store, pkg.Name, v) {
					continue
				}
				store.Pypi.Packages = append(store.Pypi.Packages, manifest.PypiPackage{
					Name:              pkg.Name,
					Version:           v,
					Mode:              pkg.Mode,
					VersionConstraint: manifest.ConstraintExact,
					RequiredBy:        pkg.RequiredBy,
				})
				fmt.Printf("  [pypi] %s: added version %s\n", pkg.Name, v)
				created++
			}
			total += len(filtered)
		}
		if created > 0 {
			if err := store.SavePypi(); err != nil {
				return fmt.Errorf("save pypi: %w", err)
			}
		}
	}

	// Gomod
	gomodCreated := 0
	if typeFilter == "" || typeFilter == manifest.TypeGomod {
		for _, entry := range store.Gomod {
			if nameFilter != "" && entry.Name != nameFilter {
				continue
			}
			if entry.VersionConstraint == "" || entry.VersionConstraint == manifest.ConstraintExact {
				continue
			}
			fmt.Printf("  [gomod] %s: querying upstream...\n", entry.Name)
			versions, err := builder.DiscoverGomodVersions(entry.Name)
			if err != nil {
				fmt.Printf("  [gomod] %s: ERROR: %v\n", entry.Name, err)
				continue
			}
			filtered := builder.FilterVersions(versions, entry.VersionConstraint, entry.Version)
			for _, v := range filtered {
				if !force && gomodVersionExists(store, entry.Name, v) {
					continue
				}
				store.Gomod = append(store.Gomod, manifest.GomodEntry{
					Name:              entry.Name,
					Version:           v,
					URL:               entry.URL,
					Mode:              entry.Mode,
					VersionConstraint: manifest.ConstraintExact,
				})
				fmt.Printf("  [gomod] %s: added version %s\n", entry.Name, v)
				gomodCreated++
			}
			total += len(filtered)
		}
		if gomodCreated > 0 {
			if err := store.SaveGomod(); err != nil {
				return fmt.Errorf("save gomod: %w", err)
			}
		}
		created += gomodCreated
	}

	// Npm
	npmCreated := 0
	if typeFilter == "" || typeFilter == manifest.TypeNpm {
		for _, entry := range store.Npm {
			if nameFilter != "" && entry.Name != nameFilter {
				continue
			}
			if entry.VersionConstraint == "" || entry.VersionConstraint == manifest.ConstraintExact {
				continue
			}
			fmt.Printf("  [npm] %s: querying upstream...\n", entry.Name)
			versions, err := builder.DiscoverNpmVersions(entry.Name)
			if err != nil {
				fmt.Printf("  [npm] %s: ERROR: %v\n", entry.Name, err)
				continue
			}
			filtered := builder.FilterVersions(versions, entry.VersionConstraint, entry.Version)
			for _, v := range filtered {
				if !force && npmVersionExists(store, entry.Name, v) {
					continue
				}
				store.Npm = append(store.Npm, manifest.NpmEntry{
					Name:              entry.Name,
					Version:           v,
					URL:               entry.URL,
					Mode:              entry.Mode,
					VersionConstraint: manifest.ConstraintExact,
				})
				fmt.Printf("  [npm] %s: added version %s\n", entry.Name, v)
				npmCreated++
			}
			total += len(filtered)
		}
		if npmCreated > 0 {
			if err := store.SaveNpm(); err != nil {
				return fmt.Errorf("save npm: %w", err)
			}
		}
		created += npmCreated
	}

	// Helm
	helmCreated := 0
	if typeFilter == "" || typeFilter == manifest.TypeHelm {
		for _, entry := range store.Helm {
			if nameFilter != "" && entry.Name != nameFilter {
				continue
			}
			if entry.VersionConstraint == "" || entry.VersionConstraint == manifest.ConstraintExact {
				continue
			}
			if entry.URL == "" {
				continue
			}
			fmt.Printf("  [helm] %s: querying upstream...\n", entry.Name)
			versions, err := builder.DiscoverHelmVersions(entry.Name, entry.URL)
			if err != nil {
				fmt.Printf("  [helm] %s: ERROR: %v\n", entry.Name, err)
				continue
			}
			filtered := builder.FilterVersions(versions, entry.VersionConstraint, entry.Version)
			for _, v := range filtered {
				if !force && helmVersionExists(store, entry.Name, v) {
					continue
				}
				store.Helm = append(store.Helm, manifest.HelmEntry{
					Name:              entry.Name,
					Version:           v,
					URL:               entry.URL,
					Mode:              entry.Mode,
					VersionConstraint: manifest.ConstraintExact,
				})
				fmt.Printf("  [helm] %s: added version %s\n", entry.Name, v)
				helmCreated++
			}
			total += len(filtered)
		}
		if helmCreated > 0 {
			if err := store.SaveHelm(); err != nil {
				return fmt.Errorf("save helm: %w", err)
			}
		}
		created += helmCreated
	}

	// Git
	gitCreated := 0
	if typeFilter == "" || typeFilter == manifest.TypeGit {
		for _, entry := range store.Git {
			if nameFilter != "" && entry.Name != nameFilter {
				continue
			}
			// Git entries with a branch ref (clone mode) don't need version discovery.
			// Only discover for release-mode entries with non-exact constraints.
			if !entry.IsRelease() {
				continue
			}
			// For git, VersionConstraint is on the entry too (reusing the field).
			// Skip exact-only entries.
			constraint := entry.Ref // base ref for filtering
			_ = constraint
			// Git doesn't have VersionConstraint field, so skip for now.
			// Future: could discover tags matching a pattern.
		}
		_ = gitCreated
	}

	fmt.Printf("\nRefresh complete: %d versions discovered, %d new records created.\n", total, created)
	return nil
}

func pypiVersionExists(store *manifest.Store, name, version string) bool {
	for _, p := range store.Pypi.Packages {
		if strings.EqualFold(p.Name, name) && p.Version == version {
			return true
		}
	}
	return false
}

func gomodVersionExists(store *manifest.Store, name, version string) bool {
	for _, e := range store.Gomod {
		if e.Name == name && e.Version == version {
			return true
		}
	}
	return false
}

func npmVersionExists(store *manifest.Store, name, version string) bool {
	for _, e := range store.Npm {
		if e.Name == name && e.Version == version {
			return true
		}
	}
	return false
}

func helmVersionExists(store *manifest.Store, name, version string) bool {
	for _, e := range store.Helm {
		if e.Name == name && e.Version == version {
			return true
		}
	}
	return false
}
