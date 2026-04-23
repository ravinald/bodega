package main

// pipeline.go contains reusable cascade helpers used by the build, package,
// and upload commands. Each helper checks whether a prerequisite stage's output
// already exists on disk and runs the stage only when it is absent.
//
// Design principle: helpers are per-type and accept an entryFilter string (the
// value of --entry). An empty filter means "all entries in the store."

import (
	"context"
	"fmt"

	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/manifest"
)

// ensureFetchedBinaries fetches any binary entries that have not yet been
// downloaded. Returns the combined summary of any fetch runs performed.
func ensureFetchedBinaries(bcfg *builder.Config, store *manifest.Store, entryFilter string) *builder.Summary {
	ctx := context.Background()
	var ss []*builder.Summary
	for _, safeName := range store.ListPackages(manifest.TypeBinary) {
		pm, err := store.GetPackage(ctx, manifest.TypeBinary, safeName)
		if err != nil || pm == nil {
			continue
		}
		if entryFilter != "" && pm.Name != entryFilter {
			continue
		}
		for _, ve := range pm.Versions {
			if ve.Frozen {
				continue
			}
			if !builder.CheckBinaryStage(bcfg, pm.Name, ve).Fetched {
				ss = append(ss, builder.FetchBinaries(bcfg, store, pm.Name))
				break
			}
		}
	}
	return builder.MergeSummaries(ss...)
}

// ensureFetchedGit fetches any git entries whose bare repository is absent.
func ensureFetchedGit(bcfg *builder.Config, store *manifest.Store, entryFilter string) *builder.Summary {
	ctx := context.Background()
	var ss []*builder.Summary
	for _, safeName := range store.ListPackages(manifest.TypeGit) {
		pm, err := store.GetPackage(ctx, manifest.TypeGit, safeName)
		if err != nil || pm == nil {
			continue
		}
		if entryFilter != "" && pm.Name != entryFilter {
			continue
		}
		for _, ve := range pm.Versions {
			if ve.Frozen {
				continue
			}
			if !builder.CheckGitStage(bcfg, pm.Name, ve).Fetched {
				ss = append(ss, builder.FetchGit(bcfg, store, pm.Name))
				break
			}
		}
	}
	return builder.MergeSummaries(ss...)
}

// ensureFetchedApt fetches any apt entries whose source directory (or .deb) is
// absent.
func ensureFetchedApt(bcfg *builder.Config, store *manifest.Store, entryFilter string) *builder.Summary {
	ctx := context.Background()
	var ss []*builder.Summary
	for _, safeName := range store.ListPackages(manifest.TypeApt) {
		pm, err := store.GetPackage(ctx, manifest.TypeApt, safeName)
		if err != nil || pm == nil {
			continue
		}
		if entryFilter != "" && pm.Name != entryFilter {
			continue
		}
		for _, ve := range pm.Versions {
			if ve.Frozen {
				continue
			}
			if !builder.CheckAptStage(bcfg, pm.Name, ve).Fetched {
				ss = append(ss, builder.FetchApt(bcfg, store, pm.Name))
				break
			}
		}
	}
	return builder.MergeSummaries(ss...)
}

// ensureFetchedPypi runs FetchPypi when combined-requirements.txt is absent.
func ensureFetchedPypi(bcfg *builder.Config, store *manifest.Store) *builder.Summary {
	if builder.CheckPypiStage(bcfg, store).Fetched {
		return &builder.Summary{}
	}
	return builder.FetchPypi(bcfg, store)
}

// ensureBuiltApt cascades: fetch first if needed, then build.
// Returns the combined summary of any stages run.
func ensureBuiltApt(bcfg *builder.Config, store *manifest.Store, entryFilter string) *builder.Summary {
	ctx := context.Background()
	var ss []*builder.Summary
	for _, safeName := range store.ListPackages(manifest.TypeApt) {
		pm, err := store.GetPackage(ctx, manifest.TypeApt, safeName)
		if err != nil || pm == nil {
			continue
		}
		if entryFilter != "" && pm.Name != entryFilter {
			continue
		}
		for _, ve := range pm.Versions {
			if ve.Frozen {
				continue
			}
			status := builder.CheckAptStage(bcfg, pm.Name, ve)
			if !status.Fetched {
				ss = append(ss, builder.FetchApt(bcfg, store, pm.Name))
			}
			if !status.Built {
				ss = append(ss, builder.BuildApt(bcfg, store, pm.Name))
			}
		}
	}
	return builder.MergeSummaries(ss...)
}

// ensureBuiltPypi cascades: fetch if needed, then build.
func ensureBuiltPypi(bcfg *builder.Config, store *manifest.Store) *builder.Summary {
	status := builder.CheckPypiStage(bcfg, store)
	var ss []*builder.Summary
	if !status.Fetched {
		s := builder.FetchPypi(bcfg, store)
		ss = append(ss, s)
		if s.HasFailures() {
			return builder.MergeSummaries(ss...)
		}
	}
	if !status.Built {
		ss = append(ss, builder.BuildPypi(bcfg, store))
	}
	return builder.MergeSummaries(ss...)
}

// ensurePackagedGit cascades fetch if needed, then packages.
func ensurePackagedGit(bcfg *builder.Config, store *manifest.Store, entryFilter string) *builder.Summary {
	ctx := context.Background()
	var ss []*builder.Summary
	for _, safeName := range store.ListPackages(manifest.TypeGit) {
		pm, err := store.GetPackage(ctx, manifest.TypeGit, safeName)
		if err != nil || pm == nil {
			continue
		}
		if entryFilter != "" && pm.Name != entryFilter {
			continue
		}
		for _, ve := range pm.Versions {
			if ve.Frozen {
				continue
			}
			status := builder.CheckGitStage(bcfg, pm.Name, ve)
			if !status.Fetched {
				ss = append(ss, builder.FetchGit(bcfg, store, pm.Name))
			}
			if !status.Packaged {
				ss = append(ss, builder.PackageGit(bcfg, store, pm.Name))
			}
		}
	}
	return builder.MergeSummaries(ss...)
}

// ensurePackagedApt cascades fetch → build → package as needed.
func ensurePackagedApt(bcfg *builder.Config, store *manifest.Store, entryFilter string) *builder.Summary {
	ctx := context.Background()
	var ss []*builder.Summary
	for _, safeName := range store.ListPackages(manifest.TypeApt) {
		pm, err := store.GetPackage(ctx, manifest.TypeApt, safeName)
		if err != nil || pm == nil {
			continue
		}
		if entryFilter != "" && pm.Name != entryFilter {
			continue
		}
		for _, ve := range pm.Versions {
			if ve.Frozen {
				continue
			}
			status := builder.CheckAptStage(bcfg, pm.Name, ve)
			if !status.Fetched {
				s := builder.FetchApt(bcfg, store, pm.Name)
				ss = append(ss, s)
				if s.HasFailures() {
					continue
				}
			}
			if !status.Built {
				s := builder.BuildApt(bcfg, store, pm.Name)
				ss = append(ss, s)
				if s.HasFailures() {
					continue
				}
			}
			if !status.Packaged {
				ss = append(ss, builder.PackageApt(bcfg, store, pm.Name))
			}
		}
	}
	return builder.MergeSummaries(ss...)
}

// ensureFetchedGomod fetches any gomod entries whose .info/.mod/.zip triplet
// is absent. gomod has no build or package step — the raw proxy artifacts are
// what clients consume.
func ensureFetchedGomod(bcfg *builder.Config, store *manifest.Store, entryFilter string) *builder.Summary {
	ctx := context.Background()
	var ss []*builder.Summary
	for _, safeName := range store.ListPackages(manifest.TypeGomod) {
		pm, err := store.GetPackage(ctx, manifest.TypeGomod, safeName)
		if err != nil || pm == nil {
			continue
		}
		if entryFilter != "" && pm.Name != entryFilter {
			continue
		}
		for _, ve := range pm.Versions {
			if ve.Frozen {
				continue
			}
			if !builder.CheckGomodStage(bcfg, pm.Name, ve).Fetched {
				ss = append(ss, builder.FetchGomod(bcfg, store, pm.Name))
				break
			}
		}
	}
	return builder.MergeSummaries(ss...)
}

// ensurePackagedHelm cascades fetch → package (the Helm index.yaml). When no
// helm entries are configured, skip the whole pipeline — PackageHelm writes an
// empty index.yaml which the caller doesn't need.
func ensurePackagedHelm(bcfg *builder.Config, store *manifest.Store, entryFilter string) *builder.Summary {
	if len(store.ListPackages(manifest.TypeHelm)) == 0 {
		fmt.Println("    No helm entries in manifest — skipping")
		return &builder.Summary{}
	}
	ctx := context.Background()
	var ss []*builder.Summary
	// Fetch missing charts.
	for _, safeName := range store.ListPackages(manifest.TypeHelm) {
		pm, err := store.GetPackage(ctx, manifest.TypeHelm, safeName)
		if err != nil || pm == nil {
			continue
		}
		if entryFilter != "" && pm.Name != entryFilter {
			continue
		}
		for _, ve := range pm.Versions {
			if ve.Frozen {
				continue
			}
			if !builder.CheckHelmStage(bcfg, pm.Name, ve).Fetched {
				ss = append(ss, builder.FetchHelm(bcfg, store, pm.Name))
				break
			}
		}
	}
	fetchSummary := builder.MergeSummaries(ss...)
	if fetchSummary.HasFailures() {
		return fetchSummary
	}
	// Always (re)generate the index after fetches.
	pkgSummary := builder.PackageHelm(bcfg, store)
	return builder.MergeSummaries(fetchSummary, pkgSummary)
}

// ensurePackagedNpm cascades fetch → package (per-package packument.json).
// Short-circuits when no npm entries are configured.
func ensurePackagedNpm(bcfg *builder.Config, store *manifest.Store, entryFilter string) *builder.Summary {
	if len(store.ListPackages(manifest.TypeNpm)) == 0 {
		fmt.Println("    No npm entries in manifest — skipping")
		return &builder.Summary{}
	}
	ctx := context.Background()
	var ss []*builder.Summary
	for _, safeName := range store.ListPackages(manifest.TypeNpm) {
		pm, err := store.GetPackage(ctx, manifest.TypeNpm, safeName)
		if err != nil || pm == nil {
			continue
		}
		if entryFilter != "" && pm.Name != entryFilter {
			continue
		}
		for _, ve := range pm.Versions {
			if ve.Frozen {
				continue
			}
			if !builder.CheckNpmStage(bcfg, pm.Name, ve).Fetched {
				ss = append(ss, builder.FetchNpm(bcfg, store, pm.Name))
				break
			}
		}
	}
	fetchSummary := builder.MergeSummaries(ss...)
	if fetchSummary.HasFailures() {
		return fetchSummary
	}
	pkgSummary := builder.PackageNpm(bcfg, store)
	return builder.MergeSummaries(fetchSummary, pkgSummary)
}

// ensurePackagedPypi cascades fetch → build → package as needed. When no pypi
// entries are configured, the whole pipeline is a no-op — otherwise PackagePypi
// would fail on "no .whl files" and abort the enclosing upload run.
func ensurePackagedPypi(bcfg *builder.Config, store *manifest.Store) *builder.Summary {
	if len(store.ListPackages(manifest.TypePypi)) == 0 {
		fmt.Println("    No pypi entries in manifest — skipping")
		return &builder.Summary{}
	}
	status := builder.CheckPypiStage(bcfg, store)
	var ss []*builder.Summary
	if !status.Fetched {
		s := builder.FetchPypi(bcfg, store)
		ss = append(ss, s)
		if s.HasFailures() {
			return builder.MergeSummaries(ss...)
		}
	}
	if !status.Built {
		s := builder.BuildPypi(bcfg, store)
		ss = append(ss, s)
		if s.HasFailures() {
			return builder.MergeSummaries(ss...)
		}
	}
	if !status.Packaged {
		ss = append(ss, builder.PackagePypi(bcfg, store))
	}
	return builder.MergeSummaries(ss...)
}
