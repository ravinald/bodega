package main

// pipeline.go contains reusable cascade helpers used by the build, package,
// and upload commands. Each helper checks whether a prerequisite stage's output
// already exists on disk and runs the stage only when it is absent.
//
// Design principle: helpers are per-type and accept an entryFilter string (the
// value of --entry). An empty filter means "all entries in the store."

import (
	"github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/builder"
	"github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/manifest"
)

// ensureFetchedBinaries fetches any binary entries that have not yet been
// downloaded. Returns the combined summary of any fetch runs performed.
func ensureFetchedBinaries(bcfg *builder.Config, store *manifest.Store, entryFilter string) *builder.Summary {
	var ss []*builder.Summary
	for _, entry := range store.Binary {
		if entryFilter != "" && entry.Name != entryFilter {
			continue
		}
		if entry.Frozen {
			continue
		}
		if !builder.CheckBinaryStage(bcfg, entry).Fetched {
			ss = append(ss, builder.FetchBinaries(bcfg, store, entry.Name))
		}
	}
	return builder.MergeSummaries(ss...)
}

// ensureFetchedGit fetches any git entries whose bare repository is absent.
func ensureFetchedGit(bcfg *builder.Config, store *manifest.Store, entryFilter string) *builder.Summary {
	var ss []*builder.Summary
	for _, entry := range store.Git {
		if entryFilter != "" && entry.Name != entryFilter {
			continue
		}
		if entry.Frozen {
			continue
		}
		if !builder.CheckGitStage(bcfg, entry).Fetched {
			ss = append(ss, builder.FetchGit(bcfg, store, entry.Name))
		}
	}
	return builder.MergeSummaries(ss...)
}

// ensureFetchedApt fetches any apt entries whose source directory (or .deb) is
// absent.
func ensureFetchedApt(bcfg *builder.Config, store *manifest.Store, entryFilter string) *builder.Summary {
	var ss []*builder.Summary
	for _, entry := range store.Apt {
		if entryFilter != "" && entry.Name != entryFilter {
			continue
		}
		if entry.Frozen {
			continue
		}
		if !builder.CheckAptStage(bcfg, entry).Fetched {
			ss = append(ss, builder.FetchApt(bcfg, store, entry.Name))
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
	var ss []*builder.Summary
	for _, entry := range store.Apt {
		if entryFilter != "" && entry.Name != entryFilter {
			continue
		}
		if entry.Frozen {
			continue
		}
		status := builder.CheckAptStage(bcfg, entry)
		if !status.Fetched {
			ss = append(ss, builder.FetchApt(bcfg, store, entry.Name))
		}
		if !status.Built {
			ss = append(ss, builder.BuildApt(bcfg, store, entry.Name))
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
	var ss []*builder.Summary
	for _, entry := range store.Git {
		if entryFilter != "" && entry.Name != entryFilter {
			continue
		}
		if entry.Frozen {
			continue
		}
		status := builder.CheckGitStage(bcfg, entry)
		if !status.Fetched {
			ss = append(ss, builder.FetchGit(bcfg, store, entry.Name))
		}
		if !status.Packaged {
			ss = append(ss, builder.PackageGit(bcfg, store, entry.Name))
		}
	}
	return builder.MergeSummaries(ss...)
}

// ensurePackagedApt cascades fetch → build → package as needed.
func ensurePackagedApt(bcfg *builder.Config, store *manifest.Store, entryFilter string) *builder.Summary {
	var ss []*builder.Summary
	for _, entry := range store.Apt {
		if entryFilter != "" && entry.Name != entryFilter {
			continue
		}
		if entry.Frozen {
			continue
		}
		status := builder.CheckAptStage(bcfg, entry)
		if !status.Fetched {
			s := builder.FetchApt(bcfg, store, entry.Name)
			ss = append(ss, s)
			if s.HasFailures() {
				continue
			}
		}
		if !status.Built {
			s := builder.BuildApt(bcfg, store, entry.Name)
			ss = append(ss, s)
			if s.HasFailures() {
				continue
			}
		}
		if !status.Packaged {
			ss = append(ss, builder.PackageApt(bcfg, store, entry.Name))
		}
	}
	return builder.MergeSummaries(ss...)
}

// ensurePackagedPypi cascades fetch → build → package as needed.
func ensurePackagedPypi(bcfg *builder.Config, store *manifest.Store) *builder.Summary {
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
