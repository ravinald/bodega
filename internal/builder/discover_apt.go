package builder

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"

	"github.com/scaleapi/bodega/internal/manifest"
)

// DiscoverAptDeps queries the local apt cache to find dependencies of pkgName.
// depth is "direct" for immediate deps only, or "transitive" for the full
// closure. Returns nil if apt-cache is not available (e.g. macOS).
func DiscoverAptDeps(store *manifest.Store, pkgName, depth string, out io.Writer) []DiscoveredDep {
	ctx := context.Background()

	if _, err := exec.LookPath("apt-cache"); err != nil {
		_, _ = fmt.Fprintf(out, "  [apt] apt-cache not found; skipping dependency discovery\n")
		return nil
	}

	recurse := depth == "transitive"

	args := []string{"depends",
		"--no-recommends", "--no-suggests",
		"--no-conflicts", "--no-breaks",
		"--no-replaces", "--no-enhances",
	}
	if recurse {
		args = append(args, "--recurse")
	}
	args = append(args, pkgName)

	_, _ = fmt.Fprintf(out, "  [apt] resolving %s dependencies for %s\n", depth, pkgName)

	cmd := exec.Command("apt-cache", args...)
	output, err := cmd.Output()
	if err != nil {
		_, _ = fmt.Fprintf(out, "  [apt] ERROR: apt-cache depends failed: %v\n", err)
		return nil
	}

	names := parseAptCacheDepends(string(output), pkgName)
	_, _ = fmt.Fprintf(out, "  [apt] found %d dependencies\n", len(names))

	var deps []DiscoveredDep
	for _, name := range names {
		d := DiscoveredDep{
			Ecosystem:  manifest.TypeApt,
			Name:       name,
			RawSpec:    name,
			RequiredBy: "apt/" + pkgName,
		}
		// Check if already in the store.
		if pm, err := store.GetPackage(ctx, manifest.TypeApt, name); err == nil && pm != nil {
			d.Exists = true
		}
		deps = append(deps, d)
	}

	return deps
}

// parseAptCacheDepends parses the output of `apt-cache depends` (with or
// without --recurse) and returns a deduplicated, sorted list of concrete
// package names. Virtual packages (angle-bracket names) and the queried
// package itself are filtered out.
//
// Sample non-recursive output:
//
//	curl
//	  Depends: libc6
//	  Depends: libcurl4t64
//	  Depends: zlib1g
//	  PreDepends: dpkg
//
// Sample recursive output (indented deps, package headers flush-left):
//
//	curl
//	  Depends: libc6
//	  Depends: libcurl4t64
//	libc6
//	  Depends: libgcc-s1
//	  PreDepends: <libc-any>
func parseAptCacheDepends(output, self string) []string {
	seen := make(map[string]bool)
	seen[self] = true // exclude the queried package

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Lines that start without a dep type prefix are package headers
		// in recursive output (e.g. "libc6"). These are themselves deps.
		if !strings.Contains(line, ":") {
			name := strings.TrimSpace(line)
			if name != "" && !isVirtualPkg(name) && !seen[name] {
				seen[name] = true
			}
			continue
		}

		// Dependency lines: "  Depends: libfoo" or "  PreDepends: libbar"
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		depType := strings.TrimSpace(parts[0])
		depName := strings.TrimSpace(parts[1])

		// Only process hard dependencies.
		switch depType {
		case "Depends", "PreDepends":
			// ok
		default:
			continue
		}

		if depName == "" || isVirtualPkg(depName) || seen[depName] {
			continue
		}
		seen[depName] = true
	}

	// Remove self from the result set (it was added to prevent self-reference).
	delete(seen, self)

	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// isVirtualPkg returns true for virtual package names like "<libc-dev>".
func isVirtualPkg(name string) bool {
	return strings.HasPrefix(name, "<") && strings.HasSuffix(name, ">")
}

// ImportAptDeps creates manifest entries and graph edges for discovered apt
// dependencies. Only imports deps where Exists is false. Returns count added.
func ImportAptDeps(ctx context.Context, store *manifest.Store, parentName string, deps []DiscoveredDep, out io.Writer) int {
	added := 0
	for _, d := range deps {
		if d.Exists {
			_, _ = fmt.Fprintf(out, "  [apt] %s: already in store, skipping\n", d.Name)
			continue
		}
		ve := manifest.VersionEntry{
			SourceName: d.Name,
			RequiredBy: []string{d.RequiredBy},
		}
		if err := store.AddVersion(ctx, manifest.TypeApt, d.Name, ve); err != nil {
			_, _ = fmt.Fprintf(out, "  [apt] WARNING: could not add %s: %v\n", d.Name, err)
			continue
		}
		added++

		// Add dependency graph edge.
		store.AddEdge(manifest.DepEdge{
			Parent:  "apt/" + parentName,
			Child:   "apt/" + d.Name,
			RawSpec: d.Name,
		})
	}

	if added > 0 {
		_, _ = fmt.Fprintf(out, "  [apt] added %d new packages\n", added)
		if err := store.SaveIndex(ctx); err != nil {
			_, _ = fmt.Fprintf(out, "  [apt] WARNING: could not save index: %v\n", err)
		}
		if err := store.SaveGraph(ctx); err != nil {
			_, _ = fmt.Fprintf(out, "  [apt] WARNING: could not save dependency graph: %v\n", err)
		}
	}

	return added
}

// ValidateAptPackage checks if a package exists in the local apt cache.
// Returns an error message string, or "" if valid.
func ValidateAptPackage(pkgName string) string {
	if _, err := exec.LookPath("apt-cache"); err != nil {
		return "" // can't validate, don't block
	}
	cmd := exec.Command("apt-cache", "show", pkgName)
	if err := cmd.Run(); err != nil {
		return fmt.Sprintf("package %q not found in apt cache", pkgName)
	}
	return ""
}

// ValidateAptSource checks if a source package exists in the local apt cache.
// Returns an error message string, or "" if valid.
func ValidateAptSource(pkgName string) string {
	if _, err := exec.LookPath("apt-cache"); err != nil {
		return "" // can't validate, don't block
	}
	cmd := exec.Command("apt-cache", "showsrc", pkgName)
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return fmt.Sprintf("source package %q not found in apt cache", pkgName)
	}
	return ""
}

// ResolveAptVersion queries the local apt cache for the candidate version of
// a package (what would be installed by `apt-get install`). Returns empty
// string if apt-cache is unavailable or the package is not found.
func ResolveAptVersion(pkgName string) string {
	if _, err := exec.LookPath("apt-cache"); err != nil {
		return ""
	}
	cmd := exec.Command("apt-cache", "policy", pkgName)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	// Parse "Candidate: 3.12.3-0ubuntu2.1" from apt-cache policy output.
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Candidate:") {
			ver := strings.TrimSpace(strings.TrimPrefix(line, "Candidate:"))
			if ver != "(none)" {
				return ver
			}
		}
	}
	return ""
}

// FetchAptMetadata runs `apt-cache show <pkgName>` and parses the output into
// a VersionEntry populated with Description, Platform, and Metadata map.
// Returns nil if apt-cache is unavailable or the package is not found.
func FetchAptMetadata(pkgName string) *manifest.VersionEntry {
	if _, err := exec.LookPath("apt-cache"); err != nil {
		return nil
	}
	cmd := exec.Command("apt-cache", "show", pkgName)
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return nil
	}
	return parseAptShowOutput(string(out), pkgName)
}

// parseAptShowOutput parses the output of `apt-cache show` into a VersionEntry.
// Extracts Version, Description, Architecture, and all other fields into Metadata.
//
// Sample output:
//
//	Package: python3
//	Version: 3.12.3-0ubuntu2.1
//	Architecture: amd64
//	Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
//	Installed-Size: 92
//	Section: python
//	Priority: important
//	Description: interactive high-level object-oriented language (default version)
//	 Python, the high-level, interactive object oriented language,
//	 includes an extensive class library with lots of goodies.
func parseAptShowOutput(output, pkgName string) *manifest.VersionEntry {
	ve := &manifest.VersionEntry{
		SourceName: pkgName,
		Metadata:   make(map[string]string),
	}

	// Fields we promote to VersionEntry fields rather than Metadata.
	promoted := map[string]bool{
		"Package": true, "Version": true, "Description": true,
		"Architecture": true,
	}

	lines := strings.Split(output, "\n")
	var currentKey string
	var descLines []string
	inDescription := false

	for _, line := range lines {
		// Continuation lines start with a space (part of multi-line Description).
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if inDescription {
				descLines = append(descLines, strings.TrimSpace(line))
			}
			continue
		}

		// End of previous multi-line field.
		inDescription = false

		// Empty line or new package stanza — stop at first stanza.
		if line == "" {
			if ve.Version != "" {
				break // we have a complete stanza
			}
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		currentKey = key

		switch key {
		case "Version":
			ve.Version = val
		case "Architecture":
			ve.Platform = "linux/" + val
			ve.Metadata[key] = val
		case "Description":
			// First line of description.
			descLines = []string{val}
			inDescription = true
		default:
			if !promoted[key] {
				ve.Metadata[key] = val
			}
		}
		_ = currentKey // used implicitly by continuation handling
	}

	// Set description from collected lines.
	if len(descLines) > 0 {
		ve.Description = descLines[0] // short description (first line)
		// Store full description in metadata if multi-line.
		if len(descLines) > 1 {
			ve.Metadata["Description-Full"] = strings.Join(descLines, "\n")
		}
	}

	if ve.Version == "" {
		return nil
	}
	return ve
}

// ResolveAndCreateConcreteVersion queries apt for the concrete version of a
// package and creates a fully-populated VersionEntry. Called after creating
// a * (any) policy entry to auto-create the resolved version alongside it.
func ResolveAndCreateConcreteVersion(ctx context.Context, store *manifest.Store, pkgName string, out io.Writer) {
	version := ResolveAptVersion(pkgName)
	if version == "" {
		_, _ = fmt.Fprintf(out, "  [apt] could not resolve version for %s\n", pkgName)
		return
	}

	// Check if this concrete version already exists.
	if pm, err := store.GetPackage(ctx, manifest.TypeApt, pkgName); err == nil && pm != nil {
		for _, ve := range pm.Versions {
			if ve.Version == version {
				_, _ = fmt.Fprintf(out, "  [apt] %s@%s already exists\n", pkgName, version)
				return
			}
		}
	}

	// Fetch full metadata.
	ve := FetchAptMetadata(pkgName)
	if ve == nil {
		// Fallback: create with just the version.
		ve = &manifest.VersionEntry{
			Version:    version,
			SourceName: pkgName,
		}
	}

	if err := store.AddVersion(ctx, manifest.TypeApt, pkgName, *ve); err != nil {
		_, _ = fmt.Fprintf(out, "  [apt] WARNING: could not add %s@%s: %v\n", pkgName, version, err)
		return
	}

	_, _ = fmt.Fprintf(out, "  [apt] resolved %s → %s\n", pkgName, version)

	// Also set the package-level description if not already set.
	if ve.Description != "" {
		if pm, err := store.GetPackage(ctx, manifest.TypeApt, pkgName); err == nil && pm != nil {
			if pm.Description == "" {
				pm.Description = ve.Description
				_ = store.SavePackage(ctx, pm)
			}
		}
	}
}
