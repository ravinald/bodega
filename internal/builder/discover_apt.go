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
