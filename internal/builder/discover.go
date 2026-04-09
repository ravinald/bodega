package builder

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/scaleapi/bodega/internal/manifest"
)

// DiscoveredDep represents a single dependency found during source scanning.
type DiscoveredDep struct {
	Ecosystem  string // "pypi", "gomod", "npm"
	Name       string // package/module name (no version specifier)
	Version    string // extracted version (may be empty)
	RawSpec    string // original specifier as found in the file (e.g. "mkdocs==1.6.1")
	RequiredBy string // git entry that requires this
	Exists     bool   // true if already in the manifest
}

// DiscoveryResult tracks what was found during source scanning.
type DiscoveryResult struct {
	FilesFound []string        // dependency files found (e.g. "requirements.txt")
	Deps       []DiscoveredDep // all parsed dependencies
}

// ScanDeps scans an extracted git source for dependency files and returns
// structured results. It does NOT modify the store. Use ImportDeps to apply.
func ScanDeps(cfg *Config, store *manifest.Store, entry manifest.GitEntry, out io.Writer) DiscoveryResult {
	result := DiscoveryResult{}

	buildRoot := cfg.rootFor(manifest.TypeGit)
	worktree, err := GitWorktreePath(buildRoot, entry.Name, entry.Ref)
	if err != nil || worktree == "" {
		_, _ = fmt.Fprintf(out, "    [discover] could not locate source for %s@%s\n", entry.Name, entry.Ref)
		return result
	}

	_, _ = fmt.Fprintf(out, "\n>>> [discover] scanning %s@%s\n", entry.Name, entry.Ref)
	_, _ = fmt.Fprintf(out, "    Source: %s\n", worktree)

	// --- requirements.txt (Python/pip) ---
	reqPath := filepath.Join(worktree, "requirements.txt")
	if _, err := os.Stat(reqPath); err == nil {
		pkgs := parseRequirementsTxt(reqPath, worktree)
		result.FilesFound = append(result.FilesFound, fmt.Sprintf("requirements.txt (%d packages)", len(pkgs)))
		_, _ = fmt.Fprintf(out, "    Found: requirements.txt (%d packages)\n", len(pkgs))

		for _, dep := range pkgs {
			exists := false
			for _, existing := range store.Pypi.Packages {
				if strings.EqualFold(pkgBaseName(existing.Name), dep.Name) {
					exists = true
					break
				}
			}
			result.Deps = append(result.Deps, DiscoveredDep{
				Ecosystem:  manifest.TypePypi,
				Name:       dep.Name,
				Version:    dep.Version,
				RawSpec:    dep.RawSpec,
				RequiredBy: entry.Name,
				Exists:     exists,
			})
		}
	}

	// --- go.mod (Go modules) ---
	goModPath := filepath.Join(worktree, "go.mod")
	if _, err := os.Stat(goModPath); err == nil {
		mods := parseGoMod(goModPath)
		result.FilesFound = append(result.FilesFound, fmt.Sprintf("go.mod (%d modules)", len(mods)))
		_, _ = fmt.Fprintf(out, "    Found: go.mod (%d modules)\n", len(mods))

		for _, mod := range mods {
			exists := store.FindGomod(mod.Name) != nil
			result.Deps = append(result.Deps, DiscoveredDep{
				Ecosystem:  manifest.TypeGomod,
				Name:       mod.Name,
				Version:    mod.Version,
				RawSpec:    mod.Name + " " + mod.Version,
				RequiredBy: entry.Name,
				Exists:     exists,
			})
		}
	}

	// --- package.json (npm) ---
	pkgJsonPath := filepath.Join(worktree, "package.json")
	if _, err := os.Stat(pkgJsonPath); err == nil {
		deps := parsePackageJSON(pkgJsonPath)
		result.FilesFound = append(result.FilesFound, fmt.Sprintf("package.json (%d dependencies)", len(deps)))
		_, _ = fmt.Fprintf(out, "    Found: package.json (%d dependencies)\n", len(deps))

		for _, dep := range deps {
			exists := store.FindNpm(dep.Name) != nil
			result.Deps = append(result.Deps, DiscoveredDep{
				Ecosystem:  manifest.TypeNpm,
				Name:       dep.Name,
				Version:    dep.Version,
				RawSpec:    dep.Name + "@" + dep.Version,
				RequiredBy: entry.Name,
				Exists:     exists,
			})
		}
	}

	// --- Log-only: unsupported ecosystems ---
	for _, name := range []string{"Gemfile", "pom.xml", "build.gradle", "Cargo.toml"} {
		if _, err := os.Stat(filepath.Join(worktree, name)); err == nil {
			result.FilesFound = append(result.FilesFound, name+" (unsupported)")
			_, _ = fmt.Fprintf(out, "    Found: %s (unsupported ecosystem -- manual entry needed)\n", name)
		}
	}

	if len(result.FilesFound) == 0 {
		_, _ = fmt.Fprintf(out, "    No dependency files found\n")
	}

	return result
}

// ImportDeps adds the given discovered dependencies to the store and saves.
// Only imports deps where Exists is false. Returns counts of added per ecosystem.
func ImportDeps(store *manifest.Store, entry manifest.GitEntry, deps []DiscoveredDep, out io.Writer) (pypiAdded, gomodAdded, npmAdded int) {
	// Auto-populate base_requirements for pypi.
	hasPypi := false
	for _, d := range deps {
		if d.Ecosystem == manifest.TypePypi && !d.Exists {
			hasPypi = true
			break
		}
	}
	if hasPypi {
		if store.Pypi.BaseRequirements == nil {
			store.Pypi.BaseRequirements = make(map[string]string)
		}
		store.Pypi.BaseRequirements[entry.Name] = entry.Ref
		_, _ = fmt.Fprintf(out, "    pypi: set base_requirements[%q] = %q\n", entry.Name, entry.Ref)
	}

	for _, d := range deps {
		if d.Exists {
			continue
		}
		switch d.Ecosystem {
		case manifest.TypePypi:
			store.Pypi.Packages = append(store.Pypi.Packages, manifest.PypiPackage{
				Name:       d.Name,
				Version:    d.Version,
				RequiredBy: []string{d.RequiredBy},
			})
			pypiAdded++
		case manifest.TypeGomod:
			store.Gomod = append(store.Gomod, manifest.GomodEntry{
				Name:    d.Name,
				Version: d.Version,
				Mode:    manifest.ModeProxy,
			})
			gomodAdded++
		case manifest.TypeNpm:
			store.Npm = append(store.Npm, manifest.NpmEntry{
				Name:    d.Name,
				Version: d.Version,
				Mode:    manifest.ModeProxy,
			})
			npmAdded++
		}
	}

	// Save modified manifests.
	if pypiAdded > 0 {
		if err := store.SavePypi(); err != nil {
			_, _ = fmt.Fprintf(out, "    pypi: WARNING: could not save: %v\n", err)
		}
		_, _ = fmt.Fprintf(out, "    pypi: added %d new packages\n", pypiAdded)
	}
	if gomodAdded > 0 {
		if err := store.SaveGomod(); err != nil {
			_, _ = fmt.Fprintf(out, "    gomod: WARNING: could not save: %v\n", err)
		}
		_, _ = fmt.Fprintf(out, "    gomod: added %d new modules\n", gomodAdded)
	}
	if npmAdded > 0 {
		if err := store.SaveNpm(); err != nil {
			_, _ = fmt.Fprintf(out, "    npm: WARNING: could not save: %v\n", err)
		}
		_, _ = fmt.Fprintf(out, "    npm: added %d new packages\n", npmAdded)
	}

	return
}

// DiscoverDeps is a convenience wrapper that scans and auto-imports all deps.
// Used by the CLI/pipeline when interactive review is not available.
func DiscoverDeps(cfg *Config, store *manifest.Store, entry manifest.GitEntry, out io.Writer) DiscoveryResult {
	result := ScanDeps(cfg, store, entry, out)
	if len(result.Deps) > 0 {
		ImportDeps(store, entry, result.Deps, out)
	}
	return result
}

// parsedPipDep holds the parsed name and version from a pip specifier.
type parsedPipDep struct {
	Name    string // normalized name without extras or version
	Version string // extracted version (empty if unpinned)
	RawSpec string // original specifier line
}

// parseRequirementsTxt reads a pip requirements file and returns parsed deps.
func parseRequirementsTxt(path, baseDir string) []parsedPipDep {
	return parseRequirementsFile(path, baseDir, 0)
}

func parseRequirementsFile(path, baseDir string, depth int) []parsedPipDep {
	if depth > 5 {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var deps []parsedPipDep
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		if strings.HasPrefix(line, "-r ") || strings.HasPrefix(line, "--requirement ") {
			incPath := strings.TrimPrefix(line, "-r ")
			incPath = strings.TrimPrefix(incPath, "--requirement ")
			incPath = strings.TrimSpace(incPath)
			if !filepath.IsAbs(incPath) {
				incPath = filepath.Join(filepath.Dir(path), incPath)
			}
			deps = append(deps, parseRequirementsFile(incPath, baseDir, depth+1)...)
			continue
		}
		if line[0] == '-' {
			continue
		}
		name, version := parsePipSpecifier(line)
		deps = append(deps, parsedPipDep{
			Name:    name,
			Version: version,
			RawSpec: line,
		})
	}
	return deps
}

// parsePipSpecifier extracts the package name and pinned version from a pip
// specifier like "mkdocs==1.6.1", "requests[security]>=2.28.0", or "boto3".
func parsePipSpecifier(spec string) (name, version string) {
	// Strip environment markers.
	if i := strings.IndexByte(spec, ';'); i >= 0 {
		spec = strings.TrimSpace(spec[:i])
	}
	// Find the first version operator.
	opIdx := -1
	for i, r := range spec {
		if r == '>' || r == '<' || r == '=' || r == '!' || r == '~' {
			opIdx = i
			break
		}
	}
	if opIdx < 0 {
		// No version specifier.
		return strings.TrimSpace(spec), ""
	}
	name = strings.TrimSpace(spec[:opIdx])
	verPart := spec[opIdx:]
	// Strip the operator (==, >=, ~=, etc.).
	for len(verPart) > 0 && (verPart[0] == '>' || verPart[0] == '<' || verPart[0] == '=' || verPart[0] == '!' || verPart[0] == '~') {
		verPart = verPart[1:]
	}
	// Take up to the first comma (handles ">=1.0,<2.0").
	if i := strings.IndexByte(verPart, ','); i >= 0 {
		verPart = verPart[:i]
	}
	return name, strings.TrimSpace(verPart)
}

// depEntry is a generic name+version pair used during parsing.
type depEntry struct {
	Name    string
	Version string
}

// parseGoMod reads a go.mod file and extracts require directives.
func parseGoMod(path string) []depEntry {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(data), "\n")

	var deps []depEntry
	inBlock := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "require ") && !strings.HasSuffix(line, "(") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				deps = append(deps, depEntry{Name: parts[1], Version: parts[2]})
			}
			continue
		}
		if strings.HasPrefix(line, "require (") || line == "require (" {
			inBlock = true
			continue
		}
		if inBlock {
			if line == ")" {
				inBlock = false
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				if len(parts) >= 4 && parts[2] == "//" && parts[3] == "indirect" {
					continue
				}
				deps = append(deps, depEntry{Name: parts[0], Version: parts[1]})
			}
		}
	}
	return deps
}

// parsePackageJSON reads a package.json and extracts dependencies.
func parsePackageJSON(path string) []depEntry {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}

	var deps []depEntry
	for name, ver := range pkg.Dependencies {
		deps = append(deps, depEntry{Name: name, Version: stripSemverRange(ver)})
	}
	for name, ver := range pkg.DevDependencies {
		dup := false
		for _, d := range deps {
			if d.Name == name {
				dup = true
				break
			}
		}
		if !dup {
			deps = append(deps, depEntry{Name: name, Version: stripSemverRange(ver)})
		}
	}
	return deps
}

// stripSemverRange removes npm version range prefixes like ^, ~, >=, etc.
func stripSemverRange(ver string) string {
	ver = strings.TrimSpace(ver)
	if ver == "" || ver == "*" || ver == "latest" {
		return ver
	}
	for len(ver) > 0 && (ver[0] == '^' || ver[0] == '~' || ver[0] == '>' || ver[0] == '<' || ver[0] == '=') {
		ver = ver[1:]
	}
	return strings.TrimSpace(ver)
}
