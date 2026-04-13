package builder

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

// DiscoveredDep represents a single dependency found during source scanning.
type DiscoveredDep struct {
	Ecosystem  string // "pypi", "gomod", "npm"
	Name       string // package/module name (no version specifier)
	Version    string // extracted version (may be empty)
	Constraint string // bodega constraint: "exact", "compatible", "patch", "any"
	RawSpec    string // original specifier as found in the file (e.g. "mkdocs==1.6.1")
	RequiredBy string // "type/name@version" of the parent that requires this
	Exists     bool   // true if already in the manifest
}

// DiscoveryResult tracks what was found during source scanning.
type DiscoveryResult struct {
	FilesFound []string        // dependency files found (e.g. "requirements.txt")
	Deps       []DiscoveredDep // all parsed dependencies
}

// ScanDeps scans an extracted git source for dependency files and returns
// structured results. It does NOT modify the store. Use ImportDeps to apply.
func ScanDeps(cfg *Config, store *manifest.Store, name string, ve manifest.VersionEntry, out io.Writer) DiscoveryResult {
	ctx := context.Background()
	result := DiscoveryResult{}

	buildRoot := cfg.rootFor(manifest.TypeGit)
	worktree, err := GitWorktreePath(buildRoot, name, ve.Ref)
	if err != nil || worktree == "" {
		_, _ = fmt.Fprintf(out, "    [discover] could not locate source for %s@%s\n", name, ve.Ref)
		return result
	}

	_, _ = fmt.Fprintf(out, "\n>>> [discover] scanning %s@%s\n", name, ve.Ref)
	_, _ = fmt.Fprintf(out, "    Source: %s\n", worktree)

	// --- Python requirements ---
	// Parse both requirements.txt (pinned) and base_requirements.txt (flexible).
	// The pinned file provides exact versions; the base file provides constraints.
	parentRef := fmt.Sprintf("git/%s@%s", name, ve.Ref)

	reqPath := filepath.Join(worktree, "requirements.txt")
	baseReqPath := filepath.Join(worktree, "base_requirements.txt")

	// Build a constraint map from base_requirements.txt (if present).
	baseConstraints := make(map[string]string) // normalized name -> constraint
	baseRawSpecs := make(map[string]string)    // normalized name -> raw spec
	if _, err := os.Stat(baseReqPath); err == nil {
		baseDeps := parseRequirementsTxt(baseReqPath, worktree)
		result.FilesFound = append(result.FilesFound, fmt.Sprintf("base_requirements.txt (%d packages)", len(baseDeps)))
		_, _ = fmt.Fprintf(out, "    Found: base_requirements.txt (%d packages)\n", len(baseDeps))
		for _, dep := range baseDeps {
			key := strings.ToLower(dep.Name)
			baseConstraints[key] = pipOperatorToConstraint(dep.RawSpec)
			baseRawSpecs[key] = dep.RawSpec
		}
	}

	if _, err := os.Stat(reqPath); err == nil {
		pkgs := parseRequirementsTxt(reqPath, worktree)
		result.FilesFound = append(result.FilesFound, fmt.Sprintf("requirements.txt (%d packages)", len(pkgs)))
		_, _ = fmt.Fprintf(out, "    Found: requirements.txt (%d packages)\n", len(pkgs))

		for _, dep := range pkgs {
			exists := false
			for _, pkgName := range store.ListPackages(manifest.TypePypi) {
				if strings.EqualFold(pkgBaseName(pkgName), dep.Name) {
					exists = true
					break
				}
			}
			// Determine constraint: from base_requirements if available, else from the pinned spec.
			constraint := pipOperatorToConstraint(dep.RawSpec)
			if bc, ok := baseConstraints[strings.ToLower(dep.Name)]; ok {
				constraint = bc
			}
			result.Deps = append(result.Deps, DiscoveredDep{
				Ecosystem:  manifest.TypePypi,
				Name:       dep.Name,
				Version:    dep.Version,
				Constraint: constraint,
				RawSpec:    dep.RawSpec,
				RequiredBy: parentRef,
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
			pm, _ := store.GetPackage(ctx, manifest.TypeGomod, mod.Name)
			exists := pm != nil
			result.Deps = append(result.Deps, DiscoveredDep{
				Ecosystem:  manifest.TypeGomod,
				Name:       mod.Name,
				Version:    mod.Version,
				Constraint: manifest.ConstraintExact,
				RawSpec:    mod.Name + " " + mod.Version,
				RequiredBy: parentRef,
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
			pm, _ := store.GetPackage(ctx, manifest.TypeNpm, dep.Name)
			exists := pm != nil
			result.Deps = append(result.Deps, DiscoveredDep{
				Ecosystem:  manifest.TypeNpm,
				Name:       dep.Name,
				Version:    dep.Version,
				Constraint: manifest.ConstraintExact,
				RawSpec:    dep.Name + "@" + dep.Version,
				RequiredBy: parentRef,
				Exists:     exists,
			})
		}
	}

	// --- Log-only: unsupported ecosystems ---
	for _, fname := range []string{"Gemfile", "pom.xml", "build.gradle", "Cargo.toml"} {
		if _, err := os.Stat(filepath.Join(worktree, fname)); err == nil {
			result.FilesFound = append(result.FilesFound, fname+" (unsupported)")
			_, _ = fmt.Fprintf(out, "    Found: %s (unsupported ecosystem -- manual entry needed)\n", fname)
		}
	}

	if len(result.FilesFound) == 0 {
		_, _ = fmt.Fprintf(out, "    No dependency files found\n")
	}

	return result
}

// ImportDeps adds the given discovered dependencies to the store and saves.
// Only imports deps where Exists is false. Returns counts of added per ecosystem.
func ImportDeps(ctx context.Context, store *manifest.Store, parentName string, parentVE manifest.VersionEntry, deps []DiscoveredDep, out io.Writer) (pypiAdded, gomodAdded, npmAdded int) {
	for _, d := range deps {
		if d.Exists {
			continue
		}
		ve := manifest.VersionEntry{
			Version:           d.Version,
			VersionConstraint: d.Constraint,
			RequiredBy:        []string{d.RequiredBy},
		}
		switch d.Ecosystem {
		case manifest.TypePypi:
			if err := store.AddVersion(ctx, manifest.TypePypi, d.Name, ve); err != nil {
				_, _ = fmt.Fprintf(out, "    pypi: WARNING: could not add %s: %v\n", d.Name, err)
			} else {
				pypiAdded++
			}
		case manifest.TypeGomod:
			ve.Mode = manifest.ModeProxy
			if err := store.AddVersion(ctx, manifest.TypeGomod, d.Name, ve); err != nil {
				_, _ = fmt.Fprintf(out, "    gomod: WARNING: could not add %s: %v\n", d.Name, err)
			} else {
				gomodAdded++
			}
		case manifest.TypeNpm:
			ve.Mode = manifest.ModeProxy
			if err := store.AddVersion(ctx, manifest.TypeNpm, d.Name, ve); err != nil {
				_, _ = fmt.Fprintf(out, "    npm: WARNING: could not add %s: %v\n", d.Name, err)
			} else {
				npmAdded++
			}
		}
		// Add dependency graph edge.
		childRef := fmt.Sprintf("%s/%s@%s", d.Ecosystem, d.Name, d.Version)
		store.AddEdge(manifest.DepEdge{
			Parent:     d.RequiredBy,
			Child:      childRef,
			Constraint: d.Constraint,
			RawSpec:    d.RawSpec,
		})
	}

	if pypiAdded > 0 {
		_, _ = fmt.Fprintf(out, "    pypi: added %d new packages\n", pypiAdded)
		if err := store.SaveIndex(ctx); err != nil {
			_, _ = fmt.Fprintf(out, "    pypi: WARNING: could not save index: %v\n", err)
		}
	}
	if gomodAdded > 0 {
		_, _ = fmt.Fprintf(out, "    gomod: added %d new modules\n", gomodAdded)
		if err := store.SaveIndex(ctx); err != nil {
			_, _ = fmt.Fprintf(out, "    gomod: WARNING: could not save index: %v\n", err)
		}
	}
	if npmAdded > 0 {
		_, _ = fmt.Fprintf(out, "    npm: added %d new packages\n", npmAdded)
		if err := store.SaveIndex(ctx); err != nil {
			_, _ = fmt.Fprintf(out, "    npm: WARNING: could not save index: %v\n", err)
		}
	}

	// Save the dependency graph.
	if pypiAdded+gomodAdded+npmAdded > 0 {
		if err := store.SaveGraph(ctx); err != nil {
			_, _ = fmt.Fprintf(out, "    WARNING: could not save dependency graph: %v\n", err)
		}
	}

	return
}

// DiscoverDeps is a convenience wrapper that scans and auto-imports all deps.
// Used by the CLI/pipeline when interactive review is not available.
func DiscoverDeps(cfg *Config, store *manifest.Store, name string, ve manifest.VersionEntry, out io.Writer) DiscoveryResult {
	ctx := context.Background()
	result := ScanDeps(cfg, store, name, ve, out)
	if len(result.Deps) > 0 {
		ImportDeps(ctx, store, name, ve, result.Deps, out)
	}
	return result
}

// pipOperatorToConstraint maps a pip version operator to a bodega constraint.
func pipOperatorToConstraint(rawSpec string) string {
	spec := strings.TrimSpace(rawSpec)
	// Strip environment markers.
	if i := strings.IndexByte(spec, ';'); i >= 0 {
		spec = strings.TrimSpace(spec[:i])
	}
	// Find the operator.
	for i, r := range spec {
		if r == '>' || r == '<' || r == '=' || r == '!' || r == '~' {
			op := spec[i:]
			// Extract just the operator portion.
			opEnd := 0
			for j, c := range op {
				if c != '>' && c != '<' && c != '=' && c != '!' && c != '~' {
					opEnd = j
					break
				}
			}
			if opEnd == 0 {
				opEnd = len(op)
			}
			operator := op[:opEnd]
			// Check for wildcard: ==X.Y.*
			if operator == "==" && strings.Contains(op[opEnd:], "*") {
				return manifest.ConstraintCompatible
			}
			switch operator {
			case "==":
				return manifest.ConstraintExact
			case "~=":
				return manifest.ConstraintPatch
			case ">=":
				return manifest.ConstraintCompatible
			case "<", "<=", "!=":
				return manifest.ConstraintExact // conservative
			}
			return manifest.ConstraintExact
		}
	}
	// No operator = unpinned.
	return manifest.ConstraintAny
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
