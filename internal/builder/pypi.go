package builder

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// hasInstallableRequirements reports whether a pip requirements file contains
// any line that pip would treat as an install target. Blank lines and comment
// lines (leading #) are ignored. An `-r other.txt` reference counts as
// installable (pip will recurse into it at wheel time).
func hasInstallableRequirements(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return true, nil
	}
	return false, scanner.Err()
}

// pypiWheelsDir returns the local wheels directory.
func pypiWheelsDir(d dirs) string {
	return d.wheels
}

// defaultPypiIndex is the index a pypi entry resolves against when it names no
// URL of its own.
const defaultPypiIndex = "https://pypi.org"

// pypiOfferedMax caps how many versions an unresolvable-version error prints.
// A popular distribution offers hundreds, and an error nobody can read at 03:00
// is not a better error than a vague one.
const pypiOfferedMax = 5

// resolvePypiVersion returns the concrete version an entry resolves to, read
// off the index that will serve it. The empty string means the entry names no
// version, so the caller writes a bare requirement and lets pip resolve it
// inside the closure the base requirements already constrain.
//
// Resolution happens here rather than being left to pip because the manifest is
// the record of what was approved: an unpinned requirement line let pip take
// whatever was newest, and a 1.16.0 entry produced a 1.17.0 wheel with nothing
// reporting the substitution.
func resolvePypiVersion(name string, ve manifest.VersionEntry) (string, error) {
	want := strings.TrimSpace(ve.Version)
	if want == "" || want == "*" {
		return "", nil
	}

	root := ve.URL
	if root == "" {
		root = defaultPypiIndex
	}
	available, err := pypiVersionsAt(root, name)
	if err != nil {
		return "", fmt.Errorf("pypi %s: reading %s to resolve %s: %w", name, root, want, err)
	}

	constraint := ve.VersionConstraint
	if constraint == "" {
		constraint = manifest.ConstraintExact
	}

	// Literal match before the semver filter. PyPI versions are PEP 440, not
	// semver, so ParseSemVer rejects "2.0.0rc1" and "0.6.dev1" outright and
	// FilterVersions would refuse a pin the index plainly offers.
	if constraint == manifest.ConstraintExact {
		for _, v := range available {
			if v == want {
				return v, nil
			}
		}
	}
	if matches := FilterVersions(available, constraint, want); len(matches) > 0 {
		return matches[len(matches)-1], nil
	}

	return "", fmt.Errorf("pypi %s: version_constraint %q on %s resolves to nothing; the index at %s offers %s",
		name, constraint, want, root, pypiOffered(available))
}

// pypiOffered renders an index's version list for an error message, newest last.
func pypiOffered(available []string) string {
	if len(available) == 0 {
		return "no versions at all"
	}
	if len(available) <= pypiOfferedMax {
		return strings.Join(available, ", ")
	}
	return fmt.Sprintf("%s (%d versions in all)",
		strings.Join(available[len(available)-pypiOfferedMax:], ", "), len(available))
}

// pypiRequirement renders one resolved entry as a pip requirement line.
func pypiRequirement(name, resolved string) string {
	if resolved == "" {
		return name
	}
	return name + "==" + resolved
}

// CheckPypiStage inspects the filesystem to determine which pipeline stages
// have completed for the pypi packages.
func CheckPypiStage(cfg *Config, store *manifest.Store) StageStatus {
	d := buildDirs(cfg.rootFor(manifest.TypePypi))
	var s StageStatus

	// Fetched = combined-requirements.txt exists.
	combinedReq := filepath.Join(cfg.rootFor(manifest.TypePypi), "combined-requirements.txt")
	if fi, err := os.Stat(combinedReq); err == nil && !fi.IsDir() {
		s.Fetched = true
	}

	if s.Fetched {
		// Built = at least one .whl file in the wheels dir.
		wheelsDir := pypiWheelsDir(d)
		whlFiles, _ := filepath.Glob(filepath.Join(wheelsDir, "*.whl"))
		s.Built = len(whlFiles) > 0

		if s.Built {
			// Packaged = MANIFEST.sha256 exists.
			manifestFile := filepath.Join(wheelsDir, "MANIFEST.sha256")
			if fi, err := os.Stat(manifestFile); err == nil && !fi.IsDir() {
				s.Packaged = true
			}
		}
	}

	return s
}

// PypiArtifactDir returns the local wheels directory and S3 prefix for the
// pypi packages. Used by the upload and sync commands.
func PypiArtifactDir(cfg *Config, store *manifest.Store) (localDir, s3Prefix string) {
	return ArtifactDir(cfg, manifest.TypePypi), manifest.PypiWheelPrefix
}

// FetchPypi resolves requirements from previously-cloned git repos and from
// the extra packages listed in the pypi manifests, then writes
// <build-root>/combined-requirements.txt.
//
// The caller must ensure that any git repos referenced by base-requirement
// entries have been fetched before calling FetchPypi.
//
// Base requirements are tracked via RequiredBy on individual pypi VersionEntry
// records: when a VersionEntry has RequiredBy set, those git repos are treated
// as base apps and their requirements.txt files are included.
func FetchPypi(cfg *Config, store *manifest.Store) *Summary {
	ctx := context.Background()
	out := cfg.stdout()
	summary := &Summary{}
	dirs := buildDirs(cfg.rootFor(manifest.TypePypi))

	start := time.Now()
	result := Result{Type: manifest.TypePypi, Name: "requirements"}

	combinedReq := filepath.Join(cfg.rootFor(manifest.TypePypi), "combined-requirements.txt")
	_, _ = fmt.Fprintf(out, "\n>>> [pypi] fetch — resolving requirements\n")

	reqLines := []string{"# Auto-generated by bodega from pypi manifests\n"}

	// Collect base requirements: git repos referenced via RequiredBy on any pypi entry.
	baseReqs := make(map[string]string) // repoName → ref
	for _, name := range store.ListPackages(manifest.TypePypi) {
		pm, err := store.GetPackage(ctx, manifest.TypePypi, name)
		if err != nil || pm == nil {
			continue
		}
		for _, ve := range pm.Versions {
			for _, requiredBy := range ve.RequiredBy {
				// Look up the git ref for this repo.
				gitPM, err := store.GetPackage(ctx, manifest.TypeGit, requiredBy)
				if err != nil || gitPM == nil {
					continue
				}
				for _, gitVE := range gitPM.Versions {
					if gitVE.Ref != "" {
						baseReqs[requiredBy] = gitVE.Ref
						break
					}
				}
			}
		}
	}

	for repoName, ref := range baseReqs {
		worktree, err := GitWorktreePath(cfg.rootFor(manifest.TypeGit), repoName, ref)
		if err != nil {
			result.Err = fmt.Errorf("git worktree for %s@%s: %w", repoName, ref, err)
			summary.Failures++
			summary.Results = append(summary.Results, result)
			summary.Total++
			return summary
		}
		if worktree == "" {
			result.Err = fmt.Errorf(
				"git repo %q not found at %s — run 'fetch git' first",
				repoName, filepath.Join(dirs.repos, repoName+".git"),
			)
			summary.Failures++
			summary.Results = append(summary.Results, result)
			summary.Total++
			return summary
		}
		reqPath := filepath.Join(worktree, "requirements.txt")
		if _, err := os.Stat(reqPath); os.IsNotExist(err) {
			result.Err = fmt.Errorf("requirements.txt not found in %s", worktree)
			summary.Failures++
			summary.Results = append(summary.Results, result)
			summary.Total++
			return summary
		}
		_, _ = fmt.Fprintf(out, "    Base: %s @ %s (%s)\n", repoName, ref, reqPath)
		reqLines = append(reqLines, fmt.Sprintf("-r %s\n", reqPath))
	}

	// Collect extra packages from the pypi manifests.
	pkgNames := store.ListPackages(manifest.TypePypi)
	_, _ = fmt.Fprintf(out, "    Extra packages: %d\n", len(pkgNames))
	reqLines = append(reqLines, "\n# Extra packages from manifest\n")
	unresolved := false
	for _, name := range pkgNames {
		if err := cfg.EnforcePolicy(ctx, manifest.TypePypi, name, "", ""); err != nil {
			_, _ = fmt.Fprintf(out, "      %s — SKIPPED: %v\n", name, err)
			summary.Failures++
			continue
		}

		pm, err := store.GetPackage(ctx, manifest.TypePypi, name)
		if err != nil {
			// The entry says which version was approved, so a fetch that cannot
			// read it has nothing to honor and must not fall back to a bare
			// requirement line.
			err = fmt.Errorf("pypi %s: read the manifest entry: %w", name, err)
			_, _ = fmt.Fprintf(out, "      %s — FAILED: %v\n", name, err)
			summary.Failures++
			summary.Total++
			summary.Results = append(summary.Results, Result{Type: manifest.TypePypi, Name: name, Err: err})
			unresolved = true
			continue
		}

		// A package with no version entries names no version, which is the
		// shape auto-imported dependencies arrive in.
		entries := []manifest.VersionEntry{{}}
		if pm != nil && len(pm.Versions) > 0 {
			entries = pm.Versions
		}
		for _, ve := range entries {
			resolved, err := resolvePypiVersion(name, ve)
			if err != nil {
				_, _ = fmt.Fprintf(out, "      %s — FAILED: %v\n", name, err)
				summary.Failures++
				summary.Total++
				summary.Results = append(summary.Results, Result{Type: manifest.TypePypi, Name: name, Err: err})
				unresolved = true
				continue
			}
			spec := pypiRequirement(name, resolved)
			_, _ = fmt.Fprintf(out, "      %s\n", spec)
			reqLines = append(reqLines, spec+"\n")
		}
	}

	// No requirements file at all rather than one missing the entry that failed:
	// a partial file builds cleanly and stores a closure nobody approved.
	if unresolved {
		return summary
	}

	// Write combined requirements file.
	content := ""
	for _, line := range reqLines {
		content += line
	}
	if err := os.WriteFile(combinedReq, []byte(content), 0o644); err != nil {
		result.Err = fmt.Errorf("write combined requirements: %w", err)
		summary.Failures++
		summary.Results = append(summary.Results, result)
		summary.Total++
		return summary
	}
	_, _ = fmt.Fprintf(out, "    Requirements written to: %s\n", combinedReq)

	result.Artifacts = []string{combinedReq}
	result.Elapsed = time.Since(start)
	summary.Results = append(summary.Results, result)
	summary.Total++
	_, _ = fmt.Fprintf(out, "    Done (%s)\n", result.Elapsed.Round(time.Millisecond))

	if cfg.Logger != nil {
		cfg.Logger.Audit("OK      pypi/requirements  (%s)", result.Elapsed.Round(time.Millisecond))
	}
	cfg.RecordAudit(audit.EventFetch, manifest.TypePypi, "requirements", "", "success", result.Elapsed, nil)

	return summary
}

// BuildPypi creates a build virtualenv and runs pip wheel to produce a
// directory of wheels under <build-root>/wheels[/<version>]/.
// combined-requirements.txt must already exist (produced by FetchPypi).
func BuildPypi(cfg *Config, store *manifest.Store) *Summary {
	out := cfg.stdout()
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypePypi))

	start := time.Now()
	result := Result{Type: manifest.TypePypi, Name: "wheels"}

	combinedReq := filepath.Join(cfg.rootFor(manifest.TypePypi), "combined-requirements.txt")
	if _, err := os.Stat(combinedReq); os.IsNotExist(err) {
		result.Err = fmt.Errorf("combined-requirements.txt not found at %s — run 'fetch pypi' first", combinedReq)
		summary.Failures++
		summary.Results = append(summary.Results, result)
		summary.Total++
		return summary
	}

	// Skip the whole venv + pip-wheel dance when the requirements file has
	// no installable lines. Saves ~8s per run when pypi entries resolve to
	// nothing (e.g. a git repo whose requirements.txt only references other
	// git repos). PackagePypi will see zero wheels and skip cleanly.
	hasReqs, err := hasInstallableRequirements(combinedReq)
	if err != nil {
		result.Err = fmt.Errorf("read combined-requirements.txt: %w", err)
		summary.Failures++
		summary.Results = append(summary.Results, result)
		summary.Total++
		return summary
	}
	if !hasReqs {
		_, _ = fmt.Fprintf(out, "\n>>> [pypi] build — combined-requirements.txt has no installable packages, skipping\n")
		return summary
	}

	wheelsDir := pypiWheelsDir(d)
	if err := mkdirAll(wheelsDir); err != nil {
		cfg.logf("ERROR: %v", err)
		return summary
	}

	// Create a build virtualenv.
	venvDir := filepath.Join(cfg.rootFor(manifest.TypePypi), "build-venv")
	if err := os.RemoveAll(venvDir); err != nil {
		result.Err = fmt.Errorf("remove old venv: %w", err)
		summary.Failures++
		summary.Results = append(summary.Results, result)
		summary.Total++
		return summary
	}

	_, _ = fmt.Fprintf(out, "\n>>> [pypi] build — creating virtualenv\n")
	// Try normal venv first; fall back to --without-pip if ensurepip is missing.
	if err := runCmd(out, "", "python3", "-m", "venv", venvDir); err != nil {
		_, _ = fmt.Fprintf(out, "    venv failed, retrying with --without-pip...\n")
		if err2 := runCmd(out, "", "python3", "-m", "venv", "--without-pip", venvDir); err2 != nil {
			result.Err = fmt.Errorf("python3 -m venv: %w", err2)
			summary.Failures++
			summary.Results = append(summary.Results, result)
			summary.Total++
			return summary
		}
		// Install pip into the venv manually.
		_, _ = fmt.Fprintf(out, "    Installing pip via get-pip.py...\n")
		pythonBin := filepath.Join(venvDir, "bin", "python3")
		if err3 := runCmd(out, "", "bash", "-c",
			"curl -sS https://bootstrap.pypa.io/get-pip.py | "+pythonBin); err3 != nil {
			result.Err = fmt.Errorf("install pip: %w", err3)
			summary.Failures++
			summary.Results = append(summary.Results, result)
			summary.Total++
			return summary
		}
	}

	pipBin := filepath.Join(venvDir, "bin", "pip")
	_, _ = fmt.Fprintf(out, "    Upgrading pip, wheel, setuptools...\n")
	if err := runCmd(out, "", pipBin, "install", "--upgrade", "pip", "wheel", "setuptools"); err != nil {
		result.Err = fmt.Errorf("pip upgrade: %w", err)
		summary.Failures++
		summary.Results = append(summary.Results, result)
		summary.Total++
		return summary
	}

	// Build wheels.
	_, _ = fmt.Fprintf(out, "\n>>> [pypi] build — building wheels (C extensions will compile from source)\n")
	if err := runCmd(out, "",
		pipBin, "wheel",
		"--wheel-dir", wheelsDir,
		"--progress-bar", "on",
		"-r", combinedReq,
	); err != nil {
		result.Err = fmt.Errorf("pip wheel: %w", err)
		summary.Failures++
		summary.Results = append(summary.Results, result)
		summary.Total++
		return summary
	}

	// Collect artifact paths.
	whlFiles, _ := filepath.Glob(filepath.Join(wheelsDir, "*.whl"))
	result.Artifacts = whlFiles
	result.Elapsed = time.Since(start)
	summary.Results = append(summary.Results, result)
	summary.Total++

	_, _ = fmt.Fprintf(out, "\n    Total wheels built: %d\n", len(whlFiles))
	_, _ = fmt.Fprintf(out, "    Done (%s)\n", result.Elapsed.Round(time.Millisecond))

	return summary
}

// PackagePypi generates MANIFEST.sha256 in the wheels directory. The wheels
// must already exist (produced by BuildPypi).
func PackagePypi(cfg *Config, store *manifest.Store) *Summary {
	out := cfg.stdout()
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypePypi))

	start := time.Now()
	result := Result{Type: manifest.TypePypi, Name: "manifest"}

	wheelsDir := pypiWheelsDir(d)
	whlFiles, _ := filepath.Glob(filepath.Join(wheelsDir, "*.whl"))
	if len(whlFiles) == 0 {
		// Two distinct states: build hasn't run at all vs. build ran but
		// produced nothing. Only the former is an error — the latter happens
		// when combined-requirements.txt resolves to zero installable packages
		// (common with pypi entries auto-imported from a git repo that has no
		// direct requirements of its own). Treat it as a skip so the caller
		// doesn't abort the whole upload run.
		if _, err := os.Stat(wheelsDir); os.IsNotExist(err) {
			result.Err = fmt.Errorf("no wheels directory at %s — run 'build pypi' first", wheelsDir)
			summary.Failures++
			summary.Results = append(summary.Results, result)
			summary.Total++
			return summary
		}
		_, _ = fmt.Fprintf(out, "\n>>> [pypi] package — no wheels produced, skipping\n")
		return summary
	}

	_, _ = fmt.Fprintf(out, "\n>>> [pypi] package — generating checksums\n")

	manifestFile := filepath.Join(wheelsDir, "MANIFEST.sha256")
	if err := generateWheelManifest(wheelsDir, manifestFile); err != nil {
		result.Err = fmt.Errorf("generate MANIFEST.sha256: %w", err)
		_, _ = fmt.Fprintf(out, "    ERROR: %v\n", result.Err)
		summary.Failures++
	} else {
		_, _ = fmt.Fprintf(out, "    Written: %s\n", manifestFile)
		result.Artifacts = []string{manifestFile}

		// Scan wheel metadata and persist the dependency graph. This is a
		// best-effort operation: failures are logged but do not fail the build.
		depGraphPath := filepath.Join(wheelsDir, "dep-graph.json")
		if graph, err := ScanWheelMetadata(wheelsDir, store); err != nil {
			_, _ = fmt.Fprintf(out, "    WARNING: dep-graph scan failed: %v\n", err)
		} else if err := SaveDepGraph(depGraphPath, graph); err != nil {
			_, _ = fmt.Fprintf(out, "    WARNING: dep-graph save failed: %v\n", err)
		} else {
			_, _ = fmt.Fprintf(out, "    Dep graph: %s (%d packages)\n", depGraphPath, len(graph.Packages))
		}
	}

	result.Elapsed = time.Since(start)
	summary.Results = append(summary.Results, result)
	summary.Total++
	_, _ = fmt.Fprintf(out, "    Done (%s)\n", result.Elapsed.Round(time.Millisecond))

	if cfg.Logger != nil {
		if result.Err != nil {
			cfg.Logger.Audit("FAILED  pypi/manifest  (%s)  %v", result.Elapsed.Round(time.Millisecond), result.Err)
		} else {
			cfg.Logger.Audit("OK      pypi/manifest  (%s)", result.Elapsed.Round(time.Millisecond))
		}
	}
	pyStatus := "success"
	if result.Err != nil {
		pyStatus = "failure"
	}
	cfg.RecordAudit(audit.EventPackage, manifest.TypePypi, "manifest", "", pyStatus, result.Elapsed, result.Err)

	return summary
}

// RunPypi runs the full pypi pipeline (FetchPypi → BuildPypi → PackagePypi)
// for backward compatibility. New callers should invoke the stage functions
// individually.
func RunPypi(cfg *Config, store *manifest.Store) *Summary {
	fetchSummary := FetchPypi(cfg, store)
	if fetchSummary.HasFailures() {
		return fetchSummary
	}
	buildSummary := BuildPypi(cfg, store)
	if buildSummary.HasFailures() {
		return mergeSummaries(fetchSummary, buildSummary)
	}
	pkgSummary := PackagePypi(cfg, store)
	return mergeSummaries(mergeSummaries(fetchSummary, buildSummary), pkgSummary)
}

// generateWheelManifest writes a MANIFEST.sha256 file with checksums of every
// .whl file in wheelDir.
func generateWheelManifest(wheelDir, destPath string) error {
	matches, err := filepath.Glob(filepath.Join(wheelDir, "*.whl"))
	if err != nil {
		return err
	}

	var lines string
	for _, whl := range matches {
		sum, err := fileSHA256(whl)
		if err != nil {
			return err
		}
		lines += fmt.Sprintf("%s  %s\n", sum, filepath.Base(whl))
	}
	return os.WriteFile(destPath, []byte(lines), 0o644)
}
