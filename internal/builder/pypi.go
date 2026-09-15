package builder

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// hasInstallableRequirements reports whether a pip requirements file contains
// any line that pip would treat as an install target. Blank lines and comment
// lines (leading #) are ignored. An `-r other.txt` reference counts as
// installable (pip will recurse into it at wheel time).
//
// A pip global option such as `--index-url` is not a target. Counting one
// builds a venv, runs pip wheel over a file naming nothing, and produces zero
// wheels without an error anywhere.
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
		if strings.HasPrefix(line, "-") && !isRequirementInclude(line) {
			continue
		}
		return true, nil
	}
	return false, scanner.Err()
}

// isRequirementInclude reports whether a leading-dash line pulls in another
// requirements file, which is the one option that names install targets.
func isRequirementInclude(line string) bool {
	field := strings.Fields(line)[0]
	field, _, _ = strings.Cut(field, "=")
	return field == "-r" || field == "--requirement"
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
func resolvePypiVersion(root, name string, ve manifest.VersionEntry) (string, error) {
	want := strings.TrimSpace(ve.Version)
	if want == "" || want == "*" {
		return "", nil
	}

	available, err := pypiVersionsAt(root, name)
	if err != nil {
		return "", fmt.Errorf("pypi %s: reading %s to resolve %s: %w", name, root, want, err)
	}

	constraint := ve.VersionConstraint
	if constraint == "" {
		constraint = manifest.ConstraintExact
	}

	// Literal match before the PEP 440 filter, for the legacy versions that
	// predate the scheme: pytz shipped "2011k", which no parser will order but
	// an index plainly offers and an entry may plainly name.
	if constraint == manifest.ConstraintExact {
		for _, v := range available {
			if v == want {
				return v, nil
			}
		}
	}
	if matches := FilterPypiVersions(available, constraint, want); len(matches) > 0 {
		return matches[len(matches)-1], nil
	}

	return "", fmt.Errorf("pypi %s: version_constraint %q on %s resolves to nothing; the index at %s offers %s",
		name, constraint, want, root, pypiOffered(available))
}

// pypiIndexRoot returns the one index every pypi entry resolves and downloads
// against, read from the `url` of whichever entries name one.
//
// One index for the whole type rather than one per entry: a fetch writes a
// single requirements file and pip honors one --index-url across all of it, so
// resolving each entry against its own origin and then downloading everything
// from pip's default is how a version gets approved on one index and fetched
// from another. Two entries naming different origins is a configuration this
// shape cannot satisfy, so it fails rather than picking a winner.
func pypiIndexRoot(ctx context.Context, store *manifest.Store) (string, error) {
	named := make(map[string][]string)
	for _, name := range store.ListPackages(manifest.TypePypi) {
		pm, err := store.GetPackage(ctx, manifest.TypePypi, name)
		if err != nil || pm == nil {
			continue
		}
		for _, ve := range pm.Versions {
			if root := strings.TrimRight(strings.TrimSpace(ve.URL), "/"); root != "" {
				named[root] = append(named[root], name)
			}
		}
	}
	switch len(named) {
	case 0:
		return defaultPypiIndex, nil
	case 1:
		for root := range named {
			return root, nil
		}
	}
	roots := make([]string, 0, len(named))
	for root, pkgs := range named {
		roots = append(roots, fmt.Sprintf("%s (%s)", root, strings.Join(pkgs, ", ")))
	}
	sort.Strings(roots)
	return "", fmt.Errorf("pypi entries name %d different indexes and one fetch can use one: %s",
		len(named), strings.Join(roots, "; "))
}

// pypiIndexLine renders the pip option that points the wheel build at the same
// index the resolution read. The default index is left unsaid so a deployment
// pointing pip at its own mirror through pip.conf keeps it.
func pypiIndexLine(root string) string {
	if root == defaultPypiIndex {
		return ""
	}
	return "--index-url " + strings.TrimRight(root, "/") + "/simple/\n"
}

// pypiSourceConflict fails when a requirements file pip is told to read names
// an origin of its own.
//
// pip parses an included file after the generated header and honors the last
// index option it finds, so an application's requirements.txt can replace the
// index the manifest approved, or add a second one beside it, and nothing in
// the resolver ever sees it. Rejecting rather than rewriting: the file belongs
// to the application, and silently editing an origin out of it hides the
// disagreement instead of settling it.
func pypiSourceConflict(path, indexRoot string, seen map[string]bool) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	if seen[abs] {
		return nil
	}
	seen[abs] = true

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("read requirements: %w", err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || !strings.HasPrefix(line, "-") {
			continue
		}
		opt, value := cutRequirementOption(line)
		switch opt {
		case "-i", "--index-url":
			if !sameIndexRoot(value, indexRoot) {
				return fmt.Errorf("%s names %s %s and the manifest resolved against %s; one fetch downloads from one index",
					path, opt, value, indexRoot)
			}
		case "--extra-index-url", "-f", "--find-links":
			return fmt.Errorf("%s names %s %s, which adds an origin beside the %s the manifest approved",
				path, opt, value, indexRoot)
		case "-r", "--requirement":
			next := value
			if next == "" {
				continue
			}
			if !filepath.IsAbs(next) {
				next = filepath.Join(filepath.Dir(path), next)
			}
			if err := pypiSourceConflict(next, indexRoot, seen); err != nil {
				return fmt.Errorf("%s includes %s: %w", path, value, err)
			}
		}
	}
	return scanner.Err()
}

// cutRequirementOption splits a pip option line into the option and its value,
// accepting both spellings pip does: `--index-url URL` and `--index-url=URL`.
func cutRequirementOption(line string) (opt, value string) {
	fields := strings.Fields(line)
	opt = fields[0]
	if name, inline, ok := strings.Cut(opt, "="); ok {
		return name, inline
	}
	if len(fields) > 1 {
		value = fields[1]
	}
	return opt, value
}

// sameIndexRoot reports whether a pip index option points at the index the
// manifest resolved against. The manifest records the root and pip is handed
// the PEP 503 path under it, so the two spellings have to compare equal.
func sameIndexRoot(value, root string) bool {
	norm := func(s string) string {
		s = strings.TrimRight(strings.TrimSpace(s), "/")
		return strings.TrimSuffix(s, "/simple")
	}
	return norm(value) == norm(root)
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
//
// Arbitrary equality (===) rather than ==: PEP 440 version matching ignores a
// candidate's local label when the specifier carries none, so `six==1.16.0`
// against an index offering both 1.16.0 and 1.16.0+vendor.1 downloads the
// vendored build. Measured against pip 26.2.1. === compares the whole
// identity, so the version the resolver chose is the version pip stores.
//
// https://packaging.python.org/en/latest/specifications/version-specifiers/#version-matching
func pypiRequirement(name, resolved string) string {
	if resolved == "" {
		return name
	}
	if v, ok := ParsePyVersion(resolved); ok {
		return name + "===" + v.Canonical()
	}
	return name + "===" + resolved
}

// pypiPins reads back the exact pins a fetch wrote, keyed by normalized
// distribution name. Only the === lines are pins: the rest of the file is the
// applications' own requirements, whose closure is pip's to resolve.
func pypiPins(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	pins := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		name, version, ok := strings.Cut(line, "===")
		if !ok || strings.HasPrefix(line, "#") {
			continue
		}
		pins[normalisePkgName(strings.TrimSpace(name))] = strings.TrimSpace(version)
	}
	return pins, scanner.Err()
}

// parseWheelName splits a wheel filename into its distribution and version.
// The remaining tags decide which interpreter and platform the wheel is for,
// which is pip's business rather than the manifest's.
func parseWheelName(base string) (name, version string, ok bool) {
	// distribution-version(-build)?-python-abi-platform.whl, and neither the
	// distribution nor the version may carry a hyphen of its own.
	fields := strings.Split(strings.TrimSuffix(base, ".whl"), "-")
	if len(fields) < 5 {
		return "", "", false
	}
	return normalisePkgName(fields[0]), fields[1], true
}

// verifyPypiWheels fails when the wheels directory holds a pinned distribution
// at a version no pin names.
//
// A pin reaches pip as a specifier, and a specifier is a filter rather than a
// fact: an index that answers it with another build, a pip resolving it out of
// a cache, or a hand-edited requirements file all end with bytes on disk the
// manifest does not describe. The store is what gets published, so the store is
// what gets checked.
//
// A pin with no wheel at all passes here. pip exiting 0 having stored nothing
// for a requirement is a different defect, and failing it in this check would
// report it as a substituted version.
func verifyPypiWheels(reqPath, wheelsDir string) error {
	pins, err := pypiPins(reqPath)
	if err != nil {
		return fmt.Errorf("read the pins back from %s: %w", reqPath, err)
	}

	stored := make(map[string][]string)
	whlFiles, err := filepath.Glob(filepath.Join(wheelsDir, "*.whl"))
	if err != nil {
		return err
	}
	for _, whl := range whlFiles {
		if name, version, ok := parseWheelName(filepath.Base(whl)); ok {
			stored[name] = append(stored[name], version)
		}
	}

	for _, name := range sortedKeys(pins) {
		want := pins[name]
		have := stored[name]
		if len(have) == 0 || slices.ContainsFunc(have, func(got string) bool { return samePyVersion(got, want) }) {
			continue
		}
		return fmt.Errorf("pypi %s: the manifest names %s and the wheels directory holds %s — pip stored a version nobody approved",
			name, want, strings.Join(have, ", "))
	}
	return nil
}

// samePyVersion compares two version strings under PEP 440, falling back to
// string equality for the legacy versions no parser will read.
func samePyVersion(a, b string) bool {
	av, aOK := ParsePyVersion(a)
	bv, bOK := ParsePyVersion(b)
	if aOK && bOK {
		return av.Equal(bv)
	}
	return a == b
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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
	summary := fetchPypi(cfg, store)
	if !summary.HasFailures() {
		return summary
	}

	// A fetch that failed must leave no resolved state behind. CheckPypiStage
	// reads the file's existence as "fetch is done" and the pipeline then skips
	// the retry, so a previous run's file outlives the pin it was resolved
	// from: edit a version, watch the re-fetch fail, and `build run pypi` still
	// stores the closure of the version nobody approved any more.
	combinedReq := filepath.Join(cfg.rootFor(manifest.TypePypi), "combined-requirements.txt")
	if err := os.Remove(combinedReq); err == nil {
		_, _ = fmt.Fprintf(cfg.stdout(), "    Discarded %s: it no longer describes the manifest\n", combinedReq)
	}
	return summary
}

func fetchPypi(cfg *Config, store *manifest.Store) *Summary {
	ctx := context.Background()
	out := cfg.stdout()
	summary := &Summary{}
	dirs := buildDirs(cfg.rootFor(manifest.TypePypi))

	start := time.Now()
	result := Result{Type: manifest.TypePypi, Name: "requirements"}

	combinedReq := filepath.Join(cfg.rootFor(manifest.TypePypi), "combined-requirements.txt")
	_, _ = fmt.Fprintf(out, "\n>>> [pypi] fetch — resolving requirements\n")

	indexRoot, err := pypiIndexRoot(ctx, store)
	if err != nil {
		result.Err = err
		_, _ = fmt.Fprintf(out, "    FAILED: %v\n", err)
		summary.Failures++
		summary.Results = append(summary.Results, result)
		summary.Total++
		return summary
	}

	reqLines := []string{"# Auto-generated by bodega from pypi manifests\n"}
	if line := pypiIndexLine(indexRoot); line != "" {
		_, _ = fmt.Fprintf(out, "    Index: %s\n", indexRoot)
		reqLines = append(reqLines, line)
	}

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
		if err := pypiSourceConflict(reqPath, indexRoot, map[string]bool{}); err != nil {
			result.Err = fmt.Errorf("pypi base requirements for %s@%s: %w", repoName, ref, err)
			_, _ = fmt.Fprintf(out, "    FAILED: %v\n", result.Err)
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
			resolved, err := resolvePypiVersion(indexRoot, name, ve)
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

	if err := verifyPypiWheels(combinedReq, wheelsDir); err != nil {
		result.Err = err
		_, _ = fmt.Fprintf(out, "    FAILED: %v\n", err)
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
