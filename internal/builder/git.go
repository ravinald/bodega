package builder

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/manifest"
)

// gitBareDir returns the path of the bare repository for a GitEntry. The
// directory is always named "<name>-<ref>.git" because the Ref field is the
// version identifier for git entries and is always non-empty.
func gitBareDir(d dirs, entry manifest.GitEntry) string {
	return filepath.Join(d.repos, entry.Name+"-"+entry.Ref+".git")
}

// CheckGitStage inspects the filesystem to determine which pipeline stages have
// completed for the given GitEntry. It does not run any commands.
func CheckGitStage(cfg *Config, entry manifest.GitEntry) StageStatus {
	d := buildDirs(cfg.rootFor(manifest.TypeGit))
	var s StageStatus

	if entry.IsRelease() {
		// Release mode: fetched = extracted directory exists.
		releaseDir := gitReleaseDir(d, entry)
		if fi, err := os.Stat(releaseDir); err == nil && fi.IsDir() {
			s.Fetched = true
			// For release mode, the tarball IS the artifact — no separate build/package.
			s.Built = true
			s.Packaged = true
		}
	} else {
		// Clone mode: fetched = bare repo exists, packaged = bundle exists.
		bareDir := gitBareDir(d, entry)
		if fi, err := os.Stat(bareDir); err == nil && fi.IsDir() {
			s.Fetched = true
		}
		bundleDir := filepath.Join(d.bundles, entry.Name)
		bundlePath := filepath.Join(bundleDir, entry.Name+"-"+entry.Ref+".bundle")
		if fi, err := os.Stat(bundlePath); err == nil && !fi.IsDir() {
			s.Built = true
			s.Packaged = true
		}
	}

	return s
}

// FetchGit clones each GitEntry as a bare repository under
// <build-root>/repos/<name>-<ref>.git. An existing clone at that path is
// removed before cloning so the result is always a fresh copy of the ref.
func FetchGit(cfg *Config, store *manifest.Store, entryFilter string) *Summary {
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypeGit))

	if err := mkdirAll(d.repos); err != nil {
		cfg.logf("ERROR: %v", err)
		return summary
	}
	if err := mkdirAll(d.sources); err != nil {
		cfg.logf("ERROR: %v", err)
		return summary
	}

	for _, entry := range store.Git {
		if entryFilter != "" && entry.Name != entryFilter {
			continue
		}
		if entry.Frozen {
			cfg.logf("  [git] %s: SKIPPED (frozen)", entry.Name)
			continue
		}

		start := time.Now()
		result := Result{Type: manifest.TypeGit, Name: entry.Name}
		out := cfg.entryWriter(manifest.TypeGit, entry.Name)

		_, _ = fmt.Fprintf(out, "\n>>> [git] fetch %s @ %s\n", entry.Name, entry.Ref)
		_, _ = fmt.Fprintf(out, "    URL: %s\n", entry.URL)

		if entry.IsRelease() {
			// Release mode: download tarball and extract.
			_, _ = fmt.Fprintf(out, "    Mode: release tarball\n")
			extractDir := gitReleaseDir(d, entry)
			if err := fetchGitRelease(out, entry, extractDir); err != nil {
				result.Err = err
				_, _ = fmt.Fprintf(out, "    ERROR: %v\n", result.Err)
				summary.Failures++
			} else {
				result.Artifacts = []string{extractDir}
				_, _ = fmt.Fprintf(out, "    Extracted: %s\n", extractDir)
			}
		} else {
			// Clone mode: bare clone.
			_, _ = fmt.Fprintf(out, "    Mode: bare clone\n")
			bareDir := gitBareDir(d, entry)
			if err := fetchGitRepo(out, bareDir, entry.URL); err != nil {
				result.Err = err
				_, _ = fmt.Fprintf(out, "    ERROR: %v\n", result.Err)
				summary.Failures++
			} else {
				result.Artifacts = []string{bareDir}
				_, _ = fmt.Fprintf(out, "    Bare repo: %s\n", bareDir)
			}
		}

		result.Elapsed = time.Since(start)
		summary.Results = append(summary.Results, result)
		summary.Total++
		_, _ = fmt.Fprintf(out, "    Done (%s)\n", result.Elapsed.Round(time.Millisecond))

		if cfg.Logger != nil {
			if result.Err != nil {
				cfg.Logger.Audit("FAILED  git/fetch/%s  (%s)  %v", entry.Name, result.Elapsed.Round(time.Millisecond), result.Err)
			} else {
				cfg.Logger.Audit("OK      git/fetch/%s  (%s)", entry.Name, result.Elapsed.Round(time.Millisecond))
			}
		}
	}

	return summary
}

// PackageGit creates a git bundle for each GitEntry and verifies it. The bare
// repo must already exist (produced by FetchGit). Bundle path:
//
//	<build-root>/bundles/<name>/<name>-<ref>.bundle
func PackageGit(cfg *Config, store *manifest.Store, entryFilter string) *Summary {
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypeGit))

	if err := mkdirAll(d.bundles); err != nil {
		cfg.logf("ERROR: %v", err)
		return summary
	}

	for _, entry := range store.Git {
		if entryFilter != "" && entry.Name != entryFilter {
			continue
		}
		if entry.Frozen {
			cfg.logf("  [git] %s: SKIPPED (frozen)", entry.Name)
			continue
		}

		start := time.Now()
		result := Result{Type: manifest.TypeGit, Name: entry.Name}
		out := cfg.entryWriter(manifest.TypeGit, entry.Name)

		_, _ = fmt.Fprintf(out, "\n>>> [git] package %s @ %s\n", entry.Name, entry.Ref)

		bareDir := gitBareDir(d, entry)
		if _, err := os.Stat(bareDir); os.IsNotExist(err) {
			result.Err = fmt.Errorf("bare repo not found at %s — run 'fetch git' first", bareDir)
			_, _ = fmt.Fprintf(out, "    ERROR: %v\n", result.Err)
			summary.Failures++
			result.Elapsed = time.Since(start)
			summary.Results = append(summary.Results, result)
			summary.Total++
			if cfg.Logger != nil {
				cfg.Logger.Audit("FAILED  git/package/%s  (%s)  %v", entry.Name, result.Elapsed.Round(time.Millisecond), result.Err)
			}
			continue
		}

		bundlePath, err := packageGitBundle(out, d, entry)
		if err != nil {
			result.Err = err
			_, _ = fmt.Fprintf(out, "    ERROR: %v\n", result.Err)
			summary.Failures++
		} else {
			result.Artifacts = []string{bundlePath}
			fi, _ := os.Stat(bundlePath)
			if fi != nil {
				_, _ = fmt.Fprintf(out, "    Bundle: %s (%s)\n", filepath.Base(bundlePath), humanBytes(fi.Size()))
			}
		}

		result.Elapsed = time.Since(start)
		summary.Results = append(summary.Results, result)
		summary.Total++
		_, _ = fmt.Fprintf(out, "    Done (%s)\n", result.Elapsed.Round(time.Millisecond))

		if cfg.Logger != nil {
			if result.Err != nil {
				cfg.Logger.Audit("FAILED  git/package/%s  (%s)  %v", entry.Name, result.Elapsed.Round(time.Millisecond), result.Err)
			} else {
				cfg.Logger.Audit("OK      git/package/%s  (%s)", entry.Name, result.Elapsed.Round(time.Millisecond))
			}
		}
	}

	return summary
}

// BuildGit runs the full git pipeline (FetchGit then PackageGit) for backward
// compatibility. New callers should invoke the stage functions individually.
func BuildGit(cfg *Config, store *manifest.Store, entryFilter string) *Summary {
	fetchSummary := FetchGit(cfg, store, entryFilter)
	if fetchSummary.HasFailures() {
		return fetchSummary
	}
	pkgSummary := PackageGit(cfg, store, entryFilter)
	return mergeSummaries(fetchSummary, pkgSummary)
}

// fetchGitRepo removes any stale clone and performs a fresh bare clone.
func fetchGitRepo(out interface{ Write([]byte) (int, error) }, bareDir, url string) error {
	if err := os.RemoveAll(bareDir); err != nil {
		return fmt.Errorf("remove old repo %s: %w", bareDir, err)
	}

	_, _ = fmt.Fprintf(out, "    Cloning (bare) %s...\n", url)
	if err := runCmd(out, "", "git", "clone", "--bare", url, bareDir); err != nil {
		return fmt.Errorf("git clone: %w", err)
	}
	return nil
}

// packageGitBundle creates and verifies a git bundle for the given entry.
func packageGitBundle(out interface{ Write([]byte) (int, error) }, d dirs, entry manifest.GitEntry) (string, error) {
	bareDir := gitBareDir(d, entry)

	bundleDir := filepath.Join(d.bundles, entry.Name)
	if err := mkdirAll(bundleDir); err != nil {
		return "", err
	}
	bundlePath := filepath.Join(bundleDir, entry.Name+"-"+entry.Ref+".bundle")

	// Remove stale lock files from previous failed runs.
	lockFile := bundlePath + ".lock"
	if _, err := os.Stat(lockFile); err == nil {
		_, _ = fmt.Fprintf(out, "    Removing stale lock: %s\n", lockFile)
		_ = os.Remove(lockFile)
	}

	_, _ = fmt.Fprintf(out, "    Creating bundle for ref %s...\n", entry.Ref)
	if err := runCmd(out, bareDir, "git", "bundle", "create", bundlePath, entry.Ref); err != nil {
		return "", fmt.Errorf("git bundle create: %w", err)
	}

	_, _ = fmt.Fprintf(out, "    Verifying bundle...\n")
	if err := runCmd(out, bareDir, "git", "bundle", "verify", bundlePath); err != nil {
		return "", fmt.Errorf("git bundle verify: %w", err)
	}

	return bundlePath, nil
}

// mergeSummaries combines two Summary values into a single one. Used by
// convenience wrapper functions that call multiple stage functions.
func mergeSummaries(a, b *Summary) *Summary {
	merged := &Summary{}
	merged.Results = append(merged.Results, a.Results...)
	merged.Results = append(merged.Results, b.Results...)
	merged.Total = a.Total + b.Total
	merged.Failures = a.Failures + b.Failures
	return merged
}

// GitWorktreePath returns the path of a checked-out worktree for a given
// repo name and ref. Used by the pypi builder to locate requirements.txt.
// Returns empty string when the bare repo does not exist.
func GitWorktreePath(buildRoot, name, ref string) (string, error) {
	d := buildDirs(buildRoot)
	entry := manifest.GitEntry{Name: name, Ref: ref}

	// Check for release-mode extraction first (preferred).
	releaseDir := gitReleaseDir(d, entry)
	if fi, err := os.Stat(releaseDir); err == nil && fi.IsDir() {
		return releaseDir, nil
	}

	// Fall back to clone-mode worktree.
	bareDir := gitBareDir(d, entry)
	if _, err := os.Stat(bareDir); os.IsNotExist(err) {
		return "", nil
	}

	workDir := filepath.Join(d.repos, name+"-"+ref+"-worktree")
	if _, err := os.Stat(workDir); os.IsNotExist(err) {
		out, err := runCmdCapture(bareDir, "git", "worktree", "add", workDir, ref)
		if err != nil {
			out2, err2 := runCmdCapture(bareDir, "git", "worktree", "add", workDir, "refs/tags/"+ref)
			if err2 != nil {
				return "", fmt.Errorf("git worktree add: %w\n%s", err, out+out2)
			}
			_ = out
		}
	}
	return workDir, nil
}

// gitReleaseDir returns the extraction directory for a release tarball.
func gitReleaseDir(d dirs, entry manifest.GitEntry) string {
	return filepath.Join(d.sources, entry.Name+"-"+entry.Ref)
}

// releaseURL constructs the GitHub release tarball URL from the repo URL and ref.
// Handles URLs ending in .git or without.
// e.g., https://github.com/netbox-community/netbox.git + v4.5.5
//     → https://github.com/netbox-community/netbox/archive/refs/tags/v4.5.5.tar.gz
func releaseURL(repoURL, ref string) string {
	base := strings.TrimSuffix(repoURL, ".git")
	return base + "/archive/refs/tags/" + ref + ".tar.gz"
}

// fetchGitRelease downloads a release tarball, extracts it, and renames the
// extracted directory to the expected path.
func fetchGitRelease(out io.Writer, entry manifest.GitEntry, extractDir string) error {
	url := releaseURL(entry.URL, entry.Ref)
	_, _ = fmt.Fprintf(out, "    Downloading %s\n", url)

	// Ensure parent directory exists.
	if err := os.MkdirAll(filepath.Dir(extractDir), 0o755); err != nil {
		return fmt.Errorf("create parent dir: %w", err)
	}

	// Download to a temp file.
	tarball := extractDir + ".tar.gz"
	if err := downloadFile(out, url, tarball); err != nil {
		return fmt.Errorf("download release tarball: %w", err)
	}
	defer func() { _ = os.Remove(tarball) }()

	// Remove any previous extraction.
	if err := os.RemoveAll(extractDir); err != nil {
		return fmt.Errorf("remove old extraction: %w", err)
	}

	// Extract. GitHub tarballs contain a single top-level directory named
	// <repo>-<ref>/ (e.g., netbox-4.5.5/ without the leading 'v').
	// We extract to a temp dir and rename the inner directory.
	tmpDir := extractDir + "-tmp"
	if err := os.RemoveAll(tmpDir); err != nil {
		return fmt.Errorf("remove temp dir: %w", err)
	}
	if err := mkdirAll(tmpDir); err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	_, _ = fmt.Fprintf(out, "    Extracting...\n")
	if err := runCmd(out, "", "tar", "xzf", tarball, "-C", tmpDir); err != nil {
		return fmt.Errorf("extract tarball: %w", err)
	}

	// Find the single extracted directory.
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return fmt.Errorf("read extracted dir: %w", err)
	}
	if len(entries) != 1 || !entries[0].IsDir() {
		return fmt.Errorf("unexpected tarball contents: expected 1 directory, got %d entries", len(entries))
	}

	innerDir := filepath.Join(tmpDir, entries[0].Name())
	if err := os.Rename(innerDir, extractDir); err != nil {
		return fmt.Errorf("rename %s → %s: %w", innerDir, extractDir, err)
	}

	fi, _ := os.Stat(extractDir)
	if fi != nil {
		_, _ = fmt.Fprintf(out, "    Extracted to: %s\n", extractDir)
	}
	return nil
}
