package builder

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/scaleapi/bodega/internal/manifest"
)

// safeName replaces forward slashes with "--" so names like
// "netbox-community/netbox" become "netbox-community--netbox",
// safe for filesystem paths, S3 keys, and URLs.
func safeName(name string) string {
	return strings.ReplaceAll(name, "/", "--")
}

// gitBareDir returns the path of the bare repository for a git package version.
func gitBareDir(d dirs, name string, ve manifest.VersionEntry) string {
	sn := safeName(name)
	return filepath.Join(d.repos, sn, sn+"-"+ve.Ref+".git")
}

// CheckGitStage inspects the filesystem to determine which pipeline stages have
// completed for the given git package version. It does not run any commands.
func CheckGitStage(cfg *Config, name string, ve manifest.VersionEntry) StageStatus {
	d := buildDirs(cfg.rootFor(manifest.TypeGit))
	var s StageStatus

	if ve.IsRelease() {
		// Release mode: fetched = extracted directory exists,
		// packaged = archive exists in bundles for upload.
		releaseDir := gitReleaseDir(d, name, ve)
		if fi, err := os.Stat(releaseDir); err == nil && fi.IsDir() {
			s.Fetched = true
			s.Built = true
		}
		archive := gitReleaseArchive(d, name, ve)
		if fi, err := os.Stat(archive); err == nil && !fi.IsDir() {
			s.Packaged = true
		}
	} else {
		// Clone mode: fetched = bare repo exists, packaged = bundle exists.
		bareDir := gitBareDir(d, name, ve)
		if fi, err := os.Stat(bareDir); err == nil && fi.IsDir() {
			s.Fetched = true
		}
		bundleDir := filepath.Join(d.bundles, safeName(name))
		bundlePath := filepath.Join(bundleDir, safeName(name)+"-"+ve.Ref+".bundle")
		if fi, err := os.Stat(bundlePath); err == nil && !fi.IsDir() {
			s.Built = true
			s.Packaged = true
		}
	}

	return s
}

// FetchGit clones each git package version as a bare repository under
// <build-root>/repos/<name>-<ref>.git. An existing clone at that path is
// removed before cloning so the result is always a fresh copy of the ref.
func FetchGit(cfg *Config, store *manifest.Store, entryFilter string) *Summary {
	ctx := context.Background()
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

	for _, name := range store.ListPackages(manifest.TypeGit) {
		if entryFilter != "" && name != entryFilter {
			continue
		}

		pm, err := store.GetPackage(ctx, manifest.TypeGit, name)
		if err != nil || pm == nil {
			cfg.logf("  [git] %s: ERROR loading package: %v", name, err)
			continue
		}

		for _, ve := range pm.Versions {
			if ve.Frozen {
				cfg.logf("  [git] %s: SKIPPED (frozen)", name)
				continue
			}
			if !cfg.Force {
				stage := CheckGitStage(cfg, name, ve)
				if stage.Fetched {
					cfg.logf("  [git] %s: already fetched, skipping (use --force to re-fetch)", name)
					continue
				}
			}

			start := time.Now()
			result := Result{Type: manifest.TypeGit, Name: name}
			out := cfg.entryWriter(manifest.TypeGit, name)

			_, _ = fmt.Fprintf(out, "\n>>> [git] fetch %s @ %s\n", name, ve.Ref)
			_, _ = fmt.Fprintf(out, "    URL: %s\n", ve.URL)

			if ve.IsRelease() {
				// Release mode: download tarball and extract.
				_, _ = fmt.Fprintf(out, "    Mode: release tarball\n")
				extractDir := gitReleaseDir(d, name, ve)
				if err := fetchGitRelease(out, d, name, ve, extractDir); err != nil {
					result.Err = err
					_, _ = fmt.Fprintf(out, "    ERROR: %v\n", result.Err)
					summary.Failures++
				} else {
					result.Artifacts = []string{extractDir}
					_, _ = fmt.Fprintf(out, "    Extracted: %s\n", extractDir)

					// Compute checksum of the archive.
					archivePath := gitReleaseArchive(d, name, ve)
					computed, hashErr := computeFileSHA256(archivePath)
					if hashErr != nil {
						_, _ = fmt.Fprintf(out, "    WARNING: could not compute checksum: %v\n", hashErr)
					} else {
						_, _ = fmt.Fprintf(out, "    SHA256: %s\n", computed)

						// Try to verify against existing entry checksum.
						verified := false
						checksumOK := true
						if ve.Checksum != nil {
							if err := verifyChecksum(ve.Checksum, computed); err != nil {
								_, _ = fmt.Fprintf(out, "    WARNING: %v\n", err)
								result.Err = fmt.Errorf("checksum mismatch for %s: %v", name, err)
								summary.Failures++
								checksumOK = false
							} else {
								verified = true
								_, _ = fmt.Fprintf(out, "    Checksum verified against manifest\n")
							}
						} else {
							// Try to fetch source checksum from GitHub.
							sourceHash := fetchGitHubSHA256(out, ve)
							if sourceHash != "" {
								if sourceHash == computed {
									verified = true
									_, _ = fmt.Fprintf(out, "    Checksum verified against source\n")
								} else {
									_, _ = fmt.Fprintf(out, "    WARNING: source checksum mismatch: expected %s, got %s\n", sourceHash, computed)
									result.Err = fmt.Errorf("source checksum mismatch for %s", name)
									summary.Failures++
									checksumOK = false
								}
							}
						}

						// Save computed checksum to manifest only if verification passed.
						if checksumOK {
							cs := newSHA256Checksum(computed)
							if err := cfg.findAndUpdateGitChecksum(store, name, ve, cs, verified); err != nil {
								_, _ = fmt.Fprintf(out, "    WARNING: could not save checksum: %v\n", err)
							}
						}
					}
				}
			} else {
				// Clone mode: bare clone.
				_, _ = fmt.Fprintf(out, "    Mode: bare clone\n")
				bareDir := gitBareDir(d, name, ve)
				if err := fetchGitRepo(out, bareDir, ve.URL); err != nil {
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

			// Stamp build environment on the entry.
			if result.Err == nil {
				cfg.StampGitEntry(store, name, ve)
			}

			// Auto-discover descriptions and dependencies in the fetched source.
			if result.Err == nil {
				// Fetch description for this git package.
				if pm.Description == "" {
					if desc := FetchDescription(manifest.TypeGit, name, ve.URL); desc != "" {
						pm.Description = desc
						_ = store.SavePackage(ctx, pm)
						_, _ = fmt.Fprintf(out, "    Description: %s\n", desc)
					}
				}

				discovery := ScanDeps(cfg, store, name, ve, out)
				cfg.LastDiscovery = &discovery
				if cfg.AutoImportDeps {
					ImportDeps(ctx, store, name, ve, discovery.Deps, out)
					// Fetch descriptions for newly imported deps.
					DiscoverDescriptions(store, out)
				} else if len(discovery.Deps) > 0 {
					newCount := 0
					for _, d := range discovery.Deps {
						if !d.Exists {
							newCount++
						}
					}
					if newCount > 0 {
						_, _ = fmt.Fprintf(out, "    %d new dependencies discovered (auto-import disabled, review pending)\n", newCount)
					}
				}
			}

			if cfg.Logger != nil {
				if result.Err != nil {
					cfg.Logger.Audit("FAILED  git/fetch/%s  (%s)  %v", name, result.Elapsed.Round(time.Millisecond), result.Err)
				} else {
					cfg.Logger.Audit("OK      git/fetch/%s  (%s)", name, result.Elapsed.Round(time.Millisecond))
				}
			}
		}
	}

	return summary
}

// PackageGit creates a git bundle for each git package version and verifies it.
// The bare repo must already exist (produced by FetchGit). Bundle path:
//
//	<build-root>/bundles/<name>/<name>-<ref>.bundle
func PackageGit(cfg *Config, store *manifest.Store, entryFilter string) *Summary {
	ctx := context.Background()
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypeGit))

	if err := mkdirAll(d.bundles); err != nil {
		cfg.logf("ERROR: %v", err)
		return summary
	}

	for _, name := range store.ListPackages(manifest.TypeGit) {
		if entryFilter != "" && name != entryFilter {
			continue
		}

		pm, err := store.GetPackage(ctx, manifest.TypeGit, name)
		if err != nil || pm == nil {
			cfg.logf("  [git] %s: ERROR loading package: %v", name, err)
			continue
		}

		for _, ve := range pm.Versions {
			if ve.Frozen {
				cfg.logf("  [git] %s: SKIPPED (frozen)", name)
				continue
			}

			// Release mode: the extracted tarball IS the artifact — no bundle needed.
			if ve.IsRelease() {
				cfg.logf("  [git] %s: release mode — no packaging needed", name)
				continue
			}

			start := time.Now()
			result := Result{Type: manifest.TypeGit, Name: name}
			out := cfg.entryWriter(manifest.TypeGit, name)

			_, _ = fmt.Fprintf(out, "\n>>> [git] package %s @ %s\n", name, ve.Ref)

			bareDir := gitBareDir(d, name, ve)
			if _, err := os.Stat(bareDir); os.IsNotExist(err) {
				result.Err = fmt.Errorf("bare repo not found at %s — run 'fetch git' first", bareDir)
				_, _ = fmt.Fprintf(out, "    ERROR: %v\n", result.Err)
				summary.Failures++
				result.Elapsed = time.Since(start)
				summary.Results = append(summary.Results, result)
				summary.Total++
				if cfg.Logger != nil {
					cfg.Logger.Audit("FAILED  git/package/%s  (%s)  %v", name, result.Elapsed.Round(time.Millisecond), result.Err)
				}
				continue
			}

			bundlePath, err := packageGitBundle(out, d, name, ve)
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
					cfg.Logger.Audit("FAILED  git/package/%s  (%s)  %v", name, result.Elapsed.Round(time.Millisecond), result.Err)
				} else {
					cfg.Logger.Audit("OK      git/package/%s  (%s)", name, result.Elapsed.Round(time.Millisecond))
				}
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

// packageGitBundle creates and verifies a git bundle for the given package version.
func packageGitBundle(out interface{ Write([]byte) (int, error) }, d dirs, name string, ve manifest.VersionEntry) (string, error) {
	bareDir := gitBareDir(d, name, ve)

	bundleDir := filepath.Join(d.bundles, safeName(name))
	if err := mkdirAll(bundleDir); err != nil {
		return "", err
	}
	bundlePath := filepath.Join(bundleDir, safeName(name)+"-"+ve.Ref+".bundle")

	// Remove stale lock files from previous failed runs.
	lockFile := bundlePath + ".lock"
	if _, err := os.Stat(lockFile); err == nil {
		_, _ = fmt.Fprintf(out, "    Removing stale lock: %s\n", lockFile)
		_ = os.Remove(lockFile)
	}

	_, _ = fmt.Fprintf(out, "    Creating bundle for ref %s...\n", ve.Ref)
	if err := runCmd(out, bareDir, "git", "bundle", "create", bundlePath, ve.Ref); err != nil {
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
	ve := manifest.VersionEntry{Ref: ref}

	// Check for release-mode extraction first (preferred).
	releaseDir := gitReleaseDir(d, name, ve)
	if fi, err := os.Stat(releaseDir); err == nil && fi.IsDir() {
		return releaseDir, nil
	}

	// Fall back to clone-mode worktree.
	bareDir := gitBareDir(d, name, ve)
	if _, err := os.Stat(bareDir); os.IsNotExist(err) {
		return "", nil
	}

	workDir := filepath.Join(d.repos, safeName(name)+"-"+ref+"-worktree")
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

// fetchGitHubSHA256 attempts to download a SHA256 checksum from the source.
// GitHub release archives don't have built-in checksums, but some projects
// publish them as release assets (e.g. SHA256SUMS or <ref>.sha256). This
// function tries common patterns and returns the hex digest, or empty string
// if no source checksum is available.
func fetchGitHubSHA256(out io.Writer, ve manifest.VersionEntry) string {
	base := strings.TrimSuffix(ve.URL, ".git")
	// Try: <repo>/releases/download/<ref>/SHA256SUMS
	candidates := []string{
		base + "/releases/download/" + ve.Ref + "/SHA256SUMS",
		base + "/releases/download/" + ve.Ref + "/sha256sums.txt",
	}
	for _, url := range candidates {
		data, err := httpGetBody(url)
		if err != nil || len(data) == 0 {
			continue
		}
		// Parse SHA256SUMS format: "<hash>  <filename>" or "<hash> <filename>"
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && len(fields[0]) == 64 {
				// Look for a line matching the tarball filename.
				tarName := ve.Ref + ".tar.gz"
				if strings.Contains(fields[1], tarName) || strings.HasSuffix(fields[1], ".tar.gz") {
					_, _ = fmt.Fprintf(out, "    Found source checksum at %s\n", url)
					return strings.ToLower(fields[0])
				}
			}
		}
	}
	return ""
}

// httpGetBody fetches a URL and returns the body, or an error.
func httpGetBody(url string) ([]byte, error) {
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
}

// gitReleaseDir returns the extraction directory for a release tarball.
func gitReleaseDir(d dirs, name string, ve manifest.VersionEntry) string {
	return filepath.Join(d.sources, safeName(name), safeName(name)+"-"+ve.Ref)
}

// releaseURL constructs the GitHub release tarball URL from the repo URL and ref.
// Handles URLs ending in .git or without.
// e.g., https://github.com/netbox-community/netbox.git + v4.5.5
//
//	→ https://github.com/netbox-community/netbox/archive/refs/tags/v4.5.5.tar.gz
func releaseURL(repoURL, ref string) string {
	base := strings.TrimSuffix(repoURL, ".git")
	return base + "/archive/refs/tags/" + ref + ".tar.gz"
}

// gitReleaseArchive returns the path where the release tarball is stored for upload.
func gitReleaseArchive(d dirs, name string, ve manifest.VersionEntry) string {
	return filepath.Join(d.bundles, safeName(name), safeName(name)+"-"+ve.Ref+".tar.gz")
}

// fetchGitRelease downloads a release tarball, saves it for S3 upload, and
// extracts it for local use by other builders (e.g. pypi reads requirements.txt).
func fetchGitRelease(out io.Writer, d dirs, name string, ve manifest.VersionEntry, extractDir string) error {
	url := releaseURL(ve.URL, ve.Ref)
	_, _ = fmt.Fprintf(out, "    Downloading %s\n", url)

	// Ensure directories exist.
	if err := os.MkdirAll(filepath.Dir(extractDir), 0o755); err != nil {
		return fmt.Errorf("create parent dir: %w", err)
	}
	archivePath := gitReleaseArchive(d, name, ve)
	if err := os.MkdirAll(filepath.Dir(archivePath), 0o755); err != nil {
		return fmt.Errorf("create bundles dir: %w", err)
	}

	// Download to the bundles directory (kept for S3 upload).
	tarball := archivePath
	if err := downloadFile(out, url, tarball); err != nil {
		return fmt.Errorf("download release tarball: %w", err)
	}
	_, _ = fmt.Fprintf(out, "    Archive: %s\n", tarball)

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
