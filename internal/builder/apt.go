package builder

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/scaleapi/bodega/internal/manifest"
)

// aptSourceDir returns the source directory path for an apt package version.
// When the VersionEntry has a Version set, the directory is named
// "<sourceName>-<version>" to allow multiple versions to coexist.
// Falls back to "<sourceName>" when empty.
func aptSourceDir(d dirs, name string, ve manifest.VersionEntry) string {
	sourceName := ve.SourceName
	if sourceName == "" {
		sourceName = name
	}
	if ve.Version != "" {
		return filepath.Join(d.sources, sourceName+"-"+ve.Version)
	}
	return filepath.Join(d.sources, sourceName)
}

// CheckAptStage inspects the filesystem to determine which pipeline stages have
// completed for the given apt package version. It does not run any commands.
func CheckAptStage(cfg *Config, name string, ve manifest.VersionEntry) StageStatus {
	d := buildDirs(cfg.rootFor(manifest.TypeApt))
	var s StageStatus

	sourceName := ve.SourceName
	if sourceName == "" {
		sourceName = name
	}

	if ve.URL != "" {
		// Source-build entry: fetch = clone dir exists.
		cloneDir := aptSourceDir(d, name, ve)
		if fi, err := os.Stat(cloneDir); err == nil && fi.IsDir() {
			s.Fetched = true
		}
		if s.Fetched {
			// Build = .deb file present inside the clone dir.
			glob := ve.DebGlob
			if glob == "" {
				glob = "*.deb"
			}
			matches, _ := filepath.Glob(filepath.Join(cloneDir, glob))
			s.Built = len(matches) > 0
		}
	} else {
		// apt-get download entry: fetch = .deb file present in sources dir.
		matches, _ := filepath.Glob(filepath.Join(d.sources, sourceName+"*.deb"))
		s.Fetched = len(matches) > 0
		s.Built = s.Fetched // no separate build step for apt-get entries
	}

	// Packaged = at least one .deb in the reprepro pool for this package.
	poolGlob := filepath.Join(d.aptRepo, "pool", "main", "*", sourceName+"*.deb")
	if matches, _ := filepath.Glob(poolGlob); len(matches) > 0 {
		s.Packaged = true
	}

	return s
}

// FetchApt fetches the source for each apt package version. For versions with
// a URL the source is git-cloned into <build-root>/sources/<source_name[-version]>/.
// For versions without a URL the .deb is downloaded via apt-get download into
// <build-root>/sources/.
func FetchApt(cfg *Config, store *manifest.Store, entryFilter string) *Summary {
	ctx := context.Background()
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypeApt))

	srcDir := d.sources
	if err := mkdirAll(srcDir); err != nil {
		cfg.logf("ERROR: %v", err)
		return summary
	}

	for _, name := range store.ListPackages(manifest.TypeApt) {
		if entryFilter != "" && name != entryFilter {
			continue
		}

		pm, err := store.GetPackage(ctx, manifest.TypeApt, name)
		if err != nil || pm == nil {
			cfg.logf("  [apt] %s: ERROR loading package: %v", name, err)
			continue
		}

		for _, ve := range pm.Versions {
			if ve.Frozen {
				cfg.logf("  [apt] %s: SKIPPED (frozen)", name)
				continue
			}
			if !cfg.Force {
				stage := CheckAptStage(cfg, name, ve)
				if stage.Fetched {
					cfg.logf("  [apt] %s: already fetched, skipping", name)
					continue
				}
			}

			start := time.Now()
			result := Result{Type: manifest.TypeApt, Name: name}
			out := cfg.entryWriter(manifest.TypeApt, name)

			_, _ = fmt.Fprintf(out, "\n>>> [apt] fetch %s\n", name)

			var artifactPath string
			var fetchErr error

			if ve.URL != "" {
				cloneDir := aptSourceDir(d, name, ve)
				if err := os.RemoveAll(cloneDir); err != nil {
					fetchErr = fmt.Errorf("remove old source %s: %w", cloneDir, err)
				} else {
					_, _ = fmt.Fprintf(out, "    Cloning %s...\n", ve.URL)
					if err := runCmd(out, "", "git", "clone", "--depth", "1", ve.URL, cloneDir); err != nil {
						fetchErr = fmt.Errorf("git clone: %w", err)
					} else {
						artifactPath = cloneDir
						_, _ = fmt.Fprintf(out, "    Source: %s\n", cloneDir)
					}
				}
			} else {
				sourceName := ve.SourceName
				if sourceName == "" {
					sourceName = name
				}
				_, _ = fmt.Fprintf(out, "    Downloading %s via apt-get download...\n", sourceName)
				if err := runCmd(out, srcDir, "apt-get", "download", sourceName); err != nil {
					fetchErr = fmt.Errorf("apt-get download %s: %w", sourceName, err)
				} else {
					matches, err := filepath.Glob(filepath.Join(srcDir, sourceName+"*.deb"))
					if err != nil || len(matches) == 0 {
						fetchErr = fmt.Errorf("no .deb found for %s in %s", sourceName, srcDir)
					} else {
						artifactPath = matches[0]
						_, _ = fmt.Fprintf(out, "    Downloaded: %s\n", filepath.Base(artifactPath))
					}
				}
			}

			if fetchErr != nil {
				result.Err = fetchErr
				_, _ = fmt.Fprintf(out, "    ERROR: %v\n", result.Err)
				summary.Failures++
			} else {
				result.Artifacts = []string{artifactPath}
			}

			result.Elapsed = time.Since(start)
			summary.Results = append(summary.Results, result)
			summary.Total++
			_, _ = fmt.Fprintf(out, "    Done (%s)\n", result.Elapsed.Round(time.Millisecond))

			if cfg.Logger != nil {
				if result.Err != nil {
					cfg.Logger.Audit("FAILED  apt/fetch/%s  (%s)  %v", name, result.Elapsed.Round(time.Millisecond), result.Err)
				} else {
					cfg.Logger.Audit("OK      apt/fetch/%s  (%s)", name, result.Elapsed.Round(time.Millisecond))
				}
			}
		}
	}

	return summary
}

// BuildApt runs the build_cmd for each apt package version that was fetched
// from a git source. Versions without a URL (downloaded via apt-get) have no
// build step and are skipped silently.
func BuildApt(cfg *Config, store *manifest.Store, entryFilter string) *Summary {
	ctx := context.Background()
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypeApt))

	for _, name := range store.ListPackages(manifest.TypeApt) {
		if entryFilter != "" && name != entryFilter {
			continue
		}

		pm, err := store.GetPackage(ctx, manifest.TypeApt, name)
		if err != nil || pm == nil {
			cfg.logf("  [apt] %s: ERROR loading package: %v", name, err)
			continue
		}

		for _, ve := range pm.Versions {
			if ve.Frozen {
				cfg.logf("  [apt] %s: SKIPPED (frozen)", name)
				continue
			}

			// Only source-build entries have a build step.
			if ve.URL == "" {
				continue
			}

			start := time.Now()
			result := Result{Type: manifest.TypeApt, Name: name}
			out := cfg.entryWriter(manifest.TypeApt, name)

			_, _ = fmt.Fprintf(out, "\n>>> [apt] build %s\n", name)

			cloneDir := aptSourceDir(d, name, ve)
			if _, err := os.Stat(cloneDir); os.IsNotExist(err) {
				result.Err = fmt.Errorf("source directory not found at %s — run 'fetch apt' first", cloneDir)
				_, _ = fmt.Fprintf(out, "    ERROR: %v\n", result.Err)
				summary.Failures++
				result.Elapsed = time.Since(start)
				summary.Results = append(summary.Results, result)
				summary.Total++
				continue
			}

			if ve.BuildCmd != "" {
				_, _ = fmt.Fprintf(out, "    Running: %s\n", ve.BuildCmd)
				if err := runCmd(out, cloneDir, "sh", "-c", ve.BuildCmd); err != nil {
					result.Err = fmt.Errorf("build_cmd %q: %w", ve.BuildCmd, err)
					_, _ = fmt.Fprintf(out, "    ERROR: %v\n", result.Err)
					summary.Failures++
					result.Elapsed = time.Since(start)
					summary.Results = append(summary.Results, result)
					summary.Total++
					continue
				}
			} else {
				_, _ = fmt.Fprintf(out, "    No build_cmd configured; skipping compilation step.\n")
			}

			// Locate the produced .deb to confirm the build succeeded.
			glob := ve.DebGlob
			if glob == "" {
				glob = "*.deb"
			}
			matches, err := filepath.Glob(filepath.Join(cloneDir, glob))
			if err != nil || len(matches) == 0 {
				result.Err = fmt.Errorf("no .deb found matching %s in %s after build", glob, cloneDir)
				_, _ = fmt.Fprintf(out, "    ERROR: %v\n", result.Err)
				summary.Failures++
			} else {
				result.Artifacts = []string{matches[0]}
				fi, _ := os.Stat(matches[0])
				if fi != nil {
					_, _ = fmt.Fprintf(out, "    Built: %s (%s)\n", filepath.Base(matches[0]), humanBytes(fi.Size()))
				}
			}

			result.Elapsed = time.Since(start)
			summary.Results = append(summary.Results, result)
			summary.Total++
			_, _ = fmt.Fprintf(out, "    Done (%s)\n", result.Elapsed.Round(time.Millisecond))

			if cfg.Logger != nil {
				if result.Err != nil {
					cfg.Logger.Audit("FAILED  apt/build/%s  (%s)  %v", name, result.Elapsed.Round(time.Millisecond), result.Err)
				} else {
					cfg.Logger.Audit("OK      apt/build/%s  (%s)", name, result.Elapsed.Round(time.Millisecond))
				}
			}
		}
	}

	return summary
}

// PackageApt adds each built .deb into a reprepro APT repository under
// <build-root>/apt-repo/. The .deb must already exist (produced by FetchApt
// for apt-get entries, or by BuildApt for source-build entries).
func PackageApt(cfg *Config, store *manifest.Store, entryFilter string) *Summary {
	ctx := context.Background()
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypeApt))

	if err := mkdirAll(d.aptRepo); err != nil {
		cfg.logf("ERROR: %v", err)
		return summary
	}

	if err := setupAptRepo(cfg, d.aptRepo); err != nil {
		cfg.logf("ERROR setting up APT repo: %v", err)
		return summary
	}

	for _, name := range store.ListPackages(manifest.TypeApt) {
		if entryFilter != "" && name != entryFilter {
			continue
		}

		pm, err := store.GetPackage(ctx, manifest.TypeApt, name)
		if err != nil || pm == nil {
			cfg.logf("  [apt] %s: ERROR loading package: %v", name, err)
			continue
		}

		for _, ve := range pm.Versions {
			if ve.Frozen {
				cfg.logf("  [apt] %s: SKIPPED (frozen)", name)
				continue
			}

			start := time.Now()
			result := Result{Type: manifest.TypeApt, Name: name}
			out := cfg.entryWriter(manifest.TypeApt, name)

			_, _ = fmt.Fprintf(out, "\n>>> [apt] package %s\n", name)

			debFile, err := locateDebFile(d, name, ve)
			if err != nil {
				result.Err = err
				_, _ = fmt.Fprintf(out, "    ERROR: %v\n", result.Err)
				summary.Failures++
				result.Elapsed = time.Since(start)
				summary.Results = append(summary.Results, result)
				summary.Total++
				continue
			}

			fi, err := os.Stat(debFile)
			if err != nil {
				result.Err = fmt.Errorf("stat deb file: %w", err)
				_, _ = fmt.Fprintf(out, "    ERROR: %v\n", result.Err)
				summary.Failures++
				result.Elapsed = time.Since(start)
				summary.Results = append(summary.Results, result)
				summary.Total++
				continue
			}
			_, _ = fmt.Fprintf(out, "    Package: %s (%s)\n", filepath.Base(debFile), humanBytes(fi.Size()))

			_, _ = fmt.Fprintf(out, "    Adding to APT repository...\n")
			if err := runCmd(out, "", "reprepro", "-b", d.aptRepo, "includedeb", "noble", debFile); err != nil {
				result.Err = fmt.Errorf("reprepro includedeb: %w", err)
				_, _ = fmt.Fprintf(out, "    ERROR: %v\n", result.Err)
				summary.Failures++
			} else {
				result.Artifacts = []string{debFile}
			}

			result.Elapsed = time.Since(start)
			summary.Results = append(summary.Results, result)
			summary.Total++
			_, _ = fmt.Fprintf(out, "    Done (%s)\n", result.Elapsed.Round(time.Millisecond))

			if cfg.Logger != nil {
				if result.Err != nil {
					cfg.Logger.Audit("FAILED  apt/package/%s  (%s)  %v", name, result.Elapsed.Round(time.Millisecond), result.Err)
				} else {
					cfg.Logger.Audit("OK      apt/package/%s  (%s)", name, result.Elapsed.Round(time.Millisecond))
				}
			}
		}
	}

	return summary
}

// RunApt runs the full apt pipeline (FetchApt → BuildApt → PackageApt) for
// backward compatibility. New callers should invoke the stage functions
// individually.
func RunApt(cfg *Config, store *manifest.Store, entryFilter string) *Summary {
	fetchSummary := FetchApt(cfg, store, entryFilter)
	if fetchSummary.HasFailures() {
		return fetchSummary
	}
	buildSummary := BuildApt(cfg, store, entryFilter)
	if buildSummary.HasFailures() {
		return mergeSummaries(fetchSummary, buildSummary)
	}
	pkgSummary := PackageApt(cfg, store, entryFilter)
	return mergeSummaries(mergeSummaries(fetchSummary, buildSummary), pkgSummary)
}

// locateDebFile returns the path of the .deb for a package version.
// For source-build versions (ve.URL set) it looks inside the versioned clone
// directory using deb_glob. For apt-get download versions it looks in the
// sources root directory for <sourceName>*.deb.
func locateDebFile(d dirs, name string, ve manifest.VersionEntry) (string, error) {
	sourceName := ve.SourceName
	if sourceName == "" {
		sourceName = name
	}

	if ve.URL != "" {
		cloneDir := aptSourceDir(d, name, ve)
		if _, err := os.Stat(cloneDir); os.IsNotExist(err) {
			return "", fmt.Errorf("source directory not found at %s — run 'fetch apt' and 'build apt' first", cloneDir)
		}
		glob := ve.DebGlob
		if glob == "" {
			glob = "*.deb"
		}
		matches, err := filepath.Glob(filepath.Join(cloneDir, glob))
		if err != nil || len(matches) == 0 {
			return "", fmt.Errorf("no .deb found matching %s in %s — run 'build apt' first", glob, cloneDir)
		}
		return matches[0], nil
	}

	// apt-get download path: .deb lands directly in sources root.
	matches, err := filepath.Glob(filepath.Join(d.sources, sourceName+"*.deb"))
	if err != nil || len(matches) == 0 {
		return "", fmt.Errorf("no .deb found for %s in %s — run 'fetch apt' first", sourceName, d.sources)
	}
	return matches[0], nil
}

// setupAptRepo creates the reprepro configuration directory and a GPG signing
// key if one does not already exist for the bootstrap email.
func setupAptRepo(cfg *Config, aptRepoDir string) error {
	out := cfg.stdout()
	confDir := filepath.Join(aptRepoDir, "conf")
	if err := mkdirAll(confDir); err != nil {
		return err
	}

	const gpgEmail = "infra@scale.com"
	const gpgName = "Scale Bootstrap Repo"

	// Generate GPG key if absent.
	checkOut, _ := runCmdCapture("", "gpg", "--list-keys", gpgEmail)
	if checkOut == "" {
		_, _ = fmt.Fprintf(out, "    Generating GPG signing key for %s...\n", gpgEmail)
		batchInput := fmt.Sprintf(
			"Key-Type: RSA\nKey-Length: 4096\nName-Real: %s\nName-Email: %s\nExpire-Date: 0\n%%no-protection\n",
			gpgName, gpgEmail,
		)
		tmpFile, err := os.CreateTemp("", "gpg-batch-*.txt")
		if err != nil {
			return fmt.Errorf("create gpg batch file: %w", err)
		}
		defer func() { _ = os.Remove(tmpFile.Name()) }()
		if _, err := tmpFile.WriteString(batchInput); err != nil {
			return fmt.Errorf("write gpg batch file: %w", err)
		}
		if err := tmpFile.Close(); err != nil {
			return fmt.Errorf("close gpg batch file: %w", err)
		}
		if err := runCmd(out, "", "gpg", "--batch", "--gen-key", tmpFile.Name()); err != nil {
			return fmt.Errorf("gpg key generation: %w", err)
		}
	} else {
		_, _ = fmt.Fprintf(out, "    GPG key for %s already exists.\n", gpgEmail)
	}

	// Retrieve key ID.
	keyOut, err := runCmdCapture("", "gpg", "--list-keys", "--keyid-format", "long", gpgEmail)
	if err != nil {
		return fmt.Errorf("gpg list-keys: %w", err)
	}
	keyID := extractGPGKeyID(keyOut)
	if keyID == "" {
		return fmt.Errorf("could not parse GPG key ID from: %s", keyOut)
	}
	_, _ = fmt.Fprintf(out, "    GPG Key ID: %s\n", keyID)

	// Export public key.
	keyExportPath := filepath.Join(aptRepoDir, "gpg-key.asc")
	keyASC, err := runCmdCapture("", "gpg", "--export", "--armor", keyID)
	if err != nil {
		return fmt.Errorf("gpg export: %w", err)
	}
	if err := os.WriteFile(keyExportPath, []byte(keyASC), 0o644); err != nil {
		return fmt.Errorf("write gpg-key.asc: %w", err)
	}

	// Write reprepro distributions file.
	distPath := filepath.Join(confDir, "distributions")
	distContent := fmt.Sprintf(
		"Codename: noble\nComponents: main\nArchitectures: amd64\nSignWith: %s\nDescription: Scale internal bootstrap packages for Ubuntu 24.04 (Noble)\n",
		keyID,
	)
	if err := os.WriteFile(distPath, []byte(distContent), 0o644); err != nil {
		return fmt.Errorf("write reprepro distributions: %w", err)
	}

	return nil
}

// extractGPGKeyID parses the key ID from gpg --list-keys output.
// It looks for lines like "      rsa4096/ABCDEF1234567890 2025-..."
func extractGPGKeyID(output string) string {
	for _, line := range splitLines(output) {
		// Look for a line containing "rsa4096/" which indicates the key line.
		const marker = "rsa4096/"
		if idx := indexOf(line, marker); idx >= 0 {
			rest := line[idx+len(marker):]
			// Key ID ends at a space or end of string.
			end := indexOf(rest, " ")
			if end < 0 {
				end = len(rest)
			}
			if end > 0 {
				return rest[:end]
			}
		}
	}
	return ""
}

// splitLines splits a string into individual lines.
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// indexOf returns the index of substr in s, or -1 if not found.
func indexOf(s, substr string) int {
	if len(substr) == 0 {
		return 0
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
