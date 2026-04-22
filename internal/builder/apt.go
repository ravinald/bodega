package builder

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
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

	switch {
	case ve.URL != "" && ve.BuildCmd != "":
		// Source build from git: fetch = clone dir exists.
		cloneDir := aptSourceDir(d, name, ve)
		if fi, err := os.Stat(cloneDir); err == nil && fi.IsDir() {
			s.Fetched = true
		}
		if s.Fetched {
			glob := ve.DebGlob
			if glob == "" {
				glob = "*.deb"
			}
			matches, _ := filepath.Glob(filepath.Join(cloneDir, glob))
			s.Built = len(matches) > 0
		}

	case ve.URL != "":
		// Direct URL download: fetch = .deb file present.
		destDir := filepath.Join(d.sources, sourceName)
		filename := filepath.Base(ve.URL)
		dest := filepath.Join(destDir, filename)
		if fileExists(dest) {
			s.Fetched = true
			s.Built = true // no build step
		}

	case ve.BuildCmd != "":
		// apt-get source build: fetch = source dir exists.
		sourceDir := aptSourceDir(d, name, ve)
		if fi, err := os.Stat(sourceDir); err == nil && fi.IsDir() {
			s.Fetched = true
		}
		if s.Fetched {
			glob := ve.DebGlob
			if glob == "" {
				glob = "../*.deb"
			}
			matches, _ := filepath.Glob(filepath.Join(sourceDir, glob))
			s.Built = len(matches) > 0
		}

	default:
		// apt-get download: fetch = .deb file present in per-package subdir.
		pkgDir := filepath.Join(d.sources, sourceName)
		matches, _ := filepath.Glob(filepath.Join(pkgDir, sourceName+"*.deb"))
		s.Fetched = len(matches) > 0
		s.Built = s.Fetched // no separate build step
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
			if err := cfg.EnforcePolicy(ctx, manifest.TypeApt, name, ve.Version, ve.URL); err != nil {
				cfg.logf("  [apt] %s: BLOCKED by policy: %v", name, err)
				summary.Failures++
				summary.Results = append(summary.Results, Result{Type: manifest.TypeApt, Name: name, Err: err})
				continue
			}

			// Policy entries (version=*) are not fetchable artifacts.
			// Auto-resolve the concrete version and discover deps as needed.
			if ve.Version == "*" && ve.VersionConstraint == manifest.ConstraintAny {
				sourceName := ve.SourceName
				if sourceName == "" {
					sourceName = name
				}
				out := cfg.entryWriter(manifest.TypeApt, name)

				// 1. Resolve concrete version if none exists yet.
				hasConcreteVersion := false
				for _, other := range pm.Versions {
					if other.Version != "" && other.Version != "*" {
						hasConcreteVersion = true
						break
					}
				}
				if !hasConcreteVersion {
					_, _ = fmt.Fprintf(out, "  [apt] %s: resolving concrete version for policy entry\n", name)
					ResolveAndCreateConcreteVersion(ctx, store, sourceName, out)
					pm, _ = store.GetPackage(ctx, manifest.TypeApt, name)
				}

				// 2. Discover deps if policy is set and none exist yet.
				if pm.DepPolicy != "" && pm.DepPolicy != "none" {
					children := store.ChildrenOf("apt/" + name)
					if len(children) == 0 {
						_, _ = fmt.Fprintf(out, "  [apt] %s: discovering %s dependencies\n", name, pm.DepPolicy)
						deps := DiscoverAptDeps(store, sourceName, pm.DepPolicy, out)
						if len(deps) > 0 {
							ImportAptDeps(ctx, store, name, deps, out)
						}
					}
				}

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

			sourceName := ve.SourceName
			if sourceName == "" {
				sourceName = name
			}

			switch {
			case ve.URL != "" && ve.BuildCmd != "":
				// Source build from git: clone and build later.
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

			case ve.URL != "":
				// Direct URL: download a .deb file.
				destDir := filepath.Join(srcDir, sourceName)
				if err := mkdirAll(destDir); err != nil {
					fetchErr = fmt.Errorf("create dir %s: %w", destDir, err)
				} else {
					filename := filepath.Base(ve.URL)
					dest := filepath.Join(destDir, filename)
					_, _ = fmt.Fprintf(out, "    Downloading %s...\n", ve.URL)
					if err := downloadURL(dest, ve.URL); err != nil {
						fetchErr = fmt.Errorf("download %s: %w", ve.URL, err)
					} else {
						artifactPath = dest
						_, _ = fmt.Fprintf(out, "    Downloaded: %s\n", filename)
					}
				}

			case ve.BuildCmd != "":
				// apt-get source: fetch official source package for local compilation.
				sourceDir := aptSourceDir(d, name, ve)
				parentDir := filepath.Dir(sourceDir)
				if err := mkdirAll(parentDir); err != nil {
					fetchErr = fmt.Errorf("create dir %s: %w", parentDir, err)
				} else {
					_, _ = fmt.Fprintf(out, "    Fetching source for %s via apt-get source...\n", sourceName)
					if err := runCmd(out, parentDir, "apt-get", "source", "--download-only", sourceName); err != nil {
						fetchErr = fmt.Errorf("apt-get source %s: %w", sourceName, err)
					} else {
						// Extract the source.
						if err := runCmd(out, parentDir, "dpkg-source", "-x", sourceName+"*.dsc", sourceDir); err != nil {
							// Try glob match for the .dsc file.
							dscMatches, _ := filepath.Glob(filepath.Join(parentDir, sourceName+"*.dsc"))
							if len(dscMatches) > 0 {
								err = runCmd(out, parentDir, "dpkg-source", "-x", dscMatches[0], sourceDir)
							}
							if err != nil {
								fetchErr = fmt.Errorf("extract source: %w", err)
							}
						}
						if fetchErr == nil {
							artifactPath = sourceDir
							_, _ = fmt.Fprintf(out, "    Source: %s\n", sourceDir)
						}
					}
				}

			default:
				// Package name download: apt-get download into per-package subdirectory.
				pkgDir := filepath.Join(srcDir, sourceName)
				if err := mkdirAll(pkgDir); err != nil {
					fetchErr = fmt.Errorf("create dir %s: %w", pkgDir, err)
				} else {
					_, _ = fmt.Fprintf(out, "    Downloading %s via apt-get download...\n", sourceName)
					if err := runCmd(out, pkgDir, "apt-get", "download", sourceName); err != nil {
						fetchErr = fmt.Errorf("apt-get download %s: %w", sourceName, err)
					} else {
						matches, err := filepath.Glob(filepath.Join(pkgDir, sourceName+"*.deb"))
						if err != nil || len(matches) == 0 {
							fetchErr = fmt.Errorf("no .deb found for %s in %s", sourceName, pkgDir)
						} else {
							artifactPath = matches[0]
							_, _ = fmt.Fprintf(out, "    Downloaded: %s\n", filepath.Base(artifactPath))
						}
					}
				}
			}

			if fetchErr != nil {
				result.Err = fetchErr
				_, _ = fmt.Fprintf(out, "    ERROR: %v\n", result.Err)
				summary.Failures++
			} else {
				result.Artifacts = []string{artifactPath}
				stampArtifactSize(ctx, store, manifest.TypeApt, name, ve, artifactPath)
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
			status := "success"
			if result.Err != nil {
				status = "failure"
			}
			cfg.RecordAudit(audit.EventFetch, manifest.TypeApt, name, ve.Version, status, result.Elapsed, result.Err)
		}
	}

	return summary
}

// BuildApt runs the build_cmd for each apt package version that has one.
// This covers both git source builds (URL set + BuildCmd) and apt-get source
// builds (URL empty + BuildCmd set). Entries without a BuildCmd are skipped.
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

			// Only entries with a build command have a build step.
			if ve.BuildCmd == "" {
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
			bStatus := "success"
			if result.Err != nil {
				bStatus = "failure"
			}
			cfg.RecordAudit(audit.EventBuild, manifest.TypeApt, name, ve.Version, bStatus, result.Elapsed, result.Err)
		}
	}

	return summary
}

// PackageApt copies each built .deb into the pool directory structure under
// <build-root>/apt-repo/pool/main/<letter>/<name>/. The server generates
// Packages and Release files dynamically, so reprepro is not required.
func PackageApt(cfg *Config, store *manifest.Store, entryFilter string) *Summary {
	ctx := context.Background()
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypeApt))

	if err := mkdirAll(d.aptRepo); err != nil {
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

			debName := filepath.Base(debFile)
			_, _ = fmt.Fprintf(out, "    Package: %s (%s)\n", debName, humanBytes(fi.Size()))

			// Copy .deb into pool/main/<letter>/<name>/ layout.
			sourceName := ve.SourceName
			if sourceName == "" {
				sourceName = name
			}
			letter := string(sourceName[0])
			poolDir := filepath.Join(d.aptRepo, "pool", "main", letter, sourceName)
			if err := mkdirAll(poolDir); err != nil {
				result.Err = fmt.Errorf("create pool dir: %w", err)
				_, _ = fmt.Fprintf(out, "    ERROR: %v\n", result.Err)
				summary.Failures++
				result.Elapsed = time.Since(start)
				summary.Results = append(summary.Results, result)
				summary.Total++
				continue
			}

			dest := filepath.Join(poolDir, debName)
			if err := copyFile(debFile, dest); err != nil {
				result.Err = fmt.Errorf("copy to pool: %w", err)
				_, _ = fmt.Fprintf(out, "    ERROR: %v\n", result.Err)
				summary.Failures++
			} else {
				poolRelPath := "pool/main/" + letter + "/" + sourceName + "/" + debName
				_, _ = fmt.Fprintf(out, "    Copied to %s\n", poolRelPath)
				result.Artifacts = []string{dest}

				// Extract control data and compute hashes for the dynamic Packages index.
				if control, err := extractDebControl(dest); err != nil {
					_, _ = fmt.Fprintf(out, "    WARNING: could not extract control data: %v\n", err)
				} else {
					if ve.Metadata == nil {
						ve.Metadata = make(map[string]string)
					}
					ve.Metadata["_control"] = control
					ve.Metadata["_pool_path"] = poolRelPath
				}
				if md5, sha1, sha256, err := computeDebHashes(dest); err != nil {
					_, _ = fmt.Fprintf(out, "    WARNING: could not compute hashes: %v\n", err)
				} else {
					if ve.Metadata == nil {
						ve.Metadata = make(map[string]string)
					}
					ve.Metadata["_md5"] = md5
					ve.Metadata["_sha1"] = sha1
					ve.Metadata["_sha256"] = sha256
				}
				ve.ArtifactSize = fi.Size()
				// Persist the updated metadata back to the store.
				if updated, err := store.GetPackage(ctx, manifest.TypeApt, name); err == nil && updated != nil {
					for i := range updated.Versions {
						if updated.Versions[i].Version == ve.Version {
							updated.Versions[i] = ve
							break
						}
					}
					if err := store.SavePackage(ctx, updated); err != nil {
						_, _ = fmt.Fprintf(out, "    WARNING: could not save metadata: %v\n", err)
					}
				}
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
			pStatus := "success"
			if result.Err != nil {
				pStatus = "failure"
			}
			cfg.RecordAudit(audit.EventPackage, manifest.TypeApt, name, ve.Version, pStatus, result.Elapsed, result.Err)
		}
	}

	return summary
}

// extractDebControl runs dpkg-deb -f on a .deb file and returns the raw
// control fields as a string. If dpkg-deb is not available, returns an error.
func extractDebControl(debPath string) (string, error) {
	out, err := runCmdCapture("", "dpkg-deb", "-f", debPath)
	if err != nil {
		return "", fmt.Errorf("dpkg-deb -f: %w", err)
	}
	return strings.TrimSpace(out), nil
}

// computeDebHashes computes MD5, SHA1, and SHA256 of a file, returning
// lowercase hex strings.
func computeDebHashes(path string) (md5hex, sha1hex, sha256hex string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", "", err
	}
	defer f.Close()

	md5w := md5.New()
	sha1w := sha1.New()
	sha256w := sha256.New()
	w := io.MultiWriter(md5w, sha1w, sha256w)
	if _, err := io.Copy(w, f); err != nil {
		return "", "", "", err
	}
	return hex.EncodeToString(md5w.Sum(nil)),
		hex.EncodeToString(sha1w.Sum(nil)),
		hex.EncodeToString(sha256w.Sum(nil)), nil
}

// copyFile copies src to dst, creating dst if it doesn't exist.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
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
// Handles all four fetch modes: git source build, direct URL, apt-get source
// build, and apt-get download.
func locateDebFile(d dirs, name string, ve manifest.VersionEntry) (string, error) {
	sourceName := ve.SourceName
	if sourceName == "" {
		sourceName = name
	}

	switch {
	case ve.URL != "" && ve.BuildCmd != "":
		// Git source build: .deb inside clone dir.
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

	case ve.URL != "":
		// Direct URL download: .deb at sources/<sourceName>/<filename>.
		destDir := filepath.Join(d.sources, sourceName)
		filename := filepath.Base(ve.URL)
		dest := filepath.Join(destDir, filename)
		if fileExists(dest) {
			return dest, nil
		}
		return "", fmt.Errorf("no .deb found at %s — run 'fetch apt' first", dest)

	case ve.BuildCmd != "":
		// apt-get source build: .deb produced by dpkg-buildpackage.
		sourceDir := aptSourceDir(d, name, ve)
		glob := ve.DebGlob
		if glob == "" {
			glob = "../*.deb"
		}
		matches, err := filepath.Glob(filepath.Join(sourceDir, glob))
		if err != nil || len(matches) == 0 {
			return "", fmt.Errorf("no .deb found matching %s for %s — run 'build apt' first", glob, sourceName)
		}
		return matches[0], nil

	default:
		// apt-get download: .deb in per-package subdir.
		pkgDir := filepath.Join(d.sources, sourceName)
		matches, err := filepath.Glob(filepath.Join(pkgDir, sourceName+"*.deb"))
		if err != nil || len(matches) == 0 {
			return "", fmt.Errorf("no .deb found for %s in %s — run 'fetch apt' first", sourceName, pkgDir)
		}
		return matches[0], nil
	}
}

// setupAptRepo creates the reprepro configuration directory and a GPG signing
// key if one does not already exist for the bootstrap email.
func setupAptRepo(cfg *Config, aptRepoDir string) error {
	out := cfg.stdout()
	confDir := filepath.Join(aptRepoDir, "conf")
	if err := mkdirAll(confDir); err != nil {
		return err
	}

	gpgEmail := cfg.GpgEmail
	if gpgEmail == "" {
		gpgEmail = "bodega@localhost"
	}
	gpgName := cfg.GpgName
	if gpgName == "" {
		gpgName = "Bodega Package Signing"
	}

	// Generate GPG key if absent. Check the exit code, not the output —
	// gpg writes error text to stderr even when the key is missing.
	_, checkErr := runCmdCapture("", "gpg", "--list-keys", gpgEmail)
	if checkErr != nil {
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
