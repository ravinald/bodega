package builder

import (
	"context"
	"crypto/md5"  //nolint:gosec // G501: Debian repository spec requires MD5 in Packages/Release for legacy client compat.
	"crypto/sha1" //nolint:gosec // G505: Debian repository spec requires SHA1 in Packages/Release for legacy client compat.
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/deb822"
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

// aptGetDownloadViaTemp runs `apt-get download` from a world-writable tempdir
// (so the _apt sandbox user can write there) and then moves the resulting .deb
// into pkgDir. Falls back to copy+remove if the tempdir and pkgDir are on
// different filesystems (os.Rename returns EXDEV in that case).
func aptGetDownloadViaTemp(out io.Writer, sourceName, pkgDir string) (string, error) {
	tmpDir, err := os.MkdirTemp("", "bodega-apt-*")
	if err != nil {
		return "", fmt.Errorf("create tempdir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	_, _ = fmt.Fprintf(out, "    Downloading %s via apt-get download...\n", sourceName)
	if err := runCmd(out, tmpDir, "apt-get", "download", sourceName); err != nil {
		return "", fmt.Errorf("apt-get download %s: %w", sourceName, err)
	}

	matches, err := filepath.Glob(filepath.Join(tmpDir, sourceName+"*.deb"))
	if err != nil || len(matches) == 0 {
		return "", fmt.Errorf("no .deb found for %s in %s", sourceName, tmpDir)
	}

	src := matches[0]
	dest := filepath.Join(pkgDir, filepath.Base(src))
	if err := moveFile(src, dest); err != nil {
		return "", fmt.Errorf("move .deb to %s: %w", dest, err)
	}
	_, _ = fmt.Fprintf(out, "    Downloaded: %s\n", filepath.Base(dest))
	return dest, nil
}

// moveFile renames src to dst, falling back to copy+remove when the two paths
// live on different filesystems (cross-device rename is not supported).
func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	fi, err := in.Stat()
	if err != nil {
		return err
	}

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fi.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(dst)
		return err
	}
	return os.Remove(src)
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
				//
				// apt-get drops privileges to the `_apt` user to sandbox the download.
				// When the destination is under /opt/bodega (root:root 0755), _apt
				// can't write there, so apt emits a noisy "Download is performed
				// unsandboxed as root" warning and proceeds. We run the download in
				// a world-writable tempdir (_apt can sandbox normally) and move the
				// .deb into the per-package dir afterwards.
				pkgDir := filepath.Join(srcDir, sourceName)
				if err := mkdirAll(pkgDir); err != nil {
					fetchErr = fmt.Errorf("create dir %s: %w", pkgDir, err)
				} else {
					artifactPath, fetchErr = aptGetDownloadViaTemp(out, sourceName, pkgDir)
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
// <build-root>/apt-repo/pool/main/<letter>/<name>/. dists/ is never written:
// the server generates every suite's Packages and Release into one snapshot
// and signs it there, so reprepro is not required and a pre-built index would
// be a second, contradictory source of truth.
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
					_, _ = fmt.Fprintf(out, "    ERROR: could not extract control data: %v\n", err)
					result.Err = err
					summary.Failures++
				} else {
					if ve.Metadata == nil {
						ve.Metadata = make(map[string]string)
					}
					fields, perr := deb822.ParseSingle([]byte(control))
					if perr != nil {
						_, _ = fmt.Fprintf(out, "    ERROR: deb822 parse failed: %v\n", perr)
						result.Err = perr
						summary.Failures++
					} else {
						for k, v := range fields {
							ve.Metadata[k] = v
						}
						delete(ve.Metadata, "_control")
						delete(ve.Metadata, "Description-Full")
					}
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

	md5w := md5.New()   //nolint:gosec // G401: MD5 required by Debian Packages/Release format.
	sha1w := sha1.New() //nolint:gosec // G401: SHA1 required by Debian Packages/Release format.
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

// AptArtifactPaths returns the local path and object key for each apt version
// whose .deb is in the local pool.
//
// One entry per version, not one sync of <build-root>/apt-repo. The pool is
// walkable per package because PackageApt records each .deb's pool path on the
// version entry, and manifest.AptKey turns that into the same key the Packages
// index publishes as Filename. dists/ is not here and never was: the server
// generates every suite's index per request, so there is nothing on disk to
// upload and nothing type-scoped left in this path.
//
// An entry written before the _pool_path metadata key existed, or one whose
// control extraction failed, is resolved against a listing of the local pool —
// the same name_version_arch lookup the server and 'build status' use, so all
// three agree on which object backs the entry.
func AptArtifactPaths(cfg *Config, store *manifest.Store, entryFilter string) []ArtifactPath {
	ctx := context.Background()
	d := buildDirs(cfg.rootFor(manifest.TypeApt))
	var paths []ArtifactPath
	var pool map[string]string // basename -> path relative to the apt prefix

	for _, name := range store.ListPackages(manifest.TypeApt) {
		if entryFilter != "" && name != entryFilter {
			continue
		}
		pm, err := store.GetPackage(ctx, manifest.TypeApt, name)
		if err != nil || pm == nil {
			continue
		}
		for _, ve := range pm.Versions {
			rel := ve.Metadata["_pool_path"]
			if rel == "" {
				if pool == nil {
					pool = walkAptPool(d.aptRepo)
				}
				srcName := ve.SourceName
				if srcName == "" {
					srcName = pm.Name
				}
				rel = findDebInLocalPool(pool, srcName, ve.Version, ve.Metadata["Architecture"])
			}
			if rel == "" {
				continue
			}
			local := filepath.Join(d.aptRepo, filepath.FromSlash(rel))
			if fi, err := os.Stat(local); err != nil || fi.IsDir() {
				continue
			}
			paths = append(paths, ArtifactPath{
				Local:   local,
				S3Key:   manifest.AptKey(rel),
				Package: name,
				Version: ve.Version,
			})
		}
	}
	return paths
}

// walkAptPool maps each pooled .deb basename to its path relative to the apt
// prefix, which is the form _pool_path and the published Filename both take.
func walkAptPool(aptRepo string) map[string]string {
	pool := map[string]string{}
	root := filepath.Join(aptRepo, "pool")
	_ = filepath.WalkDir(root, func(p string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(entry.Name(), ".deb") {
			return nil //nolint:nilerr // an unreadable subtree is a .deb this upload cannot see, not a reason to abort the rest
		}
		relFS, relErr := filepath.Rel(aptRepo, p)
		if relErr != nil {
			return nil
		}
		pool[entry.Name()] = filepath.ToSlash(relFS)
		return nil
	})
	return pool
}

// findDebInLocalPool mirrors inventory.findDebInPool so an entry with no
// _pool_path uploads to the key the server will look for. The prefix pass is
// sorted rather than a map walk: an ambiguous name must resolve to the same
// .deb on every run, or two uploads publish two different artifacts.
func findDebInLocalPool(pool map[string]string, pkgName, version, arch string) string {
	if rel, ok := pool[pkgName+"_"+version+"_"+arch+".deb"]; ok {
		return rel
	}
	prefix := pkgName + "_" + version
	bases := make([]string, 0, len(pool))
	for base := range pool {
		if strings.HasPrefix(base, prefix) {
			bases = append(bases, base)
		}
	}
	if len(bases) == 0 {
		return ""
	}
	sort.Strings(bases)
	return pool[bases[0]]
}
