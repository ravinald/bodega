package builder

import (
	"context"
	"crypto/md5"  //nolint:gosec // G501: Debian repository spec requires MD5 in Packages/Release for legacy client compat.
	"crypto/sha1" //nolint:gosec // G505: Debian repository spec requires SHA1 in Packages/Release for legacy client compat.
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
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

// aptSourceName returns the archive source package name for an entry, which
// defaults to the manifest entry's own name.
func aptSourceName(name string, ve manifest.VersionEntry) string {
	if ve.SourceName != "" {
		return ve.SourceName
	}
	return name
}

// aptPoolRelPath returns the store-relative pool path the package stage copies
// a .deb to. The fetch stage records it before the copy happens: apt's object
// key is that pool path, so a digest computed at fetch time has nothing to key
// a checksum row on until it exists.
func aptPoolRelPath(sourceName, debName string) string {
	if sourceName == "" || debName == "" {
		return ""
	}
	return "pool/main/" + sourceName[:1] + "/" + sourceName + "/" + debName
}

// aptFetchedDeb returns the .deb a completed fetch left under sources/ for this
// entry, or "" when the entry's fetch produces a source tree to build instead.
// It answers for the same two branches CheckAptStage calls fetched by finding a
// .deb, so what the fetch digests and what a later run re-checks are one path.
func aptFetchedDeb(d dirs, name string, ve manifest.VersionEntry) string {
	sourceName := aptSourceName(name, ve)
	switch {
	case ve.BuildCmd != "":
		return ""
	case ve.URL != "":
		return filepath.Join(d.sources, sourceName, filepath.Base(ve.URL))
	default:
		matches, _ := filepath.Glob(filepath.Join(d.sources, sourceName, sourceName+"*.deb"))
		if len(matches) == 0 {
			return ""
		}
		return matches[0]
	}
}

// pinFetchedDeb digests a .deb this fetch downloaded, enforces a digest an
// earlier fetch recorded, and records one when none exists.
//
// Without it apt's first record arrived at the package stage, so a second
// `build fetch apt` had no manifest digest to compare against and no pool path
// to look a pinned row up by. Both are written here, off the bytes that just
// landed.
func (c *Config) pinFetchedDeb(ctx context.Context, store *manifest.Store, name string, ve manifest.VersionEntry, debPath string, out io.Writer) error {
	computed, err := computeFileSHA256(debPath)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "    SHA-256: %s\n", computed)

	verified := false
	if ve.Checksum != nil {
		if err := verifyChecksum(ve.Checksum, computed); err != nil {
			return fmt.Errorf("apt/%s: %w", name, err)
		}
		verified = true
		_, _ = fmt.Fprintf(out, "    Checksum verified against manifest\n")
	}

	rel := aptPoolRelPath(aptSourceName(name, ve), filepath.Base(debPath))
	if err := stampAptPoolPath(ctx, store, name, ve, rel); err != nil {
		return err
	}
	return c.updateVersionChecksum(ctx, store, manifest.TypeApt, name, ve, newSHA256Checksum(computed), verified)
}

// stampAptPoolPath records the pool path on the stored version entry so
// ArtifactKeys can derive an object key from it.
func stampAptPoolPath(ctx context.Context, store *manifest.Store, name string, targetVE manifest.VersionEntry, rel string) error {
	if rel == "" {
		return nil
	}
	pm, err := store.GetPackage(ctx, manifest.TypeApt, name)
	if err != nil || pm == nil {
		return err
	}
	i := entryIndex(pm.Versions, targetVE)
	if i < 0 {
		return nil
	}
	ve := &pm.Versions[i]
	if ve.Metadata == nil {
		ve.Metadata = make(map[string]string)
	}
	if ve.Metadata["_pool_path"] == rel {
		return nil
	}
	ve.Metadata["_pool_path"] = rel
	return store.SavePackage(ctx, pm)
}

// aptPinOnOffer fails when the local cache knows the package but not the
// version the entry pins.
//
// `apt-get download <name>=<version>` refuses an absent version too, but it
// refuses with apt's own message and after the network round trip. Read the
// same table apt would resolve against first and the refusal names the entry,
// the pin and what is installable instead, which is what the operator needs to
// re-pin. Never the candidate: substituting it is the defect.
func aptPinOnOffer(name, sourceName, want string) error {
	offered, ok := aptOfferedVersions(sourceName)
	if !ok {
		return nil
	}
	if slices.Contains(offered, want) {
		return nil
	}
	have := "no versions at all"
	if len(offered) > 0 {
		have = strings.Join(offered, ", ")
	}
	return fmt.Errorf("apt/%s: the manifest pins %s and the local cache offers %s for %s — run 'apt-get update' or re-pin the entry",
		name, want, have, sourceName)
}

// aptDebVersion reads the version out of a .deb filename, which dpkg builds as
// <name>_<version>_<arch>.deb with an epoch's colon percent-encoded.
func aptDebVersion(base string) (string, bool) {
	fields := strings.Split(strings.TrimSuffix(base, ".deb"), "_")
	if len(fields) < 3 {
		return "", false
	}
	v := strings.ReplaceAll(fields[1], "%3a", ":")
	return strings.ReplaceAll(v, "%3A", ":"), true
}

// aptPinnedDeb picks the download the entry's pin names and fails when what
// landed is another version.
//
// apt-get exiting 0 says a .deb arrived, not that the pinned one did: a local
// cache stale against the archive, a pin apt resolved loosely, or a glob that
// caught a sibling all end with bytes on disk the entry does not describe. The
// pool key and the index entry are both rendered from the manifest version, so
// a substitution that reaches the pool is one no client can see.
func aptPinnedDeb(matches []string, name, want string) (string, error) {
	if want == "" {
		return matches[0], nil
	}
	got := make([]string, 0, len(matches))
	for _, m := range matches {
		base := filepath.Base(m)
		if v, ok := aptDebVersion(base); ok && v == want {
			return m, nil
		}
		got = append(got, base)
	}
	return "", fmt.Errorf("apt/%s: the manifest pins %s and apt-get download produced %s",
		name, want, strings.Join(got, ", "))
}

// aptGetDownloadViaTemp runs `apt-get download` from a world-writable tempdir
// (so the _apt sandbox user can write there) and then moves the resulting .deb
// into pkgDir. Falls back to copy+remove if the tempdir and pkgDir are on
// different filesystems (os.Rename returns EXDEV in that case).
func aptGetDownloadViaTemp(out io.Writer, name, sourceName string, ve manifest.VersionEntry, pkgDir string) (string, error) {
	tmpDir, err := os.MkdirTemp("", "bodega-apt-*")
	if err != nil {
		return "", fmt.Errorf("create tempdir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	target := sourceName
	if ve.Version != "" {
		target = sourceName + "=" + ve.Version
	}
	_, _ = fmt.Fprintf(out, "    Downloading %s via apt-get download...\n", target)
	if err := runCmd(out, tmpDir, "apt-get", "download", target); err != nil {
		return "", fmt.Errorf("apt-get download %s: %w", target, err)
	}

	matches, err := filepath.Glob(filepath.Join(tmpDir, sourceName+"*.deb"))
	if err != nil || len(matches) == 0 {
		return "", fmt.Errorf("no .deb found for %s in %s", sourceName, tmpDir)
	}

	src, err := aptPinnedDeb(matches, name, ve.Version)
	if err != nil {
		return "", err
	}
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

// cloneAptSource checks out the source an apt entry builds from. The .deb is
// published under the entry's version, so a ref that cannot be fetched fails
// here rather than falling back to the default branch: the wrong commit would
// otherwise be built, signed and served with every check passing. On failure
// dir is removed, because CheckAptStage reads its existence as "fetched".
func cloneAptSource(out io.Writer, name, url, ref, dir string) error {
	if ref == "" {
		_, _ = fmt.Fprintf(out, "    Cloning %s at its default branch: the entry names no ref\n", url)
		if err := runCmd(out, "", "git", "clone", "--depth", "1", url, dir); err != nil {
			return fmt.Errorf("git clone: %w", err)
		}
	} else {
		_, _ = fmt.Fprintf(out, "    Cloning %s at %s...\n", url, ref)
		if err := cloneAptRef(out, url, ref, dir); err != nil {
			_ = os.RemoveAll(dir)
			return fmt.Errorf("apt entry %s: fetch ref %q from %s: %w", name, ref, url, err)
		}
	}
	head, err := runCmdCapture(dir, "git", "rev-parse", "HEAD")
	if err != nil {
		_ = os.RemoveAll(dir)
		return fmt.Errorf("apt entry %s: resolve HEAD of %s: %w: %s", name, dir, err, strings.TrimSpace(head))
	}
	marker := aptRefMarkerPath(dir)
	if err := os.WriteFile(marker, []byte(ref), 0o644); err != nil {
		_ = os.RemoveAll(dir)
		return fmt.Errorf("apt entry %s: record ref in %s: %w", name, marker, err)
	}
	_, _ = fmt.Fprintf(out, "    Commit: %s\n", strings.TrimSpace(head))
	return nil
}

// aptRefMarkerPath is where a clone records the ref it was made at. It sits
// inside .git so it goes with the clone and build_cmd never sees it.
func aptRefMarkerPath(cloneDir string) string {
	return filepath.Join(cloneDir, ".git", "bodega-ref")
}

// aptRecordedRef reads the ref cloneDir was cloned at. recorded is false when
// the clone carries no marker, which a clone from before markers existed does
// not; such a clone was made at the default branch.
func aptRecordedRef(cloneDir string) (ref string, recorded bool, err error) {
	b, err := os.ReadFile(aptRefMarkerPath(cloneDir))
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return string(b), true, nil
}

// aptCloneAtRef reports whether cloneDir holds a clone made at ref.
func aptCloneAtRef(cloneDir, ref string) bool {
	if fi, err := os.Stat(cloneDir); err != nil || !fi.IsDir() {
		return false
	}
	recorded, ok, err := aptRecordedRef(cloneDir)
	if err != nil {
		return false
	}
	if !ok {
		return ref == ""
	}
	return recorded == ref
}

// describeAptRef names a ref for a log line, an empty one being the default branch.
func describeAptRef(ref string) string {
	if ref == "" {
		return "the default branch"
	}
	return "ref " + ref
}

// logAptRefChange says why an existing clone is being replaced when the ref it
// was made at is not the one the entry names.
func logAptRefChange(out io.Writer, name, cloneDir, ref string) {
	if fi, err := os.Stat(cloneDir); err != nil || !fi.IsDir() || aptCloneAtRef(cloneDir, ref) {
		return
	}
	was := "records no ref it was cloned at"
	if recorded, ok, err := aptRecordedRef(cloneDir); err != nil {
		was = fmt.Sprintf("has an unreadable ref record (%v)", err)
	} else if ok {
		was = "was cloned at " + describeAptRef(recorded)
	}
	_, _ = fmt.Fprintf(out, "    Re-fetching %s: %s %s, the entry names %s\n", name, cloneDir, was, describeAptRef(ref))
}

// cloneAptRef shallow-clones url at ref. A tag or branch goes through
// "clone --branch", which keeps the tag and the origin remote a build script
// may read; "--branch" cannot take a commit SHA, so a full SHA is fetched into
// an empty repository instead.
func cloneAptRef(out io.Writer, url, ref, dir string) error {
	if !isFullCommitSHA(ref) {
		return runCmd(out, "", "git", "clone", "--depth", "1", "--branch="+ref, url, dir)
	}
	steps := [][]string{
		{"-c", "advice.defaultBranchName=false", "init", "-q", dir},
		{"-C", dir, "remote", "add", "origin", url},
		{"-C", dir, "fetch", "--depth", "1", "origin", ref},
		{"-C", dir, "checkout", "-q", "--detach", "FETCH_HEAD"},
	}
	for _, args := range steps {
		if err := runCmd(out, "", "git", args...); err != nil {
			return fmt.Errorf("git %s: %w", args[2], err)
		}
	}
	return nil
}

// isFullCommitSHA reports whether ref is a full SHA-1 or SHA-256 object name.
func isFullCommitSHA(ref string) bool {
	if len(ref) != 40 && len(ref) != 64 {
		return false
	}
	_, err := hex.DecodeString(ref)
	return err == nil
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
		// Source build from git: fetch = a clone made at the entry's ref.
		// A version's directory outlives a change to its ref, so existence
		// alone would let build_cmd run in a tree at another commit.
		cloneDir := aptSourceDir(d, name, ve)
		s.Fetched = aptCloneAtRef(cloneDir, ve.Ref)
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
		if fileExists(aptFetchedDeb(d, name, ve)) {
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
			_, err := locateDebFile(d, name, ve)
			s.Built = err == nil
		}

	default:
		// apt-get download: fetch = .deb file present in per-package subdir.
		s.Fetched = aptFetchedDeb(d, name, ve) != ""
		s.Built = s.Fetched // no separate build step
	}

	s.Packaged = s.Built && aptPoolHoldsBuild(d, name, sourceName, ve)
	return s
}

// aptPoolHoldsBuild reports whether the pool file this version's .deb would be
// copied to already holds that .deb's bytes. A name match alone is not enough:
// a ref change can rebuild a version under the same filename, and a pool file
// from the earlier build is not this build. Any read error answers false, so
// the package stage runs and reports it.
func aptPoolHoldsBuild(d dirs, name, sourceName string, ve manifest.VersionEntry) bool {
	deb, err := locateDebFile(d, name, ve)
	if err != nil {
		return false
	}
	pool := filepath.Join(d.aptRepo, filepath.FromSlash(aptPoolRelPath(sourceName, filepath.Base(deb))))
	poolSum, err := fileSHA256(pool)
	if err != nil {
		return false
	}
	debSum, err := fileSHA256(deb)
	return err == nil && debSum == poolSum
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
			if err := manifest.ValidateDepPolicy(manifest.TypeApt, name, pm.DepPolicy); err != nil {
				cfg.logf("  [apt] %s: ERROR: %v", name, err)
				summary.Failures++
				summary.Results = append(summary.Results, Result{Type: manifest.TypeApt, Name: name, Err: err})
				continue
			}
			if err := cfg.EnforcePolicy(ctx, manifest.TypeApt, name, ve); err != nil {
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
					if ve.URL != "" && ve.BuildCmd != "" {
						cfg.logf("  [apt] %s: already fetched at %s, skipping", name, describeAptRef(ve.Ref))
					} else {
						cfg.logf("  [apt] %s: already fetched, skipping", name)
					}
					if err := cfg.verifyFetched(ctx, store, manifest.TypeApt, name, ve); err != nil {
						cfg.logf("  [apt] %s: %v", name, err)
						summary.Failures++
						summary.Results = append(summary.Results, Result{Type: manifest.TypeApt, Name: name, Err: err})
					}
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
				logAptRefChange(out, name, cloneDir, ve.Ref)
				if err := os.RemoveAll(cloneDir); err != nil {
					fetchErr = fmt.Errorf("remove old source %s: %w", cloneDir, err)
				} else if err := cloneAptSource(out, name, ve.URL, ve.Ref, cloneDir); err != nil {
					fetchErr = err
				} else {
					artifactPath = cloneDir
					_, _ = fmt.Fprintf(out, "    Source: %s\n", cloneDir)
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
				} else if cfg.Force {
					fetchErr = discardAptSourceBuild(d, name, ve, sourceDir)
				}
				if fetchErr == nil {
					_, _ = fmt.Fprintf(out, "    Fetching source for %s via apt-get source...\n", sourceName)
					if err := runCmd(out, parentDir, "apt-get", "source", "--download-only", sourceName); err != nil {
						fetchErr = fmt.Errorf("apt-get source %s: %w", sourceName, err)
					} else {
						// runCmd runs no shell, so the .dsc has to be named
						// exactly: a glob would reach dpkg-source as a literal.
						dsc, err := locateAptSourceDsc(parentDir, name, ve)
						if err != nil {
							fetchErr = err
						} else if err := runCmd(out, parentDir, "dpkg-source", "-x", dsc, sourceDir); err != nil {
							fetchErr = fmt.Errorf("extract source %s: %w", filepath.Base(dsc), err)
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
				if ve.Version != "" {
					fetchErr = aptPinOnOffer(name, sourceName, ve.Version)
				}
				if fetchErr == nil {
					if err := mkdirAll(pkgDir); err != nil {
						fetchErr = fmt.Errorf("create dir %s: %w", pkgDir, err)
					} else {
						artifactPath, fetchErr = aptGetDownloadViaTemp(out, name, sourceName, ve, pkgDir)
					}
				}
			}

			// A source-build branch leaves a directory to compile; the two
			// download branches leave the published artifact itself, which is
			// what a digest can attest to.
			if fetchErr == nil && strings.HasSuffix(artifactPath, ".deb") {
				fetchErr = cfg.pinFetchedDeb(ctx, store, name, ve, artifactPath, out)
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

			// A build that is not byte-reproducible yields a .deb whose digest
			// disagrees with the pool copy, and the package stage would then
			// refuse a version it already serves on every later run.
			if !cfg.Force && CheckAptStage(cfg, name, ve).Built {
				cfg.logf("  [apt] %s %s: already built, skipping; 'bodega build fetch apt %s force' rebuilds it", name, ve.Version, name)
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

			// The .deb the stage check and the package stage will read is the
			// one that confirms this build, so all three agree on it.
			if deb, err := locateDebFile(d, name, ve); err != nil {
				result.Err = err
				_, _ = fmt.Fprintf(out, "    ERROR: %v\n", result.Err)
				summary.Failures++
			} else {
				result.Artifacts = []string{deb}
				fi, _ := os.Stat(deb)
				if fi != nil {
					_, _ = fmt.Fprintf(out, "    Built: %s (%s)\n", filepath.Base(deb), humanBytes(fi.Size()))
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

			// The digest is checked before the copy: a refused .deb must leave
			// the pool serving the bytes the recorded digest names.
			md5, sha1, sha256, err := computeDebHashes(debFile)
			if err == nil {
				err = verifyChecksum(ve.Checksum, sha256)
				if err != nil {
					err = aptDigestRefusal(d, name, ve, sha256, err)
				}
			} else {
				err = fmt.Errorf("hash %s: %w", debFile, err)
			}
			if err != nil {
				result.Err = err
				_, _ = fmt.Fprintf(out, "    ERROR: %v\n", result.Err)
				summary.Failures++
				result.Elapsed = time.Since(start)
				summary.Results = append(summary.Results, result)
				summary.Total++
				if cfg.Logger != nil {
					cfg.Logger.Audit("FAILED  apt/package/%s  (%s)  %v", name, result.Elapsed.Round(time.Millisecond), result.Err)
				}
				cfg.RecordAudit(audit.EventPackage, manifest.TypeApt, name, ve.Version, "failure", result.Elapsed, result.Err)
				continue
			}

			// Copy .deb into pool/main/<letter>/<name>/ layout.
			sourceName := aptSourceName(name, ve)
			poolRelPath := aptPoolRelPath(sourceName, debName)
			poolDir := filepath.Dir(filepath.Join(d.aptRepo, filepath.FromSlash(poolRelPath)))
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
			if err := installPoolFile(debFile, dest, sha256); err != nil {
				result.Err = fmt.Errorf("copy to pool: %w", err)
				_, _ = fmt.Fprintf(out, "    ERROR: %v\n", result.Err)
				summary.Failures++
			} else {
				_, _ = fmt.Fprintf(out, "    Copied to %s\n", poolRelPath)
				result.Artifacts = []string{dest}

				// Extract control data for the dynamic Packages index.
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
				if ve.Metadata == nil {
					ve.Metadata = make(map[string]string)
				}
				ve.Metadata["_md5"] = md5
				ve.Metadata["_sha1"] = sha1
				ve.Metadata["_sha256"] = sha256
				ve.Checksum = newSHA256Checksum(sha256)
				ve.ArtifactSize = fi.Size()
				// Persist the updated metadata back to the store.
				if updated, err := store.GetPackage(ctx, manifest.TypeApt, name); err == nil && updated != nil {
					if i := entryIndex(updated.Versions, ve); i >= 0 {
						updated.Versions[i] = ve
					}
					if err := store.SavePackage(ctx, updated); err != nil {
						_, _ = fmt.Fprintf(out, "    WARNING: could not save metadata: %v\n", err)
					}
					// apt is the one covered type that never reaches
					// updateVersionChecksum: its digest arrives with the
					// control data rather than from a download, so the pin is
					// made here against the same _pool_path just recorded.
					if err := cfg.pinChecksum(ctx, updated, ve, ve.Checksum); err != nil {
						_, _ = fmt.Fprintf(out, "    ERROR: %v\n", err)
						result.Err = err
						summary.Failures++
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

// aptDigestRefusal explains a .deb whose digest disagrees with the one on
// record. For a direct download or an apt-get fetch the record came from the
// fetch, so the bytes changed in the build root since. A source build digests
// nothing at fetch: its record is the first package run's, so a mismatch means
// the build at the current ref produced different bytes under a version the
// pool already serves.
func aptDigestRefusal(d dirs, name string, ve manifest.VersionEntry, built string, mismatch error) error {
	if ve.URL == "" || ve.BuildCmd == "" {
		return fmt.Errorf("apt/%s: the .deb no longer matches the digest recorded at fetch: %w", name, mismatch)
	}
	if ve.Checksum == nil || ve.Checksum.Algorithm != "sha256" {
		return fmt.Errorf("apt/%s@%s: %w", name, ve.Version, mismatch)
	}
	recorded := ve.Checksum.Value
	var at string
	switch ref, ok, err := aptRecordedRef(aptSourceDir(d, name, ve)); {
	case err != nil:
		at = fmt.Sprintf("an unreadable ref record (%v)", err)
	case ok:
		at = describeAptRef(ref)
	default:
		at = describeAptRef("")
	}
	return fmt.Errorf("apt/%s@%s: the .deb built from %s has sha256 %s, but this version was packaged with sha256 %s; "+
		"the pool keeps serving the recorded bytes. To publish the changed build, give the entry a new version",
		name, ve.Version, at, built, recorded)
}

// installPoolFile copies src into the pool at dst through a temporary file and
// a rename, and refuses the copy unless its sha256 is want. src sits in a build
// root a build may still be writing, so the bytes are checked after the copy
// and the file apt serves is never left half-written.
func installPoolFile(src, dst, want string) error {
	tmp := dst + ".tmp"
	if err := copyFile(src, tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	got, err := fileSHA256(tmp)
	if err == nil && got != want {
		err = fmt.Errorf("%s changed during the copy: sha256 %s, verified %s", src, got, want)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
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
		dest := aptFetchedDeb(d, name, ve)
		if fileExists(dest) {
			return dest, nil
		}
		return "", fmt.Errorf("no .deb found at %s — run 'fetch apt' first", dest)

	case ve.BuildCmd != "":
		return locateAptSourceDeb(d, name, ve)

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

// locateAptSourceDeb returns the .deb an apt-get source build produced for this
// entry. dpkg-buildpackage writes it beside the source tree, in sources/, which
// every apt entry shares, so a loose glob there answers with whichever entry's
// .deb sorts first. Selection is by the dpkg filename's package and version,
// and anything but exactly one candidate is refused rather than guessed at.
func locateAptSourceDeb(d dirs, name string, ve manifest.VersionEntry) (string, error) {
	sourceName := aptSourceName(name, ve)
	if ve.DebGlob != "" {
		sourceDir := aptSourceDir(d, name, ve)
		matches, err := filepath.Glob(filepath.Join(sourceDir, ve.DebGlob))
		if err != nil {
			return "", fmt.Errorf("apt/%s: deb_glob %q: %w", name, ve.DebGlob, err)
		}
		switch len(matches) {
		case 0:
			return "", fmt.Errorf("apt/%s: no .deb matches deb_glob %q from %s — run 'build apt', or correct deb_glob",
				name, ve.DebGlob, sourceDir)
		case 1:
			return matches[0], nil
		}
		return "", fmt.Errorf("apt/%s: deb_glob %q matches %d files: %s — narrow deb_glob to the one this entry publishes",
			name, ve.DebGlob, len(matches), joinBases(matches))
	}

	own, present, err := aptOwnFiles(d.sources, ".deb", sourceName, ve.Version)
	if err != nil {
		return "", fmt.Errorf("apt/%s: read %s: %w", name, d.sources, err)
	}
	want := describeAptPick(sourceName, ve.Version)
	switch len(own) {
	case 0:
		found := "no .deb files"
		if len(present) > 0 {
			found = joinBases(present)
		}
		return "", fmt.Errorf("apt/%s: no .deb for %s in %s (found %s) — run 'build apt', or set deb_glob when the build names its binary package differently from its source",
			name, want, d.sources, found)
	case 1:
		return own[0], nil
	}
	return "", fmt.Errorf("apt/%s: %d .deb files in %s are %s: %s — set deb_glob to the one this entry publishes",
		name, len(own), d.sources, want, joinBases(own))
}

// discardAptSourceBuild removes an apt-get source entry's extracted tree and
// the .deb its last build left, so a forced fetch extracts afresh (dpkg-source
// refuses an existing target) and the build stage no longer reads the version
// as built. The .deb sits in the sources/ directory every entry shares, so only
// the one file locateAptSourceDeb selects for this version is removed; when it
// selects none or several, nothing there is touched and the build stage reports
// the ambiguity as it would without the force.
func discardAptSourceBuild(d dirs, name string, ve manifest.VersionEntry, sourceDir string) error {
	if deb, err := locateAptSourceDeb(d, name, ve); err == nil {
		if err := os.Remove(deb); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove old build %s: %w", deb, err)
		}
	}
	if err := os.RemoveAll(sourceDir); err != nil {
		return fmt.Errorf("remove old source %s: %w", sourceDir, err)
	}
	return nil
}

// locateAptSourceDsc returns the .dsc `apt-get source` left in dir for this
// entry, by the same rules locateAptSourceDeb selects a .deb.
func locateAptSourceDsc(dir, name string, ve manifest.VersionEntry) (string, error) {
	sourceName := aptSourceName(name, ve)
	own, present, err := aptOwnFiles(dir, ".dsc", sourceName, ve.Version)
	if err != nil {
		return "", fmt.Errorf("apt/%s: read %s: %w", name, dir, err)
	}
	want := describeAptPick(sourceName, ve.Version)
	switch len(own) {
	case 0:
		found := "no .dsc files"
		if len(present) > 0 {
			found = joinBases(present)
		}
		return "", fmt.Errorf("apt/%s: apt-get source left no .dsc for %s in %s (found %s) — apt-get source fetches the archive's candidate, so run 'apt-get update' or re-pin the entry to a version the archive offers",
			name, want, dir, found)
	case 1:
		return own[0], nil
	}
	return "", fmt.Errorf("apt/%s: %d .dsc files in %s are %s: %s — remove the stale ones from %s and fetch again",
		name, len(own), dir, want, joinBases(own), dir)
}

// aptOwnFiles lists the files directly in dir ending in ext, and of those the
// ones whose dpkg filename (<package>_<version>[_<arch>]<ext>) names pkg and,
// when version is set, that version. dpkg drops the epoch from the filename or
// percent-encodes its colon, so both forms answer for a pinned "N:" version.
func aptOwnFiles(dir, ext, pkg, version string) (own, present []string, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ext) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		present = append(present, path)
		fields := strings.Split(strings.TrimSuffix(e.Name(), ext), "_")
		if len(fields) < 2 || fields[0] != pkg {
			continue
		}
		if version != "" && !aptVersionMatches(fields[1], version) {
			continue
		}
		own = append(own, path)
	}
	return own, present, nil
}

// aptVersionMatches reports whether a version field from a dpkg filename names
// want, with or without want's epoch.
func aptVersionMatches(field, want string) bool {
	got := strings.ReplaceAll(strings.ReplaceAll(field, "%3a", ":"), "%3A", ":")
	if got == want {
		return true
	}
	epoch, rest, ok := strings.Cut(want, ":")
	if !ok || epoch == "" || strings.Trim(epoch, "0123456789") != "" {
		return false
	}
	return got == rest
}

func describeAptPick(pkg, version string) string {
	if version == "" {
		return "package " + pkg + " (any version)"
	}
	return "package " + pkg + " version " + version
}

func joinBases(paths []string) string {
	bases := make([]string, len(paths))
	for i, p := range paths {
		bases[i] = filepath.Base(p)
	}
	return strings.Join(bases, ", ")
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
				Local:     local,
				ObjectKey: manifest.AptKey(rel),
				Package:   name,
				Version:   ve.Version,
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

// findDebInLocalPool resolves an entry with no _pool_path to a .deb already in
// the local pool, so the bytes upload to the path that file occupies.
//
// It keeps the "<pkg>_<version>" prefix pass that inventory and the server both
// dropped, because refusing here would leave a built artifact unmirrored, where
// refusing there only declines to report a key nothing serves. The pass is
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
