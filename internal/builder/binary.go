package builder

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// binaryFilename returns the local filename for a binary version entry, using
// ve.Filename when set and falling back to the basename of the URL. Both are
// checked, because a URL ending in "/.." has ".." as its basename.
func binaryFilename(ve manifest.VersionEntry) (string, error) {
	name := ve.Filename
	if name == "" {
		name = filepath.Base(ve.URL)
	}
	if err := manifest.ValidateBinaryFilename(name); err != nil {
		return "", err
	}
	return name, nil
}

// binaryDestPath returns the absolute local destination path for a binary
// version entry. When the entry has a Version set, the file is placed under
// binaries/<name>/<version>/<filename> to allow multiple versions to coexist.
// Falls back to binaries/<name>/<filename> when Version is empty.
//
// The package name and version are joined as written, so each is checked as
// well: a filename is not the only operator-supplied component that can carry
// "..". A version must be one directory. A name may span several, since
// SafeName round-trips a "/" in it, but must already be clean, so it can
// neither leave the binaries directory nor land in another package's.
func binaryDestPath(d dirs, name string, ve manifest.VersionEntry) (string, error) {
	filename, err := binaryFilename(ve)
	if err != nil {
		return "", fmt.Errorf("binary %s@%s: %w", name, ve.Version, err)
	}
	if ve.Version == "." || ve.Version == ".." || strings.ContainsAny(ve.Version, "/\\\x00") {
		return "", fmt.Errorf("binary %s@%s: the version is joined into the build root as one directory, so it may not contain '/', '\\' or NUL or be \".\" or \"..\"; correct it in the manifest", name, ve.Version)
	}
	if name == "." || !filepath.IsLocal(name) || filepath.Clean(name) != name {
		return "", fmt.Errorf("binary %s@%s: the package name is joined into the build root, so it must be a clean relative path with no \".\" or \"..\" element; correct it in the manifest", name, ve.Version)
	}
	return filepath.Join(d.binaries, name, ve.Version, filename), nil
}

// binaryLocalPath returns the on-disk path of a binary version entry, refusing
// one that a symlink would carry outside the configured binary root. Every
// reader and writer of a binary artifact resolves its path here, so a link
// that fails the fetch also hides a file from the stage check, the upload walk
// and the checksum lookup rather than letting them read through it.
func binaryLocalPath(cfg *Config, name string, ve manifest.VersionEntry) (string, error) {
	root := cfg.rootFor(manifest.TypeBinary)
	dest, err := binaryDestPath(buildDirs(root), name, ve)
	if err != nil {
		return "", err
	}
	if err := confinePath(root, dest); err != nil {
		return "", err
	}
	return dest, nil
}

// confinePath refuses a destination that a symlink would carry outside root.
//
// binaryDestPath confines the path as text; this confines it on disk. root is
// the configured root, not a directory under it, because the operator chose
// the root and nobody chose what sits below it: a symlinked root is honored,
// and a link at binaries/ or deeper is not. The deepest existing ancestor of
// dest is resolved and must sit under the resolved root, and dest itself must
// not be a symlink, since curl -o follows one. The fetch runs this before it
// creates any directory, so mkdir cannot follow a link out either. Something
// racing to plant a link between this check and the write already has write
// access to the build root, and with it every artifact the build root holds.
func confinePath(root, dest string) error {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("resolve build root %s: %w", root, err)
	}
	dir := filepath.Dir(dest)
	for {
		if _, err := os.Lstat(dir); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return fmt.Errorf("no existing ancestor of %s", dest)
		}
		dir = parent
	}
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", dir, err)
	}
	if rel, err := filepath.Rel(realRoot, realDir); err != nil || !filepath.IsLocal(rel) && rel != "." {
		return fmt.Errorf("destination %s resolves through a symlink to %s, outside the build root %s; remove the link", dest, realDir, realRoot)
	}
	if fi, err := os.Lstat(dest); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("destination %s is a symlink; remove it so the download cannot be written through it", dest)
	}
	return nil
}

// CheckBinaryStage inspects the filesystem to determine which pipeline stages
// have completed for the given binary package version. For binary entries the
// download IS the final artifact; Fetched, Built, and Packaged are all set together.
func CheckBinaryStage(cfg *Config, name string, ve manifest.VersionEntry) StageStatus {
	dest, err := binaryLocalPath(cfg, name, ve)
	if err != nil {
		return StageStatus{}
	}
	if fi, err := os.Stat(dest); err == nil && !fi.IsDir() {
		return StageStatus{Fetched: true, Built: true, Packaged: true}
	}
	return StageStatus{}
}

// FetchBinaries downloads every binary package version in the store to the
// binaries/ directory. When a version has a Version field, the file is placed
// under binaries/<name>/<version>/. For binary artifacts the download IS the
// final artifact; there is no separate build or package stage.
//
// Failures are captured per-entry; the run continues on error.
func FetchBinaries(cfg *Config, store *manifest.Store, entryFilter string) *Summary {
	ctx := context.Background()
	summary := &Summary{}
	if err := mkdirAll(cfg.rootFor(manifest.TypeBinary)); err != nil {
		cfg.logf("ERROR: %v", err)
		return summary
	}

	for _, name := range store.ListPackages(manifest.TypeBinary) {
		if entryFilter != "" && name != entryFilter {
			continue
		}

		pm, err := store.GetPackage(ctx, manifest.TypeBinary, name)
		if err != nil || pm == nil {
			cfg.logf("  [binary] %s: ERROR loading package: %v", name, err)
			continue
		}

		for _, ve := range pm.Versions {
			if ve.Frozen {
				cfg.logf("  [binary] %s: SKIPPED (frozen)", name)
				continue
			}
			if err := cfg.EnforcePolicy(ctx, manifest.TypeBinary, name, ve.Version, ve.URL); err != nil {
				cfg.logf("  [binary] %s: BLOCKED by policy: %v", name, err)
				summary.Failures++
				summary.Results = append(summary.Results, Result{Type: manifest.TypeBinary, Name: name, Err: err})
				continue
			}
			if !cfg.Force {
				stage := CheckBinaryStage(cfg, name, ve)
				if stage.Fetched {
					cfg.logf("  [binary] %s: already fetched, skipping (use 'force' to re-fetch)", name)
					if err := cfg.verifyFetched(ctx, store, manifest.TypeBinary, name, ve); err != nil {
						cfg.logf("  [binary] %s: %v", name, err)
						summary.Failures++
						summary.Results = append(summary.Results, Result{Type: manifest.TypeBinary, Name: name, Err: err})
					}
					continue
				}
			}

			start := time.Now()
			result := Result{Type: manifest.TypeBinary, Name: name}
			out := cfg.entryWriter(manifest.TypeBinary, name)

			_, _ = fmt.Fprintf(out, "\n>>> [binary] fetch %s\n", name)
			_, _ = fmt.Fprintf(out, "    URL: %s\n", ve.URL)

			destPath, err := binaryLocalPath(cfg, name, ve)
			if err == nil {
				// Ensure the versioned sub-directory exists.
				if mkErr := mkdirAll(filepath.Dir(destPath)); mkErr != nil {
					err = fmt.Errorf("create destination directory: %w", mkErr)
				}
			}
			if err != nil {
				result.Err = err
				_, _ = fmt.Fprintf(out, "    ERROR: %v\n", result.Err)
				summary.Failures++
				result.Elapsed = time.Since(start)
				summary.Results = append(summary.Results, result)
				summary.Total++
				cfg.RecordAudit(audit.EventFetch, manifest.TypeBinary, name, ve.Version, "failure", result.Elapsed, result.Err)
				continue
			}
			_, _ = fmt.Fprintf(out, "    Destination: %s\n", destPath)

			if err := downloadFile(out, ve.URL, destPath); err != nil {
				result.Err = fmt.Errorf("download %s: %w", ve.URL, err)
			} else {
				actual, hashErr := fileSHA256(destPath)
				if hashErr != nil {
					_, _ = fmt.Fprintf(out, "    WARNING: could not compute checksum: %v\n", hashErr)
				} else {
					_, _ = fmt.Fprintf(out, "    SHA-256: %s\n", actual)
					verified := false
					checksumOK := true

					// Verify against SHA256 field or Checksum struct.
					if ve.SHA256 != "" {
						if err := verifySHA256(destPath, ve.SHA256); err != nil {
							result.Err = err
							checksumOK = false
						} else {
							verified = true
							_, _ = fmt.Fprintf(out, "    Checksum verified against manifest (SHA256 field)\n")
						}
					} else if ve.Checksum != nil {
						if err := verifyChecksum(ve.Checksum, actual); err != nil {
							result.Err = fmt.Errorf("checksum verification failed: %w", err)
							checksumOK = false
						} else {
							verified = true
							_, _ = fmt.Fprintf(out, "    Checksum verified against manifest\n")
						}
					}

					if checksumOK {
						cs := newSHA256Checksum(actual)
						if err := cfg.findAndUpdateBinaryChecksum(store, name, ve, cs, verified); err != nil {
							_, _ = fmt.Fprintf(out, "    WARNING: could not save checksum: %v\n", err)
						}
					}
				}
			}

			if result.Err == nil {
				result.Artifacts = []string{destPath}
				fi, _ := os.Stat(destPath)
				if fi != nil {
					_, _ = fmt.Fprintf(out, "    Size: %s\n", humanBytes(fi.Size()))
				}
				cfg.StampBinaryEntry(store, name, ve)
				stampArtifactSize(context.Background(), store, manifest.TypeBinary, name, ve, destPath)
			} else {
				_, _ = fmt.Fprintf(out, "    ERROR: %v\n", result.Err)
				summary.Failures++
			}

			result.Elapsed = time.Since(start)
			summary.Results = append(summary.Results, result)
			summary.Total++
			_, _ = fmt.Fprintf(out, "    Done (%s)\n", result.Elapsed.Round(time.Millisecond))

			if cfg.Logger != nil {
				if result.Err != nil {
					cfg.Logger.Audit("FAILED  binary/fetch/%s  (%s)  %v", name, result.Elapsed.Round(time.Millisecond), result.Err)
				} else {
					cfg.Logger.Audit("OK      binary/fetch/%s  (%s)", name, result.Elapsed.Round(time.Millisecond))
				}
			}
			bfStatus := "success"
			if result.Err != nil {
				bfStatus = "failure"
			}
			cfg.RecordAudit(audit.EventFetch, manifest.TypeBinary, name, ve.Version, bfStatus, result.Elapsed, result.Err)
		}
	}

	return summary
}

// BinaryArtifactPaths returns the local path and S3 key for each binary
// package version whose artifact exists on disk. Used by the upload and sync commands.
func BinaryArtifactPaths(cfg *Config, store *manifest.Store, entryFilter string) []ArtifactPath {
	ctx := context.Background()
	var paths []ArtifactPath

	for _, name := range store.ListPackages(manifest.TypeBinary) {
		if entryFilter != "" && name != entryFilter {
			continue
		}

		pm, err := store.GetPackage(ctx, manifest.TypeBinary, name)
		if err != nil || pm == nil {
			continue
		}

		for _, ve := range pm.Versions {
			if ve.Frozen {
				continue
			}
			local, err := binaryLocalPath(cfg, name, ve)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				cfg.logf("  [binary] %s: SKIPPED: %v", name, err)
				continue
			}
			filename, _ := binaryFilename(ve)
			if fi, err := os.Stat(local); err != nil || fi.IsDir() {
				continue
			}
			paths = append(paths, ArtifactPath{
				Local:     local,
				ObjectKey: manifest.BinaryKey(pm.Name, ve.Version, filename),
				Package:   name,
				Version:   ve.Version,
			})
		}
	}
	return paths
}

// BuildBinaries is an alias for FetchBinaries retained for backward
// compatibility. New callers should use FetchBinaries directly.
func BuildBinaries(cfg *Config, store *manifest.Store, entryFilter string) *Summary {
	return FetchBinaries(cfg, store, entryFilter)
}

// downloadFile fetches url to destPath using curl, streaming output to out.
func downloadFile(out io.Writer, url, destPath string) error {
	// Use curl: widely available and handles redirects, progress, TLS.
	return runCmd(out, "", "curl", "-fL", "--progress-bar", url, "-o", destPath)
}

// verifySHA256 computes the SHA-256 of the file at path and compares to expected.
func verifySHA256(path, expected string) error {
	actual, err := fileSHA256(path)
	if err != nil {
		return err
	}
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("SHA-256 mismatch for %s:\n  expected: %s\n  actual:   %s", path, expected, actual)
	}
	return nil
}

// fileSHA256 returns the lowercase hex SHA-256 of a file.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// humanBytes formats a byte count as a human-readable string.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for n := n / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
