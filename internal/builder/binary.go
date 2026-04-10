package builder

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/scaleapi/bodega/internal/manifest"
)

// binaryFilename returns the local filename for a binary version entry, using
// ve.Filename when set and falling back to the basename of the URL.
func binaryFilename(ve manifest.VersionEntry) string {
	if ve.Filename != "" {
		return ve.Filename
	}
	return filepath.Base(ve.URL)
}

// binaryDestPath returns the absolute local destination path for a binary
// version entry. When the entry has a Version set, the file is placed under
// binaries/<name>/<version>/<filename> to allow multiple versions to coexist.
// Falls back to binaries/<name>/<filename> when Version is empty.
func binaryDestPath(d dirs, name string, ve manifest.VersionEntry) string {
	filename := binaryFilename(ve)
	if ve.Version != "" {
		return filepath.Join(d.binaries, name, ve.Version, filename)
	}
	return filepath.Join(d.binaries, name, filename)
}

// binaryS3Key returns the S3 object key for a binary version entry.
// When the entry has a Version, the key is binaries/<name>/<version>/<filename>.
// Falls back to binaries/<name>/<filename> for unversioned entries.
func binaryS3Key(name string, ve manifest.VersionEntry) string {
	filename := binaryFilename(ve)
	if ve.Version != "" {
		return "binaries/" + name + "/" + ve.Version + "/" + filename
	}
	return "binaries/" + name + "/" + filename
}

// CheckBinaryStage inspects the filesystem to determine which pipeline stages
// have completed for the given binary package version. For binary entries the
// download IS the final artifact; Fetched, Built, and Packaged are all set together.
func CheckBinaryStage(cfg *Config, name string, ve manifest.VersionEntry) StageStatus {
	d := buildDirs(cfg.rootFor(manifest.TypeBinary))
	dest := binaryDestPath(d, name, ve)
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
	d := buildDirs(cfg.rootFor(manifest.TypeBinary))

	if err := mkdirAll(d.binaries); err != nil {
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
			if !cfg.Force {
				stage := CheckBinaryStage(cfg, name, ve)
				if stage.Fetched {
					cfg.logf("  [binary] %s: already fetched, skipping (use --force to re-fetch)", name)
					continue
				}
			}

			start := time.Now()
			result := Result{Type: manifest.TypeBinary, Name: name}
			out := cfg.entryWriter(manifest.TypeBinary, name)

			_, _ = fmt.Fprintf(out, "\n>>> [binary] fetch %s\n", name)
			_, _ = fmt.Fprintf(out, "    URL: %s\n", ve.URL)

			destPath := binaryDestPath(d, name, ve)
			// Ensure the versioned sub-directory exists.
			if err := mkdirAll(filepath.Dir(destPath)); err != nil {
				result.Err = fmt.Errorf("create destination directory: %w", err)
				_, _ = fmt.Fprintf(out, "    ERROR: %v\n", result.Err)
				summary.Failures++
				result.Elapsed = time.Since(start)
				summary.Results = append(summary.Results, result)
				summary.Total++
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
		}
	}

	return summary
}

// BinaryArtifactPaths returns the local path and S3 key for each binary
// package version whose artifact exists on disk. Used by the upload and sync commands.
func BinaryArtifactPaths(cfg *Config, store *manifest.Store, entryFilter string) []ArtifactPath {
	ctx := context.Background()
	d := buildDirs(cfg.rootFor(manifest.TypeBinary))
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
			local := binaryDestPath(d, name, ve)
			if fi, err := os.Stat(local); err != nil || fi.IsDir() {
				continue
			}
			paths = append(paths, ArtifactPath{
				Local: local,
				S3Key: binaryS3Key(name, ve),
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
