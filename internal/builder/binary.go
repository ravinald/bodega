package builder

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/scaleapi/bodega/internal/manifest"
)

// binaryFilename returns the local filename for a BinaryEntry, using
// entry.Filename when set and falling back to the basename of the URL.
func binaryFilename(entry manifest.BinaryEntry) string {
	if entry.Filename != "" {
		return entry.Filename
	}
	return filepath.Base(entry.URL)
}

// binaryDestPath returns the absolute local destination path for a BinaryEntry.
// When the entry has a Version set, the file is placed under
// binaries/<version>/<filename> to allow multiple versions to coexist.
// Falls back to binaries/<filename> when Version is empty.
func binaryDestPath(d dirs, entry manifest.BinaryEntry) string {
	filename := binaryFilename(entry)
	if entry.Version != "" {
		return filepath.Join(d.binaries, entry.Name, entry.Version, filename)
	}
	return filepath.Join(d.binaries, entry.Name, filename)
}

// binaryS3Key returns the S3 object key for a BinaryEntry.
// When the entry has a Version, the key is binaries/<name>/<version>/<filename>.
// Falls back to binaries/<filename> for unversioned entries.
func binaryS3Key(entry manifest.BinaryEntry) string {
	filename := binaryFilename(entry)
	if entry.Version != "" {
		return "binaries/" + entry.Name + "/" + entry.Version + "/" + filename
	}
	return "binaries/" + entry.Name + "/" + filename
}

// CheckBinaryStage inspects the filesystem to determine which pipeline stages
// have completed for the given BinaryEntry. For binary entries the download IS
// the final artifact; Fetched, Built, and Packaged are all set together.
func CheckBinaryStage(cfg *Config, entry manifest.BinaryEntry) StageStatus {
	d := buildDirs(cfg.rootFor(manifest.TypeBinary))
	dest := binaryDestPath(d, entry)
	if fi, err := os.Stat(dest); err == nil && !fi.IsDir() {
		return StageStatus{Fetched: true, Built: true, Packaged: true}
	}
	return StageStatus{}
}

// FetchBinaries downloads every BinaryEntry in the store to the binaries/
// directory. When an entry has a Version, the file is placed under
// binaries/<version>/. For binary artifacts the download IS the final
// artifact; there is no separate build or package stage.
//
// Failures are captured per-entry; the run continues on error.
func FetchBinaries(cfg *Config, store *manifest.Store, entryFilter string) *Summary {
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypeBinary))

	if err := mkdirAll(d.binaries); err != nil {
		cfg.logf("ERROR: %v", err)
		return summary
	}

	for _, entry := range store.Binary {
		if entryFilter != "" && entry.Name != entryFilter {
			continue
		}
		if entry.Frozen {
			cfg.logf("  [binary] %s: SKIPPED (frozen)", entry.Name)
			continue
		}
		if !cfg.Force {
			stage := CheckBinaryStage(cfg, entry)
			if stage.Fetched {
				cfg.logf("  [binary] %s: already fetched, skipping (use --force to re-fetch)", entry.Name)
				continue
			}
		}

		start := time.Now()
		result := Result{Type: manifest.TypeBinary, Name: entry.Name}
		out := cfg.entryWriter(manifest.TypeBinary, entry.Name)

		_, _ = fmt.Fprintf(out, "\n>>> [binary] fetch %s\n", entry.Name)
		_, _ = fmt.Fprintf(out, "    URL: %s\n", entry.URL)

		destPath := binaryDestPath(d, entry)
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

		if err := downloadFile(out, entry.URL, destPath); err != nil {
			result.Err = fmt.Errorf("download %s: %w", entry.URL, err)
		} else {
			actual, hashErr := fileSHA256(destPath)
			if hashErr != nil {
				_, _ = fmt.Fprintf(out, "    WARNING: could not compute checksum: %v\n", hashErr)
			} else {
				_, _ = fmt.Fprintf(out, "    SHA-256: %s\n", actual)
				verified := false
				checksumOK := true

				// Verify against legacy SHA256 field or Checksum struct.
				if entry.SHA256 != nil && *entry.SHA256 != "" {
					if err := verifySHA256(destPath, *entry.SHA256); err != nil {
						result.Err = err
						checksumOK = false
					} else {
						verified = true
						_, _ = fmt.Fprintf(out, "    Checksum verified against manifest (SHA256 field)\n")
					}
				} else if entry.Checksum != nil {
					if err := verifyChecksum(entry.Checksum, actual); err != nil {
						result.Err = fmt.Errorf("checksum verification failed: %w", err)
						checksumOK = false
					} else {
						verified = true
						_, _ = fmt.Fprintf(out, "    Checksum verified against manifest\n")
					}
				}

				if checksumOK {
					cs := newSHA256Checksum(actual)
					if err := cfg.findAndUpdateBinaryChecksum(store, entry.Name, cs, verified); err != nil {
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
			cfg.StampBinaryEntry(store, entry.Name)
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
				cfg.Logger.Audit("FAILED  binary/fetch/%s  (%s)  %v", entry.Name, result.Elapsed.Round(time.Millisecond), result.Err)
			} else {
				cfg.Logger.Audit("OK      binary/fetch/%s  (%s)", entry.Name, result.Elapsed.Round(time.Millisecond))
			}
		}
	}

	return summary
}

// BinaryArtifactPaths returns the local path and S3 key for each BinaryEntry
// whose artifact exists on disk. Used by the upload and sync commands.
func BinaryArtifactPaths(cfg *Config, store *manifest.Store, entryFilter string) []ArtifactPath {
	d := buildDirs(cfg.rootFor(manifest.TypeBinary))
	var paths []ArtifactPath
	for _, entry := range store.Binary {
		if entryFilter != "" && entry.Name != entryFilter {
			continue
		}
		if entry.Frozen {
			continue
		}
		local := binaryDestPath(d, entry)
		if fi, err := os.Stat(local); err != nil || fi.IsDir() {
			continue
		}
		paths = append(paths, ArtifactPath{
			Local: local,
			S3Key: binaryS3Key(entry),
		})
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
