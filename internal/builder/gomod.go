package builder

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/scaleapi/bodega/internal/manifest"
)

const defaultGoProxy = "https://proxy.golang.org"

// gomodDir returns the local directory for a Go module's version artifacts.
func gomodDir(d dirs, entry manifest.GomodEntry) string {
	// Module paths use slashes (github.com/aws/...) which map to nested dirs.
	return filepath.Join(d.gomod, entry.Name, "@v")
}

// gomodS3Prefix returns the S3 key prefix for a Go module.
func gomodS3Prefix(entry manifest.GomodEntry) string {
	return "gomod/" + entry.Name + "/@v/"
}

// CheckGomodStage inspects the local filesystem for fetched Go module artifacts.
func CheckGomodStage(cfg *Config, entry manifest.GomodEntry) StageStatus {
	d := buildDirs(cfg.rootFor(manifest.TypeGomod))
	dir := gomodDir(d, entry)

	infoPath := filepath.Join(dir, entry.Version+".info")
	if _, err := os.Stat(infoPath); err != nil {
		return StageStatus{}
	}

	modPath := filepath.Join(dir, entry.Version+".mod")
	zipPath := filepath.Join(dir, entry.Version+".zip")
	modExists := fileExists(modPath)
	zipExists := fileExists(zipPath)

	return StageStatus{
		Fetched:  true,
		Built:    modExists && zipExists,
		Packaged: modExists && zipExists,
	}
}

// FetchGomod downloads Go module artifacts (.info, .mod, .zip) from an upstream
// GOPROXY for each GomodEntry in the manifest.
func FetchGomod(cfg *Config, store *manifest.Store, entryFilter string) *Summary {
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypeGomod))

	for _, entry := range store.Gomod {
		if entryFilter != "" && entry.Name != entryFilter {
			continue
		}
		if entry.Frozen {
			cfg.logf("  [gomod] %s: SKIPPED (frozen)", entry.Name)
			continue
		}
		if !cfg.Force {
			stage := CheckGomodStage(cfg, entry)
			if stage.Fetched {
				cfg.logf("  [gomod] %s: already fetched, skipping", entry.Name)
				continue
			}
		}

		result := Result{Type: manifest.TypeGomod, Name: entry.Name}
		start := time.Now()
		out := cfg.entryWriter(manifest.TypeGomod, entry.Name)

		dir := gomodDir(d, entry)
		if err := mkdirAll(dir); err != nil {
			result.Err = err
			result.Elapsed = time.Since(start)
			summary.Results = append(summary.Results, result)
			summary.Total++
			summary.Failures++
			continue
		}

		proxy := entry.URL
		if proxy == "" {
			proxy = defaultGoProxy
		}

		base := proxy + "/" + entry.Name + "/@v/" + entry.Version

		var fetchErr error
		for _, ext := range []string{".info", ".mod", ".zip"} {
			url := base + ext
			dest := filepath.Join(dir, entry.Version+ext)
			_, _ = fmt.Fprintf(out, "  [gomod] %s: fetching %s\n", entry.Name, url)
			if err := downloadURL(dest, url); err != nil {
				_, _ = fmt.Fprintf(out, "  [gomod] %s: ERROR fetching %s: %v\n", entry.Name, ext, err)
				fetchErr = err
				break
			}
			result.Artifacts = append(result.Artifacts, dest)

			// Verify checksum for the .zip (primary artifact).
			if ext == ".zip" {
				computed, err := computeFileSHA256(dest)
				if err != nil {
					_, _ = fmt.Fprintf(out, "  [gomod] %s: WARNING: could not compute checksum: %v\n", entry.Name, err)
				} else if entry.Checksum != nil {
					if err := verifyChecksum(entry.Checksum, computed); err != nil {
						_, _ = fmt.Fprintf(out, "  [gomod] %s: CHECKSUM MISMATCH: %v\n", entry.Name, err)
						fetchErr = fmt.Errorf("checksum verification failed for %s: %w", entry.Name, err)
						break
					}
					_, _ = fmt.Fprintf(out, "  [gomod] %s: checksum verified (%s)\n", entry.Name, entry.Checksum.Algorithm)
					if !entry.ChecksumVerified {
						if e := cfg.findAndUpdateGomodChecksum(store, entry.Name, entry.Checksum, true); e != nil {
							_, _ = fmt.Fprintf(out, "  [gomod] %s: WARNING: could not save verified status: %v\n", entry.Name, e)
						}
					}
				} else if computed != "" {
					// Auto-populate checksum on first fetch.
					cs := newSHA256Checksum(computed)
					_, _ = fmt.Fprintf(out, "  [gomod] %s: checksum recorded (sha256:%s...)\n", entry.Name, computed[:12])
					if e := cfg.findAndUpdateGomodChecksum(store, entry.Name, cs, false); e != nil {
						_, _ = fmt.Fprintf(out, "  [gomod] %s: WARNING: could not save checksum: %v\n", entry.Name, e)
					}
				}
			}
		}

		// Update the @v/list file with this version.
		if fetchErr == nil {
			listPath := filepath.Join(dir, "list")
			if err := appendVersionToList(listPath, entry.Version); err != nil {
				_, _ = fmt.Fprintf(out, "  [gomod] %s: WARNING: could not update list: %v\n", entry.Name, err)
			}
			cfg.StampGomodEntry(store, entry.Name)
		}

		result.Err = fetchErr
		result.Elapsed = time.Since(start)
		summary.Results = append(summary.Results, result)
		summary.Total++
		if result.Err != nil {
			summary.Failures++
		}
	}

	return summary
}

// GomodArtifactPaths returns local/S3 path pairs for upload.
func GomodArtifactPaths(cfg *Config, store *manifest.Store, entryFilter string) []ArtifactPath {
	d := buildDirs(cfg.rootFor(manifest.TypeGomod))
	var paths []ArtifactPath

	for _, entry := range store.Gomod {
		if entryFilter != "" && entry.Name != entryFilter {
			continue
		}
		dir := gomodDir(d, entry)
		prefix := gomodS3Prefix(entry)

		for _, ext := range []string{".info", ".mod", ".zip"} {
			local := filepath.Join(dir, entry.Version+ext)
			if fileExists(local) {
				paths = append(paths, ArtifactPath{
					Local: local,
					S3Key: prefix + entry.Version + ext,
				})
			}
		}

		// Include @v/list if it exists.
		listPath := filepath.Join(dir, "list")
		if fileExists(listPath) {
			paths = append(paths, ArtifactPath{
				Local: listPath,
				S3Key: prefix + "list",
			})
		}
	}

	return paths
}

// downloadURL fetches a URL and writes it to dest.
func downloadURL(dest, url string) error {
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("write %s: %w", dest, err)
	}
	return f.Close()
}

// appendVersionToList appends a version to the @v/list file if not already present.
func appendVersionToList(listPath, version string) error {
	existing, _ := os.ReadFile(listPath)
	for _, line := range strings.Split(string(existing), "\n") {
		if strings.TrimSpace(line) == version {
			return nil // already listed
		}
	}

	f, err := os.OpenFile(listPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = fmt.Fprintln(f, version)
	return err
}

// fileExists returns true if path exists and is not a directory.
func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}
