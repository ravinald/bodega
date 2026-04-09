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

const defaultGoProxy = "https://proxy.golang.org"

// gomodDir returns the local directory for a Go module's version artifacts.
func gomodDir(d dirs, name string) string {
	// Module paths use slashes (github.com/aws/...) which map to nested dirs.
	return filepath.Join(d.gomod, name, "@v")
}

// gomodS3Prefix returns the S3 key prefix for a Go module.
func gomodS3Prefix(name string) string {
	return "gomod/" + name + "/@v/"
}

// CheckGomodStage inspects the local filesystem for fetched Go module artifacts.
func CheckGomodStage(cfg *Config, name string, ve manifest.VersionEntry) StageStatus {
	d := buildDirs(cfg.rootFor(manifest.TypeGomod))
	dir := gomodDir(d, name)

	infoPath := filepath.Join(dir, ve.Version+".info")
	if _, err := os.Stat(infoPath); err != nil {
		return StageStatus{}
	}

	modPath := filepath.Join(dir, ve.Version+".mod")
	zipPath := filepath.Join(dir, ve.Version+".zip")
	modExists := fileExists(modPath)
	zipExists := fileExists(zipPath)

	return StageStatus{
		Fetched:  true,
		Built:    modExists && zipExists,
		Packaged: modExists && zipExists,
	}
}

// FetchGomod downloads Go module artifacts (.info, .mod, .zip) from an upstream
// GOPROXY for each gomod package version in the manifest.
func FetchGomod(cfg *Config, store *manifest.Store, entryFilter string) *Summary {
	ctx := context.Background()
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypeGomod))

	for _, name := range store.ListPackages(manifest.TypeGomod) {
		if entryFilter != "" && name != entryFilter {
			continue
		}

		pm, err := store.GetPackage(ctx, manifest.TypeGomod, name)
		if err != nil || pm == nil {
			cfg.logf("  [gomod] %s: ERROR loading package: %v", name, err)
			continue
		}

		for _, ve := range pm.Versions {
			if ve.Frozen {
				cfg.logf("  [gomod] %s: SKIPPED (frozen)", name)
				continue
			}
			if !cfg.Force {
				stage := CheckGomodStage(cfg, name, ve)
				if stage.Fetched {
					cfg.logf("  [gomod] %s: already fetched, skipping", name)
					continue
				}
			}

			result := Result{Type: manifest.TypeGomod, Name: name}
			start := time.Now()
			out := cfg.entryWriter(manifest.TypeGomod, name)

			dir := gomodDir(d, name)
			if err := mkdirAll(dir); err != nil {
				result.Err = err
				result.Elapsed = time.Since(start)
				summary.Results = append(summary.Results, result)
				summary.Total++
				summary.Failures++
				continue
			}

			proxy := ve.URL
			if proxy == "" {
				proxy = defaultGoProxy
			}

			base := proxy + "/" + name + "/@v/" + ve.Version

			var fetchErr error
			for _, ext := range []string{".info", ".mod", ".zip"} {
				url := base + ext
				dest := filepath.Join(dir, ve.Version+ext)
				_, _ = fmt.Fprintf(out, "  [gomod] %s: fetching %s\n", name, url)
				if err := downloadURL(dest, url); err != nil {
					_, _ = fmt.Fprintf(out, "  [gomod] %s: ERROR fetching %s: %v\n", name, ext, err)
					fetchErr = err
					break
				}
				result.Artifacts = append(result.Artifacts, dest)

				// Verify checksum for the .zip (primary artifact).
				if ext == ".zip" {
					computed, err := computeFileSHA256(dest)
					if err != nil {
						_, _ = fmt.Fprintf(out, "  [gomod] %s: WARNING: could not compute checksum: %v\n", name, err)
					} else if ve.Checksum != nil {
						if err := verifyChecksum(ve.Checksum, computed); err != nil {
							_, _ = fmt.Fprintf(out, "  [gomod] %s: CHECKSUM MISMATCH: %v\n", name, err)
							fetchErr = fmt.Errorf("checksum verification failed for %s: %w", name, err)
							break
						}
						_, _ = fmt.Fprintf(out, "  [gomod] %s: checksum verified (%s)\n", name, ve.Checksum.Algorithm)
						if !ve.ChecksumVerified {
							if e := cfg.findAndUpdateGomodChecksum(store, name, ve, ve.Checksum, true); e != nil {
								_, _ = fmt.Fprintf(out, "  [gomod] %s: WARNING: could not save verified status: %v\n", name, e)
							}
						}
					} else if computed != "" {
						// Auto-populate checksum on first fetch.
						cs := newSHA256Checksum(computed)
						_, _ = fmt.Fprintf(out, "  [gomod] %s: checksum recorded (sha256:%s...)\n", name, computed[:12])
						if e := cfg.findAndUpdateGomodChecksum(store, name, ve, cs, false); e != nil {
							_, _ = fmt.Fprintf(out, "  [gomod] %s: WARNING: could not save checksum: %v\n", name, e)
						}
					}
				}
			}

			// Update the @v/list file with this version.
			if fetchErr == nil {
				listPath := filepath.Join(dir, "list")
				if err := appendVersionToList(listPath, ve.Version); err != nil {
					_, _ = fmt.Fprintf(out, "  [gomod] %s: WARNING: could not update list: %v\n", name, err)
				}
				cfg.StampGomodEntry(store, name, ve)
			}

			result.Err = fetchErr
			result.Elapsed = time.Since(start)
			summary.Results = append(summary.Results, result)
			summary.Total++
			if result.Err != nil {
				summary.Failures++
			}
		}
	}

	return summary
}

// GomodArtifactPaths returns local/S3 path pairs for upload.
func GomodArtifactPaths(cfg *Config, store *manifest.Store, entryFilter string) []ArtifactPath {
	ctx := context.Background()
	d := buildDirs(cfg.rootFor(manifest.TypeGomod))
	var paths []ArtifactPath

	for _, name := range store.ListPackages(manifest.TypeGomod) {
		if entryFilter != "" && name != entryFilter {
			continue
		}

		pm, err := store.GetPackage(ctx, manifest.TypeGomod, name)
		if err != nil || pm == nil {
			continue
		}

		for _, ve := range pm.Versions {
			dir := gomodDir(d, name)
			prefix := gomodS3Prefix(name)

			for _, ext := range []string{".info", ".mod", ".zip"} {
				local := filepath.Join(dir, ve.Version+ext)
				if fileExists(local) {
					paths = append(paths, ArtifactPath{
						Local: local,
						S3Key: prefix + ve.Version + ext,
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
