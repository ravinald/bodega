package builder

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/scaleapi/bodega/internal/manifest"
)

// helmChartFilename returns the conventional Helm chart archive name.
func helmChartFilename(entry manifest.HelmEntry) string {
	return entry.Name + "-" + entry.Version + ".tgz"
}

// helmLocalPath returns the local path for a chart archive.
func helmLocalPath(d dirs, entry manifest.HelmEntry) string {
	return filepath.Join(d.charts, entry.Name, entry.Version, helmChartFilename(entry))
}

// helmS3Key returns the S3 key for a chart archive.
func helmS3Key(entry manifest.HelmEntry) string {
	return "charts/" + helmChartFilename(entry)
}

// CheckHelmStage inspects the local filesystem for a fetched Helm chart.
func CheckHelmStage(cfg *Config, entry manifest.HelmEntry) StageStatus {
	d := buildDirs(cfg.rootFor(manifest.TypeHelm))
	path := helmLocalPath(d, entry)
	if fileExists(path) {
		return StageStatus{Fetched: true, Built: true, Packaged: true}
	}
	return StageStatus{}
}

// FetchHelm downloads Helm chart .tgz archives for each HelmEntry.
func FetchHelm(cfg *Config, store *manifest.Store, entryFilter string) *Summary {
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypeHelm))

	if err := mkdirAll(d.charts); err != nil {
		cfg.logf("ERROR: %v", err)
		return summary
	}

	for _, entry := range store.Helm {
		if entryFilter != "" && entry.Name != entryFilter {
			continue
		}
		if entry.Frozen {
			cfg.logf("  [helm] %s: SKIPPED (frozen)", entry.Name)
			continue
		}
		if !cfg.Force {
			stage := CheckHelmStage(cfg, entry)
			if stage.Fetched {
				cfg.logf("  [helm] %s: already fetched, skipping", entry.Name)
				continue
			}
		}

		result := Result{Type: manifest.TypeHelm, Name: entry.Name}
		start := time.Now()
		out := cfg.entryWriter(manifest.TypeHelm, entry.Name)

		dest := helmLocalPath(d, entry)
		if err := mkdirAll(filepath.Dir(dest)); err != nil {
			result.Err = fmt.Errorf("create chart dir: %w", err)
			summary.Failures++
			result.Elapsed = time.Since(start)
			summary.Results = append(summary.Results, result)
			summary.Total++
			continue
		}
		_, _ = fmt.Fprintf(out, "  [helm] %s: fetching %s\n", entry.Name, entry.URL)

		if err := downloadURL(dest, entry.URL); err != nil {
			_, _ = fmt.Fprintf(out, "  [helm] %s: ERROR: %v\n", entry.Name, err)
			result.Err = err
		} else {
			result.Artifacts = append(result.Artifacts, dest)

			// Checksum verification.
			computed, err := computeFileSHA256(dest)
			if err != nil {
				_, _ = fmt.Fprintf(out, "  [helm] %s: WARNING: could not compute checksum: %v\n", entry.Name, err)
			} else if entry.Checksum != nil {
				if err := verifyChecksum(entry.Checksum, computed); err != nil {
					_, _ = fmt.Fprintf(out, "  [helm] %s: CHECKSUM MISMATCH: %v\n", entry.Name, err)
					result.Err = fmt.Errorf("checksum verification failed: %w", err)
				} else {
					_, _ = fmt.Fprintf(out, "  [helm] %s: checksum verified\n", entry.Name)
					if !entry.ChecksumVerified {
						if e := cfg.findAndUpdateHelmChecksum(store, entry.Name, entry.Checksum, true); e != nil {
							_, _ = fmt.Fprintf(out, "  [helm] %s: WARNING: could not save verified status: %v\n", entry.Name, e)
						}
					}
				}
			} else if computed != "" {
				cs := newSHA256Checksum(computed)
				_, _ = fmt.Fprintf(out, "  [helm] %s: checksum recorded (sha256:%s...)\n", entry.Name, computed[:12])
				if e := cfg.findAndUpdateHelmChecksum(store, entry.Name, cs, false); e != nil {
					_, _ = fmt.Fprintf(out, "  [helm] %s: WARNING: could not save checksum: %v\n", entry.Name, e)
				}
			}

			if result.Err == nil {
				_, _ = fmt.Fprintf(out, "  [helm] %s: ok\n", entry.Name)
				cfg.StampHelmEntry(store, entry.Name)
			}
		}

		result.Elapsed = time.Since(start)
		summary.Results = append(summary.Results, result)
		summary.Total++
		if result.Err != nil {
			summary.Failures++
		}
	}

	return summary
}

// PackageHelm generates an index.yaml from all fetched chart archives.
// This is a simplified implementation that creates entries based on manifest
// data rather than parsing Chart.yaml from each tarball.
func PackageHelm(cfg *Config, store *manifest.Store) *Summary {
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypeHelm))
	out := cfg.stdout()

	_, _ = fmt.Fprintf(out, "  [helm] generating index.yaml\n")

	indexPath := filepath.Join(d.charts, "index.yaml")
	f, err := os.Create(indexPath)
	if err != nil {
		cfg.logf("ERROR creating index.yaml: %v", err)
		return summary
	}
	defer func() { _ = f.Close() }()

	_, _ = fmt.Fprintf(f, "apiVersion: v1\nentries:\n")

	for _, entry := range store.Helm {
		filename := helmChartFilename(entry)
		if !fileExists(helmLocalPath(d, entry)) {
			continue
		}

		_, _ = fmt.Fprintf(f, "  %s:\n", entry.Name)
		_, _ = fmt.Fprintf(f, "  - name: %s\n", entry.Name)
		_, _ = fmt.Fprintf(f, "    version: %s\n", entry.Version)
		if entry.AppVersion != "" {
			_, _ = fmt.Fprintf(f, "    appVersion: %q\n", entry.AppVersion)
		}
		_, _ = fmt.Fprintf(f, "    urls:\n")
		_, _ = fmt.Fprintf(f, "    - charts/%s\n", filename)
		_, _ = fmt.Fprintf(f, "    created: %s\n", time.Now().UTC().Format(time.RFC3339))

		summary.Total++
	}

	if err := f.Close(); err != nil {
		cfg.logf("ERROR writing index.yaml: %v", err)
		summary.Failures++
	}

	_, _ = fmt.Fprintf(out, "  [helm] index.yaml written with %d chart(s)\n", summary.Total)
	return summary
}

// HelmArtifactPaths returns local/S3 path pairs for upload.
func HelmArtifactPaths(cfg *Config, store *manifest.Store, entryFilter string) []ArtifactPath {
	d := buildDirs(cfg.rootFor(manifest.TypeHelm))
	var paths []ArtifactPath

	for _, entry := range store.Helm {
		if entryFilter != "" && entry.Name != entryFilter {
			continue
		}
		local := helmLocalPath(d, entry)
		if fileExists(local) {
			paths = append(paths, ArtifactPath{
				Local: local,
				S3Key: helmS3Key(entry),
			})
		}
	}

	// Include index.yaml if it exists.
	indexPath := filepath.Join(d.charts, "index.yaml")
	if fileExists(indexPath) {
		paths = append(paths, ArtifactPath{
			Local: indexPath,
			S3Key: "charts/index.yaml",
		})
	}

	return paths
}
