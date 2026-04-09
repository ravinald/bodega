package builder

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/scaleapi/bodega/internal/manifest"
)

// helmChartFilename returns the conventional Helm chart archive name.
func helmChartFilename(name string, ve manifest.VersionEntry) string {
	return name + "-" + ve.Version + ".tgz"
}

// helmLocalPath returns the local path for a chart archive.
func helmLocalPath(d dirs, name string, ve manifest.VersionEntry) string {
	return filepath.Join(d.charts, name, ve.Version, helmChartFilename(name, ve))
}

// helmS3Key returns the S3 key for a chart archive.
func helmS3Key(name string, ve manifest.VersionEntry) string {
	return "charts/" + helmChartFilename(name, ve)
}

// CheckHelmStage inspects the local filesystem for a fetched Helm chart.
func CheckHelmStage(cfg *Config, name string, ve manifest.VersionEntry) StageStatus {
	d := buildDirs(cfg.rootFor(manifest.TypeHelm))
	path := helmLocalPath(d, name, ve)
	if fileExists(path) {
		return StageStatus{Fetched: true, Built: true, Packaged: true}
	}
	return StageStatus{}
}

// FetchHelm downloads Helm chart .tgz archives for each helm package version.
func FetchHelm(cfg *Config, store *manifest.Store, entryFilter string) *Summary {
	ctx := context.Background()
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypeHelm))

	if err := mkdirAll(d.charts); err != nil {
		cfg.logf("ERROR: %v", err)
		return summary
	}

	for _, name := range store.ListPackages(manifest.TypeHelm) {
		if entryFilter != "" && name != entryFilter {
			continue
		}

		pm, err := store.GetPackage(ctx, manifest.TypeHelm, name)
		if err != nil || pm == nil {
			cfg.logf("  [helm] %s: ERROR loading package: %v", name, err)
			continue
		}

		for _, ve := range pm.Versions {
			if ve.Frozen {
				cfg.logf("  [helm] %s: SKIPPED (frozen)", name)
				continue
			}
			if !cfg.Force {
				stage := CheckHelmStage(cfg, name, ve)
				if stage.Fetched {
					cfg.logf("  [helm] %s: already fetched, skipping", name)
					continue
				}
			}

			result := Result{Type: manifest.TypeHelm, Name: name}
			start := time.Now()
			out := cfg.entryWriter(manifest.TypeHelm, name)

			dest := helmLocalPath(d, name, ve)
			if err := mkdirAll(filepath.Dir(dest)); err != nil {
				result.Err = fmt.Errorf("create chart dir: %w", err)
				summary.Failures++
				result.Elapsed = time.Since(start)
				summary.Results = append(summary.Results, result)
				summary.Total++
				continue
			}
			_, _ = fmt.Fprintf(out, "  [helm] %s: fetching %s\n", name, ve.URL)

			if err := downloadURL(dest, ve.URL); err != nil {
				_, _ = fmt.Fprintf(out, "  [helm] %s: ERROR: %v\n", name, err)
				result.Err = err
			} else {
				result.Artifacts = append(result.Artifacts, dest)

				// Checksum verification.
				computed, err := computeFileSHA256(dest)
				if err != nil {
					_, _ = fmt.Fprintf(out, "  [helm] %s: WARNING: could not compute checksum: %v\n", name, err)
				} else if ve.Checksum != nil {
					if err := verifyChecksum(ve.Checksum, computed); err != nil {
						_, _ = fmt.Fprintf(out, "  [helm] %s: CHECKSUM MISMATCH: %v\n", name, err)
						result.Err = fmt.Errorf("checksum verification failed: %w", err)
					} else {
						_, _ = fmt.Fprintf(out, "  [helm] %s: checksum verified\n", name)
						if !ve.ChecksumVerified {
							if e := cfg.findAndUpdateHelmChecksum(store, name, ve, ve.Checksum, true); e != nil {
								_, _ = fmt.Fprintf(out, "  [helm] %s: WARNING: could not save verified status: %v\n", name, e)
							}
						}
					}
				} else if computed != "" {
					cs := newSHA256Checksum(computed)
					_, _ = fmt.Fprintf(out, "  [helm] %s: checksum recorded (sha256:%s...)\n", name, computed[:12])
					if e := cfg.findAndUpdateHelmChecksum(store, name, ve, cs, false); e != nil {
						_, _ = fmt.Fprintf(out, "  [helm] %s: WARNING: could not save checksum: %v\n", name, e)
					}
				}

				if result.Err == nil {
					_, _ = fmt.Fprintf(out, "  [helm] %s: ok\n", name)
					cfg.StampHelmEntry(store, name, ve)
				}
			}

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

// PackageHelm generates an index.yaml from all fetched chart archives.
// This is a simplified implementation that creates entries based on manifest
// data rather than parsing Chart.yaml from each tarball.
func PackageHelm(cfg *Config, store *manifest.Store) *Summary {
	ctx := context.Background()
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

	for _, name := range store.ListPackages(manifest.TypeHelm) {
		pm, err := store.GetPackage(ctx, manifest.TypeHelm, name)
		if err != nil || pm == nil {
			continue
		}

		for _, ve := range pm.Versions {
			filename := helmChartFilename(name, ve)
			if !fileExists(helmLocalPath(d, name, ve)) {
				continue
			}

			_, _ = fmt.Fprintf(f, "  %s:\n", name)
			_, _ = fmt.Fprintf(f, "  - name: %s\n", name)
			_, _ = fmt.Fprintf(f, "    version: %s\n", ve.Version)
			if ve.AppVersion != "" {
				_, _ = fmt.Fprintf(f, "    appVersion: %q\n", ve.AppVersion)
			}
			_, _ = fmt.Fprintf(f, "    urls:\n")
			_, _ = fmt.Fprintf(f, "    - charts/%s\n", filename)
			_, _ = fmt.Fprintf(f, "    created: %s\n", time.Now().UTC().Format(time.RFC3339))

			summary.Total++
		}
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
	ctx := context.Background()
	d := buildDirs(cfg.rootFor(manifest.TypeHelm))
	var paths []ArtifactPath

	for _, name := range store.ListPackages(manifest.TypeHelm) {
		if entryFilter != "" && name != entryFilter {
			continue
		}

		pm, err := store.GetPackage(ctx, manifest.TypeHelm, name)
		if err != nil || pm == nil {
			continue
		}

		for _, ve := range pm.Versions {
			local := helmLocalPath(d, name, ve)
			if fileExists(local) {
				paths = append(paths, ArtifactPath{
					Local: local,
					S3Key: helmS3Key(name, ve),
				})
			}
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
