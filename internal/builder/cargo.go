package builder

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

const defaultCargoRegistry = "https://index.crates.io"

// cargoCrateFilename returns the conventional .crate tarball name.
func cargoCrateFilename(name string, ve manifest.VersionEntry) string {
	return name + "-" + ve.Version + ".crate"
}

// cargoLocalDir returns the local directory where a crate version is stored.
func cargoLocalDir(d dirs, name string, ve manifest.VersionEntry) string {
	return filepath.Join(d.cargo, name, ve.Version)
}

// cargoCratePath returns the local path for a downloaded .crate tarball.
func cargoCratePath(d dirs, name string, ve manifest.VersionEntry) string {
	return filepath.Join(cargoLocalDir(d, name, ve), cargoCrateFilename(name, ve))
}

// cargoS3Prefix returns the S3 key prefix for a cargo crate.
func cargoS3Prefix(name string) string {
	return "cargo/crates/"
}

// CheckCargoStage inspects the local filesystem for a fetched crate tarball.
func CheckCargoStage(cfg *Config, name string, ve manifest.VersionEntry) StageStatus {
	d := buildDirs(cfg.rootFor(manifest.TypeCargo))
	if fileExists(cargoCratePath(d, name, ve)) {
		return StageStatus{Fetched: true, Built: true, Packaged: true}
	}
	return StageStatus{}
}

// FetchCargo downloads .crate tarballs for each cargo manifest version.
//
// Cargo's sparse registry exposes downloads at <registry>/<crate>/<version>/download.
// Each .crate tarball is content-addressed by version, so we record the
// computed sha256 on first fetch and verify against any pre-declared checksum.
func FetchCargo(cfg *Config, store *manifest.Store, entryFilter string) *Summary {
	ctx := context.Background()
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypeCargo))

	for _, name := range store.ListPackages(manifest.TypeCargo) {
		if entryFilter != "" && name != entryFilter {
			continue
		}

		pm, err := store.GetPackage(ctx, manifest.TypeCargo, name)
		if err != nil || pm == nil {
			cfg.logf("  [cargo] %s: ERROR loading package: %v", name, err)
			continue
		}

		for _, ve := range pm.Versions {
			if ve.Frozen {
				cfg.logf("  [cargo] %s: SKIPPED (frozen)", name)
				continue
			}
			if err := cfg.EnforcePolicy(ctx, manifest.TypeCargo, name, ve.Version, ve.URL); err != nil {
				cfg.logf("  [cargo] %s: BLOCKED by policy: %v", name, err)
				summary.Failures++
				summary.Results = append(summary.Results, Result{Type: manifest.TypeCargo, Name: name, Err: err})
				continue
			}
			if !cfg.Force {
				if CheckCargoStage(cfg, name, ve).Fetched {
					cfg.logf("  [cargo] %s@%s: already fetched, skipping", pm.Name, ve.Version)
					continue
				}
			}

			result := Result{Type: manifest.TypeCargo, Name: name}
			start := time.Now()
			out := cfg.entryWriter(manifest.TypeCargo, name)

			registry := strings.TrimRight(ve.URL, "/")
			if registry == "" {
				registry = defaultCargoRegistry
			}

			if err := mkdirAll(cargoLocalDir(d, name, ve)); err != nil {
				result.Err = err
				result.Elapsed = time.Since(start)
				summary.Results = append(summary.Results, result)
				summary.Total++
				summary.Failures++
				continue
			}

			url := registry + "/" + pm.Name + "/" + ve.Version + "/download"
			dest := cargoCratePath(d, name, ve)

			_, _ = fmt.Fprintf(out, "  [cargo] %s@%s: fetching %s\n", pm.Name, ve.Version, url)
			if err := downloadURL(dest, url); err != nil {
				_, _ = fmt.Fprintf(out, "  [cargo] %s: ERROR: %v\n", name, err)
				result.Err = err
			} else {
				result.Artifacts = append(result.Artifacts, dest)

				computed, csErr := computeFileSHA256(dest)
				if csErr != nil {
					_, _ = fmt.Fprintf(out, "  [cargo] %s: WARNING: could not compute checksum: %v\n", name, csErr)
				} else if ve.Checksum != nil {
					if vErr := verifyChecksum(ve.Checksum, computed); vErr != nil {
						_, _ = fmt.Fprintf(out, "  [cargo] %s: CHECKSUM MISMATCH: %v\n", name, vErr)
						result.Err = fmt.Errorf("checksum verification failed: %w", vErr)
					} else {
						_, _ = fmt.Fprintf(out, "  [cargo] %s@%s: checksum verified\n", pm.Name, ve.Version)
						if !ve.ChecksumVerified {
							if e := cfg.findAndUpdateCargoChecksum(store, name, ve, ve.Checksum, true); e != nil {
								_, _ = fmt.Fprintf(out, "  [cargo] %s: WARNING: could not save verified status: %v\n", name, e)
							}
						}
					}
				} else if computed != "" {
					cs := newSHA256Checksum(computed)
					_, _ = fmt.Fprintf(out, "  [cargo] %s@%s: checksum recorded (sha256:%s...)\n", pm.Name, ve.Version, computed[:12])
					if e := cfg.findAndUpdateCargoChecksum(store, name, ve, cs, false); e != nil {
						_, _ = fmt.Fprintf(out, "  [cargo] %s: WARNING: could not save checksum: %v\n", name, e)
					}
				}

				if result.Err == nil {
					_, _ = fmt.Fprintf(out, "  [cargo] %s@%s: ok\n", pm.Name, ve.Version)
					cfg.StampCargoEntry(store, name, ve)
					stampArtifactSize(context.Background(), store, manifest.TypeCargo, name, ve, dest)
				}
			}

			result.Elapsed = time.Since(start)
			summary.Results = append(summary.Results, result)
			summary.Total++
			if result.Err != nil {
				summary.Failures++
			}
			status := "success"
			if result.Err != nil {
				status = "failure"
			}
			cfg.RecordAudit(audit.EventFetch, manifest.TypeCargo, name, ve.Version, status, result.Elapsed, result.Err)
		}
	}

	return summary
}

// CargoArtifactPaths returns local/S3 path pairs ready for upload.
func CargoArtifactPaths(cfg *Config, store *manifest.Store, entryFilter string) []ArtifactPath {
	ctx := context.Background()
	d := buildDirs(cfg.rootFor(manifest.TypeCargo))
	var paths []ArtifactPath

	for _, name := range store.ListPackages(manifest.TypeCargo) {
		if entryFilter != "" && name != entryFilter {
			continue
		}
		pm, err := store.GetPackage(ctx, manifest.TypeCargo, name)
		if err != nil || pm == nil {
			continue
		}
		for _, ve := range pm.Versions {
			local := cargoCratePath(d, name, ve)
			if !fileExists(local) {
				continue
			}
			paths = append(paths, ArtifactPath{
				Local: local,
				S3Key: cargoS3Prefix(name) + cargoCrateFilename(pm.Name, ve),
			})
		}
	}
	return paths
}
