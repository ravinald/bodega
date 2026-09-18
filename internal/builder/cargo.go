package builder

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// defaultCargoDownloadRoot is where crate tarballs come from when no config
// supplies one. crates.io serves the sparse index and the tarballs from
// separate hosts, and the index host answers a /download path with 404.
const defaultCargoDownloadRoot = "https://static.crates.io/crates"

// cargoDownloadURL composes where a crate tarball is fetched from. The entry's
// own URL wins as the per-entry override it has always been; otherwise the
// configured download root, never the sparse index root.
func cargoDownloadURL(cfg *Config, name string, ve manifest.VersionEntry) string {
	root := strings.TrimRight(ve.URL, "/")
	if root == "" {
		root = strings.TrimRight(cfg.CargoDLUpstream, "/")
	}
	if root == "" {
		root = defaultCargoDownloadRoot
	}
	return root + "/" + name + "/" + ve.Version + "/download"
}

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

// defaultCargoIndex is the sparse index consulted for a crate's dependency
// record when no config names one.
const defaultCargoIndex = "https://index.crates.io"

// cargoIndexMaxBytes caps an index document. One line per published version,
// and the widest crates on crates.io run to a few hundred kilobytes.
const cargoIndexMaxBytes = 8 * 1024 * 1024

// cargoIndexPath is the sparse-index path cargo resolves a crate through. The
// four shapes are the protocol's, keyed on name length, and the server's
// cargoCrateFromIndexPath parses exactly these back.
func cargoIndexPath(crate string) string {
	switch n := len(crate); {
	case n == 0:
		return ""
	case n <= 2:
		return strconv.Itoa(n) + "/" + crate
	case n == 3:
		return "3/" + crate[:1] + "/" + crate
	default:
		return crate[:2] + "/" + crate[2:4] + "/" + crate
	}
}

// cargoIndexDeps fetches the upstream sparse-index document for a crate and
// returns the dependencies its line for version declares.
//
// The index rather than Cargo.toml inside the .crate. A registry dependency
// carries name, req, features, optional, default_features, target and kind,
// and Cargo.toml's workspace inheritance, path dependencies and git
// dependencies do not map onto any of that — the registry resolved them when
// the crate was published, and the index line is where that resolution is
// recorded.
//
// Nothing found for the version returns no dependencies and no error: the
// download root an entry names may be a private mirror the public index knows
// nothing about, and a crate whose bytes fetched cleanly is not a failed fetch
// because a second host had no opinion about it.
func cargoIndexDeps(cfg *Config, crate, version string) ([]manifest.Dependency, error) {
	root := strings.TrimRight(cfg.CargoUpstream, "/")
	if root == "" {
		root = defaultCargoIndex
	}
	p := cargoIndexPath(crate)
	if p == "" {
		return nil, nil
	}
	url := root + "/" + p

	resp, err := http.Get(url) //nolint:gosec // the host is operator-configured, the path is the crate name
	if err != nil {
		return nil, fmt.Errorf("fetch cargo index %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch cargo index %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, cargoIndexMaxBytes))
	if err != nil {
		return nil, fmt.Errorf("read cargo index %s: %w", url, err)
	}

	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var doc struct {
			Vers string `json:"vers"`
			Deps []struct {
				Name            string   `json:"name"`
				Req             string   `json:"req"`
				Features        []string `json:"features"`
				Optional        bool     `json:"optional"`
				DefaultFeatures bool     `json:"default_features"`
				Target          *string  `json:"target"`
				Kind            string   `json:"kind"`
			} `json:"deps"`
		}
		if err := json.Unmarshal([]byte(line), &doc); err != nil {
			return nil, fmt.Errorf("parse cargo index %s: %w", url, err)
		}
		if doc.Vers != version {
			continue
		}
		out := make([]manifest.Dependency, 0, len(doc.Deps))
		for _, d := range doc.Deps {
			dep := manifest.Dependency{
				Name:            d.Name,
				Req:             d.Req,
				Features:        d.Features,
				Optional:        d.Optional,
				DefaultFeatures: d.DefaultFeatures,
				Kind:            d.Kind,
			}
			if d.Target != nil {
				dep.Target = *d.Target
			}
			out = append(out, dep)
		}
		return out, nil
	}
	return nil, nil
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
					if err := cfg.verifyFetched(ctx, store, manifest.TypeCargo, name, ve); err != nil {
						cfg.logf("  [cargo] %s@%s: %v", pm.Name, ve.Version, err)
						summary.Failures++
						summary.Results = append(summary.Results, Result{Type: manifest.TypeCargo, Name: name, Err: err})
					}
					continue
				}
			}

			result := Result{Type: manifest.TypeCargo, Name: name}
			start := time.Now()
			out := cfg.entryWriter(manifest.TypeCargo, name)

			if err := mkdirAll(cargoLocalDir(d, name, ve)); err != nil {
				result.Err = err
				result.Elapsed = time.Since(start)
				summary.Results = append(summary.Results, result)
				summary.Total++
				summary.Failures++
				continue
			}

			url := cargoDownloadURL(cfg, pm.Name, ve)
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

				// The dependency record comes from the index rather than the
				// crate, so a failure here is a second host being unreachable
				// and not a bad artifact. The fetch stands and the line says
				// so: without it the index bodega publishes silently declares
				// the crate needs nothing, which is the failure this replaces.
				var deps []manifest.Dependency
				if result.Err == nil {
					d, dErr := cargoIndexDeps(cfg, pm.Name, ve.Version)
					switch {
					case dErr != nil:
						_, _ = fmt.Fprintf(out, "  [cargo] %s@%s: WARNING: no dependency record: %v\n", pm.Name, ve.Version, dErr)
					case len(d) > 0:
						deps = d
						_, _ = fmt.Fprintf(out, "  [cargo] %s@%s: recorded %d dependencies\n", pm.Name, ve.Version, len(d))
					default:
						_, _ = fmt.Fprintf(out, "  [cargo] %s@%s: the index names no dependencies\n", pm.Name, ve.Version)
					}
				}

				if result.Err == nil {
					_, _ = fmt.Fprintf(out, "  [cargo] %s@%s: ok\n", pm.Name, ve.Version)
					cfg.StampCargoEntry(store, name, ve)
					stampFetchRecord(context.Background(), store, manifest.TypeCargo, name, ve, dest, computed, deps)
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
				Local:     local,
				ObjectKey: manifest.CargoCrateKey(pm.Name, ve.Version),
				Package:   name,
				Version:   ve.Version,
			})
		}
	}
	return paths
}
