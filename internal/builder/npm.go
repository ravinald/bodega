package builder

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

const defaultNpmRegistry = "https://registry.npmjs.org"

// npmPackumentMaxBytes caps packument downloads. Popular packages like
// react-native or @types/node have packuments in the multi-MB range.
const npmPackumentMaxBytes = 32 * 1024 * 1024

// isNpmDistTag reports whether v is a dist-tag rather than a concrete version.
// We treat empty as "latest" by convention.
func isNpmDistTag(v string) bool {
	return v == "" || v == "latest"
}

// resolveNpmDistTag fetches the packument for pkgName from registry and
// returns the concrete version that the named dist-tag points at.
func resolveNpmDistTag(registry, pkgName, tag string) (string, error) {
	url := registry + "/" + pkgName
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return "", fmt.Errorf("fetch packument %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch packument %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, npmPackumentMaxBytes))
	if err != nil {
		return "", fmt.Errorf("read packument %s: %w", url, err)
	}
	var doc struct {
		DistTags map[string]string `json:"dist-tags"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("parse packument: %w", err)
	}
	v, ok := doc.DistTags[tag]
	if !ok || v == "" {
		return "", fmt.Errorf("dist-tag %q not present in packument", tag)
	}
	return v, nil
}

// npmTarballFilename returns the conventional npm tarball name.
func npmTarballFilename(name string, ve manifest.VersionEntry) string {
	// Scoped packages: @scope/pkg → pkg-version.tgz
	n := name
	if idx := strings.LastIndex(n, "/"); idx >= 0 {
		n = n[idx+1:]
	}
	return n + "-" + ve.Version + ".tgz"
}

// npmLocalDir returns the local directory for an npm package version.
func npmLocalDir(d dirs, name string, ve manifest.VersionEntry) string {
	return filepath.Join(d.npm, name, ve.Version)
}

// npmTarballPath returns the local path for an npm tarball.
func npmTarballPath(d dirs, name string, ve manifest.VersionEntry) string {
	return filepath.Join(npmLocalDir(d, name, ve), npmTarballFilename(name, ve))
}

// CheckNpmStage inspects the local filesystem for a fetched npm tarball.
func CheckNpmStage(cfg *Config, name string, ve manifest.VersionEntry) StageStatus {
	d := buildDirs(cfg.rootFor(manifest.TypeNpm))
	path := npmTarballPath(d, name, ve)
	if fileExists(path) {
		return StageStatus{Fetched: true, Built: true, Packaged: true}
	}
	return StageStatus{}
}

// FetchNpm downloads npm tarballs for each npm package version.
func FetchNpm(cfg *Config, store *manifest.Store, entryFilter string) *Summary {
	ctx := context.Background()
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypeNpm))

	for _, name := range store.ListPackages(manifest.TypeNpm) {
		if entryFilter != "" && name != entryFilter {
			continue
		}

		pm, err := store.GetPackage(ctx, manifest.TypeNpm, name)
		if err != nil || pm == nil {
			cfg.logf("  [npm] %s: ERROR loading package: %v", name, err)
			continue
		}

		for _, ve := range pm.Versions {
			if ve.Frozen {
				cfg.logf("  [npm] %s: SKIPPED (frozen)", name)
				continue
			}
			if err := cfg.EnforcePolicy(ctx, manifest.TypeNpm, name, ve.Version, ve.URL); err != nil {
				cfg.logf("  [npm] %s: BLOCKED by policy: %v", name, err)
				summary.Failures++
				summary.Results = append(summary.Results, Result{Type: manifest.TypeNpm, Name: name, Err: err})
				continue
			}
			if !cfg.Force {
				stage := CheckNpmStage(cfg, name, ve)
				if stage.Fetched {
					cfg.logf("  [npm] %s: already fetched, skipping", name)
					if err := cfg.verifyFetched(ctx, store, manifest.TypeNpm, name, ve); err != nil {
						cfg.logf("  [npm] %s: %v", name, err)
						summary.Failures++
						summary.Results = append(summary.Results, Result{Type: manifest.TypeNpm, Name: name, Err: err})
					}
					continue
				}
			}

			result := Result{Type: manifest.TypeNpm, Name: name}
			start := time.Now()
			out := cfg.entryWriter(manifest.TypeNpm, name)

			registry := ve.URL
			if registry == "" {
				registry = defaultNpmRegistry
			}

			// Resolve dist-tags (e.g. "latest") to a concrete version via the
			// packument. fetchVe is the version we actually download; ve is the
			// manifest entry, which we leave alone so the dist-tag stays as a
			// floating ref for future fetches.
			fetchVe := ve
			distTag := ""
			if isNpmDistTag(ve.Version) {
				distTag = ve.Version
				if distTag == "" {
					distTag = "latest"
				}
				resolved, err := resolveNpmDistTag(registry, pm.Name, distTag)
				if err != nil {
					_, _ = fmt.Fprintf(out, "  [npm] %s: ERROR resolving dist-tag %q: %v\n", pm.Name, distTag, err)
					result.Err = err
					result.Elapsed = time.Since(start)
					summary.Results = append(summary.Results, result)
					summary.Total++
					summary.Failures++
					cfg.RecordAudit(audit.EventFetch, manifest.TypeNpm, name, ve.Version, "failure", result.Elapsed, result.Err)
					continue
				}
				_, _ = fmt.Fprintf(out, "  [npm] %s: dist-tag %q → %s\n", pm.Name, distTag, resolved)
				fetchVe.Version = resolved
			}

			dir := npmLocalDir(d, name, fetchVe)
			if err := mkdirAll(dir); err != nil {
				result.Err = err
				result.Elapsed = time.Since(start)
				summary.Results = append(summary.Results, result)
				summary.Total++
				summary.Failures++
				continue
			}

			// Use pm.Name (canonical, with slashes for scoped packages) for the
			// upstream URL. The `name` from ListPackages is safe-encoded
			// (@scope/pkg → @scope--pkg) and is only valid as a local path/key.
			upstreamName := pm.Name
			tarballName := npmTarballFilename(upstreamName, fetchVe)
			url := registry + "/" + upstreamName + "/-/" + tarballName
			dest := npmTarballPath(d, name, fetchVe)

			_, _ = fmt.Fprintf(out, "  [npm] %s@%s: fetching %s\n", pm.Name, fetchVe.Version, url)

			if err := downloadURL(dest, url); err != nil {
				_, _ = fmt.Fprintf(out, "  [npm] %s: ERROR: %v\n", name, err)
				result.Err = err
			} else {
				result.Artifacts = append(result.Artifacts, dest)

				computed, err := computeFileSHA256(dest)
				if err != nil {
					_, _ = fmt.Fprintf(out, "  [npm] %s: WARNING: could not compute checksum: %v\n", name, err)
				} else if distTag != "" {
					// A floating dist-tag cannot carry a digest on its manifest
					// entry: the entry stays on the tag, so a value written there
					// would refuse the next legitimate release as a mismatch. The
					// pin goes on the resolved version's own object key instead,
					// which is the key the server serves those bytes under. Every
					// concrete version the tag has resolved to is on record, and a
					// later resolution to the same version is checked against it.
					if e := cfg.pinChecksum(ctx, pm, fetchVe, newSHA256Checksum(computed)); e != nil {
						_, _ = fmt.Fprintf(out, "  [npm] %s: CHECKSUM REFUSED: %v\n", name, e)
						result.Err = fmt.Errorf("checksum verification failed: %w", e)
					} else {
						_, _ = fmt.Fprintf(out, "  [npm] %s@%s: checksum pinned to the resolved version (dist-tag %q is floating, sha256:%s...)\n", pm.Name, fetchVe.Version, distTag, computed[:12])
					}
				} else if ve.Checksum != nil {
					if err := verifyChecksum(ve.Checksum, computed); err != nil {
						_, _ = fmt.Fprintf(out, "  [npm] %s: CHECKSUM MISMATCH: %v\n", name, err)
						result.Err = fmt.Errorf("checksum verification failed: %w", err)
					} else {
						_, _ = fmt.Fprintf(out, "  [npm] %s@%s: checksum verified\n", pm.Name, fetchVe.Version)
						if !ve.ChecksumVerified {
							if e := cfg.findAndUpdateNpmChecksum(store, name, ve, ve.Checksum, true); e != nil {
								_, _ = fmt.Fprintf(out, "  [npm] %s: WARNING: could not save verified status: %v\n", name, e)
							}
						}
					}
				} else if computed != "" {
					cs := newSHA256Checksum(computed)
					_, _ = fmt.Fprintf(out, "  [npm] %s@%s: checksum recorded (sha256:%s...)\n", pm.Name, fetchVe.Version, computed[:12])
					if e := cfg.findAndUpdateNpmChecksum(store, name, ve, cs, false); e != nil {
						_, _ = fmt.Fprintf(out, "  [npm] %s: WARNING: could not save checksum: %v\n", name, e)
					}
				}

				if result.Err == nil {
					_, _ = fmt.Fprintf(out, "  [npm] %s@%s: ok\n", pm.Name, fetchVe.Version)
					cfg.StampNpmEntry(store, name, ve)
					stampArtifactSize(context.Background(), store, manifest.TypeNpm, name, ve, dest)
				}
			}

			result.Elapsed = time.Since(start)
			summary.Results = append(summary.Results, result)
			summary.Total++
			if result.Err != nil {
				summary.Failures++
			}
			nStatus := "success"
			if result.Err != nil {
				nStatus = "failure"
			}
			cfg.RecordAudit(audit.EventFetch, manifest.TypeNpm, name, ve.Version, nStatus, result.Elapsed, result.Err)
		}
	}

	return summary
}

// NpmArtifactPaths returns local/S3 path pairs for upload.
func NpmArtifactPaths(cfg *Config, store *manifest.Store, entryFilter string) []ArtifactPath {
	ctx := context.Background()
	d := buildDirs(cfg.rootFor(manifest.TypeNpm))
	var paths []ArtifactPath

	for _, name := range store.ListPackages(manifest.TypeNpm) {
		if entryFilter != "" && name != entryFilter {
			continue
		}

		pm, err := store.GetPackage(ctx, manifest.TypeNpm, name)
		if err != nil || pm == nil {
			continue
		}

		for _, ve := range pm.Versions {
			local := npmTarballPath(d, name, ve)
			if fileExists(local) {
				paths = append(paths, ArtifactPath{
					Local:     local,
					ObjectKey: manifest.NpmTarballKey(pm.Name, ve.Version),
					Package:   name,
					Version:   ve.Version,
				})
			}
		}
	}

	return paths
}
