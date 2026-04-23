package builder

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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

// npmS3Prefix returns the S3 key prefix for an npm package.
func npmS3Prefix(name string) string {
	return "npm/" + name + "/"
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

				// Checksum verification — skipped for floating dist-tags since the
				// resolved version (and therefore the hash) changes upstream over time.
				computed, err := computeFileSHA256(dest)
				if err != nil {
					_, _ = fmt.Fprintf(out, "  [npm] %s: WARNING: could not compute checksum: %v\n", name, err)
				} else if distTag != "" {
					_, _ = fmt.Fprintf(out, "  [npm] %s@%s: checksum recorded for this fetch only (dist-tag %q is floating, sha256:%s...)\n", pm.Name, fetchVe.Version, distTag, computed[:12])
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

// npmVersionEntry pairs a package name with its VersionEntry for packument building.
type npmVersionEntry struct {
	name string
	ve   manifest.VersionEntry
}

// PackageNpm generates packument JSON files for each npm package by reading
// package.json from the tarballs. The packument is pre-computed and cached
// in S3 so the server can serve it without per-request tarball extraction.
func PackageNpm(cfg *Config, store *manifest.Store) *Summary {
	ctx := context.Background()
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypeNpm))
	out := cfg.stdout()

	for _, name := range store.ListPackages(manifest.TypeNpm) {
		pm, err := store.GetPackage(ctx, manifest.TypeNpm, name)
		if err != nil || pm == nil {
			continue
		}

		_, _ = fmt.Fprintf(out, "  [npm] %s: generating packument\n", pm.Name)

		// pm.Name is the canonical name (e.g. "@bitwarden/cli"); `name` from the
		// index is safe-encoded (e.g. "@bitwarden--cli") and unfit for the
		// packument that clients consume.
		var entries []npmVersionEntry
		for _, ve := range pm.Versions {
			entries = append(entries, npmVersionEntry{name: pm.Name, ve: ve})
		}

		packument := buildPackument(pm.Name, entries, d)

		dir := filepath.Join(d.npm, name)
		if err := mkdirAll(dir); err != nil {
			cfg.logf("ERROR creating dir %s: %v", dir, err)
			summary.Failures++
			summary.Total++
			continue
		}

		path := filepath.Join(dir, "packument.json")
		data, err := json.MarshalIndent(packument, "", "  ")
		if err != nil {
			cfg.logf("ERROR marshaling packument for %s: %v", name, err)
			summary.Failures++
			summary.Total++
			continue
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			cfg.logf("ERROR writing packument for %s: %v", name, err)
			summary.Failures++
			summary.Total++
			continue
		}

		summary.Total++
		_, _ = fmt.Fprintf(out, "  [npm] %s: packument written (%d version(s))\n", name, len(entries))
	}

	return summary
}

// NpmArtifactPaths returns local/S3 path pairs for upload.
func NpmArtifactPaths(cfg *Config, store *manifest.Store, entryFilter string) []ArtifactPath {
	ctx := context.Background()
	d := buildDirs(cfg.rootFor(manifest.TypeNpm))
	var paths []ArtifactPath

	seen := make(map[string]bool)
	for _, name := range store.ListPackages(manifest.TypeNpm) {
		if entryFilter != "" && name != entryFilter {
			continue
		}

		pm, err := store.GetPackage(ctx, manifest.TypeNpm, name)
		if err != nil || pm == nil {
			continue
		}

		for _, ve := range pm.Versions {
			// Tarball.
			local := npmTarballPath(d, name, ve)
			if fileExists(local) {
				paths = append(paths, ArtifactPath{
					Local: local,
					S3Key: npmS3Prefix(name) + npmTarballFilename(name, ve),
				})
			}

			// Packument (once per package name).
			if !seen[name] {
				seen[name] = true
				packumentPath := filepath.Join(npmLocalDir(d, name, ve), "packument.json")
				if fileExists(packumentPath) {
					paths = append(paths, ArtifactPath{
						Local: packumentPath,
						S3Key: npmS3Prefix(name) + "packument.json",
					})
				}
			}
		}
	}

	return paths
}

// packument is the npm registry metadata document.
type packument struct {
	Name     string                    `json:"name"`
	DistTags map[string]string         `json:"dist-tags"`
	Versions map[string]packumentEntry `json:"versions"`
}

type packumentEntry struct {
	Name    string          `json:"name"`
	Version string          `json:"version"`
	Dist    packumentDist   `json:"dist"`
	Main    string          `json:"main,omitempty"`
	Extra   json.RawMessage `json:"-"` // unused, for future expansion
}

type packumentDist struct {
	Tarball string `json:"tarball"`
}

// buildPackument creates a packument from version entries and local tarballs.
func buildPackument(name string, entries []npmVersionEntry, d dirs) packument {
	p := packument{
		Name:     name,
		DistTags: make(map[string]string),
		Versions: make(map[string]packumentEntry),
	}

	var latestVersion string
	for _, nve := range entries {
		tarballName := npmTarballFilename(nve.name, nve.ve)
		tarballPath := filepath.Join(d.npm, nve.name, tarballName)

		pe := packumentEntry{
			Name:    nve.name,
			Version: nve.ve.Version,
			Dist: packumentDist{
				// Relative URL — the server's base URL is prepended by clients.
				Tarball: nve.name + "/-/" + tarballName,
			},
		}

		// Try to read main field from package.json inside tarball.
		if meta := readPackageJSON(tarballPath); meta != nil {
			if m, ok := meta["main"].(string); ok {
				pe.Main = m
			}
		}

		p.Versions[nve.ve.Version] = pe
		latestVersion = nve.ve.Version
	}

	if latestVersion != "" {
		p.DistTags["latest"] = latestVersion
	}

	return p
}

// readPackageJSON extracts and parses package.json from an npm tarball.
// Returns nil on any error (best-effort).
func readPackageJSON(tarballPath string) map[string]interface{} {
	f, err := os.Open(tarballPath)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err != nil {
			return nil
		}
		// npm tarballs have package/package.json at the root.
		base := filepath.Base(hdr.Name)
		if base == "package.json" && strings.Count(hdr.Name, "/") <= 1 {
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil
			}
			var meta map[string]interface{}
			if err := json.Unmarshal(data, &meta); err != nil {
				return nil
			}
			return meta
		}
	}
}
