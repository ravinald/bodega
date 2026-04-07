package builder

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/manifest"
)

const defaultNpmRegistry = "https://registry.npmjs.org"

// npmTarballFilename returns the conventional npm tarball name.
func npmTarballFilename(entry manifest.NpmEntry) string {
	name := entry.Name
	// Scoped packages: @scope/pkg → pkg-version.tgz
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		name = name[idx+1:]
	}
	return name + "-" + entry.Version + ".tgz"
}

// npmLocalDir returns the local directory for an npm package.
func npmLocalDir(d dirs, entry manifest.NpmEntry) string {
	return filepath.Join(d.npm, entry.Name)
}

// npmTarballPath returns the local path for an npm tarball.
func npmTarballPath(d dirs, entry manifest.NpmEntry) string {
	return filepath.Join(npmLocalDir(d, entry), npmTarballFilename(entry))
}

// npmS3Prefix returns the S3 key prefix for an npm package.
func npmS3Prefix(entry manifest.NpmEntry) string {
	return "npm/" + entry.Name + "/"
}

// CheckNpmStage inspects the local filesystem for a fetched npm tarball.
func CheckNpmStage(cfg *Config, entry manifest.NpmEntry) StageStatus {
	d := buildDirs(cfg.rootFor(manifest.TypeNpm))
	path := npmTarballPath(d, entry)
	if fileExists(path) {
		return StageStatus{Fetched: true, Built: true, Packaged: true}
	}
	return StageStatus{}
}

// FetchNpm downloads npm tarballs for each NpmEntry.
func FetchNpm(cfg *Config, store *manifest.Store, entryFilter string) *Summary {
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypeNpm))

	for _, entry := range store.Npm {
		if entryFilter != "" && entry.Name != entryFilter {
			continue
		}
		if entry.Frozen {
			cfg.logf("  [npm] %s: SKIPPED (frozen)", entry.Name)
			continue
		}

		result := Result{Type: manifest.TypeNpm, Name: entry.Name}
		start := time.Now()
		out := cfg.entryWriter(manifest.TypeNpm, entry.Name)

		dir := npmLocalDir(d, entry)
		if err := mkdirAll(dir); err != nil {
			result.Err = err
			result.Elapsed = time.Since(start)
			summary.Results = append(summary.Results, result)
			summary.Total++
			summary.Failures++
			continue
		}

		registry := entry.URL
		if registry == "" {
			registry = defaultNpmRegistry
		}

		// npm tarball URL format: {registry}/{name}/-/{tarball}
		tarballName := npmTarballFilename(entry)
		url := registry + "/" + entry.Name + "/-/" + tarballName
		dest := npmTarballPath(d, entry)

		_, _ = fmt.Fprintf(out, "  [npm] %s@%s: fetching %s\n", entry.Name, entry.Version, url)

		if err := downloadURL(dest, url); err != nil {
			_, _ = fmt.Fprintf(out, "  [npm] %s: ERROR: %v\n", entry.Name, err)
			result.Err = err
		} else {
			result.Artifacts = append(result.Artifacts, dest)

			// Checksum verification.
			computed, err := computeFileSHA256(dest)
			if err != nil {
				_, _ = fmt.Fprintf(out, "  [npm] %s: WARNING: could not compute checksum: %v\n", entry.Name, err)
			} else if entry.Checksum != nil {
				if err := verifyChecksum(entry.Checksum, computed); err != nil {
					_, _ = fmt.Fprintf(out, "  [npm] %s: CHECKSUM MISMATCH: %v\n", entry.Name, err)
					result.Err = fmt.Errorf("checksum verification failed: %w", err)
				} else {
					_, _ = fmt.Fprintf(out, "  [npm] %s@%s: checksum verified\n", entry.Name, entry.Version)
				}
			} else if computed != "" {
				entry.Checksum = newSHA256Checksum(computed)
				_, _ = fmt.Fprintf(out, "  [npm] %s@%s: checksum recorded (sha256:%s...)\n", entry.Name, entry.Version, computed[:12])
				if e := cfg.findAndUpdateNpmChecksum(store, entry.Name, entry.Checksum); e != nil {
					_, _ = fmt.Fprintf(out, "  [npm] %s: WARNING: could not save checksum: %v\n", entry.Name, e)
				}
			}

			if result.Err == nil {
				_, _ = fmt.Fprintf(out, "  [npm] %s@%s: ok\n", entry.Name, entry.Version)
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

// PackageNpm generates packument JSON files for each npm package by reading
// package.json from the tarballs. The packument is pre-computed and cached
// in S3 so the server can serve it without per-request tarball extraction.
func PackageNpm(cfg *Config, store *manifest.Store) *Summary {
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypeNpm))
	out := cfg.stdout()

	// Group entries by package name.
	byName := make(map[string][]manifest.NpmEntry)
	for _, entry := range store.Npm {
		byName[entry.Name] = append(byName[entry.Name], entry)
	}

	for name, entries := range byName {
		_, _ = fmt.Fprintf(out, "  [npm] %s: generating packument\n", name)

		packument := buildPackument(name, entries, d)

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
	d := buildDirs(cfg.rootFor(manifest.TypeNpm))
	var paths []ArtifactPath

	seen := make(map[string]bool)
	for _, entry := range store.Npm {
		if entryFilter != "" && entry.Name != entryFilter {
			continue
		}

		// Tarball.
		local := npmTarballPath(d, entry)
		if fileExists(local) {
			paths = append(paths, ArtifactPath{
				Local: local,
				S3Key: npmS3Prefix(entry) + npmTarballFilename(entry),
			})
		}

		// Packument (once per package name).
		if !seen[entry.Name] {
			seen[entry.Name] = true
			packumentPath := filepath.Join(npmLocalDir(d, entry), "packument.json")
			if fileExists(packumentPath) {
				paths = append(paths, ArtifactPath{
					Local: packumentPath,
					S3Key: npmS3Prefix(entry) + "packument.json",
				})
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

// buildPackument creates a packument from manifest entries and local tarballs.
func buildPackument(name string, entries []manifest.NpmEntry, d dirs) packument {
	p := packument{
		Name:     name,
		DistTags: make(map[string]string),
		Versions: make(map[string]packumentEntry),
	}

	var latestVersion string
	for _, entry := range entries {
		tarballName := npmTarballFilename(entry)
		tarballPath := filepath.Join(d.npm, entry.Name, tarballName)

		pe := packumentEntry{
			Name:    entry.Name,
			Version: entry.Version,
			Dist: packumentDist{
				// Relative URL — the server's base URL is prepended by clients.
				Tarball: entry.Name + "/-/" + tarballName,
			},
		}

		// Try to read main field from package.json inside tarball.
		if meta := readPackageJSON(tarballPath); meta != nil {
			if m, ok := meta["main"].(string); ok {
				pe.Main = m
			}
		}

		p.Versions[entry.Version] = pe
		latestVersion = entry.Version
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
