package builder

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// rubygemsDownloadURL composes where a gem file is fetched from:
// <registry>/gems/<name>-<version>.gem, the path the server's /rubygems/gems/
// route proxies. The entry's own URL is a registry root and wins over
// rubygems_upstream.
func rubygemsDownloadURL(cfg *Config, name string, ve manifest.VersionEntry) string {
	root := strings.TrimRight(ve.URL, "/")
	if root == "" {
		root = strings.TrimRight(cfg.RubygemsUpstream, "/")
	}
	if root == "" {
		root = config.DefaultRubygemsUpstream
	}
	return root + "/gems/" + name + "-" + ve.Version + ".gem"
}

// rubygemsGemPath returns where a gem version is kept locally:
// <root>/rubygems/<name>/<version>/<name>-<version>.gem, with a platform
// build's suffix part of the version, as the file name carries it.
//
// "" for a name or version that would not stay inside its directory. A gem
// name holds no separator, so one that does came from somewhere other than a
// registry.
func rubygemsGemPath(d dirs, name string, ve manifest.VersionEntry) string {
	if !filepath.IsLocal(name) || !filepath.IsLocal(ve.Version) ||
		strings.ContainsAny(name+ve.Version, `/\`) {
		return ""
	}
	return filepath.Join(d.rubygems, name, ve.Version, name+"-"+ve.Version+".gem")
}

// RubygemsArtifactPaths returns every gem file under rubygems_root that an
// entry names, keyed where the /rubygems/gems/ route reads it.
func RubygemsArtifactPaths(cfg *Config, store *manifest.Store, entryFilter string) []ArtifactPath {
	ctx := context.Background()
	d := buildDirs(cfg.rootFor(manifest.TypeRubygems))
	var paths []ArtifactPath
	for _, name := range store.ListPackages(manifest.TypeRubygems) {
		if entryFilter != "" && name != entryFilter {
			continue
		}
		pm, err := store.GetPackage(ctx, manifest.TypeRubygems, name)
		if err != nil || pm == nil {
			continue
		}
		for _, ve := range pm.Versions {
			local := rubygemsGemPath(d, pm.Name, ve)
			if local == "" || !fileExists(local) {
				continue
			}
			paths = append(paths, ArtifactPath{
				Local:     local,
				ObjectKey: manifest.RubygemsGemKey(pm.Name, ve.Version),
				Package:   name,
				Version:   ve.Version,
			})
		}
	}
	return paths
}

// CheckRubygemsStage inspects the local filesystem for a fetched gem file.
func CheckRubygemsStage(cfg *Config, name string, ve manifest.VersionEntry) StageStatus {
	d := buildDirs(cfg.rootFor(manifest.TypeRubygems))
	if p := rubygemsGemPath(d, name, ve); p != "" && fileExists(p) {
		return StageStatus{Fetched: true, Built: true, Packaged: true}
	}
	return StageStatus{}
}

// FetchRubygems downloads the .gem file for each rubygems manifest version
// into rubygems_root, where upload reads it and keys it under the object the
// /rubygems/gems/ route serves, so a catalog-mode gem needs no upstream at
// request time.
//
// A gem file never changes under its name, so the sha256 computed on the first
// fetch is recorded on the entry and pinned, and every later fetch is checked
// against it.
func FetchRubygems(cfg *Config, store *manifest.Store, entryFilter string) *Summary {
	ctx := context.Background()
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypeRubygems))

	for _, name := range store.ListPackages(manifest.TypeRubygems) {
		if entryFilter != "" && name != entryFilter {
			continue
		}

		pm, err := store.GetPackage(ctx, manifest.TypeRubygems, name)
		if err != nil || pm == nil {
			cfg.logf("  [rubygems] %s: ERROR loading package: %v", name, err)
			summary.loadFailed(manifest.TypeRubygems, name, err)
			continue
		}

		for _, ve := range pm.Versions {
			if ve.Frozen {
				cfg.logf("  [rubygems] %s: SKIPPED (frozen)", name)
				continue
			}
			if err := cfg.EnforcePolicy(ctx, manifest.TypeRubygems, name, ve); err != nil {
				cfg.logf("  [rubygems] %s: BLOCKED by policy: %v", name, err)
				summary.Failures++
				summary.Results = append(summary.Results, Result{Type: manifest.TypeRubygems, Name: name, Err: err})
				continue
			}
			if !cfg.Force && CheckRubygemsStage(cfg, name, ve).Fetched {
				cfg.logf("  [rubygems] %s@%s: already fetched, skipping", pm.Name, ve.Version)
				if err := cfg.verifyFetched(ctx, store, manifest.TypeRubygems, name, ve); err != nil {
					cfg.logf("  [rubygems] %s@%s: %v", pm.Name, ve.Version, err)
					summary.Failures++
					summary.Results = append(summary.Results, Result{Type: manifest.TypeRubygems, Name: name, Err: err})
				}
				continue
			}

			result := Result{Type: manifest.TypeRubygems, Name: name}
			start := time.Now()
			result.Err = fetchRubygem(ctx, cfg, store, d, pm, name, ve, &result)
			result.Elapsed = time.Since(start)
			summary.Results = append(summary.Results, result)
			summary.Total++
			status := "success"
			if result.Err != nil {
				summary.Failures++
				status = "failure"
			}
			cfg.RecordAudit(audit.EventFetch, manifest.TypeRubygems, name, ve.Version, status, result.Elapsed, result.Err)
		}
	}
	return summary
}

// fetchRubygem downloads one gem version into rubygems_root and records it.
func fetchRubygem(ctx context.Context, cfg *Config, store *manifest.Store, d dirs,
	pm *manifest.PackageManifest, name string, ve manifest.VersionEntry, result *Result) error {
	out := cfg.entryWriter(manifest.TypeRubygems, name)
	dest := rubygemsGemPath(d, pm.Name, ve)
	if dest == "" {
		return fmt.Errorf("rubygems %q@%q: the name or version would leave rubygems_root; a registry never publishes one with a path separator", pm.Name, ve.Version)
	}
	if err := mkdirAll(filepath.Dir(dest)); err != nil {
		return err
	}

	url := rubygemsDownloadURL(cfg, pm.Name, ve)
	_, _ = fmt.Fprintf(out, "  [rubygems] %s@%s: fetching %s\n", pm.Name, ve.Version, url)
	err := downloadURL(dest, url)
	if err == nil {
		err = recordRubygem(ctx, cfg, store, out, pm, name, ve, dest)
	}
	if err != nil {
		// Upload reads whatever sits at dest, so refused bytes may not stay
		// there for the next upload to publish under the gem's name.
		_ = os.Remove(dest)
		_, _ = fmt.Fprintf(out, "  [rubygems] %s: ERROR: %v\n", name, err)
		return err
	}
	result.Artifacts = append(result.Artifacts, dest)
	_, _ = fmt.Fprintf(out, "  [rubygems] %s@%s: ok\n", pm.Name, ve.Version)
	return nil
}

// recordRubygem checks a downloaded gem against any digest the entry already
// declares, then records the digest, size and platform it measured.
func recordRubygem(ctx context.Context, cfg *Config, store *manifest.Store, out io.Writer,
	pm *manifest.PackageManifest, name string, ve manifest.VersionEntry, dest string) error {
	computed, err := computeFileSHA256(dest)
	if err != nil {
		return fmt.Errorf("compute the sha256 of %s: %w", dest, err)
	}
	// Checked before anything is written: updateVersionChecksum saves the
	// entry and only then enforces the pin, which would leave a refused digest
	// on the entry for the next fetch to "verify" against.
	if cfg.AuditDB != nil {
		key := manifest.RubygemsGemKey(pm.Name, ve.Version)
		prior, err := cfg.AuditDB.GetChecksum(ctx, key)
		if err != nil {
			return fmt.Errorf("read pinned checksum for %s: %w", key, err)
		}
		if prior != nil && prior.Value != "" && !strings.EqualFold(prior.Value, computed) {
			return fmt.Errorf("rubygems/%s@%s: sha256 mismatch against the pinned digest for %s: pinned=%s fetched=%s",
				pm.Name, ve.Version, key, prior.Value, computed)
		}
	}
	if ve.Checksum != nil {
		if err := verifyChecksum(ve.Checksum, computed); err != nil {
			return fmt.Errorf("checksum verification failed: %w", err)
		}
		_, _ = fmt.Fprintf(out, "  [rubygems] %s@%s: checksum verified\n", pm.Name, ve.Version)
		if err := cfg.updateVersionChecksum(ctx, store, manifest.TypeRubygems, name, ve, ve.Checksum, true); err != nil {
			return err
		}
	} else {
		_, _ = fmt.Fprintf(out, "  [rubygems] %s@%s: checksum recorded (sha256:%s...)\n", pm.Name, ve.Version, computed[:12])
		if err := cfg.updateVersionChecksum(ctx, store, manifest.TypeRubygems, name, ve, newSHA256Checksum(computed), false); err != nil {
			return err
		}
	}

	platform := "any"
	if _, p := manifest.RubygemsPlatform(ve.Version); p != "" {
		platform = p
	}
	stampVersion(ctx, store, manifest.TypeRubygems, name, ve, cfg.GetBuildEnv(), platform)
	stampFetchRecord(ctx, store, manifest.TypeRubygems, name, ve, dest, computed, nil)
	return nil
}
