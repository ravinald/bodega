package builder

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

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
