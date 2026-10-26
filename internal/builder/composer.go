package builder

import (
	"context"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

// composerArchivePath returns where a Composer dist archive is kept locally:
// <root>/composer/<vendor>/<package>/<version>/<reference>, the object key's
// own layout under the type's root, with the version path-escaped as the key
// escapes it.
//
// "" for an entry that records no dist reference, or a name, version or
// reference that would not stay inside its directory.
func composerArchivePath(d dirs, name string, ve manifest.VersionEntry) string {
	version := url.PathEscape(ve.Version)
	if ve.Version == "" || !manifest.ComposerValidReference(ve.Ref) ||
		!filepath.IsLocal(name) || !filepath.IsLocal(version) || strings.Contains(name, `\`) {
		return ""
	}
	return filepath.Join(d.composer, filepath.FromSlash(name), version, ve.Ref)
}

// ComposerArtifactPaths returns every dist archive under composer_root that
// an entry names, keyed where the /composer/dist/ route reads it.
func ComposerArtifactPaths(cfg *Config, store *manifest.Store, entryFilter string) []ArtifactPath {
	ctx := context.Background()
	d := buildDirs(cfg.rootFor(manifest.TypeComposer))
	var paths []ArtifactPath
	for _, name := range store.ListPackages(manifest.TypeComposer) {
		pm, err := store.GetPackage(ctx, manifest.TypeComposer, name)
		if err != nil || pm == nil {
			continue
		}
		if entryFilter != "" && pm.Name != entryFilter && name != entryFilter {
			continue
		}
		for _, ve := range pm.Versions {
			local := composerArchivePath(d, pm.Name, ve)
			if local == "" || !fileExists(local) {
				continue
			}
			paths = append(paths, ArtifactPath{
				Local:     local,
				ObjectKey: manifest.ComposerDistKey(pm.Name, ve.Version, ve.Ref),
				Package:   pm.Name,
				Version:   ve.Version,
			})
		}
	}
	return paths
}
