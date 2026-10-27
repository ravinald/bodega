package builder

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

// ociManifestPath returns where an OCI manifest is kept locally: the object
// key's own layout under the type's root, since the key is what /v2/ reads.
//
// "" for an entry whose Ref is not a sha256 digest, or a name that is not
// <registry>/<repository>. Blobs have no local path: they are shared across
// images and no entry owns one.
func ociManifestPath(cfg *Config, name string, ve manifest.VersionEntry) string {
	registry, repo, ok := strings.Cut(name, "/")
	if !ok || !manifest.OCIValidRegistryName(registry) || !manifest.OCIValidRepository(repo) || !manifest.OCIValidDigest(ve.Ref) {
		return ""
	}
	key := strings.TrimPrefix(manifest.OCIManifestKey(registry, repo, ve.Ref), "oci/")
	return filepath.Join(buildDirs(cfg.rootFor(manifest.TypeOCI)).oci, filepath.FromSlash(key))
}

// OCIArtifactPaths returns every manifest under oci_root that an entry names,
// keyed where the /v2/ manifest route reads it.
func OCIArtifactPaths(cfg *Config, store *manifest.Store, entryFilter string) []ArtifactPath {
	ctx := context.Background()
	var paths []ArtifactPath
	for _, name := range store.ListPackages(manifest.TypeOCI) {
		pm, err := store.GetPackage(ctx, manifest.TypeOCI, name)
		if err != nil || pm == nil {
			continue
		}
		if entryFilter != "" && pm.Name != entryFilter && name != entryFilter {
			continue
		}
		registry, repo, _ := strings.Cut(pm.Name, "/")
		for _, ve := range pm.Versions {
			local := ociManifestPath(cfg, pm.Name, ve)
			if local == "" || !fileExists(local) {
				continue
			}
			paths = append(paths, ArtifactPath{
				Local:     local,
				ObjectKey: manifest.OCIManifestKey(registry, repo, ve.Ref),
				Package:   pm.Name,
				Version:   ve.Version,
			})
		}
	}
	return paths
}
