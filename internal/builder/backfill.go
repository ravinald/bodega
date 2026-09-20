package builder

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/ravinald/bodega/internal/manifest"
)

// BackfillArtifactSizes scans all package versions and sets ArtifactSize from
// local artifact files when it is currently zero. This handles packages that
// were fetched before size tracking was added. Returns the number of entries
// updated.
func BackfillArtifactSizes(cfg *Config, store *manifest.Store, out io.Writer) int {
	ctx := context.Background()
	updated := 0

	for _, typ := range manifest.AllTypes {
		for _, name := range store.ListPackages(typ) {
			pm, err := store.GetPackage(ctx, typ, name)
			if err != nil || pm == nil {
				continue
			}

			dirty := false
			for i := range pm.Versions {
				ve := &pm.Versions[i]
				if ve.ArtifactSize > 0 {
					continue // already set
				}

				// Try local artifact file first.
				path := artifactPathForVersion(cfg, typ, name, *ve)
				if path != "" {
					if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
						ve.ArtifactSize = fi.Size()
						dirty = true
						_, _ = fmt.Fprintf(out, "  [%s] %s: backfilled %s\n", typ, name, humanBytes(fi.Size()))
						continue
					}
				}

				// For apt entries, try the Size field from metadata.
				if typ == manifest.TypeApt && ve.Metadata != nil {
					if sizeStr, ok := ve.Metadata["Size"]; ok {
						if n, err := strconv.ParseInt(sizeStr, 10, 64); err == nil && n > 0 {
							ve.ArtifactSize = n
							dirty = true
							_, _ = fmt.Fprintf(out, "  [%s] %s: backfilled %s from metadata\n", typ, name, humanBytes(n))
						}
					}
				}
			}

			if dirty {
				if err := store.SavePackage(ctx, pm); err != nil {
					_, _ = fmt.Fprintf(out, "  [%s] %s: ERROR saving: %v\n", typ, name, err)
				} else {
					updated++
				}
			}
		}
	}

	return updated
}

// artifactPathForVersion returns the local artifact path for a version entry,
// or "" if the path cannot be determined (e.g. apt/pypi use globs).
func artifactPathForVersion(cfg *Config, typ, name string, ve manifest.VersionEntry) string {
	switch typ {
	case manifest.TypeBinary:
		d := buildDirs(cfg.rootFor(typ))
		return binaryDestPath(d, name, ve)
	case manifest.TypeGit:
		d := buildDirs(cfg.rootFor(typ))
		if ve.IsRelease() {
			return gitReleaseArchive(d, name, ve)
		}
		sn := safeName(name)
		return filepath.Join(d.bundles, sn, sn+"-"+ve.Ref+".bundle")
	case manifest.TypeGomod:
		d := buildDirs(cfg.rootFor(typ))
		dir := gomodDir(d, name)
		return filepath.Join(dir, ve.Version+".zip")
	case manifest.TypeHelm:
		d := buildDirs(cfg.rootFor(typ))
		return helmLocalPath(d, name, ve)
	case manifest.TypeNpm:
		d := buildDirs(cfg.rootFor(typ))
		return npmTarballPath(d, name, ve)
	default:
		// apt and pypi use globs / multiple files; skip for now.
		return ""
	}
}
