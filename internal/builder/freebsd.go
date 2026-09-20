package builder

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// ---- FreeBSD pkg mirror ----------------------------------------------------
//
// A freebsd entry is one repository, not one package: the name is the
// repository directory a pkg client asks under ("latest", "base_latest") and
// the version is the ABI above it ("FreeBSD:14:amd64"), which is the string
// pkg substitutes for ${ABI} in the URL it was configured with.
//
// The mirror copies bytes and never produces any. packagesite.pkg carries
// FreeBSD's own signature as a member, so a byte-exact copy validates against
// the stock fingerprint at /usr/share/keys/pkg/trusted/pkg.freebsd.org.2013102301
// with no key of bodega's anywhere in the path. Regenerating the catalogue
// with `pkg repo` would discard that attestation permanently and force a
// fingerprint onto every client, which is why nothing here re-tars or
// recompresses.

// freeBSDStagingDir is where a catalogue lands before its objects are
// fetched. It sits beside the mirrored repositories rather than inside one, so
// FreeBSDArtifactPaths cannot pick a half-fetched catalogue up off the tree.
const freeBSDStagingDir = ".staging"

// freeBSDRepoDir is where one mirrored repository lives on disk. The layout is
// the repository's own, so the directory can be served by any static file
// server and diffed against the upstream URL path for path.
func freeBSDRepoDir(d dirs, repo string, ve manifest.VersionEntry) string {
	return filepath.Join(d.freebsd, ve.Version, repo)
}

// freeBSDStagingRepoDir is the same repository's staging area.
func freeBSDStagingRepoDir(d dirs, repo string, ve manifest.VersionEntry) string {
	return filepath.Join(d.freebsd, freeBSDStagingDir, ve.Version, repo)
}

// freeBSDCatalogPath is the local path of the catalogue archive, which is what
// CheckFreeBSDStage reads to decide whether the repository was mirrored.
func freeBSDCatalogPath(d dirs, repo string, ve manifest.VersionEntry) string {
	return filepath.Join(freeBSDRepoDir(d, repo, ve), manifest.FreeBSDCatalogFile)
}

// freeBSDRepoURL is the upstream repository root for an entry.
//
// The entry's URL is the repository root exactly as it would be written in
// pkg.conf after ${ABI} has been substituted — "https://pkg.freebsd.org/FreeBSD:14:amd64/latest".
// Composed from an ABI and a repository name instead, this would be wrong for
// every private repository that does not nest its ABIs, and there is nothing
// in a URL that says which convention it follows.
func freeBSDRepoURL(ve manifest.VersionEntry) string {
	return strings.TrimRight(ve.URL, "/")
}

// CheckFreeBSDStage reports whether a repository is already mirrored. The
// catalogue is written last, so its presence is what says the mirror finished.
func CheckFreeBSDStage(cfg *Config, repo string, ve manifest.VersionEntry) StageStatus {
	d := buildDirs(cfg.rootFor(manifest.TypeFreeBSD))
	if fileExists(freeBSDCatalogPath(d, repo, ve)) {
		return StageStatus{Fetched: true, Built: true, Packaged: true}
	}
	return StageStatus{}
}

// FetchFreeBSD mirrors each configured repository: meta.conf and both
// catalogue archives to staging, every object the catalogue names to the tree,
// and the catalogue into the tree last.
//
// The ordering is the whole point. A catalogue that lands ahead of the objects
// it names is a repository where `pkg install` resolves a package and then
// 404s halfway through fetching it, and the upstream repositories rebuild
// continuously, so the window is not theoretical. Objects first, catalogue
// last, at every layer: here on disk, in FreeBSDArtifactPaths on upload, and
// in the server's refusal to proxy a catalogue for a mirrored entry.
func FetchFreeBSD(cfg *Config, store *manifest.Store, entryFilter string) *Summary {
	ctx := context.Background()
	summary := &Summary{}
	d := buildDirs(cfg.rootFor(manifest.TypeFreeBSD))

	for _, repo := range store.ListPackages(manifest.TypeFreeBSD) {
		if entryFilter != "" && repo != entryFilter {
			continue
		}
		pm, err := store.GetPackage(ctx, manifest.TypeFreeBSD, repo)
		if err != nil || pm == nil {
			cfg.logf("  [freebsd] %s: ERROR loading package: %v", repo, err)
			continue
		}

		for _, ve := range pm.Versions {
			if ve.Frozen {
				cfg.logf("  [freebsd] %s@%s: SKIPPED (frozen)", repo, ve.Version)
				continue
			}
			if ve.EffectiveMode() == manifest.ModeProxy {
				// Proxy mode holds no snapshot by definition: the catalogue
				// and the objects both come from upstream per request, so
				// there is nothing for this stage to place and no skew it
				// could introduce.
				cfg.logf("  [freebsd] %s@%s: proxy mode, nothing to mirror", repo, ve.Version)
				continue
			}
			if err := cfg.EnforcePolicy(ctx, manifest.TypeFreeBSD, repo, ve.Version, ve.URL); err != nil {
				cfg.logf("  [freebsd] %s@%s: BLOCKED by policy: %v", repo, ve.Version, err)
				summary.Failures++
				summary.Results = append(summary.Results, Result{Type: manifest.TypeFreeBSD, Name: repo, Err: err})
				continue
			}
			if !cfg.Force && CheckFreeBSDStage(cfg, repo, ve).Fetched {
				cfg.logf("  [freebsd] %s@%s: already mirrored, skipping", repo, ve.Version)
				continue
			}

			result := Result{Type: manifest.TypeFreeBSD, Name: repo}
			start := time.Now()
			artifacts, err := mirrorFreeBSDRepo(cfg, d, repo, ve)
			result.Artifacts = artifacts
			result.Err = err
			result.Elapsed = time.Since(start)

			status := "success"
			if err != nil {
				status = "failure"
				summary.Failures++
			} else {
				catalog := freeBSDCatalogPath(d, repo, ve)
				digest, _ := computeFileSHA256(catalog)
				stampFetchRecord(ctx, store, manifest.TypeFreeBSD, repo, ve, catalog, digest, nil)
			}
			summary.Results = append(summary.Results, result)
			summary.Total++
			cfg.RecordAudit(audit.EventFetch, manifest.TypeFreeBSD, repo, ve.Version, status, result.Elapsed, err)
		}
	}

	return summary
}

// mirrorFreeBSDRepo copies one repository and returns every local file it
// wrote, catalogue last.
func mirrorFreeBSDRepo(cfg *Config, d dirs, repo string, ve manifest.VersionEntry) ([]string, error) {
	base := freeBSDRepoURL(ve)
	if base == "" {
		return nil, fmt.Errorf("freebsd %s@%s records no url; set it to the repository root a pkg client would be pointed at, for example https://pkg.freebsd.org/%s/%s",
			repo, ve.Version, ve.Version, repo)
	}
	out := cfg.entryWriter(manifest.TypeFreeBSD, repo)
	repoDir := freeBSDRepoDir(d, repo, ve)
	staging := freeBSDStagingRepoDir(d, repo, ve)
	if err := mkdirAll(staging); err != nil {
		return nil, err
	}

	// The catalogue is fetched first because it is the only thing that says
	// which objects exist, and staged rather than placed because nothing it
	// names has been fetched yet.
	var staged []string
	for _, name := range manifest.FreeBSDCatalogFiles {
		dest := filepath.Join(staging, name)
		_, _ = fmt.Fprintf(out, "  [freebsd] %s@%s: fetching %s\n", repo, ve.Version, base+"/"+name)
		if err := downloadURL(dest, base+"/"+name); err != nil {
			return nil, fmt.Errorf("fetch %s for %s@%s: %w", name, repo, ve.Version, err)
		}
		staged = append(staged, dest)
	}

	meta, err := os.ReadFile(filepath.Join(staging, manifest.FreeBSDMetaFile)) //nolint:gosec // G304: composed under the build root.
	if err != nil {
		return nil, fmt.Errorf("read staged meta.conf for %s@%s: %w", repo, ve.Version, err)
	}
	format, err := freeBSDPackingFormat(meta)
	if err != nil {
		return nil, fmt.Errorf("%s@%s: %w", repo, ve.Version, err)
	}
	_, _ = fmt.Fprintf(out, "  [freebsd] %s@%s: packing_format is %q\n", repo, ve.Version, format)

	repoPaths, err := freeBSDCatalogRepoPaths(filepath.Join(staging, manifest.FreeBSDCatalogFile), format)
	if err != nil {
		return nil, fmt.Errorf("%s@%s: %w", repo, ve.Version, err)
	}
	_, _ = fmt.Fprintf(out, "  [freebsd] %s@%s: the catalogue names %d objects\n", repo, ve.Version, len(repoPaths))

	written := make([]string, 0, len(repoPaths)+len(manifest.FreeBSDCatalogFiles))
	for _, rel := range repoPaths {
		dest := filepath.Join(repoDir, filepath.FromSlash(rel))
		if !cfg.Force && fileExists(dest) {
			written = append(written, dest)
			continue
		}
		if err := mkdirAll(filepath.Dir(dest)); err != nil {
			return written, err
		}
		if err := downloadURL(dest, base+"/"+rel); err != nil {
			return written, fmt.Errorf("fetch %s for %s@%s: %w", rel, repo, ve.Version, err)
		}
		written = append(written, dest)
	}

	// Every object is on disk, so the catalogue may now describe the tree.
	if err := mkdirAll(repoDir); err != nil {
		return written, err
	}
	for i, name := range manifest.FreeBSDCatalogFiles {
		dest := filepath.Join(repoDir, name)
		if err := os.Rename(staged[i], dest); err != nil {
			return written, fmt.Errorf("place %s for %s@%s: %w", name, repo, ve.Version, err)
		}
		written = append(written, dest)
	}
	_, _ = fmt.Fprintf(out, "  [freebsd] %s@%s: ok\n", repo, ve.Version)
	return written, nil
}

// FreeBSDArtifactPaths returns local/object-key pairs ready for upload, every
// mirrored object first and the catalogue files last.
//
// UploadPaths writes the slice in order, so this ordering is what keeps the
// published catalogue from ever naming an object the backend does not hold.
// The reverse — an object uploaded ahead of the catalogue that names it — is
// invisible to a client, which reads the catalogue first and will not ask for
// what it has not been told about.
func FreeBSDArtifactPaths(cfg *Config, store *manifest.Store, entryFilter string) []ArtifactPath {
	ctx := context.Background()
	d := buildDirs(cfg.rootFor(manifest.TypeFreeBSD))
	var objects, catalog []ArtifactPath

	for _, repo := range store.ListPackages(manifest.TypeFreeBSD) {
		if entryFilter != "" && repo != entryFilter {
			continue
		}
		pm, err := store.GetPackage(ctx, manifest.TypeFreeBSD, repo)
		if err != nil || pm == nil {
			continue
		}
		for _, ve := range pm.Versions {
			repoDir := freeBSDRepoDir(d, repo, ve)
			_ = filepath.WalkDir(repoDir, func(p string, entry fs.DirEntry, err error) error {
				if err != nil || entry.IsDir() {
					return nil //nolint:nilerr // an unreadable subtree is nothing to upload, not a failed upload.
				}
				rel, relErr := filepath.Rel(repoDir, p)
				if relErr != nil {
					return nil
				}
				repoPath := filepath.ToSlash(rel)
				ap := ArtifactPath{
					Local:     p,
					ObjectKey: manifest.FreeBSDKey(ve.Version, pm.Name, repoPath),
					Package:   repo,
					Version:   ve.Version,
				}
				if slices.Contains(manifest.FreeBSDCatalogFiles, repoPath) {
					catalog = append(catalog, ap)
					return nil
				}
				objects = append(objects, ap)
				return nil
			})
		}
	}

	// Sorted within each half so an upload is reproducible; the two halves
	// stay in this order whatever the walk returned.
	slices.SortFunc(objects, func(a, b ArtifactPath) int { return strings.Compare(a.ObjectKey, b.ObjectKey) })
	freeBSDSortCatalog(catalog)
	return append(objects, catalog...)
}

// freeBSDSortCatalog puts the repository-root files in manifest's own order,
// which ends on packagesite.pkg: meta.conf and data.pkg are what a client
// reads before the catalogue, and the catalogue is what commits the snapshot.
func freeBSDSortCatalog(paths []ArtifactPath) {
	slices.SortFunc(paths, func(a, b ArtifactPath) int {
		return slices.Index(manifest.FreeBSDCatalogFiles, filepath.Base(a.Local)) -
			slices.Index(manifest.FreeBSDCatalogFiles, filepath.Base(b.Local))
	})
}
