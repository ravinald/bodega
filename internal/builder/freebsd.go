package builder

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/http"
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

// freeBSDStagingDir holds the scratch areas a mirror and an upload own for
// the length of one call. It sits beside the mirrored repositories rather
// than inside one, so FreeBSDArtifactPaths cannot pick a half-fetched
// catalogue up off the tree.
const freeBSDStagingDir = ".staging"

// freeBSDRepoDir is where one mirrored repository lives on disk. The layout is
// the repository's own, so the directory can be served by any static file
// server and diffed against the upstream URL path for path.
func freeBSDRepoDir(d dirs, repo string, ve manifest.VersionEntry) string {
	return filepath.Join(d.freebsd, ve.Version, repo)
}

// freeBSDScratch creates a directory this call alone writes, under the
// repository's staging area, and returns it with the remove that ends its
// life.
//
// Unique per call rather than one path per repository. Two mirrors of the
// same repository overlap whenever a scheduled run meets a manual one, and a
// shared staging path gave both of them the same three filenames: the first
// to finish renamed whichever bytes were there, which is the second run's
// catalogue naming objects the second run has not fetched yet. Nothing
// reports that — every transfer succeeded and both archives are valid — and
// the client is the one that finds out, halfway through an install. A
// directory nobody else can name is what makes "the archives this call
// publishes are the archives this call parsed" true across processes as well
// as goroutines, without a lock the CLI has nowhere to hold.
func freeBSDScratch(d dirs, repo string, ve manifest.VersionEntry, prefix string) (string, func(), error) {
	base := filepath.Join(d.freebsd, freeBSDStagingDir, ve.Version, repo)
	if err := mkdirAll(base); err != nil {
		return "", func() {}, err
	}
	dir, err := os.MkdirTemp(base, prefix+"-")
	if err != nil {
		return "", func() {}, fmt.Errorf("stage %s@%s under %s: %w", repo, ve.Version, base, err)
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
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
//
// A generated repository has no fetch stage at all and reports complete. Its
// packages arrive in the build tree from wherever the operator built them —
// poudriere, a hand-run `pkg create` — and its catalogue is produced by the
// server from what the upload placed, so there is nothing on this side to do
// and nothing whose absence would mean it had not been done.
func CheckFreeBSDStage(cfg *Config, repo string, ve manifest.VersionEntry) StageStatus {
	if generated, err := ve.FreeBSDGenerated(); err == nil && generated {
		return StageStatus{Fetched: true, Built: true, Packaged: true}
	}
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
			generated, err := ve.FreeBSDGenerated()
			if err != nil {
				cfg.logf("  [freebsd] %s@%s: REFUSED: %v", repo, ve.Version, err)
				summary.Failures++
				summary.Results = append(summary.Results, Result{Type: manifest.TypeFreeBSD, Name: repo, Err: err})
				continue
			}
			if generated {
				// No upstream, so no fetch. The packages are whatever the
				// operator put in the build tree and the catalogue is the
				// server's to produce; a fetch here would have nowhere to
				// fetch from and nothing to overwrite.
				cfg.logf("  [freebsd] %s@%s: generated repository, nothing to fetch", repo, ve.Version)
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
			artifacts, digest, err := mirrorFreeBSDRepo(cfg, d, repo, ve)
			result.Artifacts = artifacts
			result.Err = err
			result.Elapsed = time.Since(start)

			status := "success"
			if err != nil {
				status = "failure"
				summary.Failures++
			} else {
				// The digest is the one mirrorFreeBSDRepo took of the bytes it
				// published, not one read back off the tree: an overlapping
				// run can have replaced the file by now, and a fetch record
				// naming another run's catalogue is a record that verifies
				// against nothing.
				stampFetchRecord(ctx, store, manifest.TypeFreeBSD, repo, ve, freeBSDCatalogPath(d, repo, ve), digest, nil)
			}
			summary.Results = append(summary.Results, result)
			summary.Total++
			cfg.RecordAudit(audit.EventFetch, manifest.TypeFreeBSD, repo, ve.Version, status, result.Elapsed, err)
		}
	}

	return summary
}

// mirrorFreeBSDRepo copies one repository and returns every local file it
// wrote, catalogue last, with the SHA-256 of the catalogue it published.
func mirrorFreeBSDRepo(cfg *Config, d dirs, repo string, ve manifest.VersionEntry) ([]string, string, error) {
	base := freeBSDRepoURL(ve)
	if base == "" {
		return nil, "", fmt.Errorf("freebsd %s@%s records no url; set it to the repository root a pkg client would be pointed at, for example https://pkg.freebsd.org/%s/%s",
			repo, ve.Version, ve.Version, repo)
	}
	out := cfg.entryWriter(manifest.TypeFreeBSD, repo)
	repoDir := freeBSDRepoDir(d, repo, ve)
	staging, releaseStaging, err := freeBSDScratch(d, repo, ve, "mirror")
	if err != nil {
		return nil, "", err
	}
	defer releaseStaging()

	// The catalogue is fetched first because it is the only thing that says
	// which objects exist, and staged rather than placed because nothing it
	// names has been fetched yet.
	ctx := context.Background()
	var staged []string
	for _, name := range manifest.FreeBSDCatalogFiles {
		dest := filepath.Join(staging, name)
		_, _ = fmt.Fprintf(out, "  [freebsd] %s@%s: fetching %s\n", repo, ve.Version, base+"/"+name)
		if err := freeBSDDownload(ctx, dest, base+"/"+name); err != nil {
			return nil, "", fmt.Errorf("fetch %s for %s@%s: %w", name, repo, ve.Version, err)
		}
		staged = append(staged, dest)
	}

	// Both archives, not the catalogue alone. data.pkg carries its own record
	// per package — pkg_repo_fetch_data_fd reads the member meta.conf's "data"
	// key names — and the two are fetched a moment apart from a repository
	// that rebuilds continuously. Publishing the pair after mirroring only
	// what packagesite.pkg named leaves data.pkg describing a generation whose
	// objects were never fetched, and the ordering rule does not help: copying
	// it last still copies it.
	repoPaths, format, err := freeBSDPublicationSet(staging)
	if err != nil {
		return nil, "", fmt.Errorf("%s@%s: %w", repo, ve.Version, err)
	}
	_, _ = fmt.Fprintf(out, "  [freebsd] %s@%s: packing_format is %q; the two catalogues name %d objects between them\n",
		repo, ve.Version, format, len(repoPaths))

	written := make([]string, 0, len(repoPaths)+len(manifest.FreeBSDCatalogFiles))
	for _, rel := range repoPaths {
		dest := filepath.Join(repoDir, filepath.FromSlash(rel))
		if !cfg.Force && fileExists(dest) {
			written = append(written, dest)
			continue
		}
		if err := mkdirAll(filepath.Dir(dest)); err != nil {
			return written, "", err
		}
		if err := freeBSDDownload(ctx, dest, base+"/"+rel); err != nil {
			return written, "", fmt.Errorf("fetch %s for %s@%s: %w", rel, repo, ve.Version, err)
		}
		written = append(written, dest)
	}

	// Taken from the staged file rather than from the tree, and taken before
	// the rename: after it, the catalogue at that path may be another run's.
	digest, err := computeFileSHA256(filepath.Join(staging, manifest.FreeBSDCatalogFile))
	if err != nil {
		return written, "", fmt.Errorf("digest the staged catalogue for %s@%s: %w", repo, ve.Version, err)
	}

	// Every object is on disk, so the catalogue may now describe the tree.
	if err := mkdirAll(repoDir); err != nil {
		return written, "", err
	}
	for i, name := range manifest.FreeBSDCatalogFiles {
		dest := filepath.Join(repoDir, name)
		if err := os.Rename(staged[i], dest); err != nil {
			return written, "", fmt.Errorf("place %s for %s@%s: %w", name, repo, ve.Version, err)
		}
		written = append(written, dest)
	}
	_, _ = fmt.Fprintf(out, "  [freebsd] %s@%s: ok\n", repo, ve.Version)
	return written, digest, nil
}

// FreeBSDRepoPaths is every object the three repository-root files in dir name
// between them, read out of those files and nothing else.
//
// It exists for 'bodega pkg move', which republishes a mirrored repository
// into another backend and so needs the same answer the mirror and the upload
// already build from: what the archives about to be published name. A prefix
// listing of the source cannot answer it, because a listing is a snapshot of
// whatever the backend held at that instant rather than of the document that
// is going to be served, and the two diverge the moment an upload lands
// between them. The caller owns dir and must hold copies nobody else can
// replace; see freeBSDPin for what that costs and why.
func FreeBSDRepoPaths(dir string) ([]string, error) {
	paths, _, err := freeBSDPublicationSet(dir)
	return paths, err
}

// freeBSDPublicationSet is every object the three archives in dir name between
// them: the codec and the data member come out of that directory's own
// meta.conf, and both archives beside it are read.
//
// One directory in, one object list out. A mirror reads its staging area and
// an upload reads its pinned copy, and neither can be handed a path a
// concurrent run rewrites underneath it.
func freeBSDPublicationSet(dir string) ([]string, string, error) {
	meta, err := os.ReadFile(filepath.Join(dir, manifest.FreeBSDMetaFile)) //nolint:gosec // G304: composed by this package under the build root.
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", filepath.Join(dir, manifest.FreeBSDMetaFile), err)
	}
	format, err := freeBSDPackingFormat(meta)
	if err != nil {
		return nil, "", err
	}
	dataMember, err := freeBSDDataMember(meta)
	if err != nil {
		return nil, "", err
	}
	paths, err := freeBSDMirrorSet(
		filepath.Join(dir, manifest.FreeBSDCatalogFile),
		filepath.Join(dir, manifest.FreeBSDDataFile), format, dataMember)
	if err != nil {
		return nil, "", err
	}
	return paths, format, nil
}

// freeBSDDownload copies one upstream file to dest, and either writes every
// byte upstream served or leaves dest as it found it.
//
// Three things separate it from downloadURL, and each of them is a way a
// mirror publishes a catalogue over bytes that are not what it names.
//
// It asks for identity encoding and refuses a body that arrives encoded
// anyway. Go's transport adds "Accept-Encoding: gzip" on its own and decodes
// the answer transparently, so the bytes written are the ones the transport
// produced rather than the ones the upstream signed — and a re-encode of an
// already-compressed archive is a signature failure a client reports against
// bodega. Setting the header explicitly turns both halves of that off.
//
// It compares what it read against the declared Content-Length, because a cut
// transfer arrives as a short read and no error.
//
// And it writes through a temporary sibling and renames, so a failed or
// partial transfer cannot be mistaken for a mirrored object. downloadURL
// creates and truncates dest first and leaves the stub behind, which is how a
// retry skipped a file holding 3 bytes of 100 and published the catalogue
// over it. A forced refresh that fails keeps the good copy for the same
// reason.
func freeBSDDownload(ctx context.Context, dest, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) //nolint:gosec // G704: the URL is the entry's repository root plus a repopath the catalogue reader has already validated.
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G704: see the request above.
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		return fmt.Errorf("GET %s: the upstream answered with Content-Encoding %q after identity was asked for; "+
			"decoding it would store bytes the repository never signed, so nothing was written. "+
			"Point the entry at an origin rather than at a rewriting proxy", url, enc)
	}

	tmp, err := os.CreateTemp(filepath.Dir(dest), "."+filepath.Base(dest)+".part-*")
	if err != nil {
		return fmt.Errorf("stage %s: %w", dest, err)
	}
	// Named once: every failure below has to remove the same file, and a
	// rename makes the remove a no-op rather than a hazard.
	staged := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(staged)
	}()

	n, err := io.Copy(tmp, resp.Body)
	if err != nil {
		return fmt.Errorf("read %s after %d bytes: %w — nothing was written", url, n, err)
	}
	if resp.ContentLength >= 0 && n != resp.ContentLength {
		return fmt.Errorf("%s sent %d bytes against a declared Content-Length of %d: the transfer was cut and nothing was written", url, n, resp.ContentLength)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("flush %s: %w", staged, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", staged, err)
	}
	if err := os.Rename(staged, dest); err != nil {
		return fmt.Errorf("place %s: %w", dest, err)
	}
	return nil
}

// FreeBSDArtifactPaths returns local/object-key pairs ready for upload — every
// object the mirrored catalogue names first, the three repository-root files
// last — together with the release that ends the returned paths' lives.
//
// The archives are pinned: copied out of the tree into a directory this call
// owns, and the object list read back out of those copies rather than off a
// walk of the repository. Enumeration and upload are separated by however long
// the objects take to write, and a forced mirror landing in that window
// replaces the catalogue under the very path the caller is still holding. The
// upload then publishes a generation it never enumerated, whose new objects
// are in nobody's list — with the catalogue-last ordering satisfied, every
// transfer successful, and the repository broken. Sorting cannot fix a stale
// list; only holding the bytes can.
//
// Reading the object list out of the pinned archives rather than off the tree
// is the other half. A walk uploads what happens to be on disk, which is a
// superset on a good day and a subset on a bad one; the pinned archives are
// the document a client reads, so what they name is what has to be in the
// backend before they are. An object they name that is not on disk fails the
// call, because the alternative is publishing a catalogue that resolves an
// install and then 404s.
//
// The caller must run release when the upload is over. Afterwards the
// catalogue paths name nothing.
func FreeBSDArtifactPaths(cfg *Config, store *manifest.Store, entryFilter string) ([]ArtifactPath, func(), error) {
	ctx := context.Background()
	d := buildDirs(cfg.rootFor(manifest.TypeFreeBSD))
	var pins []func()
	release := func() {
		for _, remove := range pins {
			remove()
		}
	}
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
			generated, err := ve.FreeBSDGenerated()
			if err != nil {
				release()
				return nil, func() {}, fmt.Errorf("freebsd %s@%s: %w", repo, ve.Version, err)
			}
			if generated {
				objs, err := freeBSDGeneratedUploadSet(cfg, pm.Name, repo, ve, repoDir)
				if err != nil {
					release()
					return nil, func() {}, err
				}
				objects = append(objects, objs...)
				continue
			}
			if !fileExists(filepath.Join(repoDir, manifest.FreeBSDCatalogFile)) {
				// No catalogue is no snapshot: a proxy-mode entry, or one
				// whose mirror failed before the catalogue was placed. Either
				// way there is no generation to publish, and the objects
				// beneath it belong to no document.
				continue
			}
			pin, remove, err := freeBSDPin(d, repo, ve, repoDir)
			if err != nil {
				release()
				return nil, func() {}, err
			}
			pins = append(pins, remove)

			objs, roots, err := freeBSDUploadSet(pm.Name, repo, ve, repoDir, pin)
			if err != nil {
				release()
				return nil, func() {}, err
			}
			objects = append(objects, objs...)
			catalog = append(catalog, roots...)
		}
	}

	// Sorted within each half so an upload is reproducible; the two halves
	// stay in this order whatever the enumeration returned.
	slices.SortFunc(objects, func(a, b ArtifactPath) int { return strings.Compare(a.ObjectKey, b.ObjectKey) })
	freeBSDSortCatalog(catalog)
	return append(objects, catalog...), release, nil
}

// freeBSDPin copies one repository's three root files into a directory this
// call owns, and returns it with the remove that ends its life.
//
// Copied rather than linked or referenced: the point is bytes no other run can
// replace, and a hard link to a path a rename is about to take over is the
// same file under a different name only until the rename lands.
//
// The three are copied one at a time, so a mirror publishing mid-copy can
// leave the pin holding two generations. That fails closed rather than
// silently: the object check below is against whatever the pinned archives
// name, so a mixed pin either names objects that are all on disk — both
// generations placed theirs before publishing — or fails the enumeration by
// name. A packing_format that differed between the two would fail in the
// reader instead, which is the same answer arrived at earlier.
func freeBSDPin(d dirs, repo string, ve manifest.VersionEntry, repoDir string) (string, func(), error) {
	pin, remove, err := freeBSDScratch(d, repo, ve, "upload")
	if err != nil {
		return "", func() {}, err
	}
	for _, name := range manifest.FreeBSDCatalogFiles {
		if err := copyFile(filepath.Join(repoDir, name), filepath.Join(pin, name)); err != nil {
			remove()
			return "", func() {}, fmt.Errorf("pin %s for freebsd %s@%s: %w. "+
				"A mirrored repository holds all three root files; re-run `bodega build fetch freebsd %s`", name, repo, ve.Version, err, repo)
		}
	}
	return pin, remove, nil
}

// freeBSDUploadSet is the object half and the repository-root half of one
// entry's upload, read out of its pinned archives.
func freeBSDUploadSet(name, repo string, ve manifest.VersionEntry, repoDir, pin string) (objects, roots []ArtifactPath, err error) {
	repoPaths, _, err := freeBSDPublicationSet(pin)
	if err != nil {
		return nil, nil, fmt.Errorf("freebsd %s@%s: %w", repo, ve.Version, err)
	}
	for _, rel := range repoPaths {
		local := filepath.Join(repoDir, filepath.FromSlash(rel))
		if !fileExists(local) {
			return nil, nil, fmt.Errorf("freebsd %s@%s: the mirrored catalogue names %s, but %s is not on disk. "+
				"Uploading it would publish a repository whose client resolves that package and then 404s, so nothing was uploaded for this entry. "+
				"Re-run `bodega build fetch freebsd %s force` and upload again", repo, ve.Version, rel, local, repo)
		}
		objects = append(objects, ArtifactPath{
			Local:     local,
			ObjectKey: manifest.FreeBSDKey(ve.Version, name, rel),
			Package:   repo,
			Version:   ve.Version,
		})
	}
	for _, root := range manifest.FreeBSDCatalogFiles {
		roots = append(roots, ArtifactPath{
			Local:     filepath.Join(pin, root),
			ObjectKey: manifest.FreeBSDKey(ve.Version, name, root),
			Package:   repo,
			Version:   ve.Version,
		})
	}
	return objects, roots, nil
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

// freeBSDGeneratedUploadSet is every package in a generated repository's build
// tree, as local/object-key pairs.
//
// A plain walk, which is the answer the mirror refuses and for a reason that
// does not apply here. A mirror uploads what a published document names,
// because the document is what a client reads and a walk would disagree with
// it. A generated repository publishes no document until the server builds one
// from the objects that land here, so the walk is upstream of the catalogue
// rather than in competition with it: whatever this uploads is what the
// catalogue will name, and nothing can name an object the store does not hold.
//
// No repository-root file is uploaded. meta.conf, data.pkg and packagesite.pkg
// are the generator's namespace, and an object stored under one of those names
// is one no request can ever reach — the route answers all three from the
// build. One left in the tree by an entry that used to mirror is named in the
// log rather than skipped in silence.
func freeBSDGeneratedUploadSet(cfg *Config, name, repo string, ve manifest.VersionEntry, repoDir string) ([]ArtifactPath, error) {
	if info, err := os.Stat(repoDir); err != nil || !info.IsDir() {
		// Not an error: an entry created but not yet populated is the
		// ordinary state between `bodega pkg create` and the first build.
		cfg.logf("  [freebsd] %s@%s: %s does not exist, so the generated repository publishes nothing yet", repo, ve.Version, repoDir)
		return nil, nil
	}
	var out []ArtifactPath
	err := filepath.WalkDir(repoDir, func(p string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(repoDir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if root, reserved := manifest.FreeBSDReservedRoot(rel); reserved {
			cfg.logf("  [freebsd] %s@%s: skipping %s — %s is the generated catalogue's own name and an object stored under it is one no request reaches",
				repo, ve.Version, rel, root)
			return nil
		}
		if !strings.HasSuffix(rel, ".pkg") {
			cfg.logf("  [freebsd] %s@%s: skipping %s — a generated catalogue names .pkg archives only", repo, ve.Version, rel)
			return nil
		}
		out = append(out, ArtifactPath{
			Local:     p,
			ObjectKey: manifest.FreeBSDKey(ve.Version, name, rel),
			Package:   repo,
			Version:   ve.Version,
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("freebsd %s@%s: walk %s: %w", repo, ve.Version, repoDir, err)
	}
	return out, nil
}
