package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// A freebsd version is a whole mirrored repository, so moving one is a
// publication rather than a copy of a list of objects.
//
// Every other type moves one artifact that stands on its own: read the key,
// copy it, verify it, record the backend. A repository is two documents and
// everything they name, and a client reads the documents to find the rest —
// so the destination is only a repository once every repopath the archives
// about to be served name is already there. Two things follow, and neither is
// true of the generic path.
//
// The archives are pinned before they are read. inventory.ArtifactKeys
// answers "what is under this prefix right now", which is the right list to
// size a mirror or to delete one; it is not the set a document names. An
// upload landing between the listing and the copy left the move carrying the
// old generation's object list and the new generation's catalogue bytes, and
// it published that pair: the destination served packages it did not hold,
// while the source still had the complete generation. Both commands returned
// success.
//
// And the three repository-root files go last, which is the inverse of the
// order manifest.ArtifactKeys returns them in. That ordering is the same one
// the mirror keeps on disk and the upload keeps into a backend; a move is the
// third way a repository reaches storage, and it was the one place the rule
// was not being kept.

// moveFreeBSDRepo publishes one mirrored repository on the destination
// backend: the archives are copied out of the source first, every object they
// name is written and verified, and only then do the root files and the
// manifest follow.
//
// Nothing reaches the destination's repository root until the whole object set
// is established there, so a refusal anywhere above leaves whatever generation
// the destination already served intact and the manifest still pointing at the
// source.
func (m *mover) moveFreeBSDRepo(ctx context.Context, pm *manifest.PackageManifest, i int, src storage.ObjectStore, srcName, label string) error {
	ve := pm.Versions[i]
	// manifest owns the ABI check: an entry with no ABI has no repository
	// prefix, so there is nothing to pin and no key to write.
	if _, err := manifest.ArtifactKeys(pm, ve); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}

	pin, release, err := m.pinFreeBSDRoots(ctx, src, srcName, pm, ve, label)
	if err != nil {
		return err
	}
	defer release()

	repoPaths, err := builder.FreeBSDRepoPaths(pin)
	if err != nil {
		return fmt.Errorf("%s: the repository root files on %q do not enumerate: %w. "+
			"Nothing was written to %q and the manifest still points at %q",
			label, srcName, err, m.dstName, srcName)
	}
	fmt.Fprintf(m.out, "  %s: the two archives on %q name %d object(s) between them\n", label, srcName, len(repoPaths))

	var objects []string
	for _, rel := range repoPaths {
		key := manifest.FreeBSDKey(ve.Version, pm.Name, rel)
		info, err := src.Head(ctx, key)
		if err != nil {
			return fmt.Errorf("%s: head %s on %q: %w", label, key, srcName, err)
		}
		if !info.Exists {
			return fmt.Errorf("%s: the archives on %q name %s, which is not there. "+
				"Publishing it on %q would hand a client a repository that resolves that package and then 404s, "+
				"so nothing was written to %q and the manifest still points at %q. "+
				"Re-run `bodega build fetch freebsd %s force` and `bodega build upload freebsd`, then move again",
				label, srcName, rel, m.dstName, m.dstName, srcName, pm.Name)
		}
		fmt.Fprintf(m.out, "  %s: %s -> %s (%s)\n", label, srcName, m.dstName, key)
		size, err := m.copyObject(ctx, src, key)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		// Never the primary: the manifest's size and digest describe the
		// catalogue, and pinFreeBSDRoots has already checked it against them.
		if err := m.verify(ctx, key, size, ve, false); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		objects = append(objects, key)
	}

	roots, err := m.publishFreeBSDRoots(ctx, pin, pm, ve, label)
	if err != nil {
		return err
	}

	// The removal list runs the other way from the publication: catalogue
	// first, so the window on the source that --delete-source opens is a
	// client told there is no such repository rather than one that resolves a
	// package out of a live catalogue and then cannot fetch it.
	removal := slices.Clone(roots)
	slices.Reverse(removal)
	return m.commit(ctx, pm, i, label, srcName, src, append(removal, objects...))
}

// pinFreeBSDRoots copies the three repository-root files out of the source
// backend into a directory this move owns, and returns it with the remove that
// ends its life.
//
// Copied rather than read twice from the backend. The enumeration and the
// publication are separated by however long every package takes to copy, and a
// `bodega build upload freebsd` landing in that window replaces the very keys
// the move is still holding: reading them again at publication time writes one
// generation's catalogue over another generation's object set. Bytes on local
// disk are the only version of those archives nothing else can rewrite.
//
// The three are copied one at a time, so an upload landing mid-copy can leave
// the pin holding two generations. That fails closed. The object check in
// moveFreeBSDRepo runs against whatever the pinned archives name, and an upload
// writes every object before either archive, so a mixed pin either names
// objects that are all on the source — both generations placed theirs — or
// refuses by name before the destination is touched. A packing_format that
// differed between the two fails in the reader instead, which is the same
// answer reached earlier.
func (m *mover) pinFreeBSDRoots(ctx context.Context, src storage.ObjectStore, srcName string, pm *manifest.PackageManifest, ve manifest.VersionEntry, label string) (string, func(), error) {
	none := func() {}
	if err := os.MkdirAll(m.spool, 0o755); err != nil {
		return "", none, fmt.Errorf("%s: create spool dir %s: %w", label, m.spool, err)
	}
	dir, err := os.MkdirTemp(m.spool, "freebsd-move-*")
	if err != nil {
		return "", none, fmt.Errorf("%s: stage the repository root files under %s: %w", label, m.spool, err)
	}
	remove := func() { _ = os.RemoveAll(dir) }

	for _, name := range manifest.FreeBSDCatalogFiles {
		key := manifest.FreeBSDKey(ve.Version, pm.Name, name)
		local := filepath.Join(dir, name)
		size, err := spoolObject(ctx, src, key, local)
		if err != nil {
			remove()
			return "", none, fmt.Errorf("%s: %w on %q. A repository is only movable whole, "+
				"so nothing was written to %q. Run `bodega build upload freebsd %s` against %q first",
				label, err, srcName, m.dstName, pm.Name, srcName)
		}
		if name != manifest.FreeBSDCatalogFile {
			continue
		}
		if err := verifyPinnedCatalog(local, size, ve); err != nil {
			remove()
			return "", none, fmt.Errorf("%s: %w on %q. Nothing was written to %q. "+
				"Re-fetch and re-upload the repository so the manifest and the backend agree on which generation is published",
				label, err, srcName, m.dstName)
		}
	}
	return dir, remove, nil
}

// verifyPinnedCatalog checks the copied catalogue against what the manifest
// records for this version, before any byte reaches the destination.
//
// verifyCopy asks the same question of the destination, and for a type whose
// version is one object that is the right place to ask it: the object is
// written, read back, and a mismatch costs nothing that was already there. A
// repository publishes in a fixed order, so by the time the catalogue reaches
// the destination the two files a client reads ahead of it have already
// replaced the generation that was being served. One hash of a local file
// keeps the refusal ahead of the first destination write.
func verifyPinnedCatalog(local string, size int64, ve manifest.VersionEntry) error {
	if ve.ArtifactSize > 0 && size != ve.ArtifactSize {
		return fmt.Errorf("%s is %d bytes, manifest records %d", manifest.FreeBSDCatalogFile, size, ve.ArtifactSize)
	}
	if ve.Checksum == nil || ve.Checksum.Value == "" {
		return nil
	}
	h, err := hasherFor(ve.Checksum.Algorithm)
	if err != nil {
		return fmt.Errorf("%s: %w", manifest.FreeBSDCatalogFile, err)
	}
	f, err := os.Open(local) //nolint:gosec // G304: composed by pinFreeBSDRoots under the spool dir.
	if err != nil {
		return fmt.Errorf("read the copied %s: %w", manifest.FreeBSDCatalogFile, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("read the copied %s: %w", manifest.FreeBSDCatalogFile, err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, ve.Checksum.Value) {
		return fmt.Errorf("%s has %s %s, manifest records %s", manifest.FreeBSDCatalogFile, ve.Checksum.Algorithm, got, ve.Checksum.Value)
	}
	return nil
}

// publishFreeBSDRoots writes the pinned meta.conf, data.pkg and
// packagesite.pkg to the destination, in the order a client reads them, and
// returns the keys it wrote.
//
// The pinned copies, not the source keys. Re-reading the source here is what
// would let a generation that landed during the object copy be published over
// an object set nobody enumerated — the fault this whole path exists to
// prevent, reintroduced one line from the end.
func (m *mover) publishFreeBSDRoots(ctx context.Context, pin string, pm *manifest.PackageManifest, ve manifest.VersionEntry, label string) ([]string, error) {
	var written []string
	for _, name := range manifest.FreeBSDCatalogFiles {
		key := manifest.FreeBSDKey(ve.Version, pm.Name, name)
		local := filepath.Join(pin, name)
		info, err := os.Stat(local)
		if err != nil {
			return written, fmt.Errorf("%s: read the copied %s: %w", label, name, err)
		}
		fmt.Fprintf(m.out, "  %s: publishing %s on %q\n", label, key, m.dstName)
		if err := m.dst.PutFile(ctx, local, key); err != nil {
			return written, fmt.Errorf("%s: write %s to %q: %w", label, key, m.dstName, err)
		}
		if err := m.verify(ctx, key, info.Size(), ve, name == manifest.FreeBSDCatalogFile); err != nil {
			return written, fmt.Errorf("%s: %w", label, err)
		}
		written = append(written, key)
	}
	return written, nil
}

// spoolObject streams one object out of store into dest and returns its size.
// The file outlives the call, which is what separates it from copyObject: a
// repository publication reads its archives after writing everything they
// name, and reading them again from the backend would defeat the point.
func spoolObject(ctx context.Context, store storage.ObjectStore, key, dest string) (int64, error) {
	stream, err := store.GetStream(ctx, key)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", key, err)
	}
	if stream == nil {
		return 0, fmt.Errorf("read %s: it is not there", key)
	}
	defer func() { _ = stream.Body.Close() }()

	f, err := os.Create(dest) //nolint:gosec // G304: composed by pinFreeBSDRoots under the spool dir.
	if err != nil {
		return 0, fmt.Errorf("stage %s: %w", key, err)
	}
	n, copyErr := io.Copy(f, stream.Body)
	closeErr := f.Close()
	if copyErr != nil {
		return 0, fmt.Errorf("copy %s: %w", key, copyErr)
	}
	if closeErr != nil {
		return 0, fmt.Errorf("close the copy of %s: %w", key, closeErr)
	}
	return n, nil
}
