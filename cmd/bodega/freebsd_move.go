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

// A freebsd version is a whole repository, so moving one is a publication
// rather than a copy of a list of objects. Which publication depends on where
// the catalogue comes from: a mirrored repository carries its three root files
// in the backend and this file's first half moves them, while a generated one
// has none — the server builds them per request from whatever backend the
// manifest names — and moveFreeBSDGenerated moves its packages alone.
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
	generated, err := ve.FreeBSDGenerated()
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if generated {
		return m.moveFreeBSDGenerated(ctx, pm, i, src, srcName, label)
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

// moveFreeBSDGenerated relocates a repository whose catalogue bodega builds.
//
// Its packages are the whole of it. meta.conf, data.pkg and packagesite.pkg
// are produced per request from whatever backend the manifest names, so there
// is nothing to pin, nothing to publish last and no generation to keep
// together: the listing under the repository prefix is the document, and the
// move's job is to make the destination's listing equal the source's.
//
// That inverts one rule and keeps the other two. A mirror enumerates from its
// archives because a prefix listing is not the set a published catalogue
// names; here the listing is the only thing that names anything, and the
// catalogue is derived from it after the move. The manifest still changes
// last, and the source is still left alone unless --delete-source says
// otherwise.
//
// Two windows are closed rather than documented. The destination is asked
// first whether it already holds objects under this prefix that the source
// does not: those would be packages in the destination's generated catalogue
// the moment the manifest points at it, which is a repository growing a
// package nobody uploaded. And the source is listed again after the copy,
// because an upload landing mid-move would otherwise leave the new packages on
// the backend the manifest is about to stop naming, with both commands
// reporting success.
func (m *mover) moveFreeBSDGenerated(ctx context.Context, pm *manifest.PackageManifest, i int, src storage.ObjectStore, srcName, label string) error {
	ve := pm.Versions[i]
	prefix := manifest.FreeBSDRepoPrefix(ve.Version, pm.Name)

	keys, err := src.List(ctx, prefix)
	if err != nil {
		return fmt.Errorf("%s: list %s on %q: %w", label, prefix, srcName, err)
	}
	if len(keys) == 0 {
		return fmt.Errorf("%s: %q holds no object under %s, so there is no repository to move. "+
			"Run `bodega build upload freebsd %s` against %q first", label, srcName, prefix, pm.Name, srcName)
	}
	// Sorted rather than trusted-sorted: the comparison below is against
	// another listing, and one backend answering in walk order would make a
	// repository that did not change look like one that did.
	slices.Sort(keys)

	// Cheap precondition before the expensive operation, and the one check a
	// mirror does not need: its catalogue would simply not name a stranger,
	// while a generated catalogue is the listing and names every one of them.
	strangers, err := freeBSDForeignObjects(ctx, m.dst, prefix, keys)
	if err != nil {
		return fmt.Errorf("%s: list %s on %q: %w", label, prefix, m.dstName, err)
	}
	if len(strangers) > 0 {
		return fmt.Errorf("%s: %q already holds %d object(s) under %s that %q does not, the first being %s. "+
			"A generated catalogue is built from whatever is under the prefix, so the moved repository would publish them as packages nobody uploaded. "+
			"Nothing was written to %q and the manifest still points at %q: remove them, or move to a backend that is not already serving this repository",
			label, m.dstName, len(strangers), prefix, srcName, strangers[0], m.dstName, srcName)
	}

	fmt.Fprintf(m.out, "  %s: %q holds %d package object(s) under %s\n", label, srcName, len(keys), prefix)
	var moved []string
	for _, key := range keys {
		info, err := src.Head(ctx, key)
		if err != nil {
			return fmt.Errorf("%s: head %s on %q: %w", label, key, srcName, err)
		}
		if !info.Exists {
			return fmt.Errorf("%s: %s was listed on %q and is gone, so a delete is running against this repository. "+
				"Nothing was committed and the manifest still points at %q: move again once it has finished",
				label, key, srcName, srcName)
		}
		fmt.Fprintf(m.out, "  %s: %s -> %s (%s)\n", label, srcName, m.dstName, key)
		size, err := m.copyObject(ctx, src, key)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		// Never the primary: the manifest records a size and a digest for a
		// mirrored catalogue, and a generated repository has no such object
		// for them to describe.
		if err := m.verify(ctx, key, size, ve, false); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		moved = append(moved, key)
	}

	after, err := src.List(ctx, prefix)
	if err != nil {
		return fmt.Errorf("%s: re-list %s on %q: %w", label, prefix, srcName, err)
	}
	slices.Sort(after)
	if !slices.Equal(after, keys) {
		return fmt.Errorf("%s: the object set under %s on %q changed while the move was copying it (%d object(s) before, %d now). "+
			"Committing would point the manifest at %q while the packages that landed in between are on %q, and the catalogue is built from whichever backend the manifest names. "+
			"Nothing was committed and the manifest still points at %q: move again once the upload has finished",
			label, prefix, srcName, len(keys), len(after), m.dstName, srcName, srcName)
	}

	// No ordering claim on the removal, because there is no document on the
	// source for a client to read a stale object list out of: the catalogue
	// is built from the backend the manifest names, and by here that is the
	// destination. Reversed only so two runs delete in the same sequence.
	removal := slices.Clone(moved)
	slices.Reverse(removal)
	return m.commit(ctx, pm, i, label, srcName, src, removal)
}

// freeBSDForeignObjects is every key under prefix on store that want does not
// hold. want must be sorted.
func freeBSDForeignObjects(ctx context.Context, store storage.ObjectStore, prefix string, want []string) ([]string, error) {
	have, err := store.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, key := range have {
		if _, found := slices.BinarySearch(want, key); !found {
			out = append(out, key)
		}
	}
	slices.Sort(out)
	return out, nil
}
