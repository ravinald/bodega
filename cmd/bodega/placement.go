package main

// placement.go decides which storage backend an upload writes to, and records
// that decision on the version entry before any bytes move.
//
// Placement and resolution are separate questions. The config hierarchy
// answers "where does the next write go?"; the name recorded here answers
// "where does this artifact already live?". Nothing on the read path may
// consult the hierarchy, or a rule change would orphan everything already
// uploaded.

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// placer routes upload writes and keeps the manifest's record of them honest.
type placer struct {
	stores  storage.Resolver
	store   *manifest.Store
	out     io.Writer
	replace bool // --replace-placement: apply the current rule to already-placed versions
}

// newPlacer builds the resolver described by cfg and wraps it for upload use.
func newPlacer(ctx context.Context, cfg *config.Config, store *manifest.Store, out io.Writer, replace bool) (*placer, error) {
	stores, err := storage.NewResolver(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect to storage: %w", err)
	}
	return &placer{stores: stores, store: store, out: out, replace: replace}, nil
}

// forVersion returns the backend to write this artifact to, having first
// recorded that backend on the version entry.
//
// An already-recorded name wins over the current rule. Re-resolving would
// write new bytes to a new backend while the manifest still named the old one:
// two divergent copies, reads serving whichever the manifest points at, and an
// upload that reported success. --replace-placement is the deliberate case.
//
// An artifact with no manifest entry (a generated index, a packument) is
// regenerable and routed by type.
func (p *placer) forVersion(ctx context.Context, typ, pkg, version, key string) (storage.ObjectStore, error) {
	if pkg == "" {
		return p.stores.ForType(typ), nil
	}
	pm, err := p.store.GetPackage(ctx, typ, pkg)
	if err != nil || pm == nil {
		return p.stores.ForType(typ), nil
	}
	i := versionIndex(pm, version)
	if i < 0 {
		return p.stores.ForType(typ), nil
	}

	// An empty record is "default" when reading, because that is where the
	// bytes are. When writing it is "nothing was ever recorded", so the rule
	// decides — otherwise storage_by_type could never take effect on a version
	// that predates it. The manifest is written before the bytes either way,
	// so the record and the newest copy always agree.
	recorded := pm.Versions[i].Storage
	name := writePlacement(p.stores, typ, pm.StoragePolicy).Name
	if recorded != "" && !p.replace {
		name = recorded
	}
	if err := p.record(ctx, pm, i, name, key); err != nil {
		return nil, err
	}
	return p.stores.ByName(name)
}

// forType returns the backend for a whole-directory upload, having recorded it
// on every version entry of that type.
//
// SyncDir has no per-version granularity and git is served with no listing to
// fan out over, so a rule changed between two runs would strand half a tree in
// the old backend with nothing to find it again. Refuse instead, naming the
// versions that would need moving.
//
// A per-package storage_policy is deliberately not consulted here. SyncDir
// uploads one directory to one prefix, so honoring a policy for some packages
// of the type and not others would split the tree exactly the way the refusal
// below exists to prevent. See directoryPlaced: 'bodega pkg move' refuses
// these types for the same reason, so a whole type moves or none of it does.
func (p *placer) forType(ctx context.Context, typ string) (storage.ObjectStore, error) {
	name := writePlacement(p.stores, typ, "").Name

	var stranded []string
	for _, pkg := range p.store.ListPackages(typ) {
		pm, err := p.store.GetPackage(ctx, typ, pkg)
		if err != nil || pm == nil {
			continue
		}
		for i := range pm.Versions {
			if effectiveStorage(pm.Versions[i].Storage) == name {
				continue
			}
			stranded = append(stranded, fmt.Sprintf("%s@%s (on %q)",
				pkg, versionLabel(pm.Versions[i]), effectiveStorage(pm.Versions[i].Storage)))
		}
	}
	sort.Strings(stranded)

	if len(stranded) > 0 && !p.replace {
		// The remedy names --replace-placement and nothing else. "Move those
		// objects" was the other branch until 'pkg move' started refusing
		// these types outright, and offering an operator a command that
		// refuses is worse than offering them one option.
		return nil, fmt.Errorf(
			"storage_by_type[%q] now resolves to %q, but %d %s version(s) are recorded elsewhere:\n  %s\n"+
				"%s uploads whole directories, so proceeding would split the tree across backends with no listing to reunite it.\n"+
				"Pass --replace-placement to repoint the manifest at %q and re-upload; the old copies stay where they are and nothing copies them",
			typ, name, len(stranded), typ, strings.Join(stranded, "\n  "), typ, name)
	}

	for _, pkg := range p.store.ListPackages(typ) {
		pm, err := p.store.GetPackage(ctx, typ, pkg)
		if err != nil || pm == nil {
			continue
		}
		for i := range pm.Versions {
			if err := p.record(ctx, pm, i, name, ""); err != nil {
				return nil, err
			}
		}
	}
	if len(stranded) > 0 {
		fmt.Fprintf(p.out, "    warning: repointed %d %s version(s) to %q; the old objects are still in their previous backend\n",
			len(stranded), typ, name)
	}
	return p.stores.ByName(name)
}

// record writes the backend name to the manifest before the upload runs. That
// order is deliberate: a recorded-but-missing object is a state bodega status
// reports, while an uploaded-but-unrecorded object is invisible.
//
// The default backend is stored as the zero value rather than as the literal
// "default", which is what keeps an existing manifest byte-identical when
// nothing about its placement changed.
//
// When key is non-empty and a copy already sits at the old placement, say so.
// The new copy is what every read will reach, but the old one still occupies
// space and nothing else will ever mention it.
func (p *placer) record(ctx context.Context, pm *manifest.PackageManifest, i int, name, key string) error {
	want := name
	if want == storage.DefaultName {
		want = ""
	}
	old := pm.Versions[i].Storage
	if old == want {
		return nil
	}
	if key != "" {
		if left, err := p.strandedAt(ctx, old, key); err == nil && left {
			fmt.Fprintf(p.out, "    warning: %s@%s moves to %q; the copy in %q is left behind\n",
				pm.Name, versionLabel(pm.Versions[i]), name, effectiveStorage(old))
		}
	}
	pm.Versions[i].Storage = want
	if err := p.store.SavePackage(ctx, pm); err != nil {
		return fmt.Errorf("record storage backend for %s/%s: %w", pm.Type, pm.Name, err)
	}
	return nil
}

// strandedAt reports whether an object already sits at key on the backend a
// version is moving away from. Probed rather than assumed: a version that was
// never uploaded strands nothing, and warning about it on every first upload
// under a new rule would train operators to ignore the line.
func (p *placer) strandedAt(ctx context.Context, recorded, key string) (bool, error) {
	store, err := p.stores.ByName(recorded)
	if err != nil {
		return false, err
	}
	info, err := store.Head(ctx, key)
	if err != nil || info == nil {
		return false, err
	}
	return info.Exists, nil
}

// directoryPlaced reports whether a type's artifacts reach storage as a whole
// directory rather than one object per version.
//
// SyncDir uploads one tree to one prefix, so these three have no per-version
// granularity at either end. Two rules follow: the package level of the
// placement hierarchy is not consulted for them, and 'bodega pkg move' refuses
// them. A package placed apart from the rest of its type splits a tree with
// nothing to reunite it — git and apt are served with no listing to fan out
// over, and pypi has no per-version object key at all.
func directoryPlaced(typ string) bool {
	switch typ {
	case manifest.TypeApt, manifest.TypeGit, manifest.TypePypi:
		return true
	}
	return false
}

// noPerPackagePlacement says why one type cannot carry a per-package
// placement, in whichever terms that type's operator will recognize.
func noPerPackagePlacement(typ string) string {
	if typ == manifest.TypePypi {
		return "pypi wheels upload as a directory with no per-version object key"
	}
	return typ + " uploads whole directories with SyncDir, so one package cannot be placed apart from the rest of its type"
}

// writePlacement resolves the backend the write path will actually target.
//
// Resolver.Placement answers the three-level hierarchy in the abstract.
// Whole-directory types never reach the package level, so asking it with a
// policy it will not honor produces an answer no upload would ever act on —
// which is what 'bodega pkg storage' was printing. The skipped policy travels
// on the Decision so a caller can name it instead of quietly dropping it.
func writePlacement(stores storage.Resolver, typ, policy string) storage.Decision {
	if !directoryPlaced(typ) {
		return stores.Placement(typ, policy)
	}
	d := stores.Placement(typ, "")
	d.IgnoredPolicy = policy
	return d
}

// storagePolicyWarning reports a storage_policy the write path will never
// consult. Recording an inert field without comment is how an operator comes
// to believe a package has been placed when nothing about it moved.
func storagePolicyWarning(typ, policy string) string {
	if policy == "" || !directoryPlaced(typ) {
		return ""
	}
	return fmt.Sprintf("warning: storage_policy %q has no effect for %s: %s. "+
		"Set storage_by_type.%s to place the whole type; 'bodega pkg move' refuses %s for the same reason.",
		policy, typ, noPerPackagePlacement(typ), typ, typ)
}

// effectiveStorage applies the empty-means-default rule. It is the only place
// a bare VersionEntry.Storage should be compared against a backend name.
func effectiveStorage(recorded string) string {
	if recorded == "" {
		return storage.DefaultName
	}
	return recorded
}

// versionIndex finds the entry matching v by Version or Ref, mirroring
// ScopeToVersion. Returns -1 when nothing matches.
func versionIndex(pm *manifest.PackageManifest, v string) int {
	for i, ve := range pm.Versions {
		if ve.Version == v || (v != "" && ve.Ref == v) {
			return i
		}
	}
	return -1
}

// versionLabel names an entry for an operator: Version, else Ref, else "?".
func versionLabel(ve manifest.VersionEntry) string {
	if ve.Version != "" {
		return ve.Version
	}
	if ve.Ref != "" {
		return ve.Ref
	}
	return "?"
}
