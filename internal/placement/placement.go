// Package placement decides which storage backend an upload writes to, and
// records that decision on the version entry before any bytes move.
//
// Placement and resolution are separate questions. The config hierarchy
// answers "where does the next write go?"; the name recorded here answers
// "where does this artifact already live?". Nothing on the read path may
// consult the hierarchy, or a rule change would orphan everything already
// uploaded.
//
// It is an internal package rather than a file in cmd/bodega because the TUI
// uploads too. A second copy of this logic behind the TUI's own switch is
// what let it write every type to the default bucket while the CLI honored
// storage_by_type, with nothing reporting the disagreement.
package placement

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// Placer routes upload writes and keeps the manifest's record of them honest.
type Placer struct {
	stores  storage.Resolver
	store   *manifest.Store
	out     io.Writer
	replace bool // --replace-placement: apply the current rule to already-placed versions
	pin     *pin // --storage: one version's write goes here, whatever the rule says
	only    string
}

// pin is one version's write-time backend, named on the command line.
//
// It is a flag rather than a fourth level of the hierarchy, and the two differ
// on the next upload of the same package. A flag records a name once; from
// there the existing "a recorded name wins over the rule" rule in ForVersion
// carries it, so the following upload writes to the same backend without the
// flag and without anything still deciding. A fourth level would need a
// per-version rule that outranks the record at every future upload, which is
// --replace-placement permanently on for that one version — and it would have
// to live somewhere config can hold it, which is the one place per-version
// state does not belong.
//
// applied is what separates "the operator named a version and it was written"
// from "the operator named a version this run never reached". Without it a
// mistyped version writes to the rule's backend and reports success.
type pin struct {
	pkg     string
	version string
	backend string
	applied bool
}

// matches reports whether this pin names ve, under the same rule VersionIndex
// uses: Version or Ref.
func (p *pin) matches(pkg string, ve manifest.VersionEntry) bool {
	if p == nil || p.pkg != pkg {
		return false
	}
	return ve.Version == p.version || (ve.Ref != "" && ve.Ref == p.version)
}

// New builds the resolver described by cfg and wraps it for upload use.
func New(ctx context.Context, cfg *config.Config, store *manifest.Store, out io.Writer, replace bool) (*Placer, error) {
	stores, err := storage.NewResolver(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect to storage: %w", err)
	}
	return &Placer{stores: stores, store: store, out: out, replace: replace}, nil
}

// NewWith wraps a resolver the caller already built. The TUI holds one for its
// status pane, and building a second here would give one process two views of
// the same backends.
func NewWith(stores storage.Resolver, store *manifest.Store, out io.Writer, replace bool) *Placer {
	return &Placer{stores: stores, store: store, out: out, replace: replace}
}

// PlaceVersion directs the next write of one version at a named backend,
// overriding every level of the placement hierarchy and the name already
// recorded. See pin for why this is a flag and not a fourth level.
//
// Whole-directory types are refused by the command layer before they reach
// here: a pypi version has no object of its own to place.
func (p *Placer) PlaceVersion(pkg, version, backend string) {
	p.pin = &pin{pkg: pkg, version: version, backend: backend}
}

// Only restricts UploadType to one package's artifacts. Empty, the default,
// uploads every package of the type.
func (p *Placer) Only(pkg string) { p.only = pkg }

// PlacedVersion reports whether the version named by PlaceVersion was reached.
// False after a run means the artifact was never uploaded, so the backend the
// operator named was never written to.
func (p *Placer) PlacedVersion() bool { return p.pin != nil && p.pin.applied }

// Stores exposes the resolver the placer was built over, for a caller that
// needs to reach a backend by name rather than by placement.
func (p *Placer) Stores() storage.Resolver { return p.stores }

// ForVersion returns the backend to write this artifact to, having first
// recorded that backend on the version entry.
//
// An already-recorded name wins over the current rule. Re-resolving would
// write new bytes to a new backend while the manifest still named the old one:
// two divergent copies, reads serving whichever the manifest points at, and an
// upload that reported success. --replace-placement is the deliberate case.
//
// An artifact with no manifest entry (a generated index, a packument) is
// regenerable and routed by type.
func (p *Placer) ForVersion(ctx context.Context, typ, pkg, version, key string) (storage.ObjectStore, error) {
	if pkg == "" {
		return p.stores.ForType(typ), nil
	}
	pm, err := p.store.GetPackage(ctx, typ, pkg)
	if err != nil || pm == nil {
		return p.stores.ForType(typ), nil
	}
	i := VersionIndex(pm, version)
	if i < 0 {
		return p.stores.ForType(typ), nil
	}

	// An empty record is "default" when reading, because that is where the
	// bytes are. When writing it is "nothing was ever recorded", so the rule
	// decides — otherwise storage_by_type could never take effect on a version
	// that predates it. The manifest is written before the bytes either way,
	// so the record and the newest copy always agree.
	recorded := pm.Versions[i].Storage
	name := WritePlacement(p.stores, typ, pm.StoragePolicy, pm.StorageGroups).Name
	if recorded != "" && !p.replace {
		name = recorded
	}
	// Last, so it beats both the rule and the recorded name: an operator
	// naming a backend for one artifact is answering a question neither of
	// those can be asked. record() below still warns about the copy left at
	// the old placement, which is the whole difference between this and a
	// hand edit of the manifest.
	if p.pin.matches(pm.Name, pm.Versions[i]) {
		name = p.pin.backend
		p.pin.applied = true
	}
	if err := p.record(ctx, pm, i, name, key); err != nil {
		return nil, err
	}
	return p.stores.ByName(name)
}

// ForType returns the backend for a whole-directory upload, having recorded it
// on every version entry of that type.
//
// pypi is the only type left here. Its wheels have no per-version object key
// at all — the PEP 503 index is generated from a listing over the whole tree —
// so a rule changed between two runs would strand half a tree in the old
// backend with nothing to find it again. Refuse instead, naming the versions
// that would need moving.
//
// Neither a per-package storage_policy nor a group rule is consulted. One
// directory goes to one prefix, so honoring either for some packages of the
// type and not others would split the tree exactly the way the refusal below
// exists to prevent. See DirectoryPlaced: 'bodega pkg move' refuses pypi for the same
// reason, so the whole type moves or none of it does.
func (p *Placer) ForType(ctx context.Context, typ string) (storage.ObjectStore, error) {
	name := WritePlacement(p.stores, typ, "", nil).Name

	var stranded []string
	for _, pkg := range p.store.ListPackages(typ) {
		pm, err := p.store.GetPackage(ctx, typ, pkg)
		if err != nil || pm == nil {
			continue
		}
		for i := range pm.Versions {
			if EffectiveStorage(pm.Versions[i].Storage) == name {
				continue
			}
			stranded = append(stranded, fmt.Sprintf("%s@%s (on %q)",
				pkg, VersionLabel(pm.Versions[i]), EffectiveStorage(pm.Versions[i].Storage)))
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
func (p *Placer) record(ctx context.Context, pm *manifest.PackageManifest, i int, name, key string) error {
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
				pm.Name, VersionLabel(pm.Versions[i]), name, EffectiveStorage(old))
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
func (p *Placer) strandedAt(ctx context.Context, recorded, key string) (bool, error) {
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

// DirectoryPlaced reports whether a type's artifacts reach storage as a whole
// directory rather than one object per version.
//
// pypi is the last one. Two rules follow from it: the package level of the
// placement hierarchy is not consulted for pypi, and 'bodega pkg move' refuses
// it. A package placed apart from the rest of its type splits a tree with
// nothing to reunite it, and pypi has no per-version object key at all.
func DirectoryPlaced(typ string) bool {
	return admit.DirectoryPlaced(typ)
}

// WritePlacement resolves the backend the write path will actually target.
//
// Resolver.Placement answers the four-level hierarchy in the abstract.
// Whole-directory types never reach the package level or the group level, so
// asking it with a policy or a membership it will not honor produces an answer
// no upload would ever act on — which is what 'bodega pkg storage' was
// printing. Both skipped rules travel on the Decision so a caller can name
// them instead of quietly dropping them.
//
// The group level is dropped for the same reason the package level is, not for
// a weaker one: a group holds packages across types, so honoring it for a pypi
// package would place that package's wheels apart from the tree the PEP 503
// index is a listing over. Set storage_by_type.pypi to place the whole type.
func WritePlacement(stores storage.Resolver, typ, policy string, groups []string) storage.Decision {
	if !DirectoryPlaced(typ) {
		return stores.Placement(typ, policy, groups)
	}
	d := stores.Placement(typ, "", nil)
	d.IgnoredPolicy = policy
	// Only a group that would have decided is reported. Naming every group the
	// package belongs to would report a membership that changes nothing here
	// even on an install with no storage_by_group at all.
	if g := stores.Placement(typ, "", groups); g.Level == storage.LevelGroup {
		d.IgnoredGroup = g.Group
	}
	return d
}

// StoragePolicyWarning reports a storage_policy the write path will never
// consult. Recording an inert field without comment is how an operator comes
// to believe a package has been placed when nothing about it moved.
func StoragePolicyWarning(typ, policy string) string {
	return admit.StoragePolicyWarning(typ, policy)
}

// StorageGroupWarning reports a group rule the write path will never consult,
// for the same reason and on the same terms.
func StorageGroupWarning(typ, group string) string {
	return admit.StorageGroupWarning(typ, group)
}

// NoPerPackagePlacement says why one type cannot carry a per-package
// placement, in whichever terms that type's operator will recognize.
func NoPerPackagePlacement(typ string) string {
	return admit.NoPerPackagePlacement(typ)
}

// EffectiveStorage applies the empty-means-default rule. It is the only place
// a bare VersionEntry.Storage should be compared against a backend name.
func EffectiveStorage(recorded string) string {
	if recorded == "" {
		return storage.DefaultName
	}
	return recorded
}

// VersionIndex finds the entry matching v by Version or Ref, mirroring
// ScopeToVersion. Returns -1 when nothing matches.
func VersionIndex(pm *manifest.PackageManifest, v string) int {
	for i, ve := range pm.Versions {
		if ve.Version == v || (v != "" && ve.Ref == v) {
			return i
		}
	}
	return -1
}

// VersionLabel names an entry for an operator: Version, else Ref, else "?".
func VersionLabel(ve manifest.VersionEntry) string {
	if ve.Version != "" {
		return ve.Version
	}
	if ve.Ref != "" {
		return ve.Ref
	}
	return "?"
}

// UploadPaths writes each artifact to the backend its own version entry
// records, recording that backend before the bytes move, and returns the
// number of objects written.
//
// One loop for every type. The command layer and the TUI each carried their
// own, and the TUI's wrote every type to the default bucket because its copy
// never grew a placement lookup. An artifact with no manifest entry — a helm
// index.yaml, an npm packument — leaves Package empty and is routed by type,
// which ForVersion already handles.
//
// Each artifact resolves its own backend, except for a set-placed type: see
// destination for the one version of that rule a published freebsd repository
// cannot survive.
func (p *Placer) UploadPaths(ctx context.Context, typ string, paths []builder.ArtifactPath) (int, error) {
	n := 0
	bound := map[versionRef]storage.ObjectStore{}
	for _, ap := range paths {
		st, err := p.destination(ctx, typ, ap, bound)
		if err != nil {
			return n, err
		}
		fmt.Fprintf(p.out, "    upload: %s/%s\n", st.Label(), ap.ObjectKey)
		if err := st.PutFile(ctx, ap.Local, ap.ObjectKey); err != nil {
			return n, fmt.Errorf("upload %s %s: %w", typ, ap.Local, err)
		}
		n++
	}
	return n, nil
}

// versionRef names one version of one package, which is the unit a set-placed
// type publishes as.
type versionRef struct{ pkg, version string }

// setPlaced reports whether one version of typ reaches storage as a set of
// objects that is only meaningful whole.
//
// freebsd is the only one, and it is not the same property DirectoryPlaced
// names. A pypi tree has no per-version key at all; a freebsd repository has
// one key per object and a catalogue listing every one of them, so the
// catalogue is valid in exactly one place: a backend already holding what it
// names. Every other type's artifact stands on its own, apt's generated
// indexes included — those are rebuilt from the backend rather than pinned to
// a set enumerated somewhere else.
func setPlaced(typ string) bool { return typ == manifest.TypeFreeBSD }

// destination returns the backend ap is written to, resolving a set-placed
// version once and holding that answer for the rest of the upload.
//
// ForVersion reads the manifest on every call and follows the Storage it
// finds there. For a type whose artifacts stand alone that is the right
// answer: an operator repointing a version mid-upload leaves each file at
// whatever its own record said when that file went, and each file is
// separately complete. For freebsd it is a hole wide enough to break a
// published repository. The object set and the three repository-root files
// are one publication, so re-resolving between them let a placement edit land
// the objects in the backend the run established and the catalogue in a
// different one, replacing that backend's complete generation with a
// catalogue whose packages were written somewhere else. Both uploads return
// a file count and no error; the client is what finds out, when it resolves a
// package out of the catalogue it just read and gets a 404.
//
// Held rather than re-checked and refused. A refusal would throw away a
// generation that is whole where this run put it, over an edit that is about
// the next upload rather than this one. The edit still wins where it is asked
// to: the manifest keeps the operator's new name, so the following upload
// writes the whole set there.
func (p *Placer) destination(ctx context.Context, typ string, ap builder.ArtifactPath, bound map[versionRef]storage.ObjectStore) (storage.ObjectStore, error) {
	if !setPlaced(typ) || ap.Package == "" {
		return p.ForVersion(ctx, typ, ap.Package, ap.Version, ap.ObjectKey)
	}
	ref := versionRef{pkg: ap.Package, version: ap.Version}
	if st, ok := bound[ref]; ok {
		return st, nil
	}
	st, err := p.ForVersion(ctx, typ, ap.Package, ap.Version, ap.ObjectKey)
	if err != nil {
		return nil, err
	}
	bound[ref] = st
	return st, nil
}

// UploadType writes one type's local artifacts to the backends the manifest
// records, and returns how many objects landed.
//
// pypi is the one type that still syncs a directory: its wheels have no
// per-version object key, so there is nothing to place per package and ForType
// refuses a rule change that would split the tree. Every other type resolves
// one key per version.
func (p *Placer) UploadType(ctx context.Context, bcfg *builder.Config, typ string) (int, error) {
	if typ == manifest.TypePypi {
		if p.only != "" {
			// One pypi package cannot be uploaded apart from the rest of its
			// type: the wheels share a prefix and the PEP 503 index is a
			// listing over the whole tree. Skipping loudly beats uploading
			// every other package the operator did not name.
			fmt.Fprintf(p.out, "    %s — skipping\n", NoPerPackagePlacement(typ))
			return 0, nil
		}
		localDir, keyPrefix := builder.PypiArtifactDir(bcfg, p.store)
		if _, err := os.Stat(localDir); os.IsNotExist(err) {
			fmt.Fprintf(p.out, "    No wheels directory at %s — skipping\n", localDir)
			return 0, nil
		}
		st, err := p.ForType(ctx, typ)
		if err != nil {
			return 0, err
		}
		n, err := st.SyncDir(ctx, p.out, localDir, keyPrefix)
		if err != nil {
			return n, fmt.Errorf("upload pypi: %w", err)
		}
		fmt.Fprintf(p.out, "    Uploaded %d file(s) to %s/%s\n", n, st.Label(), keyPrefix)
		return n, nil
	}

	paths, release, err := ArtifactPaths(bcfg, p.store, typ, p.only)
	if err != nil {
		return 0, err
	}
	defer release()
	if len(paths) == 0 {
		// Naming the directory is what separates "nothing was built" from
		// "this command resolved a different root than the build did".
		fmt.Fprintf(p.out, "    No local %s artifacts found under %s — skipping\n",
			typ, builder.ArtifactDir(bcfg, typ))
		return 0, nil
	}
	return p.UploadPaths(ctx, typ, paths)
}

// ArtifactPaths returns every local artifact of one type that is ready to
// upload, per version, with the release the caller runs once the upload is
// over. entryFilter limits the walk to one package.
//
// The release and the error are freebsd's. Its paths are not a plain walk of
// the tree: the catalogue archives are pinned first, so that the upload writes
// the generation it enumerated rather than whichever one a concurrent mirror
// has published by the time PutFile opens the file. Every other type reads
// files nothing rewrites underneath it, so each returns a no-op release and no
// error. pypi is absent on purpose and returns nothing: its wheels have no
// per-version object key, so they upload through ForType and SyncDir.
func ArtifactPaths(cfg *builder.Config, store *manifest.Store, typ, entryFilter string) ([]builder.ArtifactPath, func(), error) {
	noRelease := func() {}
	switch typ {
	case manifest.TypeBinary:
		return builder.BinaryArtifactPaths(cfg, store, entryFilter), noRelease, nil
	case manifest.TypeGit:
		return builder.GitArtifactPaths(cfg, store, entryFilter), noRelease, nil
	case manifest.TypeApt:
		return builder.AptArtifactPaths(cfg, store, entryFilter), noRelease, nil
	case manifest.TypeGomod:
		return builder.GomodArtifactPaths(cfg, store, entryFilter), noRelease, nil
	case manifest.TypeHelm:
		return builder.HelmArtifactPaths(cfg, store, entryFilter), noRelease, nil
	case manifest.TypeNpm:
		return builder.NpmArtifactPaths(cfg, store, entryFilter), noRelease, nil
	case manifest.TypeCargo:
		return builder.CargoArtifactPaths(cfg, store, entryFilter), noRelease, nil
	case manifest.TypeFreeBSD:
		return builder.FreeBSDArtifactPaths(cfg, store, entryFilter)
	}
	return nil, noRelease, nil
}
