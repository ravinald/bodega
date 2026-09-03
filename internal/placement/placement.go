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
	name := WritePlacement(p.stores, typ, pm.StoragePolicy).Name
	if recorded != "" && !p.replace {
		name = recorded
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
// A per-package storage_policy is deliberately not consulted. One directory
// goes to one prefix, so honoring a policy for some packages of the type and
// not others would split the tree exactly the way the refusal below exists to
// prevent. See DirectoryPlaced: 'bodega pkg move' refuses pypi for the same
// reason, so the whole type moves or none of it does.
func (p *Placer) ForType(ctx context.Context, typ string) (storage.ObjectStore, error) {
	name := WritePlacement(p.stores, typ, "").Name

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
// Resolver.Placement answers the three-level hierarchy in the abstract.
// Whole-directory types never reach the package level, so asking it with a
// policy it will not honor produces an answer no upload would ever act on —
// which is what 'bodega pkg storage' was printing. The skipped policy travels
// on the Decision so a caller can name it instead of quietly dropping it.
func WritePlacement(stores storage.Resolver, typ, policy string) storage.Decision {
	if !DirectoryPlaced(typ) {
		return stores.Placement(typ, policy)
	}
	d := stores.Placement(typ, "")
	d.IgnoredPolicy = policy
	return d
}

// StoragePolicyWarning reports a storage_policy the write path will never
// consult. Recording an inert field without comment is how an operator comes
// to believe a package has been placed when nothing about it moved.
func StoragePolicyWarning(typ, policy string) string {
	return admit.StoragePolicyWarning(typ, policy)
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
func (p *Placer) UploadPaths(ctx context.Context, typ string, paths []builder.ArtifactPath) (int, error) {
	n := 0
	for _, ap := range paths {
		st, err := p.ForVersion(ctx, typ, ap.Package, ap.Version, ap.S3Key)
		if err != nil {
			return n, err
		}
		fmt.Fprintf(p.out, "    upload: %s/%s\n", st.Label(), ap.S3Key)
		if err := st.PutFile(ctx, ap.Local, ap.S3Key); err != nil {
			return n, fmt.Errorf("upload %s %s: %w", typ, ap.Local, err)
		}
		n++
	}
	return n, nil
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

	paths := ArtifactPaths(bcfg, p.store, typ, "")
	if len(paths) == 0 {
		fmt.Fprintf(p.out, "    No local %s artifacts found — skipping\n", typ)
		return 0, nil
	}
	return p.UploadPaths(ctx, typ, paths)
}

// ArtifactPaths returns every local artifact of one type that is ready to
// upload, per version. entryFilter limits the walk to one package.
//
// pypi is absent on purpose and returns nothing: its wheels have no
// per-version object key, so they upload through ForType and SyncDir. Every
// other type answers here, which is what lets one caller cover all eight.
func ArtifactPaths(cfg *builder.Config, store *manifest.Store, typ, entryFilter string) []builder.ArtifactPath {
	switch typ {
	case manifest.TypeBinary:
		return builder.BinaryArtifactPaths(cfg, store, entryFilter)
	case manifest.TypeGit:
		return builder.GitArtifactPaths(cfg, store, entryFilter)
	case manifest.TypeApt:
		return builder.AptArtifactPaths(cfg, store, entryFilter)
	case manifest.TypeGomod:
		return builder.GomodArtifactPaths(cfg, store, entryFilter)
	case manifest.TypeHelm:
		return builder.HelmArtifactPaths(cfg, store, entryFilter)
	case manifest.TypeNpm:
		return builder.NpmArtifactPaths(cfg, store, entryFilter)
	case manifest.TypeCargo:
		return builder.CargoArtifactPaths(cfg, store, entryFilter)
	}
	return nil
}
