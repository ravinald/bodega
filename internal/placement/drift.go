package placement

// drift.go answers "which versions are not where the rule now says they should
// be?" across the whole catalog.
//
// Placer.ForType already refuses an upload that would strand a directory-placed
// type, but that is one type on one code path: every other type writes to the
// backend its own entry records and reports nothing, so a storage_by_type
// change was invisible on seven of the eight until someone read a manifest.
//
// This reads both sides and resolves neither. It asks Placement for the name
// the rule produces and reads the name the entry recorded, then reports the
// pair; it never calls ByName, ForType or Fanout, opens no backend and returns
// no ObjectStore. That separation is the property the rest of the layer rests
// on — a resolver answering from config serves 404 for content that exists —
// and TestDriftResolvesNothing holds this file to it.

import (
	"context"
	"fmt"

	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// DriftRow is one version whose recorded backend is not the one the placement
// rule now names.
//
// On is where the bytes are, under the empty-means-default rule. Rule is what
// the hierarchy resolves to today. Both are carried because the remedy needs
// each: the operator has to know what they are repointing and to where.
type DriftRow struct {
	Type    string
	Package string
	Version string
	On      string
	Rule    string

	// Frozen changes the remedy rather than the finding. 'pkg move' refuses a
	// frozen version for the whole command, so a row that named the move
	// without naming the unfreeze would hand the operator a command that
	// fails.
	Frozen bool

	// IgnoredPolicy is a package storage_policy the write path will not
	// consult, which happens only for a directory-placed type. It is on the
	// row because a drifted pypi package whose operator set a storage_policy
	// has two things wrong with it and fixing one leaves the other.
	IgnoredPolicy string
}

// DirectoryPlaced reports whether this row's type moves as a whole directory.
func (r DriftRow) DirectoryPlaced() bool { return DirectoryPlaced(r.Type) }

// Remedy names the command that discharges this row, with the arguments that
// would move it.
//
// pypi gets a different sentence rather than a skipped row. Its wheels have no
// per-version object key and 'pkg move' refuses the type outright, so the only
// thing that moves them is the type rule plus a re-upload; printing the move
// command would be offering a command that refuses.
func (r DriftRow) Remedy() string {
	if r.DirectoryPlaced() {
		return fmt.Sprintf("set storage_by_type.%s to %q and re-run 'bodega build upload %s --replace-placement'"+
			" — %s moves as a whole type or not at all",
			r.Type, r.Rule, r.Type, r.Type)
	}
	move := fmt.Sprintf("bodega pkg move %s %s@%s --to %s", r.Type, r.Package, r.Version, r.Rule)
	if r.Frozen {
		return fmt.Sprintf("bodega pkg freeze %s %s   # unfreeze first, then: %s", r.Type, r.Package, move)
	}
	return move
}

// Drift reports every version of the named types whose recorded backend
// differs from the backend the placement hierarchy resolves to now.
//
// stores is consulted for Placement alone. Passing a Resolver is what lets the
// config hierarchy answer; nothing here asks it where anything lives.
//
// A version that records nothing is on the default backend, so it drifts the
// moment a type rule names something else — which is the case that made a
// forgotten storage_by_type invisible. The rows come back in catalog order:
// types as given, packages as the store lists them, versions as the manifest
// holds them.
func Drift(ctx context.Context, stores storage.Resolver, store *manifest.Store, types []string) ([]DriftRow, error) {
	var out []DriftRow
	for _, typ := range types {
		for _, pkg := range store.ListPackages(typ) {
			pm, err := store.GetPackage(ctx, typ, pkg)
			if err != nil {
				return out, fmt.Errorf("get %s/%s: %w", typ, pkg, err)
			}
			if pm == nil {
				continue
			}
			d := WritePlacement(stores, typ, pm.StoragePolicy)
			for _, ve := range pm.Versions {
				on := EffectiveStorage(ve.Storage)
				if on == d.Name {
					continue
				}
				out = append(out, DriftRow{
					Type:          typ,
					Package:       pm.Name,
					Version:       VersionLabel(ve),
					On:            on,
					Rule:          d.Name,
					Frozen:        ve.Frozen,
					IgnoredPolicy: d.IgnoredPolicy,
				})
			}
		}
	}
	return out, nil
}
