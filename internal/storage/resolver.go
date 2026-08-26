package storage

import (
	"context"
	"fmt"
)

// DefaultName is the reserved name of the backend described by the global
// storage_backend / storage_path / bucket / region keys. Every artifact
// uploaded before named backends existed lives there, which is why an empty
// recorded name resolves here rather than through the config hierarchy.
const DefaultName = "default"

// NamedStore pairs a backend with the name recorded for artifacts written to
// it. Fan-out results carry the name so a per-backend failure can be reported
// against a place an operator can act on.
type NamedStore struct {
	Name  string
	Store ObjectStore
}

// Resolver answers two different questions with two different methods, and
// keeping them apart is the whole point of the type.
//
// Placement answers "where should the next write go?" and consults the config
// hierarchy. Resolution answers "where does this artifact already live?" and
// consults the name recorded on VersionEntry.Storage when the artifact was
// written. So Placement returns a *name* — the caller records it — and ByName
// takes one.
//
// Answering a read from the hierarchy is the failure this shape exists to
// prevent: change a placement rule and everything already uploaded is still in
// the old backend, so a resolver that reads config looks in the new one, finds
// nothing, and serves 404 for content that exists. A single
// For(typ, pkg) ObjectStore would make that mistake the easy thing to type.
//
// Resolver deliberately does not implement ObjectStore. A prefix-routing
// multiplexer looks like the obvious shortcut and is wrong twice: a key prefix
// carries the artifact's type but neither its package nor its version, so it
// cannot implement a per-package placement rule at all, and it would silently
// turn every List into a fan-out at call sites that never asked for one.
type Resolver interface {
	// Default returns the backend named DefaultName.
	Default() ObjectStore

	// ByName returns the named backend. "" means DefaultName — see the
	// VersionEntry.Storage contract above. An unknown name is an error, not a
	// silent fallback to the default: falling back would serve the wrong
	// bytes under a digest recorded against another backend.
	ByName(name string) (ObjectStore, error)

	// Placement returns the *name* of the backend the next write for this
	// type and package should target. Callers record the returned name
	// alongside the artifact.
	Placement(typ, pkg string) string

	// ForType returns the backend for objects that carry no recorded name:
	// generated indexes, the GPG key, proxy-cache entries and attestation
	// blobs. Safe only because every one of them is regenerable.
	ForType(typ string) ObjectStore

	// Fanout returns every backend a read of this type may have to consult.
	// Listing endpoints union the results; a per-backend error fails the
	// request rather than serving a partial index, which a client cannot
	// distinguish from packages having been removed.
	Fanout(ctx context.Context, typ string) []NamedStore

	// All returns every configured backend, for diagnostics that report per
	// backend rather than aggregating.
	All() []NamedStore
}

// single is a Resolver over exactly one backend. Every method that would
// consult the config hierarchy answers DefaultName.
type single struct {
	store ObjectStore
}

// NewSingle wraps one ObjectStore as the default backend.
func NewSingle(store ObjectStore) Resolver {
	return &single{store: store}
}

func (r *single) Default() ObjectStore { return r.store }

func (r *single) ByName(name string) (ObjectStore, error) {
	if name == "" || name == DefaultName {
		return r.store, nil
	}
	return nil, fmt.Errorf("unknown storage backend %q (configured: %s)", name, DefaultName)
}

func (r *single) Placement(_, _ string) string { return DefaultName }

func (r *single) ForType(_ string) ObjectStore { return r.store }

func (r *single) Fanout(_ context.Context, _ string) []NamedStore { return r.All() }

func (r *single) All() []NamedStore {
	return []NamedStore{{Name: DefaultName, Store: r.store}}
}
