package storage

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/ravinald/bodega/internal/config"
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

// Level names which rule of the placement hierarchy chose a backend. Printing
// it is what makes a three-level hierarchy debuggable: "bulk" alone does not
// say whether an operator's package policy took effect or a type rule they
// forgot about did.
type Level int

const (
	// LevelDefault: neither a package policy nor a type rule applied.
	LevelDefault Level = iota
	// LevelType: storage_by_type[typ] decided.
	LevelType
	// LevelPackage: the package manifest's storage_policy decided.
	LevelPackage
)

// Decision is a placement answer: the backend name, and the rule that chose it.
//
// IgnoredPolicy carries a package storage_policy the write path will not
// consult, for the types that upload a whole directory at a time. It is set by
// the caller, which knows how the type reaches storage; storage does not, and
// giving it that knowledge would make a second place answer the question.
// Dropping the policy silently is what made 'bodega pkg storage' print a level
// no upload would ever act on.
type Decision struct {
	Name          string
	Level         Level
	IgnoredPolicy string
}

// Reason renders the deciding rule for an operator, naming the config key the
// type level reads so it can be found and changed.
func (d Decision) Reason(typ string) string {
	var reason string
	switch d.Level {
	case LevelPackage:
		reason = "package policy"
	case LevelType:
		reason = "type rule: storage_by_type." + typ
	default:
		reason = "global default; no type or package rule"
	}
	if d.IgnoredPolicy != "" {
		reason += fmt.Sprintf("; storage_policy %q is not consulted for %s", d.IgnoredPolicy, typ)
	}
	return reason
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

	// Placement returns the backend the next write for this type should
	// target, and the level that decided it. Callers record the returned
	// name alongside the artifact.
	//
	// policy is the package's PackageManifest.StoragePolicy. It arrives as a
	// string rather than being looked up here because storage must never
	// import manifest, and every caller already holds the manifest it came
	// from. Empty means the package has no rule; pass "" for a write that
	// belongs to no package.
	//
	// The most specific rule wins: package policy, then type rule, then the
	// default backend. A package policy that lost to a type rule would be a
	// trap — it is set precisely for the package whose bytes must not go
	// where the rest of its type goes.
	Placement(typ, policy string) Decision

	// ForType returns the backend for objects that carry no recorded name:
	// generated indexes, proxy-cache entries and attestation
	// blobs. Safe only because every one of them is regenerable.
	ForType(typ string) ObjectStore

	// Fanout returns every backend a read of this type may have to consult:
	// the default, the type rule's target, and every name in recorded.
	//
	// recorded is the set of names the manifests hold for this type — both
	// VersionEntry.Storage and PackageManifest.StoragePolicy. It is a
	// parameter because storage must never import manifest, and because
	// config alone cannot answer the question: a package moved to another
	// backend, or placed there by its own policy, is on a backend no config
	// key for this type names.
	//
	// Narrowing matters. Returning every configured backend means one
	// unrelated backend's outage fails every type's index, since a
	// per-backend error fails the request rather than serving a partial one
	// a client cannot distinguish from packages having been removed.
	Fanout(ctx context.Context, typ string, recorded []string) []NamedStore

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

// Placement here returns a package policy verbatim rather than flattening it
// to DefaultName. A policy naming a backend this install does not define is an
// operator error, and ByName reporting it beats writing the bytes somewhere
// the manifest did not ask for.
func (r *single) Placement(_, policy string) Decision {
	if policy != "" {
		return Decision{Name: policy, Level: LevelPackage}
	}
	return Decision{Name: DefaultName, Level: LevelDefault}
}

func (r *single) ForType(_ string) ObjectStore { return r.store }

func (r *single) Fanout(_ context.Context, _ string, _ []string) []NamedStore { return r.All() }

func (r *single) All() []NamedStore {
	return []NamedStore{{Name: DefaultName, Store: r.store}}
}

// multi is a Resolver over the default backend plus every entry in
// storage_backends, with placement decided by storage_by_type.
type multi struct {
	stores map[string]ObjectStore
	byType map[string]string
	names  []string // DefaultName first, then the rest sorted
}

// NewResolver builds the resolver described by the whole config: the default
// backend from the global keys, plus one per storage_backends entry.
//
// config.Load has already rejected a name that collides with the reserved
// default or with a driver, and a storage_by_type value naming nothing, so
// every lookup here can treat its input as valid.
func NewResolver(ctx context.Context, cfg *config.Config) (Resolver, error) {
	def, err := New(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if len(cfg.StorageBackends) == 0 && len(cfg.StorageByType) == 0 {
		return NewSingle(def), nil
	}

	m := &multi{
		stores: map[string]ObjectStore{DefaultName: def},
		byType: cfg.StorageByType,
		names:  []string{DefaultName},
	}
	named := make([]string, 0, len(cfg.StorageBackends))
	for name := range cfg.StorageBackends {
		named = append(named, name)
	}
	sort.Strings(named)
	for _, name := range named {
		spec := cfg.StorageBackends[name]
		store, err := NewFromSpec(ctx, Spec{
			Driver: spec.Driver,
			Path:   spec.Path,
			Bucket: spec.Bucket,
			Region: spec.Region,
			Prefix: spec.Prefix,
		})
		if err != nil {
			return nil, fmt.Errorf("storage backend %q: %w", name, err)
		}
		m.stores[name] = store
		m.names = append(m.names, name)
	}
	return m, nil
}

func (r *multi) Default() ObjectStore { return r.stores[DefaultName] }

func (r *multi) ByName(name string) (ObjectStore, error) {
	if name == "" {
		name = DefaultName
	}
	store, ok := r.stores[name]
	if !ok {
		return nil, fmt.Errorf("unknown storage backend %q (configured: %s)", name, strings.Join(r.names, ", "))
	}
	return store, nil
}

func (r *multi) Placement(typ, policy string) Decision {
	if policy != "" {
		return Decision{Name: policy, Level: LevelPackage}
	}
	if name := r.byType[typ]; name != "" {
		return Decision{Name: name, Level: LevelType}
	}
	return Decision{Name: DefaultName, Level: LevelDefault}
}

func (r *multi) ForType(typ string) ObjectStore {
	store, err := r.ByName(r.Placement(typ, "").Name)
	if err != nil {
		return r.Default()
	}
	return store
}

func (r *multi) Fanout(_ context.Context, typ string, recorded []string) []NamedStore {
	want := map[string]struct{}{DefaultName: {}}
	if name := r.byType[typ]; name != "" {
		want[name] = struct{}{}
	}
	for _, name := range recorded {
		if name == "" {
			name = DefaultName
		}
		want[name] = struct{}{}
	}

	out := make([]NamedStore, 0, len(want))
	for _, name := range r.names {
		if _, ok := want[name]; !ok {
			continue
		}
		out = append(out, NamedStore{Name: name, Store: r.stores[name]})
	}
	// A recorded name no backend answers to is skipped rather than fatal.
	// Its artifacts are unreachable either way, and listing them would
	// advertise keys every fetch answers with 502.
	return dedupByLabel(out)
}

func (r *multi) All() []NamedStore {
	out := make([]NamedStore, 0, len(r.names))
	for _, name := range r.names {
		out = append(out, NamedStore{Name: name, Store: r.stores[name]})
	}
	return out
}

// dedupByLabel drops backends that resolve to the same physical location.
// Two names pointing at one bucket or one directory is a normal way to stage a
// migration, and listing it twice would double every fan-out and hand the
// union a duplicate of every key. Label is the identity because it is the only
// thing an ObjectStore exposes about where it writes.
func dedupByLabel(in []NamedStore) []NamedStore {
	seen := make(map[string]struct{}, len(in))
	out := make([]NamedStore, 0, len(in))
	for _, ns := range in {
		label := ns.Store.Label()
		if _, dup := seen[label]; dup {
			continue
		}
		seen[label] = struct{}{}
		out = append(out, ns)
	}
	return out
}
