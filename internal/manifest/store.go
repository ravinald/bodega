// Package manifest — store.go provides the Store type, which is the primary
// entry point for reading and writing package manifests. Manifests are stored
// as per-package JSON files on a Backend (S3 or local filesystem) and loaded
// lazily on first access. An Index provides fast package listings without
// touching individual manifest files, and a DependencyGraph records inter-package
// relationships.
//
// Concurrency: Store is safe for concurrent use by multiple goroutines. All
// public methods acquire the appropriate mutex (read lock for queries, write
// lock for mutations).
package manifest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
)

const (
	indexFile = "index.json"

	// manifestFile is the per-package manifest's basename. One directory per
	// package, not a flat <type>.json: the flat layout is what cmd_verify's
	// walk was still looking at when it reported every type MISSING.
	manifestFile = "manifest.json"
)

// packageKey returns the canonical map key for a package: "type/safeName".
func packageKey(typ, name string) string {
	return typ + "/" + SafeName(name)
}

// manifestPath returns the backend-relative path for a package manifest file.
func manifestPath(typ, name string) string {
	return typ + "/" + SafeName(name) + "/" + manifestFile
}

// Store is the in-memory cache of package manifests, their index, and their
// dependency graph. Use NewStore or NewLocalStore to construct a Store.
type Store struct {
	backend Backend

	// baseDir is used only when backend is nil (pure-local fallback constructed
	// by NewLocalStore without an explicit Backend wrapper).
	baseDir string

	mu       sync.RWMutex
	index    *Index
	graph    *DependencyGraph
	packages map[string]*PackageManifest // "type/safeName" -> manifest
}

// NewStore creates a Store backed by an arbitrary Backend.
func NewStore(backend Backend) *Store {
	return &Store{
		backend:  backend,
		packages: make(map[string]*PackageManifest),
	}
}

// NewLocalStore creates a Store whose backend is a LocalBackend rooted at dir.
func NewLocalStore(dir string) *Store {
	return &Store{
		backend:  &LocalBackend{Dir: dir},
		baseDir:  dir,
		packages: make(map[string]*PackageManifest),
	}
}

// backend returns the configured Backend, creating a LocalBackend from baseDir
// when none was explicitly set.
func (s *Store) resolveBackend() Backend {
	if s.backend != nil {
		return s.backend
	}
	return &LocalBackend{Dir: s.baseDir}
}

// Label names the place this store reads and writes: a directory on the local
// backend, a bucket prefix on S3. Callers use it to name the source in an
// error or a startup log rather than reconstructing it from config.
func (s *Store) Label() string { return s.resolveBackend().Label() }

// ---- Index ---------------------------------------------------------------

// LoadIndex fetches and deserialises index.json from the backend.
// Returns nil without modifying the store when the file does not exist.
func (s *Store) LoadIndex(ctx context.Context) error {
	b := s.resolveBackend()
	data, err := b.Read(ctx, indexFile)
	if err != nil {
		return fmt.Errorf("load index from %s: %w", b.Label(), err)
	}
	if data == nil {
		// No index yet; leave s.index nil — ListPackages will return empty.
		return nil
	}
	var idx Index
	if err := json.Unmarshal(data, &idx); err != nil {
		return fmt.Errorf("parse %s: %w", indexFile, err)
	}
	s.mu.Lock()
	s.index = &idx
	// Clear the package cache so stale data isn't served after index reload.
	for k := range s.packages {
		delete(s.packages, k)
	}
	s.mu.Unlock()
	return nil
}

// SaveIndex serialises the in-memory index and writes it to the backend.
// The caller is responsible for holding or acquiring appropriate locks if
// the index is being mutated concurrently.
func (s *Store) SaveIndex(ctx context.Context) error {
	b := s.resolveBackend()
	s.mu.RLock()
	idx := s.index
	s.mu.RUnlock()

	if idx == nil {
		idx = &Index{
			ConfigVersion: CurrentConfigVersion,
			Packages:      make(map[string][]string),
		}
	}

	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", indexFile, err)
	}
	data = append(data, '\n')
	if err := writeManifest(ctx, b, indexFile, data); err != nil {
		return fmt.Errorf("write %s to %s: %w", indexFile, b.Label(), err)
	}
	// Metrics are written through the same helper, so a sidecar that fails to
	// land here would otherwise leave metrics.json unverifiable behind a
	// successful SaveIndex.
	if err := s.SaveMetrics(ctx); err != nil {
		return fmt.Errorf("update cached metrics in %s: %w", b.Label(), err)
	}
	return nil
}

// ensureIndex initialises an empty index when none has been loaded. Must be
// called with the write lock held.
func (s *Store) ensureIndex() {
	if s.index == nil {
		s.index = &Index{
			ConfigVersion: CurrentConfigVersion,
			Packages:      make(map[string][]string),
		}
	}
	if s.index.Packages == nil {
		s.index.Packages = make(map[string][]string)
	}
}

// indexAdd records name under typ in the index when it is not already present.
// Must be called with the write lock held.
func (s *Store) indexAdd(typ, name string) {
	s.ensureIndex()
	safe := SafeName(name)
	for _, existing := range s.index.Packages[typ] {
		if existing == safe {
			return
		}
	}
	s.index.Packages[typ] = append(s.index.Packages[typ], safe)
}

// indexRemove deletes name from the index under typ.
// Must be called with the write lock held.
func (s *Store) indexRemove(typ, name string) {
	if s.index == nil {
		return
	}
	safe := SafeName(name)
	list := s.index.Packages[typ]
	filtered := list[:0]
	for _, existing := range list {
		if existing != safe {
			filtered = append(filtered, existing)
		}
	}
	s.index.Packages[typ] = filtered
}

// ---- Package CRUD --------------------------------------------------------

// GetPackage returns the PackageManifest for the named package, loading it
// from the backend on first access and caching the result. Returns a non-nil
// error when the backend read or JSON decode fails. Returns (nil, nil) when
// the manifest file does not exist.
//
// The name is canonicalized for its type before the path is composed, and
// SavePackage canonicalizes what it writes, so the read and the write cannot
// disagree about where a pypi distribution lives. The store is the place for it
// rather than each caller: seven paths write a pypi manifest (pkg create,
// import, convert, two API endpoints, discover promote and
// generate-manifests) and two routes read one, and a rule held in nine places
// is a rule until somebody adds the tenth.
func (s *Store) GetPackage(ctx context.Context, typ, name string) (*PackageManifest, error) {
	name = CanonicalName(typ, name)
	key := packageKey(typ, name)

	s.mu.RLock()
	if pm, ok := s.packages[key]; ok {
		s.mu.RUnlock()
		return pm, nil
	}
	s.mu.RUnlock()

	// Not cached — load from backend.
	b := s.resolveBackend()
	data, err := b.Read(ctx, manifestPath(typ, name))
	if err != nil {
		return nil, fmt.Errorf("get package %s/%s from %s: %w", typ, name, b.Label(), err)
	}
	if data == nil {
		return nil, nil
	}

	var pm PackageManifest
	if err := json.Unmarshal(data, &pm); err != nil {
		return nil, fmt.Errorf("parse package %s/%s: %w", typ, name, err)
	}

	s.mu.Lock()
	s.packages[key] = &pm
	s.mu.Unlock()

	return &pm, nil
}

// SavePackage serialises pm and writes it to the backend, then updates the index.
// The index is updated in memory only; call SaveIndex separately to persist it.
func (s *Store) SavePackage(ctx context.Context, pm *PackageManifest) error {
	if pm.Type == "" {
		return errors.New("SavePackage: PackageManifest.Type must not be empty")
	}
	if pm.Name == "" {
		return errors.New("SavePackage: PackageManifest.Name must not be empty")
	}
	// The backstop for the name checks admit runs. 'bodega pkg create' writes
	// through AddVersion without going through admit, so a rule that lived
	// only there would hold for the API and the importers and not for the one
	// command an operator types by hand.
	if err := ValidatePackageName(pm.Name); err != nil {
		return fmt.Errorf("SavePackage: %w", err)
	}
	// After the refusal, not before: "." and ".." canonicalize to "-" for pypi,
	// and a name the check exists to reject would slip through as an ordinary
	// one.
	pm.Name = CanonicalName(pm.Type, pm.Name)

	pm.ConfigVersion = CurrentConfigVersion

	data, err := json.MarshalIndent(pm, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal package %s/%s: %w", pm.Type, pm.Name, err)
	}
	data = append(data, '\n')

	b := s.resolveBackend()
	if err := writeManifest(ctx, b, manifestPath(pm.Type, pm.Name), data); err != nil {
		return fmt.Errorf("write package %s/%s to %s: %w", pm.Type, pm.Name, b.Label(), err)
	}

	key := packageKey(pm.Type, pm.Name)
	s.mu.Lock()
	s.packages[key] = pm
	s.indexAdd(pm.Type, pm.Name)
	s.mu.Unlock()

	return nil
}

// DeletePackage removes the package manifest from the backend and from the index.
// The index change is in-memory only; call SaveIndex to persist it.
// Returns nil when the manifest does not exist.
func (s *Store) DeletePackage(ctx context.Context, typ, name string) error {
	name = CanonicalName(typ, name)
	b := s.resolveBackend()
	if err := deleteManifest(ctx, b, manifestPath(typ, name)); err != nil {
		return fmt.Errorf("delete package %s/%s from %s: %w", typ, name, b.Label(), err)
	}

	key := packageKey(typ, name)
	s.mu.Lock()
	delete(s.packages, key)
	s.indexRemove(typ, name)
	s.mu.Unlock()

	return nil
}

// MisnamedPackage is one stored manifest whose path segment is not the
// canonical name for its type.
type MisnamedPackage struct {
	Type      string
	Stored    string // the name the stored path spells
	Canonical string // the name every read now composes
}

// MisnamedPackages walks the backend for manifests stored under a name that is
// not canonical for their type, sorted by path.
//
// An install that predates canonicalization holds pypi manifests under whatever
// `pip list` reported — `Django`, `zope.interface` — and every read now composes
// the canonical path, so each one is a manifest nothing can reach. Listing them
// is what lets `bodega repair check` name them without moving anything: a
// rename is a manifest disappearing from under a running server, so it waits for
// the operator to run `bodega repair`.
func (s *Store) MisnamedPackages(ctx context.Context) ([]MisnamedPackage, error) {
	b := s.resolveBackend()
	names, err := b.List(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", b.Label(), err)
	}
	var out []MisnamedPackage
	for _, n := range names {
		segs := strings.Split(n, "/")
		if len(segs) != 3 || segs[2] != manifestFile {
			continue
		}
		typ, stored := segs[0], segs[1]
		if nameCarriesSlash(typ) {
			stored = unsafeName(stored)
		}
		canonical := CanonicalName(typ, stored)
		if canonical == stored {
			continue
		}
		out = append(out, MisnamedPackage{Type: typ, Stored: stored, Canonical: canonical})
	}
	slices.SortFunc(out, func(a, b MisnamedPackage) int {
		if c := strings.Compare(a.Type, b.Type); c != 0 {
			return c
		}
		return strings.Compare(a.Stored, b.Stored)
	})
	return out, nil
}

// nameCarriesSlash reports whether a stored path segment for this type can
// encode a "/". SafeName encodes that character and nothing else, so decoding a
// segment for a type whose names cannot carry one reads a literal "--" as a
// separator: the pypi distribution "a--b" comes back as "a/b", which is already
// canonical, and a manifest no route can reach is reported as correctly named.
func nameCarriesSlash(typ string) bool {
	switch typ {
	case TypeNpm, TypeGit, TypeBinary, TypeGomod:
		return true
	}
	return false
}

// RenameToCanonical moves one misnamed manifest onto its canonical path and
// drops the old name from the index. The index change is in-memory only; call
// SaveIndex to persist it.
//
// It refuses when the canonical path already holds a manifest whose entries
// differ. Two manifests for one distribution is two sets of version entries, and
// merging them is a decision about which pins survive: the error names both so
// the operator makes it, and neither is touched.
//
// The new copy lands before the old one is deleted, so an interrupted rename
// leaves two manifests rather than none. A second run finds the canonical path
// occupied by bytes identical to the old manifest's and finishes the delete,
// which is the only reading of that state: nothing is lost by dropping a copy of
// what is already there.
//
// A case-insensitive backend is the other shape of that. `pypi/Django` and
// `pypi/django` are one object on APFS and on a bucket mounted through one, so
// the canonical path reads back as the manifest being renamed and the delete
// would remove what the write just produced. The old path is re-read after the
// write for exactly that: it is deleted only while it still holds something
// else.
func (s *Store) RenameToCanonical(ctx context.Context, m MisnamedPackage) error {
	b := s.resolveBackend()
	oldPath := manifestPath(m.Type, m.Stored)
	data, err := b.Read(ctx, oldPath)
	if err != nil {
		return fmt.Errorf("read %s from %s: %w", oldPath, b.Label(), err)
	}
	if data == nil {
		return fmt.Errorf("nothing stored at %s in %s", oldPath, b.Label())
	}
	occupied, err := b.Read(ctx, manifestPath(m.Type, m.Canonical))
	if err != nil {
		return fmt.Errorf("read %s from %s: %w", manifestPath(m.Type, m.Canonical), b.Label(), err)
	}

	var pm PackageManifest
	if err := json.Unmarshal(data, &pm); err != nil {
		return fmt.Errorf("parse %s: %w", oldPath, err)
	}
	stored := pm
	pm.Name = m.Canonical
	pm.Type = m.Type
	pm.ConfigVersion = CurrentConfigVersion

	if occupied != nil && !sameManifest(occupied, &pm) && !sameManifest(occupied, &stored) {
		return fmt.Errorf("%s/%s and %s/%s are the same package under two names carrying different version entries; merge them by hand and delete one — neither was moved",
			m.Type, m.Stored, m.Type, m.Canonical)
	}
	if err := s.SavePackage(ctx, &pm); err != nil {
		return err
	}
	remains, err := b.Read(ctx, oldPath)
	if err != nil {
		return fmt.Errorf("re-read %s from %s: %w — %s/%s is written and reachable, and the old path was left alone",
			oldPath, b.Label(), err, m.Type, m.Canonical)
	}
	if remains != nil && sameManifest(remains, &pm) {
		// The write landed on the object the old path names, which only
		// happens when the backend folds the two keys together. Deleting the
		// old path here would delete the manifest this call just wrote, and
		// the stored segment keeps its old spelling whatever we do: a backend
		// that cannot tell the two names apart has no rename to offer.
		return fmt.Errorf("%s and %s are one object on %s, so %s/%s cannot be renamed there: the manifest is correct and every read finds it, but the stored path still spells %q and this repair will report it again. Move the store to a case-sensitive filesystem, or rename the directory by hand in two steps",
			oldPath, manifestPath(m.Type, m.Canonical), b.Label(), m.Type, m.Stored, m.Stored)
	}
	if remains != nil {
		if err := deleteManifest(ctx, b, oldPath); err != nil {
			return fmt.Errorf("delete %s from %s: %w — %s/%s is written and reachable, so re-running the repair finishes it",
				oldPath, b.Label(), err, m.Type, m.Canonical)
		}
	}
	s.mu.Lock()
	delete(s.packages, packageKey(m.Type, m.Stored))
	s.indexRemove(m.Type, m.Stored)
	s.mu.Unlock()
	return nil
}

// sameManifest reports whether the bytes already at a canonical path are the
// copy an interrupted rename wrote. Compared as decoded manifests rather than
// as bytes: the two were serialized by the same writer, but a hand-edited file
// differing only in indentation is the same manifest and refusing it would
// strand the rename.
func sameManifest(raw []byte, pm *PackageManifest) bool {
	var other PackageManifest
	if err := json.Unmarshal(raw, &other); err != nil {
		return false
	}
	want := *pm
	other.ConfigVersion, want.ConfigVersion = CurrentConfigVersion, CurrentConfigVersion
	a, aerr := json.Marshal(&other)
	b, berr := json.Marshal(&want)
	return aerr == nil && berr == nil && bytes.Equal(a, b)
}

// ---- Version helpers -----------------------------------------------------

// FindVersion returns a pointer to the VersionEntry whose Version (or Ref for
// git packages) matches version, loading the manifest if needed. Returns nil
// when the package or version is not found.
func (s *Store) FindVersion(ctx context.Context, typ, name, version string) (*VersionEntry, error) {
	pm, err := s.GetPackage(ctx, typ, name)
	if err != nil {
		return nil, err
	}
	if pm == nil {
		return nil, nil
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := range pm.Versions {
		ve := &pm.Versions[i]
		if ve.Version == version || ve.Ref == version {
			return ve, nil
		}
	}
	return nil, nil
}

// AddVersion appends ve to the named package's version list and saves the
// manifest. If the package does not exist a new PackageManifest is created.
// The index is updated in memory; call SaveIndex to persist it.
func (s *Store) AddVersion(ctx context.Context, typ, name string, ve VersionEntry) error {
	pm, err := s.GetPackage(ctx, typ, name)
	if err != nil {
		return err
	}
	if pm == nil {
		pm = &PackageManifest{
			Name: name,
			Type: typ,
		}
	}

	// Guard against duplicate entries (match on Version or Ref).
	ver := ve.Version
	if ver == "" {
		ver = ve.Ref
	}
	for _, existing := range pm.Versions {
		ev := existing.Version
		if ev == "" {
			ev = existing.Ref
		}
		if ev == ver && ver != "" {
			return fmt.Errorf("version %q already exists for %s/%s", ver, typ, name)
		}
	}

	pm.Versions = append(pm.Versions, ve)
	return s.SavePackage(ctx, pm)
}

// RemoveVersion deletes the VersionEntry matching version from the named package
// and saves the manifest. Returns an error when the package or version is not found.
func (s *Store) RemoveVersion(ctx context.Context, typ, name, version string) error {
	pm, err := s.GetPackage(ctx, typ, name)
	if err != nil {
		return err
	}
	if pm == nil {
		return fmt.Errorf("package %s/%s not found", typ, name)
	}

	orig := len(pm.Versions)
	filtered := pm.Versions[:0]
	for _, ve := range pm.Versions {
		if ve.Version != version && ve.Ref != version {
			filtered = append(filtered, ve)
		}
	}
	if len(filtered) == orig {
		return fmt.Errorf("version %q not found in %s/%s", version, typ, name)
	}
	pm.Versions = filtered
	return s.SavePackage(ctx, pm)
}

// ---- Listings ------------------------------------------------------------

// ListPackages returns the safe names registered under typ in the index.
// Returns an empty slice when the type is not present or no index has been loaded.
func (s *Store) ListPackages(typ string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.index == nil {
		return nil
	}
	names := s.index.Packages[typ]
	out := make([]string, len(names))
	copy(out, names)
	return out
}

// AllPackages returns a map of package type -> slice of safe names for every
// type recorded in the index.
func (s *Store) AllPackages() map[string][]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.index == nil {
		return map[string][]string{}
	}
	out := make(map[string][]string, len(s.index.Packages))
	for typ, names := range s.index.Packages {
		cp := make([]string, len(names))
		copy(cp, names)
		out[typ] = cp
	}
	return out
}

// ---- Dependency graph ----------------------------------------------------

// LoadGraph fetches graph.json from the backend and populates the in-memory graph.
// Returns nil when the file does not exist.
func (s *Store) LoadGraph(ctx context.Context) error {
	b := s.resolveBackend()
	var g DependencyGraph
	if err := loadGraph(ctx, b, &g); err != nil {
		return err
	}
	s.mu.Lock()
	s.graph = &g
	s.mu.Unlock()
	return nil
}

// SaveGraph serialises the in-memory dependency graph and writes it to the backend.
func (s *Store) SaveGraph(ctx context.Context) error {
	b := s.resolveBackend()
	s.mu.RLock()
	g := s.graph
	s.mu.RUnlock()

	if g == nil {
		g = &DependencyGraph{}
	}
	return saveGraph(ctx, b, g)
}

// ensureGraph initialises an empty graph when none has been loaded.
// Must be called with the write lock held.
func (s *Store) ensureGraph() {
	if s.graph == nil {
		s.graph = &DependencyGraph{}
	}
}

// AddEdge records a directed dependency edge and deduplicates.
// The change is in-memory only; call SaveGraph to persist it.
func (s *Store) AddEdge(edge DepEdge) {
	s.mu.Lock()
	s.ensureGraph()
	addEdge(s.graph, edge)
	s.mu.Unlock()
}

// RemoveEdge removes every edge where Parent == parent and Child == child.
// The change is in-memory only; call SaveGraph to persist it.
func (s *Store) RemoveEdge(parent, child string) {
	s.mu.Lock()
	s.ensureGraph()
	removeEdge(s.graph, parent, child)
	s.mu.Unlock()
}

// ParentsOf returns all edges where Child == child.
func (s *Store) ParentsOf(child string) []DepEdge {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.graph == nil {
		return nil
	}
	return parentsOf(s.graph, child)
}

// Edges returns a copy of every dependency edge.
//
// ParentsOf and ChildrenOf match a reference exactly, which answers one hop
// and cannot answer a closure: the writers spell a node two ways — apt records
// "apt/nginx" and the language discoverers record "pypi/django@5.2.12" — so a
// walk that probes by exact reference misses every edge stored under the other
// spelling. A caller walking the graph reads it whole and matches on its own
// terms.
func (s *Store) Edges() []DepEdge {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.graph == nil {
		return nil
	}
	return slices.Clone(s.graph.Edges)
}

// ChildrenOf returns all edges where Parent == parent.
func (s *Store) ChildrenOf(parent string) []DepEdge {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.graph == nil {
		return nil
	}
	return childrenOf(s.graph, parent)
}

// AllEdges returns every edge in the dependency graph.
func (s *Store) AllEdges() []DepEdge {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.graph == nil {
		return nil
	}
	return s.graph.Edges
}

// Orphans returns the set of packages (as "type/name" strings) that appear in
// dependency graph edges but don't have a corresponding manifest in the store.
// These are broken references that should be repaired.
func (s *Store) Orphans() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.graph == nil {
		return nil
	}
	candidates := orphans(s.graph)
	// Build a lookup set from the index for fast membership checks.
	known := make(map[string]bool)
	for typ, names := range s.index.Packages {
		for _, safeName := range names {
			known[typ+"/"+safeName] = true
		}
	}
	var result []string
	for _, ref := range candidates {
		// Split "type/name" into type and name, then check with SafeName.
		parts := strings.SplitN(ref, "/", 2)
		if len(parts) != 2 {
			continue
		}
		typ, name := parts[0], parts[1]
		key := typ + "/" + SafeName(name)
		if !known[key] {
			result = append(result, ref)
		}
	}
	return result
}
