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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
)

const (
	indexFile = "index.json"
)

// packageKey returns the canonical map key for a package: "type/safeName".
func packageKey(typ, name string) string {
	return typ + "/" + SafeName(name)
}

// manifestPath returns the backend-relative path for a package manifest file.
func manifestPath(typ, name string) string {
	return typ + "/" + SafeName(name) + "/manifest.json"
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
	if err := b.Write(ctx, indexFile, data); err != nil {
		return fmt.Errorf("write %s to %s: %w", indexFile, b.Label(), err)
	}
	// Also update cached metrics.
	_ = s.SaveMetrics(ctx)
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
func (s *Store) GetPackage(ctx context.Context, typ, name string) (*PackageManifest, error) {
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

	pm.ConfigVersion = CurrentConfigVersion

	data, err := json.MarshalIndent(pm, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal package %s/%s: %w", pm.Type, pm.Name, err)
	}
	data = append(data, '\n')

	b := s.resolveBackend()
	if err := b.Write(ctx, manifestPath(pm.Type, pm.Name), data); err != nil {
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
	b := s.resolveBackend()
	if err := b.Delete(ctx, manifestPath(typ, name)); err != nil {
		return fmt.Errorf("delete package %s/%s from %s: %w", typ, name, b.Label(), err)
	}

	key := packageKey(typ, name)
	s.mu.Lock()
	delete(s.packages, key)
	s.indexRemove(typ, name)
	s.mu.Unlock()

	return nil
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
