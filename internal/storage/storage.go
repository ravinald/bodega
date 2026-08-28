// Package storage defines the ObjectStore interface for pluggable object
// storage backends. The default backend is the local filesystem; S3 is
// available when configured. GCS and Azure can be added via build tags.
//
// This package must never import internal/manifest. Placement is recorded in
// the manifest and resolved by internal/server, which owns both imports; see
// Resolver in resolver.go for the split.
package storage

import (
	"context"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/config"
)

// ObjectStore is the unified interface for all object storage operations.
// Implementations must be safe for concurrent use.
//
// Every method that takes a key rejects one ValidateKey rejects, on every
// backend. Uniformity is the point: a key is derived once in internal/manifest
// and handed to whichever backend a version records, so a key one driver
// stores and another refuses would make placement decide whether an artifact
// is reachable.
type ObjectStore interface {
	// Get returns the raw bytes stored at key. Returns (nil, nil) when the
	// object does not exist.
	Get(ctx context.Context, key string) ([]byte, error)

	// GetStream returns a streaming reader for the object at key.
	// Returns (nil, nil) when the object does not exist. The caller must
	// close Body when done.
	GetStream(ctx context.Context, key string) (*StreamResult, error)

	// Head returns metadata about the object at key without reading its body.
	// Returns ObjectInfo with Exists=false when the object does not exist.
	Head(ctx context.Context, key string) (*ObjectInfo, error)

	// List returns the keys of all objects whose key begins with prefix.
	List(ctx context.Context, prefix string) ([]string, error)

	// Put stores data at key, overwriting any existing content.
	Put(ctx context.Context, key string, data []byte) error

	// PutFile uploads a local file to the given key.
	PutFile(ctx context.Context, localPath, key string) error

	// Delete removes the object at key. Returns nil if the object does not
	// exist (idempotent).
	Delete(ctx context.Context, key string) error

	// SyncDir uploads all files under localDir to the store under keyPrefix,
	// preserving relative paths. Returns the number of files uploaded.
	SyncDir(ctx context.Context, out io.Writer, localDir, keyPrefix string) (int, error)

	// Label returns a human-readable description of the storage location,
	// e.g. "s3://bucket-name", "file:///var/lib/bodega/data".
	Label() string
}

// keyRoot is the virtual root ValidateKey resolves a key against. It never
// touches a filesystem; it exists so the traversal rule can be stated once, in
// terms every backend shares, rather than once per driver.
const keyRoot = "/store"

// ValidateKey rejects a key no backend may store, whatever its namespace.
//
// A NUL truncates the path at the syscall boundary, so "a\x00/../../etc"
// reaches the kernel as "a" and any traversal check that ran on the Go string
// passed on something the filesystem never saw. A key that normalizes above
// the root addresses an object outside the store.
//
// Flat backends enforce it too. A test double that accepted keys the
// filesystem backend rejects lets a server test pass on a key that errors in
// production, which is the one failure a shared contract exists to prevent.
func ValidateKey(key string) error {
	if strings.ContainsRune(key, 0) {
		return fmt.Errorf("key %q contains a NUL byte", key)
	}
	p := path.Join(keyRoot, key)
	if p != keyRoot && !strings.HasPrefix(p, keyRoot+"/") {
		return fmt.Errorf("key %q escapes storage root", key)
	}
	return nil
}

// StreamResult holds the response from a streaming read.
type StreamResult struct {
	Body          io.ReadCloser
	ContentLength int64
	ETag          string
	ContentType   string
}

// ObjectInfo holds metadata about a stored object.
type ObjectInfo struct {
	Key          string
	Exists       bool
	Size         int64
	LastModified time.Time
	ETag         string
}

// Spec is the resolved parameter set for one backend. Each backend reads only
// the fields its driver uses; a backend that reached into the global config
// could not be instantiated twice with different parameters, which is what
// naming backends requires.
type Spec struct {
	Driver string // "local" | "s3"
	Path   string // local: filesystem root
	Bucket string // s3
	Region string // s3
	Prefix string // key prefix within the backend
}

// Constructor creates an ObjectStore from one backend's Spec.
type Constructor func(ctx context.Context, spec Spec) (ObjectStore, error)

// backends is the registry of available storage backends, keyed by driver.
var backends = map[string]Constructor{}

// Register adds a driver constructor. Called from init() in each backend
// implementation file.
func Register(driver string, fn Constructor) {
	backends[driver] = fn
}

// NewFromSpec creates an ObjectStore for the driver named in spec.
func NewFromSpec(ctx context.Context, spec Spec) (ObjectStore, error) {
	driver := spec.Driver
	if driver == "" {
		driver = "local"
	}
	fn, ok := backends[driver]
	if !ok {
		return nil, fmt.Errorf("unknown storage backend %q (available: %v)", driver, Drivers())
	}
	store, err := fn(ctx, spec)
	if err != nil {
		return nil, err
	}
	return withPrefix(store, spec.Prefix), nil
}

// withPrefix returns store with every key rooted under prefix. Keys coming
// back out of List have the prefix stripped, so a caller comparing keys across
// backends — the listing fan-out does exactly that — sees one namespace rather
// than one per backend.
func withPrefix(store ObjectStore, prefix string) ObjectStore {
	prefix = strings.TrimPrefix(prefix, "/")
	if prefix == "" {
		return store
	}
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return &prefixed{inner: store, prefix: prefix}
}

// prefixed roots one backend under a key prefix.
type prefixed struct {
	inner  ObjectStore
	prefix string
}

func (p *prefixed) key(k string) string { return p.prefix + k }

func (p *prefixed) Get(ctx context.Context, key string) ([]byte, error) {
	return p.inner.Get(ctx, p.key(key))
}

func (p *prefixed) GetStream(ctx context.Context, key string) (*StreamResult, error) {
	return p.inner.GetStream(ctx, p.key(key))
}

func (p *prefixed) Head(ctx context.Context, key string) (*ObjectInfo, error) {
	info, err := p.inner.Head(ctx, p.key(key))
	if info != nil {
		info.Key = key
	}
	return info, err
}

func (p *prefixed) List(ctx context.Context, prefix string) ([]string, error) {
	keys, err := p.inner.List(ctx, p.key(prefix))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, strings.TrimPrefix(k, p.prefix))
	}
	return out, nil
}

func (p *prefixed) Put(ctx context.Context, key string, data []byte) error {
	return p.inner.Put(ctx, p.key(key), data)
}

func (p *prefixed) PutFile(ctx context.Context, localPath, key string) error {
	return p.inner.PutFile(ctx, localPath, p.key(key))
}

func (p *prefixed) Delete(ctx context.Context, key string) error {
	return p.inner.Delete(ctx, p.key(key))
}

func (p *prefixed) SyncDir(ctx context.Context, out io.Writer, localDir, keyPrefix string) (int, error) {
	return p.inner.SyncDir(ctx, out, localDir, p.key(keyPrefix))
}

// Label carries the prefix so two names rooted at different prefixes of one
// bucket are distinguishable, which is what the fan-out dedup compares.
func (p *prefixed) Label() string {
	return strings.TrimSuffix(p.inner.Label(), "/") + "/" + strings.TrimSuffix(p.prefix, "/")
}

// SpecFromConfig derives the default backend's Spec from the global config.
// The global storage_backend / storage_path / bucket / region keys describe
// exactly one backend, whose reserved name is DefaultName.
func SpecFromConfig(cfg *config.Config) Spec {
	return Spec{
		Driver: cfg.StorageBackend,
		Path:   cfg.StoragePath,
		Bucket: cfg.Bucket,
		Region: cfg.Region,
	}
}

// New creates the default ObjectStore described by the global config.
func New(ctx context.Context, cfg *config.Config) (ObjectStore, error) {
	return NewFromSpec(ctx, SpecFromConfig(cfg))
}

// Drivers returns every registered driver name, sorted.
func Drivers() []string {
	names := make([]string, 0, len(backends))
	for k := range backends {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// config.Load rejects a backend name that reads as a driver, and asks the
// registry rather than a hardcoded list so a driver added under a build tag is
// covered without a second edit. The wiring lives here because storage imports
// config and not the other way round.
func init() { config.StorageDrivers = Drivers }
