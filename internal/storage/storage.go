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

	// List returns the keys of all objects whose key begins with prefix,
	// sorted by key.
	//
	// Sorted by key, not by tree walk. The two differ: a walk orders
	// directory entries, so it descends "x/b/" before reaching the sibling
	// file "x/b-1", while "/" (0x2f) sorts after "-" (0x2d) and the keys
	// run the other way. Local sorts for this reason; the flat backends get
	// it for free.
	//
	// No caller depends on the order today — listFanout re-sorts its union
	// and 'bodega reset' deletes what comes back regardless of sequence —
	// so this is a guarantee stated before something needs it rather than
	// after. Generated indexes (Packages.gz, the PEP 503 pages) are built
	// per request from these keys and gzipped, so an unstable order changes
	// the bytes and every client refetches; one backend answering in walk
	// order would put that one refactor away.
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

// key roots k under the prefix, refusing anything that would leave the
// namespace the prefix defines.
//
// The inner store validates the composed key against the backend root, which
// is a weaker question: under prefix "cold/x/", the key "../escaped" composes
// to "cold/escaped", lands inside the root and is accepted there. That reads
// and writes another backend's keys through this one.
func (p *prefixed) key(k string) (string, error) {
	if err := ValidateKey(k); err != nil {
		return "", err
	}
	return p.prefix + k, nil
}

func (p *prefixed) Get(ctx context.Context, key string) ([]byte, error) {
	k, err := p.key(key)
	if err != nil {
		return nil, err
	}
	return p.inner.Get(ctx, k)
}

func (p *prefixed) GetStream(ctx context.Context, key string) (*StreamResult, error) {
	k, err := p.key(key)
	if err != nil {
		return nil, err
	}
	return p.inner.GetStream(ctx, k)
}

func (p *prefixed) Head(ctx context.Context, key string) (*ObjectInfo, error) {
	k, err := p.key(key)
	if err != nil {
		return nil, err
	}
	info, err := p.inner.Head(ctx, k)
	if info != nil {
		info.Key = key
	}
	return info, err
}

func (p *prefixed) List(ctx context.Context, prefix string) ([]string, error) {
	k, err := p.key(prefix)
	if err != nil {
		return nil, err
	}
	keys, err := p.inner.List(ctx, k)
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
	k, err := p.key(key)
	if err != nil {
		return err
	}
	return p.inner.Put(ctx, k, data)
}

func (p *prefixed) PutFile(ctx context.Context, localPath, key string) error {
	k, err := p.key(key)
	if err != nil {
		return err
	}
	return p.inner.PutFile(ctx, localPath, k)
}

func (p *prefixed) Delete(ctx context.Context, key string) error {
	k, err := p.key(key)
	if err != nil {
		return err
	}
	return p.inner.Delete(ctx, k)
}

func (p *prefixed) SyncDir(ctx context.Context, out io.Writer, localDir, keyPrefix string) (int, error) {
	k, err := p.key(keyPrefix)
	if err != nil {
		return 0, err
	}
	return p.inner.SyncDir(ctx, out, localDir, k)
}

// Label carries the prefix so two names rooted at different prefixes of one
// bucket are distinguishable, which is what the fan-out dedup compares.
//
// The prefix is cleaned rather than concatenated verbatim. "cold//x",
// "./cold/x" and "cold/y/../x" all name the directory the local backend
// resolves through filepath.Join, so a verbatim label gave one directory four
// names: selectForMove's same-location refusal could not fire and
// --delete-source removed the only copy (#189).
//
// Cleaning here is safe only because config.validateStorage refuses those
// spellings at admission. s3 does not clean keys, so "cold//x/k" and
// "cold/x/k" are two distinct objects in one bucket, and a cleaned label over
// an s3 inner would claim an identity the bucket does not have.
func (p *prefixed) Label() string {
	cleaned := strings.TrimPrefix(path.Clean("/"+p.prefix), "/")
	base := strings.TrimSuffix(p.inner.Label(), "/")
	if cleaned == "" {
		return base
	}
	return base + "/" + cleaned
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
