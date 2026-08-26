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
	"sort"
	"time"

	"github.com/ravinald/bodega/internal/config"
)

// ObjectStore is the unified interface for all object storage operations.
// Implementations must be safe for concurrent use.
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
		available := make([]string, 0, len(backends))
		for k := range backends {
			available = append(available, k)
		}
		sort.Strings(available)
		return nil, fmt.Errorf("unknown storage backend %q (available: %v)", driver, available)
	}
	return fn(ctx, spec)
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
