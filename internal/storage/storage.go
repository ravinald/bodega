// Package storage defines the ObjectStore interface for pluggable object
// storage backends. The default backend is the local filesystem; S3 is
// available when configured. GCS and Azure can be added via build tags.
package storage

import (
	"context"
	"fmt"
	"io"
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

// Constructor is a function that creates an ObjectStore from config.
type Constructor func(ctx context.Context, cfg *config.Config) (ObjectStore, error)

// backends is the registry of available storage backends.
var backends = map[string]Constructor{}

// Register adds a named backend constructor. Called from init() in each
// backend implementation file.
func Register(name string, fn Constructor) {
	backends[name] = fn
}

// New creates an ObjectStore based on the configured storage backend.
func New(ctx context.Context, cfg *config.Config) (ObjectStore, error) {
	name := cfg.StorageBackend
	if name == "" {
		name = "local"
	}
	fn, ok := backends[name]
	if !ok {
		available := make([]string, 0, len(backends))
		for k := range backends {
			available = append(available, k)
		}
		return nil, fmt.Errorf("unknown storage backend %q (available: %v)", name, available)
	}
	return fn(ctx, cfg)
}
