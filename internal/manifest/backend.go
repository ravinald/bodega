// Package manifest — backend.go defines the Backend interface and its two
// built-in implementations: S3Backend (function-pointer based, avoiding import
// cycles) and LocalBackend (plain filesystem).
package manifest

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Backend abstracts the storage layer for manifest files.
// Implementations must be safe to call from multiple goroutines.
type Backend interface {
	// Read returns the raw bytes stored at name. Returns (nil, nil) when
	// the object does not exist.
	Read(ctx context.Context, name string) ([]byte, error)

	// Write stores data at name, overwriting any existing content.
	Write(ctx context.Context, name string, data []byte) error

	// Delete removes the object at name. Implementations should return nil
	// (not an error) when the object does not exist.
	Delete(ctx context.Context, name string) error

	// List returns the names of all objects whose key begins with prefix.
	// The returned names are relative to the backend root (i.e. the prefix
	// is not stripped).
	List(ctx context.Context, prefix string) ([]string, error)

	// Label returns a human-readable description of the storage location,
	// used in error messages and log output.
	Label() string
}

// S3Backend implements Backend using injected function pointers so that the
// manifest package does not import the s3 package directly (which would
// create a circular dependency because s3 imports manifest for status checks).
// The caller wires GetFn, PutFn, DeleteFn, and ListFn when constructing the backend.
type S3Backend struct {
	// Prefix is prepended to every key passed to the function pointers,
	// for example "manifests/".
	Prefix string

	// GetFn fetches the object at key. Returns (nil, nil) when not found.
	GetFn func(ctx context.Context, key string) ([]byte, error)

	// PutFn stores data at key.
	PutFn func(ctx context.Context, key string, data []byte) error

	// DeleteFn removes the object at key. Should return nil when not found.
	DeleteFn func(ctx context.Context, key string) error

	// ListFn returns all keys that start with prefix.
	ListFn func(ctx context.Context, prefix string) ([]string, error)

	// Label_ is returned verbatim by Label().
	Label_ string
}

// Read fetches the object at Prefix+name from S3.
func (b *S3Backend) Read(ctx context.Context, name string) ([]byte, error) {
	return b.GetFn(ctx, b.Prefix+name)
}

// Write stores data at Prefix+name in S3.
func (b *S3Backend) Write(ctx context.Context, name string, data []byte) error {
	return b.PutFn(ctx, b.Prefix+name, data)
}

// Delete removes Prefix+name from S3.
func (b *S3Backend) Delete(ctx context.Context, name string) error {
	return b.DeleteFn(ctx, b.Prefix+name)
}

// List returns all keys that begin with Prefix+prefix from S3.
func (b *S3Backend) List(ctx context.Context, prefix string) ([]string, error) {
	keys, err := b.ListFn(ctx, b.Prefix+prefix)
	if err != nil {
		return nil, err
	}
	// Strip the backend-level Prefix so callers receive store-relative names.
	if b.Prefix == "" {
		return keys, nil
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, strings.TrimPrefix(k, b.Prefix))
	}
	return out, nil
}

// Label returns the human-readable storage description.
func (b *S3Backend) Label() string { return b.Label_ }

// LocalBackend implements Backend using the local filesystem rooted at Dir.
type LocalBackend struct {
	// Dir is the root directory for all manifest files.
	Dir string
}

// safePath joins name onto b.Dir and refuses any input that escapes the root.
// Defense in depth: SafeName at the call site already strips "/", but a future
// caller (or a malformed manifest name reaching the mutation API) could carry
// "..", an absolute path, or a NUL byte. Reject those here so no Backend
// method ever opens a file outside Dir.
func (b *LocalBackend) safePath(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("backend: empty name")
	}
	if strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("backend: name contains NUL byte")
	}
	if filepath.IsAbs(name) {
		return "", fmt.Errorf("backend: refusing absolute path %q", name)
	}
	full := filepath.Join(b.Dir, name)
	rel, err := filepath.Rel(b.Dir, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("backend: refusing path %q (escapes root)", name)
	}
	return full, nil
}

// Read returns the contents of Dir/name. Returns (nil, nil) when the file does not exist.
func (b *LocalBackend) Read(_ context.Context, name string) ([]byte, error) {
	path, err := b.safePath(name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return data, nil
}

// Write stores data at Dir/name, creating any intermediate directories as needed.
func (b *LocalBackend) Write(_ context.Context, name string, data []byte) error {
	path, err := b.safePath(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// Delete removes Dir/name. Returns nil when the file does not exist.
func (b *LocalBackend) Delete(_ context.Context, name string) error {
	path, err := b.safePath(name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("delete %s: %w", path, err)
	}
	return nil
}

// List returns the store-relative paths of all files under Dir whose path
// begins with prefix. Directories themselves are not included.
func (b *LocalBackend) List(_ context.Context, prefix string) ([]string, error) {
	root := filepath.Join(b.Dir, prefix)
	var names []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(b.Dir, path)
		if relErr != nil {
			return relErr
		}
		names = append(names, rel)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", root, err)
	}
	return names, nil
}

// Label returns the filesystem directory used as storage root.
func (b *LocalBackend) Label() string { return b.Dir }
