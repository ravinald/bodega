package manifest

import (
	"context"
	"crypto/md5" //nolint:gosec
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Backend abstracts where manifests are stored — local filesystem or S3.
type Backend interface {
	// Read returns the contents of a manifest file. Returns nil, nil if not found.
	Read(ctx context.Context, name string) ([]byte, error)
	// Write saves manifest data and its MD5 companion.
	Write(ctx context.Context, name string, data []byte) error
	// ReadMD5 returns the stored MD5 digest. Returns "" if not found.
	ReadMD5(ctx context.Context, name string) (string, error)
	// Label returns a human-readable description of where manifests are stored.
	Label() string
}

// S3Backend is provided as an interface so the manifest package doesn't import
// the s3 package directly (which would create a circular dependency since s3
// imports manifest for status checks). The caller wires it up.
type S3Backend struct {
	Prefix string // S3 key prefix, e.g. "manifests/"
	// These function fields are injected by the caller to avoid importing
	// the s3 package here.
	GetFn func(ctx context.Context, key string) ([]byte, error)
	PutFn func(ctx context.Context, key string, data []byte) error
	Label_ string
}

func (b *S3Backend) Read(ctx context.Context, name string) ([]byte, error) {
	return b.GetFn(ctx, b.Prefix+name)
}

func (b *S3Backend) Write(ctx context.Context, name string, data []byte) error {
	if err := b.PutFn(ctx, b.Prefix+name, data); err != nil {
		return err
	}
	// Also write the MD5 companion
	digest := fmt.Sprintf("%x", md5.Sum(data)) //nolint:gosec
	return b.PutFn(ctx, b.Prefix+name+".md5", []byte(digest+"\n"))
}

func (b *S3Backend) ReadMD5(ctx context.Context, name string) (string, error) {
	data, err := b.GetFn(ctx, b.Prefix+name+".md5")
	if err != nil || data == nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func (b *S3Backend) Label() string { return b.Label_ }

// LocalBackend reads/writes manifests from the local filesystem.
type LocalBackend struct {
	Dir string
}

func (b *LocalBackend) Read(_ context.Context, name string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(b.Dir, name))
	if os.IsNotExist(err) {
		return nil, nil
	}
	return data, err
}

func (b *LocalBackend) Write(_ context.Context, name string, data []byte) error {
	path := filepath.Join(b.Dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	// Write MD5 companion
	digest := fmt.Sprintf("%x", md5.Sum(data)) //nolint:gosec
	md5Path := path + ".md5"
	if err := os.WriteFile(md5Path, []byte(digest+"\n"), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", md5Path, err)
	}
	return nil
}

func (b *LocalBackend) ReadMD5(_ context.Context, name string) (string, error) {
	data, err := os.ReadFile(filepath.Join(b.Dir, name+".md5"))
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func (b *LocalBackend) Label() string { return b.Dir }
