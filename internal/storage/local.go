package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/config"
)

func init() {
	Register("local", newLocalFromConfig)
}

func newLocalFromConfig(_ context.Context, cfg *config.Config) (ObjectStore, error) {
	root := cfg.StoragePath
	if root == "" {
		root = "/var/lib/bodega"
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("create storage root %s: %w", root, err)
	}
	return &Local{root: root}, nil
}

// Local is a filesystem-backed ObjectStore. Objects are stored as files at
// <root>/<key>, with directories created as needed.
type Local struct {
	root string
}

// NewLocal creates a Local backend rooted at the given directory.
func NewLocal(root string) *Local {
	return &Local{root: root}
}

func (l *Local) path(key string) (string, error) {
	p := filepath.Join(l.root, filepath.FromSlash(key))
	// Prevent path traversal out of the storage root.
	if !strings.HasPrefix(p, l.root+string(filepath.Separator)) && p != l.root {
		return "", fmt.Errorf("key %q escapes storage root", key)
	}
	return p, nil
}

func (l *Local) Get(_ context.Context, key string) ([]byte, error) {
	p, err := l.path(key)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

func (l *Local) GetStream(_ context.Context, key string) (*StreamResult, error) {
	p, err := l.path(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	ct := mime.TypeByExtension(filepath.Ext(key))
	if ct == "" {
		ct = "application/octet-stream"
	}
	return &StreamResult{
		Body:          f,
		ContentLength: fi.Size(),
		ContentType:   ct,
	}, nil
}

func (l *Local) Head(_ context.Context, key string) (*ObjectInfo, error) {
	p, err := l.path(key)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return &ObjectInfo{Key: key, Exists: false}, nil
	}
	if err != nil {
		return nil, err
	}
	return &ObjectInfo{
		Key:          key,
		Exists:       true,
		Size:         fi.Size(),
		LastModified: fi.ModTime(),
	}, nil
}

func (l *Local) List(_ context.Context, prefix string) ([]string, error) {
	dir, err := l.path(prefix)
	if err != nil {
		return nil, err
	}
	var keys []string

	// If the prefix path doesn't exist, return empty.
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		// The prefix might be a partial directory name. Walk the parent.
		dir = filepath.Dir(dir)
		if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
	}

	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(l.root, path)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(rel)
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func (l *Local) Put(_ context.Context, key string, data []byte) error {
	p, err := l.path(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o644)
}

func (l *Local) PutFile(_ context.Context, localPath, key string) error {
	p, err := l.path(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	src, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.Create(p)
	if err != nil {
		return err
	}
	defer dst.Close()
	if _, err := io.Copy(dst, src); err != nil {
		return err
	}
	return dst.Close()
}

func (l *Local) Delete(_ context.Context, key string) error {
	p, err := l.path(key)
	if err != nil {
		return err
	}
	err = os.Remove(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func (l *Local) SyncDir(_ context.Context, out io.Writer, localDir, keyPrefix string) (int, error) {
	count := 0
	err := filepath.WalkDir(localDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(localDir, path)
		if err != nil {
			return err
		}
		key := keyPrefix + filepath.ToSlash(rel)
		dest, err := l.path(key)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}

		//nolint:gosec // G122: walk root is the operator-owned storage directory; no untrusted symlink injection vector.
		src, err := os.Open(path)
		if err != nil {
			return err
		}
		defer src.Close()

		fi, _ := src.Stat()
		df, err := os.Create(dest)
		if err != nil {
			return err
		}
		defer df.Close()
		if _, err := io.Copy(df, src); err != nil {
			return err
		}
		if err := df.Close(); err != nil {
			return err
		}

		if out != nil {
			fmt.Fprintf(out, "    upload: file://%s (%s)\n", dest, humanSize(fi.Size()))
		}
		count++
		return nil
	})
	return count, err
}

func (l *Local) Label() string {
	return "file://" + l.root
}

// LastModified returns the modification time for the given key, or a zero time
// if the file does not exist. Used for cache staleness checks.
func (l *Local) LastModified(key string) time.Time {
	p, err := l.path(key)
	if err != nil {
		return time.Time{}
	}
	fi, err := os.Stat(p)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

func humanSize(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMG"[exp])
}
