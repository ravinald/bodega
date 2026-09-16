package storage

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/config"
)

func init() {
	Register("local", newLocalFromSpec)
}

// newLocalFromSpec creates the root and then hands it to NewLocal rather than
// building a Local itself. The driver registry is the only path a configured
// backend takes, so an invariant that lived in NewLocal alone would hold for
// every test and no deployment.
func newLocalFromSpec(_ context.Context, spec Spec) (ObjectStore, error) {
	root := spec.Path
	if root == "" {
		root = config.DefaultStoragePath
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("create storage root %s: %w", root, err)
	}
	return NewLocal(root), nil
}

// Local is a filesystem-backed ObjectStore. Objects are stored as files at
// <root>/<key>, with directories created as needed.
type Local struct {
	root string
}

// NewLocal creates a Local backend rooted at the given directory, canonicalized
// once so that every later comparison has one string to compare.
func NewLocal(root string) *Local {
	return &Local{root: canonicalRoot(root)}
}

// canonicalRoot reduces the spellings of one directory to one string.
//
// Label() is built from root, and 'bodega pkg move' compares two Labels to
// decide whether a copy would land on top of its own source. A symlinked
// second root, a trailing slash or an "/a/../b" spelling would each produce a
// second label for one directory, the refusal would not fire, and
// --delete-source would remove the only copy of the artifact. The trailing
// slash also breaks path(): its prefix test is against root + "/", which
// "/srv/store//key" fails, so every write on such a root is refused.
//
// EvalSymlinks needs the directory to exist. A root that does not yet keeps
// the absolute cleaned form, which is what newLocalFromSpec creates a moment
// later and what a second name for the same not-yet-created path also yields.
func canonicalRoot(root string) string {
	abs, err := filepath.Abs(root)
	if err != nil {
		return filepath.Clean(root)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return abs
	}
	return resolved
}

func (l *Local) path(key string) (string, error) {
	if err := ValidateKey(key); err != nil {
		return "", err
	}
	p := filepath.Join(l.root, filepath.FromSlash(key))
	// ValidateKey answers the same question against a virtual root. This
	// repeats it against the real one, because l.root is operator-supplied and
	// a root that is not already clean would not resolve the way the virtual
	// check assumed.
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
		LastModified:  fi.ModTime(),
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

	// A prefix that does not end in a separator is a string prefix, not a
	// directory: "packages/ap" has to match "packages/apt/..." even when
	// "packages/ap/" also exists as a directory of its own. Walking the parent
	// and filtering is a superset of the correct answer in every case, since
	// any key starting with the prefix lives under the prefix's parent.
	// The root has no parent to walk: a prefix that normalizes to it (".",
	// "./") would otherwise send the walk one level up, where every relative
	// path starts "../" and satisfies a "." prefix filter — keys outside the
	// store, returned as if they were in it.
	if prefix != "" && !strings.HasSuffix(prefix, "/") && dir != l.root {
		dir = filepath.Dir(dir)
	}
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}

	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasPrefix(d.Name(), tmpPrefix) {
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
	// WalkDir orders per directory, which is not key order: it descends into
	// "x/b/" before reaching the sibling file "x/b". The fan-out merges these
	// lists and a merge needs each input sorted.
	sort.Strings(keys)
	return keys, nil
}

// tmpPrefix marks a staging file that is not yet an object. It leads with a
// dot so an operator listing the directory sees it as machinery, and List
// skips it by this prefix so a walk concurrent with a write never returns a
// name that is about to stop existing.
const tmpPrefix = ".bodega-tmp-"

// createStaged opens a staging file in dir at perm, which the process umask
// filters exactly as it filters any other creation. os.CreateTemp is not used
// because it hardcodes 0600, and correcting that afterwards means either
// publishing every object 0644 or reading the umask back, which is only
// possible by setting it: a window in which every other goroutine's file
// creation takes the wrong mode.
func createStaged(dir string, perm os.FileMode) (*os.File, error) {
	for range 100 {
		//nolint:gosec // perm is the destination's own mode or 0666 before umask, never a widening.
		f, err := os.OpenFile(filepath.Join(dir, tmpPrefix+rand.Text()), os.O_RDWR|os.O_CREATE|os.O_EXCL, perm)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		return f, err
	}
	return nil, fmt.Errorf("create staging file in %s: no unused name", dir)
}

// publish writes p by filling a sibling staging file and renaming it into
// place, so the key goes from its previous bytes to its new ones with no
// intermediate state and no reuse of the inode.
//
// A reader holding an open handle keeps the object it opened. That is what
// binds a cached artifact's recorded origin to the bytes the client receives:
// the proxy takes an object's identity from the same open that supplies the
// body, and truncating in place changed the bytes behind that handle while the
// recorded length, timestamp and upstream still described what had been there
// — a row crediting a server that supplied none of what was served. Locking
// the proxy against itself would not close it, because the writer is often
// another process using this same root.
//
// Publishing a new inode carries no mode of its own, so both halves of what
// writing in place used to decide are restated here: a fresh object takes 0666
// before the umask, which is what os.Create left, and a replacement keeps the
// mode the object already had. An operator who restricted one artifact
// restricted it; a refill is not a decision to publish it. Ownership is the
// part that cannot follow, since rename gives the object the writer's uid and
// chown across users needs privilege the server does not hold; the same goes
// for an ACL set on the object rather than on its directory.
func (l *Local) publish(p string, write func(io.Writer) error) (err error) {
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	perm, replacing := os.FileMode(0o666), false
	if fi, statErr := os.Stat(p); statErr == nil && fi.Mode().IsRegular() {
		perm, replacing = fi.Mode().Perm(), true
	}
	tmp, err := createStaged(dir, perm)
	if err != nil {
		return err
	}
	staged := tmp.Name()
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(staged)
		}
	}()
	if err = write(tmp); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	// The umask can only narrow a creation, so a replacement whose mode it
	// clipped is restored after the bytes are written. Correcting it before
	// the write would be the other direction on a fresh object: a moment in
	// which the staging file is readable more widely than the object is.
	if replacing {
		if err = os.Chmod(staged, perm); err != nil {
			return err
		}
	}
	return os.Rename(staged, p)
}

func (l *Local) Put(_ context.Context, key string, data []byte) error {
	p, err := l.path(key)
	if err != nil {
		return err
	}
	return l.publish(p, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

func (l *Local) PutFile(_ context.Context, localPath, key string) error {
	p, err := l.path(key)
	if err != nil {
		return err
	}
	src, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer src.Close()
	return l.publish(p, func(w io.Writer) error {
		_, err := io.Copy(w, src)
		return err
	})
}

func (l *Local) Delete(_ context.Context, key string) error {
	p, err := l.path(key)
	if err != nil {
		return err
	}
	// A key naming a directory names no object. os.Remove would fail on a
	// populated one and succeed on an empty one, so the same call either
	// errors on a key that was never stored or removes a tree node no caller
	// asked about; every other backend answers "not there" and returns nil.
	if fi, err := os.Lstat(p); err == nil && fi.IsDir() {
		return nil
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

		//nolint:gosec // G122: walk root is the operator-owned storage directory; no untrusted symlink injection vector.
		src, err := os.Open(path)
		if err != nil {
			return err
		}
		defer src.Close()

		fi, _ := src.Stat()
		if err := l.publish(dest, func(w io.Writer) error {
			_, err := io.Copy(w, src)
			return err
		}); err != nil {
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
