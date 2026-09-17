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
//
// Write contract (ObjectStore.Put). Local keeps all four. A write fills a
// staging file and renames it over the key, so replacement is atomic and a
// reader holding an open handle keeps the inode it opened for as long as it
// holds it; an interrupted write leaves a .bodega-tmp-* entry that List skips
// and nothing reads. It is the only backend that carries access state, so the
// fourth promise is mostly about this one: a replacement restates the object's
// mode, owner, group, ACL and extended attributes, and fails with the previous
// object untouched where it cannot. See publish.
//
// Durability is not promised, and this is the one clause Local declines.
// publish closes the staging file and renames it with no fsync of either the
// file or the directory, so a host that loses power moments after Put returns
// can come up holding the previous object, the new one, or a key whose rename
// the journal never recorded. The ordering promises above survive that — the
// rename is atomic whether or not it landed — and the bytes may not. Every
// artifact this store holds is refetchable from an upstream or rebuildable
// from source, and an fsync per object is paid on every proxy cache fill,
// which is the trade taken. An operator who needs the other one mounts the
// storage tree with the filesystem's own barrier settings.
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
			// A staging enclosure holds nothing this store would return and
			// is readable by the writer alone, so a walk by any other account
			// is refused entry to it. Descending would make one process's
			// in-flight write another's listing error.
			if strings.HasPrefix(d.Name(), tmpPrefix) {
				return fs.SkipDir
			}
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
		//nolint:gosec // perm is the writer's own mode on a replacement, or the fresh mode before umask; never a widening.
		f, err := os.OpenFile(filepath.Join(dir, tmpPrefix+rand.Text()), os.O_RDWR|os.O_CREATE|os.O_EXCL, perm)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		return f, err
	}
	return nil, fmt.Errorf("create staging file in %s: no unused name", dir)
}

// staging is the file a publication fills, together with the directory it was
// given to itself when it was given one.
type staging struct {
	file *os.File
	// enclosure is a directory holding nothing but the staging file, empty for
	// a staging file that is a sibling of its destination.
	enclosure string
}

// enclose stages a replacement inside a directory nothing but this server may
// enter, and gives the staging file inside it no grant of its own.
//
// Confidentiality is a rule the staging file needs separately from the object,
// because for the length of the write the two are not the same thing. The
// staging file holds the whole replacement body before it holds any of the
// access state of the object it replaces, so it is an artifact under the
// writer's mode and the writer's ownership rather than the object's, and every
// ordering of the syscalls that fix that discloses it to somebody. Restate the
// object's mode first and the staging file is readable at that mode while it
// is still owned by the server, so the server's group gets it. Hand it to the
// object's owner first and it is readable at the staging mode by an owner the
// object's own mode may deny. Fixing both at once is not something the two
// kernels offer, and an extended-attribute call against a file at 0000 is
// refused, so there is no mode that is safe throughout either.
//
// A directory the server has to itself removes the question rather than
// answering it: a path nothing else may traverse cannot be opened, whatever
// the inode at the end of it says at any instant. The rename out of it is the
// first moment the bytes are addressable, and by then they carry the object's
// access state.
//
// A fresh object gets none of this and must not: it is the staging file, so it
// takes the directory's inheritance and the umask exactly as a direct create
// would, and it discloses nothing before the rename that it will not disclose
// after.
func enclose(dir string) (staging, error) {
	for range 100 {
		enclosure := filepath.Join(dir, tmpPrefix+rand.Text())
		if err := os.Mkdir(enclosure, stagedDirPerm); err != nil {
			if errors.Is(err, fs.ErrExist) {
				continue
			}
			return staging{}, err
		}
		f, err := sealEnclosure(enclosure)
		if err != nil {
			os.RemoveAll(enclosure)
			return staging{}, err
		}
		return staging{file: f, enclosure: enclosure}, nil
	}
	return staging{}, fmt.Errorf("create staging directory in %s: no unused name", dir)
}

// sealEnclosure strips the enclosure of whatever its parent's inheritance put
// on it and then opens the staging file, which therefore inherits nothing.
// Restricting the file too is not redundant: it makes the guarantee a property
// of the inode rather than of an argument about the directory above it.
func sealEnclosure(enclosure string) (*os.File, error) {
	d, err := os.Open(enclosure)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	if err := restrictStaged(d, stagedDirPerm); err != nil {
		return nil, fmt.Errorf("hold the staging directory %s to this server: %w", enclosure, err)
	}
	f, err := createStaged(enclosure, stagedPerm)
	if err != nil {
		return nil, err
	}
	if err := restrictStaged(f, stagedPerm); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// discard removes a staging file that will not be published, and the enclosure
// with it. A failed publication leaves the previous object and nothing else.
func (s staging) discard() {
	s.file.Close()
	if s.enclosure != "" {
		os.RemoveAll(s.enclosure)
		return
	}
	os.Remove(s.file.Name())
}

// publishAs renames the staging file onto p, which is the instant the key
// starts naming the new object.
func (s staging) publishAs(p string) error {
	if err := s.file.Close(); err != nil {
		return err
	}
	if err := os.Rename(s.file.Name(), p); err != nil {
		return err
	}
	// The enclosure is empty now and the object is published either way, so a
	// failure to remove it is not a failed write. What is left is a directory
	// List already skips and nothing reads.
	if s.enclosure != "" {
		_ = os.Remove(s.enclosure)
	}
	return nil
}

// openPrior opens the object a publication is about to replace, or returns nil
// when the key holds nothing yet.
//
// The handle, not the path, is what the new object's access state is read
// from, and it is held across the write so that the state applied is one the
// object genuinely had. A key holding something that is not a regular file
// names no object: publication replaces the name either way, and there is no
// mode, owner or ACL on a directory that means anything on a file.
func openPrior(p string) (*os.File, error) {
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w. A replacement carries the access state of the object it replaces, "+
			"which has to be read first; the previous object is unchanged", err)
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, err
	}
	return f, nil
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
// A new inode carries nothing the old one decided, so a replacement restates
// all of it: mode, owner, group and extended attributes, applied to the
// staging file before the mode that makes it readable. An operator who
// restricted one artifact restricted it, and a refill is not a decision to
// publish it, nor to hand it to a reader the ACL denied, nor to take it from
// the group that owned it. Where that cannot be restated, the publication
// fails and the old object stays: a replacement is bytes, never a change of
// who may read them. A fresh object has no predecessor and takes freshPerm as
// the process umask filters it, which is what the direct os.Create it replaced
// left behind.
func (l *Local) publish(p string, freshPerm os.FileMode, write func(io.Writer) error) (err error) {
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	prior, err := openPrior(p)
	if err != nil {
		return err
	}
	var tmp staging
	if prior == nil {
		f, createErr := createStaged(dir, freshPerm)
		if createErr != nil {
			return createErr
		}
		tmp = staging{file: f}
	} else {
		defer prior.Close()
		if tmp, err = enclose(dir); err != nil {
			return err
		}
	}
	defer func() {
		if err != nil {
			tmp.discard()
		}
	}()
	if err = write(tmp.file); err != nil {
		return err
	}
	if prior != nil {
		// Read after the write rather than before it. A chmod during a long
		// fetch is a decision about the object, and the handle still names the
		// inode whose state is being carried.
		var want access
		if want, err = readAccess(prior); err != nil {
			return err
		}
		if err = want.applyTo(tmp.file, p); err != nil {
			return err
		}
	}
	return tmp.publishAs(p)
}

func (l *Local) Put(_ context.Context, key string, data []byte) error {
	p, err := l.path(key)
	if err != nil {
		return err
	}
	// 0666 before the umask is what a file creation leaves. Put wrote 0644
	// through os.WriteFile and is the one caller whose fresh objects are not
	// group-writable on a permissive umask.
	return l.publish(p, 0o644, func(w io.Writer) error {
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
	return l.publish(p, 0o666, func(w io.Writer) error {
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
		if err := l.publish(dest, 0o666, func(w io.Writer) error {
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
