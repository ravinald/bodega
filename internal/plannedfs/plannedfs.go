// Package plannedfs reads the host's files as a plan would leave them.
//
// doctor's trust verdict reads a client's configuration from disk. Run
// inside With, the same verdict sees every file a plan would write at its
// target, with the rest of the disk unchanged, so a plan can be judged by
// the code that judges the installed result, before anything is written.
// Outside With, each function is its os or filepath counterpart.
package plannedfs

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

var (
	mu      sync.RWMutex
	planned map[string][]byte
)

// With runs fn while files, keyed by absolute path, read as their content
// here. Calls do not nest.
func With(files map[string][]byte, fn func() error) error {
	clean := make(map[string][]byte, len(files))
	for name, data := range files {
		clean[filepath.Clean(name)] = data
	}
	mu.Lock()
	planned = clean
	mu.Unlock()
	defer func() {
		mu.Lock()
		planned = nil
		mu.Unlock()
	}()
	return fn()
}

func lookup(name string) ([]byte, bool) {
	mu.RLock()
	defer mu.RUnlock()
	data, ok := planned[filepath.Clean(name)]
	return data, ok
}

// plannedDir reports whether a planned file lies below dir, which then
// exists in the planned tree whether or not it does on disk.
func plannedDir(dir string) bool {
	mu.RLock()
	defer mu.RUnlock()
	prefix := filepath.Clean(dir) + string(filepath.Separator)
	for name := range planned {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// ReadFile is os.ReadFile over the planned tree.
func ReadFile(name string) ([]byte, error) {
	if data, ok := lookup(name); ok {
		return slices.Clone(data), nil
	}
	return os.ReadFile(name)
}

// Stat is os.Stat over the planned tree.
func Stat(name string) (fs.FileInfo, error) {
	if data, ok := lookup(name); ok {
		mode := fs.FileMode(0o644)
		if info, err := os.Stat(name); err == nil {
			mode = info.Mode()
		}
		return info{name: filepath.Base(name), size: int64(len(data)), mode: mode}, nil
	}
	got, err := os.Stat(name)
	if err != nil && os.IsNotExist(err) && plannedDir(name) {
		return info{name: filepath.Base(name), mode: fs.ModeDir | 0o755}, nil
	}
	return got, err
}

// ReadDir is os.ReadDir over the planned tree: the directory's entries on
// disk, plus each planned file or directory directly inside it.
func ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := os.ReadDir(name)
	if err != nil && !(os.IsNotExist(err) && plannedDir(name)) {
		return entries, err
	}
	have := map[string]bool{}
	for _, e := range entries {
		have[e.Name()] = true
	}
	mu.RLock()
	prefix := filepath.Clean(name) + string(filepath.Separator)
	for file, data := range planned {
		rest, ok := strings.CutPrefix(file, prefix)
		if !ok {
			continue
		}
		first, deeper, _ := strings.Cut(rest, string(filepath.Separator))
		if have[first] {
			continue
		}
		have[first] = true
		if deeper != "" {
			entries = append(entries, fs.FileInfoToDirEntry(info{name: first, mode: fs.ModeDir | 0o755}))
		} else {
			entries = append(entries, fs.FileInfoToDirEntry(info{name: first, size: int64(len(data)), mode: 0o644}))
		}
	}
	mu.RUnlock()
	slices.SortFunc(entries, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return entries, nil
}

// Glob is filepath.Glob over the planned tree.
func Glob(pattern string) ([]string, error) {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	mu.RLock()
	for file := range planned {
		// The file and each directory above it, which the planned tree
		// holds even where the disk does not.
		for p := file; p != filepath.Dir(p); p = filepath.Dir(p) {
			if ok, _ := filepath.Match(pattern, p); ok && !slices.Contains(matches, p) {
				matches = append(matches, p)
			}
		}
	}
	mu.RUnlock()
	slices.Sort(matches)
	return matches, nil
}

type info struct {
	name string
	size int64
	mode fs.FileMode
}

func (i info) Name() string       { return i.name }
func (i info) Size() int64        { return i.size }
func (i info) Mode() fs.FileMode  { return i.mode }
func (i info) ModTime() time.Time { return time.Time{} }
func (i info) IsDir() bool        { return i.mode.IsDir() }
func (i info) Sys() any           { return nil }
