package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Memory is an in-memory ObjectStore. It exists so tests in other packages can
// exercise the real ObjectStore contract instead of a hand-rolled fake per
// package: PutFile reads the file, Head reports Exists=false for a key that was
// never written, and a missing Get returns (nil, nil) like every other backend.
//
// Safe for concurrent use. Not a cache and not persistent — process exit loses
// everything.
type Memory struct {
	mu      sync.RWMutex
	objects map[string]memObject
	label   string
}

type memObject struct {
	data     []byte
	modified time.Time
}

// memSeq numbers Memory instances so each one has its own Label.
//
// Label is the identity dedupByLabel compares to decide whether two backend
// names are one physical location, and 'pkg move' refuses a move between two
// names that share one. Every Memory answering "mem://" would make a fixture
// of two independent stores look like a single place to both.
var memSeq atomic.Uint64

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		objects: map[string]memObject{},
		label:   "mem://" + strconv.FormatUint(memSeq.Add(1), 10),
	}
}

// Seed stores data at key without a context or an error return, for test
// fixtures that set up state rather than exercise the write path.
func (m *Memory) Seed(key, data string) {
	_ = m.Put(context.Background(), key, []byte(data))
}

// Keys returns every stored key in lexical order.
func (m *Memory) Keys() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	keys := make([]string, 0, len(m.objects))
	for k := range m.objects {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (m *Memory) Get(_ context.Context, key string) ([]byte, error) {
	if err := ValidateKey(key); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	obj, ok := m.objects[key]
	if !ok {
		return nil, nil
	}
	// nil is the answer to "no such object" and nothing else, so a stored
	// zero-length object comes back as a non-nil empty slice. append to a nil
	// slice would return nil for one, making an empty artifact
	// indistinguishable from a missing one.
	out := make([]byte, len(obj.data))
	copy(out, obj.data)
	return out, nil
}

func (m *Memory) GetStream(_ context.Context, key string) (*StreamResult, error) {
	if err := ValidateKey(key); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	obj, ok := m.objects[key]
	if !ok {
		return nil, nil
	}
	data := append([]byte(nil), obj.data...)
	return &StreamResult{
		Body:          io.NopCloser(bytes.NewReader(data)),
		ContentLength: int64(len(data)),
		ContentType:   "application/octet-stream",
	}, nil
}

func (m *Memory) Head(_ context.Context, key string) (*ObjectInfo, error) {
	if err := ValidateKey(key); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	obj, ok := m.objects[key]
	if !ok {
		return &ObjectInfo{Key: key, Exists: false}, nil
	}
	return &ObjectInfo{
		Key:          key,
		Exists:       true,
		Size:         int64(len(obj.data)),
		LastModified: obj.modified,
	}, nil
}

func (m *Memory) List(_ context.Context, prefix string) ([]string, error) {
	if err := ValidateKey(prefix); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var keys []string
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

func (m *Memory) Put(_ context.Context, key string, data []byte) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[key] = memObject{data: append([]byte(nil), data...), modified: time.Now()}
	return nil
}

func (m *Memory) PutFile(ctx context.Context, localPath, key string) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", localPath, err)
	}
	return m.Put(ctx, key, data)
}

func (m *Memory) Delete(_ context.Context, key string) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objects, key)
	return nil
}

func (m *Memory) SyncDir(ctx context.Context, out io.Writer, localDir, keyPrefix string) (int, error) {
	count := 0
	err := filepath.WalkDir(localDir, func(path string, d os.DirEntry, err error) error {
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
		if err := m.PutFile(ctx, path, key); err != nil {
			return err
		}
		if out != nil {
			fmt.Fprintf(out, "    upload: %s%s\n", m.label, key)
		}
		count++
		return nil
	})
	return count, err
}

func (m *Memory) Label() string { return m.label }
