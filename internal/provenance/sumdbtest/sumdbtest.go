// Package sumdbtest stands up a Go checksum database for tests: a
// sumdb.TestServer behind httptest, signed with a key named sum.golang.org,
// so no test reads the public database.
package sumdbtest

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/mod/sumdb"
	"golang.org/x/mod/sumdb/dirhash"
	"golang.org/x/mod/sumdb/note"
)

// Name is the database every log here signs as: the only one bodega checks.
const Name = "sum.golang.org"

// Key is a signer key and the verifier key that checks it.
type Key struct {
	Signer, Verifier string
}

// NewKey generates a key named sum.golang.org.
func NewKey(t testing.TB) Key {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, Name)
	if err != nil {
		t.Fatal(err)
	}
	return Key{Signer: skey, Verifier: vkey}
}

// Log is a checksum database serving the lines Add gave it. A version with
// no lines is answered 404, as sum.golang.org answers a module it cannot
// fetch.
type Log struct {
	*httptest.Server
	Key Key
	// Wrap, when set, answers every request in place of the database, and
	// is handed the database to call for the requests it passes through.
	Wrap func(w http.ResponseWriter, r *http.Request, db http.Handler)

	mu    sync.Mutex
	lines map[string]string
	hits  map[string]int
}

// New starts a log signed with key. It closes with the test.
func New(t testing.TB, key Key) *Log {
	t.Helper()
	l := &Log{Key: key, lines: map[string]string{}, hits: map[string]int{}}
	db := sumdb.NewServer(sumdb.NewTestServer(key.Signer, l.gosum))
	l.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		l.hits[r.URL.Path]++
		wrap := l.Wrap
		l.mu.Unlock()
		if wrap != nil {
			wrap(w, r, db)
			return
		}
		db.ServeHTTP(w, r)
	}))
	t.Cleanup(l.Close)
	return l
}

// Add records the go.sum lines for module@version: zipHash for the module
// zip and modHash for its go.mod. Either empty leaves that line out.
func (l *Log) Add(module, version, zipHash, modHash string) {
	var b strings.Builder
	if zipHash != "" {
		fmt.Fprintf(&b, "%s %s %s\n", module, version, zipHash)
	}
	if modHash != "" {
		fmt.Fprintf(&b, "%s %s/go.mod %s\n", module, version, modHash)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines[module+"@"+version] = b.String()
}

// Hits is how many requests reached path.
func (l *Log) Hits(path string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.hits[path]
}

func (l *Log) gosum(module, version string) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	lines, ok := l.lines[module+"@"+version]
	if !ok {
		return nil, os.ErrNotExist
	}
	return []byte(lines), nil
}

// Module is one module version's files and the h1: hashes the go command
// computes for them.
type Module struct {
	Path, Version string
	Zip, Mod      []byte
	ZipHash       string
	ModHash       string
}

// NewModule builds module@version with a go.mod and one source file whose
// content is body, and hashes both as dirhash does.
func NewModule(t testing.TB, module, version, body string) Module {
	t.Helper()
	m := Module{Path: module, Version: version, Mod: []byte("module " + module + "\n\ngo 1.22\n")}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	prefix := module + "@" + version + "/"
	for name, data := range map[string][]byte{"go.mod": m.Mod, "lib.go": []byte("package lib\n\n// " + body + "\n")} {
		f, err := zw.Create(prefix + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	m.Zip = buf.Bytes()
	path := filepath.Join(t.TempDir(), "m.zip")
	if err := os.WriteFile(path, m.Zip, 0o600); err != nil {
		t.Fatal(err)
	}
	var err error
	if m.ZipHash, err = dirhash.HashZip(path, dirhash.Hash1); err != nil {
		t.Fatal(err)
	}
	if m.ModHash, err = dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(m.Mod)), nil
	}); err != nil {
		t.Fatal(err)
	}
	return m
}

// AddModule records m's hashes in the log.
func (l *Log) AddModule(m Module) { l.Add(m.Path, m.Version, m.ZipHash, m.ModHash) }
