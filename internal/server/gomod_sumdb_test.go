package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	bos3 "github.com/ravinald/bodega/internal/s3"
	"github.com/ravinald/bodega/internal/storage"
)

func (u *recordingUpstream) hits(p string) int {
	n := 0
	for _, got := range u.paths() {
		if got == p {
			n++
		}
	}
	return n
}

// expireMetadata makes every mutable object the cache holds stale, so the next
// request for one has to go upstream again.
func expireMetadata(s *Server) {
	s.cache.MetadataTTL = time.Nanosecond
	time.Sleep(5 * time.Millisecond)
}

// sumdbServer is a proxying server whose checksum database is a recording
// fixture.
func sumdbServer(t *testing.T) (*Server, *recordingUpstream) {
	t.Helper()
	s := proxyingServer(t)
	up := newRecordingUpstream(t)
	s.cfg.GomodSumdbURL = up.ts.URL
	s.cfg.GomodUpstream = up.ts.URL
	return s, up
}

func TestSumdbSupportedContactsNoUpstream(t *testing.T) {
	s, up := sumdbServer(t)
	status, body := getStatusAndBody(t, s, "/go/sumdb/sum.golang.org/supported")
	if status != http.StatusOK || body != "" {
		t.Errorf("supported = %d %q, want 200 and an empty body", status, body)
	}
	if got := up.paths(); len(got) != 0 {
		t.Errorf("supported reached the upstream: %v", got)
	}
}

// With the proxy off, a 200 on supported would route lookups to a server
// that cannot answer them; the 404 sends the go command to the database.
func TestSumdbSupportedIs404WithTheProxyOff(t *testing.T) {
	s, _ := sumdbServer(t)
	s.cache.Enabled = false
	if status, _ := getStatusAndBody(t, s, "/go/sumdb/sum.golang.org/supported"); status != http.StatusNotFound {
		t.Errorf("supported with the proxy off = %d, want 404", status)
	}
}

func TestSumdbMutableDocumentsRefetchAfterTTL(t *testing.T) {
	for _, p := range []string{"latest", "lookup/golang.org/toolchain@v0.0.1-go1.25.3.linux-amd64"} {
		t.Run(p, func(t *testing.T) {
			s, up := sumdbServer(t)
			up.route("/"+p, "signed tree head\n")
			for range 2 {
				status, body := getStatusAndBody(t, s, "/go/sumdb/sum.golang.org/"+p)
				if status != http.StatusOK || body != "signed tree head\n" {
					t.Fatalf("GET %s = %d %q, want 200 with the upstream bytes", p, status, body)
				}
			}
			if n := up.hits("/" + p); n != 1 {
				t.Fatalf("%s fetched %d times inside the TTL, want 1", p, n)
			}
			expireMetadata(s)
			getStatusAndBody(t, s, "/go/sumdb/sum.golang.org/"+p)
			if n := up.hits("/" + p); n != 2 {
				t.Errorf("%s fetched %d times after the TTL, want 2", p, n)
			}
		})
	}
}

func TestSumdbTiles(t *testing.T) {
	const full, partial = "tile/8/0/x001/234", "tile/8/0/x001/235.p/5"
	s, up := sumdbServer(t)
	up.route("/"+full, "full tile")
	up.route("/"+partial, "partial tile")
	for _, p := range []string{full, partial} {
		if status, body := getStatusAndBody(t, s, "/go/sumdb/sum.golang.org/"+p); status != http.StatusOK {
			t.Fatalf("GET %s = %d %q", p, status, body)
		}
	}
	expireMetadata(s)
	for _, p := range []string{full, partial} {
		getStatusAndBody(t, s, "/go/sumdb/sum.golang.org/"+p)
	}
	if n := up.hits("/" + full); n != 1 {
		t.Errorf("a full tile was fetched %d times, want 1: it never changes", n)
	}
	if n := up.hits("/" + partial); n != 2 {
		t.Errorf("a partial tile was fetched %d times after the TTL, want 2: it grows under one name", n)
	}
}

func TestSumdbRefusesOtherPaths(t *testing.T) {
	s, up := sumdbServer(t)
	for _, p := range []string{
		"/go/sumdb/sum.example.com/latest",
		"/go/sumdb/sum.golang.org/../latest",
		"/go/sumdb/sum.golang.org/lookup/%2e%2e/x",
		"/go/sumdb/sum.golang.org/verifier",
		"/go/sumdb/sum.golang.org/",
	} {
		if status, _ := getStatusAndBody(t, s, p); status != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, status)
		}
	}
	if got := up.paths(); len(got) != 0 {
		t.Errorf("a refused path reached the upstream: %v", got)
	}
}

func TestGomodLatestProxies(t *testing.T) {
	s, up := sumdbServer(t)
	const doc = `{"Version":"v0.0.1-go1.25.3.linux-amd64","Time":"2025-10-13T00:00:00Z"}`
	up.route("/golang.org/toolchain/@latest", doc)
	status, body := getStatusAndBody(t, s, "/go/golang.org/toolchain/@latest")
	if status != http.StatusOK || body != doc {
		t.Fatalf("@latest = %d %q, want 200 with the upstream document", status, body)
	}
	expireMetadata(s)
	getStatusAndBody(t, s, "/go/golang.org/toolchain/@latest")
	if n := up.hits("/golang.org/toolchain/@latest"); n != 2 {
		t.Errorf("@latest fetched %d times across a TTL, want 2: it is a mutable document", n)
	}
}

func TestGomodLatestHiddenModuleRefused(t *testing.T) {
	s, up := sumdbServer(t)
	up.route("/example.com/mod/@latest", `{"Version":"v1.0.0"}`)
	if err := s.store.SavePackage(t.Context(), &manifest.PackageManifest{
		ConfigVersion: manifest.CurrentConfigVersion,
		Name:          "example.com/mod",
		Type:          manifest.TypeGomod,
		Versions:      []manifest.VersionEntry{{Version: "v1.0.0", Mode: manifest.ModeProxy, Hidden: true}},
	}); err != nil {
		t.Fatalf("seed the gomod manifest: %v", err)
	}
	if status, _ := getStatusAndBody(t, s, "/go/example.com/mod/@latest"); status == http.StatusOK {
		t.Errorf("@latest of a hidden module answered 200")
	}
	if up.sawPath("/example.com/mod/@latest") {
		t.Errorf("@latest of a hidden module reached the upstream")
	}
}

func TestProfileRefusesAGomodLatestItWouldFilter(t *testing.T) {
	s, up := sumdbServer(t)
	up.route("/example.com/mod/@latest", `{"Version":"v2.0.0"}`)
	if err := s.store.SavePackage(t.Context(), &manifest.PackageManifest{
		ConfigVersion: manifest.CurrentConfigVersion,
		Name:          "example.com/mod",
		Type:          manifest.TypeGomod,
		Versions:      []manifest.VersionEntry{{Version: "v1.0.0", Mode: manifest.ModeProxy}},
	}); err != nil {
		t.Fatalf("seed the gomod manifest: %v", err)
	}
	f := bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeGomod, audit.VersionPinned, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{
			Type: manifest.TypeGomod, Name: "example.com/mod",
			Constraint: manifest.ConstraintExact, Version: "v1.1.0",
		}})
	if status, body := f.get(t, "/go/example.com/mod/@latest"); status != http.StatusNotFound {
		t.Errorf("@latest naming a version the pin refuses = %d %q, want 404", status, body)
	}
	up.route("/example.com/mod/@latest", `{"Version":"v1.1.0"}`)
	expireMetadata(s)
	if status, body := f.get(t, "/go/example.com/mod/@latest"); status != http.StatusOK {
		t.Errorf("@latest naming the pinned version = %d %q, want 200", status, body)
	}
}

func TestBinaryRevalidatePatterns(t *testing.T) {
	s := proxyingServer(t)
	up := newRecordingUpstream(t)
	const channel, tarball = "dist/channel-rust-stable.toml", "dist/2026-01-01/rust-std.tar.xz"
	tarBytes := "\xfd7zXZ\x00 rust-std bytes"
	up.route("/"+channel, "[pkg.rust]\n")
	up.route("/"+tarball, tarBytes)
	s.cfg.BinaryUpstreams = map[string]config.BinaryUpstream{
		"rust": {URL: up.ts.URL + "/", Mode: config.UpstreamModeOpen, Revalidate: []string{"dist/channel-rust-*"}},
	}
	for _, p := range []string{channel, tarball} {
		if status, body := getStatusAndBody(t, s, "/binaries/rust/"+p); status != http.StatusOK {
			t.Fatalf("GET %s = %d %q", p, status, body)
		}
	}
	expireMetadata(s)
	status, body := getStatusAndBody(t, s, "/binaries/rust/"+tarball)
	if status != http.StatusOK || body != tarBytes {
		t.Errorf("cached tarball = %d %q, want 200 with the upstream bytes unchanged", status, body)
	}
	getStatusAndBody(t, s, "/binaries/rust/"+channel)
	if n := up.hits("/" + channel); n != 2 {
		t.Errorf("the channel manifest was fetched %d times after the TTL, want 2", n)
	}
	if n := up.hits("/" + tarball); n != 1 {
		t.Errorf("the dated tarball was fetched %d times, want 1: it never changes", n)
	}
}

// TestRustupRecipeRevalidates reads the rust namespace out of docs/usage.md
// rather than a copy of its list, so the recipe an operator pastes is the one
// tested.
func TestRustupRecipeRevalidates(t *testing.T) {
	usage, err := os.ReadFile("../../docs/usage.md")
	if err != nil {
		t.Fatal(err)
	}
	var block string
	for _, part := range strings.Split(string(usage), "```json\n")[1:] {
		if body, _, _ := strings.Cut(part, "```"); strings.Contains(body, "https://static.rust-lang.org/") {
			block = body
			break
		}
	}
	if block == "" {
		t.Fatal("docs/usage.md has no ```json block naming https://static.rust-lang.org/: the rustup recipe moved or lost its fence")
	}
	var recipe struct {
		BinaryUpstreams map[string]config.BinaryUpstream `json:"binary_upstreams"`
	}
	if err := json.Unmarshal([]byte("{"+block+"}"), &recipe); err != nil {
		t.Fatalf("the rustup recipe in docs/usage.md is not valid JSON once wrapped in {}: %v\n%s", err, block)
	}
	patterns := recipe.BinaryUpstreams["rust"].Revalidate
	if len(patterns) == 0 {
		t.Fatalf("the rustup recipe has no binary_upstreams.rust.revalidate list:\n%s", block)
	}
	for p, want := range map[string]bool{
		"dist/channel-rust-stable.toml":                                   true,
		"rustup/release-stable.toml":                                      true,
		"rustup/dist/x86_64-unknown-linux-gnu/rustup-init":                true,
		"rustup/dist/x86_64-unknown-linux-gnu/rustup-init.sha256":         true,
		"rustup/archive/1.28.2/x86_64-unknown-linux-gnu/rustup-init":      false,
		"dist/2026-01-01/rust-std-1.90.0-x86_64-unknown-linux-gnu.tar.xz": false,
	} {
		if got := revalidates(patterns, p); got != want {
			t.Errorf("recipe %q: revalidates(%s) = %v, want %v", patterns, p, got, want)
		}
	}
}

// sumdbTileBytes is a hash tile of width hashes, each one distinct so that a
// slice taken at the wrong offset cannot match.
func sumdbTileBytes(width int) []byte {
	b := make([]byte, width*sumdbHashSize)
	for i := range b {
		b[i] = byte(i*7 + i/sumdbHashSize)
	}
	return b
}

// cutSumdbUpstream points the checksum database at an address nothing
// listens on, as an egress lock or an outage leaves it.
func cutSumdbUpstream(t *testing.T, s *Server) {
	t.Helper()
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	s.cfg.GomodSumdbURL = dead.URL
}

const sumdbTileDir = "tile/8/1/x001/081"

func TestSumdbPartialTileFromWiderCachedTile(t *testing.T) {
	for _, src := range []struct {
		name  string
		path  string
		width int
	}{
		{"wider partial", sumdbTileDir + ".p/5", 5},
		{"full tile", sumdbTileDir, 256},
	} {
		t.Run(src.name, func(t *testing.T) {
			s, up := sumdbServer(t)
			body := sumdbTileBytes(src.width)
			up.route("/"+src.path, string(body))
			if status, _ := getStatusAndBody(t, s, "/go/sumdb/sum.golang.org/"+src.path); status != http.StatusOK {
				t.Fatalf("filling %s = %d", src.path, status)
			}
			cutSumdbUpstream(t, s)
			status, got := getStatusAndBody(t, s, "/go/sumdb/sum.golang.org/"+sumdbTileDir+".p/3")
			if status != http.StatusOK || got != string(body[:3*sumdbHashSize]) {
				t.Fatalf(".p/3 with the upstream down = %d (%d bytes), want 200 and the first 96 bytes of the cached %s", status, len(got), src.path)
			}
			if up.hits("/"+sumdbTileDir+".p/3") != 0 {
				t.Errorf(".p/3 reached the upstream")
			}
			if info, err := s.typeStore(manifest.TypeGomod).Head(t.Context(), manifest.GomodSumdbKey(gomodSumdbName, sumdbTileDir+".p/3")); err != nil || info.Exists {
				t.Errorf("the derived .p/3 was written under its own key (head %+v, %v)", info, err)
			}
		})
	}
}

func TestSumdbPartialTileNarrowerCachedGoesUpstream(t *testing.T) {
	s, up := sumdbServer(t)
	up.route("/"+sumdbTileDir+".p/2", string(sumdbTileBytes(2)))
	want := sumdbTileBytes(3)
	up.route("/"+sumdbTileDir+".p/3", string(want))
	getStatusAndBody(t, s, "/go/sumdb/sum.golang.org/"+sumdbTileDir+".p/2")
	status, got := getStatusAndBody(t, s, "/go/sumdb/sum.golang.org/"+sumdbTileDir+".p/3")
	if status != http.StatusOK || got != string(want) {
		t.Fatalf(".p/3 = %d, want 200 with the upstream bytes", status)
	}
	if n := up.hits("/" + sumdbTileDir + ".p/3"); n != 1 {
		t.Errorf(".p/3 reached the upstream %d times with only .p/2 cached, want 1", n)
	}
}

// A corrupt source is not sliced: a client handed it would fail the tree head
// check and report a checksum-database security error rather than an outage.
func TestSumdbPartialTileCorruptSourceGoesUpstream(t *testing.T) {
	for _, src := range []struct {
		name  string
		path  string
		width int
	}{
		{"wider partial", sumdbTileDir + ".p/5", 5},
		{"full tile", sumdbTileDir, 256},
	} {
		t.Run(src.name, func(t *testing.T) {
			s, up := sumdbServer(t)
			up.route("/"+src.path, string(sumdbTileBytes(src.width)))
			want := sumdbTileBytes(3)
			up.route("/"+sumdbTileDir+".p/3", string(want))
			getStatusAndBody(t, s, "/go/sumdb/sum.golang.org/"+src.path)
			live := s.cfg.GomodSumdbURL
			cutSumdbUpstream(t, s)
			if status, got := getStatusAndBody(t, s, "/go/sumdb/sum.golang.org/"+sumdbTileDir+".p/3"); status != http.StatusOK || got != string(want) {
				t.Fatalf(".p/3 from the intact %s with the upstream down = %d, want 200 and its prefix", src.path, status)
			}
			s.cfg.GomodSumdbURL = live
			corrupt := sumdbTileBytes(src.width)
			corrupt[0] ^= 0xff
			if err := s.typeStore(manifest.TypeGomod).Put(t.Context(), manifest.GomodSumdbKey(gomodSumdbName, src.path), corrupt); err != nil {
				t.Fatal(err)
			}
			status, got := getStatusAndBody(t, s, "/go/sumdb/sum.golang.org/"+sumdbTileDir+".p/3")
			if status != http.StatusOK || got != string(want) {
				t.Fatalf(".p/3 = %d, want 200 with the upstream bytes, not a slice of the corrupt %s", status, src.path)
			}
			if n := up.hits("/" + sumdbTileDir + ".p/3"); n != 1 {
				t.Errorf(".p/3 reached the upstream %d times past a corrupt source, want 1", n)
			}
		})
	}
}

// countingStore counts every call that reads the store.
type countingStore struct {
	storage.ObjectStore
	reads atomic.Int64
}

func (c *countingStore) Get(ctx context.Context, key string) ([]byte, error) {
	c.reads.Add(1)
	return c.ObjectStore.Get(ctx, key)
}

func (c *countingStore) GetStream(ctx context.Context, key string) (*storage.StreamResult, error) {
	c.reads.Add(1)
	return c.ObjectStore.GetStream(ctx, key)
}

func (c *countingStore) Head(ctx context.Context, key string) (*storage.ObjectInfo, error) {
	c.reads.Add(1)
	return c.ObjectStore.Head(ctx, key)
}

func (c *countingStore) List(ctx context.Context, prefix string) ([]string, error) {
	c.reads.Add(1)
	return c.ObjectStore.List(ctx, prefix)
}

// fakeS3 is enough of the S3 object API for the storage.S3 driver to get,
// head and put objects, counting the requests that read.
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	reads   atomic.Int64
	ts      *httptest.Server
}

func newFakeS3(t *testing.T) *fakeS3 {
	t.Helper()
	f := &fakeS3{objects: map[string][]byte{}}
	f.ts = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.ts.Close)
	return f
}

func (f *fakeS3) serve(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/bucket"), "/")
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.Method {
	case http.MethodPut:
		b, _ := io.ReadAll(r.Body)
		f.objects[key] = b
		w.Header().Set("ETag", fmt.Sprintf(`"%x"`, sha256.Sum256(b)))
	case http.MethodGet, http.MethodHead:
		f.reads.Add(1)
		b, ok := f.objects[key]
		if !ok {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusNotFound)
			if r.Method == http.MethodGet {
				_, _ = io.WriteString(w, `<Error><Code>NoSuchKey</Code><Message>no such key</Message></Error>`)
			}
			return
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%x"`, sha256.Sum256(b)))
		w.Header().Set("Last-Modified", time.Unix(1700000000, 0).UTC().Format(http.TimeFormat))
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		if r.Method == http.MethodGet {
			_, _ = w.Write(b)
		}
	default:
		w.WriteHeader(http.StatusNotImplemented)
	}
}

func (f *fakeS3) store() storage.ObjectStore {
	cfg := aws.Config{
		Region:                     "us-east-1",
		Credentials:                aws.AnonymousCredentials{},
		BaseEndpoint:               aws.String(f.ts.URL),
		HTTPClient:                 f.ts.Client(),
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	}
	return storage.NewS3(bos3.NewClientFromConfig(cfg, "bucket", "us-east-1"))
}

// Finding the widest cached partial reads the store a fixed number of times,
// whatever the requested width: probing every width above it would cost up to
// 255 reads on a miss, each one a request on S3.
func TestSumdbPartialTileStoreReadsBounded(t *testing.T) {
	const maxReads = 5
	backends := []struct {
		name  string
		store func(t *testing.T) (storage.ObjectStore, func() int64)
	}{
		{"filesystem", func(t *testing.T) (storage.ObjectStore, func() int64) {
			c := &countingStore{ObjectStore: storage.NewLocal(t.TempDir())}
			return c, c.reads.Load
		}},
		{"s3", func(t *testing.T) (storage.ObjectStore, func() int64) {
			f := newFakeS3(t)
			return f.store(), f.reads.Load
		}},
	}
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			s, up := sumdbServer(t)
			store, reads := b.store(t)
			s.stores = storage.NewSingle(store)
			const wide = 250
			body := sumdbTileBytes(wide)
			up.route("/"+sumdbTileDir+".p/250", string(body))
			if status, _ := getStatusAndBody(t, s, "/go/sumdb/sum.golang.org/"+sumdbTileDir+".p/250"); status != http.StatusOK {
				t.Fatalf("filling .p/250 = %d", status)
			}
			cutSumdbUpstream(t, s)
			var costs []int64
			for _, w := range []int{1, 3, 128, 249} {
				before := reads()
				p := fmt.Sprintf("%s.p/%d", sumdbTileDir, w)
				status, got := getStatusAndBody(t, s, "/go/sumdb/sum.golang.org/"+p)
				if status != http.StatusOK || got != string(body[:w*sumdbHashSize]) {
					t.Fatalf("%s = %d (%d bytes), want the prefix of .p/250", p, status, len(got))
				}
				costs = append(costs, reads()-before)
			}
			for i, c := range costs {
				if c != costs[0] || c > maxReads {
					t.Fatalf("store reads per miss %v (index %d), want one constant at most %d", costs, i, maxReads)
				}
			}
		})
	}
}
