package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// ctxStore records the context every List was handed and can be made to
// honor cancellation, which storage.Local does not and storage.S3 does.
type ctxStore struct {
	*storage.Memory
	lastListErr atomic.Value // error or nil
	honorCtx    atomic.Bool
}

func (c *ctxStore) List(ctx context.Context, prefix string) ([]string, error) {
	err := ctx.Err()
	c.lastListErr.Store(errBox{err})
	if c.honorCtx.Load() && err != nil {
		return nil, err
	}
	return c.Memory.List(ctx, prefix)
}

type errBox struct{ err error }

func (c *ctxStore) listErr() error {
	v, _ := c.lastListErr.Load().(errBox)
	return v.err
}

// refreshTestServer builds a Server over a real manifest directory on disk, so
// a test can edit a manifest out of band the way an operator does.
func refreshTestServer(t *testing.T) (*Server, *ctxStore, string) {
	t.Helper()
	dir := t.TempDir()
	store := manifest.NewLocalStore(dir)
	ctx := t.Context()
	if err := store.AddVersion(ctx, manifest.TypeApt, "hello", manifest.VersionEntry{
		Version:      "1.0.0",
		SourceName:   "hello",
		ArtifactSize: 10,
		Description:  "original",
		Metadata: map[string]string{
			"Architecture": "amd64",
			"_pool_path":   "pool/main/h/hello/hello_1.0.0_amd64.deb",
		},
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	if err := store.SaveIndex(ctx); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}

	cs := &ctxStore{Memory: storage.NewMemory()}
	cs.Seed("packages/apt/pool/main/h/hello/hello_1.0.0_amd64.deb", "\x00deb")

	cfg := &config.Config{ManifestDir: dir, AptCodename: "noble", MetadataTTL: "1h"}
	s := newServer(cfg, store, storage.NewSingle(cs), ":0", nil)
	return s, cs, dir
}

// TestRebuildAfterWriteOutlivesTheRequest covers the mutation path: the write
// has already committed when the rebuild starts, so a client that hangs up
// must not be able to cancel the index update and leave a 201 describing state
// the index does not show.
func TestRebuildAfterWriteOutlivesTheRequest(t *testing.T) {
	s, cs, _ := refreshTestServer(t)
	cs.honorCtx.Store(true)

	// Drop the cached pool listing: with it, the rebuild never reaches List
	// and the test would pass against the defect.
	s.aptPool.Store(nil)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	s.rebuildAptIndexAfterWrite(canceled, manifest.TypeApt)

	if err := cs.listErr(); err != nil {
		t.Errorf("pool listing ran on a canceled context (%v); the rebuild must detach from the request", err)
	}
	if snap := s.aptSnap.Load(); snap == nil || snap.suites["noble"] == nil {
		t.Fatal("no snapshot after the post-write rebuild")
	}
}

// TestRefreshReloadsManifestsFromDisk is the hourly tick's contract: an edit
// made outside the process has to reach the index. Without the reload the
// tick re-stamps Valid-Until over an unchanged in-memory cache forever.
func TestRefreshReloadsManifestsFromDisk(t *testing.T) {
	s, _, dir := refreshTestServer(t)

	path := filepath.Join(dir, "apt", "hello", "manifest.json")
	raw, err := os.ReadFile(path) //nolint:gosec // test-owned temp dir
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var pm map[string]any
	if err := json.Unmarshal(raw, &pm); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	versions, _ := pm["versions"].([]any)
	if len(versions) == 0 {
		t.Fatalf("manifest has no versions: %s", raw)
	}
	v, _ := versions[0].(map[string]any)
	v["description"] = "EDITED-BY-HAND"
	edited, err := json.Marshal(pm)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	ctx := t.Context()
	s.reloadManifests(ctx)
	s.rebuildAptSnapshot(ctx)

	snap := s.aptSnap.Load()
	if snap == nil || snap.suites["noble"] == nil {
		t.Fatal("no snapshot after refresh")
	}
	packages := string(snap.suites["noble"].packages["amd64"])
	if !strings.Contains(packages, "EDITED-BY-HAND") {
		t.Errorf("out-of-band manifest edit did not reach the index:\n%s", packages)
	}
}

// TestTickIntervalShortensWithoutASnapshot covers the 503 window: with no
// snapshot every apt request fails, and the failures that put it there
// (credentials, a network that was not up at unit start) are usually over in
// seconds rather than in an hour.
func TestTickIntervalShortensWithoutASnapshot(t *testing.T) {
	s, _, _ := refreshTestServer(t)

	if got := s.aptTickInterval(); got != aptRefreshInterval {
		t.Errorf("interval with a snapshot = %v, want %v", got, aptRefreshInterval)
	}
	s.aptSnap.Store(nil)
	if got := s.aptTickInterval(); got != aptRetryInterval {
		t.Errorf("interval with no snapshot = %v, want %v", got, aptRetryInterval)
	}
}

// TestPoolListFailureStillLeavesAnErrorPath pins the 503 the operator sees
// when the very first snapshot cannot be built, message included: it names
// what failed and where to look, which the retry loop then works to clear.
func TestPoolListFailureStillLeavesAnErrorPath(t *testing.T) {
	s, _, _ := refreshTestServer(t)
	s.aptSnap.Store(nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/apt/dists/noble/Release", nil)
	s.handleAptRelease(w, r, "noble")

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 with no snapshot", w.Code)
	}
	if !strings.Contains(w.Body.String(), "no snapshot has been built") {
		t.Errorf("503 body does not say what failed: %q", w.Body.String())
	}
}
