package server_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/server"
	"github.com/ravinald/bodega/internal/storage"
)

// multiResolver is a Resolver whose backends are supplied directly, which
// storage.NewResolver cannot do: it builds from config, and a config-built
// backend cannot be wrapped to fail on demand. Tests that only need two real
// backends use storage.NewResolver instead — see placement_test.go.
type multiResolver struct {
	stores []storage.NamedStore
}

func (r *multiResolver) Default() storage.ObjectStore { return r.stores[0].Store }

func (r *multiResolver) ByName(name string) (storage.ObjectStore, error) {
	if name == "" {
		name = storage.DefaultName
	}
	for _, ns := range r.stores {
		if ns.Name == name {
			return ns.Store, nil
		}
	}
	return nil, errors.New("unknown storage backend " + name)
}

func (r *multiResolver) Placement(_, _ string) storage.Decision {
	return storage.Decision{Name: storage.DefaultName}
}
func (r *multiResolver) ForType(_ string) storage.ObjectStore { return r.stores[0].Store }
func (r *multiResolver) All() []storage.NamedStore            { return r.stores }
func (r *multiResolver) Fanout(context.Context, string, []string) []storage.NamedStore {
	return r.stores
}

// countingStore records how many times List was called and can be made to fail.
type countingStore struct {
	storage.ObjectStore
	lists   atomic.Int64
	listErr error
}

func (c *countingStore) List(ctx context.Context, prefix string) ([]string, error) {
	c.lists.Add(1)
	if c.listErr != nil {
		return nil, c.listErr
	}
	return c.ObjectStore.List(ctx, prefix)
}

func fanoutServer(t *testing.T, stores ...storage.NamedStore) *httptest.Server {
	t.Helper()
	store := manifest.NewLocalStore(t.TempDir())
	if err := store.AddVersion(t.Context(), manifest.TypePypi, "thing", manifest.VersionEntry{Version: "1.0"}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	cfg := &config.Config{ManifestDir: "manifests", AptCodename: "noble", MetadataTTL: "1h"}
	ts := httptest.NewServer(server.New(cfg, store, &multiResolver{stores: stores}, ":0", nil).Handler())
	t.Cleanup(ts.Close)
	return ts
}

func getBody(t *testing.T, ts *httptest.Server, path string) (int, string) {
	t.Helper()
	resp, err := http.Get(ts.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// TestListFanoutSortsTheUnion pins the ordering rule. Each backend returns
// lexical order, but concatenating two sorted lists is not sorted, and the
// PEP 503 body (like Packages.gz) is generated per request — an unstable order
// changes the bytes and every client refetches.
func TestListFanoutSortsTheUnion(t *testing.T) {
	a := storage.NewMemory()
	a.Seed("pypi/wheels/thing-1.0-py3-none-any.whl", "a")
	a.Seed("pypi/wheels/thing-3.0-py3-none-any.whl", "a")
	b := storage.NewMemory()
	b.Seed("pypi/wheels/thing-2.0-py3-none-any.whl", "b")

	ts := fanoutServer(t,
		storage.NamedStore{Name: storage.DefaultName, Store: a},
		storage.NamedStore{Name: "bulk", Store: b},
	)

	status, body := getBody(t, ts, "/pypi/simple/thing/")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", status, body)
	}
	var at []int
	for _, wheel := range []string{"thing-1.0", "thing-2.0", "thing-3.0"} {
		i := strings.Index(body, wheel)
		if i < 0 {
			t.Fatalf("index does not list %s, so the fan-out dropped a backend:\n%s", wheel, body)
		}
		at = append(at, i)
	}
	if !(at[0] < at[1] && at[1] < at[2]) {
		t.Errorf("union is not sorted; wheels 1.0/2.0/3.0 appear at %v:\n%s", at, body)
	}
}

// TestListFanoutDedupesTheUnion covers the same key present on two backends,
// which a re-upload after a placement change produces.
func TestListFanoutDedupesTheUnion(t *testing.T) {
	const key = "pypi/wheels/thing-1.0-py3-none-any.whl"
	a := storage.NewMemory()
	a.Seed(key, "a")
	b := storage.NewMemory()
	b.Seed(key, "b")

	ts := fanoutServer(t,
		storage.NamedStore{Name: storage.DefaultName, Store: a},
		storage.NamedStore{Name: "bulk", Store: b},
	)

	_, body := getBody(t, ts, "/pypi/simple/thing/")
	if got := strings.Count(body, "thing-1.0-py3-none-any.whl</a>"); got != 1 {
		t.Errorf("wheel listed %d times, want 1:\n%s", got, body)
	}
}

// TestListFanoutFailsRequestOnBackendError pins the failure mode. A partial
// PEP 503 index is indistinguishable from packages having been withdrawn, and
// a client acts on the difference, so one backend failing fails the request.
func TestListFanoutFailsRequestOnBackendError(t *testing.T) {
	a := storage.NewMemory()
	a.Seed("pypi/wheels/thing-1.0-py3-none-any.whl", "a")
	broken := &countingStore{ObjectStore: storage.NewMemory(), listErr: errors.New("backend down")}

	ts := fanoutServer(t,
		storage.NamedStore{Name: storage.DefaultName, Store: a},
		storage.NamedStore{Name: "bulk", Store: broken},
	)

	status, body := getBody(t, ts, "/pypi/simple/thing/")
	if status != http.StatusBadGateway {
		t.Errorf("status = %d, want 502; a partial index would have been served as 200:\n%s", status, body)
	}
	if strings.Contains(body, "thing-1.0") {
		t.Errorf("served the reachable backend's half of the index:\n%s", body)
	}
}

// TestAptPoolListingIsCached pins the cache in front of the pool listing.
// Every apt-touching API write rebuilds the snapshot and the rebuild lists the
// whole pool, so without this each write paid for a full unbounded listing,
// multiplied by the number of backends once the listing fans out.
//
// The fixture turns on the one entry with no _pool_path: an index whose
// entries all carry one never lists at all, which is the cheaper path
// TestNoListingWhenEveryEntryCarriesPoolPath covers. This is the case where
// the listing is genuinely needed and the cache is what bounds it.
//
// That entry's .deb is deliberately absent from the pool. A fallback that
// resolves proves nothing here: the re-list this bound was lost to only fires
// when one does not, and staging an entry before uploading its .deb is the
// ordinary way to hold one unresolved for hours. Seeding it made the test
// green against a rebuild that listed the pool on every write.
func TestAptPoolListingIsCached(t *testing.T) {
	mem := storage.NewMemory()
	mem.Seed("packages/apt/pool/main/h/hello/hello_1.0_amd64.deb", "\x00deb")
	counting := &countingStore{ObjectStore: mem}

	store := manifest.NewLocalStore(t.TempDir())
	if err := store.AddVersion(t.Context(), manifest.TypeApt, "hello", manifest.VersionEntry{
		Version:  "1.0",
		Metadata: map[string]string{"Architecture": "amd64", "_pool_path": "pool/main/h/hello/hello_1.0_amd64.deb"},
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	if err := store.AddVersion(t.Context(), manifest.TypeApt, "older", manifest.VersionEntry{
		Version:  "0.9",
		Metadata: map[string]string{"Architecture": "amd64"},
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	cfg := &config.Config{
		ManifestDir:     "manifests",
		AptCodename:     "noble",
		MetadataTTL:     "1h",
		AdminPermitCIDR: []string{"127.0.0.0/8", "::1/128"},
	}
	res := &multiResolver{stores: []storage.NamedStore{{Name: storage.DefaultName, Store: counting}}}
	ts := httptest.NewServer(server.New(cfg, store, res, ":0", nil).Handler())
	t.Cleanup(ts.Close)

	after := counting.lists.Load()
	if after != 1 {
		t.Fatalf("startup listed the pool %d times, want 1; a listing taken on this call cannot be stale to it", after)
	}

	for i := 0; i < 3; i++ {
		body := `{"name":"n` + string(rune('a'+i)) + `","type":"apt","versions":[{"version":"3.0.0","metadata":{"Architecture":"amd64","_pool_path":"pool/main/n/n/n_3.0.0_amd64.deb"}}]}`
		resp, err := http.Post(ts.URL+"/api/v1/packages/apt", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		got, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("POST status = %d, want 201 (a rejected write rebuilds nothing and the count proves nothing): %s", resp.StatusCode, got)
		}
	}

	if got := counting.lists.Load(); got != after {
		t.Errorf("three apt writes listed the pool %d more times, want 0 within metadata_ttl", got-after)
	}
}

// TestPackageRouteWithoutStorageDoesNotBlameS3 pins caveat #34. A local
// install whose storage_path cannot be created used to serve a 503 naming a
// backend the config never asked for, sending operators after a bucket.
func TestPackageRouteWithoutStorageDoesNotBlameS3(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	cfg := &config.Config{StorageBackend: "local", ManifestDir: "manifests", AptCodename: "noble"}
	ts := httptest.NewServer(server.New(cfg, store, nil, ":0", nil).Handler())
	t.Cleanup(ts.Close)

	for _, path := range []string{
		"/apt/pool/main/a/acme/acme_1.0_amd64.deb",
		"/pypi/simple/",
		"/binaries/thing",
	} {
		status, body := getBody(t, ts, path)
		if status != http.StatusServiceUnavailable {
			t.Errorf("GET %s status = %d, want 503", path, status)
		}
		for _, blame := range []string{"S3", "s3://", "bucket", "BOOTSTRAP_BUCKET", "REPO_BUCKET"} {
			if strings.Contains(body, blame) {
				t.Errorf("GET %s 503 body names %q on a local install: %q", path, blame, strings.TrimSpace(body))
			}
		}
		if !strings.Contains(body, "startup log") {
			t.Errorf("GET %s 503 body does not point at the reason: %q", path, strings.TrimSpace(body))
		}
	}
}
