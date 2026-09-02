package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// newDiscoveryServer builds a Server in observe mode with an empty manifest
// store and drives the recorder's worker, so a row a handler enqueues actually
// reaches SQLite. Without the worker every assertion here would pass against a
// tree whose handlers record nothing: the queue is buffered.
func newDiscoveryServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		AptCodename: "noble",
		LogDir:      dir,
		AuditDB:     filepath.Join(dir, "audit.db"),
		// The git smart-HTTP root hangs off storage_path. Left empty it
		// resolves to /var/lib/bodega and a test that clones writes outside
		// its own temp tree.
		StoragePath:    dir,
		DiscoverMode:   "observe",
		GomodUpstream:  "https://proxy.golang.org",
		NpmUpstream:    "https://registry.npmjs.org",
		AllowPlaintext: true,
	}
	s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), storage.NewSingle(storage.NewMemory()),
		"127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if s.discovery == nil {
		t.Fatal("discovery recorder not constructed; the test would assert nothing")
	}
	ctx, cancel := context.WithCancel(context.Background())
	go s.discovery.Start(ctx)
	t.Cleanup(func() {
		cancel()
		_ = s.auditDB.Close()
	})
	return s
}

// waitForDiscovery polls until at least want rows are visible, because the
// recorder writes off the request goroutine.
func waitForDiscovery(t *testing.T, s *Server, want int) []audit.DiscoveryRow {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var rows []audit.DiscoveryRow
	for time.Now().Before(deadline) {
		var err error
		rows, err = s.auditDB.ListDiscovery(context.Background(), audit.DiscoveryFilter{
			Decision: audit.DecisionNoManifest,
		})
		if err != nil {
			t.Fatalf("list discovery: %v", err)
		}
		if len(rows) >= want {
			return rows
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("discovery rows = %d after 3s, want %d (%+v)", len(rows), want, rows)
	return nil
}

// The four handlers that 404 an unknown package have to leave a row behind, or
// a clean-host bootstrap records nothing for the ecosystems that need it most.
// The 404 itself is unchanged: this item adds an observation, not a fetch.
func TestUnknownPackageRecordsNoManifest(t *testing.T) {
	s := newDiscoveryServer(t)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	for _, path := range []string{
		"/go/github.com/aws/aws-sdk-go-v2/@v/v1.30.0.info",
		"/pypi/wheels/boto3-1.26.0-py3-none-any.whl",
		"/npm/lodash/-/lodash-4.17.21.tgz",
		"/helm/charts/ingress-nginx-4.0.0.tgz",
	} {
		resp, err := http.Get(ts.URL + path) //nolint:gosec,noctx // test-owned loopback URL
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 — this item records the miss, it does not serve it", path, resp.StatusCode)
		}
	}

	rows := waitForDiscovery(t, s, 4)
	got := map[string]audit.DiscoveryRow{}
	for _, r := range rows {
		got[r.RegistryType] = r
	}

	for _, want := range []struct {
		typ, pkg, version, upstream string
	}{
		{manifest.TypeGomod, "github.com/aws/aws-sdk-go-v2", "v1.30.0", "https://proxy.golang.org/github.com/aws/aws-sdk-go-v2/@v/v1.30.0.info"},
		{manifest.TypePypi, "boto3", "1.26.0", "https://pypi.org/packages/boto3-1.26.0-py3-none-any.whl"},
		{manifest.TypeNpm, "lodash", "4.17.21", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"},
		// helm chart repos are named per version entry, so with no entry there
		// is no URL to record. The empty column is what promote reports back.
		{manifest.TypeHelm, "ingress-nginx", "4.0.0", ""},
	} {
		row, ok := got[want.typ]
		if !ok {
			t.Errorf("no %s discovery row; the handler 404s without recording", want.typ)
			continue
		}
		if row.PkgName != want.pkg {
			t.Errorf("%s pkg_name = %q, want %q", want.typ, row.PkgName, want.pkg)
		}
		if row.PkgVersion != want.version {
			t.Errorf("%s pkg_version = %q, want %q", want.typ, row.PkgVersion, want.version)
		}
		if row.UpstreamURL != want.upstream {
			t.Errorf("%s upstream_url = %q, want %q", want.typ, row.UpstreamURL, want.upstream)
		}
	}
}

// A package with a manifest entry in hosted mode reaches the same 404 as one
// with no entry at all. Recording it as no_manifest would tell an operator to
// create an entry that is already there.
func TestHostedPackageMissDoesNotRecordNoManifest(t *testing.T) {
	s := newDiscoveryServer(t)
	if err := s.store.AddVersion(t.Context(), manifest.TypeNpm, "lodash", manifest.VersionEntry{
		Version: "4.17.21",
	}); err != nil {
		t.Fatalf("seed manifest: %v", err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/npm/lodash/-/lodash-4.17.21.tgz") //nolint:gosec,noctx // test-owned loopback URL
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()

	// The recorder is asynchronous, so absence needs a window to be meaningful.
	time.Sleep(250 * time.Millisecond)
	rows, err := s.auditDB.ListDiscovery(context.Background(), audit.DiscoveryFilter{
		Decision: audit.DecisionNoManifest,
	})
	if err != nil {
		t.Fatalf("list discovery: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("no_manifest rows = %d, want 0; the entry exists and the operator needs a mode change, not a create (%+v)", len(rows), rows)
	}
}
