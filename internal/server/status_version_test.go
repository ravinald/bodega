package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// The build stamp reaches the web UI through /api/v1/status, which answers
// anyone who can reach the listener. A package repository exists to be reached
// by a whole fleet, so an ungated version field publishes which advisories
// apply to it. The gate is the one spool.Dir already uses.
func TestStatusVersionIsAdminOnly(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		AptCodename:     "noble",
		LogDir:          dir,
		StoragePath:     dir,
		AuditDB:         filepath.Join(dir, "audit.db"),
		AdminPermitCIDR: []string{"127.0.0.0/8"},
	}
	s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), nil, "127.0.0.1:0",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if s.auditDB != nil {
		t.Cleanup(func() { _ = s.auditDB.Close() })
	}

	// builder.Version is "unknown" under `go test`, since only main's init
	// stamps it. The assertion is on which caller sees the field, so the value
	// only has to be non-empty and the same one the handler reads.
	want := builder.Version
	if want == "" {
		t.Fatal("builder.Version is empty; the test would assert nothing")
	}

	for _, tc := range []struct {
		name   string
		remote string
		want   string
	}{
		{"admin sees the build", "127.0.0.1:40000", want},
		{"everyone else sees nothing", "203.0.113.9:40000", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
			req.RemoteAddr = tc.remote
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, req)

			var got struct {
				Version string `json:"version"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode %q: %v", rec.Body.String(), err)
			}
			if got.Version != tc.want {
				t.Errorf("version = %q, want %q", got.Version, tc.want)
			}
		})
	}
}

// A local backend that cannot walk its pool reports the directory it failed
// on, which is a path under storage_path: the datum spool.Dir is withheld for.
// The failure is planted on a real Local rather than a stub, so the text under
// test is the one an operator's server would put on the wire. A second backend
// holds an empty, readable pool, because the monitor reading this endpoint
// anonymously has to tell the broken backend from one that merely holds
// nothing, and without a per-row healthy the two rows read the same. Rows are
// decoded as raw JSON: a struct cannot tell an absent error from an empty one.
func TestStatusBackendErrorIsAdminOnly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root walks a mode-0 directory, so the probe would not fail")
	}
	dir, emptyRoot := t.TempDir(), t.TempDir()
	pool := filepath.Join(dir, filepath.FromSlash(manifest.AptPoolPrefix))
	if err := os.MkdirAll(pool, 0o755); err != nil {
		t.Fatalf("create the pool: %v", err)
	}
	if err := os.Chmod(pool, 0o000); err != nil {
		t.Fatalf("make the pool unreadable: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(pool, 0o755) })

	cfg := &config.Config{
		AptCodename:     "noble",
		LogDir:          dir,
		StorageBackend:  "local",
		StoragePath:     dir,
		StorageBackends: map[string]config.StorageSpec{"empty": {Driver: "local", Path: emptyRoot}},
		AuditDB:         filepath.Join(dir, "audit.db"),
		AdminPermitCIDR: []string{"127.0.0.0/8"},
	}
	stores, err := storage.NewResolver(t.Context(), cfg)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), stores,
		"127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if s.auditDB != nil {
		t.Cleanup(func() { _ = s.auditDB.Close() })
	}

	type row struct {
		healthy bool
		err     string
	}
	probe := func(who, remote string) (string, map[string]row) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		body := rec.Body.String()
		var got struct {
			Healthy        bool                         `json:"healthy"`
			BackendEntries []map[string]json.RawMessage `json:"backend_entries"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("%s: decode %q: %v", who, body, err)
		}
		if got.Healthy {
			t.Errorf("%s: healthy = true with a backend that failed its probe", who)
		}
		rows := make(map[string]row, len(got.BackendEntries))
		for _, raw := range got.BackendEntries {
			var name string
			var r row
			for key, dst := range map[string]any{"backend": &name, "healthy": &r.healthy, "error": &r.err} {
				v, ok := raw[key]
				if !ok {
					t.Errorf("%s: row %v has no %q key; a monitor reads a missing key as a server that predates it", who, raw, key)
					continue
				}
				if err := json.Unmarshal(v, dst); err != nil {
					t.Errorf("%s: row key %q = %s: %v", who, key, v, err)
				}
			}
			rows[name] = r
		}
		if len(rows) != 2 {
			t.Fatalf("%s: backend_entries = %s, want one row each for %q and \"empty\"", who, body, storage.DefaultName)
		}
		return body, rows
	}

	_, admin := probe("admin", "127.0.0.1:40000")
	if !strings.Contains(admin[storage.DefaultName].err, pool) {
		t.Errorf("admin: error = %q, want the failure naming %s", admin[storage.DefaultName].err, pool)
	}

	anonBody, anon := probe("anonymous", "203.0.113.9:40000")
	if anon[storage.DefaultName].err != "" {
		t.Errorf("anonymous: error = %q, which hands anyone who can reach the listener a path under storage_path", anon[storage.DefaultName].err)
	}
	for _, root := range []string{dir, emptyRoot} {
		if strings.Contains(anonBody, root) {
			t.Errorf("anonymous: body names storage root %s: %s", root, anonBody)
		}
	}

	for who, rows := range map[string]map[string]row{"admin": admin, "anonymous": anon} {
		if rows[storage.DefaultName].healthy {
			t.Errorf("%s: %s row healthy = true, but its pool could not be walked", who, storage.DefaultName)
		}
		if !rows["empty"].healthy {
			t.Errorf("%s: empty row healthy = false, but an empty pool is a probe that answered", who)
		}
		if rows["empty"].err != "" {
			t.Errorf("%s: empty row error = %q, want \"\" for a probe that succeeded", who, rows["empty"].err)
		}
	}
}
