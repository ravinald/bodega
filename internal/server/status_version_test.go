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
// test is the one an operator's server would put on the wire. healthy and
// backend stay public on both sides, because a monitor reading this endpoint
// anonymously acts on which backend is broken.
func TestStatusBackendErrorIsAdminOnly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root walks a mode-0 directory, so the probe would not fail")
	}
	dir := t.TempDir()
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
		StoragePath:     dir,
		AuditDB:         filepath.Join(dir, "audit.db"),
		AdminPermitCIDR: []string{"127.0.0.0/8"},
	}
	s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), storage.NewSingle(storage.NewLocal(dir)),
		"127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if s.auditDB != nil {
		t.Cleanup(func() { _ = s.auditDB.Close() })
	}

	probe := func(remote string) (bool, backendEntryStatus) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		var got struct {
			Healthy        bool                 `json:"healthy"`
			BackendEntries []backendEntryStatus `json:"backend_entries"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode %q: %v", rec.Body.String(), err)
		}
		if len(got.BackendEntries) != 1 {
			t.Fatalf("backend_entries = %+v, want one probe row", got.BackendEntries)
		}
		return got.Healthy, got.BackendEntries[0]
	}

	adminHealthy, admin := probe("127.0.0.1:40000")
	if !strings.Contains(admin.Error, pool) {
		t.Errorf("error = %q for an admin caller, want the failure naming %s", admin.Error, pool)
	}

	anonHealthy, anon := probe("203.0.113.9:40000")
	if anon.Error != "" {
		t.Errorf("error = %q for a caller outside admin_permit_cidr, which hands anyone who can reach the listener a path under storage_path", anon.Error)
	}
	for _, side := range []struct {
		who     string
		healthy bool
		row     backendEntryStatus
	}{{"admin", adminHealthy, admin}, {"anonymous", anonHealthy, anon}} {
		if side.healthy {
			t.Errorf("%s: healthy = true with a backend that failed its probe", side.who)
		}
		if side.row.Backend != storage.DefaultName {
			t.Errorf("%s: backend = %q, want %q: the gate is on the error text, not on which backend failed", side.who, side.row.Backend, storage.DefaultName)
		}
	}
}
