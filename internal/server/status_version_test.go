package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
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
