package server

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// A pepper the process cannot read is a refusal before the listener binds, for
// every reason it cannot be read rather than permission alone. The reproduction
// is a symlink cycle: the resolver returned a bare error, newServer logged it
// and continued, and the result was a server answering /healthz 200 while every
// token minted on that host got 401 "invalid token" — the credential named, the
// file never.
func TestUnopenablePepperIsFatalForServe(t *testing.T) {
	dir := t.TempDir()
	pepper := filepath.Join(dir, "pepper")
	if err := os.Symlink("pepper", pepper); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	prev := audit.DefaultPepperPaths
	audit.DefaultPepperPaths = []string{pepper}
	t.Cleanup(func() { audit.DefaultPepperPaths = prev })

	s := newServer(&config.Config{
		AptCodename:     "noble",
		LogDir:          dir,
		AuditDB:         filepath.Join(dir, "audit.db"),
		StoragePath:     dir,
		AllowPlaintext:  true,
		AdminPermitCIDR: []string{"127.0.0.0/8", "::1/128"},
	}, manifest.NewLocalStore(t.TempDir()), storage.NewSingle(storage.NewMemory()),
		"127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() {
		if s.auditDB != nil {
			_ = s.auditDB.Close()
		}
	})

	if s.pepperErr == nil {
		t.Fatal("newServer accepted a pepper it could not open; serve would answer 401 to every minted token")
	}
	err := s.Start(context.Background())
	if err == nil {
		t.Fatal("Start bound a listener with an unreadable pepper")
	}
	if !strings.Contains(err.Error(), pepper) {
		t.Errorf("Start returned %v, want a refusal naming %s", err, pepper)
	}
}
