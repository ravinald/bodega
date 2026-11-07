package server

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/logging"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// A SIGKILL mid-fetch leaves its spool file behind, and nothing but startup
// can tell it from a live one. The sweep must take those and nothing that
// merely sits beside them: bodega move's parts, a directory, or what a
// symlink points at.
func TestStartSweepsSpoolLeftovers(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{
		LogDir: t.TempDir(), StoragePath: root, AuditDB: filepath.Join(root, "audit.db"), AllowPlaintext: true,
	}
	var buf syncBuffer
	s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), nil, "127.0.0.1:0", slog.New(slog.NewTextHandler(&buf, nil)))
	if s.auditDB != nil {
		t.Cleanup(func() { _ = s.auditDB.Close() })
	}
	if s.spoolErr != nil {
		t.Fatal(s.spoolErr)
	}
	dir := s.spool.dir

	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	leftovers := []string{filepath.Join(dir, "bodega-upstream-111"), filepath.Join(dir, "bodega-upstream-222")}
	write(leftovers[0], "12345")
	write(leftovers[1], "123")
	part := filepath.Join(dir, "move-abc.part")
	write(part, "part")
	subdir := filepath.Join(dir, "bodega-upstream-dir")
	if err := os.Mkdir(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "outside")
	write(target, "keep me")
	link := filepath.Join(dir, "bodega-upstream-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()
	waitFor(t, func() bool { return strings.Contains(buf.String(), "bodega server listening") })
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Start: %v", err)
	}

	for _, p := range leftovers {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived startup (err=%v)", p, err)
		}
	}
	for _, p := range []string{part, subdir, link} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s was removed: %v", p, err)
		}
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "keep me" {
		t.Errorf("symlink target = %q, %v; want it untouched", got, err)
	}

	log := buf.String()
	sweep := strings.Index(log, "removed proxy spool files")
	if sweep < 0 {
		t.Fatalf("no sweep line logged:\n%s", log)
	}
	if listen := strings.Index(log, "bodega server listening"); listen >= 0 && listen < sweep {
		t.Errorf("sweep logged after the listener opened:\n%s", log)
	}
	line := log[sweep:]
	line = line[:strings.IndexByte(line, '\n')]
	for _, want := range []string{"spool_dir=" + dir, "files=2", "bytes=8"} {
		if !strings.Contains(line, want) {
			t.Errorf("sweep line missing %q: %s", want, line)
		}
	}
}

// A leftover the process cannot remove is reported by path and does not end
// the sweep, so startup carries on and the operator learns what to delete.
func TestSweepSpoolLeftoversLogsUnremovable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root removes files from a read-only directory")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "bodega-upstream-stuck")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	var buf syncBuffer
	sweepSpoolLeftovers(dir, slog.New(slog.NewTextHandler(&buf, nil)))

	log := buf.String()
	if !strings.Contains(log, "level=ERROR") || !strings.Contains(log, "path="+path) || !strings.Contains(log, "error=") {
		t.Errorf("unremovable leftover not logged with its path and error:\n%s", log)
	}
	if strings.Contains(log, "removed proxy spool files") {
		t.Errorf("logged a removal that did not happen:\n%s", log)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file should still exist: %v", err)
	}
}

func TestSweepSpoolLogsAtShippedDefault(t *testing.T) {
	t.Run("removed", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bodega-upstream-leftover")
		if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
			t.Fatal(err)
		}
		var buf syncBuffer
		logger := slog.New(logging.NewHandler(&buf, logging.SlogLevel(config.DefaultLogLevel)))
		sweepSpoolLeftovers(dir, logger)
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("leftover survived: %v", err)
		}
		for _, want := range []string{"spool_dir=" + dir, "files=1", "bytes=5"} {
			if !strings.Contains(buf.String(), want) {
				t.Errorf("default logger dropped cleanup summary: missing %q in %q", want, buf.String())
			}
		}
	})
	t.Run("unremovable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("requires an unprivileged process")
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "bodega-upstream-stuck")
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
		var buf syncBuffer
		logger := slog.New(logging.NewHandler(&buf, logging.SlogLevel(config.DefaultLogLevel)))
		sweepSpoolLeftovers(dir, logger)
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("unremovable file changed: %v", err)
		}
		if !strings.Contains(buf.String(), "path="+path) || !strings.Contains(buf.String(), "error=") {
			t.Fatalf("default logger dropped removal failure: %q", buf.String())
		}
	})
}

func TestFailedSecondStartPreservesLiveSpool(t *testing.T) {
	dir := t.TempDir()
	makeServer := func(addr string, buf *syncBuffer) *Server {
		t.Helper()
		root := t.TempDir()
		cfg := &config.Config{
			LogDir: t.TempDir(), StoragePath: root, AuditDB: filepath.Join(root, "audit.db"),
			AllowPlaintext: true, SpoolDir: dir,
		}
		s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), nil, addr,
			slog.New(slog.NewTextHandler(buf, nil)))
		if s.auditDB != nil {
			t.Cleanup(func() { _ = s.auditDB.Close() })
		}
		if s.spoolErr != nil {
			t.Fatal(s.spoolErr)
		}
		return s
	}
	var firstLog, secondLog syncBuffer
	first := makeServer("127.0.0.1:0", &firstLog)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- first.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("first Start: %v", err)
		}
	})
	waitFor(t, func() bool { return strings.Contains(firstLog.String(), "bodega server listening") })
	sp, err := first.spoolUpstream(&upstreamStream{
		body: io.NopCloser(strings.NewReader("live artifact")), contentLength: 13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sp.close()
	cache := storage.NewLocal(t.TempDir())
	if err := cache.PutFile(t.Context(), sp.path(), "before"); err != nil {
		t.Fatalf("live fetch cannot publish before second startup: %v", err)
	}
	second := makeServer("missing-port", &secondLog)
	if err := second.Start(t.Context()); err == nil {
		t.Fatal("invalid listener address unexpectedly accepted")
	}
	if err := cache.PutFile(t.Context(), sp.path(), "after"); err != nil {
		t.Fatalf("live fetch cannot publish after failed second startup: %v", err)
	}
}

// A Start that fails after claiming the spool must give it back, or a bind
// failure retried in the same process would refuse on its own lock.
func TestFailedStartReleasesSpoolLock(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{
		LogDir: t.TempDir(), StoragePath: root, AuditDB: filepath.Join(root, "audit.db"), AllowPlaintext: true,
	}
	s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), nil, "missing-port", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if s.auditDB != nil {
		t.Cleanup(func() { _ = s.auditDB.Close() })
	}
	if s.spoolErr != nil {
		t.Fatal(s.spoolErr)
	}
	if err := s.Start(t.Context()); err == nil {
		t.Fatal("invalid listener address unexpectedly accepted")
	}
	lock, err := lockSpoolDir(s.spool.dir)
	if err != nil {
		t.Fatalf("spool lock still held after a failed Start: %v", err)
	}
	_ = lock.Close()
}
