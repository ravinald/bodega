package manifest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalBackendSafePath(t *testing.T) {
	t.Parallel()

	b := &LocalBackend{Dir: t.TempDir()}

	bad := []string{
		"..",
		"../escape",
		"a/../../escape",
		"/etc/passwd",
		"foo/\x00bar",
		"",
	}
	for _, name := range bad {
		t.Run("rejects "+name, func(t *testing.T) {
			if _, err := b.Read(context.Background(), name); err == nil {
				t.Errorf("Read(%q): expected error, got nil", name)
			}
			if err := b.Write(context.Background(), name, []byte("x")); err == nil {
				t.Errorf("Write(%q): expected error, got nil", name)
			}
			if err := b.Delete(context.Background(), name); err == nil {
				t.Errorf("Delete(%q): expected error, got nil", name)
			}
		})
	}

	ctx := context.Background()
	if err := b.Write(ctx, "git/foo--bar/manifest.json", []byte("ok")); err != nil {
		t.Fatalf("Write(legitimate path): %v", err)
	}
	got, err := b.Read(ctx, "git/foo--bar/manifest.json")
	if err != nil || string(got) != "ok" {
		t.Fatalf("Read(legitimate path) = %q, %v; want \"ok\", nil", got, err)
	}
}

// TestLocalBackendNoEscapeOnDisk asserts that a rejected name never lands
// on disk anywhere — not under Dir, not under Dir's parent.
func TestLocalBackendNoEscapeOnDisk(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	b := &LocalBackend{Dir: root}

	if err := b.Write(context.Background(), "../escaped.json", []byte("nope")); err == nil {
		t.Fatal("Write(\"../escaped.json\"): expected rejection")
	}
	escaped := filepath.Join(parent, "escaped.json")
	if _, err := os.Stat(escaped); err == nil {
		t.Fatalf("file leaked outside Dir: %s exists", escaped)
	}
}

// TestLocalBackendErrorMessageDoesNotLeakDir verifies error wrapping doesn't
// expand traversal hints.
func TestLocalBackendErrorMessageRefuses(t *testing.T) {
	t.Parallel()

	b := &LocalBackend{Dir: t.TempDir()}
	_, err := b.Read(context.Background(), "../passwd")
	if err == nil || !strings.Contains(err.Error(), "escapes root") {
		t.Fatalf("Read(\"../passwd\"): want error mentioning 'escapes root', got %v", err)
	}
}
