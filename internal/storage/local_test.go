package storage

import (
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestLocalRoundTrip(t *testing.T) {
	root := t.TempDir()
	l := NewLocal(root)
	ctx := t.Context()

	const key = "packages/apt/pool/main/a/acme/acme_1.0_amd64.deb"
	body := []byte("\x00deb-content")

	if err := l.Put(ctx, key, body); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := l.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("Get = %q, want %q", got, body)
	}

	info, err := l.Head(ctx, key)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if !info.Exists || info.Size != int64(len(body)) {
		t.Errorf("Head = %+v, want Exists=true Size=%d", info, len(body))
	}

	stream, err := l.GetStream(ctx, key)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	streamed, _ := io.ReadAll(stream.Body)
	_ = stream.Body.Close()
	if string(streamed) != string(body) {
		t.Errorf("GetStream body = %q, want %q", streamed, body)
	}
	if stream.ContentLength != int64(len(body)) {
		t.Errorf("GetStream ContentLength = %d, want %d", stream.ContentLength, len(body))
	}

	keys, err := l.List(ctx, "packages/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 || keys[0] != key {
		t.Errorf("List = %v, want [%s]", keys, key)
	}

	if err := l.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got, err := l.Get(ctx, key); err != nil || got != nil {
		t.Errorf("Get after Delete = (%q, %v), want (nil, nil)", got, err)
	}
	// Delete is idempotent: a second call on a missing key is not an error.
	if err := l.Delete(ctx, key); err != nil {
		t.Errorf("Delete on missing key: %v", err)
	}
}

func TestLocalGetMissingReturnsNilNil(t *testing.T) {
	l := NewLocal(t.TempDir())
	ctx := t.Context()

	data, err := l.Get(ctx, "nope/missing.bin")
	if err != nil || data != nil {
		t.Errorf("Get = (%v, %v), want (nil, nil)", data, err)
	}
	stream, err := l.GetStream(ctx, "nope/missing.bin")
	if err != nil || stream != nil {
		t.Errorf("GetStream = (%v, %v), want (nil, nil)", stream, err)
	}
	info, err := l.Head(ctx, "nope/missing.bin")
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if info.Exists {
		t.Error("Head reported Exists=true for a missing key")
	}
}

func TestLocalPutFile(t *testing.T) {
	root := t.TempDir()
	l := NewLocal(root)
	ctx := t.Context()

	src := filepath.Join(t.TempDir(), "wheel.whl")
	if err := os.WriteFile(src, []byte("wheel-bytes"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	if err := l.PutFile(ctx, src, "pypi/wheels/wheel.whl"); err != nil {
		t.Fatalf("PutFile: %v", err)
	}
	got, err := l.Get(ctx, "pypi/wheels/wheel.whl")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "wheel-bytes" {
		t.Errorf("Get = %q, want %q", got, "wheel-bytes")
	}
}

func TestLocalSyncDir(t *testing.T) {
	root := t.TempDir()
	l := NewLocal(root)
	ctx := t.Context()

	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "main", "a"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(src, "Release"), []byte("release"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(src, "main", "a", "acme.deb"), []byte("deb"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	var out strings.Builder
	n, err := l.SyncDir(ctx, &out, src, "packages/apt/")
	if err != nil {
		t.Fatalf("SyncDir: %v", err)
	}
	if n != 2 {
		t.Errorf("SyncDir uploaded %d files, want 2", n)
	}

	keys, err := l.List(ctx, "packages/apt/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	sort.Strings(keys)
	want := []string{"packages/apt/Release", "packages/apt/main/a/acme.deb"}
	if len(keys) != len(want) || keys[0] != want[0] || keys[1] != want[1] {
		t.Errorf("List = %v, want %v", keys, want)
	}
	// Relative paths survive the walk; the progress writer names the destination.
	if !strings.Contains(out.String(), "packages/apt/main/a/acme.deb") {
		t.Errorf("SyncDir progress output missing nested key:\n%s", out.String())
	}
}

// List walks the parent and string-filters when the prefix names no directory,
// so a partial segment must still match as a true prefix across siblings.
func TestLocalListPrefixSemantics(t *testing.T) {
	l := NewLocal(t.TempDir())
	ctx := t.Context()

	seed := []string{
		"packages/apt/acme.deb",
		"packages/apple/pie.deb",
		"packages/npm/left-pad.tgz",
		"repos/netbox/netbox.bundle",
	}
	for _, k := range seed {
		if err := l.Put(ctx, k, []byte("x")); err != nil {
			t.Fatalf("Put %s: %v", k, err)
		}
	}

	cases := []struct {
		prefix string
		want   []string
	}{
		{"packages/ap", []string{"packages/apple/pie.deb", "packages/apt/acme.deb"}},
		{"packages/apt", []string{"packages/apt/acme.deb"}},
		{"packages/", []string{"packages/apple/pie.deb", "packages/apt/acme.deb", "packages/npm/left-pad.tgz"}},
		{"packages/zz", nil},
		{"nothing/here", nil},
	}
	for _, tc := range cases {
		got, err := l.List(ctx, tc.prefix)
		if err != nil {
			t.Fatalf("List(%q): %v", tc.prefix, err)
		}
		sort.Strings(got)
		if len(got) != len(tc.want) {
			t.Errorf("List(%q) = %v, want %v", tc.prefix, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("List(%q) = %v, want %v", tc.prefix, got, tc.want)
				break
			}
		}
	}
}

func TestLocalPathTraversalRejected(t *testing.T) {
	root := t.TempDir()
	l := NewLocal(filepath.Join(root, "store"))
	ctx := t.Context()

	for _, key := range []string{
		"../escaped.txt",
		"packages/../../escaped.txt",
		"a\x00/../../escaped.txt",
		"..",
	} {
		if err := l.Put(ctx, key, []byte("pwned")); err == nil {
			t.Errorf("Put(%q) succeeded, want rejection", key)
		}
		if _, err := l.Get(ctx, key); err == nil {
			t.Errorf("Get(%q) succeeded, want rejection", key)
		}
		if _, err := l.Head(ctx, key); err == nil {
			t.Errorf("Head(%q) succeeded, want rejection", key)
		}
		if err := l.Delete(ctx, key); err == nil {
			t.Errorf("Delete(%q) succeeded, want rejection", key)
		}
	}

	if _, err := os.Stat(filepath.Join(root, "escaped.txt")); !os.IsNotExist(err) {
		t.Error("a rejected key still wrote outside the storage root")
	}
}

// An absolute key is not an escape: Join re-roots it under the store. Assert
// containment rather than an error, so nobody "fixes" this into a rejection
// and breaks callers that pass a leading slash.
func TestLocalAbsoluteKeyStaysInRoot(t *testing.T) {
	root := t.TempDir()
	store := filepath.Join(root, "store")
	l := NewLocal(store)
	ctx := t.Context()

	if err := l.Put(ctx, "/etc/passwd", []byte("contained")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store, "etc", "passwd")); err != nil {
		t.Errorf("absolute key did not land under the root: %v", err)
	}
}

// TestLocalLabel pins the resolved form rather than the configured one. On
// macOS t.TempDir() hands back a /var/folders path whose first component is a
// symlink to /private, so asserting the string that went in would assert the
// absence of the canonicalization pkg move depends on.
func TestLocalLabel(t *testing.T) {
	root := t.TempDir()
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("resolve %s: %v", root, err)
	}
	if got, want := NewLocal(root).Label(), "file://"+resolved; got != want {
		t.Errorf("Label() = %q, want %q", got, want)
	}
}

// TestLocalTrailingSlashRootStillWrites covers the second defect the trailing
// slash produced. path() tests its result against root + "/", so an
// unnormalized "/srv/store/" root refused every key it was handed and the
// artifact survived a move only by accident.
func TestLocalTrailingSlashRootStillWrites(t *testing.T) {
	root := t.TempDir()
	l := NewLocal(root + string(filepath.Separator))
	if err := l.Put(t.Context(), "a/b.txt", []byte("x")); err != nil {
		t.Fatalf("Put on a root with a trailing slash: %v", err)
	}
	got, err := l.Get(t.Context(), "a/b.txt")
	if err != nil || string(got) != "x" {
		t.Fatalf("Get = %q, %v; want \"x\", nil", got, err)
	}
}
