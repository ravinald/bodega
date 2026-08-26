package storage

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// backends is the set every ObjectStore implementation is held to. A new
// backend joins by adding one line here.
func conformanceBackends() map[string]func(t *testing.T) ObjectStore {
	return map[string]func(t *testing.T) ObjectStore{
		"local":  func(t *testing.T) ObjectStore { return NewLocal(t.TempDir()) },
		"memory": func(t *testing.T) ObjectStore { return NewMemory() },
	}
}

func TestObjectStoreConformance(t *testing.T) {
	for name, mk := range conformanceBackends() {
		t.Run(name, func(t *testing.T) {
			testObjectStore(t, func() ObjectStore { return mk(t) })
		})
	}
}

// testObjectStore runs the ObjectStore contract against one implementation.
// Each case gets a fresh store so an assertion never depends on the order the
// table happens to run in.
func testObjectStore(t *testing.T, mk func() ObjectStore) {
	t.Helper()

	cases := []struct {
		name string
		run  func(t *testing.T, ctx context.Context, s ObjectStore)
	}{
		{"put_get_round_trip", func(t *testing.T, ctx context.Context, s ObjectStore) {
			body := []byte("\x00binary\xffbytes\n")
			if err := s.Put(ctx, "a/b/c.bin", body); err != nil {
				t.Fatalf("Put: %v", err)
			}
			got, err := s.Get(ctx, "a/b/c.bin")
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if !bytes.Equal(got, body) {
				t.Fatalf("Get returned %q, want %q", got, body)
			}
		}},

		// The (nil, nil) contract. Every caller in the tree reads a nil body
		// with a nil error as 404, so an implementation that returned an error
		// instead would turn a missing object into a 502 and one that returned
		// an empty non-nil slice would serve a zero-byte artifact as success.
		{"get_missing_is_nil_nil", func(t *testing.T, ctx context.Context, s ObjectStore) {
			data, err := s.Get(ctx, "nothing/here")
			if err != nil {
				t.Fatalf("Get of a missing key returned error %v, want nil", err)
			}
			if data != nil {
				t.Fatalf("Get of a missing key returned %q, want nil", data)
			}
		}},
		{"getstream_missing_is_nil_nil", func(t *testing.T, ctx context.Context, s ObjectStore) {
			r, err := s.GetStream(ctx, "nothing/here")
			if err != nil {
				t.Fatalf("GetStream of a missing key returned error %v, want nil", err)
			}
			if r != nil {
				t.Fatalf("GetStream of a missing key returned %+v, want nil", r)
			}
		}},

		{"getstream_body_and_length", func(t *testing.T, ctx context.Context, s ObjectStore) {
			body := []byte("stream me")
			if err := s.Put(ctx, "s/obj.txt", body); err != nil {
				t.Fatalf("Put: %v", err)
			}
			r, err := s.GetStream(ctx, "s/obj.txt")
			if err != nil || r == nil {
				t.Fatalf("GetStream: %v, %v", r, err)
			}
			defer r.Body.Close()
			got, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			if !bytes.Equal(got, body) {
				t.Fatalf("body %q, want %q", got, body)
			}
			if r.ContentLength != int64(len(body)) {
				t.Fatalf("ContentLength %d, want %d", r.ContentLength, len(body))
			}
		}},

		{"head_reports_existence", func(t *testing.T, ctx context.Context, s ObjectStore) {
			if err := s.Put(ctx, "h/there.txt", []byte("1234")); err != nil {
				t.Fatalf("Put: %v", err)
			}
			info, err := s.Head(ctx, "h/there.txt")
			if err != nil {
				t.Fatalf("Head: %v", err)
			}
			if info == nil || !info.Exists {
				t.Fatalf("Head of an existing key returned %+v, want Exists=true", info)
			}
			if info.Size != 4 {
				t.Fatalf("Head Size %d, want 4", info.Size)
			}
			missing, err := s.Head(ctx, "h/absent.txt")
			if err != nil {
				t.Fatalf("Head of a missing key: %v", err)
			}
			if missing == nil || missing.Exists {
				t.Fatalf("Head of a missing key returned %+v, want non-nil with Exists=false", missing)
			}
		}},

		{"list_is_a_string_prefix", func(t *testing.T, ctx context.Context, s ObjectStore) {
			for _, k := range []string{
				"packages/ap/decoy.deb",
				"packages/apt/pool/main/a/acme/acme_1.0_amd64.deb",
				"packages/apt/pool/main/b/bar/bar_2.0_amd64.deb",
				"pypi/wheels/thing-1.0.whl",
			} {
				if err := s.Put(ctx, k, []byte(k)); err != nil {
					t.Fatalf("Put %s: %v", k, err)
				}
			}
			got, err := s.List(ctx, "packages/apt/pool/")
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			want := []string{
				"packages/apt/pool/main/a/acme/acme_1.0_amd64.deb",
				"packages/apt/pool/main/b/bar/bar_2.0_amd64.deb",
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("List(%q) = %v, want %v", "packages/apt/pool/", got, want)
			}

			// A prefix that stops mid-segment matches by string, not by
			// directory: "packages/ap" has to reach packages/apt/ even though
			// packages/ap/ exists as a directory beside it.
			partial, err := s.List(ctx, "packages/ap")
			if err != nil {
				t.Fatalf("List partial: %v", err)
			}
			if len(partial) != 3 {
				t.Fatalf("List(%q) = %v, want 3 keys", "packages/ap", partial)
			}
		}},

		{"list_missing_prefix_is_empty", func(t *testing.T, ctx context.Context, s ObjectStore) {
			got, err := s.List(ctx, "no/such/prefix/")
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(got) != 0 {
				t.Fatalf("List of an empty prefix returned %v, want none", got)
			}
		}},

		{"list_is_sorted", func(t *testing.T, ctx context.Context, s ObjectStore) {
			for _, k := range []string{"x/c", "x/a", "x/b"} {
				if err := s.Put(ctx, k, []byte(k)); err != nil {
					t.Fatalf("Put %s: %v", k, err)
				}
			}
			got, err := s.List(ctx, "x/")
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			want := []string{"x/a", "x/b", "x/c"}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("List = %v, want %v", got, want)
			}
		}},

		// PutFile has to read the file. A backend that recorded the path and
		// stored nothing passes every "did the upload succeed" assertion while
		// serving an empty artifact.
		{"putfile_stores_file_bytes", func(t *testing.T, ctx context.Context, s ObjectStore) {
			body := []byte("real artifact bytes")
			local := filepath.Join(t.TempDir(), "artifact.bin")
			if err := os.WriteFile(local, body, 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			if err := s.PutFile(ctx, local, "up/artifact.bin"); err != nil {
				t.Fatalf("PutFile: %v", err)
			}
			got, err := s.Get(ctx, "up/artifact.bin")
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if !bytes.Equal(got, body) {
				t.Fatalf("PutFile stored %q, want %q", got, body)
			}
		}},

		{"putfile_missing_source_errors", func(t *testing.T, ctx context.Context, s ObjectStore) {
			if err := s.PutFile(ctx, filepath.Join(t.TempDir(), "absent"), "up/absent"); err == nil {
				t.Fatal("PutFile of a missing local file returned nil, want an error")
			}
		}},

		{"put_overwrites", func(t *testing.T, ctx context.Context, s ObjectStore) {
			if err := s.Put(ctx, "o/key", []byte("first")); err != nil {
				t.Fatalf("Put: %v", err)
			}
			if err := s.Put(ctx, "o/key", []byte("second")); err != nil {
				t.Fatalf("Put: %v", err)
			}
			got, err := s.Get(ctx, "o/key")
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if string(got) != "second" {
				t.Fatalf("Get = %q, want %q", got, "second")
			}
		}},

		{"delete_is_idempotent", func(t *testing.T, ctx context.Context, s ObjectStore) {
			if err := s.Put(ctx, "d/key", []byte("gone soon")); err != nil {
				t.Fatalf("Put: %v", err)
			}
			if err := s.Delete(ctx, "d/key"); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if err := s.Delete(ctx, "d/key"); err != nil {
				t.Fatalf("second Delete: %v, want nil", err)
			}
			data, err := s.Get(ctx, "d/key")
			if err != nil || data != nil {
				t.Fatalf("Get after Delete = %q, %v; want nil, nil", data, err)
			}
		}},

		{"syncdir_uploads_tree", func(t *testing.T, ctx context.Context, s ObjectStore) {
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, "nested"), 0o750); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if err := os.WriteFile(filepath.Join(dir, "top.txt"), []byte("top"), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			if err := os.WriteFile(filepath.Join(dir, "nested", "deep.txt"), []byte("deep"), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			var out strings.Builder
			n, err := s.SyncDir(ctx, &out, dir, "sync/")
			if err != nil {
				t.Fatalf("SyncDir: %v", err)
			}
			if n != 2 {
				t.Fatalf("SyncDir uploaded %d files, want 2", n)
			}
			got, err := s.Get(ctx, "sync/nested/deep.txt")
			if err != nil || string(got) != "deep" {
				t.Fatalf("Get sync/nested/deep.txt = %q, %v; want %q", got, err, "deep")
			}
		}},

		{"label_is_addressable", func(t *testing.T, _ context.Context, s ObjectStore) {
			if !strings.Contains(s.Label(), "://") {
				t.Fatalf("Label() = %q, want a scheme-qualified location", s.Label())
			}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.run(t, t.Context(), mk())
		})
	}
}
