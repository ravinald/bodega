package storage

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// backends is the set every ObjectStore implementation is held to. A new
// backend joins by adding one line here.
//
// S3 is absent because it needs a live bucket. It implements the same contract
// — including the ValidateKey rule every case below pins — but nothing here
// proves it, so a change to internal/storage/s3.go is held to this file by
// reading rather than by running.
func conformanceBackends() map[string]func(t *testing.T) ObjectStore {
	return map[string]func(t *testing.T) ObjectStore{
		"local":  func(t *testing.T) ObjectStore { return NewLocal(rootWithDecoySibling(t)) },
		"memory": func(t *testing.T) ObjectStore { return NewMemory() },
		// prefixed is a wrapper rather than a driver, and it was absent long
		// enough for Label() to grow a second spelling of one directory that
		// TestLabelIsOnePerLocation would have caught (#189).
		"prefixed": func(t *testing.T) ObjectStore {
			return withPrefix(NewLocal(rootWithDecoySibling(t)), "cold/x")
		},
	}
}

// rootWithDecoySibling returns a storage root whose parent directory holds a
// file the store does not own. The local backend resolves keys against a real
// tree, so this is what gives list_never_escapes_the_store something to catch:
// without a decoy outside the root, a walk that stepped up a level would find
// nothing and the case would pass on a broken backend.
func rootWithDecoySibling(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	if err := os.WriteFile(filepath.Join(parent, "not-ours.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write decoy: %v", err)
	}
	root := filepath.Join(parent, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	return root
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

		// Sorted by key, across directory levels. A tree walk orders directory
		// entries, not keys: "b" sorts before "b-1", so the walk emits
		// "x/b/z" before "x/b-1" while "/" (0x2f) sorts after "-" (0x2d) and
		// the keys run the other way.
		// The listing fan-out merges two of these and sorts the union, which
		// is only a merge if each input is already ordered, and Packages.gz is
		// generated per request — an unstable order changes the bytes and
		// every client refetches.
		{"list_is_sorted", func(t *testing.T, ctx context.Context, s ObjectStore) {
			for _, k := range []string{"x/c", "x/a", "x/b/z", "x/b-1"} {
				if err := s.Put(ctx, k, []byte(k)); err != nil {
					t.Fatalf("Put %s: %v", k, err)
				}
			}
			got, err := s.List(ctx, "x/")
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			want := []string{"x/a", "x/b-1", "x/b/z", "x/c"}
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

		// A prefix that normalizes to the store root must not reach outside
		// it. The local backend walks a real directory tree, so this is the
		// one place a key can be manufactured from a file nobody stored.
		{"list_never_escapes_the_store", func(t *testing.T, ctx context.Context, s ObjectStore) {
			if err := s.Put(ctx, "inside.txt", []byte("x")); err != nil {
				t.Fatalf("Put: %v", err)
			}
			for _, prefix := range []string{"", ".", "./"} {
				keys, err := s.List(ctx, prefix)
				if err != nil {
					continue // rejecting the prefix outright is also correct
				}
				for _, k := range keys {
					if strings.HasPrefix(k, "../") || strings.HasPrefix(k, "/") || strings.Contains(k, "not-ours") {
						t.Fatalf("List(%q) returned %q, which is outside the store", prefix, k)
					}
				}
			}
		}},

		{"label_is_addressable", func(t *testing.T, _ context.Context, s ObjectStore) {
			if !strings.Contains(s.Label(), "://") {
				t.Fatalf("Label() = %q, want a scheme-qualified location", s.Label())
			}
		}},

		// Label is not only an error-message string. dedupByLabel treats two
		// backends sharing one as one physical location, and 'pkg move'
		// refuses a move between two names that do, so a Label that changed
		// between calls would make the same pair of backends distinct on one
		// call and identical on the next.
		{"label_is_stable", func(t *testing.T, _ context.Context, s ObjectStore) {
			if first, second := s.Label(), s.Label(); first != second {
				t.Fatalf("Label() returned %q then %q", first, second)
			}
		}},

		// A key with a NUL truncates at the syscall boundary, so a traversal
		// check that ran on the Go string passed on something the filesystem
		// never saw. Every method that takes a key refuses it, on every
		// backend: a double that accepted one would let a server test pass on
		// a key that errors in production.
		{"nul_in_a_key_is_refused", func(t *testing.T, ctx context.Context, s ObjectStore) {
			assertKeyRefused(t, ctx, s, "a\x00/b")
		}},

		// Same rule for a key that normalizes above the root. The filesystem
		// backend resolves keys against a real tree, so this one addresses a
		// file outside the store; the flat backends enforce it anyway, because
		// the key is derived once and handed to whichever backend the version
		// records.
		{"traversal_out_of_the_store_is_refused", func(t *testing.T, ctx context.Context, s ObjectStore) {
			for _, key := range []string{"../escaped", "a/../../escaped", ".."} {
				assertKeyRefused(t, ctx, s, key)
			}
		}},

		// A key that normalizes back inside the store is not traversal and
		// must still work: rejecting it would refuse legitimate keys on a
		// technicality.
		{"traversal_that_stays_inside_is_allowed", func(t *testing.T, ctx context.Context, s ObjectStore) {
			if err := s.Put(ctx, "a/b/../c.txt", []byte("fine")); err != nil {
				t.Fatalf("Put of a key that normalizes inside the root: %v", err)
			}
		}},

		// The keys internal/manifest derives are full of characters an
		// ecosystem chose and bodega cannot rename: npm scopes lead with "@",
		// the Go proxy layout puts "@v" in its own segment, and a semver build
		// tag carries "+". Each has to round-trip verbatim, including out of
		// List, or the uploader and the handler stop agreeing on one key.
		{"ecosystem_key_characters_round_trip", func(t *testing.T, ctx context.Context, s ObjectStore) {
			keys := []string{
				"npm/@bitwarden/cli/-/cli-2026.4.0.tgz",
				"gomod/github.com/aws/aws-sdk-go-v2/@v/v1.30.0.zip",
				"binaries/awscli-v2/2.1.0+build.7/awscli.zip",
				"apt/pool/main/libf/libfoo++/libfoo++_1.0_amd64.deb",
			}
			for _, k := range keys {
				if err := s.Put(ctx, k, []byte(k)); err != nil {
					t.Fatalf("Put %q: %v", k, err)
				}
			}
			for _, k := range keys {
				got, err := s.Get(ctx, k)
				if err != nil || string(got) != k {
					t.Fatalf("Get %q = %q, %v", k, got, err)
				}
			}
			listed, err := s.List(ctx, "npm/@bitwarden/")
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if !reflect.DeepEqual(listed, []string{keys[0]}) {
				t.Fatalf("List(npm/@bitwarden/) = %v, want %v", listed, keys[:1])
			}
		}},

		// bodega reset lists a prefix and deletes what comes back, so a key
		// List returns has to be a key the other methods accept unchanged. A
		// backend that returned a filesystem path would delete nothing and
		// report success.
		{"listed_keys_are_addressable", func(t *testing.T, ctx context.Context, s ObjectStore) {
			if err := s.Put(ctx, "manifests/apt/nginx.json", []byte("{}")); err != nil {
				t.Fatalf("Put: %v", err)
			}
			keys, err := s.List(ctx, "manifests/")
			if err != nil || len(keys) != 1 {
				t.Fatalf("List = %v, %v; want one key", keys, err)
			}
			info, err := s.Head(ctx, keys[0])
			if err != nil || info == nil || !info.Exists {
				t.Fatalf("Head(%q) = %+v, %v; want Exists=true", keys[0], info, err)
			}
			if err := s.Delete(ctx, keys[0]); err != nil {
				t.Fatalf("Delete(%q): %v", keys[0], err)
			}
			if info, _ := s.Head(ctx, keys[0]); info == nil || info.Exists {
				t.Fatalf("Head(%q) after Delete says it is still there", keys[0])
			}
		}},

		// Delete takes one key, never a prefix. 'bodega pkg delete' removes
		// the keys one version resolves to; a Delete that took the key as a
		// subtree would take every other version of the package with it.
		{"delete_is_not_a_prefix_delete", func(t *testing.T, ctx context.Context, s ObjectStore) {
			if err := s.Put(ctx, "binaries/awscli/2.1.0/awscli.zip", []byte("keep")); err != nil {
				t.Fatalf("Put: %v", err)
			}
			if err := s.Delete(ctx, "binaries/awscli"); err != nil {
				t.Fatalf("Delete of a prefix: %v", err)
			}
			got, err := s.Get(ctx, "binaries/awscli/2.1.0/awscli.zip")
			if err != nil || string(got) != "keep" {
				t.Fatalf("Delete of a prefix removed the objects under it: %q, %v", got, err)
			}
		}},

		// nil from Get means "no such object" and nothing else. A stored
		// zero-length object exists — an empty Packages index or a zero-byte
		// artifact — and a backend that answered nil for it would make the two
		// indistinguishable to every caller that tests for nil.
		{"empty_object_is_not_a_missing_one", func(t *testing.T, ctx context.Context, s ObjectStore) {
			if err := s.Put(ctx, "e/empty", []byte{}); err != nil {
				t.Fatalf("Put: %v", err)
			}
			info, err := s.Head(ctx, "e/empty")
			if err != nil || info == nil || !info.Exists {
				t.Fatalf("Head of a zero-byte object = %+v, %v; want Exists=true", info, err)
			}
			if info.Size != 0 {
				t.Fatalf("Head Size %d, want 0", info.Size)
			}
			got, err := s.Get(ctx, "e/empty")
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if got == nil {
				t.Fatal("Get of a stored zero-byte object returned nil, which every caller reads as missing")
			}
			if len(got) != 0 {
				t.Fatalf("Get = %q, want zero bytes", got)
			}
		}},

		// pkg move verifies a copy by comparing Head().Size against the bytes
		// it spooled, then serves the object with GetStream and sets
		// Content-Length from ContentLength. The two have to be the same
		// number or the verify passes on a body the client then truncates.
		{"head_size_and_stream_length_agree", func(t *testing.T, ctx context.Context, s ObjectStore) {
			body := []byte("0123456789")
			if err := s.Put(ctx, "sz/obj", body); err != nil {
				t.Fatalf("Put: %v", err)
			}
			info, err := s.Head(ctx, "sz/obj")
			if err != nil || info == nil {
				t.Fatalf("Head: %+v, %v", info, err)
			}
			r, err := s.GetStream(ctx, "sz/obj")
			if err != nil || r == nil {
				t.Fatalf("GetStream: %+v, %v", r, err)
			}
			defer r.Body.Close()
			if info.Size != r.ContentLength {
				t.Fatalf("Head Size %d, GetStream ContentLength %d", info.Size, r.ContentLength)
			}
		}},

		// An interrupted 'pkg move' or 'repair keys' is re-run, and the second
		// pass PutFiles onto a key the first one already wrote. A backend that
		// refused or appended would make recovery the dangerous operation.
		{"putfile_overwrites", func(t *testing.T, ctx context.Context, s ObjectStore) {
			dir := t.TempDir()
			first := filepath.Join(dir, "first")
			second := filepath.Join(dir, "second")
			if err := os.WriteFile(first, []byte("partial"), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			if err := os.WriteFile(second, []byte("whole artifact"), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			if err := s.PutFile(ctx, first, "re/run.bin"); err != nil {
				t.Fatalf("PutFile: %v", err)
			}
			if err := s.PutFile(ctx, second, "re/run.bin"); err != nil {
				t.Fatalf("second PutFile: %v", err)
			}
			got, err := s.Get(ctx, "re/run.bin")
			if err != nil || string(got) != "whole artifact" {
				t.Fatalf("Get after re-run = %q, %v; want the second file's bytes", got, err)
			}
		}},

		// "Implementations must be safe for concurrent use" is on the
		// interface and nothing held a backend to it. The server writes a
		// proxy-cache entry from one request while others read, so this is the
		// live shape, not a hypothetical. Run under -race, which make test does.
		{"concurrent_use_is_safe", func(t *testing.T, ctx context.Context, s ObjectStore) {
			if err := s.Put(ctx, "c/seed", []byte("seed")); err != nil {
				t.Fatalf("Put: %v", err)
			}
			var wg sync.WaitGroup
			for i := range 8 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					key := "c/" + strconv.Itoa(i)
					if err := s.Put(ctx, key, []byte(key)); err != nil {
						t.Errorf("concurrent Put: %v", err)
						return
					}
					if _, err := s.Get(ctx, "c/seed"); err != nil {
						t.Errorf("concurrent Get: %v", err)
					}
					if _, err := s.Head(ctx, key); err != nil {
						t.Errorf("concurrent Head: %v", err)
					}
					if _, err := s.List(ctx, "c/"); err != nil {
						t.Errorf("concurrent List: %v", err)
					}
				}()
			}
			wg.Wait()
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.run(t, t.Context(), mk())
		})
	}
}

// assertKeyRefused holds every method that takes a key to the same answer for
// a key ValidateKey rejects. Checking only Put would let a backend refuse the
// write and then happily read, list or delete the same string.
func assertKeyRefused(t *testing.T, ctx context.Context, s ObjectStore, key string) {
	t.Helper()
	local := filepath.Join(t.TempDir(), "src")
	if err := os.WriteFile(local, []byte("x"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	for _, op := range []struct {
		name string
		call func() error
	}{
		{"Get", func() error { _, err := s.Get(ctx, key); return err }},
		{"GetStream", func() error { _, err := s.GetStream(ctx, key); return err }},
		{"Head", func() error { _, err := s.Head(ctx, key); return err }},
		{"List", func() error { _, err := s.List(ctx, key); return err }},
		{"Put", func() error { return s.Put(ctx, key, []byte("x")) }},
		{"PutFile", func() error { return s.PutFile(ctx, local, key) }},
		{"Delete", func() error { return s.Delete(ctx, key) }},
	} {
		if err := op.call(); err == nil {
			t.Errorf("%s(%q) returned nil, want a rejection", op.name, key)
		}
	}
}

// TestLabelDistinguishesTwoStores pins the other half of the Label contract.
// Two stores over different locations must not share one: dedupByLabel drops
// the second of any pair that does, so a fan-out would silently list one
// backend, and 'pkg move' would refuse a legitimate move as a copy onto
// itself.
func TestLabelDistinguishesTwoStores(t *testing.T) {
	for name, mk := range conformanceBackends() {
		t.Run(name, func(t *testing.T) {
			if a, b := mk(t).Label(), mk(t).Label(); a == b {
				t.Fatalf("two independent stores both report Label() = %q", a)
			}
		})
	}
}

// sameLocationSpellings returns, per backend, several stores that name one
// location in different ways. Every backend in conformanceBackends needs an
// entry, empty or not, so joining the suite forces an answer to "how else can
// this location be spelled".
func sameLocationSpellings(t *testing.T) map[string][]ObjectStore {
	t.Helper()

	// The three spellings a staged migration actually produces. A second
	// storage_backends entry pointing at a symlink of the first root is the
	// documented way to do it; the trailing slash and the "/a/../b" form are
	// what an operator's config file carries after hand-editing a path.
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	// EvalSymlinks walks components rather than cleaning lexically, so the
	// "/a/../b" spelling needs "a" to exist for the resolution to succeed.
	if err := os.MkdirAll(filepath.Join(parent, "sibling"), 0o755); err != nil {
		t.Fatalf("mkdir sibling: %v", err)
	}

	return map[string][]ObjectStore{
		"local": {
			NewLocal(root),
			NewLocal(link),
			NewLocal(root + string(filepath.Separator)),
			NewLocal(parent + "/sibling/../root"),
		},
		// Memory has no second spelling: its location is the instance, and
		// two instances are two locations. TestLabelDistinguishesTwoStores
		// covers that direction already.
		"memory": nil,
		// A prefix multiplies the spellings: everything the inner root can be
		// called, times everything the prefix can be called. The last two are
		// the pair that reached #189 through a config file.
		"prefixed": {
			withPrefix(NewLocal(root), "cold/x"),
			withPrefix(NewLocal(link), "cold/x"),
			withPrefix(NewLocal(root), "/cold/x"),
			withPrefix(NewLocal(root), "cold/x/"),
			withPrefix(NewLocal(root), "cold//x"),
			withPrefix(NewLocal(root), "./cold/x"),
			withPrefix(NewLocal(root), "cold/y/../x"),
		},
	}
}

// TestLabelIsOnePerLocation pins the direction pkg move depends on, and the one
// TestLabelDistinguishesTwoStores does not reach. Distinct locations giving
// distinct labels keeps a legitimate move working; one location giving one
// label is what makes the same-location refusal fire at all. Without it,
// 'pkg move --delete-source' between a root and a symlink of that root copies
// every object onto itself, verifies what it overwrote, and deletes the only
// copy.
func TestLabelIsOnePerLocation(t *testing.T) {
	spellings := sameLocationSpellings(t)
	for name := range conformanceBackends() {
		stores, ok := spellings[name]
		if !ok {
			t.Errorf("backend %q has no entry in sameLocationSpellings; add one, empty if the backend has no second spelling of a location", name)
			continue
		}
		if len(stores) == 0 {
			continue
		}
		t.Run(name, func(t *testing.T) {
			want := stores[0].Label()
			for _, s := range stores[1:] {
				if got := s.Label(); got != want {
					t.Errorf("Label() = %q, want %q — one location must produce one label", got, want)
				}
			}
		})
	}
}
