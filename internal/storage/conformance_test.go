package storage

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	bos3 "github.com/ravinald/bodega/internal/s3"
)

// backends is the set every ObjectStore implementation is held to. A new
// backend joins by adding one line here, and one to requireReachable if it
// needs something the machine running the tests may not have.
//
// S3 runs against a live bucket, which a gate that needs an AWS account can
// only do while the account is available. So it runs when credentials
// resolve, and skips when none do unless s3ConformanceEnv promises them, in
// which case their absence fails the run: a skip nothing forces is a gate that
// stops blocking without anyone deciding it should.
func conformanceBackends() map[string]func(t *testing.T) ObjectStore {
	return map[string]func(t *testing.T) ObjectStore{
		"local":  func(t *testing.T) ObjectStore { return NewLocal(rootWithDecoySibling(t)) },
		"memory": func(t *testing.T) ObjectStore { return NewMemory() },
		"s3":     newConformanceS3,
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

// s3ConformanceEnv promises this run an S3 endpoint. Set to anything, it turns
// "no AWS credentials resolved" from a skip into a failure, so a pipeline that
// is meant to exercise S3 cannot pass by quietly not doing so.
const s3ConformanceEnv = "BODEGA_S3_CONFORMANCE"

// conformanceBucketPrefix is the name every bucket this file creates starts
// with. The development account's test role may create and delete only
// buckets under it, and a crashed run is cleaned by one sweep over it.
const conformanceBucketPrefix = "bodega-conf-"

var (
	s3ConfOnce sync.Once
	s3Conf     aws.Config
	s3ConfErr  error
)

// liveS3Config resolves the AWS default chain once per test binary. Retrieving
// is what proves credentials exist: loading succeeds with none, and the first
// request would fail instead.
func liveS3Config() (aws.Config, error) {
	s3ConfOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		s3Conf, s3ConfErr = awsconfig.LoadDefaultConfig(ctx)
		if s3ConfErr != nil {
			return
		}
		if s3Conf.Region == "" {
			s3Conf.Region = "us-west-2"
		}
		_, s3ConfErr = s3Conf.Credentials.Retrieve(ctx)
	})
	return s3Conf, s3ConfErr
}

// requireReachable skips or fails a backend's subtest before any case runs,
// so the decision is made once per backend on the goroutine that owns it.
func requireReachable(t *testing.T, name string) {
	t.Helper()
	if name != "s3" {
		return
	}
	if _, err := liveS3Config(); err != nil {
		if os.Getenv(s3ConformanceEnv) != "" {
			t.Fatalf("%s is set, so this run was promised an S3 endpoint, and no AWS credentials resolved: %v", s3ConformanceEnv, err)
		}
		t.Skipf("no AWS credentials resolved (%v); set %s to make that a failure", err, s3ConformanceEnv)
	}
}

// liveS3Bucket names a fresh bucket and registers its teardown. Each store
// gets its own because S3.Label() is s3://<bucket>, and
// TestLabelDistinguishesTwoStores is only meaningful if two stores are two
// buckets rather than one bucket under a wrapper this file would then be
// testing instead of s3.go.
func liveS3Bucket(t *testing.T) (aws.Config, *bos3.Client) {
	t.Helper()
	cfg, err := liveS3Config()
	if err != nil {
		t.Fatalf("requireReachable did not run before the s3 factory: %v", err)
	}
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	bucket := conformanceBucketPrefix + hex.EncodeToString(raw[:])
	client := bos3.NewClientFromConfig(cfg, bucket, cfg.Region)
	t.Cleanup(func() { dropLiveBucket(t, client) })
	return cfg, client
}

func newConformanceS3(t *testing.T) ObjectStore {
	t.Helper()
	cfg, client := liveS3Bucket(t)
	// CreateBucket rather than InitBucket: versioning would make teardown walk
	// delete markers, and an InitBucket defect would fail every case here
	// instead of the one test that is about it.
	in := &awss3.CreateBucketInput{Bucket: aws.String(client.Bucket())}
	if cfg.Region != "us-east-1" {
		in.CreateBucketConfiguration = &s3types.CreateBucketConfiguration{
			LocationConstraint: s3types.BucketLocationConstraint(cfg.Region),
		}
	}
	if _, err := client.S3Client().CreateBucket(t.Context(), in); err != nil {
		t.Fatalf("create s3://%s in %s: %v", client.Bucket(), cfg.Region, err)
	}
	return NewS3(client)
}

// dropLiveBucket empties and deletes a bucket this file created. It is
// best-effort: a leaked bucket costs a sweep, and failing the case over it
// would report a teardown problem as a contract violation. It runs on its own
// context because t.Context() is already canceled when cleanup runs.
func dropLiveBucket(t *testing.T, client *bos3.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	api, bucket := client.S3Client(), aws.String(client.Bucket())

	var objects []s3types.ObjectIdentifier
	versions := awss3.NewListObjectVersionsPaginator(api, &awss3.ListObjectVersionsInput{Bucket: bucket})
	for versions.HasMorePages() {
		page, err := versions.NextPage(ctx)
		if err != nil {
			if isNoSuchBucket(err) {
				return
			}
			t.Logf("teardown: list s3://%s: %v; sweep %s* by hand", *bucket, err, conformanceBucketPrefix)
			return
		}
		for _, v := range page.Versions {
			objects = append(objects, s3types.ObjectIdentifier{Key: v.Key, VersionId: v.VersionId})
		}
		for _, m := range page.DeleteMarkers {
			objects = append(objects, s3types.ObjectIdentifier{Key: m.Key, VersionId: m.VersionId})
		}
	}
	for len(objects) > 0 {
		n := min(len(objects), 1000)
		if _, err := api.DeleteObjects(ctx, &awss3.DeleteObjectsInput{
			Bucket: bucket, Delete: &s3types.Delete{Objects: objects[:n], Quiet: aws.Bool(true)},
		}); err != nil {
			t.Logf("teardown: empty s3://%s: %v", *bucket, err)
		}
		objects = objects[n:]
	}
	if _, err := api.DeleteBucket(ctx, &awss3.DeleteBucketInput{Bucket: bucket}); err != nil && !isNoSuchBucket(err) {
		t.Logf("teardown: delete s3://%s: %v; sweep %s* by hand", *bucket, err, conformanceBucketPrefix)
	}
}

func isNoSuchBucket(err error) bool {
	var ae smithy.APIError
	return errors.As(err, &ae) && ae.ErrorCode() == "NoSuchBucket"
}

// TestInitBucketAgainstALiveBucket runs InitBucket where the conformance
// cases do not: a versioned, encrypted, lifecycle-configured bucket, created
// by the code an operator runs. The second pass is the idempotence claim, and
// it must report every step as already correct.
func TestInitBucketAgainstALiveBucket(t *testing.T) {
	requireReachable(t, "s3")
	cfg, client := liveS3Bucket(t)
	for pass, wantChange := range []bool{true, false} {
		var out bytes.Buffer
		if err := bos3.InitBucket(t.Context(), client.S3Client(), &out, client.Bucket(), cfg.Region); err != nil {
			t.Fatalf("pass %d: %v\n%s", pass+1, err, out.String())
		}
		changed := strings.Contains(out.String(), "CREATED") || strings.Contains(out.String(), "CONFIGURED") || strings.Contains(out.String(), "ENABLED")
		if changed != wantChange {
			t.Errorf("pass %d reported a change = %v, want %v:\n%s", pass+1, changed, wantChange, out.String())
		}
	}
	lc, err := client.S3Client().GetBucketLifecycleConfiguration(t.Context(), &awss3.GetBucketLifecycleConfigurationInput{Bucket: aws.String(client.Bucket())})
	if err != nil {
		t.Fatalf("read back lifecycle: %v", err)
	}
	if got, want := len(lc.Rules), len(bos3.LifecycleRules()); got != want {
		t.Errorf("bucket holds %d lifecycle rules, want %d", got, want)
	}
}

// heldByReading is the set of registered drivers no case in this file runs
// against, each with the argument standing in for a run. It is empty, and
// stays declared for the next driver that cannot run here.
//
// Reading is the weaker substitute and the argument has to say what it costs.
// It can lean on a service's documented guarantees for the ordering promises
// of the write contract; it cannot catch the wrapper: a Put that silently
// drops a key, a GetStream that returns a closed body, a ValidateKey call left
// off a method. Each is caught by nothing until an operator meets it.
var heldByReading = map[string]string{}

// A backend satisfies ObjectStore as documented while keeping less than the
// write contract says, and the only thing standing between that and a
// deployment is a suite it has to remember to join. Remembering is what this
// case replaces: a driver registered under a name config can select is either
// run against the contract or carries a written argument for why it is not.
func TestEveryRegisteredDriverIsHeldToTheContract(t *testing.T) {
	run := conformanceBackends()
	for _, driver := range Drivers() {
		if _, ok := run[driver]; ok {
			continue
		}
		if why, ok := heldByReading[driver]; ok {
			t.Logf("%s is held by reading: %s", driver, why)
			continue
		}
		t.Errorf("driver %q is registered, so an operator can place artifacts on it, "+
			"and no case in this file runs against it. Add it to conformanceBackends, "+
			"or add it to heldByReading with the argument that stands in for a run.", driver)
	}
}

func TestObjectStoreConformance(t *testing.T) {
	for name, mk := range conformanceBackends() {
		t.Run(name, func(t *testing.T) {
			requireReachable(t, name)
			testObjectStore(t, mk)
		})
	}
}

// testObjectStore runs the ObjectStore contract against one implementation.
// Each case gets a fresh store so an assertion never depends on the order the
// table happens to run in.
//
// mk takes the per-case *testing.T, not the one the backend's subtest holds.
// A factory that fails or registers cleanup does so on the goroutine running
// the case; handed the parent's, a t.Fatal inside it would call Goexit on the
// wrong goroutine and a store's cleanup would outlive the case that used it.
func testObjectStore(t *testing.T, mk func(t *testing.T) ObjectStore) {
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
				"npm/@example-corp/widget-cli/-/widget-cli-1.5.0.tgz",
				"gomod/example.com/example-corp/widget-sdk/@v/v1.30.0.zip",
				"binaries/example-tool-v2/2.1.0+build.7/example-tool.zip",
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
			listed, err := s.List(ctx, "npm/@example-corp/")
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if !reflect.DeepEqual(listed, []string{keys[0]}) {
				t.Fatalf("List(npm/@example-corp/) = %v, want %v", listed, keys[:1])
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
			if err := s.Put(ctx, "binaries/example-tool/2.1.0/example-tool.zip", []byte("keep")); err != nil {
				t.Fatalf("Put: %v", err)
			}
			if err := s.Delete(ctx, "binaries/example-tool"); err != nil {
				t.Fatalf("Delete of a prefix: %v", err)
			}
			got, err := s.Get(ctx, "binaries/example-tool/2.1.0/example-tool.zip")
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
			// The proxy records which upstream supplied a cached object
			// against what the store said when it read those bytes, and
			// compares it against what the store says when it serves them. A
			// backend whose open reports a different timestamp from its Head,
			// or none, makes every object it holds unattributable.
			if !info.LastModified.Equal(r.LastModified) {
				t.Fatalf("Head LastModified %v, GetStream LastModified %v", info.LastModified, r.LastModified)
			}
		}},

		// The proxy binds a cache hit's recorded origin to the identity
		// GetStream reported and then streams that same handle. Nothing
		// orders a publication against a read in progress — the writer is
		// often a 'pkg upload' in another process — so a backend that let a
		// replacement reach an open handle would serve one artifact's bytes
		// under another artifact's provenance, with a length and timestamp
		// describing neither.
		//
		// Both lengths, because an equal-length replacement is what a check
		// reading ContentLength cannot tell apart.
		{"an_open_reader_is_a_snapshot", func(t *testing.T, ctx context.Context, s ObjectStore) {
			for _, sameLength := range []bool{true, false} {
				key := "snap/obj-" + strconv.FormatBool(sameLength)
				original := []byte("the bytes this reader opened")
				replacement := []byte("a locally built artifact landing mid-read")
				if sameLength {
					replacement = bytes.Repeat([]byte("L"), len(original))
				}
				if err := s.Put(ctx, key, original); err != nil {
					t.Fatalf("Put: %v", err)
				}
				r, err := s.GetStream(ctx, key)
				if err != nil || r == nil {
					t.Fatalf("GetStream: %+v, %v", r, err)
				}
				if err := s.Put(ctx, key, replacement); err != nil {
					r.Body.Close()
					t.Fatalf("replacement Put: %v", err)
				}
				got, err := io.ReadAll(r.Body)
				r.Body.Close()
				if err != nil {
					t.Fatalf("read the open handle: %v", err)
				}
				if !bytes.Equal(got, original) {
					t.Errorf("same_length=%v: open handle read %q, want %q — the write reached a reader already on the object",
						sameLength, got, original)
				}
				if r.ContentLength != int64(len(original)) {
					t.Errorf("same_length=%v: ContentLength %d, want %d", sameLength, r.ContentLength, len(original))
				}
				next, err := s.GetStream(ctx, key)
				if err != nil || next == nil {
					t.Fatalf("GetStream after the replacement: %+v, %v", next, err)
				}
				after, err := io.ReadAll(next.Body)
				next.Body.Close()
				if err != nil {
					t.Fatalf("read the replacement: %v", err)
				}
				if !bytes.Equal(after, replacement) {
					t.Errorf("same_length=%v: the next open read %q, want the replacement %q", sameLength, after, replacement)
				}
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
			tc.run(t, t.Context(), mk(t))
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
			requireReachable(t, name)
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
		// A bucket name is global, so a region is not part of the location
		// and two clients spelling it differently name one bucket. The prefix
		// spellings that would need cleaning are refused at load, and s3
		// takes no prefix of its own: s3://<bucket> is one string per bucket.
		// Label reads no network, so this entry needs no credentials.
		"s3": {
			NewS3(bos3.NewClientFromConfig(aws.Config{Region: "us-west-2"}, "bodega-conf-label", "us-west-2")),
			NewS3(bos3.NewClientFromConfig(aws.Config{Region: "us-east-1"}, "bodega-conf-label", "us-east-1")),
			NewS3(bos3.NewClientFromConfig(aws.Config{}, "bodega-conf-label", "")),
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

// FreeBSD's extended-attribute and ACL interfaces are covered here rather than
// on a FreeBSD host, because no FreeBSD host exists in this project yet (E08
// owns standing one up). What runs is the encoding and decoding between
// bodega and the kernel, which is the layer the interface differences reach.
// What does not run is the syscalls themselves: acl_freebsd.go's __acl_get_fd
// and __acl_set_fd, and xattr_freebsd.go's extattr_list_fd, are unexercised.

// extattrList builds the answer extattr_list_fd(2) gives: one byte of length
// per name, then the name, and no terminator.
func extattrList(names ...string) []byte {
	var buf []byte
	for _, name := range names {
		//nolint:gosec // G115: every name below is far shorter than 255 bytes.
		buf = append(buf, byte(len(name)))
		buf = append(buf, name...)
	}
	return buf
}

// xattrNamespaceAccepts restates unix.xattrnamespace (x/sys/unix v0.48.0,
// xattr_bsd.go), which is unexported and which every Fgetxattr, Fsetxattr and
// Fremovexattr on FreeBSD runs its name through. A name it refuses comes back
// ENOATTR, which readAccess hands to missingXattr and then skips.
func xattrNamespaceAccepts(name string) bool {
	ns, _, ok := strings.Cut(name, ".")
	return ok && (ns == "user" || ns == "system")
}

func TestFreeBSDAttributeNamesDecodeFromLengthPrefixes(t *testing.T) {
	t.Parallel()
	buf := extattrList("bodega.sha256", "md5")
	got, err := splitExtattrNames(buf, "user.")
	if err != nil {
		t.Fatalf("decode the user namespace: %v", err)
	}
	want := []string{"user.bodega.sha256", "user.md5"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("splitExtattrNames = %q, want %q", got, want)
	}
	// The same buffer read the way Linux and macOS answer: one run of bytes
	// with no NUL in it, so the whole answer is a single name carrying a
	// length prefix in place of its first character.
	nul := strings.Split(string(buf), "\x00")
	if len(nul) != 1 {
		t.Fatalf("the FreeBSD answer split on NUL into %d names; it holds no NUL at all", len(nul))
	}
	if xattrNamespaceAccepts(nul[0]) {
		t.Errorf("unix.Fgetxattr would accept %q, so splitting on NUL would have gone unnoticed", nul[0])
	}
}

func TestEveryDecodedAttributeNameReadsBackThroughFgetxattr(t *testing.T) {
	t.Parallel()
	for _, ns := range []struct {
		prefix string
		buf    []byte
	}{
		{"user.", extattrList("bodega.sha256", "md5")},
		{"system.", extattrList("posix1e.acl_access", "md5")},
	} {
		names, err := splitExtattrNames(ns.buf, ns.prefix)
		if err != nil {
			t.Fatalf("decode the %s namespace: %v", ns.prefix, err)
		}
		if len(names) == 0 {
			t.Fatalf("decode the %s namespace: no names", ns.prefix)
		}
		for _, name := range names {
			if !xattrNamespaceAccepts(name) {
				t.Errorf("unix.Fgetxattr refuses %q, so the attribute is read as ENOATTR and dropped", name)
			}
		}
	}
	// Unqualified is what the kernel hands back and what a decoder that only
	// fixed the length prefixes would return. "posix1e" is not a namespace, so
	// the ACL every object on an ACL-enabled UFS carries is the first casualty.
	if xattrNamespaceAccepts("posix1e.acl_access") {
		t.Error("xattrNamespaceAccepts admits an unqualified name; the mirror of unix.xattrnamespace is wrong")
	}
}

func TestSplitExtattrNamesRefusesAnAnswerThatRunsPastItsEnd(t *testing.T) {
	t.Parallel()
	if _, err := splitExtattrNames([]byte{9, 'm', 'd', '5'}, "user."); err == nil {
		t.Error("splitExtattrNames accepted a 9-byte name in a 3-byte answer")
	}
}

func TestMinimalACLIsTheModeBitsAndNothingNamed(t *testing.T) {
	t.Parallel()
	acl := minimalACL(0o640)
	if err := checkStructACL(aclTypeAccess, acl); err != nil {
		t.Fatalf("minimalACL built a struct acl __acl_set_fd would refuse: %v", err)
	}
	if cnt := binary.NativeEndian.Uint32(acl[4:8]); cnt != 3 {
		t.Errorf("acl_cnt = %d, want 3: the owner, the owning group and everyone else", cnt)
	}
	for i, want := range []struct{ tag, perm uint32 }{
		{tagUserObj, 6},
		{tagGroupObj, 4},
		{tagOther, 0},
	} {
		off := aclEntryStart + i*aclEntrySize
		tag := binary.NativeEndian.Uint32(acl[off : off+4])
		id := binary.NativeEndian.Uint32(acl[off+4 : off+8])
		perm := binary.NativeEndian.Uint32(acl[off+8 : off+12])
		if tag != want.tag || perm != want.perm || id != undefinedID {
			t.Errorf("entry %d = {tag %#x, id %#x, perm %d}, want {tag %#x, id %#x, perm %d}",
				i, tag, id, perm, want.tag, undefinedID, want.perm)
		}
	}
}

func TestTrivialNFS4ACLIsTheModeBitsAndNothingNamed(t *testing.T) {
	t.Parallel()
	acl := trivialNFS4ACL(0o751)
	if err := checkStructACL(aclTypeNFS4, acl); err != nil {
		t.Fatalf("trivialNFS4ACL built a struct acl __acl_set_fd would refuse: %v", err)
	}
	if i, ok := grantBeyondMode(acl); ok {
		t.Errorf("entry %d of trivialNFS4ACL grants past the mode", i)
	}
	// getfacl -n on a ZFS directory chmod'd 0751: rwxp--aARWcCos, r-x---a-R-c--s
	// and --x---a-R-c--s, every one an allow with no flags.
	for i, want := range []struct{ tag, perm uint32 }{
		{tagUserObj, 0xF6F9},
		{tagGroupObj, 0x9249},
		{tagEveryone, 0x9241},
	} {
		off := aclEntryStart + i*aclEntrySize
		tag := binary.NativeEndian.Uint32(acl[off : off+4])
		perm := binary.NativeEndian.Uint32(acl[off+8 : off+12])
		kind := binary.NativeEndian.Uint16(acl[off+12 : off+14])
		flags := binary.NativeEndian.Uint16(acl[off+14 : off+16])
		if tag != want.tag || perm != want.perm || kind != entryAllow || flags != 0 {
			t.Errorf("entry %d = {tag %#x, perm %#x, type %#x, flags %#x}, want {tag %#x, perm %#x, allow, no flags}",
				i, tag, perm, kind, flags, want.tag, want.perm)
		}
	}
}

func TestGrantBeyondModeFindsANamedOrInheritableEntry(t *testing.T) {
	t.Parallel()
	named := trivialNFS4ACL(0o600)
	binary.NativeEndian.PutUint32(named[aclEntryStart+aclEntrySize:], tagUser)
	if i, ok := grantBeyondMode(named); !ok || i != 1 {
		t.Errorf("grantBeyondMode on a named entry at 1 = %d, %v", i, ok)
	}
	inheritable := trivialNFS4ACL(0o700)
	binary.NativeEndian.PutUint16(inheritable[aclEntryStart+2*aclEntrySize+14:], 0x0080)
	if i, ok := grantBeyondMode(inheritable); !ok || i != 2 {
		t.Errorf("grantBeyondMode on an inherited everyone@ at 2 = %d, %v", i, ok)
	}
	if _, ok := grantBeyondMode(minimalACL(0o640)); ok {
		t.Error("grantBeyondMode flagged a minimal POSIX.1e ACL")
	}
}

func TestCheckStructACLRefusesABlobTheKernelWould(t *testing.T) {
	t.Parallel()
	if err := checkStructACL(aclTypeAccess, make([]byte, aclSize)); err == nil {
		t.Error("a struct acl with acl_maxcnt 0 was accepted; acl_copyout answers that one EINVAL")
	}
	if err := checkStructACL(aclTypeAccess, minimalACL(0o644)[:aclSize-1]); err == nil {
		t.Error("a short struct acl was accepted")
	}
	tooMany := blankACL()
	binary.NativeEndian.PutUint32(tooMany[4:8], aclMaxEntries+1)
	if err := checkStructACL(aclTypeNFS4, tooMany); err == nil {
		t.Error("a struct acl claiming more entries than it holds was accepted")
	}
	if err := checkStructACL(aclTypeDefault, minimalACL(0o644)); err == nil {
		t.Error("a default ACL was accepted; publication carries an object's ACL, and an object has no default")
	}
}

// nfs4Entry is one row of a struct acl in the NFSv4 layout.
type nfs4Entry struct {
	tag, id, perm uint32
	kind, flags   uint16
}

func nfs4ACL(entries ...nfs4Entry) []byte {
	acl := blankACL()
	binary.NativeEndian.PutUint32(acl[4:8], uint32(len(entries))) //nolint:gosec // G115: a handful of test entries.
	for i, e := range entries {
		off := aclEntryStart + i*aclEntrySize
		binary.NativeEndian.PutUint32(acl[off:off+4], e.tag)
		binary.NativeEndian.PutUint32(acl[off+4:off+8], e.id)
		binary.NativeEndian.PutUint32(acl[off+8:off+12], e.perm)
		binary.NativeEndian.PutUint16(acl[off+12:off+14], e.kind)
		binary.NativeEndian.PutUint16(acl[off+14:off+16], e.flags)
	}
	return acl
}

// deniedNobody is what getfacl printed on a ZFS object after
// setfacl -a0 user:nobody:r::deny: the named deny ahead of the three entries
// every NFSv4 object carries. ACL_READ_DATA is 0x8, and 65534 is nobody.
func deniedNobody() []byte {
	return nfs4ACL(
		nfs4Entry{tagUser, 65534, 0x8, entryDeny, 0},
		nfs4Entry{tagUserObj, undefinedID, 0x1f0bf, entryAllow, 0},
		nfs4Entry{tagGroupObj, undefinedID, 0x12089, entryAllow, 0},
		nfs4Entry{tagEveryone, undefinedID, 0x12089, entryAllow, 0},
	)
}

// ZFS answers fpathconf(_PC_ACL_NFS4) with 1 and _PC_ACL_EXTENDED with 0, and
// refuses ACL_TYPE_ACCESS with the EINVAL a filesystem with no ACL gives.
// Asking for ACL_TYPE_ACCESS alone and reading the refusal as "no ACL" landed
// every replaced ZFS object without the deny entries it carried.
func TestACLTypeForAsksTheFilesystemWhichACLItKeeps(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		fs            string
		nfs4, posix1e int
		want          uint32
	}{
		{"ZFS, and UFS mounted -o nfsv4acls", 1, 0, aclTypeNFS4},
		{"UFS mounted -o acls", 0, 1, aclTypeAccess},
		{"a filesystem with no ACL", 0, 0, 0},
	} {
		got, err := aclTypeFor(c.nfs4, c.posix1e)
		if err != nil || got != c.want {
			t.Errorf("%s: aclTypeFor(%d, %d) = %s (%v), want %s", c.fs, c.nfs4, c.posix1e, aclTypeName(got), err, aclTypeName(c.want))
		}
	}
	if _, err := aclTypeFor(1, 1); err == nil {
		t.Error("a filesystem claiming both types was given one of them")
	}
}

func TestTaggedACLCarriesItsTypeAndItsEntries(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name    string
		aclType uint32
		acl     []byte
	}{
		{"NFSv4 with a deny entry", aclTypeNFS4, deniedNobody()},
		{"POSIX.1e", aclTypeAccess, minimalACL(0o640)},
	} {
		gotType, got, err := untagACL(tagACL(c.aclType, c.acl))
		if err != nil {
			t.Fatalf("%s: untagACL: %v", c.name, err)
		}
		if gotType != c.aclType || !bytes.Equal(got, c.acl) {
			t.Errorf("%s: round trip gave a %s ACL of %d bytes, want %s and the %d bytes it was given",
				c.name, aclTypeName(gotType), len(got), aclTypeName(c.aclType), len(c.acl))
		}
	}
	if _, _, err := untagACL([]byte{4, 0}); err == nil {
		t.Error("untagACL accepted a blob too short to name its type")
	}
}

// The two layouts share one struct, so a blob handed to the kernel under the
// other type is either refused with the EINVAL a filesystem without ACLs gives
// or read as an ACL nobody wrote.
func TestCheckStructACLHoldsEachLayoutToItsOwnType(t *testing.T) {
	t.Parallel()
	if err := checkStructACL(aclTypeAccess, deniedNobody()); err == nil {
		t.Error("an NFSv4 ACL naming everyone@ was accepted as POSIX.1e")
	}
	if err := checkStructACL(aclTypeNFS4, minimalACL(0o644)); err == nil {
		t.Error("a POSIX.1e ACL naming other, with no allow or deny, was accepted as NFSv4")
	}
	if err := checkStructACL(aclTypeNFS4, blankACL()); err == nil {
		t.Error("an NFSv4 ACL with no entries was accepted; ZFS refuses one")
	}

	// UFS keeps a POSIX.1e ACL as struct oldacl, 32 entries at most. NFSv4
	// has the whole struct.
	var many []nfs4Entry
	for i := range posix1eMaxEntries + 1 {
		many = append(many, nfs4Entry{tagUser, uint32(1000 + i), 0x8, entryDeny, 0}) //nolint:gosec // G115: small.
	}
	if err := checkStructACL(aclTypeNFS4, nfs4ACL(many...)); err != nil {
		t.Errorf("an NFSv4 ACL of %d entries was refused: %v", len(many), err)
	}
	longPOSIX := minimalACL(0o644)
	binary.NativeEndian.PutUint32(longPOSIX[4:8], posix1eMaxEntries+1)
	if err := checkStructACL(aclTypeAccess, longPOSIX); err == nil {
		t.Errorf("a POSIX.1e ACL of %d entries was accepted", posix1eMaxEntries+1)
	}
}
