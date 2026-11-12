package storage

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	gstorage "cloud.google.com/go/storage"
	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"google.golang.org/api/option"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/gcs/gcstest"
	bos3 "github.com/ravinald/bodega/internal/s3"
)

// fakeGCS is a gcs store on a fresh bucket of an in-process fake, driven
// through the real SDK client.
func fakeGCS(t *testing.T) (*GCS, *gcstest.Server, string) {
	t.Helper()
	srv := gcstest.New(t)
	var raw [6]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	bucket := "bodega-fake-" + hex.EncodeToString(raw[:])
	srv.AddBucket(bucket)
	return NewGCS(srv.Client(t), bucket), srv, bucket
}

// TestGCSDriverKeepsTheContractOffline runs every conformance case against
// the gcs driver with no credentials, so the wrapper is held to the contract
// on every run and not only when a live bucket is reachable. The fake stands
// in for the service's own guarantees; the live suite is what proves those.
func TestGCSDriverKeepsTheContractOffline(t *testing.T) {
	if !slices.Contains(Drivers(), "gcs") {
		t.Fatalf("gcs is not a registered driver: %v", Drivers())
	}
	testObjectStore(t, func(t *testing.T) ObjectStore {
		s, _, _ := fakeGCS(t)
		return s
	})
}

func uploadsOf(srv *gcstest.Server) []string {
	var out []string
	for _, r := range srv.Requests() {
		if strings.HasPrefix(r, "POST /upload/") {
			out = append(out, r)
		}
	}
	return out
}

// TestGCSWritesCarryAGenerationPrecondition pins how a write is made
// conditional: absent means "must not exist", present means "must still be
// the generation this write read".
func TestGCSWritesCarryAGenerationPrecondition(t *testing.T) {
	s, srv, _ := fakeGCS(t)
	ctx := t.Context()
	if err := s.Put(ctx, "k", []byte("one")); err != nil {
		t.Fatal(err)
	}
	info, err := s.Head(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(t.TempDir(), "two")
	if err := os.WriteFile(local, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.PutFile(ctx, local, "k"); err != nil {
		t.Fatal(err)
	}
	ups := uploadsOf(srv)
	if len(ups) != 2 {
		t.Fatalf("saw %d uploads, want 2: %v", len(ups), ups)
	}
	if !strings.Contains(ups[0], "ifGenerationMatch=0") {
		t.Errorf("a write to an absent key carried no must-not-exist precondition: %s", ups[0])
	}
	if !strings.Contains(ups[1], "ifGenerationMatch="+info.ETag) {
		t.Errorf("a replacement was not conditional on generation %s: %s", info.ETag, ups[1])
	}
}

// TestGCSPutSurvivesALostRace: a writer landing between the generation read
// and the upload fails the precondition, and Put replaces what that writer
// left rather than failing the caller or applying a stale write blind.
func TestGCSPutSurvivesALostRace(t *testing.T) {
	s, srv, bucket := fakeGCS(t)
	srv.RaceNext(bucket, "k", 2)
	if err := s.Put(t.Context(), "k", []byte("mine")); err != nil {
		t.Fatalf("Put after two lost races: %v", err)
	}
	if got, _ := srv.Object(bucket, "k"); string(got) != "mine" {
		t.Errorf("key holds %q, want the write that returned nil", got)
	}

	srv.RaceNext(bucket, "k", publishAttempts)
	err := s.Put(t.Context(), "k", []byte("never"))
	if err == nil || !strings.Contains(err.Error(), "another writer") {
		t.Fatalf("Put that lost every race: err = %v, want a refusal naming the other writer", err)
	}
	if got, _ := srv.Object(bucket, "k"); string(got) != "another writer" {
		t.Errorf("key holds %q after a Put that failed, want the other writer's object", got)
	}
}

// failingReader yields its bytes and then an error in place of io.EOF.
type failingReader struct{ r io.Reader }

func (f *failingReader) Read(p []byte) (int, error) {
	n, err := f.r.Read(p)
	if err == io.EOF {
		return n, errors.New("source went away")
	}
	return n, err
}

// TestGCSInterruptedUploadPublishesNothing holds both upload paths to the
// third promise of the write contract. Closing the SDK's writer finalizes
// what it was given, so a source that dies partway has to cancel instead.
func TestGCSInterruptedUploadPublishesNothing(t *testing.T) {
	for name, chunk := range map[string]int{"single_request": 0, "resumable": 256 << 10} {
		t.Run(name, func(t *testing.T) {
			s, srv, bucket := fakeGCS(t)
			s.chunkSize = chunk
			if err := s.Put(t.Context(), "k", []byte("previous")); err != nil {
				t.Fatal(err)
			}
			partial := bytes.Repeat([]byte("p"), 700<<10)
			err := s.publish(t.Context(), "k", func() (io.ReadCloser, error) {
				return io.NopCloser(&failingReader{bytes.NewReader(partial)}), nil
			})
			if err == nil {
				t.Fatal("an upload whose source failed returned nil")
			}
			if got, _ := srv.Object(bucket, "k"); string(got) != "previous" {
				t.Errorf("key holds %d bytes after an interrupted replacement, want the previous object", len(got))
			}
			err = s.publish(t.Context(), "fresh", func() (io.ReadCloser, error) {
				return io.NopCloser(&failingReader{bytes.NewReader(partial)}), nil
			})
			if err == nil {
				t.Fatal("an upload whose source failed returned nil")
			}
			if _, ok := srv.Object(bucket, "fresh"); ok {
				t.Error("an interrupted upload to a new key published an object")
			}
		})
	}
}

// TestGCSLargeObjectsGoUpInChunks drives the resumable path every artifact
// past the SDK's chunk size takes, which no conformance case is large enough
// to reach.
func TestGCSLargeObjectsGoUpInChunks(t *testing.T) {
	s, srv, _ := fakeGCS(t)
	s.chunkSize = 256 << 10
	body := make([]byte, 700<<10)
	if _, err := rand.Read(body); err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(local, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.PutFile(t.Context(), local, "big.bin"); err != nil {
		t.Fatalf("PutFile: %v", err)
	}
	got, err := s.Get(t.Context(), "big.bin")
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("Get returned %d bytes, %v; want the %d uploaded", len(got), err, len(body))
	}
	if !slices.ContainsFunc(srv.Requests(), func(r string) bool { return strings.Contains(r, "uploadType=resumable") }) {
		t.Error("a body past the chunk size did not take the resumable path")
	}
}

// TestGCSSpecTakesBucketAndPrefixOnly: the driver reads bucket and prefix. A
// key only s3 reads is refused rather than ignored, and no key of either
// config shape names a credential, because credentials are Application
// Default Credentials and nothing else.
func TestGCSSpecTakesBucketAndPrefixOnly(t *testing.T) {
	ctx := context.Background()
	if _, err := NewFromSpec(ctx, Spec{Driver: "gcs"}); err == nil || !strings.Contains(err.Error(), "requires a bucket") {
		t.Errorf("no bucket: err = %v, want a refusal naming the bucket", err)
	}
	for _, spec := range []Spec{
		{Driver: "gcs", Bucket: "b", Endpoint: "https://storage.example.net"},
		{Driver: "gcs", Bucket: "b", PathStyle: true},
		{Driver: "gcs", Bucket: "b", Checksums: "when_required"},
	} {
		if _, err := NewFromSpec(ctx, spec); err == nil || !strings.Contains(err.Error(), "only the s3 driver reads") {
			t.Errorf("%+v: err = %v, want a refusal of the s3-only key", spec, err)
		}
	}

	for _, typ := range []reflect.Type{reflect.TypeFor[Spec](), reflect.TypeFor[config.StorageSpec]()} {
		for i := range typ.NumField() {
			name := strings.ToLower(typ.Field(i).Name + " " + typ.Field(i).Tag.Get("json"))
			for _, word := range []string{"credential", "keyfile", "key_file", "secret", "token", "serviceaccount", "service_account"} {
				if strings.Contains(name, word) {
					t.Errorf("%s.%s reads as a credential setting; the gcs driver takes Application Default Credentials only", typ.Name(), typ.Field(i).Name)
				}
			}
		}
	}
}

func TestGCSLabelCarriesThePrefix(t *testing.T) {
	s, _, bucket := fakeGCS(t)
	if got, want := s.Label(), "gs://"+bucket; got != want {
		t.Errorf("Label() = %q, want %q", got, want)
	}
	if got, want := withPrefix(s, "cold/x").Label(), "gs://"+bucket+"/cold/x"; got != want {
		t.Errorf("prefixed Label() = %q, want %q", got, want)
	}
}

// TestSameLocationGCSAndItsS3Aliases: a gcs backend and an s3 backend on
// Cloud Storage's S3-compatible endpoint are one location when they name one
// bucket and prefix, by every host and addressing form that reaches it and in
// both directions, and two locations otherwise. No request is sent.
func TestSameLocationGCSAndItsS3Aliases(t *testing.T) {
	const bucket = "example-artifacts"
	native := func(t *testing.T, emulator, bucket, prefix string) ObjectStore {
		t.Helper()
		t.Setenv("STORAGE_EMULATOR_HOST", emulator)
		client, err := gstorage.NewClient(t.Context(), option.WithoutAuthentication())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		return withPrefix(NewGCS(client, bucket), prefix)
	}
	s3 := func(endpoint, bucket, prefix string, pathStyle bool) ObjectStore {
		client := bos3.NewClientFromConfig(aws.Config{Region: "us-east-1", Credentials: aws.AnonymousCredentials{}},
			bucket, "us-east-1", func(o *awss3.Options) {
				if endpoint != "" {
					o.BaseEndpoint = aws.String(endpoint)
				}
				o.UsePathStyle = pathStyle
			})
		return withPrefix(NewS3(client), prefix)
	}
	for _, tc := range []struct {
		name     string
		emulator string
		gcs      [2]string // bucket, prefix
		s3       ObjectStore
		want     bool
	}{
		{"path-style", "", [2]string{bucket, ""}, s3("https://storage.googleapis.com", bucket, "", true), true},
		{"virtual-hosted", "", [2]string{bucket, ""}, s3("https://storage.googleapis.com", bucket, "", false), true},
		{"plain http", "", [2]string{bucket, ""}, s3("http://storage.googleapis.com:80/", bucket, "", true), true},
		{"mTLS host", "", [2]string{bucket, ""}, s3("https://storage.mtls.googleapis.com", bucket, "", true), true},
		{"regional endpoint", "", [2]string{bucket, ""}, s3("https://storage.us-central1.rep.googleapis.com", bucket, "", true), true},
		{"same prefix", "", [2]string{bucket, "cold"}, s3("https://storage.googleapis.com", bucket, "cold/", false), true},
		{"bucket in the endpoint path", "", [2]string{bucket, "cold"}, s3("https://storage.googleapis.com/"+bucket, "cold", "", true), true},
		{"prefix on one side only", "", [2]string{bucket, "cold"}, s3("https://storage.googleapis.com", bucket, "", true), false},
		{"different prefixes", "", [2]string{bucket, "cold"}, s3("https://storage.googleapis.com", bucket, "warm", true), false},
		{"different buckets", "", [2]string{bucket, ""}, s3("https://storage.googleapis.com", "example-other", "", true), false},
		{"bucket that only starts alike", "", [2]string{bucket, ""}, s3("https://storage.googleapis.com", bucket+"-2", "", false), false},
		{"the same name on AWS", "", [2]string{bucket, ""}, s3("", bucket, "", false), false},
		{"another host", "", [2]string{bucket, ""}, s3("https://storage.example.com", bucket, "", true), false},
		{"emulator and a path-style s3 client on it", "127.0.0.1:4443", [2]string{bucket, "cold"}, s3("http://127.0.0.1:4443", bucket, "cold", true), true},
		{"emulator named with a scheme and a path", "http://LOCALHOST:4443/ignored", [2]string{bucket, ""}, s3("http://localhost:4443", bucket, "", true), true},
		{"emulator is not Cloud Storage", "127.0.0.1:4443", [2]string{bucket, ""}, s3("https://storage.googleapis.com", bucket, "", true), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := native(t, tc.emulator, tc.gcs[0], tc.gcs[1])
			if got := SameLocation(g, tc.s3); got != tc.want {
				gr, _ := objectRoute(g)
				sr, _ := objectRoute(tc.s3)
				t.Errorf("SameLocation(gcs, s3) = %v, want %v (routes %q and %q)", got, tc.want, gr, sr)
			}
			if got := SameLocation(tc.s3, g); got != tc.want {
				t.Errorf("SameLocation(s3, gcs) = %v, want %v", got, tc.want)
			}
			if g.Label() == tc.s3.Label() {
				t.Errorf("the two share the label %q; they are separate identities to the fan-out", g.Label())
			}
		})
	}

	// Two s3 spellings of one Cloud Storage bucket are one location too, and
	// two gcs stores are told apart by prefix as any two stores are.
	if !SameLocation(s3("https://storage.googleapis.com", bucket, "", true), s3("https://storage.mtls.googleapis.com", bucket, "", true)) {
		t.Error("two Cloud Storage hosts for one bucket are two locations to a move")
	}
	if SameLocation(native(t, "", bucket, ""), native(t, "", bucket, "cold")) {
		t.Error("a bucket and a prefix of it are one location to a move")
	}
}

// TestGCSRouteIsWhereTheSDKSendsARead holds gcsRouteRoot to the client it
// stands in for: the SDK is asked for an object through each spelling of
// STORAGE_EMULATOR_HOST, and the request has to arrive at the URL the store's
// route names.
func TestGCSRouteIsWhereTheSDKSendsARead(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, "http://"+r.Host+r.URL.Path)
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	for _, emulator := range []string{host, srv.URL, srv.URL + "/ignored"} {
		got = nil
		t.Setenv("STORAGE_EMULATOR_HOST", emulator)
		client, err := gstorage.NewClient(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		store := withPrefix(NewGCS(client, "example-artifacts"), "cold")
		if _, err := store.Get(t.Context(), "key"); err != nil {
			t.Fatalf("%s: %v", emulator, err)
		}
		_ = client.Close()
		route, _ := objectRoute(store)
		if len(got) != 1 || got[0] != route+"key" {
			t.Errorf("STORAGE_EMULATOR_HOST=%s: the SDK asked %q, and the route says %q", emulator, got, route+"key")
		}
	}
}
