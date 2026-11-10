package storage

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/url"
	"strings"

	bos3 "github.com/ravinald/bodega/internal/s3"
)

func init() {
	Register("s3", newS3FromSpec)
}

func newS3FromSpec(ctx context.Context, spec Spec) (ObjectStore, error) {
	if spec.Bucket == "" {
		return nil, fmt.Errorf("s3 backend requires a bucket (set bucket in config or REPO_BUCKET env)")
	}
	client, err := bos3.NewClient(ctx, spec.Bucket, spec.Region, spec.S3Options())
	if err != nil {
		return nil, fmt.Errorf("create S3 client: %w", err)
	}
	return &S3{client: client}, nil
}

// S3 adapts the existing internal/s3.Client to the ObjectStore interface.
//
// Write contract (ObjectStore.Put). S3 keeps the first three, per object, and
// they are the service's documented behavior before they are anything the
// conformance suite observes: a PUT is atomic, so a reader gets the previous
// object or the new one; a GET already in flight is served from the version it
// opened, so an open handle is a snapshot. An interrupted upload publishes
// nothing. A multipart upload that dies partway leaves uploaded parts behind,
// which are billed and are not an object: they never appear in List and
// nothing serves them. This package does not abort them; the lifecycle rule
// InitBucket sets on the bucket root does, after
// bos3.AbortIncompleteMultipartDays. A bucket bodega did not initialize has no
// such rule unless its owner added one.
//
// Durability is the bucket's. PutBytes and UploadFile return when S3
// acknowledges the object, which is a stronger promise than Local's and is
// still not one this package makes; it is a property of the service, and a
// caller may not assume it of an ObjectStore.
//
// The fourth it keeps vacuously, and the difference from Local is worth
// reading before an artifact is restricted. S3 carries no per-object access
// state this backend reads or writes: no mode, no owner, no ACL. So a refill
// has nothing to restate and nothing to widen, which is why no conformance
// case can fail on it here, and equally, an object ACL or a
// bucket policy applied outside bodega is not something a refill preserves:
// the next write is a plain PUT. An artifact whose restriction has to survive
// refills belongs on a local backend, which placement can arrange per package.
type S3 struct {
	client *bos3.Client
}

// NewS3 wraps an existing S3 client as an ObjectStore.
func NewS3(client *bos3.Client) *S3 {
	return &S3{client: client}
}

// Client returns the underlying S3 client for operations that need direct
// access (e.g. InitBucket, status checks).
func (s *S3) Client() *bos3.Client {
	return s.client
}

// S3 enforces ValidateKey on the same methods Local and Memory do. S3 itself
// would happily store a key with ".." in it; the contract is uniform on
// purpose, because a key is derived once and handed to whichever backend the
// version records, and a driver that accepted more than its siblings would
// make placement decide whether an artifact is reachable.
func (s *S3) Get(ctx context.Context, key string) ([]byte, error) {
	if err := ValidateKey(key); err != nil {
		return nil, err
	}
	return s.client.GetObject(ctx, key)
}

func (s *S3) GetStream(ctx context.Context, key string) (*StreamResult, error) {
	if err := ValidateKey(key); err != nil {
		return nil, err
	}
	r, err := s.client.GetObjectStream(ctx, key)
	if err != nil || r == nil {
		return nil, err
	}
	return &StreamResult{
		Body:          r.Body,
		ContentLength: r.ContentLength,
		ETag:          r.ETag,
		ContentType:   r.ContentType,
		LastModified:  r.LastModified,
	}, nil
}

func (s *S3) Head(ctx context.Context, key string) (*ObjectInfo, error) {
	if err := ValidateKey(key); err != nil {
		return nil, err
	}
	st, err := s.client.HeadObject(ctx, key)
	if err != nil {
		return nil, err
	}
	return &ObjectInfo{
		Key:          st.Key,
		Exists:       st.Exists,
		Size:         st.Size,
		LastModified: st.LastModified,
		ETag:         st.ETag,
	}, nil
}

func (s *S3) List(ctx context.Context, prefix string) ([]string, error) {
	if err := ValidateKey(prefix); err != nil {
		return nil, err
	}
	return s.client.ListPrefix(ctx, prefix)
}

func (s *S3) Put(ctx context.Context, key string, data []byte) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	return s.client.PutBytes(ctx, key, data)
}

func (s *S3) PutFile(ctx context.Context, localPath, key string) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	return s.client.UploadFile(ctx, localPath, key)
}

func (s *S3) Delete(ctx context.Context, key string) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	return s.client.DeleteObject(ctx, key)
}

func (s *S3) SyncDir(ctx context.Context, out io.Writer, localDir, keyPrefix string) (int, error) {
	return s.client.SyncDir(ctx, out, localDir, keyPrefix)
}

// Label is "s3://<bucket>" on AWS and "s3+<endpoint>/<bucket>" on a store
// reached through an endpoint, because a bucket name is unique only within
// one service: two MinIO instances can each hold "artifacts", and a label
// that said only the bucket made them one location, so the fan-out dropped
// one and 'pkg move' refused a real copy as a copy onto itself.
//
// The region stays out of it. An AWS bucket name is global, so two entries
// naming one bucket under different regions are one location.
func (s *S3) Label() string {
	ns := endpointNamespace(s.client.Endpoint())
	if ns == "" {
		return s3BucketScheme + s.client.Bucket()
	}
	return "s3+" + ns + "/" + s.client.Bucket()
}

const s3BucketScheme = "s3://"

// endpointNamespace reduces an endpoint to the part that says which service
// it is, so two spellings of one endpoint are one namespace: the scheme, the
// host in lower case with no trailing dot, the port unless it is the scheme's
// default, and the path with no trailing slash. Addressing style and
// checksums are how a client talks to the store, not where it is.
//
// Userinfo, a query and a fragment are dropped, and an endpoint that does not
// parse is named by a digest instead of its text. Config load refuses all of
// those, but an endpoint the SDK read from the environment was never checked,
// and a label is printed in logs and errors.
func endpointNamespace(endpoint string) string {
	if endpoint == "" {
		return ""
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return fmt.Sprintf("endpoint-%x", sha256.Sum256([]byte(endpoint)))[:21]
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	return u.Scheme + "://" + host + strings.TrimRight(u.EscapedPath(), "/")
}

// S3BucketLabel returns an s3 store's location as "s3://<bucket>" or
// "s3://<bucket>/<prefix>", with no endpoint, and false for a store on
// another driver. It is the form an s3:// URI written outside bodega takes,
// which has nowhere to name an endpoint, so it is what such a URI is matched
// against; Label is the identity and is not interchangeable with it.
func S3BucketLabel(store ObjectStore) (string, bool) {
	switch s := store.(type) {
	case *S3:
		return s3BucketScheme + s.client.Bucket(), true
	case *prefixed:
		inner, ok := S3BucketLabel(s.inner)
		if !ok {
			return "", false
		}
		return joinLabel(inner, s.prefix), true
	}
	return "", false
}
