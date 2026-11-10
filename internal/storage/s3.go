package storage

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/url"
	"regexp"
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

// Label is "s3://<bucket>" on AWS and "s3+<endpoint>#<bucket>" on any other
// store reached through an endpoint, because a bucket name is unique only
// within one service: two MinIO instances can each hold "artifacts", and a
// label that said only the bucket made them one location, so the fan-out
// dropped one and 'pkg move' refused a real copy as a copy onto itself.
//
// The split is by which service answers, not by whether an endpoint was
// written down. An endpoint naming AWS's own S3 service is the bucket the SDK
// reaches with no endpoint at all, and 'pkg move --delete-source' between two
// labels for one bucket deletes the only copy, so those collapse to the AWS
// form (see awsS3Endpoint).
//
// The region stays out of it. An AWS bucket name is global, so two entries
// naming one bucket under different regions are one location.
//
// What this cannot equate is two hostnames for one compatible service (a DNS
// name and its address, a CNAME): nothing short of a request tells them
// apart from two services, and they are kept apart.
//
// The label, and a prefixed store's label over it, decodes to one (endpoint,
// bucket, prefix): a namespace holds no "#" (see endpointNamespace), so the
// first one ends it; the bucket is escaped (see bucketSegment), so the first
// "/" after it starts the prefix. A "/" between endpoint and bucket instead
// gave the endpoint "https://gw/tenant" with bucket "artifacts" the label of
// the endpoint "https://gw" with bucket "tenant" and prefix "artifacts".
func (s *S3) Label() string {
	ns := endpointNamespace(s.client.Endpoint())
	if ns == "" {
		return s3BucketScheme + bucketSegment(s.client.Bucket())
	}
	return "s3+" + ns + "#" + bucketSegment(s.client.Bucket())
}

// bucketSegment is a bucket name as one label segment. A name any S3 service
// accepts comes back unchanged. Config load does not check bucket names, and
// one holding "/" would otherwise read as a bucket and a prefix.
func bucketSegment(bucket string) string {
	return url.PathEscape(bucket)
}

const s3BucketScheme = "s3://"

// awsS3Endpoint matches the hosts AWS serves the S3 API on: the global and
// regional endpoints with their dual-stack, FIPS and accelerate variants, the
// dash-region form older regions keep, the China partition's suffix, and an
// interface VPC endpoint. All of them reach the buckets the SDK reaches with
// no endpoint configured.
//
// Partitions are not told apart, which matches a bucket reached with no
// endpoint: the label never carried the region that would say which one.
// Outposts, access-point and control hosts are left out because the name
// they take is not a bucket in that namespace.
var awsS3Endpoint = regexp.MustCompile(`^(?:bucket\.vpce-[a-z0-9-]+\.)?s3(?:-fips|-accelerate)?(?:\.dualstack)?(?:\.[a-z0-9-]+|-[a-z]{2}(?:-[a-z]+)+-\d+)?(?:\.vpce)?\.amazonaws\.com(?:\.cn)?$`)

// endpointNamespace reduces an endpoint to the part that says which service
// it is, and to "" for AWS's own, so two spellings of one endpoint are one
// namespace: the scheme, the
// host in lower case with no trailing dot, the port unless it is the scheme's
// default, and the path with no trailing slash. Addressing style and
// checksums are how a client talks to the store, not where it is.
//
// Userinfo, a query and a fragment are dropped, and an endpoint that does not
// parse, or whose scheme is not http or https, is named by a digest instead
// of its text. So a namespace is "http://...", "https://..." or
// "endpoint-<hex>", holds no "#", and is never awsRecordNamespace. Config
// load refuses all of those, but an endpoint the SDK read from the environment was never checked,
// and a label is printed in logs and errors.
func endpointNamespace(endpoint string) string {
	if endpoint == "" {
		return ""
	}
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
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
	if port == "" && strings.Trim(u.Path, "/") == "" && awsS3Endpoint.MatchString(host) {
		return ""
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

// awsRecordNamespace stands where an endpoint would in the label an AWS
// bucket is recorded under. endpointNamespace never returns a namespace
// opening with it, so it collides with no compatible store's.
const awsRecordNamespace = "aws:/"

// S3RecordLabel is the location a record about an object is written under.
// It is Label for every store but an s3 one on AWS, whose Label is
// "s3://<bucket>": that is also what every s3 store's label was before a
// label carried an endpoint, so a row saying only that cannot tell an AWS
// bucket recorded today from a compatible store's bucket recorded then.
// Naming AWS here ("s3+aws://<bucket>") leaves the bare spelling to mean one
// thing, a row from before, which a reader has to resolve against every
// configured store instead of matching by text.
//
// Label stays the identity that location comparisons use and is not
// interchangeable with this.
func S3RecordLabel(store ObjectStore) string {
	switch s := store.(type) {
	case *S3:
		if endpointNamespace(s.client.Endpoint()) == "" {
			return "s3+" + awsRecordNamespace + "/" + bucketSegment(s.client.Bucket())
		}
	case *prefixed:
		return joinLabel(S3RecordLabel(s.inner), s.prefix)
	}
	return store.Label()
}
