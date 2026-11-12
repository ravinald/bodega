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

// Label is the store's location (see s3Location): "s3://<bucket>" on AWS and
// "s3+<scheme>://<host>/[<path>|]<bucket>" on any other store.
func (s *S3) Label() string {
	return s.location("").label()
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

// s3Location is where an s3 store's keys land, and the one identity every
// consumer compares: the fan-out's dedup and both 'pkg move' guards through
// Label, and a cache-origin record through S3RecordLabel.
//
// It is the three things the store was configured with, each kept whole: the
// endpoint, the bucket and the key prefix. Nothing moves between them. A
// bucket with a dot in it is not a bucket under a prefix, an endpoint path is
// not a subdomain, and an access-point ARN stays the ARN whatever prefix
// follows it, because only the service knows where its own boundaries are and
// the route a request takes does not say: path-style
// "https://gw/tenant" + "artifacts" and "https://gw" + "tenant" under prefix
// "artifacts" send one URL, and so do a dotted bucket and a bucket plus prefix
// on a virtual-hosted store that are two buckets.
//
// Two spellings of one component are one location: the endpoint's case,
// default port, trailing slash and percent-encoding, and any of AWS's own
// hosts for AWS. The addressing style is no component at all. path_style
// chooses how the client writes the bucket into a request for the same
// endpoint and bucket.
//
// Two configurations with different components can still reach one object.
// They are two locations here, which costs a fan-out a duplicate listing and
// lets either read the other's cache origin for bytes they share. What it may
// not cost is the object, so a move asks SameLocation, which also compares
// the routes.
type s3Location struct {
	aws bool
	// root is "<scheme>://<host>[:<port>]/", then the endpoint's path as
	// escaped segments closed by a "|" when it has one. An endpoint that does
	// not parse is "unresolved-<digest>/". Empty on AWS.
	root   string
	bucket string
	// segs are the complete segments of the key prefix.
	segs []string
	// tail is the start of the segment a key continues. It is empty for every
	// store built from configuration, whose prefix ends at a "/".
	tail string
}

// unwrapPrefixes returns the store under any prefixes and the prefix they
// compose to.
func unwrapPrefixes(store ObjectStore) (inner ObjectStore, prefix string) {
	for {
		p, ok := store.(*prefixed)
		if !ok {
			return store, prefix
		}
		prefix, store = p.prefix+prefix, p.inner
	}
}

// s3Under unwraps prefixes down to the s3 store they are over, and reports
// false for any other store.
func s3Under(store ObjectStore) (s3 *S3, prefix string, ok bool) {
	inner, prefix := unwrapPrefixes(store)
	s3, ok = inner.(*S3)
	return s3, prefix, ok
}

// s3LocationOf is the location of an s3 store or of prefixes over one, and
// false for any other store.
func s3LocationOf(store ObjectStore) (s3Location, bool) {
	s, prefix, ok := s3Under(store)
	if !ok {
		return s3Location{}, false
	}
	return s.location(prefix), true
}

// location is the one place an s3 identity is built.
func (s *S3) location(prefix string) s3Location {
	loc := s3Location{bucket: s.client.Bucket()}
	loc.aws, loc.root = endpointRoot(s.client.Endpoint())
	loc.segs, loc.tail = splitKeyPath(prefix)
	return loc
}

// endpointRoot normalizes the endpoint a client dials, whether the endpoint
// key supplied it or the SDK read it from the environment, and reports AWS
// for no endpoint and for any of AWS's own hosts.
//
// The path is the decoded one, opened and closed by a "/" as the SDK's rules
// normalize it, so "/a/b", "/a/b/" and "/a%2Fb" are one root and "/a//" is
// another. Userinfo and a query are dropped: neither is part of where the
// store is, and a label is printed.
func endpointRoot(endpoint string) (aws bool, root string) {
	if endpoint == "" {
		return true, ""
	}
	u, hostname, ok := parseEndpoint(endpoint)
	if !ok {
		// Nothing validated this text when the SDK read it from the
		// environment, so a digest keeps it out of logs.
		sum := sha256.Sum256([]byte(endpoint))
		return false, fmt.Sprintf("unresolved-%x/", sum[:8])
	}
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	path := u.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	root = u.Scheme + "://" + hostPort(hostname, port) + "/"
	if path == "/" {
		return port == "" && awsS3Endpoint.MatchString(hostname), root
	}
	segs := strings.Split(path[1:len(path)-1], "/")
	for i, seg := range segs {
		segs[i] = url.PathEscape(seg)
	}
	return false, root + strings.Join(segs, "/") + "|"
}

// parseEndpoint reads an endpoint as an http or https URL with a hostname,
// which it returns lowercased and without a trailing dot.
func parseEndpoint(endpoint string) (u *url.URL, hostname string, ok bool) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, "", false
	}
	u.Scheme = strings.ToLower(u.Scheme)
	hostname = strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if (u.Scheme != "http" && u.Scheme != "https") || hostname == "" || strings.ContainsAny(hostname, "/|* ") {
		return nil, "", false
	}
	return u, hostname, true
}

// splitKeyPath splits a key prefix into its complete segments and the start
// of the segment the key continues. Nothing is cleaned: "a//b" and "a/b" are
// two prefixes of one bucket.
func splitKeyPath(p string) (segs []string, tail string) {
	segs = strings.Split(p, "/")
	return segs[:len(segs)-1], segs[len(segs)-1]
}

func hostPort(hostname, port string) string {
	if strings.Contains(hostname, ":") {
		hostname = "[" + hostname + "]"
	}
	if port != "" {
		return hostname + ":" + port
	}
	return hostname
}

// label serializes the location so that two labels are equal exactly when
// two locations are. Every component is escaped, so a "/" separates
// components and prefix segments and nothing else, the "|" closing an
// endpoint path and the "*" marking a tail are bytes no escaped component
// holds, and a "/" inside a bucket (an access-point ARN has one) is "%2F".
func (l s3Location) label() string {
	if l.aws {
		return s3BucketScheme + l.path()
	}
	return "s3+" + l.root + l.path()
}

// path is the bucket and the prefix under it.
func (l s3Location) path() string {
	escaped := make([]string, 0, len(l.segs)+2)
	escaped = append(escaped, url.PathEscape(l.bucket))
	for _, seg := range l.segs {
		escaped = append(escaped, url.PathEscape(seg))
	}
	if l.tail != "" {
		escaped = append(escaped, url.PathEscape(l.tail)+"*")
	}
	return strings.Join(escaped, "/")
}

// SameLocation reports whether writing a key to one store overwrites that key
// in the other. It is what a move asks before it copies or deletes anything,
// and it is wider than the identity: two stores are the same location when
// their labels are equal, and also when the pinned SDKs send a key for each
// to one object. The second holds for s3 configurations whose components
// differ (an endpoint path segment spelled as a bucket under path-style
// addressing, a dotted bucket spelled as a bucket and a prefix), and for a
// gcs backend beside an s3 backend on Cloud Storage's S3-compatible endpoint
// for the same bucket. All of them stay separate identities everywhere else.
// The route only ever refuses here; it never names a store.
func SameLocation(a, b ObjectStore) bool {
	if a.Label() == b.Label() {
		return true
	}
	ra, ok := objectRoute(a)
	if !ok {
		return false
	}
	rb, ok := objectRoute(b)
	return ok && ra == rb
}

// objectRoute is where a key of an s3 or gcs store lands, prefix included,
// in a form two stores share exactly when they share objects. False for
// another driver and for a store its SDK resolves no route for.
func objectRoute(store ObjectStore) (string, bool) {
	inner, prefix := unwrapPrefixes(store)
	if g, ok := inner.(*GCS); ok {
		return g.root + g.name + "/" + prefix, true
	}
	return s3ObjectRoute(store)
}

// s3ObjectRoute is the URL the SDK puts a key under for an s3 store: the
// resolved scheme and host, the decoded path closed by a "/" as the request
// middleware joins it, then the prefix. A URL on Cloud Storage is rewritten
// to the form a gcs store's route has. False for a store the SDK resolves no
// route for, and for another driver.
func s3ObjectRoute(store ObjectStore) (string, bool) {
	s, prefix, ok := s3Under(store)
	if !ok {
		return "", false
	}
	route, err := s.client.Route(context.Background())
	if err != nil {
		return "", false
	}
	u := route.URL
	hostname := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	path := u.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	if port == "" {
		if gcs, ok := cloudStorageRoute(hostname, path+prefix); ok {
			return gcs, true
		}
	}
	return u.Scheme + "://" + hostPort(hostname, port) + path + prefix, true
}

// cloudStorageRoot opens the route of every object in Cloud Storage's one
// global bucket namespace, whichever host and scheme a request reaches it by.
const cloudStorageRoot = "gs://"

// cloudStorageHost matches the hosts Cloud Storage serves its XML API on with
// the bucket as the first path segment: the global host, the mTLS host the
// pinned Go SDK names beside it (WithDefaultMTLSEndpoint in storage.NewClient)
// and a regional endpoint. The XML API is the one an s3 client speaks to it.
var cloudStorageHost = regexp.MustCompile(`^storage(?:\.mtls|\.[a-z0-9-]+\.rep)?\.googleapis\.com$`)

// cloudStorageRoute rewrites an XML API URL as cloudStorageRoot, the bucket
// and the key prefix. objectPath is the URL's path with the prefix appended.
// A bucket name holds no "/", so on a path-style host the first segment is
// the bucket however the s3 configuration divided endpoint path, bucket and
// prefix; on the virtual-hosted form the bucket is the host's own label.
func cloudStorageRoute(hostname, objectPath string) (string, bool) {
	if bucket, ok := strings.CutSuffix(hostname, ".storage.googleapis.com"); ok && bucket != "" {
		return cloudStorageRoot + bucket + objectPath, true
	}
	if rest := strings.TrimPrefix(objectPath, "/"); cloudStorageHost.MatchString(hostname) && rest != "" && rest[0] != '/' {
		return cloudStorageRoot + rest, true
	}
	return "", false
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

// S3RecordLabel is the location a record about an object is written under.
// It is Label for every store but an s3 one on AWS, whose Label is
// "s3://<bucket>": that is also what every s3 store's label was before a
// label carried an endpoint, so a row saying only that cannot tell an AWS
// bucket recorded today from a compatible store's bucket recorded then.
// Naming AWS here ("s3+aws://<bucket>") leaves the bare spelling to mean one
// thing, a row from before, which a reader has to resolve against every
// configured store instead of matching by text. No other label opens that
// way: a compatible store's root is "http://", "https://" or "unresolved-".
func S3RecordLabel(store ObjectStore) string {
	loc, ok := s3LocationOf(store)
	if !ok {
		return store.Label()
	}
	if loc.aws {
		return "s3+aws://" + loc.path()
	}
	return loc.label()
}
