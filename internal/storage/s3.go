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
// "s3+<scheme>://<host>[/<path>]" on any other store.
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
// It is derived from the route the pinned SDK resolves, never from the
// configured strings. One object namespace has many spellings in a config
// file (an encoded endpoint path, or a path segment moved between endpoint,
// bucket and prefix under path-style addressing), the SDK sends all of them to
// one URL, and 'pkg move --delete-source' between two names for one URL
// deletes the only copy. So two stores whose requests for a key reach one URL
// are one location.
//
// One equivalence is added to the SDK's: a name the SDK addresses as
// <name>.<host> is the same place as <host>/<name>, which is how every S3
// service reads the two addressing styles, and what makes path_style a
// setting of the client and not part of where the store is. Taken with the
// first rule it cannot stop at the bucket. "https://b.gw" with path-style
// bucket "x" and "https://gw" with bucket "b" under prefix "x" send one URL,
// and the first is "https://b.gw" with bucket "x" either way, so a leading
// path segment the SDK would address as a host label is one wherever the
// configuration put it. The location is that normal form: every such leading
// segment in the host, the rest as the path.
//
// AWS is the exception, because its hosts are known: whatever precedes one of
// them is a bucket name, dots included, and the region, the partition and the
// FIPS, dual-stack and accelerate variants all reach one global namespace. An
// AWS location is the bucket and the path under it, with no host.
//
// What this cannot equate is two hostnames for one compatible service (a DNS
// name and its address, a CNAME): nothing short of a request tells them
// apart from two services, and they are kept apart.
type s3Location struct {
	aws bool
	// root is "<scheme>://<host>[:<port>]" for a compatible store, or
	// "unresolved-<digest>" where the SDK resolves no route at all. Empty on
	// AWS.
	root string
	// segs are the percent-decoded path segments below root, and on AWS the
	// bucket then the segments below it.
	segs []string
	// tail is the start of the segment a key continues. It is empty for every
	// store built from configuration, whose prefix ends at a "/".
	tail string
}

// s3LocationOf is the location of an s3 store or of prefixes over one, and
// false for any other store.
func s3LocationOf(store ObjectStore) (s3Location, bool) {
	var prefix string
	for {
		switch s := store.(type) {
		case *prefixed:
			prefix, store = s.prefix+prefix, s.inner
		case *S3:
			return s.location(prefix), true
		default:
			return s3Location{}, false
		}
	}
}

// location is the one place an s3 identity is built: the SDK's route for the
// bucket, the key prefix appended as the SDK appends a key, then the normal
// form s3Location describes.
func (s *S3) location(prefix string) s3Location {
	ctx := context.Background()
	bucket := s.client.Bucket()
	route, err := s.client.Route(ctx)
	if err != nil {
		// No request for this store resolves, so there is no URL to share
		// with another. A digest keeps the endpoint's text, which nothing
		// validated when the SDK read it from the environment, out of logs.
		sum := sha256.Sum256([]byte(route.Endpoint + "\x00" + bucket))
		loc := s3Location{root: fmt.Sprintf("unresolved-%x", sum[:8])}
		loc.segs, loc.tail = splitKeyPath(prefix)
		return loc
	}
	u := route.URL
	hostname := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	// smithy's JoinPath, which is how the SDK puts a key under the route.
	path := u.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	segs, tail := splitKeyPath(path[1:] + prefix)

	if route.Endpoint == "" {
		// The SDK derived the host, so it is AWS's whether or not
		// awsS3Endpoint knows the partition.
		under, known := awsBucketHost(hostname)
		switch {
		case known:
		case len(segs) > 0 && segs[0] == bucket:
		case strings.HasPrefix(hostname, bucket+"."):
			under = bucket
		}
		if under != "" {
			segs = append([]string{under}, segs...)
		}
		if len(segs) > 0 && segs[0] != "" {
			return s3Location{aws: true, segs: segs, tail: tail}
		}
	}
	for {
		if under, ok := awsBucketHost(hostname); ok && port == "" && route.Endpoint != "" {
			all := segs
			if under != "" {
				all = append([]string{under}, segs...)
			}
			if len(all) > 0 && all[0] != "" {
				return s3Location{aws: true, segs: all, tail: tail}
			}
		}
		if len(segs) == 0 || !virtualHosted(ctx, s.client.Region(), u.Scheme, hostPort(hostname, port), segs[0]) {
			break
		}
		hostname, segs = segs[0]+"."+hostname, segs[1:]
	}
	return s3Location{root: u.Scheme + "://" + hostPort(hostname, port), segs: segs, tail: tail}
}

// splitKeyPath splits the path a key is appended to into its complete
// segments and the start of the segment the key continues. Nothing is cleaned:
// "a//b" and "a/b" are two prefixes of one bucket.
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

// awsBucketHost reports whether host is one AWS serves the S3 API on, alone
// or behind a bucket name, and returns that name.
func awsBucketHost(host string) (bucket string, ok bool) {
	for i := 0; ; {
		if awsS3Endpoint.MatchString(host[i:]) {
			return strings.TrimSuffix(host[:i], "."), true
		}
		dot := strings.IndexByte(host[i:], '.')
		if dot < 0 {
			return "", false
		}
		i += dot + 1
	}
}

// virtualHosted asks the SDK whether it addresses name on host as
// <name>.<host>. Its rules decide (a name's length and characters, a host
// that is an address), so the normal form moves a segment exactly where a
// configuration could have.
func virtualHosted(ctx context.Context, region, scheme, host, name string) bool {
	route, err := bos3.ResolveRoute(ctx, region, scheme+"://"+host, name, false)
	return err == nil && route.URL.Host == name+"."+host
}

// label serializes the location so that two labels are equal exactly when
// two locations are: each segment is escaped, so a "/" separates segments and
// nothing else, and a tail is marked with a "*" no escaped segment holds.
func (l s3Location) label() string {
	if l.aws {
		return s3BucketScheme + l.path()
	}
	if p := l.path(); p != "" || len(l.segs) > 0 {
		return "s3+" + l.root + "/" + p
	}
	return "s3+" + l.root
}

func (l s3Location) path() string {
	escaped := make([]string, 0, len(l.segs)+1)
	for _, seg := range l.segs {
		escaped = append(escaped, url.PathEscape(seg))
	}
	if l.tail != "" {
		escaped = append(escaped, url.PathEscape(l.tail)+"*")
	}
	return strings.Join(escaped, "/")
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
