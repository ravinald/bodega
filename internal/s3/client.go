package s3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// ObjectAPI is every SDK call a running bodega makes against its bucket, and
// RuntimePolicy grants exactly what these methods need. Client reaches the
// SDK through nothing else, so a call added to client.go does not compile
// until it is named here, and a method named here fails TestEveryCallMapsToAnAction
// until it maps to an IAM action.
//
// The four multipart methods are manager.UploadAPIClient's, called by the
// uploader above uploadPartSize rather than by this file.
type ObjectAPI interface {
	HeadObject(ctx context.Context, in *awss3.HeadObjectInput, optFns ...func(*awss3.Options)) (*awss3.HeadObjectOutput, error)
	GetObject(ctx context.Context, in *awss3.GetObjectInput, optFns ...func(*awss3.Options)) (*awss3.GetObjectOutput, error)
	PutObject(ctx context.Context, in *awss3.PutObjectInput, optFns ...func(*awss3.Options)) (*awss3.PutObjectOutput, error)
	DeleteObject(ctx context.Context, in *awss3.DeleteObjectInput, optFns ...func(*awss3.Options)) (*awss3.DeleteObjectOutput, error)
	ListObjectsV2(ctx context.Context, in *awss3.ListObjectsV2Input, optFns ...func(*awss3.Options)) (*awss3.ListObjectsV2Output, error)
	CreateMultipartUpload(ctx context.Context, in *awss3.CreateMultipartUploadInput, optFns ...func(*awss3.Options)) (*awss3.CreateMultipartUploadOutput, error)
	UploadPart(ctx context.Context, in *awss3.UploadPartInput, optFns ...func(*awss3.Options)) (*awss3.UploadPartOutput, error)
	CompleteMultipartUpload(ctx context.Context, in *awss3.CompleteMultipartUploadInput, optFns ...func(*awss3.Options)) (*awss3.CompleteMultipartUploadOutput, error)
	AbortMultipartUpload(ctx context.Context, in *awss3.AbortMultipartUploadInput, optFns ...func(*awss3.Options)) (*awss3.AbortMultipartUploadOutput, error)
}

// Client wraps the AWS S3 client with bootstrap-specific helpers.
type Client struct {
	s3     ObjectAPI
	raw    *awss3.Client
	bucket string
	region string
}

// The two values the checksums key takes, which are the SDK's own names for
// them in AWS_REQUEST_CHECKSUM_CALCULATION.
const (
	ChecksumsWhenSupported = "when_supported"
	ChecksumsWhenRequired  = "when_required"
)

// Options are the s3 driver's settings past bucket and region: what a store
// that is not AWS needs. A zero field is not written to the client, so
// whatever the SDK resolved for it from the environment or the shared config
// (AWS_ENDPOINT_URL_S3, AWS_REQUEST_CHECKSUM_CALCULATION and the rest) stands.
type Options struct {
	// Endpoint is the store's base URL.
	Endpoint string
	// PathStyle addresses the bucket as <endpoint>/<bucket> rather than
	// <bucket>.<endpoint>, for a store with no wildcard DNS.
	PathStyle bool
	// Checksums is ChecksumsWhenSupported, ChecksumsWhenRequired or empty. It
	// governs both directions: the CRC32 the SDK adds to a request, which
	// several compatible stores reject, and the validation of one on a
	// response.
	Checksums string
}

// ClientOptions renders o as SDK client options. It is the one place the
// three settings meet the SDK, so the driver and the conformance suite
// configure a client identically.
func (o Options) ClientOptions() ([]func(*awss3.Options), error) {
	var fns []func(*awss3.Options)
	if o.Endpoint != "" {
		fns = append(fns, func(so *awss3.Options) { so.BaseEndpoint = aws.String(o.Endpoint) })
	}
	if o.PathStyle {
		fns = append(fns, func(so *awss3.Options) { so.UsePathStyle = true })
	}
	switch o.Checksums {
	case "":
	case ChecksumsWhenSupported:
		fns = append(fns, func(so *awss3.Options) {
			so.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenSupported
			so.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenSupported
		})
	case ChecksumsWhenRequired:
		fns = append(fns, func(so *awss3.Options) {
			so.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
			so.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
		})
	default:
		return nil, fmt.Errorf("checksums %q is not a known value: use %q or %q",
			o.Checksums, ChecksumsWhenSupported, ChecksumsWhenRequired)
	}
	return fns, nil
}

// NewClient creates an S3 Client using the default credential chain. An
// empty region is left to that chain (AWS_REGION, AWS_DEFAULT_REGION, the
// profile's region), and Region reports what it resolved to, which may still
// be empty.
func NewClient(ctx context.Context, bucket, region string, opts Options) (*Client, error) {
	optFns, err := opts.ClientOptions()
	if err != nil {
		return nil, err
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return NewClientFromConfig(cfg, bucket, cfg.Region, optFns...), nil
}

// NewClientFromConfig returns an S3 Client from a pre-built aws.Config.
func NewClientFromConfig(cfg aws.Config, bucket, region string, optFns ...func(*awss3.Options)) *Client {
	raw := awss3.NewFromConfig(cfg, optFns...)
	return &Client{
		s3:     raw,
		raw:    raw,
		bucket: bucket,
		region: region,
	}
}

// S3Client exposes the underlying SDK client for commands that need direct
// access (e.g. InitBucket).
func (c *Client) S3Client() *awss3.Client { return c.raw }

// Route is where the pinned SDK sends a request for the client's bucket.
type Route struct {
	// URL carries the scheme, host and percent-decoded path the SDK resolved.
	// A key is appended to that path.
	URL url.URL
	// Endpoint is the base URL handed to the client, by the endpoint key or by
	// whatever the SDK read for it (AWS_ENDPOINT_URL_S3, AWS_ENDPOINT_URL, the
	// profile), and "" when the SDK derives AWS's own host from the region.
	Endpoint string
}

// Route resolves the client's bucket through the SDK's own endpoint rules,
// with the endpoint and addressing style the client was built with, so it is
// the route a request takes and not a reading of the configuration: the rules
// decode the endpoint's path, choose between <bucket>.<host> and
// <host>/<bucket>, and fall back to the second for a bucket or host they will
// not address the first way. Endpoint is set even when it fails.
//
// A client with no region and no endpoint is resolved as if it had a region.
// Its requests fail until the SDK's chain supplies one, but the rules resolve
// nothing without it, and which region is no part of where an AWS bucket is:
// the answer would otherwise change with AWS_REGION.
func (c *Client) Route(ctx context.Context) (Route, error) {
	region, endpoint, pathStyle := c.region, c.Endpoint(), false
	if c.raw != nil {
		opts := c.raw.Options()
		region, pathStyle = opts.Region, opts.UsePathStyle
	}
	if region == "" && endpoint == "" {
		region = "us-east-1"
	}
	return ResolveRoute(ctx, region, endpoint, c.bucket, pathStyle)
}

// ResolveRoute is Route for a bucket no client was built for.
func ResolveRoute(ctx context.Context, region, endpoint, bucket string, pathStyle bool) (Route, error) {
	params := awss3.EndpointParameters{
		Region:         aws.String(region),
		Bucket:         aws.String(bucket),
		ForcePathStyle: aws.Bool(pathStyle),
	}
	if endpoint != "" {
		params.Endpoint = aws.String(endpoint)
	}
	route := Route{Endpoint: endpoint}
	ep, err := awss3.NewDefaultEndpointResolverV2().ResolveEndpoint(ctx, params)
	if err != nil {
		return route, err
	}
	route.URL = ep.URI
	return route, nil
}

// Endpoint is the base URL the client dials, from the endpoint key or from
// whatever the SDK read for it (AWS_ENDPOINT_URL_S3, AWS_ENDPOINT_URL, the
// profile), and "" when the SDK derives AWS's own host from the region.
func (c *Client) Endpoint() string {
	if c.raw == nil {
		return ""
	}
	return aws.ToString(c.raw.Options().BaseEndpoint)
}

// Bucket returns the configured bucket name.
func (c *Client) Bucket() string { return c.bucket }

// Region returns the region the client dials.
func (c *Client) Region() string { return c.region }

// ObjectStatus describes whether a key exists in S3.
type ObjectStatus struct {
	Key          string
	Exists       bool
	Size         int64
	LastModified time.Time
	ETag         string
}

// HeadObject checks whether a key exists and returns its metadata.
func (c *Client) HeadObject(ctx context.Context, key string) (*ObjectStatus, error) {
	out, err := c.s3.HeadObject(ctx, &awss3.HeadObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		// A 404 is not an error — the object just doesn't exist.
		if isNotFound(err) {
			return &ObjectStatus{Key: key, Exists: false}, nil
		}
		return nil, fmt.Errorf("head object s3://%s/%s: %w", c.bucket, key, err)
	}
	status := &ObjectStatus{
		Key:    key,
		Exists: true,
		Size:   aws.ToInt64(out.ContentLength),
	}
	if out.LastModified != nil {
		status.LastModified = *out.LastModified
	}
	if out.ETag != nil {
		status.ETag = strings.Trim(*out.ETag, `"`)
	}
	return status, nil
}

// uploadPartSize is the multipart chunk. S3 caps an upload at 10,000 parts, so
// 16 MiB puts the object ceiling at 160,000 MiB (about 156 GiB) while holding
// at most uploadPartSize × uploadConcurrency in memory at once.
const (
	uploadPartSize    = 16 * 1024 * 1024
	uploadConcurrency = 4
)

// UploadFile uploads a local file to S3 at the given key.
//
// It goes through the multipart uploader rather than a single PutObject, which
// caps at 5 GB. Per-package placement exists so one enormous artifact can live
// on separate storage, and that artifact could not reach an S3 backend at all
// under the single-part path.
func (c *Client) UploadFile(ctx context.Context, localPath, key string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", localPath, err)
	}
	defer func() { _ = f.Close() }()

	// feature/s3/manager is marked deprecated in favor of
	// feature/s3/transfermanager, which is still v0.3.x. A pre-1.0 module on
	// the upload path buys a breaking change for no behavior we need, so this
	// stays on the v1 API until the replacement tags v1.
	uploader := manager.NewUploader(c.s3, func(u *manager.Uploader) { //nolint:staticcheck // see above
		u.PartSize = uploadPartSize
		u.Concurrency = uploadConcurrency
	})
	if _, err := uploader.Upload(ctx, &awss3.PutObjectInput{ //nolint:staticcheck // see above
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
		Body:   f,
	}); err != nil {
		return fmt.Errorf("put object s3://%s/%s: %w", c.bucket, key, err)
	}
	return nil
}

// StreamResult holds the streaming body and metadata for an S3 object.
type StreamResult struct {
	// Body is the object data stream. The caller must close it.
	Body io.ReadCloser
	// ContentLength is the object size in bytes, or -1 if unknown.
	ContentLength int64
	// ETag is the object's ETag with surrounding quotes stripped.
	ETag string
	// ContentType is the S3-stored content type, which may be empty.
	ContentType string
	// LastModified is the object's stored timestamp, zero if S3 sent none.
	LastModified time.Time
}

// GetObjectStream opens a streaming GET for the given key.
// Returns nil, nil when the key does not exist.
// The caller must close StreamResult.Body after reading.
func (c *Client) GetObjectStream(ctx context.Context, key string) (*StreamResult, error) {
	out, err := c.s3.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get object stream s3://%s/%s: %w", c.bucket, key, err)
	}
	result := &StreamResult{
		Body:          out.Body,
		ContentLength: aws.ToInt64(out.ContentLength),
	}
	if out.ETag != nil {
		result.ETag = strings.Trim(*out.ETag, `"`)
	}
	if out.ContentType != nil {
		result.ContentType = *out.ContentType
	}
	if out.LastModified != nil {
		result.LastModified = *out.LastModified
	}
	return result, nil
}

// GetObject reads the contents of an S3 key. Returns nil, nil if the key doesn't exist.
func (c *Client) GetObject(ctx context.Context, key string) ([]byte, error) {
	out, err := c.s3.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get object s3://%s/%s: %w", c.bucket, key, err)
	}
	defer func() { _ = out.Body.Close() }()
	data, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf("read body s3://%s/%s: %w", c.bucket, key, err)
	}
	return data, nil
}

// PutBytes uploads raw bytes to an S3 key.
func (c *Client) PutBytes(ctx context.Context, key string, data []byte) error {
	_, err := c.s3.PutObject(ctx, &awss3.PutObjectInput{
		Bucket:        aws.String(c.bucket),
		Key:           aws.String(key),
		Body:          strings.NewReader(string(data)),
		ContentLength: aws.Int64(int64(len(data))),
	})
	if err != nil {
		return fmt.Errorf("put object s3://%s/%s: %w", c.bucket, key, err)
	}
	return nil
}

// DeleteObject removes a single key from S3.
func (c *Client) DeleteObject(ctx context.Context, key string) error {
	_, err := c.s3.DeleteObject(ctx, &awss3.DeleteObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("delete object s3://%s/%s: %w", c.bucket, key, err)
	}
	return nil
}

// ListPrefix returns all keys with the given prefix.
func (c *Client) ListPrefix(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	paginator := awss3.NewListObjectsV2Paginator(c.s3, &awss3.ListObjectsV2Input{
		Bucket: aws.String(c.bucket),
		Prefix: aws.String(prefix),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list objects s3://%s/%s: %w", c.bucket, prefix, err)
		}
		for _, obj := range page.Contents {
			if obj.Key != nil {
				keys = append(keys, *obj.Key)
			}
		}
	}
	return keys, nil
}

// SyncDir uploads every file under localDir to S3 under the given keyPrefix.
// Files are uploaded unconditionally (no ETag comparison); use for build
// outputs where correctness trumps incremental cost.
func (c *Client) SyncDir(ctx context.Context, out io.Writer, localDir, keyPrefix string) (int, error) {
	uploaded := 0
	err := filepath.Walk(localDir, func(path string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if fi.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(localDir, path)
		if err != nil {
			return err
		}
		key := keyPrefix + rel

		if out != nil {
			_, _ = fmt.Fprintf(out, "    upload: s3://%s/%s (%s)\n", c.bucket, key, humanBytesS3(fi.Size()))
		}
		if err := c.UploadFile(ctx, path, key); err != nil {
			return err
		}
		uploaded++
		return nil
	})
	return uploaded, err
}

// isNotFound reports whether err says the object is absent. The checks run
// in order and the order is not interchangeable:
//
//   - NoSuchBucket answers false, and runs first because S3 reports a missing
//     bucket with a 404 too. Checked by status alone, every key in a mistyped
//     bucket reads as an absent object and the backend looks empty instead of
//     misconfigured. GetObject does not model NoSuchBucket, so it arrives as a
//     generic API error and is matched on its code as well as its type.
//   - NoSuchKey is the modeled GetObject answer.
//   - NotFound is HeadObject's: a HEAD response has no body, so its 404 never
//     deserializes to NoSuchKey. For the same reason a HeadObject against a
//     missing bucket is indistinguishable from a missing key here.
//   - Any other response error carrying status 404.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	var nsb *types.NoSuchBucket
	if errors.As(err, &nsb) {
		return false
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchBucket" {
		return false
	}
	var nsk *types.NoSuchKey
	if errors.As(err, &nsk) {
		return true
	}
	var nf *types.NotFound
	if errors.As(err, &nf) {
		return true
	}
	var re *awshttp.ResponseError
	return errors.As(err, &re) && re.HTTPStatusCode() == http.StatusNotFound
}

// humanBytesS3 is a copy of the builder helper to avoid a circular import.
func humanBytesS3(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for n := n / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
