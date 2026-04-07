package s3

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// Client wraps the AWS S3 client with bootstrap-specific helpers.
type Client struct {
	s3     *awss3.Client
	bucket string
	region string
}

// NewClient creates an S3 Client using the default credential chain.
func NewClient(ctx context.Context, bucket, region string) (*Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return &Client{
		s3:     awss3.NewFromConfig(cfg),
		bucket: bucket,
		region: region,
	}, nil
}

// NewClientFromConfig returns an S3 Client from a pre-built aws.Config.
func NewClientFromConfig(cfg aws.Config, bucket, region string) *Client {
	return &Client{
		s3:     awss3.NewFromConfig(cfg),
		bucket: bucket,
		region: region,
	}
}

// S3Client exposes the underlying SDK client for commands that need direct
// access (e.g. InitBucket).
func (c *Client) S3Client() *awss3.Client { return c.s3 }

// Bucket returns the configured bucket name.
func (c *Client) Bucket() string { return c.bucket }

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

// UploadFile uploads a local file to S3 at the given key.
func (c *Client) UploadFile(ctx context.Context, localPath, key string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", localPath, err)
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", localPath, err)
	}

	_, err = c.s3.PutObject(ctx, &awss3.PutObjectInput{
		Bucket:        aws.String(c.bucket),
		Key:           aws.String(key),
		Body:          f,
		ContentLength: aws.Int64(fi.Size()),
	})
	if err != nil {
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

// isNotFound checks if an AWS error represents a 404 / NoSuchKey.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	var nsk *types.NoSuchKey
	if ok := isErrorType(err, &nsk); ok {
		return true
	}
	// HeadObject returns a generic HTTP 404 that doesn't unwrap to NoSuchKey.
	return strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "NoSuchKey")
}

// isErrorType is a type-assertion helper compatible with errors.As.
func isErrorType(err error, target interface{}) bool {
	switch t := target.(type) {
	case **types.NoSuchKey:
		var v *types.NoSuchKey
		if ok := asError(err, &v); ok {
			*t = v
			return true
		}
	}
	return false
}

func asError(err error, target interface{}) bool {
	switch t := target.(type) {
	case **types.NoSuchKey:
		var nsk *types.NoSuchKey
		for err != nil {
			if v, ok := err.(*types.NoSuchKey); ok {
				*t = v
				_ = nsk
				return true
			}
			type unwrapper interface{ Unwrap() error }
			if u, ok := err.(unwrapper); ok {
				err = u.Unwrap()
			} else {
				break
			}
		}
	}
	return false
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
