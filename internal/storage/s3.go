package storage

import (
	"context"
	"fmt"
	"io"

	"github.com/ravinald/bodega/internal/config"
	bos3 "github.com/ravinald/bodega/internal/s3"
)

func init() {
	Register("s3", newS3FromConfig)
}

func newS3FromConfig(ctx context.Context, cfg *config.Config) (ObjectStore, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("s3 backend requires a bucket (set bucket in config or REPO_BUCKET env)")
	}
	client, err := bos3.NewClient(ctx, cfg.Bucket, cfg.Region)
	if err != nil {
		return nil, fmt.Errorf("create S3 client: %w", err)
	}
	return &S3{client: client}, nil
}

// S3 adapts the existing internal/s3.Client to the ObjectStore interface.
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

func (s *S3) Get(ctx context.Context, key string) ([]byte, error) {
	return s.client.GetObject(ctx, key)
}

func (s *S3) GetStream(ctx context.Context, key string) (*StreamResult, error) {
	r, err := s.client.GetObjectStream(ctx, key)
	if err != nil || r == nil {
		return nil, err
	}
	return &StreamResult{
		Body:          r.Body,
		ContentLength: r.ContentLength,
		ETag:          r.ETag,
		ContentType:   r.ContentType,
	}, nil
}

func (s *S3) Head(ctx context.Context, key string) (*ObjectInfo, error) {
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
	return s.client.ListPrefix(ctx, prefix)
}

func (s *S3) Put(ctx context.Context, key string, data []byte) error {
	return s.client.PutBytes(ctx, key, data)
}

func (s *S3) PutFile(ctx context.Context, localPath, key string) error {
	return s.client.UploadFile(ctx, localPath, key)
}

func (s *S3) Delete(ctx context.Context, key string) error {
	return s.client.DeleteObject(ctx, key)
}

func (s *S3) SyncDir(ctx context.Context, out io.Writer, localDir, keyPrefix string) (int, error) {
	return s.client.SyncDir(ctx, out, localDir, keyPrefix)
}

func (s *S3) Label() string {
	return fmt.Sprintf("s3://%s", s.client.Bucket())
}
