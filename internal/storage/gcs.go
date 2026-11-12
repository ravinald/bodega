package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	gstorage "cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iterator"

	bogcs "github.com/ravinald/bodega/internal/gcs"
)

func init() {
	Register("gcs", newGCSFromSpec)
}

func newGCSFromSpec(ctx context.Context, spec Spec) (ObjectStore, error) {
	if spec.Bucket == "" {
		return nil, fmt.Errorf("gcs backend requires a bucket (set bucket in config or REPO_BUCKET env)")
	}
	if spec.Endpoint != "" || spec.PathStyle || spec.Checksums != "" {
		return nil, fmt.Errorf("gcs backend for bucket %s sets endpoint, path_style or checksums, which only the s3 driver reads; "+
			"remove them (the gcs driver reads bucket and prefix)", spec.Bucket)
	}
	client, err := bogcs.Dial(ctx)
	if err != nil {
		return nil, err
	}
	return NewGCS(client, spec.Bucket), nil
}

// publishAttempts bounds how often one Put re-reads the generation after
// another writer landed between its read and its write.
const publishAttempts = 5

// GCS is the ObjectStore over one Cloud Storage bucket.
//
// Write contract (ObjectStore.Put). GCS keeps the first three, and they are
// the service's documented behavior before they are anything the conformance
// suite observes. An object is immutable and an upload becomes one only when
// its last byte is acknowledged, so a reader gets the previous object or the
// new one. A reader is pinned to the generation its first response named: the
// SDK asks for that generation again if it has to reconnect, so an open handle
// reads the object it opened or fails, and never continues into a replacement.
// An interrupted upload publishes nothing: an unfinished resumable session is
// not an object, appears in no listing and expires after a week.
//
// Every write is conditional. Put reads the key's generation and uploads with
// a precondition on it (or on the key being absent), which is what makes the
// upload safe for the SDK to retry: a retry of a write that already landed is
// refused rather than applied twice over someone else's. When another writer
// wins the race Put reads again and retries, so the caller still sees a plain
// replace; after publishAttempts lost races it fails with nothing published.
//
// Durability is the bucket's. Put returns when Cloud Storage acknowledges the
// object, and that is a property of the service, not a promise an ObjectStore
// makes.
//
// The fourth it keeps vacuously, as S3 does. bodega's buckets run with uniform
// bucket-level access, so an object carries no ACL to restate or to widen, and
// access is the bucket's IAM policy alone. An artifact whose restriction has
// to survive refills belongs on a local backend.
type GCS struct {
	bucket *gstorage.BucketHandle
	name   string
	// chunkSize overrides the SDK's 16 MiB upload chunk when positive, so a
	// test reaches the resumable path with a small body.
	chunkSize int
}

// NewGCS wraps one bucket of an existing client as an ObjectStore.
func NewGCS(client *gstorage.Client, bucket string) *GCS {
	return &GCS{bucket: client.Bucket(bucket), name: bucket}
}

// identity is the string a GCS object is known by across Head and GetStream.
// The generation changes on every write and on nothing else, and both calls
// report it, which the service's two ETag spellings (one per API) do not.
func identity(generation int64) string {
	return strconv.FormatInt(generation, 10)
}

func (g *GCS) Get(ctx context.Context, key string) ([]byte, error) {
	r, err := g.GetStream(ctx, key)
	if err != nil || r == nil {
		return nil, err
	}
	defer func() { _ = r.Body.Close() }()
	// io.ReadAll never returns nil, so a stored zero-byte object stays
	// distinct from a missing one, which every caller reads nil as.
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("read body gs://%s/%s: %w", g.name, key, err)
	}
	return data, nil
}

func (g *GCS) GetStream(ctx context.Context, key string) (*StreamResult, error) {
	if err := ValidateKey(key); err != nil {
		return nil, err
	}
	r, err := g.bucket.Object(key).NewReader(ctx)
	if errors.Is(err, gstorage.ErrObjectNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get object gs://%s/%s: %w", g.name, key, err)
	}
	return &StreamResult{
		Body:          r,
		ContentLength: r.Attrs.Size,
		ETag:          identity(r.Attrs.Generation),
		ContentType:   r.Attrs.ContentType,
		LastModified:  r.Attrs.LastModified,
	}, nil
}

func (g *GCS) Head(ctx context.Context, key string) (*ObjectInfo, error) {
	if err := ValidateKey(key); err != nil {
		return nil, err
	}
	attrs, err := g.bucket.Object(key).Attrs(ctx)
	if errors.Is(err, gstorage.ErrObjectNotExist) {
		return &ObjectInfo{Key: key, Exists: false}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("head object gs://%s/%s: %w", g.name, key, err)
	}
	return &ObjectInfo{
		Key:    key,
		Exists: true,
		Size:   attrs.Size,
		// A read reports the object's time from an HTTP header, which has
		// whole seconds. Truncating here is what lets a caller compare the
		// two; the metadata's own microseconds would never match.
		LastModified: attrs.Updated.Truncate(time.Second),
		ETag:         identity(attrs.Generation),
	}, nil
}

func (g *GCS) List(ctx context.Context, prefix string) ([]string, error) {
	if err := ValidateKey(prefix); err != nil {
		return nil, err
	}
	q := &gstorage.Query{Prefix: prefix}
	if err := q.SetAttrSelection([]string{"Name"}); err != nil {
		return nil, err
	}
	var keys []string
	it := g.bucket.Objects(ctx, q)
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			return keys, nil
		}
		if err != nil {
			return nil, fmt.Errorf("list objects gs://%s/%s: %w", g.name, prefix, err)
		}
		keys = append(keys, attrs.Name)
	}
}

func (g *GCS) Put(ctx context.Context, key string, data []byte) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	return g.publish(ctx, key, func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
}

func (g *GCS) PutFile(ctx context.Context, localPath, key string) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	return g.publish(ctx, key, func() (io.ReadCloser, error) {
		f, err := os.Open(localPath)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", localPath, err)
		}
		return f, nil
	})
}

// publish replaces the object at key with what open yields, under a
// precondition on the generation it read. open is called once per attempt.
func (g *GCS) publish(ctx context.Context, key string, open func() (io.ReadCloser, error)) error {
	obj := g.bucket.Object(key)
	for range publishAttempts {
		cond := gstorage.Conditions{DoesNotExist: true}
		attrs, err := obj.Attrs(ctx)
		switch {
		case err == nil:
			cond = gstorage.Conditions{GenerationMatch: attrs.Generation}
		case !errors.Is(err, gstorage.ErrObjectNotExist):
			return fmt.Errorf("put object gs://%s/%s: read its generation: %w", g.name, key, err)
		}
		err = g.upload(ctx, obj.If(cond), open)
		var ge *googleapi.Error
		if errors.As(err, &ge) && ge.Code == http.StatusPreconditionFailed {
			continue
		}
		if err != nil {
			return fmt.Errorf("put object gs://%s/%s: %w", g.name, key, err)
		}
		return nil
	}
	return fmt.Errorf("put object gs://%s/%s: another writer replaced it %d times in a row, each between this write's read and its upload; "+
		"nothing of this write was published, and the key holds the other writer's object", g.name, key, publishAttempts)
}

// upload sends one object. A source that fails partway cancels the upload
// rather than closing the writer: Close finalizes whatever was written, which
// would publish a truncated object under the key.
func (g *GCS) upload(ctx context.Context, obj *gstorage.ObjectHandle, open func() (io.ReadCloser, error)) error {
	src, err := open()
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	w := obj.NewWriter(ctx)
	if g.chunkSize > 0 {
		w.ChunkSize = g.chunkSize
	}
	if _, err := io.Copy(w, src); err != nil {
		cancel()
		_ = w.Close()
		return err
	}
	return w.Close()
}

// Delete removes the live object. On a versioned bucket the generation stays
// behind as noncurrent, which is what versioning is for. The delete is retried
// on a transient failure with no precondition, because removing the live
// object twice is the same as removing it once.
func (g *GCS) Delete(ctx context.Context, key string) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	err := g.bucket.Object(key).Retryer(gstorage.WithPolicy(gstorage.RetryAlways)).Delete(ctx)
	if err != nil && !errors.Is(err, gstorage.ErrObjectNotExist) {
		return fmt.Errorf("delete object gs://%s/%s: %w", g.name, key, err)
	}
	return nil
}

func (g *GCS) SyncDir(ctx context.Context, out io.Writer, localDir, keyPrefix string) (int, error) {
	if err := ValidateKey(keyPrefix); err != nil {
		return 0, err
	}
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
		key := keyPrefix + filepath.ToSlash(rel)
		if out != nil {
			_, _ = fmt.Fprintf(out, "    upload: gs://%s/%s (%d bytes)\n", g.name, key, fi.Size())
		}
		if err := g.PutFile(ctx, path, key); err != nil {
			return err
		}
		uploaded++
		return nil
	})
	return uploaded, err
}

// Label is "gs://<bucket>". A bucket name is global and the driver takes no
// endpoint, so the name is the whole location.
func (g *GCS) Label() string {
	return "gs://" + g.name
}
