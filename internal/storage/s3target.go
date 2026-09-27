package storage

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/ravinald/bodega/internal/config"
	bos3 "github.com/ravinald/bodega/internal/s3"
)

// S3Target is the one s3 backend an init action acts on. Region is as
// configured and may be empty; DialS3Target reports the one the SDK resolves.
type S3Target struct {
	Name   string
	Bucket string
	Region string
	Prefix string
}

// S3TargetNames lists the backends an init action can reach: the default when
// its driver is s3, then each storage_backends entry on the s3 driver, sorted.
func S3TargetNames(cfg *config.Config) []string {
	var names []string
	if cfg.StorageBackend == "s3" {
		names = append(names, DefaultName)
	}
	var named []string
	for n, b := range cfg.StorageBackends {
		if b.Driver == "s3" {
			named = append(named, n)
		}
	}
	sort.Strings(named)
	return append(names, named...)
}

// ResolveS3Target names the backend an init action reaches: the default one,
// or a storage_backends entry, read through the same SpecFor the service's
// resolver builds its stores from. It refuses a backend whose driver is not
// s3 rather than falling back to the bucket key, which an install on the
// local driver may still carry, so init never dials AWS for a backend that
// stores nothing there.
func ResolveS3Target(cfg *config.Config, name string) (S3Target, error) {
	spec, ok := SpecFor(cfg, name)
	if !ok {
		names := []string{DefaultName}
		for n := range cfg.StorageBackends {
			names = append(names, n)
		}
		sort.Strings(names[1:])
		return S3Target{}, fmt.Errorf("unknown storage backend %q (configured: %s)", name, strings.Join(names, ", "))
	}
	t := S3Target{Name: name, Bucket: spec.Bucket, Region: spec.Region, Prefix: spec.Prefix}
	driver := spec.Driver
	if driver == "" {
		driver = "local"
	}
	if driver != "s3" {
		return t, fmt.Errorf("storage backend %q uses the %s driver, which keeps artifacts in a directory and needs no init; "+
			"init prepares s3 backends only (set storage_backend to \"s3\", or name an s3 entry from storage_backends)", name, driver)
	}
	if t.Bucket == "" {
		if name == DefaultName {
			return t, fmt.Errorf("S3 bucket is required: set --bucket, the REPO_BUCKET env var, or add \"bucket\" to config.json")
		}
		return t, fmt.Errorf("storage_backends[%q] uses the s3 driver and names no bucket; add \"bucket\" to that entry", name)
	}
	return t, nil
}

// S3Dialer builds a client for a bucket and a configured region, which may be
// empty. bos3.NewClient is the one every caller outside a test passes.
type S3Dialer func(ctx context.Context, bucket, region string) (*bos3.Client, error)

// DialS3Target builds the client the service would build for t, through the
// same bos3.NewClient call, so an entry with no region resolves through the
// SDK's chain here exactly as it does there.
func DialS3Target(ctx context.Context, t S3Target) (*bos3.Client, error) {
	return DialS3TargetWith(ctx, t, bos3.NewClient)
}

// DialS3TargetWith is DialS3Target through dial. It refuses when the resolved
// region is empty, because every call would fail, in the service as well.
func DialS3TargetWith(ctx context.Context, t S3Target, dial S3Dialer) (*bos3.Client, error) {
	client, err := dial(ctx, t.Bucket, t.Region)
	if err != nil {
		return nil, fmt.Errorf("storage backend %q: %w", t.Name, err)
	}
	if err := RequireS3Region(t, client.Region()); err != nil {
		return nil, err
	}
	return client, nil
}

// RequireS3Region refuses an empty resolved region for t.
func RequireS3Region(t S3Target, region string) error {
	if region != "" {
		return nil
	}
	return fmt.Errorf("storage backend %q has no AWS region: storage_backends[%q] sets no \"region\", and neither AWS_REGION, "+
		"AWS_DEFAULT_REGION nor the AWS profile names one, so the service could not reach s3://%s either; add \"region\" to that entry",
		t.Name, t.Name, t.Bucket)
}
