// Package s3 wraps the AWS SDK v2 S3 client for bootstrap-specific operations.
package s3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/ravinald/bodega/internal/manifest"
)

// expectedPrefixes are the top-level S3 "directories" that services expect.
// Each is checked and created (as an empty marker object) if missing.
var expectedPrefixes = manifest.StoragePrefixes()

// BucketAPI is the subset of the SDK client InitBucket calls. *s3.Client
// satisfies it; tests substitute a fake.
type BucketAPI interface {
	HeadBucket(ctx context.Context, in *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
	CreateBucket(ctx context.Context, in *s3.CreateBucketInput, optFns ...func(*s3.Options)) (*s3.CreateBucketOutput, error)
	GetPublicAccessBlock(ctx context.Context, in *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
	PutPublicAccessBlock(ctx context.Context, in *s3.PutPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.PutPublicAccessBlockOutput, error)
	GetBucketVersioning(ctx context.Context, in *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	PutBucketVersioning(ctx context.Context, in *s3.PutBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.PutBucketVersioningOutput, error)
	GetBucketEncryption(ctx context.Context, in *s3.GetBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	PutBucketEncryption(ctx context.Context, in *s3.PutBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.PutBucketEncryptionOutput, error)
	GetBucketLifecycleConfiguration(ctx context.Context, in *s3.GetBucketLifecycleConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error)
	PutBucketLifecycleConfiguration(ctx context.Context, in *s3.PutBucketLifecycleConfigurationInput, optFns ...func(*s3.Options)) (*s3.PutBucketLifecycleConfigurationOutput, error)
	ListObjectsV2(ctx context.Context, in *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	PutObject(ctx context.Context, in *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// InitBucket creates the S3 bucket (if needed) and ensures all required
// configuration and directory structure is in place. It is idempotent:
// each step checks the current state before making changes.
//
// This is the recovery path when the infrastructure tooling partially applied or was
// never run. It creates anything that is missing and logs what already
// exists. Each step's result goes to out, which may be nil.
func InitBucket(ctx context.Context, client BucketAPI, out io.Writer, bucket, region string) error {
	if out == nil {
		out = io.Discard
	}
	if err := ensureBucket(ctx, client, out, bucket, region); err != nil {
		return err
	}
	if err := ensurePublicAccessBlock(ctx, client, out, bucket); err != nil {
		return err
	}
	if err := ensureVersioning(ctx, client, out, bucket); err != nil {
		return err
	}
	if err := ensureEncryption(ctx, client, out, bucket); err != nil {
		return err
	}
	if err := ensureLifecycle(ctx, client, out, bucket); err != nil {
		return err
	}
	if err := ensurePrefixes(ctx, client, out, bucket); err != nil {
		return err
	}
	return nil
}

func ensureBucket(ctx context.Context, client BucketAPI, out io.Writer, bucket, region string) error {
	_, err := client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucket),
	})
	if err == nil {
		fmt.Fprintf(out, "  bucket:     exists\n")
		return nil
	}

	// Bucket doesn't exist — create it.
	createInput := &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}
	if region != "us-east-1" {
		createInput.CreateBucketConfiguration = &types.CreateBucketConfiguration{
			LocationConstraint: types.BucketLocationConstraint(region),
		}
	}

	_, err = client.CreateBucket(ctx, createInput)
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) && ae.ErrorCode() == "BucketAlreadyOwnedByYou" {
			fmt.Fprintf(out, "  bucket:     exists (owned by you)\n")
			return nil
		}
		return fmt.Errorf("create bucket %s: %w", bucket, err)
	}
	fmt.Fprintf(out, "  bucket:     CREATED s3://%s\n", bucket)
	return nil
}

func ensurePublicAccessBlock(ctx context.Context, client BucketAPI, out io.Writer, bucket string) error {
	resp, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucket),
	})
	if err == nil && resp.PublicAccessBlockConfiguration != nil {
		cfg := resp.PublicAccessBlockConfiguration
		if aws.ToBool(cfg.BlockPublicAcls) &&
			aws.ToBool(cfg.BlockPublicPolicy) &&
			aws.ToBool(cfg.IgnorePublicAcls) &&
			aws.ToBool(cfg.RestrictPublicBuckets) {
			fmt.Fprintf(out, "  public acl: blocked\n")
			return nil
		}
	}

	_, err = client.PutPublicAccessBlock(ctx, &s3.PutPublicAccessBlockInput{
		Bucket: aws.String(bucket),
		PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{
			BlockPublicAcls:       aws.Bool(true),
			BlockPublicPolicy:     aws.Bool(true),
			IgnorePublicAcls:      aws.Bool(true),
			RestrictPublicBuckets: aws.Bool(true),
		},
	})
	if err != nil {
		return fmt.Errorf("put public access block on %s: %w", bucket, err)
	}
	fmt.Fprintf(out, "  public acl: CONFIGURED (all blocked)\n")
	return nil
}

func ensureVersioning(ctx context.Context, client BucketAPI, out io.Writer, bucket string) error {
	resp, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
		Bucket: aws.String(bucket),
	})
	if err == nil && resp.Status == types.BucketVersioningStatusEnabled {
		fmt.Fprintf(out, "  versioning: enabled\n")
		return nil
	}

	_, err = client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{
		Bucket: aws.String(bucket),
		VersioningConfiguration: &types.VersioningConfiguration{
			Status: types.BucketVersioningStatusEnabled,
		},
	})
	if err != nil {
		return fmt.Errorf("enable versioning on %s: %w", bucket, err)
	}
	fmt.Fprintf(out, "  versioning: ENABLED\n")
	return nil
}

func ensureEncryption(ctx context.Context, client BucketAPI, out io.Writer, bucket string) error {
	resp, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
		Bucket: aws.String(bucket),
	})
	if err == nil && resp.ServerSideEncryptionConfiguration != nil {
		for _, rule := range resp.ServerSideEncryptionConfiguration.Rules {
			if rule.ApplyServerSideEncryptionByDefault != nil {
				algo := rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm
				fmt.Fprintf(out, "  encryption: %s\n", algo)
				return nil
			}
		}
	}

	_, err = client.PutBucketEncryption(ctx, &s3.PutBucketEncryptionInput{
		Bucket: aws.String(bucket),
		ServerSideEncryptionConfiguration: &types.ServerSideEncryptionConfiguration{
			Rules: []types.ServerSideEncryptionRule{
				{
					ApplyServerSideEncryptionByDefault: &types.ServerSideEncryptionByDefault{
						SSEAlgorithm: types.ServerSideEncryptionAes256,
					},
					BucketKeyEnabled: aws.Bool(true),
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("enable encryption on %s: %w", bucket, err)
	}
	fmt.Fprintf(out, "  encryption: CONFIGURED (AES-256)\n")
	return nil
}

// Lifecycle retention. Both are stated in `bodega init --help` and
// docs/usage.md, which is where an operator who disagrees looks for them.
const (
	AbortIncompleteMultipartDays = 7
	NoncurrentVersionDays        = 30
)

// lifecycleRulePrefix marks the rules InitBucket owns. A lifecycle PUT
// replaces the whole configuration, so every rule without it is the
// operator's and is written back unchanged.
const lifecycleRulePrefix = "bodega-"

// LifecycleRules are the rules InitBucket keeps on the bucket.
//
// Abandoned multipart parts are billed, appear in no listing and serve
// nothing, so the abort rule covers the bucket root unconditionally.
//
// Noncurrent versions expire under every artifact prefix and never under
// manifests/: versioning is what a manifest has against whoever can already
// write it, and RuntimePolicy withholds s3:DeleteObjectVersion so that history
// outlives a compromised service. Elsewhere a noncurrent version is a
// byte-identical replacement or a catalogue upstream has since replaced. S3
// filters take a prefix and no wildcard, hence one rule per prefix.
func LifecycleRules() []types.LifecycleRule {
	rules := []types.LifecycleRule{{
		ID:     aws.String(lifecycleRulePrefix + "abort-incomplete-multipart"),
		Status: types.ExpirationStatusEnabled,
		Filter: &types.LifecycleRuleFilter{Prefix: aws.String("")},
		AbortIncompleteMultipartUpload: &types.AbortIncompleteMultipartUpload{
			DaysAfterInitiation: aws.Int32(AbortIncompleteMultipartDays),
		},
	}}
	for _, prefix := range expectedPrefixes {
		if prefix == manifest.ManifestsPrefix {
			continue
		}
		rules = append(rules, types.LifecycleRule{
			ID:     aws.String(lifecycleRulePrefix + "expire-noncurrent-" + strings.TrimSuffix(prefix, "/")),
			Status: types.ExpirationStatusEnabled,
			Filter: &types.LifecycleRuleFilter{Prefix: aws.String(prefix)},
			NoncurrentVersionExpiration: &types.NoncurrentVersionExpiration{
				NoncurrentDays: aws.Int32(NoncurrentVersionDays),
			},
		})
	}
	return rules
}

func ensureLifecycle(ctx context.Context, client BucketAPI, out io.Writer, bucket string) error {
	want := LifecycleRules()

	var current []types.LifecycleRule
	resp, err := client.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{
		Bucket: aws.String(bucket),
	})
	var ae smithy.APIError
	switch {
	case err == nil:
		current = resp.Rules
	case errors.As(err, &ae) && ae.ErrorCode() == "NoSuchLifecycleConfiguration":
	default:
		// Refusing here rather than writing blind: the PUT below replaces
		// every rule on the bucket, and rules this run could not read are
		// rules it would delete.
		return fmt.Errorf("read lifecycle configuration on %s: %w", bucket, err)
	}

	if lifecycleSatisfied(current, want) {
		fmt.Fprintf(out, "  lifecycle:  configured\n")
		return nil
	}

	var kept []types.LifecycleRule
	for _, r := range current {
		if !strings.HasPrefix(aws.ToString(r.ID), lifecycleRulePrefix) {
			kept = append(kept, r)
		}
	}
	_, err = client.PutBucketLifecycleConfiguration(ctx, &s3.PutBucketLifecycleConfigurationInput{
		Bucket:                 aws.String(bucket),
		LifecycleConfiguration: &types.BucketLifecycleConfiguration{Rules: append(kept, want...)},
	})
	if err != nil {
		return fmt.Errorf("put lifecycle configuration on %s: %w", bucket, err)
	}
	fmt.Fprintf(out, "  lifecycle:  CONFIGURED (abort multipart after %dd, noncurrent versions after %dd, manifests/ kept)\n",
		AbortIncompleteMultipartDays, NoncurrentVersionDays)
	return nil
}

// lifecycleSatisfied reports whether current holds exactly the bodega rules
// in want. A bodega rule edited by hand, or one left over for a prefix that
// no longer exists, is drift and gets rewritten.
func lifecycleSatisfied(current, want []types.LifecycleRule) bool {
	have := map[string]types.LifecycleRule{}
	for _, r := range current {
		if id := aws.ToString(r.ID); strings.HasPrefix(id, lifecycleRulePrefix) {
			have[id] = r
		}
	}
	if len(have) != len(want) {
		return false
	}
	for _, w := range want {
		h, ok := have[aws.ToString(w.ID)]
		if !ok || !sameLifecycleRule(h, w) {
			return false
		}
	}
	return true
}

func sameLifecycleRule(a, b types.LifecycleRule) bool {
	if a.Status != b.Status || a.Filter == nil || b.Filter == nil ||
		aws.ToString(a.Filter.Prefix) != aws.ToString(b.Filter.Prefix) ||
		a.Filter.Tag != nil || a.Filter.And != nil ||
		a.Filter.ObjectSizeGreaterThan != nil || a.Filter.ObjectSizeLessThan != nil ||
		a.Expiration != nil || len(a.Transitions) > 0 || len(a.NoncurrentVersionTransitions) > 0 {
		return false
	}
	if (a.AbortIncompleteMultipartUpload == nil) != (b.AbortIncompleteMultipartUpload == nil) ||
		(a.NoncurrentVersionExpiration == nil) != (b.NoncurrentVersionExpiration == nil) {
		return false
	}
	if a.AbortIncompleteMultipartUpload != nil &&
		aws.ToInt32(a.AbortIncompleteMultipartUpload.DaysAfterInitiation) != aws.ToInt32(b.AbortIncompleteMultipartUpload.DaysAfterInitiation) {
		return false
	}
	if a.NoncurrentVersionExpiration != nil &&
		(aws.ToInt32(a.NoncurrentVersionExpiration.NoncurrentDays) != aws.ToInt32(b.NoncurrentVersionExpiration.NoncurrentDays) ||
			a.NoncurrentVersionExpiration.NewerNoncurrentVersions != nil) {
		return false
	}
	return true
}

func ensurePrefixes(ctx context.Context, client BucketAPI, out io.Writer, bucket string) error {
	for _, prefix := range expectedPrefixes {
		// Check if any object exists under this prefix.
		resp, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:  aws.String(bucket),
			Prefix:  aws.String(prefix),
			MaxKeys: aws.Int32(1),
		})
		if err != nil {
			return fmt.Errorf("list prefix %s: %w", prefix, err)
		}

		if aws.ToInt32(resp.KeyCount) > 0 {
			fmt.Fprintf(out, "  %-22s exists\n", prefix)
			continue
		}

		// Create a zero-byte marker object so the "directory" exists.
		_, err = client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(prefix),
		})
		if err != nil {
			return fmt.Errorf("create prefix marker %s: %w", prefix, err)
		}
		fmt.Fprintf(out, "  %-22s CREATED\n", prefix)
	}
	return nil
}
