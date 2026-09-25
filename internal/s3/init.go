// Package s3 wraps the AWS SDK v2 S3 client for bootstrap-specific operations.
package s3

import (
	"context"
	"errors"
	"fmt"
	"io"

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
