// Package s3 wraps the AWS SDK v2 S3 client for bootstrap-specific operations.
package s3

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// expectedPrefixes are the top-level S3 "directories" that services expect.
// Each is checked and created (as an empty marker object) if missing.
var expectedPrefixes = []string{
	"packages/apt/",
	"pypi/wheels/",
	"repos/",
	"binaries/",
	"services/",
}

// InitBucket creates the S3 bucket (if needed) and ensures all required
// configuration and directory structure is in place. It is idempotent:
// each step checks the current state before making changes.
//
// This is the recovery path when Terraform partially applied or was
// never run. It creates anything that is missing and logs what already
// exists.
func InitBucket(ctx context.Context, client *s3.Client, bucket, region string) error {
	if err := ensureBucket(ctx, client, bucket, region); err != nil {
		return err
	}
	if err := ensurePublicAccessBlock(ctx, client, bucket); err != nil {
		return err
	}
	if err := ensureVersioning(ctx, client, bucket); err != nil {
		return err
	}
	if err := ensureEncryption(ctx, client, bucket); err != nil {
		return err
	}
	if err := ensurePrefixes(ctx, client, bucket); err != nil {
		return err
	}
	return nil
}

func ensureBucket(ctx context.Context, client *s3.Client, bucket, region string) error {
	// Check if bucket exists first.
	_, err := client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucket),
	})
	if err == nil {
		fmt.Printf("  bucket:     exists\n")
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
			fmt.Printf("  bucket:     exists (owned by you)\n")
			return nil
		}
		return fmt.Errorf("create bucket %s: %w", bucket, err)
	}
	fmt.Printf("  bucket:     CREATED s3://%s\n", bucket)
	return nil
}

func ensurePublicAccessBlock(ctx context.Context, client *s3.Client, bucket string) error {
	resp, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucket),
	})
	if err == nil && resp.PublicAccessBlockConfiguration != nil {
		cfg := resp.PublicAccessBlockConfiguration
		if aws.ToBool(cfg.BlockPublicAcls) &&
			aws.ToBool(cfg.BlockPublicPolicy) &&
			aws.ToBool(cfg.IgnorePublicAcls) &&
			aws.ToBool(cfg.RestrictPublicBuckets) {
			fmt.Printf("  public acl: blocked\n")
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
	fmt.Printf("  public acl: CONFIGURED (all blocked)\n")
	return nil
}

func ensureVersioning(ctx context.Context, client *s3.Client, bucket string) error {
	resp, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
		Bucket: aws.String(bucket),
	})
	if err == nil && resp.Status == types.BucketVersioningStatusEnabled {
		fmt.Printf("  versioning: enabled\n")
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
	fmt.Printf("  versioning: ENABLED\n")
	return nil
}

func ensureEncryption(ctx context.Context, client *s3.Client, bucket string) error {
	resp, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
		Bucket: aws.String(bucket),
	})
	if err == nil && resp.ServerSideEncryptionConfiguration != nil {
		for _, rule := range resp.ServerSideEncryptionConfiguration.Rules {
			if rule.ApplyServerSideEncryptionByDefault != nil {
				algo := rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm
				fmt.Printf("  encryption: %s\n", algo)
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
	fmt.Printf("  encryption: CONFIGURED (AES-256)\n")
	return nil
}

func ensurePrefixes(ctx context.Context, client *s3.Client, bucket string) error {
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
			fmt.Printf("  %-22s exists\n", prefix)
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
		fmt.Printf("  %-22s CREATED\n", prefix)
	}
	return nil
}
