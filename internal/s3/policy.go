package s3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"

	"github.com/ravinald/bodega/internal/manifest"
)

// iamAction is the IAM action that authorizes one SDK call, and whether it is
// granted on the bucket ARN or on the objects under it.
type iamAction struct {
	name   string
	object bool
}

// callActions maps every method of BucketAPI and ObjectAPI to what IAM checks
// for it. Most share the call's name; the ones that do not are why a policy
// written from memory goes wrong:
//
//   - HeadBucket and ListObjectsV2 are both s3:ListBucket.
//   - HeadObject is s3:GetObject.
//   - The bucket-configuration calls are named for the resource
//     (s3:GetEncryptionConfiguration, s3:PutBucketPublicAccessBlock), not the
//     operation.
//   - Three of the four multipart calls are s3:PutObject; only the abort has
//     an action of its own.
var callActions = map[string]iamAction{
	"HeadBucket":                      {"s3:ListBucket", false},
	"CreateBucket":                    {"s3:CreateBucket", false},
	"GetPublicAccessBlock":            {"s3:GetBucketPublicAccessBlock", false},
	"PutPublicAccessBlock":            {"s3:PutBucketPublicAccessBlock", false},
	"GetBucketVersioning":             {"s3:GetBucketVersioning", false},
	"PutBucketVersioning":             {"s3:PutBucketVersioning", false},
	"GetBucketEncryption":             {"s3:GetEncryptionConfiguration", false},
	"PutBucketEncryption":             {"s3:PutEncryptionConfiguration", false},
	"GetBucketLifecycleConfiguration": {"s3:GetLifecycleConfiguration", false},
	"PutBucketLifecycleConfiguration": {"s3:PutLifecycleConfiguration", false},
	"ListObjectsV2":                   {"s3:ListBucket", false},
	"HeadObject":                      {"s3:GetObject", true},
	"GetObject":                       {"s3:GetObject", true},
	"PutObject":                       {"s3:PutObject", true},
	"DeleteObject":                    {"s3:DeleteObject", true},
	"CreateMultipartUpload":           {"s3:PutObject", true},
	"UploadPart":                      {"s3:PutObject", true},
	"CompleteMultipartUpload":         {"s3:PutObject", true},
	"AbortMultipartUpload":            {"s3:AbortMultipartUpload", true},
}

// Policy is an IAM identity policy document.
type Policy struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

// Statement is one Allow statement. Action is kept sorted so two runs over
// the same call set print the same document.
type Statement struct {
	Sid      string   `json:"Sid"`
	Effect   string   `json:"Effect"`
	Action   []string `json:"Action"`
	Resource string   `json:"Resource"`
}

// Actions returns every action the policy grants, sorted and deduplicated.
func (p Policy) Actions() []string {
	var out []string
	for _, st := range p.Statement {
		out = append(out, st.Action...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// SetupPolicy grants what InitBucket calls, and nothing a running service
// needs beyond the prefix markers it writes. It is for whoever runs
// `bodega init`, who is often not whoever runs bodega.
func SetupPolicy(bucket, region string) (Policy, error) {
	return policyFor(reflect.TypeFor[BucketAPI](), bucket, region)
}

// RuntimePolicy grants what Client calls: object reads and writes, listing,
// and aborting a failed multipart upload. It carries no bucket-configuration
// action, so a compromised service cannot switch off the public-access block
// or versioning, and no s3:DeleteObjectVersion, so it cannot remove the
// history versioning keeps.
func RuntimePolicy(bucket, region string) (Policy, error) {
	return policyFor(reflect.TypeFor[ObjectAPI](), bucket, region)
}

// bucketName is the S3 naming rule. It is enforced here because the name is
// interpolated into an ARN, and a "*" reaching one would grant every bucket
// in the account.
var bucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

func policyFor(api reflect.Type, bucket, region string) (Policy, error) {
	if !bucketName.MatchString(bucket) {
		return Policy{}, fmt.Errorf("bucket %q is not a valid S3 bucket name (3-63 characters: lowercase letters, digits, '.' and '-')", bucket)
	}
	var bucketActions, objectActions []string
	for i := range api.NumMethod() {
		name := api.Method(i).Name
		a, ok := callActions[name]
		if !ok {
			return Policy{}, fmt.Errorf("%s.%s has no IAM action in callActions", api.Name(), name)
		}
		if a.object {
			objectActions = append(objectActions, a.name)
		} else {
			bucketActions = append(bucketActions, a.name)
		}
	}
	slices.Sort(bucketActions)
	slices.Sort(objectActions)

	arn := "arn:" + partition(region) + ":s3:::" + bucket
	p := Policy{Version: "2012-10-17"}
	if len(bucketActions) > 0 {
		p.Statement = append(p.Statement, Statement{
			Sid: "Bucket", Effect: "Allow", Action: slices.Compact(bucketActions), Resource: arn,
		})
	}
	if len(objectActions) > 0 {
		p.Statement = append(p.Statement, Statement{
			Sid: "Objects", Effect: "Allow", Action: slices.Compact(objectActions), Resource: arn + "/*",
		})
	}
	return p, nil
}

// partition names the ARN partition a region belongs to. A policy naming
// arn:aws in GovCloud or China matches no resource and refuses everything.
func partition(region string) string {
	switch {
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov"
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn"
	}
	return "aws"
}

// AccessReport is what CheckAccess proved, per IAM action. The three lists
// are disjoint, and an action in none of them was never reached: a probe
// before it returned an error.
type AccessReport struct {
	Allowed   []string // the API answered without refusing
	Missing   []string // the API refused
	Unchecked []string // no probe can answer without writing, or an earlier refusal hid the answer
}

// CheckAccess asks the bucket whether the current credentials hold what
// RuntimePolicy grants, writing one line per probe to out, and reports each
// action as allowed, refused or not checked. It writes nothing to the bucket:
// s3:PutObject is proven with a conditional PUT against the manifests/
// marker, which S3 authorizes before it evaluates the condition and then
// refuses with 412.
// s3:DeleteObject and s3:AbortMultipartUpload cannot be proven without a
// write, and the output says so rather than claiming them.
//
// A refusal counts only when the API returned it. An error raised before a
// request was signed, or one the network returned, says nothing about the
// policy, and CheckAccess returns it as an error instead of a missing action.
func CheckAccess(ctx context.Context, api ObjectAPI, out io.Writer, bucket, region string) (AccessReport, error) {
	if out == nil {
		out = io.Discard
	}
	var r AccessReport
	refused := func(step, action string, err error) {
		r.Missing = append(r.Missing, action)
		fmt.Fprintf(out, "  %-11s refused by the API (%s); grant %s on %s\n", step+":", apiCode(err), action, resourceFor(bucket, region, action))
	}

	_, err := api.ListObjectsV2(ctx, &awss3.ListObjectsV2Input{
		Bucket:  aws.String(bucket),
		MaxKeys: aws.Int32(1),
	})
	switch {
	case err == nil:
		r.Allowed = append(r.Allowed, "s3:ListBucket")
		fmt.Fprintf(out, "  list:       allowed (s3:ListBucket)\n")
	case apiCode(err) == "NoSuchBucket":
		fmt.Fprintf(out, "  bucket:     does not exist; run `bodega init` with the setup policy first\n")
		return r, fmt.Errorf("bucket %s does not exist", bucket)
	case isRedirect(err):
		fmt.Fprintf(out, "  bucket:     lives in another region; set region to the bucket's own\n")
		return r, fmt.Errorf("bucket %s is not in the configured region: %w", bucket, err)
	case isRefusal(err):
		refused("list", "s3:ListBucket", err)
	default:
		return r, notFromAPI("list", err)
	}

	// The manifests/ marker is the one key InitBucket guarantees, and a
	// zero-byte object. A 404 answers the question as well as a 200 does,
	// provided s3:ListBucket was granted: without it S3 reports a missing key
	// as 403 so as not to confirm what exists.
	marker := manifest.ManifestsPrefix
	head, err := api.HeadObject(ctx, &awss3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(marker),
	})
	markerPresent := false
	listRefused := slices.Contains(r.Missing, "s3:ListBucket")
	switch {
	case err == nil:
		markerPresent = aws.ToInt64(head.ContentLength) == 0
		r.Allowed = append(r.Allowed, "s3:GetObject")
		fmt.Fprintf(out, "  read:       allowed (s3:GetObject)\n")
	case isNotFound(err):
		r.Allowed = append(r.Allowed, "s3:GetObject")
		fmt.Fprintf(out, "  read:       allowed (s3:GetObject)\n")
	case isRefusal(err) && listRefused:
		r.Unchecked = append(r.Unchecked, "s3:GetObject")
		fmt.Fprintf(out, "  read:       not checked: without s3:ListBucket, S3 answers 403 for a missing key as well as a refused one\n")
	case isRefusal(err):
		refused("read", "s3:GetObject", err)
	default:
		return r, notFromAPI("read", err)
	}

	if markerPresent {
		_, err = api.PutObject(ctx, &awss3.PutObjectInput{
			Bucket:      aws.String(bucket),
			Key:         aws.String(marker),
			IfNoneMatch: aws.String("*"),
		})
		switch {
		case err == nil:
			// Only a store that ignores If-None-Match reaches this, and it
			// rewrote a zero-byte marker with zero bytes.
			r.Allowed = append(r.Allowed, "s3:PutObject")
			fmt.Fprintf(out, "  write:      allowed (s3:PutObject); this store ignored If-None-Match and rewrote the empty %s marker\n", marker)
		case isPreconditionFailed(err):
			r.Allowed = append(r.Allowed, "s3:PutObject")
			fmt.Fprintf(out, "  write:      allowed (s3:PutObject)\n")
		case isRefusal(err):
			refused("write", "s3:PutObject", err)
		default:
			return r, notFromAPI("write", err)
		}
	} else {
		r.Unchecked = append(r.Unchecked, "s3:PutObject")
		fmt.Fprintf(out, "  write:      not checked: no empty %s marker to test against without writing; run `bodega init`\n", marker)
	}

	r.Unchecked = append(r.Unchecked, "s3:DeleteObject", "s3:AbortMultipartUpload")
	fmt.Fprintf(out, "  delete:     not checked: s3:DeleteObject and s3:AbortMultipartUpload cannot be proven without a write\n")
	return r, nil
}

func resourceFor(bucket, region, action string) string {
	arn := "arn:" + partition(region) + ":s3:::" + bucket
	for _, a := range callActions {
		if a.name == action && a.object {
			return arn + "/*"
		}
	}
	return arn
}

// isRefusal reports a 403 the API returned. HeadObject's has no body, so its
// code is "Forbidden" rather than "AccessDenied"; the status is what both
// share.
func isRefusal(err error) bool {
	var re *awshttp.ResponseError
	return errors.As(err, &re) && re.HTTPStatusCode() == http.StatusForbidden
}

func isPreconditionFailed(err error) bool {
	var re *awshttp.ResponseError
	return errors.As(err, &re) && re.HTTPStatusCode() == http.StatusPreconditionFailed
}

func isRedirect(err error) bool {
	var re *awshttp.ResponseError
	return (errors.As(err, &re) && re.HTTPStatusCode() == http.StatusMovedPermanently) ||
		apiCode(err) == "PermanentRedirect"
}

func apiCode(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode()
	}
	return ""
}

func notFromAPI(step string, err error) error {
	return fmt.Errorf("%s: no answer from the S3 API, so this says nothing about the policy "+
		"(check the credentials the AWS default chain resolves, AWS_PROFILE, and the network): %w", step, err)
}
