package s3

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// The SDK client has to satisfy both call sets, or the interfaces name a
// method the policies grant and nothing can call.
var (
	_ BucketAPI = (*awss3.Client)(nil)
	_ ObjectAPI = (*awss3.Client)(nil)
)

// TestEveryCallMapsToAnAction is what makes a call added later a policy line
// added later: a method on either interface with no entry in callActions
// fails here, and an entry no interface names is a grant nothing uses.
func TestEveryCallMapsToAnAction(t *testing.T) {
	used := map[string]bool{}
	for _, api := range []reflect.Type{reflect.TypeFor[BucketAPI](), reflect.TypeFor[ObjectAPI]()} {
		for i := range api.NumMethod() {
			name := api.Method(i).Name
			if _, ok := callActions[name]; !ok {
				t.Errorf("%s.%s has no entry in callActions; add the IAM action that authorizes it", api.Name(), name)
			}
			used[name] = true
		}
	}
	for name := range callActions {
		if !used[name] {
			t.Errorf("callActions maps %s, which neither BucketAPI nor ObjectAPI calls", name)
		}
	}
}

// The expected documents are written out rather than derived, because the
// point is to catch the derivation. They match the bodega-s3-setup and
// bodega-s3-runtime roles built by hand in the development account, with two
// recorded differences: the setup policy adds the two lifecycle actions that
// role lacks, and the runtime policy omits s3:ListMultipartUploadParts, which
// authorizes ListParts, a call the uploader never makes.
const (
	wantSetup = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Bucket",
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketVersioning",
        "s3:GetEncryptionConfiguration",
        "s3:GetLifecycleConfiguration",
        "s3:ListBucket",
        "s3:PutBucketPublicAccessBlock",
        "s3:PutBucketVersioning",
        "s3:PutEncryptionConfiguration",
        "s3:PutLifecycleConfiguration"
      ],
      "Resource": "arn:aws:s3:::bodega-dev-975648378721"
    },
    {
      "Sid": "Objects",
      "Effect": "Allow",
      "Action": [
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::bodega-dev-975648378721/*"
    }
  ]
}`
	wantRuntime = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Bucket",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket"
      ],
      "Resource": "arn:aws:s3:::bodega-dev-975648378721"
    },
    {
      "Sid": "Objects",
      "Effect": "Allow",
      "Action": [
        "s3:AbortMultipartUpload",
        "s3:DeleteObject",
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::bodega-dev-975648378721/*"
    }
  ]
}`
)

func TestPoliciesMatchTheRecordedRoles(t *testing.T) {
	for _, tc := range []struct {
		name string
		gen  func(bucket, region string) (Policy, error)
		want string
	}{
		{"setup", SetupPolicy, wantSetup},
		{"runtime", RuntimePolicy, wantRuntime},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := tc.gen("bodega-dev-975648378721", "us-west-2")
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.MarshalIndent(p, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("%s policy =\n%s\nwant\n%s", tc.name, got, tc.want)
			}
		})
	}
}

// TestRuntimePolicyWithholdsWhatVersioningProtects asserts the absence by
// name. Deriving the policy from ObjectAPI omits these today only because
// nothing calls them, and a derived policy grows silently the day something
// does. s3:DeleteObjectVersion is the one that matters most: a manifest
// rewritten under versioning leaves its previous version in place, and this
// is the action that would remove it.
func TestRuntimePolicyWithholdsWhatVersioningProtects(t *testing.T) {
	p, err := RuntimePolicy("b-b", "us-west-2")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"s3:DeleteObjectVersion", "s3:PutBucketVersioning", "s3:DeleteBucket"} {
		if slices.Contains(p.Actions(), forbidden) {
			t.Errorf("runtime policy grants %s", forbidden)
		}
	}
	for _, st := range p.Statement {
		for _, a := range st.Action {
			if strings.Contains(a, "*") {
				t.Errorf("runtime policy grants wildcard action %s", a)
			}
		}
	}
}

func TestSetupPolicyCannotDeleteTheBucket(t *testing.T) {
	p, err := SetupPolicy("b-b", "us-west-2")
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(p.Actions(), "s3:DeleteBucket") {
		t.Error("setup policy grants s3:DeleteBucket")
	}
}

func TestPolicyRefusesABucketNameThatWidensTheARN(t *testing.T) {
	for _, bucket := range []string{"", "*", "bodega-*", "Bodega", "a", "b/c", "b?b"} {
		if _, err := RuntimePolicy(bucket, "us-west-2"); err == nil {
			t.Errorf("RuntimePolicy(%q) accepted the name", bucket)
		}
	}
}

func TestPolicyNamesThePartitionTheRegionIsIn(t *testing.T) {
	for region, want := range map[string]string{
		"us-west-2":     "arn:aws:s3:::b-b",
		"us-gov-west-1": "arn:aws-us-gov:s3:::b-b",
		"cn-north-1":    "arn:aws-cn:s3:::b-b",
	} {
		p, err := RuntimePolicy("b-b", region)
		if err != nil {
			t.Fatal(err)
		}
		if p.Statement[0].Resource != want {
			t.Errorf("%s: resource = %s, want %s", region, p.Statement[0].Resource, want)
		}
	}
}

// fakeObjects answers CheckAccess's three probes and records any call that
// would change the bucket.
type fakeObjects struct {
	ObjectAPI // nil: any call CheckAccess is not expected to make panics

	listErr   error
	headErr   error
	headSize  int64
	putErr    error
	putCalled *awss3.PutObjectInput
}

func (f *fakeObjects) ListObjectsV2(context.Context, *awss3.ListObjectsV2Input, ...func(*awss3.Options)) (*awss3.ListObjectsV2Output, error) {
	return &awss3.ListObjectsV2Output{}, f.listErr
}

func (f *fakeObjects) HeadObject(context.Context, *awss3.HeadObjectInput, ...func(*awss3.Options)) (*awss3.HeadObjectOutput, error) {
	if f.headErr != nil {
		return nil, f.headErr
	}
	return &awss3.HeadObjectOutput{ContentLength: aws.Int64(f.headSize)}, nil
}

func (f *fakeObjects) PutObject(_ context.Context, in *awss3.PutObjectInput, _ ...func(*awss3.Options)) (*awss3.PutObjectOutput, error) {
	f.putCalled = in
	return &awss3.PutObjectOutput{}, f.putErr
}

func TestCheckAccess(t *testing.T) {
	denied := func(op string) error { return sdkErr(op, 403, &smithy.GenericAPIError{Code: "AccessDenied"}) }
	precondition := sdkErr("PutObject", 412, &smithy.GenericAPIError{Code: "PreconditionFailed"})
	cases := []struct {
		name        string
		f           fakeObjects
		wantMissing []string
		// wantUnchecked is compared only when set.
		wantUnchecked []string
		wantErr       string
		wantLines     []string
		wantPut       bool
	}{
		{
			name:          "runtime policy passes",
			f:             fakeObjects{putErr: precondition},
			wantUnchecked: []string{"s3:DeleteObject", "s3:AbortMultipartUpload"},
			wantLines:     []string{"  list:       allowed (s3:ListBucket)", "  read:       allowed (s3:GetObject)", "  write:      allowed (s3:PutObject)", "  delete:     not checked"},
			wantPut:       true,
		},
		{
			name:        "list refused leaves a 403 on read ambiguous",
			f:           fakeObjects{listErr: denied("ListObjectsV2"), headErr: sdkErr("HeadObject", 403, &smithy.GenericAPIError{Code: "Forbidden"})},
			wantMissing: []string{"s3:ListBucket"},
			wantLines:   []string{"  list:       refused by the API (AccessDenied); grant s3:ListBucket on arn:aws:s3:::b-b", "  read:       not checked", "  write:      not checked"},
		},
		{
			name:        "read refused names s3:GetObject on the objects",
			f:           fakeObjects{headErr: sdkErr("HeadObject", 403, &smithy.GenericAPIError{Code: "Forbidden"})},
			wantMissing: []string{"s3:GetObject"},
			wantLines:   []string{"  read:       refused by the API (Forbidden); grant s3:GetObject on arn:aws:s3:::b-b/*"},
		},
		{
			name:        "write refused",
			f:           fakeObjects{putErr: denied("PutObject")},
			wantMissing: []string{"s3:PutObject"},
			wantLines:   []string{"  write:      refused by the API (AccessDenied); grant s3:PutObject on arn:aws:s3:::b-b/*"},
			wantPut:     true,
		},
		{
			name:          "an absent marker is read access, and no write is attempted",
			f:             fakeObjects{headErr: sdkErr("HeadObject", 404, &types.NotFound{})},
			wantUnchecked: []string{"s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload"},
			wantLines:     []string{"  read:       allowed (s3:GetObject)", "  write:      not checked: no empty manifests/ marker"},
		},
		{
			name:      "a non-empty object at the marker key is never written",
			f:         fakeObjects{headSize: 12},
			wantLines: []string{"  write:      not checked"},
		},
		{
			name:    "missing bucket",
			f:       fakeObjects{listErr: sdkErr("ListObjectsV2", 404, &types.NoSuchBucket{})},
			wantErr: "does not exist",
		},
		{
			name:    "wrong region",
			f:       fakeObjects{listErr: sdkErr("ListObjectsV2", 301, &smithy.GenericAPIError{Code: "PermanentRedirect"})},
			wantErr: "not in the configured region",
		},
		{
			// No credentials, a client-side validation failure, a dead
			// network: none of these reached the API, so none is a denial.
			name:    "an error the API did not return is not a refusal",
			f:       fakeObjects{listErr: errors.New("failed to retrieve credentials")},
			wantErr: "no answer from the S3 API",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			report, err := CheckAccess(context.Background(), &tc.f, &out, "b-b", "us-west-2")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(report.Missing, tc.wantMissing) {
				t.Errorf("missing = %v, want %v", report.Missing, tc.wantMissing)
			}
			if tc.wantUnchecked != nil && !slices.Equal(report.Unchecked, tc.wantUnchecked) {
				t.Errorf("unchecked = %v, want %v", report.Unchecked, tc.wantUnchecked)
			}
			seen := map[string]string{}
			for list, actions := range map[string][]string{"allowed": report.Allowed, "missing": report.Missing, "unchecked": report.Unchecked} {
				for _, a := range actions {
					if prev, dup := seen[a]; dup {
						t.Errorf("%s reported both %s and %s", a, prev, list)
					}
					seen[a] = list
				}
			}
			for _, line := range tc.wantLines {
				if !strings.Contains(out.String(), line) {
					t.Errorf("output lacks %q:\n%s", line, out.String())
				}
			}
			if (tc.f.putCalled != nil) != tc.wantPut {
				t.Fatalf("PutObject called = %v, want %v", tc.f.putCalled != nil, tc.wantPut)
			}
			if tc.f.putCalled != nil && aws.ToString(tc.f.putCalled.IfNoneMatch) != "*" {
				t.Errorf("PutObject sent without If-None-Match: *, so it would overwrite")
			}
			assertNoChangeMarkers(t, out.String())
		})
	}
}

// assertNoChangeMarkers holds read-only output to the init convention:
// UPPERCASE means this run changed something, and check changes nothing.
func assertNoChangeMarkers(t *testing.T, out string) {
	t.Helper()
	for _, word := range regexp.MustCompile(`\b[A-Z]{3,}\b`).FindAllString(out, -1) {
		if word != "API" {
			t.Errorf("read-only output carries %q, which reads as a change:\n%s", word, out)
		}
	}
}

// TestUsageDocPoliciesAreTheGeneratedOnes holds the two policies printed in
// docs/usage.md against the generator, so the page an operator copies from
// cannot fall behind a call added later. It compares parsed documents because
// the formatter reflows the JSON.
func TestUsageDocPoliciesAreTheGeneratedOnes(t *testing.T) {
	raw, err := os.ReadFile("../../docs/usage.md")
	if err != nil {
		t.Fatal(err)
	}
	var docs []Policy
	for _, m := range regexp.MustCompile("(?s)```json\n(\\{[^`]*?\"2012-10-17\"[^`]*?)```").FindAllStringSubmatch(string(raw), -1) {
		var p Policy
		if err := json.Unmarshal([]byte(m[1]), &p); err != nil {
			t.Fatalf("policy block in docs/usage.md does not parse: %v\n%s", err, m[1])
		}
		docs = append(docs, p)
	}
	var want []Policy
	for _, gen := range []func(string, string) (Policy, error){SetupPolicy, RuntimePolicy} {
		p, err := gen("example-bodega-artifacts", "us-west-2")
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, p)
	}
	if !reflect.DeepEqual(docs, want) {
		t.Errorf("docs/usage.md policy blocks = %+v\nwant setup then runtime as generated: %+v", docs, want)
	}
}
