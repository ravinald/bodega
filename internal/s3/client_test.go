package s3

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// sdkErr builds the chain the SDK returns: an operation error wrapping a
// response error that carries the status code and wraps the API error.
func sdkErr(op string, status int, apiErr error) error {
	return &smithy.OperationError{
		ServiceID:     "S3",
		OperationName: op,
		Err: &awshttp.ResponseError{
			ResponseError: &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
				Err:      apiErr,
			},
		},
	}
}

func TestIsNotFound(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unrelated error containing 404", fmt.Errorf("connect to 10.0.0.404: connection refused"), false},
		{"unrelated error containing NoSuchKey", errors.New("parse NoSuchKey fixture"), false},
		{"bare NoSuchKey", &types.NoSuchKey{}, true},
		{"NoSuchKey wrapped by fmt.Errorf", fmt.Errorf("get object: %w", &types.NoSuchKey{}), true},
		{"GetObject NoSuchKey from the SDK", sdkErr("GetObject", 404, &types.NoSuchKey{}), true},
		{"HeadObject NotFound from the SDK", sdkErr("HeadObject", 404, &types.NotFound{}), true},
		{"bare 404 response", sdkErr("GetObject", 404, errors.New("not found")), true},
		{"typed NoSuchBucket", &types.NoSuchBucket{}, false},
		{"typed NoSuchBucket in a 404", sdkErr("ListObjectsV2", 404, &types.NoSuchBucket{}), false},
		{"GetObject NoSuchBucket as generic API error in a 404", sdkErr("GetObject", 404, &smithy.GenericAPIError{Code: "NoSuchBucket"}), false},
		{"403 response", sdkErr("GetObject", 403, &smithy.GenericAPIError{Code: "AccessDenied"}), false},
		{"500 response", sdkErr("GetObject", 500, &smithy.GenericAPIError{Code: "InternalError"}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNotFound(tc.err); got != tc.want {
				t.Errorf("isNotFound(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// sdkEnv are the variables the SDK reads for what Options sets. isolateSDK
// clears them and the shared config, so a test sees only what it sets.
var sdkEnv = []string{"AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_S3", "AWS_REQUEST_CHECKSUM_CALCULATION", "AWS_RESPONSE_CHECKSUM_VALIDATION"}

func isolateSDK(t *testing.T) {
	t.Helper()
	for _, env := range sdkEnv {
		t.Setenv(env, "")
	}
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "none"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "none"))
}

func TestNewClientPassesEachKeyToTheSDK(t *testing.T) {
	cases := []struct {
		name          string
		opts          Options
		wantEndpoint  string
		wantPathStyle bool
		wantRequest   aws.RequestChecksumCalculation
		wantResponse  aws.ResponseChecksumValidation
	}{
		{
			name:         "endpoint",
			opts:         Options{Endpoint: "https://us-ord-1.linodeobjects.com"},
			wantEndpoint: "https://us-ord-1.linodeobjects.com",
			wantRequest:  aws.RequestChecksumCalculationWhenSupported,
			wantResponse: aws.ResponseChecksumValidationWhenSupported,
		},
		{
			name:          "path_style",
			opts:          Options{PathStyle: true},
			wantPathStyle: true,
			wantRequest:   aws.RequestChecksumCalculationWhenSupported,
			wantResponse:  aws.ResponseChecksumValidationWhenSupported,
		},
		{
			name:         "checksums when_required",
			opts:         Options{Checksums: ChecksumsWhenRequired},
			wantRequest:  aws.RequestChecksumCalculationWhenRequired,
			wantResponse: aws.ResponseChecksumValidationWhenRequired,
		},
		{
			name:         "checksums when_supported",
			opts:         Options{Checksums: ChecksumsWhenSupported},
			wantRequest:  aws.RequestChecksumCalculationWhenSupported,
			wantResponse: aws.ResponseChecksumValidationWhenSupported,
		},
		{
			name:          "all three",
			opts:          Options{Endpoint: "http://127.0.0.1:9000", PathStyle: true, Checksums: ChecksumsWhenRequired},
			wantEndpoint:  "http://127.0.0.1:9000",
			wantPathStyle: true,
			wantRequest:   aws.RequestChecksumCalculationWhenRequired,
			wantResponse:  aws.ResponseChecksumValidationWhenRequired,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateSDK(t)
			client, err := NewClient(context.Background(), "b", "us-ord", tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			got := client.S3Client().Options()
			if aws.ToString(got.BaseEndpoint) != tc.wantEndpoint {
				t.Errorf("BaseEndpoint = %q, want %q", aws.ToString(got.BaseEndpoint), tc.wantEndpoint)
			}
			if got.UsePathStyle != tc.wantPathStyle {
				t.Errorf("UsePathStyle = %v, want %v", got.UsePathStyle, tc.wantPathStyle)
			}
			if got.RequestChecksumCalculation != tc.wantRequest {
				t.Errorf("RequestChecksumCalculation = %v, want %v", got.RequestChecksumCalculation, tc.wantRequest)
			}
			if got.ResponseChecksumValidation != tc.wantResponse {
				t.Errorf("ResponseChecksumValidation = %v, want %v", got.ResponseChecksumValidation, tc.wantResponse)
			}
		})
	}
}

// TestNewClientLeavesUnsetKeysToTheSDK is the operator who already runs a
// compatible store through the SDK's environment: with no key set, what the
// SDK resolved must reach the client untouched, and a key that is set wins.
func TestNewClientLeavesUnsetKeysToTheSDK(t *testing.T) {
	isolateSDK(t)
	t.Setenv("AWS_ENDPOINT_URL_S3", "https://from-env.example.net")
	t.Setenv("AWS_REQUEST_CHECKSUM_CALCULATION", "when_required")
	t.Setenv("AWS_RESPONSE_CHECKSUM_VALIDATION", "when_required")

	client, err := NewClient(context.Background(), "b", "us-ord", Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := client.S3Client().Options()
	if aws.ToString(got.BaseEndpoint) != "https://from-env.example.net" {
		t.Errorf("BaseEndpoint = %q, want the one AWS_ENDPOINT_URL_S3 names", aws.ToString(got.BaseEndpoint))
	}
	if got.UsePathStyle {
		t.Error("UsePathStyle = true with path_style unset")
	}
	if got.RequestChecksumCalculation != aws.RequestChecksumCalculationWhenRequired ||
		got.ResponseChecksumValidation != aws.ResponseChecksumValidationWhenRequired {
		t.Errorf("checksums = %v/%v, want the environment's when_required for both",
			got.RequestChecksumCalculation, got.ResponseChecksumValidation)
	}

	client, err = NewClient(context.Background(), "b", "us-ord",
		Options{Endpoint: "https://from-config.example.net", Checksums: ChecksumsWhenSupported})
	if err != nil {
		t.Fatal(err)
	}
	got = client.S3Client().Options()
	if aws.ToString(got.BaseEndpoint) != "https://from-config.example.net" ||
		got.RequestChecksumCalculation != aws.RequestChecksumCalculationWhenSupported ||
		got.ResponseChecksumValidation != aws.ResponseChecksumValidationWhenSupported {
		t.Errorf("set keys lost to the environment: endpoint %q, checksums %v/%v",
			aws.ToString(got.BaseEndpoint), got.RequestChecksumCalculation, got.ResponseChecksumValidation)
	}
}

func TestNewClientRefusesAnUnknownChecksumsValue(t *testing.T) {
	isolateSDK(t)
	_, err := NewClient(context.Background(), "b", "us-ord", Options{Checksums: "never"})
	if err == nil || !strings.Contains(err.Error(), `checksums "never"`) || !strings.Contains(err.Error(), ChecksumsWhenRequired) {
		t.Errorf("err = %v, want a refusal naming the value and the ones accepted", err)
	}
}
