package s3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
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

type recordingTransport struct{ url string }

func (r *recordingTransport) Do(req *http.Request) (*http.Response, error) {
	r.url = req.URL.Scheme + "://" + req.URL.Host + req.URL.Path
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
}

// TestRouteIsWhereTheSDKSendsARequest holds Route to the request itself: for
// each configuration it records the URL a GetObject leaves the client for,
// with a transport that answers in memory, and requires Route to name it.
// The cases are the settings the SDK infers at request time rather than
// reading off the client's options.
func TestRouteIsWhereTheSDKSendsARequest(t *testing.T) {
	cases := []struct {
		name, region, bucket string
		opts                 Options
		env                  map[string]string
		want                 string
	}{
		{name: "region", region: "us-west-2", bucket: "artifacts", want: "https://artifacts.s3.us-west-2.amazonaws.com/key"},
		{name: "fips prefix", region: "fips-us-west-2", bucket: "artifacts", want: "https://artifacts.s3-fips.us-west-2.amazonaws.com/key"},
		{name: "fips suffix", region: "us-gov-west-1-fips", bucket: "artifacts", want: "https://artifacts.s3-fips.us-gov-west-1.amazonaws.com/key"},
		{name: "fips from the environment", region: "us-west-2", bucket: "artifacts",
			env: map[string]string{"AWS_USE_FIPS_ENDPOINT": "true"}, want: "https://artifacts.s3-fips.us-west-2.amazonaws.com/key"},
		{name: "dual stack from the environment", region: "us-west-2", bucket: "artifacts",
			env: map[string]string{"AWS_USE_DUALSTACK_ENDPOINT": "true"}, want: "https://artifacts.s3.dualstack.us-west-2.amazonaws.com/key"},
		{name: "fips path style", region: "fips-us-west-2", bucket: "artifacts", opts: Options{PathStyle: true},
			want: "https://s3-fips.us-west-2.amazonaws.com/artifacts/key"},
		{name: "dotted bucket", region: "us-west-2", bucket: "a.b", want: "https://s3.us-west-2.amazonaws.com/a.b/key"},
		{name: "endpoint path, path style", region: "us-east-1", bucket: "artifacts",
			opts: Options{Endpoint: "https://store.example.net/%74enant", PathStyle: true}, want: "https://store.example.net/tenant/artifacts/key"},
		{name: "endpoint, virtual host", region: "us-ord-1", bucket: "artifacts",
			opts: Options{Endpoint: "https://us-ord-1.linodeobjects.com"}, want: "https://artifacts.us-ord-1.linodeobjects.com/key"},
		{name: "endpoint from the environment", region: "us-east-1", bucket: "artifacts",
			env: map[string]string{"AWS_ENDPOINT_URL_S3": "http://127.0.0.1:9000"}, want: "http://127.0.0.1:9000/artifacts/key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateSDK(t)
			for _, env := range []string{"AWS_USE_FIPS_ENDPOINT", "AWS_USE_DUALSTACK_ENDPOINT"} {
				t.Setenv(env, "")
			}
			t.Setenv("AWS_ACCESS_KEY_ID", "test")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			client, err := NewClient(t.Context(), tc.bucket, tc.region, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			wire := &recordingTransport{}
			out, err := client.S3Client().GetObject(t.Context(), &awss3.GetObjectInput{
				Bucket: aws.String(tc.bucket), Key: aws.String("key"),
			}, func(o *awss3.Options) { o.HTTPClient = wire })
			if err != nil {
				t.Fatal(err)
			}
			_ = out.Body.Close()
			route, err := client.Route(t.Context())
			if err != nil {
				t.Fatalf("Route: %v", err)
			}
			got := route.URL.Scheme + "://" + route.URL.Host + strings.TrimSuffix(route.URL.Path, "/") + "/key"
			if got != wire.url {
				t.Errorf("Route = %s; the SDK sent %s", got, wire.url)
			}
			if tc.want != "" && wire.url != tc.want {
				t.Errorf("the SDK sent %s; the case expects %s", wire.url, tc.want)
			}
		})
	}
}

type failingCredentials struct{ t *testing.T }

func (f failingCredentials) Retrieve(context.Context) (aws.Credentials, error) {
	f.t.Error("Route read the client's credentials")
	return aws.Credentials{}, errors.New("no credentials")
}

type failingTransport struct{ t *testing.T }

func (f failingTransport) Do(*http.Request) (*http.Response, error) {
	f.t.Error("Route sent a request")
	return nil, errors.New("no network")
}

// TestRouteReadsNoCredentialAndSendsNothing keeps Route usable before a
// move has proven it can sign anything, and off the network in every test
// that compares two stores.
func TestRouteReadsNoCredentialAndSendsNothing(t *testing.T) {
	for _, bucket := range []string{"artifacts", "artifacts--usw2-az1--x-s3"} {
		client := NewClientFromConfig(aws.Config{
			Region:      "us-west-2",
			Credentials: failingCredentials{t},
			HTTPClient:  failingTransport{t},
		}, bucket, "us-west-2")
		route, err := client.Route(t.Context())
		if err != nil {
			t.Fatalf("Route(%s): %v", bucket, err)
		}
		if !strings.HasPrefix(route.URL.Host, bucket+".") {
			t.Errorf("Route(%s) host = %s", bucket, route.URL.Host)
		}
	}
}

// TestRouteWithoutARegionStillNamesTheBucket pins the one place Route
// answers for a client that cannot send: no region resolves as us-east-1, so
// two region-less spellings of one bucket still compare.
func TestRouteWithoutARegionStillNamesTheBucket(t *testing.T) {
	client := NewClientFromConfig(aws.Config{}, "artifacts", "")
	route, err := client.Route(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got := route.URL.String(); got != "https://artifacts.s3.us-east-1.amazonaws.com" {
		t.Errorf("Route = %s", got)
	}
}
