package s3

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

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
