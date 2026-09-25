package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"

	bos3 "github.com/ravinald/bodega/internal/s3"
)

func TestResolveS3Target(t *testing.T) {
	const named = `{
	  "storage_backend": "s3", "bucket": "main-bucket", "region": "eu-west-1",
	  "storage_backends": {
	    "archive": {"driver": "s3", "bucket": "archive-bucket", "region": "us-east-1", "prefix": "cold"},
	    "nearby":  {"driver": "s3", "bucket": "nearby-bucket"},
	    "bulk":    {"driver": "local", "path": "/srv/bulk"},
	    "nobucket":{"driver": "s3"}
	  }
	}`
	cases := []struct {
		name    string
		config  string
		args    []string
		want    s3Target
		wantErr string
	}{
		{name: "default", config: named, want: s3Target{name: "default", bucket: "main-bucket", region: "eu-west-1"}},
		{name: "named", config: named, args: []string{"archive"}, want: s3Target{name: "archive", bucket: "archive-bucket", region: "us-east-1", prefix: "cold"}},
		{name: "named without a region takes the global one", config: named, args: []string{"nearby"}, want: s3Target{name: "nearby", bucket: "nearby-bucket", region: "eu-west-1"}},
		{name: "named local", config: named, args: []string{"bulk"}, wantErr: `"bulk" uses the local driver`},
		{name: "unknown", config: named, args: []string{"nope"}, wantErr: "configured: default, archive, bulk, nearby, nobucket"},
		{name: "named s3 without a bucket", config: named, args: []string{"nobucket"}, wantErr: `storage_backends["nobucket"]`},
		// The case that used to dial AWS: a local install that happens to
		// carry a bucket key.
		{name: "local default with a bucket set", config: `{"bucket": "stray"}`, wantErr: `"default" uses the local driver`},
		{name: "s3 default without a bucket", config: `{"storage_backend": "s3"}`, wantErr: "S3 bucket is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("REPO_BUCKET", "")
			t.Setenv("AWS_REGION", "")
			cfg := loadFrom(t, tc.config)
			got, err := resolveS3Target(cfg, tc.args)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("target = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func runInit(t *testing.T, config string, args ...string) (string, error) {
	t.Helper()
	t.Setenv("REPO_BUCKET", "")
	t.Setenv("AWS_REGION", "")
	loadFrom(t, config)
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"init"}, args...))
	err := root.Execute()
	return out.String(), err
}

func TestPrintPolicyEmitsOneDocumentAlone(t *testing.T) {
	const cfg = `{"storage_backend": "s3", "bucket": "b-b", "region": "us-west-2"}`
	for which, gen := range map[string]func(string, string) (bos3.Policy, error){
		"setup":   bos3.SetupPolicy,
		"runtime": bos3.RuntimePolicy,
	} {
		t.Run(which, func(t *testing.T) {
			out, err := runInit(t, cfg, "--print-policy="+which)
			if err != nil {
				t.Fatal(err)
			}
			var got bos3.Policy
			if err := json.Unmarshal([]byte(out), &got); err != nil {
				t.Fatalf("output is not one JSON document: %v\n%s", err, out)
			}
			want, _ := gen("b-b", "us-west-2")
			if !reflect.DeepEqual(got, want) {
				t.Errorf("printed %+v, want %+v", got, want)
			}
		})
	}
}

func TestPrintPolicyBothChangesNothing(t *testing.T) {
	out, err := runInit(t, `{"storage_backend": "s3", "bucket": "b-b"}`, "--print-policy")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"  setup: ", "  runtime: ", `"s3:CreateBucket"`, `"s3:AbortMultipartUpload"`} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if w := regexp.MustCompile(`\b[A-Z]{3,}\b`).FindString(out); w != "" {
		t.Errorf("--print-policy output carries %q, which reads as a change:\n%s", w, out)
	}
}

func TestPrintPolicyRefusesUnknownValueAndLocalBackend(t *testing.T) {
	if _, err := runInit(t, `{"storage_backend": "s3", "bucket": "b-b"}`, "--print-policy=admin"); err == nil ||
		!strings.Contains(err.Error(), "want setup, runtime") {
		t.Errorf("err = %v, want a refusal naming the values", err)
	}
	if _, err := runInit(t, `{"bucket": "b-b"}`, "--print-policy"); err == nil ||
		!strings.Contains(err.Error(), "local driver") {
		t.Errorf("err = %v, want the local backend refused", err)
	}
}
