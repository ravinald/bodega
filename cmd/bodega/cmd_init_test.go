package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	bos3 "github.com/ravinald/bodega/internal/s3"
	"github.com/ravinald/bodega/internal/storage"
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
		// Left to the SDK chain, as the service's resolver leaves it; the
		// global region belongs to the default backend alone.
		{name: "named without a region leaves it empty", config: named, args: []string{"nearby"}, want: s3Target{name: "nearby", bucket: "nearby-bucket"}},
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

// isolateAWS points the SDK at a shared config holding profileRegion as the
// selected profile's region, or at no config at all when it is empty, so
// nothing on the host reaches the client under test.
func isolateAWS(t *testing.T, profileRegion string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "absent"))
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	if profileRegion == "" {
		t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "absent"))
		t.Setenv("AWS_PROFILE", "")
		return
	}
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte("[profile p]\nregion = "+profileRegion+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", path)
	t.Setenv("AWS_PROFILE", "p")
}

func runInit(t *testing.T, config string, args ...string) (string, error) {
	t.Helper()
	t.Setenv("REPO_BUCKET", "")
	isolateAWS(t, "")
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

// TestInitDialsTheRegionTheServiceDials is the case where init used to fill a
// named entry's empty region with the global one while the service left it to
// the SDK: under a profile naming eu-west-1, init created the bucket in
// us-west-2 and the service then dialed eu-west-1. Both now build the client
// with bos3.NewClient from storage.SpecFor.
func TestInitDialsTheRegionTheServiceDials(t *testing.T) {
	const body = `{
	  "storage_backend": "s3", "bucket": "main-bucket", "region": "us-west-2",
	  "storage_backends": {
	    "nearby": {"driver": "s3", "bucket": "nearby-bucket"},
	    "pinned": {"driver": "s3", "bucket": "pinned-bucket", "region": "ap-south-1"}
	  }
	}`
	t.Setenv("REPO_BUCKET", "")
	isolateAWS(t, "eu-west-1")
	cfg := loadFrom(t, body)
	ctx := context.Background()
	for name, want := range map[string]string{"default": "us-west-2", "nearby": "eu-west-1", "pinned": "ap-south-1"} {
		target, err := resolveS3Target(cfg, []string{name})
		if err != nil {
			t.Fatal(err)
		}
		client, err := dialS3Target(ctx, target)
		if err != nil {
			t.Fatal(err)
		}
		spec, _ := storage.SpecFor(cfg, name)
		service, err := bos3.NewClient(ctx, spec.Bucket, spec.Region)
		if err != nil {
			t.Fatal(err)
		}
		if client.Region() != want || service.Region() != want {
			t.Errorf("%s: init dials %q, service dials %q, want %q", name, client.Region(), service.Region(), want)
		}
	}
}

func TestInitRefusesABackendNoChainGivesARegion(t *testing.T) {
	const body = `{"storage_backend": "s3", "bucket": "main-bucket",
	  "storage_backends": {"nearby": {"driver": "s3", "bucket": "nearby-bucket"}}}`
	for _, args := range [][]string{{"nearby", "--print-policy"}, {"check", "nearby"}, {"nearby"}} {
		_, err := runInit(t, body, args...)
		if err == nil || !strings.Contains(err.Error(), `add "region" to that entry`) {
			t.Errorf("init %v: err = %v, want a refusal naming the missing region", args, err)
		}
	}
}

// TestCheckVerdictNamesWhatItDidNotProve holds the closing line of `init
// check`, the one read at 03:00, to what the probes answered.
func TestCheckVerdictNamesWhatItDidNotProve(t *testing.T) {
	target := s3Target{name: "archive", bucket: "archive-bucket"}
	cases := []struct {
		name   string
		report bos3.AccessReport
		want   []string
	}{
		{
			name: "every probe answered",
			report: bos3.AccessReport{
				Allowed:   []string{"s3:ListBucket", "s3:GetObject", "s3:PutObject"},
				Unchecked: []string{"s3:DeleteObject", "s3:AbortMultipartUpload"},
			},
			want: []string{"allowed s3:ListBucket, s3:GetObject, s3:PutObject; not checked: s3:DeleteObject, s3:AbortMultipartUpload."},
		},
		{
			name: "no marker, so the write probe was skipped",
			report: bos3.AccessReport{
				Allowed:   []string{"s3:ListBucket", "s3:GetObject"},
				Unchecked: []string{"s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload"},
			},
			want: []string{"not checked: s3:PutObject, s3:DeleteObject", "Writing was not proven", "run `bodega init archive`, then check again"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			writeCheckVerdict(&out, target, []string{"archive"}, tc.report)
			for _, want := range tc.want {
				if !strings.Contains(out.String(), want) {
					t.Errorf("verdict lacks %q:\n%s", want, out.String())
				}
			}
			if strings.Contains(out.String(), "can run bodega") {
				t.Errorf("verdict claims more than the probes answered:\n%s", out.String())
			}
		})
	}
}
