package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
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
		service, err := bos3.NewClient(ctx, spec.Bucket, spec.Region, spec.S3Options())
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

// compatibleStore is an S3-compatible store with no public access block and
// no default encryption. It records each request as "METHOD
// path?subresource" and whether each object PUT carried a CRC32 checksum.
//
// It does not prove path_style: httptest listens on an IP address, and the
// SDK addresses a bucket path-style at an IP whatever the option says.
// TestNewClientPassesEachKeyToTheSDK in internal/s3 holds that key.
type compatibleStore struct {
	sync.Mutex
	requests   []string
	markerCRCs []bool
}

func (c *compatibleStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sub := ""
	for _, name := range []string{"publicAccessBlock", "versioning", "encryption", "lifecycle", "list-type"} {
		if r.URL.Query().Has(name) {
			sub = name
		}
	}
	c.Lock()
	c.requests = append(c.requests, r.Method+" "+r.URL.Path+"?"+sub)
	if r.Method == http.MethodPut && sub == "" {
		c.markerCRCs = append(c.markerCRCs, r.Header.Get("X-Amz-Checksum-Crc32") != "" || r.Header.Get("X-Amz-Trailer") != "")
	}
	c.Unlock()

	fail := func(status int, code string) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, code, code)
	}
	switch {
	case !strings.HasPrefix(r.URL.Path, "/bodega-onprem"):
		fail(http.StatusNotFound, "NoSuchBucket")
	case sub == "publicAccessBlock" || sub == "encryption":
		fail(http.StatusNotImplemented, "NotImplemented")
	case sub == "versioning" && r.Method == http.MethodGet:
		_, _ = w.Write([]byte(`<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>`))
	case sub == "lifecycle" && r.Method == http.MethodGet:
		fail(http.StatusNotFound, "NoSuchLifecycleConfiguration")
	case sub == "list-type":
		_, _ = w.Write([]byte(`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><KeyCount>0</KeyCount></ListBucketResult>`))
	}
}

func (c *compatibleStore) count(prefix string) int {
	c.Lock()
	defer c.Unlock()
	n := 0
	for _, r := range c.requests {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

// TestInitAgainstACompatibleStore runs `bodega init` through the real SDK to
// a store over HTTP, which is where the three keys and the not-implemented
// classification meet: the config key has to become a request line, and a 501
// with an XML body has to come back out of the SDK as a control to name.
func TestInitAgainstACompatibleStore(t *testing.T) {
	run := func(t *testing.T, checksums string, args ...string) (*compatibleStore, error) {
		store := &compatibleStore{}
		srv := httptest.NewServer(store)
		t.Cleanup(srv.Close)
		t.Setenv("AWS_ACCESS_KEY_ID", "test")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
		for _, env := range []string{"AWS_SESSION_TOKEN", "AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_S3", "AWS_REQUEST_CHECKSUM_CALCULATION", "AWS_RESPONSE_CHECKSUM_VALIDATION"} {
			t.Setenv(env, "")
		}
		body := fmt.Sprintf(`{"allow_plaintext": true, "storage_backends": {"onprem": {
		  "driver": "s3", "bucket": "bodega-onprem", "region": "us-east-1",
		  "endpoint": %q, "path_style": true%s}}}`, srv.URL, checksums)
		_, err := runInit(t, body, append([]string{"onprem"}, args...)...)
		return store, err
	}

	t.Run("refused naming both controls", func(t *testing.T) {
		store, err := run(t, `, "checksums": "when_required"`)
		if err == nil || !strings.Contains(err.Error(), "does not implement: public access block, default encryption") ||
			!strings.Contains(err.Error(), "--allow-unsupported") {
			t.Fatalf("err = %v, want both controls named and the flag offered", err)
		}
		if store.count("PUT /bodega-onprem?lifecycle") != 1 {
			t.Errorf("lifecycle was not applied after the unsupported controls: %v", store.requests)
		}
		if len(store.markerCRCs) != 0 {
			t.Errorf("prefix markers written on a refused run: %v", store.requests)
		}
	})

	t.Run("allowed, and when_required sends no CRC32", func(t *testing.T) {
		store, err := run(t, `, "checksums": "when_required"`, "--allow-unsupported")
		if err != nil {
			t.Fatalf("err = %v, want the run to finish: %v", err, store.requests)
		}
		if len(store.markerCRCs) == 0 {
			t.Fatalf("no prefix marker written: %v", store.requests)
		}
		for _, crc := range store.markerCRCs {
			if crc {
				t.Fatal("a marker PUT carried a CRC32 checksum under checksums: when_required")
			}
		}
	})

	t.Run("checksums unset keeps the SDK default on the wire", func(t *testing.T) {
		store, err := run(t, "", "--allow-unsupported")
		if err != nil {
			t.Fatalf("err = %v: %v", err, store.requests)
		}
		if len(store.markerCRCs) == 0 || !store.markerCRCs[0] {
			t.Errorf("marker PUT carried no CRC32 with checksums unset; the when_required case above proves nothing: %v", store.markerCRCs)
		}
	})
}
