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
	"slices"
	"strings"
	"sync"
	"testing"

	gstorage "cloud.google.com/go/storage"
	bogcs "github.com/ravinald/bodega/internal/gcs"
	"github.com/ravinald/bodega/internal/gcs/gcstest"
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

// gcsInit runs `bodega init` with the SDK pointed at an in-process Cloud
// Storage fake through STORAGE_EMULATOR_HOST, the SDK's own switch, so the
// command builds its client exactly as it does against the service.
func gcsInit(t *testing.T, srv *gcstest.Server, config string, args ...string) (string, error) {
	t.Helper()
	t.Setenv("STORAGE_EMULATOR_HOST", srv.Host())
	t.Setenv(bogcs.ProjectEnv, "example-project")
	return runInit(t, config, args...)
}

// TestInitGCS covers `bodega init` on the gcs driver end to end: the driver
// name as the argument, a create with all four controls in the project and
// location given, an idempotent second run, a named backend, and the flags
// that belong to the other driver.
func TestInitGCS(t *testing.T) {
	const cfg = `{"storage_backend": "gcs", "bucket": "example-bodega-artifacts",
	  "storage_backends": {"bulk": {"driver": "local", "path": "/srv/bulk"}}}`

	t.Run("init gcs creates and configures the bucket", func(t *testing.T) {
		srv := gcstest.New(t)
		out, err := gcsInit(t, srv, cfg, "gcs", "--location", "us-central1")
		if err != nil {
			t.Fatalf("err = %v\n%s", err, out)
		}
		for _, want := range []string{
			`Initializing bucket gs://example-bodega-artifacts (backend "default")`,
			"CREATED gs://example-bodega-artifacts in project example-project, US-CENTRAL1",
			"Bucket gs://example-bodega-artifacts is ready.",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("output lacks %q:\n%s", want, out)
			}
		}
		b := srv.Bucket("example-bodega-artifacts")
		if b == nil {
			t.Fatal("no bucket was created")
		}
		raw, _ := json.Marshal(b)
		for _, want := range []string{
			`"uniformBucketLevelAccess":{"enabled":true`, `"publicAccessPrevention":"enforced"`, `"versioning":{"enabled":true}`,
			`"daysSinceNoncurrentTime":30`, `"isLive":false`, `"location":"US-CENTRAL1"`,
		} {
			if !strings.Contains(string(raw), want) {
				t.Errorf("created bucket lacks %s:\n%s", want, raw)
			}
		}
		if strings.Contains(string(raw), `"manifests/"`) || strings.Contains(string(raw), `"attestations/"`) {
			t.Errorf("the lifecycle rule names a prefix whose history is kept:\n%s", raw)
		}

		out, err = gcsInit(t, srv, cfg)
		if err != nil || strings.Contains(out, "CREATED") || strings.Contains(out, "CONFIGURED") || strings.Contains(out, "ENABLED") {
			t.Errorf("second run, no argument: err %v, want every line lowercase:\n%s", err, out)
		}
	})

	t.Run("named backend", func(t *testing.T) {
		srv := gcstest.New(t)
		named := `{"storage_backends": {"archive": {"driver": "gcs", "bucket": "example-archive", "prefix": "cold"}}}`
		out, err := gcsInit(t, srv, named, "archive")
		if err != nil || srv.Bucket("example-archive") == nil || !strings.Contains(out, `(backend "archive")`) || !strings.Contains(out, "prefix:     cold/ (the lifecycle rule is scoped under it)") {
			t.Errorf("err %v, bucket %v:\n%s", err, srv.Bucket("example-archive"), out)
		}
		// The driver name finds the one backend on it.
		if out, err := gcsInit(t, srv, named, "gcs"); err != nil || !strings.Contains(out, `(backend "archive")`) {
			t.Errorf("init gcs with one gcs backend: err %v:\n%s", err, out)
		}
	})

	t.Run("refusals", func(t *testing.T) {
		srv := gcstest.New(t)
		two := `{"storage_backend": "gcs", "bucket": "one-bucket", "storage_backends": {"archive": {"driver": "gcs", "bucket": "two-bucket"}}}`
		for _, tc := range []struct {
			name, config string
			args         []string
			want         string
		}{
			{"driver name with two backends", two, []string{"gcs"}, "2 storage backends use the gcs driver (default, archive)"},
			{"driver name with none", `{"storage_backend": "s3", "bucket": "b-b"}`, []string{"gcs"}, "no storage backend uses the gcs driver"},
			{"allow-unsupported is s3's", cfg, []string{"--allow-unsupported"}, "--allow-unsupported is for an S3-compatible store"},
			{"location is gcs's", `{"storage_backend": "s3", "bucket": "b-b"}`, []string{"--location", "us-central1"}, "--location places a new gcs bucket"},
			{"no bucket", `{"storage_backend": "gcs"}`, nil, "a bucket is required"},
			{"named, no bucket", `{"storage_backends": {"archive": {"driver": "gcs"}}}`, []string{"archive"}, `storage_backends["archive"] uses the gcs driver and names no bucket`},
			{"invalid bucket name", `{"storage_backend": "gcs", "bucket": "Not_A*Bucket"}`, nil, "not a valid Cloud Storage bucket name"},
			{"local stays refused", cfg, []string{"bulk"}, `"bulk" uses the local driver`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := gcsInit(t, srv, tc.config, tc.args...)
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Errorf("err = %v, want %q", err, tc.want)
				}
			})
		}
		if n := len(srv.Requests()); n != 0 {
			t.Errorf("a refused run reached the API %d times: %v", n, srv.Requests())
		}
	})

	t.Run("credentials are Application Default Credentials", func(t *testing.T) {
		t.Setenv("STORAGE_EMULATOR_HOST", "")
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "absent.json"))
		_, err := runInit(t, cfg)
		if err == nil || !strings.Contains(err.Error(), "Application Default Credentials") {
			t.Errorf("err = %v, want the missing credentials named as ADC", err)
		}
	})
}

// TestInitGCSPrintPolicy: one role prints as the bare definition gcloud
// reads, both print with who each is for, and neither needs credentials or
// reaches the API.
func TestInitGCSPrintPolicy(t *testing.T) {
	const cfg = `{"storage_backend": "gcs", "bucket": "example-bodega-artifacts"}`
	srv := gcstest.New(t)
	for which, role := range map[string]bogcs.Role{"setup": bogcs.SetupRole(), "runtime": bogcs.RuntimeRole()} {
		out, err := gcsInit(t, srv, cfg, "--print-policy="+which)
		if err != nil || out != role.YAML() {
			t.Errorf("--print-policy=%s: err %v, output is not the bare role definition:\n%s", which, err, out)
		}
	}
	out, err := gcsInit(t, srv, cfg, "--print-policy")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"setup: for whoever runs `bodega init`; creates and configures gs://example-bodega-artifacts and cannot delete it",
		"bind on:    the project", "predefined: roles/storage.admin",
		"runtime: for the service", "bind on:    the bucket", "predefined: roles/storage.objectUser",
		bogcs.SetupRole().YAML(), bogcs.RuntimeRole().YAML(),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--print-policy lacks %q:\n%s", want, out)
		}
	}
	if _, err := gcsInit(t, srv, cfg, "--print-policy=both"); err == nil || !strings.Contains(err.Error(), "want setup, runtime") {
		t.Errorf("unknown value: err = %v", err)
	}
	if n := len(srv.Requests()); n != 0 {
		t.Errorf("printing roles reached the API %d times: %v", n, srv.Requests())
	}
}

// TestInitCheckGCS: the check names each runtime permission, exits non-zero
// naming the ones missing, and writes nothing.
func TestInitCheckGCS(t *testing.T) {
	const cfg = `{"storage_backend": "gcs", "bucket": "example-bodega-artifacts"}`
	srv := gcstest.New(t)
	srv.AddBucket("example-bodega-artifacts")

	out, err := gcsInit(t, srv, cfg, "check")
	if err != nil {
		t.Fatalf("err = %v\n%s", err, out)
	}
	for _, want := range append([]string{
		`Checking gs://example-bodega-artifacts (backend "default") with Application Default Credentials...`,
		"these credentials hold everything the runtime role grants",
	}, bogcs.RuntimeRole().Permissions...) {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	srv.Deny("storage.objects.create")
	out, err = gcsInit(t, srv, cfg, "check", "gcs")
	if err == nil || !strings.Contains(err.Error(), "these credentials lack storage.objects.create") ||
		!strings.Contains(err.Error(), "`bodega init --print-policy=runtime`") {
		t.Errorf("err = %v, want the missing permission and the command that prints the role\n%s", err, out)
	}
	if !strings.Contains(out, "storage.objects.create   missing; grant it on gs://example-bodega-artifacts") {
		t.Errorf("output does not say where to grant it:\n%s", out)
	}
	for _, r := range srv.Requests() {
		if !strings.HasPrefix(r, "GET ") {
			t.Errorf("check wrote to the bucket: %s", r)
		}
	}
}

func TestReviewGCSPrefixedLifecycle(t *testing.T) {
	for _, prefix := range []string{"cold", "binaries"} {
		t.Run(prefix, func(t *testing.T) {
			srv := gcstest.New(t)
			cfg := fmt.Sprintf(`{"storage_backends":{"archive":{"driver":"gcs","bucket":"review-bucket","prefix":%q}}}`, prefix)
			out, err := gcsInit(t, srv, cfg, "archive")
			if err != nil {
				t.Fatalf("init: %v\n%s", err, out)
			}
			attrs, err := srv.Client(t).Bucket("review-bucket").Attrs(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				key  string
				want bool
			}{
				{prefix + "/binaries/tool/v1/tool.zip", true},
				{prefix + "/manifests/index.json", false},
				{prefix + "/attestations/record.json", false},
			} {
				selected, expiresAfter30Days := false, false
				for _, rule := range attrs.Lifecycle.Rules {
					if rule.Action.Type != gstorage.DeleteAction {
						continue
					}
					matches := len(rule.Condition.MatchesPrefix) == 0
					for _, p := range rule.Condition.MatchesPrefix {
						matches = matches || strings.HasPrefix(tc.key, p)
					}
					selected = selected || matches
					if matches && rule.Condition.Liveness == gstorage.Archived && rule.Condition.DaysSinceNoncurrentTime == 30 {
						expiresAfter30Days = true
					}
				}
				if tc.want && !expiresAfter30Days {
					t.Errorf("artifact %q has no 30-day noncurrent expiry rule", tc.key)
				}
				if !tc.want && selected {
					t.Errorf("history %q is selected by a delete rule", tc.key)
				}
			}
		})
	}
}

// gcsExpiry reports, for one object name, whether any delete rule on the
// bucket selects it and whether one expires its noncurrent generations after
// 30 days. Cloud Storage matches a prefix against the start of the name.
func gcsExpiry(rules []gstorage.LifecycleRule, key string) (selected, expires bool) {
	for _, rule := range rules {
		if rule.Action.Type != gstorage.DeleteAction {
			continue
		}
		matches := len(rule.Condition.MatchesPrefix) == 0
		for _, p := range rule.Condition.MatchesPrefix {
			matches = matches || strings.HasPrefix(key, p)
		}
		selected = selected || matches
		expires = expires || (matches && rule.Condition.Liveness == gstorage.Archived && rule.Condition.DaysSinceNoncurrentTime == 30)
	}
	return selected, expires
}

func gcsRules(t *testing.T, srv *gcstest.Server, bucket string) []gstorage.LifecycleRule {
	t.Helper()
	attrs, err := srv.Client(t).Bucket(bucket).Attrs(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return attrs.Lifecycle.Rules
}

// TestInitGCSLifecycleFollowsThePrefix is the lifecycle rule against where
// each backend's objects really are: a root and a prefixed backend sharing a
// bucket each get their artifacts expired and their history kept, running
// init again for either changes nothing, the rule names what the driver
// writes, a rule an earlier init left that reaches a backend's history is
// removed from an existing bucket while the operator's own rule stays, and
// two backends no rules can serve are refused before the API is reached.
func TestInitGCSLifecycleFollowsThePrefix(t *testing.T) {
	const bucket = "shared-bucket"
	shared := `{"storage_backend": "gcs", "bucket": "shared-bucket",
	  "storage_backends": {"archive": {"driver": "gcs", "bucket": "shared-bucket", "prefix": "/cold"},
	                       "elsewhere": {"driver": "gcs", "bucket": "other-bucket", "prefix": "binaries"}}}`

	t.Run("backends sharing a bucket", func(t *testing.T) {
		srv := gcstest.New(t)
		for _, args := range [][]string{nil, {"archive"}} {
			if out, err := gcsInit(t, srv, shared, args...); err != nil || !strings.Contains(out, "lifecycle:  CONFIGURED") {
				t.Fatalf("init %v: %v\n%s", args, err, out)
			}
		}
		rules := gcsRules(t, srv, bucket)
		if len(rules) != 2 {
			t.Fatalf("rules = %+v, want one per backend", rules)
		}
		for key, want := range map[string]bool{
			"binaries/tool/v1/tool.zip":      true,
			"oci/manifests/sha256/abc":       true,
			"cold/binaries/tool/v1/tool.zip": true,
			"cold/npm/left-pad/1.0.0.tgz":    true,
			"manifests/index.json":           false,
			"attestations/record.json":       false,
			"cold/manifests/index.json":      false,
			"cold/attestations/record.json":  false,
			"coldbinaries/tool.zip":          false,
		} {
			if selected, expires := gcsExpiry(rules, key); expires != want || selected != want {
				t.Errorf("%s: selected %v, expires after 30 days %v; want both %v", key, selected, expires, want)
			}
		}

		// What the rule names is what the driver writes.
		t.Setenv("STORAGE_EMULATOR_HOST", srv.Host())
		store, err := storage.NewFromSpec(t.Context(), storage.Spec{Driver: "gcs", Bucket: bucket, Prefix: "/cold"})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Put(t.Context(), "binaries/tool/v1/tool.zip", []byte("artifact")); err != nil {
			t.Fatal(err)
		}
		if _, ok := srv.Object(bucket, "cold/binaries/tool/v1/tool.zip"); !ok {
			t.Error("the archive backend did not write under cold/, where its rule is scoped")
		}

		before := len(srv.Requests())
		for _, args := range [][]string{nil, {"archive"}, {"archive"}} {
			out, err := gcsInit(t, srv, shared, args...)
			if err != nil || strings.Contains(out, "CONFIGURED") || strings.Contains(out, "REMOVED") {
				t.Errorf("repeat init %v: err %v, want every line lowercase:\n%s", args, err, out)
			}
		}
		for _, r := range srv.Requests()[before:] {
			if !strings.HasPrefix(r, "GET ") {
				t.Errorf("a repeat init wrote to the bucket: %s", r)
			}
		}
		if got := gcsRules(t, srv, bucket); !reflect.DeepEqual(got, rules) {
			t.Errorf("rules changed across repeat runs:\n%+v\n%+v", rules, got)
		}
	})

	t.Run("existing bucket with a root rule", func(t *testing.T) {
		for prefix, removed := range map[string]bool{"binaries": true, "cold": false} {
			t.Run(prefix, func(t *testing.T) {
				srv := gcstest.New(t)
				srv.AddBucket(bucket)
				theirs := gstorage.LifecycleRule{
					Action:    gstorage.LifecycleAction{Type: gstorage.SetStorageClassAction, StorageClass: "NEARLINE"},
					Condition: gstorage.LifecycleCondition{AgeInDays: 90},
				}
				if _, err := srv.Client(t).Bucket(bucket).Update(t.Context(), gstorage.BucketAttrsToUpdate{
					Lifecycle: &gstorage.Lifecycle{Rules: []gstorage.LifecycleRule{bogcs.LifecycleRule(""), theirs}},
				}); err != nil {
					t.Fatal(err)
				}
				cfg := fmt.Sprintf(`{"storage_backends":{"archive":{"driver":"gcs","bucket":%q,"prefix":%q}}}`, bucket, prefix)
				out, err := gcsInit(t, srv, cfg, "archive")
				if err != nil || strings.Contains(out, "REMOVED the rule matching") != removed {
					t.Fatalf("init: %v, want a removal reported = %v\n%s", err, removed, out)
				}
				rules := gcsRules(t, srv, bucket)
				want := 3
				if removed {
					want = 2
				}
				if len(rules) != want || !slices.ContainsFunc(rules, func(r gstorage.LifecycleRule) bool { return reflect.DeepEqual(r.Action, theirs.Action) }) {
					t.Errorf("rules = %+v, want %d with the operator's kept", rules, want)
				}
				for key, expire := range map[string]bool{prefix + "/binaries/tool.zip": true, prefix + "/manifests/index.json": false, prefix + "/attestations/a.json": false} {
					if selected, expires := gcsExpiry(rules, key); expires != expire || selected != expire {
						t.Errorf("%s: selected %v, expires %v; want both %v", key, selected, expires, expire)
					}
				}
				if out, err := gcsInit(t, srv, cfg, "archive"); err != nil || strings.Contains(out, "CONFIGURED") {
					t.Errorf("repeat init: %v\n%s", err, out)
				}
			})
		}
	})

	t.Run("a prefix inside another backend's artifacts is refused", func(t *testing.T) {
		srv := gcstest.New(t)
		clash := `{"storage_backend": "gcs", "bucket": "shared-bucket",
		  "storage_backends": {"archive": {"driver": "gcs", "bucket": "shared-bucket", "prefix": "binaries"}}}`
		for _, args := range [][]string{nil, {"archive"}} {
			_, err := gcsInit(t, srv, clash, args...)
			if err == nil || !strings.Contains(err.Error(), "the bucket root") || !strings.Contains(err.Error(), "binaries/") ||
				!strings.Contains(err.Error(), "cannot exclude a prefix") {
				t.Errorf("init %v: err = %v, want both backends named and the reason", args, err)
			}
		}
		if n := len(srv.Requests()); n != 0 {
			t.Errorf("a refused run reached the API %d times: %v", n, srv.Requests())
		}
	})
}
