package s3

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/ravinald/bodega/internal/manifest"
)

// fakeBucket answers each SDK call from its fields and records the writes.
// A zero fakeBucket is a fully configured bucket holding one object under
// every expected prefix, so each test states only the drift it exercises.
type fakeBucket struct {
	headErr   error
	createErr error

	pab       *types.PublicAccessBlockConfiguration
	pabGetErr error
	pabPutErr error

	versioning    types.BucketVersioningStatus
	versionGetErr error
	versionPutErr error

	encryption *types.ServerSideEncryptionConfiguration
	encGetErr  error
	encPutErr  error

	lifecycle       []types.LifecycleRule
	lifecycleGetErr error
	lifecyclePutErr error

	missing   map[string]bool
	listErr   error
	putObjErr error

	created     *s3.CreateBucketInput
	pabPut      bool
	versionPut  bool
	encPut      bool
	lifecycleIn *types.BucketLifecycleConfiguration
	markers     []string
}

func newFake() *fakeBucket {
	return &fakeBucket{
		pab: &types.PublicAccessBlockConfiguration{
			BlockPublicAcls:       aws.Bool(true),
			BlockPublicPolicy:     aws.Bool(true),
			IgnorePublicAcls:      aws.Bool(true),
			RestrictPublicBuckets: aws.Bool(true),
		},
		versioning: types.BucketVersioningStatusEnabled,
		encryption: &types.ServerSideEncryptionConfiguration{
			Rules: []types.ServerSideEncryptionRule{{
				ApplyServerSideEncryptionByDefault: &types.ServerSideEncryptionByDefault{
					SSEAlgorithm: types.ServerSideEncryptionAwsKms,
				},
			}},
		},
		lifecycle: LifecycleRules(),
		missing:   map[string]bool{},
	}
}

func (f *fakeBucket) HeadBucket(context.Context, *s3.HeadBucketInput, ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	return &s3.HeadBucketOutput{}, f.headErr
}

func (f *fakeBucket) CreateBucket(_ context.Context, in *s3.CreateBucketInput, _ ...func(*s3.Options)) (*s3.CreateBucketOutput, error) {
	f.created = in
	return &s3.CreateBucketOutput{}, f.createErr
}

func (f *fakeBucket) GetPublicAccessBlock(context.Context, *s3.GetPublicAccessBlockInput, ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	if f.pabGetErr != nil {
		return nil, f.pabGetErr
	}
	return &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: f.pab}, nil
}

func (f *fakeBucket) PutPublicAccessBlock(context.Context, *s3.PutPublicAccessBlockInput, ...func(*s3.Options)) (*s3.PutPublicAccessBlockOutput, error) {
	f.pabPut = true
	return &s3.PutPublicAccessBlockOutput{}, f.pabPutErr
}

func (f *fakeBucket) GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	if f.versionGetErr != nil {
		return nil, f.versionGetErr
	}
	return &s3.GetBucketVersioningOutput{Status: f.versioning}, nil
}

func (f *fakeBucket) PutBucketVersioning(context.Context, *s3.PutBucketVersioningInput, ...func(*s3.Options)) (*s3.PutBucketVersioningOutput, error) {
	f.versionPut = true
	return &s3.PutBucketVersioningOutput{}, f.versionPutErr
}

func (f *fakeBucket) GetBucketEncryption(context.Context, *s3.GetBucketEncryptionInput, ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	if f.encGetErr != nil {
		return nil, f.encGetErr
	}
	return &s3.GetBucketEncryptionOutput{ServerSideEncryptionConfiguration: f.encryption}, nil
}

func (f *fakeBucket) PutBucketEncryption(context.Context, *s3.PutBucketEncryptionInput, ...func(*s3.Options)) (*s3.PutBucketEncryptionOutput, error) {
	f.encPut = true
	return &s3.PutBucketEncryptionOutput{}, f.encPutErr
}

func (f *fakeBucket) GetBucketLifecycleConfiguration(context.Context, *s3.GetBucketLifecycleConfigurationInput, ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error) {
	if f.lifecycleGetErr != nil {
		return nil, f.lifecycleGetErr
	}
	return &s3.GetBucketLifecycleConfigurationOutput{Rules: f.lifecycle}, nil
}

func (f *fakeBucket) PutBucketLifecycleConfiguration(_ context.Context, in *s3.PutBucketLifecycleConfigurationInput, _ ...func(*s3.Options)) (*s3.PutBucketLifecycleConfigurationOutput, error) {
	f.lifecycleIn = in.LifecycleConfiguration
	return &s3.PutBucketLifecycleConfigurationOutput{}, f.lifecyclePutErr
}

func (f *fakeBucket) ListObjectsV2(_ context.Context, in *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.missing[aws.ToString(in.Prefix)] {
		return &s3.ListObjectsV2Output{KeyCount: aws.Int32(0)}, nil
	}
	return &s3.ListObjectsV2Output{KeyCount: aws.Int32(1)}, nil
}

func (f *fakeBucket) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if f.putObjErr != nil {
		return nil, f.putObjErr
	}
	f.markers = append(f.markers, aws.ToString(in.Key))
	return &s3.PutObjectOutput{}, nil
}

var errBoom = errors.New("boom")

func TestEnsureBucket(t *testing.T) {
	notFound := &types.NotFound{}
	cases := []struct {
		name       string
		region     string
		headErr    error
		createErr  error
		wantOut    string
		wantErr    bool
		wantCreate bool
		wantLoc    types.BucketLocationConstraint
	}{
		{name: "exists", region: "us-west-2", wantOut: "  bucket:     exists\n"},
		{name: "created in us-east-1 without a location constraint", region: "us-east-1", headErr: notFound, wantOut: "  bucket:     CREATED s3://b\n", wantCreate: true},
		{name: "created elsewhere with a location constraint", region: "eu-west-1", headErr: notFound, wantOut: "  bucket:     CREATED s3://b\n", wantCreate: true, wantLoc: "eu-west-1"},
		{name: "already owned by you", region: "us-west-2", headErr: notFound, createErr: &smithy.GenericAPIError{Code: "BucketAlreadyOwnedByYou"}, wantOut: "  bucket:     exists (owned by you)\n", wantCreate: true, wantLoc: "us-west-2"},
		{name: "create fails", region: "us-west-2", headErr: notFound, createErr: errBoom, wantErr: true, wantCreate: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.headErr, f.createErr = tc.headErr, tc.createErr
			var out bytes.Buffer
			err := ensureBucket(context.Background(), f, &out, "b", tc.region)
			if tc.wantErr {
				if !errors.Is(err, errBoom) || !strings.Contains(err.Error(), "create bucket b") {
					t.Fatalf("err = %v, want create bucket b wrapping boom", err)
				}
				if out.Len() != 0 {
					t.Errorf("output on failure = %q, want none", out.String())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if out.String() != tc.wantOut {
				t.Errorf("output = %q, want %q", out.String(), tc.wantOut)
			}
			if (f.created != nil) != tc.wantCreate {
				t.Fatalf("CreateBucket called = %v, want %v", f.created != nil, tc.wantCreate)
			}
			if f.created == nil {
				return
			}
			var loc types.BucketLocationConstraint
			if f.created.CreateBucketConfiguration != nil {
				loc = f.created.CreateBucketConfiguration.LocationConstraint
			}
			if loc != tc.wantLoc {
				t.Errorf("location constraint = %q, want %q", loc, tc.wantLoc)
			}
		})
	}
}

func TestEnsurePublicAccessBlock(t *testing.T) {
	partial := &types.PublicAccessBlockConfiguration{
		BlockPublicAcls:       aws.Bool(true),
		BlockPublicPolicy:     aws.Bool(true),
		IgnorePublicAcls:      aws.Bool(true),
		RestrictPublicBuckets: aws.Bool(false),
	}
	cases := []struct {
		name    string
		mutate  func(*fakeBucket)
		wantOut string
		wantPut bool
		wantErr bool
	}{
		{name: "already blocked", mutate: func(*fakeBucket) {}, wantOut: "  public acl: blocked\n"},
		{name: "one flag off", mutate: func(f *fakeBucket) { f.pab = partial }, wantOut: "  public acl: CONFIGURED (all blocked)\n", wantPut: true},
		{name: "no configuration", mutate: func(f *fakeBucket) { f.pab = nil }, wantOut: "  public acl: CONFIGURED (all blocked)\n", wantPut: true},
		{name: "read fails", mutate: func(f *fakeBucket) { f.pabGetErr = errBoom }, wantOut: "  public acl: CONFIGURED (all blocked)\n", wantPut: true},
		{name: "write fails", mutate: func(f *fakeBucket) { f.pab = nil; f.pabPutErr = errBoom }, wantPut: true, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			tc.mutate(f)
			var out bytes.Buffer
			err := ensurePublicAccessBlock(context.Background(), f, &out, "b")
			checkStep(t, err, tc.wantErr, "put public access block on b", &out, tc.wantOut)
			if f.pabPut != tc.wantPut {
				t.Errorf("PutPublicAccessBlock called = %v, want %v", f.pabPut, tc.wantPut)
			}
		})
	}
}

func TestEnsureVersioning(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*fakeBucket)
		wantOut string
		wantPut bool
		wantErr bool
	}{
		{name: "already enabled", mutate: func(*fakeBucket) {}, wantOut: "  versioning: enabled\n"},
		{name: "suspended", mutate: func(f *fakeBucket) { f.versioning = types.BucketVersioningStatusSuspended }, wantOut: "  versioning: ENABLED\n", wantPut: true},
		{name: "never set", mutate: func(f *fakeBucket) { f.versioning = "" }, wantOut: "  versioning: ENABLED\n", wantPut: true},
		{name: "read fails", mutate: func(f *fakeBucket) { f.versionGetErr = errBoom }, wantOut: "  versioning: ENABLED\n", wantPut: true},
		{name: "write fails", mutate: func(f *fakeBucket) { f.versioning = ""; f.versionPutErr = errBoom }, wantPut: true, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			tc.mutate(f)
			var out bytes.Buffer
			err := ensureVersioning(context.Background(), f, &out, "b")
			checkStep(t, err, tc.wantErr, "enable versioning on b", &out, tc.wantOut)
			if f.versionPut != tc.wantPut {
				t.Errorf("PutBucketVersioning called = %v, want %v", f.versionPut, tc.wantPut)
			}
		})
	}
}

func TestEnsureEncryption(t *testing.T) {
	noDefault := &types.ServerSideEncryptionConfiguration{
		Rules: []types.ServerSideEncryptionRule{{BucketKeyEnabled: aws.Bool(true)}},
	}
	cases := []struct {
		name    string
		mutate  func(*fakeBucket)
		wantOut string
		wantPut bool
		wantErr bool
	}{
		{name: "already encrypted reports the algorithm in place", mutate: func(*fakeBucket) {}, wantOut: "  encryption: aws:kms\n"},
		{name: "rule without a default", mutate: func(f *fakeBucket) { f.encryption = noDefault }, wantOut: "  encryption: CONFIGURED (AES-256)\n", wantPut: true},
		{name: "no configuration", mutate: func(f *fakeBucket) { f.encryption = nil }, wantOut: "  encryption: CONFIGURED (AES-256)\n", wantPut: true},
		{name: "read fails", mutate: func(f *fakeBucket) { f.encGetErr = errBoom }, wantOut: "  encryption: CONFIGURED (AES-256)\n", wantPut: true},
		{name: "write fails", mutate: func(f *fakeBucket) { f.encryption = nil; f.encPutErr = errBoom }, wantPut: true, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			tc.mutate(f)
			var out bytes.Buffer
			err := ensureEncryption(context.Background(), f, &out, "b")
			checkStep(t, err, tc.wantErr, "enable encryption on b", &out, tc.wantOut)
			if f.encPut != tc.wantPut {
				t.Errorf("PutBucketEncryption called = %v, want %v", f.encPut, tc.wantPut)
			}
		})
	}
}

func TestEnsureLifecycle(t *testing.T) {
	const changed = "  lifecycle:  CONFIGURED (abort multipart after 7d, noncurrent versions after 30d, manifests/ kept)\n"
	operatorRule := types.LifecycleRule{
		ID:         aws.String("operator-tmp"),
		Status:     types.ExpirationStatusEnabled,
		Filter:     &types.LifecycleRuleFilter{Prefix: aws.String("tmp/")},
		Expiration: &types.LifecycleExpiration{Days: aws.Int32(1)},
	}
	edited := LifecycleRules()
	edited[1].NoncurrentVersionExpiration = &types.NoncurrentVersionExpiration{NoncurrentDays: aws.Int32(3650)}
	stale := append(LifecycleRules(), types.LifecycleRule{
		ID: aws.String("bodega-expire-noncurrent-services"), Status: types.ExpirationStatusEnabled,
		Filter:                      &types.LifecycleRuleFilter{Prefix: aws.String("services/")},
		NoncurrentVersionExpiration: &types.NoncurrentVersionExpiration{NoncurrentDays: aws.Int32(30)},
	})
	cases := []struct {
		name     string
		mutate   func(*fakeBucket)
		wantOut  string
		wantPut  bool
		wantErr  string
		wantKept bool
	}{
		{name: "already configured", mutate: func(*fakeBucket) {}, wantOut: "  lifecycle:  configured\n"},
		{name: "already configured beside an operator rule", mutate: func(f *fakeBucket) { f.lifecycle = append(f.lifecycle, operatorRule) }, wantOut: "  lifecycle:  configured\n"},
		{name: "no configuration", mutate: func(f *fakeBucket) {
			f.lifecycleGetErr = &smithy.GenericAPIError{Code: "NoSuchLifecycleConfiguration"}
		}, wantOut: changed, wantPut: true},
		{name: "operator rule survives the rewrite", mutate: func(f *fakeBucket) { f.lifecycle = []types.LifecycleRule{operatorRule} }, wantOut: changed, wantPut: true, wantKept: true},
		{name: "a hand-edited bodega rule is drift", mutate: func(f *fakeBucket) { f.lifecycle = edited }, wantOut: changed, wantPut: true},
		{name: "a rule for a retired prefix is drift", mutate: func(f *fakeBucket) { f.lifecycle = stale }, wantOut: changed, wantPut: true},
		{name: "read fails refuses rather than overwrite unseen rules", mutate: func(f *fakeBucket) { f.lifecycleGetErr = errBoom }, wantErr: "read lifecycle configuration on b"},
		{name: "write fails", mutate: func(f *fakeBucket) { f.lifecycle = nil; f.lifecyclePutErr = errBoom }, wantPut: true, wantErr: "put lifecycle configuration on b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			tc.mutate(f)
			var out bytes.Buffer
			err := ensureLifecycle(context.Background(), f, &out, "b")
			checkStep(t, err, tc.wantErr != "", tc.wantErr, &out, tc.wantOut)
			if (f.lifecycleIn != nil) != tc.wantPut {
				t.Fatalf("PutBucketLifecycleConfiguration called = %v, want %v", f.lifecycleIn != nil, tc.wantPut)
			}
			if f.lifecycleIn == nil || tc.wantErr != "" {
				return
			}
			if !lifecycleSatisfied(f.lifecycleIn.Rules, LifecycleRules()) {
				t.Errorf("written rules do not satisfy LifecycleRules(): %+v", f.lifecycleIn.Rules)
			}
			kept := slices.ContainsFunc(f.lifecycleIn.Rules, func(r types.LifecycleRule) bool { return aws.ToString(r.ID) == "operator-tmp" })
			if kept != tc.wantKept {
				t.Errorf("operator rule kept = %v, want %v", kept, tc.wantKept)
			}
		})
	}
}

// TestLifecycleKeepsManifestHistory pins the split: every artifact prefix
// expires its noncurrent versions and manifests/ never does, because that
// history is what survives whoever can rewrite a manifest.
func TestLifecycleKeepsManifestHistory(t *testing.T) {
	var abort int
	expiring := map[string]bool{}
	for _, r := range LifecycleRules() {
		if r.Status != types.ExpirationStatusEnabled || r.Filter == nil {
			t.Fatalf("rule %s is not an enabled prefix rule", aws.ToString(r.ID))
		}
		prefix := aws.ToString(r.Filter.Prefix)
		if r.AbortIncompleteMultipartUpload != nil {
			abort++
			if prefix != "" || aws.ToInt32(r.AbortIncompleteMultipartUpload.DaysAfterInitiation) != AbortIncompleteMultipartDays {
				t.Errorf("abort rule = prefix %q, %d days; want the bucket root", prefix, aws.ToInt32(r.AbortIncompleteMultipartUpload.DaysAfterInitiation))
			}
		}
		if r.NoncurrentVersionExpiration != nil {
			expiring[prefix] = true
		}
	}
	if abort != 1 {
		t.Errorf("%d abort-multipart rules, want 1", abort)
	}
	if expiring["manifests/"] || expiring[""] {
		t.Errorf("noncurrent versions expire under manifests/ (or the whole bucket): %v", expiring)
	}
	for _, p := range manifest.StoragePrefixes() {
		if p != manifest.ManifestsPrefix && !expiring[p] {
			t.Errorf("artifact prefix %s keeps noncurrent versions forever", p)
		}
	}
}

func TestEnsurePrefixes(t *testing.T) {
	t.Run("all present", func(t *testing.T) {
		f := newFake()
		var out bytes.Buffer
		if err := ensurePrefixes(context.Background(), f, &out, "b"); err != nil {
			t.Fatal(err)
		}
		var want strings.Builder
		for _, p := range expectedPrefixes {
			want.WriteString("  " + padPrefix(p) + " exists\n")
		}
		if out.String() != want.String() {
			t.Errorf("output = %q, want %q", out.String(), want.String())
		}
		if len(f.markers) != 0 {
			t.Errorf("markers written = %v, want none", f.markers)
		}
	})

	t.Run("missing ones get a marker", func(t *testing.T) {
		f := newFake()
		f.missing["freebsd/"] = true
		f.missing["npm/"] = true
		var out bytes.Buffer
		if err := ensurePrefixes(context.Background(), f, &out, "b"); err != nil {
			t.Fatal(err)
		}
		if want := []string{"freebsd/", "npm/"}; !slices.Equal(f.markers, want) {
			t.Errorf("markers = %v, want %v", f.markers, want)
		}
		for _, p := range expectedPrefixes {
			verdict := " exists\n"
			if f.missing[p] {
				verdict = " CREATED\n"
			}
			if line := "  " + padPrefix(p) + verdict; !strings.Contains(out.String(), line) {
				t.Errorf("output lacks %q:\n%s", line, out.String())
			}
		}
	})

	t.Run("list fails", func(t *testing.T) {
		f := newFake()
		f.listErr = errBoom
		var out bytes.Buffer
		err := ensurePrefixes(context.Background(), f, &out, "b")
		checkStep(t, err, true, "list prefix "+expectedPrefixes[0], &out, "")
	})

	t.Run("marker write fails", func(t *testing.T) {
		f := newFake()
		first := expectedPrefixes[0]
		f.missing[first] = true
		f.putObjErr = errBoom
		var out bytes.Buffer
		err := ensurePrefixes(context.Background(), f, &out, "b")
		checkStep(t, err, true, "create prefix marker "+first, &out, "")
	})
}

func TestInitBucketStopsAtFirstFailure(t *testing.T) {
	f := newFake()
	f.versioning = ""
	f.versionPutErr = errBoom
	f.encryption = nil
	var out bytes.Buffer
	err := InitBucket(context.Background(), f, &out, "b", "us-west-2")
	if !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want boom", err)
	}
	if f.encPut {
		t.Error("encryption step ran after versioning failed")
	}
	want := "  bucket:     exists\n  public acl: blocked\n"
	if out.String() != want {
		t.Errorf("output = %q, want %q", out.String(), want)
	}
}

func TestInitBucketNilWriter(t *testing.T) {
	f := newFake()
	f.headErr = &types.NotFound{}
	f.missing["charts/"] = true
	if err := InitBucket(context.Background(), f, nil, "b", "us-west-2"); err != nil {
		t.Fatal(err)
	}
	if f.created == nil || !slices.Equal(f.markers, []string{"charts/"}) {
		t.Errorf("nil writer changed what ran: created=%v markers=%v", f.created != nil, f.markers)
	}
}

// TestExpectedPrefixesMatchUsageDoc holds the prefix list against the
// "Storage Layout" table in docs/usage.md, where the two drifted before:
// the code lacked cargo/crates/ and freebsd/ and carried a services/ nothing
// writes to.
func TestExpectedPrefixesMatchUsageDoc(t *testing.T) {
	documented := usageDocPrefixes(t)
	got := slices.Clone(expectedPrefixes)
	if !slices.IsSorted(got) {
		t.Errorf("expectedPrefixes is not sorted: %v", got)
	}
	if len(slices.Compact(slices.Clone(got))) != len(got) {
		t.Errorf("expectedPrefixes has duplicates: %v", got)
	}
	slices.Sort(documented)
	if !slices.Equal(got, documented) {
		t.Errorf("expectedPrefixes = %v\ndocs/usage.md Storage Layout = %v", got, documented)
	}
}

func usageDocPrefixes(t *testing.T) []string {
	t.Helper()
	fh, err := os.Open("../../docs/usage.md")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()

	var prefixes []string
	inSection := false
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "## ") {
			inSection = line == "## Storage Layout"
			continue
		}
		if !inSection || !strings.HasPrefix(line, "|") {
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) < 3 {
			continue
		}
		cell := strings.TrimSpace(cells[2])
		if strings.HasPrefix(cell, "`") && strings.HasSuffix(cell, "/`") {
			prefixes = append(prefixes, strings.Trim(cell, "`"))
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(prefixes) == 0 {
		t.Fatal(`no prefixes parsed from the "## Storage Layout" table in docs/usage.md; the heading or table moved`)
	}
	return prefixes
}

func padPrefix(p string) string {
	const width = 22
	if len(p) >= width {
		return p
	}
	return p + strings.Repeat(" ", width-len(p))
}

func checkStep(t *testing.T, err error, wantErr bool, errPrefix string, out *bytes.Buffer, wantOut string) {
	t.Helper()
	if wantErr {
		if !errors.Is(err, errBoom) || !strings.HasPrefix(err.Error(), errPrefix) {
			t.Fatalf("err = %v, want %q wrapping boom", err, errPrefix)
		}
		if out.Len() != 0 {
			t.Errorf("output on failure = %q, want none", out.String())
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != wantOut {
		t.Errorf("output = %q, want %q", out.String(), wantOut)
	}
}
