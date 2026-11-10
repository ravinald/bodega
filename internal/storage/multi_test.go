package storage

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/ravinald/bodega/internal/config"
	bos3 "github.com/ravinald/bodega/internal/s3"
)

// TestDriverRegistryIsWiredIntoConfig proves the hook config.Load reads is
// actually installed. Without it the reserved-name check is vacuous and a
// backend called "s3" loads clean.
func TestDriverRegistryIsWiredIntoConfig(t *testing.T) {
	got := config.StorageDrivers()
	want := map[string]bool{"local": true, "s3": true}
	for _, name := range got {
		delete(want, name)
	}
	if len(want) != 0 {
		t.Errorf("config.StorageDrivers() = %v, missing %v", got, want)
	}
}

// TestNewResolverWithoutNamedBackendsIsSingle pins the back-compat shape: a
// config with none of the new keys produces exactly the resolver it produced
// before they existed.
func TestNewResolverWithoutNamedBackendsIsSingle(t *testing.T) {
	cfg := &config.Config{StorageBackend: "local", StoragePath: t.TempDir()}
	r, err := NewResolver(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if all := r.All(); len(all) != 1 || all[0].Name != DefaultName {
		t.Fatalf("All() = %v, want one backend named %q", all, DefaultName)
	}
	for _, typ := range []string{"apt", "pypi", "binary", "git"} {
		if got := r.Placement(typ, "", nil); got.Name != DefaultName {
			t.Errorf("Placement(%q) = %q, want %q", typ, got.Name, DefaultName)
		}
	}
}

func TestPlacementFollowsStorageByType(t *testing.T) {
	r := twoBackendResolver(t, t.TempDir(), t.TempDir(), map[string]string{"apt": "bulk"})
	if got := r.Placement("apt", "", nil); got.Name != "bulk" || got.Level != LevelType {
		t.Errorf("Placement(apt) = %+v, want bulk at LevelType", got)
	}
	if got := r.Placement("pypi", "", nil); got.Name != DefaultName || got.Level != LevelDefault {
		t.Errorf("Placement(pypi) = %+v, want %q at LevelDefault", got, DefaultName)
	}
}

// TestPackagePolicyBeatsTheTypeRule is the whole reason the package level
// exists. The motivating case is a package whose bytes must live in a specific
// bucket under a specific KMS key while its type is shared with packages that
// must not; a package policy that lost to the type rule could not express it,
// and would silently move that package the day someone added a type rule.
func TestPackagePolicyBeatsTheTypeRule(t *testing.T) {
	r := twoBackendResolver(t, t.TempDir(), t.TempDir(), map[string]string{"git": "bulk"})

	// git's type rule says bulk. This one package says otherwise and must win.
	if got := r.Placement("git", DefaultName, nil); got.Name != DefaultName || got.Level != LevelPackage {
		t.Errorf("Placement(git, %q) = %+v, want %q at LevelPackage", DefaultName, got, DefaultName)
	}
	if got := r.Placement("git", "", nil); got.Name != "bulk" || got.Level != LevelType {
		t.Errorf("Placement(git, no policy) = %+v, want bulk at LevelType", got)
	}
	// A type with no rule of its own still honors the package policy.
	if got := r.Placement("npm", "bulk", nil); got.Name != "bulk" || got.Level != LevelPackage {
		t.Errorf("Placement(npm, bulk) = %+v, want bulk at LevelPackage", got)
	}
}

// TestDecisionReasonNamesTheDecidingRule: printing the winning level is what
// makes a three-level hierarchy debuggable, and the type level names the config
// key so an operator can find and change it.
func TestDecisionReasonNamesTheDecidingRule(t *testing.T) {
	for _, tc := range []struct {
		d    Decision
		want string
	}{
		{Decision{Name: "bulk", Level: LevelPackage}, "package policy"},
		{Decision{Name: "bulk", Level: LevelType}, "type rule: storage_by_type.apt"},
		{Decision{Name: DefaultName, Level: LevelDefault}, "global default; no type, group or package rule"},
	} {
		if got := tc.d.Reason("apt"); got != tc.want {
			t.Errorf("Reason() = %q, want %q", got, tc.want)
		}
	}
}

// TestByNameRejectsUnknownRatherThanFallingBack pins that resolution has no
// fallback. Serving from another backend would publish bytes under a digest
// recorded against the one named.
func TestByNameRejectsUnknownRatherThanFallingBack(t *testing.T) {
	r := twoBackendResolver(t, t.TempDir(), t.TempDir(), nil)
	if _, err := r.ByName("ghost"); err == nil {
		t.Fatal("ByName(ghost) succeeded, want an error")
	} else if !strings.Contains(err.Error(), "default, bulk") {
		t.Errorf("error = %q, want it to list the configured backends", err)
	}
	if _, err := r.ByName(""); err != nil {
		t.Errorf(`ByName("") = %v, want the default backend`, err)
	}
}

// TestFanoutDedupsBackendsAtOneLocation covers the staged-migration config:
// two names for one directory. Listing it twice doubles every fan-out and
// hands the union a duplicate of every key.
func TestFanoutDedupsBackendsAtOneLocation(t *testing.T) {
	shared := t.TempDir()
	r := twoBackendResolver(t, shared, shared, nil)

	if all := r.All(); len(all) != 2 {
		t.Fatalf("All() = %d backends, want 2 — dedup belongs to Fanout, not All", len(all))
	}
	fan := r.Fanout(context.Background(), "apt", []string{"bulk"})
	if len(fan) != 1 {
		t.Fatalf("Fanout() = %d backends, want 1: %v", len(fan), fan)
	}
	if fan[0].Name != DefaultName {
		t.Errorf("Fanout kept %q, want the default to win the tie", fan[0].Name)
	}
}

// TestFanoutNarrowsToWhatAReadCanReach: a backend that holds nothing for this
// type must not join its fan-out. A per-backend error fails the whole index,
// so an unrelated backend being down would otherwise 502 every type.
func TestFanoutNarrowsToWhatAReadCanReach(t *testing.T) {
	r := twoBackendResolver(t, t.TempDir(), t.TempDir(), map[string]string{"apt": "bulk"})

	names := func(in []NamedStore) []string {
		out := make([]string, 0, len(in))
		for _, ns := range in {
			out = append(out, ns.Name)
		}
		sort.Strings(out)
		return out
	}

	if got := names(r.Fanout(context.Background(), "pypi", nil)); len(got) != 1 || got[0] != DefaultName {
		t.Errorf("Fanout(pypi) = %v, want only %q — bulk holds no pypi", got, DefaultName)
	}
	if got := names(r.Fanout(context.Background(), "apt", nil)); len(got) != 2 {
		t.Errorf("Fanout(apt) = %v, want both — storage_by_type sends apt to bulk", got)
	}
	// A pypi package moved to bulk puts bulk back in pypi's fan-out, which
	// config alone cannot say.
	if got := names(r.Fanout(context.Background(), "pypi", []string{"bulk"})); len(got) != 2 {
		t.Errorf("Fanout(pypi, [bulk]) = %v, want both — a moved artifact was dropped from the index", got)
	}
	// An empty recorded name is the default, not a third backend.
	if got := names(r.Fanout(context.Background(), "pypi", []string{""})); len(got) != 1 {
		t.Errorf("Fanout(pypi, [\"\"]) = %v, want only the default", got)
	}
}

func TestPrefixScopesKeysAndStripsThemBack(t *testing.T) {
	root := t.TempDir()
	store, err := NewFromSpec(context.Background(), Spec{Driver: "local", Path: root, Prefix: "cold/"})
	if err != nil {
		t.Fatalf("NewFromSpec: %v", err)
	}
	ctx := context.Background()
	if err := store.Put(ctx, "packages/apt/pool/x.deb", []byte("bytes")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	keys, err := store.List(ctx, "packages/apt/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 || keys[0] != "packages/apt/pool/x.deb" {
		t.Fatalf("List = %v, want the prefix stripped back off", keys)
	}

	// The prefix has to be real on disk, or it is decoration.
	unprefixed := NewLocal(root)
	if got, err := unprefixed.Get(ctx, "cold/packages/apt/pool/x.deb"); err != nil || string(got) != "bytes" {
		t.Fatalf("underlying key = %q (err %v), want the object under cold/", got, err)
	}
}

// twoBackendResolver builds a real resolver over "default" and "bulk", both
// local, so tests exercise NewResolver rather than a hand-written double.
func twoBackendResolver(t *testing.T, defaultPath, bulkPath string, byType map[string]string) Resolver {
	t.Helper()
	cfg := &config.Config{
		StorageBackend: "local",
		StoragePath:    defaultPath,
		StorageBackends: map[string]config.StorageSpec{
			"bulk": {Driver: "local", Path: bulkPath},
		},
		StorageByType: byType,
	}
	r, err := NewResolver(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return r
}

// groupResolver builds a real resolver over "default", "bulk" and "cold" with
// both maps populated, so the group level is exercised against NewResolver
// rather than a hand-written double.
func groupResolver(t *testing.T, byType, byGroup map[string]string) Resolver {
	t.Helper()
	cfg := &config.Config{
		StorageBackend: "local",
		StoragePath:    t.TempDir(),
		StorageBackends: map[string]config.StorageSpec{
			"bulk": {Driver: "local", Path: t.TempDir()},
			"cold": {Driver: "local", Path: t.TempDir()},
		},
		StorageByType:  byType,
		StorageByGroup: byGroup,
	}
	r, err := NewResolver(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return r
}

// TestGroupSitsBetweenTypeAndPackage pins the one property the level was added
// for. A group that lost to the type rule would place nothing an operator
// could not already place, and one that beat the package policy would move the
// single package that must not move.
func TestGroupSitsBetweenTypeAndPackage(t *testing.T) {
	r := groupResolver(t,
		map[string]string{"apt": "bulk"},
		map[string]string{"mirror-set": "cold"})

	if got := r.Placement("apt", "", []string{"mirror-set"}); got.Name != "cold" || got.Level != LevelGroup {
		t.Errorf("Placement(apt, no policy, mirror-set) = %+v, want cold at LevelGroup", got)
	}
	if got := r.Placement("apt", DefaultName, []string{"mirror-set"}); got.Name != DefaultName || got.Level != LevelPackage {
		t.Errorf("Placement(apt, policy, mirror-set) = %+v, want %q at LevelPackage", got, DefaultName)
	}
	if got := r.Placement("apt", "", []string{"unmapped"}); got.Name != "bulk" || got.Level != LevelType {
		t.Errorf("Placement(apt, group with no rule) = %+v, want bulk at LevelType", got)
	}
	if got := r.Placement("npm", "", []string{"unmapped"}); got.Name != DefaultName || got.Level != LevelDefault {
		t.Errorf("Placement(npm, group with no rule) = %+v, want %q at LevelDefault", got, DefaultName)
	}
}

// TestTwoGroupsResolveByNameNotByOrder is the answer to "what does a package in
// two groups get". Both orderings are driven because manifest order is exactly
// what the rule must not depend on: a rewrite that reorders the list would
// otherwise move the next upload's bytes.
func TestTwoGroupsResolveByNameNotByOrder(t *testing.T) {
	r := groupResolver(t, nil, map[string]string{"alpha": "bulk", "omega": "cold"})

	for _, groups := range [][]string{{"alpha", "omega"}, {"omega", "alpha"}} {
		got := r.Placement("apt", "", groups)
		if got.Name != "bulk" || got.Group != "alpha" {
			t.Errorf("Placement(apt, %v) = %+v, want bulk decided by alpha", groups, got)
		}
	}

	// The caller's slice is its manifest's field; sorting it in place would
	// rewrite the manifest on the next save.
	groups := []string{"omega", "alpha"}
	r.Placement("apt", "", groups)
	if groups[0] != "omega" {
		t.Errorf("groups = %v after Placement, want the caller's order untouched", groups)
	}
}

// TestGroupReasonNamesBothEdits keeps the level debuggable: a reason saying
// only "group rule" leaves the operator hunting for which of the two files to
// change.
func TestGroupReasonNamesBothEdits(t *testing.T) {
	r := groupResolver(t, nil, map[string]string{"mirror-set": "cold"})
	got := r.Placement("apt", "", []string{"mirror-set"}).Reason("apt")
	for _, want := range []string{"storage_by_group.mirror-set", "storage_groups"} {
		if !strings.Contains(got, want) {
			t.Errorf("Reason() = %q, want it to name %q", got, want)
		}
	}
}

// TestStorageByGroupAloneStillBuildsMulti guards the reporting path: with only
// the default backend every group resolves to it, so the answer is the same
// either way and a single resolver would report LevelDefault for a package the
// operator did place by group.
func TestStorageByGroupAloneStillBuildsMulti(t *testing.T) {
	cfg := &config.Config{
		StorageBackend: "local",
		StoragePath:    t.TempDir(),
		StorageByGroup: map[string]string{"mirror-set": DefaultName},
	}
	r, err := NewResolver(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if got := r.Placement("apt", "", []string{"mirror-set"}); got.Level != LevelGroup || got.Name != DefaultName {
		t.Errorf("Placement(apt, mirror-set) = %+v, want %q at LevelGroup", got, DefaultName)
	}
}

// awsProfileRegion points the SDK at a shared config whose only region comes
// from the selected profile, so a region that reaches a client from anywhere
// else shows up as the wrong answer.
func awsProfileRegion(t *testing.T, region string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte("[profile p]\nregion = "+region+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", path)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "absent"))
	t.Setenv("AWS_PROFILE", "p")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
}

// TestResolverDialsTheRegionSpecForDescribes holds the service to the same
// region `bodega init` reports: both build their client with bos3.NewClient
// from SpecFor, so a named s3 entry with no region resolves through the SDK
// chain in each, and the default backend keeps the global region.
func TestResolverDialsTheRegionSpecForDescribes(t *testing.T) {
	awsProfileRegion(t, "eu-west-1")
	cfg := &config.Config{
		StorageBackend: "s3", Bucket: "main-bucket", Region: "us-west-2",
		StorageBackends: map[string]config.StorageSpec{
			"nearby": {Driver: "s3", Bucket: "nearby-bucket"},
			"pinned": {Driver: "s3", Bucket: "pinned-bucket", Region: "ap-south-1"},
		},
	}
	r, err := NewResolver(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{DefaultName: "us-west-2", "nearby": "eu-west-1", "pinned": "ap-south-1"} {
		store, err := r.ByName(name)
		if err != nil {
			t.Fatal(err)
		}
		if got := store.(*S3).client.Region(); got != want {
			t.Errorf("%s: service dials %q, want %q", name, got, want)
		}
		spec, _ := SpecFor(cfg, name)
		viaSpec, err := bos3.NewClient(context.Background(), spec.Bucket, spec.Region, spec.S3Options())
		if err != nil {
			t.Fatal(err)
		}
		if viaSpec.Region() != want {
			t.Errorf("%s: SpecFor resolves %q, want %q", name, viaSpec.Region(), want)
		}
	}
}

// TestSpecForCarriesTheS3StoreKeys holds endpoint, path_style and checksums to
// the path region takes: from the config, through SpecFor, into the client
// the resolver builds and the target `bodega init` dials. A named entry
// inherits none of the default backend's.
func TestSpecForCarriesTheS3StoreKeys(t *testing.T) {
	for _, env := range []string{"AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_S3", "AWS_REQUEST_CHECKSUM_CALCULATION", "AWS_RESPONSE_CHECKSUM_VALIDATION"} {
		t.Setenv(env, "")
	}
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "none"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "none"))
	cfg := &config.Config{
		StorageBackend: "s3", Bucket: "main-bucket", Region: "us-ord",
		Endpoint: "https://us-ord-1.linodeobjects.com", Checksums: bos3.ChecksumsWhenRequired,
		StorageBackends: map[string]config.StorageSpec{
			"minio": {Driver: "s3", Bucket: "minio-bucket", Region: "us-east-1", Endpoint: "https://minio.example.net:9000", PathStyle: true},
			"aws":   {Driver: "s3", Bucket: "aws-bucket", Region: "us-west-2"},
		},
	}
	want := map[string]bos3.Options{
		DefaultName: {Endpoint: "https://us-ord-1.linodeobjects.com", Checksums: bos3.ChecksumsWhenRequired},
		"minio":     {Endpoint: "https://minio.example.net:9000", PathStyle: true},
		"aws":       {},
	}
	r, err := NewResolver(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for name, opts := range want {
		target, err := ResolveS3Target(cfg, name)
		if err != nil {
			t.Fatal(err)
		}
		if target.Options != opts {
			t.Errorf("%s: init target carries %+v, want %+v", name, target.Options, opts)
		}
		store, err := r.ByName(name)
		if err != nil {
			t.Fatal(err)
		}
		got := store.(*S3).client.S3Client().Options()
		if aws.ToString(got.BaseEndpoint) != opts.Endpoint || got.UsePathStyle != opts.PathStyle {
			t.Errorf("%s: service client has endpoint %q, path style %v; want %q, %v",
				name, aws.ToString(got.BaseEndpoint), got.UsePathStyle, opts.Endpoint, opts.PathStyle)
		}
		wantSum := aws.RequestChecksumCalculationWhenSupported
		if opts.Checksums == bos3.ChecksumsWhenRequired {
			wantSum = aws.RequestChecksumCalculationWhenRequired
		}
		if got.RequestChecksumCalculation != wantSum {
			t.Errorf("%s: service client request checksums = %v, want %v", name, got.RequestChecksumCalculation, wantSum)
		}
	}
}

func TestReviewF113S3FanoutKeepsSeparateEndpoints(t *testing.T) {
	for _, key := range []string{"AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_S3", "AWS_REQUEST_CHECKSUM_CALCULATION", "AWS_RESPONSE_CHECKSUM_VALIDATION"} {
		t.Setenv(key, "")
	}
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "none"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "none"))
	cfg := &config.Config{
		StorageBackend: "s3", Bucket: "artifacts", Region: "us-east-1", Endpoint: "https://minio-a.example.net",
		StorageBackends: map[string]config.StorageSpec{
			"archive": {Driver: "s3", Bucket: "artifacts", Region: "us-east-1", Endpoint: "https://minio-b.example.net"},
			"alias":   {Driver: "s3", Bucket: "artifacts", Region: "us-east-1", Endpoint: "https://minio-a.example.net", PathStyle: true, Checksums: bos3.ChecksumsWhenRequired},
		},
	}
	r, err := NewResolver(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := r.ByName("archive")
	if err != nil {
		t.Fatal(err)
	}
	if r.Default().Label() == archive.Label() {
		t.Errorf("different endpoints share location %q", archive.Label())
	}
	got := r.Fanout(context.Background(), "apt", []string{"archive", "alias"})
	var names []string
	for _, store := range got {
		names = append(names, store.Name)
	}
	if len(got) != 2 {
		t.Errorf("Fanout = %v; want two locations (default/alias plus archive)", names)
	}
}

// isolateS3Env keeps the SDK from reading an endpoint, a checksum mode or a
// profile off the machine running the test.
func isolateS3Env(t *testing.T) {
	t.Helper()
	for _, key := range []string{"AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_S3", "AWS_REQUEST_CHECKSUM_CALCULATION", "AWS_RESPONSE_CHECKSUM_VALIDATION"} {
		t.Setenv(key, "")
	}
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "none"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "none"))
}

func s3Label(t *testing.T, region string, opts bos3.Options) string {
	t.Helper()
	client, err := bos3.NewClient(context.Background(), "b", region, opts)
	if err != nil {
		t.Fatal(err)
	}
	return NewS3(client).Label()
}

// TestS3LabelIsOnePerLocation holds S3.Label to what dedupByLabel and
// 'pkg move' read it as: equal exactly when two stores are one place. A
// spelling of one endpoint that produced a second label would list a bucket
// twice; two endpoints under one label is the collision that hid a store.
func TestS3LabelIsOnePerLocation(t *testing.T) {
	isolateS3Env(t)
	cases := []struct {
		name     string
		endpoint string
		want     string
	}{
		{"AWS", "", "s3://b"},
		{"endpoint", "https://minio.example.net", "s3+https://minio.example.net/b"},
		{"case, default port and trailing slash", "HTTPS://MinIO.Example.NET:443/", "s3+https://minio.example.net/b"},
		{"trailing dot", "https://minio.example.net.", "s3+https://minio.example.net/b"},
		{"another port is another service", "https://minio.example.net:9000", "s3+https://minio.example.net:9000/b"},
		{"http default port", "http://minio.example.net:80", "s3+http://minio.example.net/b"},
		{"https port over http is not the default", "http://minio.example.net:443", "s3+http://minio.example.net:443/b"},
		{"path", "https://gw.example.net/tenant-a/", "s3+https://tenant-a.gw.example.net/b"},
		{"another path is another service", "https://gw.example.net/tenant-b", "s3+https://tenant-b.gw.example.net/b"},
		{"IPv6", "https://[::1]:9000", "s3+https://[::1]:9000/b"},
		{"AWS regional endpoint is AWS", "https://s3.us-west-2.amazonaws.com", "s3://b"},
		{"AWS global endpoint", "https://s3.amazonaws.com/", "s3://b"},
		{"AWS dash-region endpoint", "https://s3-us-west-2.amazonaws.com", "s3://b"},
		{"AWS dual-stack endpoint", "https://S3.dualstack.eu-west-1.amazonaws.com:443", "s3://b"},
		{"AWS FIPS endpoint", "https://s3-fips.us-gov-west-1.amazonaws.com", "s3://b"},
		{"AWS accelerate endpoint", "https://s3-accelerate.amazonaws.com", "s3://b"},
		{"AWS China endpoint", "https://s3.cn-north-1.amazonaws.com.cn", "s3://b"},
		{"AWS interface VPC endpoint", "https://bucket.vpce-0a1b2c-abcd.s3.us-east-1.vpce.amazonaws.com", "s3://b"},
		{"AWS over plaintext is still AWS", "http://s3.us-west-2.amazonaws.com", "s3://b"},
		{"a port on an AWS name is not AWS's service", "https://s3.us-west-2.amazonaws.com:9000", "s3+https://s3.us-west-2.amazonaws.com:9000/b"},
		{"the first path segment on an AWS host is the bucket", "https://s3.us-west-2.amazonaws.com/x", "s3://x/b"},
		{"Outposts is another namespace", "https://s3-outposts.us-west-2.amazonaws.com", "s3+https://s3-outposts.us-west-2.amazonaws.com/b"},
		{"an AWS suffix inside another domain", "https://s3.us-west-2.amazonaws.com.example.net", "s3+https://s3.us-west-2.amazonaws.com.example.net/b"},
		{"an AWS lookalike", "https://xs3.amazonaws.com", "s3+https://xs3.amazonaws.com/b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := s3Label(t, "us-east-1", bos3.Options{Endpoint: tc.endpoint}); got != tc.want {
				t.Errorf("Label = %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("region is not part of an AWS location", func(t *testing.T) {
		if a, b := s3Label(t, "us-east-1", bos3.Options{}), s3Label(t, "eu-west-1", bos3.Options{}); a != b {
			t.Errorf("one AWS bucket under two regions = %q and %q, want one label", a, b)
		}
	})
	t.Run("addressing and checksums are not part of a location", func(t *testing.T) {
		plain := s3Label(t, "us-east-1", bos3.Options{Endpoint: "https://minio.example.net"})
		tuned := s3Label(t, "us-east-1", bos3.Options{Endpoint: "https://minio.example.net", PathStyle: true, Checksums: bos3.ChecksumsWhenRequired})
		if plain != tuned {
			t.Errorf("one endpoint = %q and %q, want one label", plain, tuned)
		}
	})
}

// TestS3LabelFollowsTheEnvironmentEndpoint: an entry with no endpoint key
// dials whatever the SDK read, so that is where it is. It must match an entry
// that names the same endpoint by key and differ from AWS.
func TestS3LabelFollowsTheEnvironmentEndpoint(t *testing.T) {
	isolateS3Env(t)
	byKey := s3Label(t, "us-east-1", bos3.Options{Endpoint: "https://minio.example.net"})
	t.Setenv("AWS_ENDPOINT_URL_S3", "https://minio.example.net/")
	if got := s3Label(t, "us-east-1", bos3.Options{}); got != byKey {
		t.Errorf("Label under AWS_ENDPOINT_URL_S3 = %q, want %q", got, byKey)
	}
}

// TestS3LabelNeverPrintsEndpointCredentials: config load refuses userinfo in
// the endpoint key, but nothing checks an endpoint the SDK read from the
// environment, and a label goes to logs and error text.
func TestS3LabelNeverPrintsEndpointCredentials(t *testing.T) {
	isolateS3Env(t)
	for _, endpoint := range []string{
		"https://access:sentinel-secret@minio.example.net",
		"https://access:sentinel-secret@minio.example.net:bad",
		"https://minio.example.net?token=sentinel-secret",
		"access:sentinel-secret@minio.example.net",
		"sentinel-secret",
	} {
		t.Setenv("AWS_ENDPOINT_URL_S3", endpoint)
		got := s3Label(t, "us-east-1", bos3.Options{})
		if strings.Contains(got, "sentinel-secret") {
			t.Errorf("Label for %q = %q, which prints the credential", endpoint, got)
		}
		if got == "s3://b" {
			t.Errorf("Label for %q is AWS's %q, and the client does not dial AWS", endpoint, got)
		}
	}
}

// TestS3BucketLabelDropsTheEndpoint: an s3:// URI written outside bodega
// names a bucket and a key and nothing else, so the form it is matched
// against carries the bucket and the backend's prefix and no endpoint.
func TestS3BucketLabelDropsTheEndpoint(t *testing.T) {
	isolateS3Env(t)
	cfg := &config.Config{
		StorageBackend: "local", StoragePath: t.TempDir(),
		StorageBackends: map[string]config.StorageSpec{
			"aws":    {Driver: "s3", Bucket: "artifacts", Region: "us-east-1"},
			"linode": {Driver: "s3", Bucket: "artifacts", Region: "us-ord", Endpoint: "https://us-ord-1.linodeobjects.com"},
			"cold":   {Driver: "s3", Bucket: "artifacts", Region: "us-ord", Endpoint: "https://us-ord-1.linodeobjects.com", Prefix: "cold/"},
		},
	}
	r, err := NewResolver(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][2]string{
		"aws":    {"s3://artifacts", "s3://artifacts"},
		"linode": {"s3+https://artifacts.us-ord-1.linodeobjects.com", "s3://artifacts"},
		"cold":   {"s3+https://cold.artifacts.us-ord-1.linodeobjects.com", "s3://artifacts/cold"},
	}
	for name, w := range want {
		store, err := r.ByName(name)
		if err != nil {
			t.Fatal(err)
		}
		bucket, ok := S3BucketLabel(store)
		if store.Label() != w[0] || !ok || bucket != w[1] {
			t.Errorf("%s: Label = %q, S3BucketLabel = %q, %v; want %q and %q", name, store.Label(), bucket, ok, w[0], w[1])
		}
	}
	if got, ok := S3BucketLabel(r.Default()); ok {
		t.Errorf("S3BucketLabel(local store) = %q, true; want false", got)
	}
}

// TestS3RecordLabelNamesAWS: the label a record is written under is never
// the bare "s3://<bucket>" a row from before endpoints carries, on AWS or
// off it, with or without a prefix, and is Label for everything else.
func TestS3RecordLabelNamesAWS(t *testing.T) {
	isolateS3Env(t)
	cfg := &config.Config{
		StorageBackend: "local", StoragePath: t.TempDir(),
		StorageBackends: map[string]config.StorageSpec{
			"aws":      {Driver: "s3", Bucket: "artifacts", Region: "us-east-1"},
			"regional": {Driver: "s3", Bucket: "artifacts", Region: "us-west-2", Endpoint: "https://s3.us-west-2.amazonaws.com"},
			"nested":   {Driver: "s3", Bucket: "artifacts", Region: "us-east-1", Prefix: "cold/"},
			"linode":   {Driver: "s3", Bucket: "artifacts", Region: "us-ord", Endpoint: "https://us-ord-1.linodeobjects.com"},
			"cold":     {Driver: "s3", Bucket: "artifacts", Region: "us-ord", Endpoint: "https://us-ord-1.linodeobjects.com", Prefix: "cold/"},
		},
	}
	r, err := NewResolver(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"aws":      "s3+aws://artifacts",
		"regional": "s3+aws://artifacts",
		"nested":   "s3+aws://artifacts/cold",
		"linode":   "s3+https://artifacts.us-ord-1.linodeobjects.com",
		"cold":     "s3+https://cold.artifacts.us-ord-1.linodeobjects.com",
	}
	for name, w := range want {
		store, err := r.ByName(name)
		if err != nil {
			t.Fatal(err)
		}
		bucket, _ := S3BucketLabel(store)
		if got := S3RecordLabel(store); got != w || got == bucket {
			t.Errorf("%s: S3RecordLabel = %q, want %q and never the bare spelling %q", name, got, w, bucket)
		}
	}
	if got := S3RecordLabel(r.Default()); got != r.Default().Label() {
		t.Errorf("S3RecordLabel(local store) = %q, want its Label %q", got, r.Default().Label())
	}
}

func TestReviewF113EndpointPathKeepsBucketBoundary(t *testing.T) {
	isolateS3Env(t)
	cfg := &config.Config{
		StorageBackend: "s3", Bucket: "artifacts", Region: "us-east-1",
		Endpoint: "https://store.example.net/tenant",
		StorageBackends: map[string]config.StorageSpec{
			"other": {Driver: "s3", Bucket: "tenant", Region: "us-east-1", Endpoint: "https://store.example.net", Prefix: "artifacts"},
		},
	}
	stores, err := NewResolver(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var routes []string
	for _, name := range []string{DefaultName, "other"} {
		spec, _ := SpecFor(cfg, name)
		client, err := bos3.NewClient(t.Context(), spec.Bucket, spec.Region, spec.S3Options())
		if err != nil {
			t.Fatal(err)
		}
		opts := client.S3Client().Options()
		ep, err := awss3.NewDefaultEndpointResolverV2().ResolveEndpoint(t.Context(), awss3.EndpointParameters{
			Region: aws.String(opts.Region), Bucket: aws.String(spec.Bucket), Endpoint: opts.BaseEndpoint,
			ForcePathStyle: aws.Bool(opts.UsePathStyle),
		})
		if err != nil {
			t.Fatal(err)
		}
		route := strings.TrimRight(ep.URI.String(), "/")
		if spec.Prefix != "" {
			route += "/" + spec.Prefix
		}
		routes = append(routes, route+"/object")
	}
	if routes[0] == routes[1] {
		t.Fatalf("fixture resolved both objects to %s", routes[0])
	}
	t.Logf("SDK routes: %s and %s", routes[0], routes[1])
	other, err := stores.ByName("other")
	if err != nil {
		t.Fatal(err)
	}
	if a, b := stores.Default().Label(), other.Label(); a == b {
		t.Errorf("distinct SDK locations share label %q", a)
	}
	if got := stores.Fanout(t.Context(), "apt", []string{"other"}); len(got) != 2 {
		t.Errorf("Fanout returned %d locations, want 2", len(got))
	}
}

// sdkNamespace is what a key is appended to on the wire for one (endpoint,
// bucket, prefix), computed from the SDK's resolver the way the request
// middleware applies it: the resolved scheme and host, the decoded path with
// one "/" closing it, then the prefix.
func sdkNamespace(t *testing.T, client *bos3.Client, bucket, prefix string) string {
	t.Helper()
	opts := client.S3Client().Options()
	ep, err := awss3.NewDefaultEndpointResolverV2().ResolveEndpoint(t.Context(), awss3.EndpointParameters{
		Region: aws.String(opts.Region), Bucket: aws.String(bucket), Endpoint: opts.BaseEndpoint,
		ForcePathStyle: aws.Bool(opts.UsePathStyle),
	})
	if err != nil {
		return "unresolved " + aws.ToString(opts.BaseEndpoint) + " " + bucket + " " + prefix
	}
	return ep.URI.Scheme + "://" + ep.URI.Host + strings.TrimSuffix(ep.URI.Path, "/") + "/" + prefix
}

// TestS3LabelsKeepComponentBoundaries: two (endpoint, bucket, prefix) tuples
// share a location label, and a record label, exactly when the SDK sends
// their keys under one URL, whichever component a separator is moved into,
// and a record label is never another location's label. The names here are
// ones the SDK does not address as a host label, so the SDK's route is the
// whole of the identity; TestS3LocationIsTheSDKRoute covers the ones it does.
func TestS3LabelsKeepComponentBoundaries(t *testing.T) {
	isolateS3Env(t)
	tuples := [][3]string{
		{"", "a", ""}, {"", "a", "b"}, {"", "a", "b/"}, {"", "a/b", ""}, {"", "a", "b#c"}, {"", "a#b", "c"},
		{"https://gw.example.net", "a", ""}, {"https://gw.example.net", "a", "b"}, {"https://gw.example.net", "a", "b/"},
		{"https://gw.example.net", "a/b", ""}, {"https://gw.example.net", "a#b", ""},
		{"https://gw.example.net/a", "b", ""}, {"https://gw.example.net/a", "b", "c"},
		{"https://gw.example.net/a/b", "c", ""}, {"https://gw.example.net/a%2Fb", "c", ""},
		{"https://gw.example.net/a", "b", "c/"}, {"https://gw.example.net/a//", "b", "c/"},
		{"aws://a", "b", ""}, {"aws://a/b", "c", ""},
	}
	type seen struct {
		tuple     [3]string
		namespace string
	}
	labels, records := map[string]seen{}, map[string]seen{}
	var shared int
	for _, tuple := range tuples {
		client, err := bos3.NewClient(t.Context(), tuple[1], "us-east-1", bos3.Options{Endpoint: tuple[0]})
		if err != nil {
			t.Fatal(err)
		}
		var store ObjectStore = &S3{client: client}
		if tuple[2] != "" {
			store = &prefixed{inner: store, prefix: tuple[2]}
		}
		this := seen{tuple, sdkNamespace(t, client, tuple[1], tuple[2])}
		for label, into := range map[string]map[string]seen{store.Label(): labels, S3RecordLabel(store): records} {
			for prevLabel, prev := range into {
				if (prevLabel == label) != (prev.namespace == this.namespace) {
					t.Errorf("%q is %q under %s and %q is %q under %s", prev.tuple, prevLabel, prev.namespace, tuple, label, this.namespace)
				}
			}
			if _, dup := into[label]; dup {
				shared++
			}
			into[label] = this
		}
	}
	// Each of "/a/b", its encoded spelling and the same path split across
	// bucket and prefix is one namespace, so the list has to hold aliases or
	// it only shows that different strings differ.
	if shared < 6 {
		t.Errorf("the tuples hold %d aliases, want at least 6", shared)
	}
	for record, r := range records {
		if l, dup := labels[record]; dup && l.namespace != r.namespace {
			t.Errorf("the record label of %q is the label %q of %q", r.tuple, record, l.tuple)
		}
	}
}

// TestS3LocationIsTheSDKRoute: every consumer of an s3 identity reads one
// location, and it follows where the SDK sends a request and not how the
// configuration spelled it. Each group is one object namespace under several
// spellings (the addressing style, an encoded endpoint path, a path segment
// moved between endpoint, bucket and prefix) and no two groups are the same
// place.
func TestS3LocationIsTheSDKRoute(t *testing.T) {
	isolateS3Env(t)
	type spelling struct {
		endpoint  string
		pathStyle bool
		bucket    string
		prefix    string
	}
	const gw = "https://gw.example.net"
	groups := []struct {
		label, record string
		spellings     []spelling
	}{
		{"s3+https://artifacts.gw.example.net", "", []spelling{
			{gw, false, "artifacts", ""}, {gw, true, "artifacts", ""}, {"HTTPS://GW.Example.NET:443/", true, "artifacts", ""},
		}},
		{"s3+https://cold.artifacts.gw.example.net", "", []spelling{
			{gw, false, "artifacts", "cold/"}, {gw, true, "artifacts", "cold"},
			{"https://artifacts.gw.example.net", true, "cold", ""}, {"https://artifacts.gw.example.net", false, "cold", ""},
			{gw + "/artifacts", true, "cold", ""}, {gw + "/%61rtifacts/", true, "cold", ""},
		}},
		{"s3+https://tenant.artifacts.gw.example.net", "", []spelling{
			{gw + "/tenant", false, "artifacts", ""}, {gw, true, "artifacts", "tenant/"},
		}},
		{"s3+https://artifacts.tenant.gw.example.net", "", []spelling{
			{gw + "/tenant", true, "artifacts", ""}, {gw, false, "tenant", "artifacts/"},
		}},
		{"s3+https://gw.example.net/a/b/artifacts", "", []spelling{
			{gw + "/a/b", true, "artifacts", ""}, {gw + "/a%2Fb", true, "artifacts", ""}, {gw + "/a", true, "b", "artifacts/"},
		}},
		{"s3+https://gw.example.net/Cold", "", []spelling{{gw, true, "Cold", ""}, {gw, false, "Cold", ""}}},
		{"s3+https://cold.artifacts.gw.example.net/", "", []spelling{{gw, true, "artifacts", "cold//"}, {gw, false, "artifacts", "cold//"}}},
		{"s3+http://artifacts.gw.example.net", "", []spelling{{"http://gw.example.net", false, "artifacts", ""}}},
		{"s3+https://10.0.0.1/artifacts", "", []spelling{{"https://10.0.0.1", false, "artifacts", ""}, {"https://10.0.0.1", true, "artifacts", ""}}},
		{"s3://artifacts", "s3+aws://artifacts", []spelling{
			{"", false, "artifacts", ""}, {"", true, "artifacts", ""}, {"https://s3.eu-west-1.amazonaws.com", true, "artifacts", ""},
		}},
		{"s3://artifacts/cold", "s3+aws://artifacts/cold", []spelling{
			{"", false, "artifacts", "cold/"}, {"https://s3.us-west-2.amazonaws.com", false, "artifacts", "cold/"},
			{"https://s3.us-west-2.amazonaws.com/artifacts", true, "cold", ""}, {"https://s3.us-west-2.amazonaws.com/cold", false, "artifacts", ""},
		}},
		{"s3://my.dotted.bucket/cold", "s3+aws://my.dotted.bucket/cold", []spelling{
			{"", false, "my.dotted.bucket", "cold/"}, {"http://s3.us-west-2.amazonaws.com", false, "my.dotted.bucket", "cold/"},
		}},
	}
	for _, g := range groups {
		if g.record == "" {
			g.record = g.label
		}
		for _, sp := range g.spellings {
			store, err := NewFromSpec(t.Context(), Spec{Driver: "s3", Bucket: sp.bucket, Region: "us-east-1", Prefix: sp.prefix, Endpoint: sp.endpoint, PathStyle: sp.pathStyle})
			if err != nil {
				t.Fatal(err)
			}
			if got := store.Label(); got != g.label {
				t.Errorf("%+v: Label = %q, want %q", sp, got, g.label)
			}
			if got := S3RecordLabel(store); got != g.record {
				t.Errorf("%+v: S3RecordLabel = %q, want %q", sp, got, g.record)
			}
		}
	}
}
