package s3_test

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
	bos3 "github.com/ravinald/bodega/internal/s3"
)

// fakeProber is an in-memory ObjectProber recording every key it is asked about.
type fakeProber struct {
	objects map[string]int64
	heads   []string
}

func (f *fakeProber) HeadObject(_ context.Context, key string) (*bos3.ObjectStatus, error) {
	f.heads = append(f.heads, key)
	size, ok := f.objects[key]
	return &bos3.ObjectStatus{Key: key, Exists: ok, Size: size, ETag: "etag-" + key}, nil
}

func (f *fakeProber) ListPrefix(_ context.Context, prefix string) ([]string, error) {
	var out []string
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

// TestCheckAptStatusPoolOnly pins the fix for the dead dists/ probe: a store
// holding only pool objects must report its apt entries present. Both the
// _pool_path path and the pool-listing fallback are covered.
func TestCheckAptStatusPoolOnly(t *testing.T) {
	ctx := t.Context()
	store := manifest.NewLocalStore(t.TempDir())

	if err := store.AddVersion(ctx, manifest.TypeApt, "amazon-efs-utils", manifest.VersionEntry{
		Version:    "2.4.2",
		SourceName: "amazon-efs-utils",
		Metadata: map[string]string{
			"Architecture": "amd64",
			"_pool_path":   "pool/main/a/amazon-efs-utils/amazon-efs-utils_2.4.2_amd64.deb",
		},
	}); err != nil {
		t.Fatalf("add amazon-efs-utils: %v", err)
	}
	// No _pool_path: predates the metadata key, so status must fall back to a
	// pool listing rather than report a false negative.
	if err := store.AddVersion(ctx, manifest.TypeApt, "linux-headers", manifest.VersionEntry{
		Version:    "5.15.0",
		SourceName: "linux-headers",
		Metadata:   map[string]string{"Architecture": "arm64"},
	}); err != nil {
		t.Fatalf("add linux-headers: %v", err)
	}
	// Nothing in the pool backs this one.
	if err := store.AddVersion(ctx, manifest.TypeApt, "nginx", manifest.VersionEntry{
		Version:    "1.24.0",
		SourceName: "nginx",
		Metadata:   map[string]string{"Architecture": "amd64"},
	}); err != nil {
		t.Fatalf("add nginx: %v", err)
	}

	// A healthy install: pool objects, no dists/ tree anywhere.
	fake := &fakeProber{objects: map[string]int64{
		"packages/apt/pool/main/a/amazon-efs-utils/amazon-efs-utils_2.4.2_amd64.deb": 12345,
		"packages/apt/pool/main/l/linux-headers/linux-headers_5.15.0_arm64.deb":      678,
	}}

	statuses, err := bos3.CheckStatus(ctx, fake, store, []string{manifest.TypeApt})
	if err != nil {
		t.Fatalf("CheckStatus: %v", err)
	}

	byName := make(map[string]bos3.EntryStatus, len(statuses))
	for _, s := range statuses {
		byName[s.Name] = s
	}
	if len(byName) != 3 {
		t.Fatalf("got %d entries, want 3: %+v", len(byName), statuses)
	}

	want := []struct {
		name string
		key  string
		inS3 bool
		size int64
	}{
		{"amazon-efs-utils@2.4.2", "packages/apt/pool/main/a/amazon-efs-utils/amazon-efs-utils_2.4.2_amd64.deb", true, 12345},
		{"linux-headers@5.15.0", "packages/apt/pool/main/l/linux-headers/linux-headers_5.15.0_arm64.deb", true, 678},
		{"nginx@1.24.0", "", false, 0},
	}
	for _, w := range want {
		got, ok := byName[w.name]
		if !ok {
			t.Errorf("%s: missing from status output", w.name)
			continue
		}
		if got.InS3 != w.inS3 {
			t.Errorf("%s: InS3 = %v, want %v", w.name, got.InS3, w.inS3)
		}
		if got.S3Key != w.key {
			t.Errorf("%s: S3Key = %q, want %q", w.name, got.S3Key, w.key)
		}
		if got.SizeS3 != w.size {
			t.Errorf("%s: SizeS3 = %d, want %d", w.name, got.SizeS3, w.size)
		}
	}

	for _, key := range fake.heads {
		if strings.Contains(key, "/dists/") {
			t.Errorf("probed a generated path that is never stored: %s", key)
		}
	}
}
