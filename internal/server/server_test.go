package server_test

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/server"
	"github.com/ravinald/bodega/internal/storage"
)

// mockStore implements storage.ObjectStore for testing.
type mockStore struct {
	objects    map[string]string
	prefixKeys map[string][]string
}

func (m *mockStore) Get(_ context.Context, key string) ([]byte, error) {
	data, ok := m.objects[key]
	if !ok {
		return nil, nil
	}
	return []byte(data), nil
}

func (m *mockStore) GetStream(_ context.Context, key string) (*storage.StreamResult, error) {
	data, ok := m.objects[key]
	if !ok {
		return nil, nil
	}
	return &storage.StreamResult{
		Body:          io.NopCloser(strings.NewReader(data)),
		ContentLength: int64(len(data)),
		ETag:          "abc123",
	}, nil
}

func (m *mockStore) Head(_ context.Context, key string) (*storage.ObjectInfo, error) {
	data, ok := m.objects[key]
	return &storage.ObjectInfo{Key: key, Exists: ok, Size: int64(len(data))}, nil
}

func (m *mockStore) List(_ context.Context, prefix string) ([]string, error) {
	if keys, ok := m.prefixKeys[prefix]; ok {
		return keys, nil
	}
	var result []string
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) {
			result = append(result, k)
		}
	}
	return result, nil
}

func (m *mockStore) Put(_ context.Context, key string, data []byte) error {
	m.objects[key] = string(data)
	return nil
}

func (m *mockStore) PutFile(_ context.Context, _, key string) error {
	m.objects[key] = ""
	return nil
}

func (m *mockStore) Delete(_ context.Context, key string) error {
	delete(m.objects, key)
	return nil
}

func (m *mockStore) SyncDir(_ context.Context, _ io.Writer, _, _ string) (int, error) {
	return 0, nil
}

func (m *mockStore) Label() string { return "mock://" }

// newTestServer builds a Server with canned manifests and a mock S3 client.
func newTestServer(t *testing.T) (*httptest.Server, *mockStore) {
	t.Helper()

	store := manifest.NewLocalStore(t.TempDir())
	ctx := t.Context()
	_ = store.AddVersion(ctx, manifest.TypeApt, "amazon-efs-utils", manifest.VersionEntry{
		Version:      "2.4.2",
		SourceName:   "amazon-efs-utils",
		ArtifactSize: 12345,
		Checksum:     &manifest.Checksum{Algorithm: "sha256", Value: "deadbeef0123456789abcdef"},
		Metadata: map[string]string{
			"Architecture":   "amd64",
			"Maintainer":     "Amazon.com, Inc.",
			"Installed-Size": "200",
			"Section":        "utils",
			"Priority":       "optional",
			"Depends":        "nfs-common",
		},
		Description: "Amazon EFS mount helper",
	})
	_ = store.AddVersion(ctx, manifest.TypeApt, "linux-headers", manifest.VersionEntry{
		Version:    "5.15.0",
		SourceName: "linux-headers",
		Metadata: map[string]string{
			"Architecture": "arm64",
			"Section":      "kernel",
			"Priority":     "optional",
		},
		Description: "Linux kernel headers",
	})
	_ = store.AddVersion(ctx, manifest.TypeGit, "netbox", manifest.VersionEntry{
		URL: "https://github.com/netbox-community/netbox",
		Ref: "v4.5.5",
	})
	_ = store.AddVersion(ctx, manifest.TypePypi, "boto3", manifest.VersionEntry{})
	_ = store.AddVersion(ctx, manifest.TypePypi, "django", manifest.VersionEntry{})
	_ = store.AddVersion(ctx, manifest.TypeBinary, "awscli-v2", manifest.VersionEntry{
		Version: "2.0.0",
		URL:     "https://example.com/awscli.zip",
	})

	mock := &mockStore{
		objects: map[string]string{
			"packages/apt/gpg-key.asc": "-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n",
			"packages/apt/pool/main/a/amazon-efs-utils/amazon-efs-utils_2.4.2_amd64.deb": "\x00deb-content-efs",
			"packages/apt/pool/main/l/linux-headers/linux-headers_5.15.0_arm64.deb":      "\x00deb-content-linux",
			"pypi/wheels/boto3-1.35.0-py3-none-any.whl":                                  "fake-wheel-boto3",
			"pypi/wheels/django-5.0.0-py3-none-any.whl":                                  "fake-wheel-django",
			"repos/netbox/netbox-v4.5.5.bundle":                                          "fake-bundle",
			"binaries/awscli-v2/2.0.0/awscli.zip":                                        "fake-binary",
		},
	}

	cfg := &config.Config{
		Bucket:      "test-bucket",
		Region:      "us-west-2",
		ManifestDir: "manifests",
		AptCodename: "noble",
	}

	srv := server.New(cfg, store, mock, ":0", nil)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, mock
}

// ---- Health ----------------------------------------------------------------

func TestHealthz(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.TrimSpace(string(body)) != "ok" {
		t.Errorf("body = %q, want \"ok\"", string(body))
	}
}

// ---- APT proxy -------------------------------------------------------------

func TestAptRelease(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/apt/dists/noble/Release")
	if err != nil {
		t.Fatalf("GET /apt/dists/noble/Release: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	for _, want := range []string{"Codename: noble", "Components: main", "SHA256:", "Architectures:"} {
		if !strings.Contains(s, want) {
			t.Errorf("Release missing %q:\n%s", want, s)
		}
	}
}

func TestAptReleaseWrongCodename(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/apt/dists/jammy/Release")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for wrong codename", resp.StatusCode)
	}
}

func TestAptGPGKey(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/apt/gpg-key.asc")
	if err != nil {
		t.Fatalf("GET /apt/gpg-key.asc: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
}

func TestAptNotFound(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/apt/dists/noble/nonexistent")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestAptPackages(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/apt/dists/noble/main/binary-amd64/Packages")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	// Should contain the amazon-efs-utils entry (amd64).
	for _, want := range []string{
		"Package: amazon-efs-utils",
		"Version: 2.4.2",
		"Architecture: amd64",
		"Maintainer: Amazon.com, Inc.",
		"Section: utils",
		"SHA256: deadbeef0123456789abcdef",
		"Filename: pool/main/a/amazon-efs-utils/amazon-efs-utils_2.4.2_amd64.deb",
		"Description: Amazon EFS mount helper",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("Packages missing %q:\n%s", want, s)
		}
	}
	// Should NOT contain the arm64 linux-headers entry.
	if strings.Contains(s, "linux-headers") {
		t.Error("Packages for amd64 should not contain arm64-only linux-headers")
	}
}

func TestAptPackagesGz(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/apt/dists/noble/main/binary-amd64/Packages.gz")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "application/gzip" {
		t.Errorf("Content-Type = %q, want application/gzip", ct)
	}
	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	body, _ := io.ReadAll(gr)
	if !strings.Contains(string(body), "Package: amazon-efs-utils") {
		t.Errorf("decompressed Packages.gz missing expected content:\n%s", string(body))
	}
}

func TestAptPackagesArchFilter(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/apt/dists/noble/main/binary-arm64/Packages")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, "linux-headers") {
		t.Error("arm64 Packages should contain linux-headers")
	}
	if strings.Contains(s, "amazon-efs-utils") {
		t.Error("arm64 Packages should not contain amd64-only amazon-efs-utils")
	}
}

func TestAptPackagesFieldInjection(t *testing.T) {
	// Ensure metadata with embedded newlines cannot inject extra fields.
	store := manifest.NewLocalStore(t.TempDir())
	ctx := context.Background()
	_ = store.AddVersion(ctx, manifest.TypeApt, "evil-pkg", manifest.VersionEntry{
		Version: "1.0",
		Metadata: map[string]string{
			"Architecture": "amd64",
			"Maintainer":   "attacker\nEvil-Field: injected",
			"Section":      "utils",
			"Priority":     "optional",
		},
		Description: "test package",
	})
	mock := &mockStore{
		objects: map[string]string{
			"packages/apt/pool/main/e/evil-pkg/evil-pkg_1.0_amd64.deb": "fake",
		},
	}
	cfg := &config.Config{Bucket: "test", Region: "us-west-2", ManifestDir: "manifests"}
	srv := server.New(cfg, store, mock, ":0", nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/apt/dists/noble/main/binary-amd64/Packages")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "Evil-Field") {
		t.Errorf("field injection succeeded — newlines in metadata were not sanitized:\n%s", string(body))
	}
}

// ---- PyPI ------------------------------------------------------------------

func TestPypiRootIndex(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/pypi/simple/")
	if err != nil {
		t.Fatalf("GET /pypi/simple/: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	html := string(body)
	for _, pkg := range []string{"boto3", "django"} {
		if !strings.Contains(html, pkg) {
			t.Errorf("root index missing package %q", pkg)
		}
	}
}

func TestPypiPackageIndex(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/pypi/simple/boto3/")
	if err != nil {
		t.Fatalf("GET /pypi/simple/boto3/: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	html := string(body)
	if !strings.Contains(html, "boto3-1.35.0-py3-none-any.whl") {
		t.Errorf("package index missing wheel link: %s", html)
	}
	if strings.Contains(html, "django") {
		t.Error("boto3 index should not contain django wheels")
	}
}

func TestPypiPackageIndexNormalization(t *testing.T) {
	// pip normalises package names: boto_3, Boto3, boto3 all refer to the same package.
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/pypi/simple/Boto3/")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (normalized lookup)", resp.StatusCode)
	}
}

func TestPypiPackageNotFound(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/pypi/simple/nonexistent/")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestPypiWheelProxy(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/pypi/wheels/boto3-1.35.0-py3-none-any.whl")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "fake-wheel-boto3" {
		t.Errorf("body = %q, want fake-wheel-boto3", string(body))
	}

	// Wheel files must carry immutable cache headers.
	cc := resp.Header.Get("Cache-Control")
	if !strings.Contains(cc, "immutable") {
		t.Errorf("Cache-Control = %q, want immutable", cc)
	}
}

// ---- Git bundles -----------------------------------------------------------

func TestGitBundleProxy(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/git/netbox/netbox-v4.5.5.bundle")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "fake-bundle" {
		t.Errorf("body = %q, want fake-bundle", string(body))
	}

	cc := resp.Header.Get("Cache-Control")
	if !strings.Contains(cc, "immutable") {
		t.Errorf("Cache-Control = %q, want immutable", cc)
	}
}

// ---- Binaries --------------------------------------------------------------

func TestBinaryProxy(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/binaries/awscli-v2/2.0.0/awscli.zip")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "fake-binary" {
		t.Errorf("body = %q, want fake-binary", string(body))
	}
}

// ---- API -------------------------------------------------------------------

func TestAPIPackages(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/api/v1/packages")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	for _, key := range []string{"apt", "git", "pypi", "binary"} {
		if _, ok := result[key]; !ok {
			t.Errorf("response missing key %q", key)
		}
	}
}

func TestAPIPackagesByType(t *testing.T) {
	ts, _ := newTestServer(t)
	tests := []struct {
		typ      string
		wantCode int
	}{
		{"apt", http.StatusOK},
		{"git", http.StatusOK},
		{"pypi", http.StatusOK},
		{"binary", http.StatusOK},
		{"unknown", http.StatusNotFound},
	}

	for _, tc := range tests {
		t.Run(tc.typ, func(t *testing.T) {
			resp, err := http.Get(ts.URL + "/api/v1/packages/" + tc.typ)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != tc.wantCode {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.wantCode)
			}
		})
	}
}

func TestAPIPackageSingle(t *testing.T) {
	ts, _ := newTestServer(t)
	tests := []struct {
		path     string
		wantCode int
		wantName string
	}{
		{"/api/v1/packages/apt/amazon-efs-utils", http.StatusOK, "amazon-efs-utils"},
		{"/api/v1/packages/apt/nonexistent", http.StatusNotFound, ""},
		{"/api/v1/packages/git/netbox", http.StatusOK, "netbox"},
		{"/api/v1/packages/binary/awscli-v2", http.StatusOK, "awscli-v2"},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			resp, err := http.Get(ts.URL + tc.path)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantCode {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.wantCode)
			}
			if tc.wantName != "" {
				var result map[string]interface{}
				if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
					t.Fatalf("decode JSON: %v", err)
				}
				if got, _ := result["name"].(string); got != tc.wantName {
					t.Errorf("name = %q, want %q", got, tc.wantName)
				}
			}
		})
	}
}

func TestAPIStatus(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/api/v1/status")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if _, ok := result["healthy"]; !ok {
		t.Error("response missing 'healthy' field")
	}
	if _, ok := result["entry_count"]; !ok {
		t.Error("response missing 'entry_count' field")
	}
}

func TestAPIConfig(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/api/v1/config")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if result["bucket"] != "test-bucket" {
		t.Errorf("bucket = %v, want test-bucket", result["bucket"])
	}
	if result["region"] != "us-west-2" {
		t.Errorf("region = %v, want us-west-2", result["region"])
	}
	// build_root must NOT be present — it is a sensitive filesystem path.
	if _, ok := result["build_root"]; ok {
		t.Error("config response must not expose build_root")
	}
}

// ---- Streaming correctness -------------------------------------------------

func TestS3ProxyStreamsLargeBody(t *testing.T) {
	// Verify the proxy streams rather than buffers by serving a non-trivial body.
	ts, mock := newTestServer(t)
	large := strings.Repeat("x", 1<<20) // 1 MiB
	mock.objects["packages/apt/pool/main/t/test-large/test-large_1.0_amd64.deb"] = large

	resp, err := http.Get(ts.URL + "/apt/pool/main/t/test-large/test-large_1.0_amd64.deb")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if len(body) != len(large) {
		t.Errorf("body length = %d, want %d", len(body), len(large))
	}
}

func TestS3ProxyContentLength(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/apt/pool/main/a/amazon-efs-utils/amazon-efs-utils_2.4.2_amd64.deb")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.ContentLength <= 0 {
		t.Errorf("Content-Length = %d, want > 0", resp.ContentLength)
	}
}
