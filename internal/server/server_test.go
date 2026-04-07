package server_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/config"
	"github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/manifest"
	bos3 "github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/s3"
	"github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/server"
)

// mockS3 is a test double for the s3Getter interface.
type mockS3 struct {
	// objects maps S3 keys to their raw content.
	objects map[string]string
	// prefixKeys maps a prefix to the list of keys returned by ListPrefix.
	prefixKeys map[string][]string
}

func (m *mockS3) GetObjectStream(_ context.Context, key string) (*bos3.StreamResult, error) {
	data, ok := m.objects[key]
	if !ok {
		return nil, nil // not found
	}
	return &bos3.StreamResult{
		Body:          io.NopCloser(strings.NewReader(data)),
		ContentLength: int64(len(data)),
		ETag:          "abc123",
	}, nil
}

func (m *mockS3) ListPrefix(_ context.Context, prefix string) ([]string, error) {
	if keys, ok := m.prefixKeys[prefix]; ok {
		return keys, nil
	}
	// Fall back to scanning the objects map.
	var result []string
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) {
			result = append(result, k)
		}
	}
	return result, nil
}

func (m *mockS3) HeadObject(_ context.Context, key string) (*bos3.ObjectStatus, error) {
	_, ok := m.objects[key]
	return &bos3.ObjectStatus{Key: key, Exists: ok}, nil
}

// newTestServer builds a Server with canned manifests and a mock S3 client.
func newTestServer(t *testing.T) (*httptest.Server, *mockS3) {
	t.Helper()

	store := &manifest.Store{
		Apt: []manifest.AptEntry{
			{Name: "amazon-efs-utils", Version: "1.36.0"},
			{Name: "linux-headers", Version: "5.15.0"},
		},
		Git: []manifest.GitEntry{
			{Name: "netbox", URL: "https://github.com/netbox-community/netbox", Ref: "v4.5.5"},
		},
		Pypi: manifest.PypiManifest{
			ConfigVersion: 1,
			Version:       "v4.5.5",
			Packages: []manifest.PypiPackage{
				{Name: "boto3"},
				{Name: "django"},
			},
		},
		Binary: []manifest.BinaryEntry{
			{Name: "awscli-v2", Version: "2.0.0", URL: "https://example.com/awscli.zip"},
		},
	}

	mock := &mockS3{
		objects: map[string]string{
			"packages/apt/dists/noble/Release":   "Archive: ubuntu\nVersion: 22.04\n",
			"packages/apt/gpg-key.asc":           "-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n",
			"packages/apt/pool/main/a/foo/foo.deb": "\x00deb-content",
			"pypi/wheels/boto3-1.35.0-py3-none-any.whl":  "fake-wheel-boto3",
			"pypi/wheels/django-5.0.0-py3-none-any.whl":  "fake-wheel-django",
			"repos/netbox/netbox-v4.5.5.bundle":          "fake-bundle",
			"binaries/awscli-v2/2.0.0/awscli.zip":       "fake-binary",
		},
	}

	cfg := &config.Config{
		Bucket:      "test-bucket",
		Region:      "us-west-2",
		ManifestDir: "manifests",
	}

	srv := server.NewWithS3Getter(cfg, store, mock, ":0", nil)
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
	if !strings.Contains(string(body), "Archive: ubuntu") {
		t.Errorf("body does not contain Release data: %q", string(body))
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
	mock.objects["packages/apt/dists/noble/Packages.gz"] = large

	resp, err := http.Get(ts.URL + "/apt/dists/noble/Packages.gz")
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
	resp, err := http.Get(ts.URL + "/apt/dists/noble/Release")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.ContentLength <= 0 {
		t.Errorf("Content-Length = %d, want > 0", resp.ContentLength)
	}
}
