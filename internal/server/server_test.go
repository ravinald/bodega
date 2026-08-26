package server_test

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/server"
	"github.com/ravinald/bodega/internal/storage"
)

// memStore returns an in-memory ObjectStore seeded with the given objects.
// storage.Memory is the real implementation the storage conformance suite
// runs against, so a defect it papers over would fail there first — which the
// hand-rolled mock this replaced did not: its Head reported a non-nil
// ObjectInfo on every path and its PutFile stored an empty string, so any
// assertion on uploaded bytes passed without reading them.
func memStore(objects map[string]string) *storage.Memory {
	m := storage.NewMemory()
	for k, v := range objects {
		m.Seed(k, v)
	}
	return m
}

// newTestServer builds a Server with canned manifests and an in-memory store.
func newTestServer(t *testing.T) (*httptest.Server, *storage.Memory) {
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

	mock := memStore(map[string]string{
		"packages/apt/pool/main/a/amazon-efs-utils/amazon-efs-utils_2.4.2_amd64.deb": "\x00deb-content-efs",
		"packages/apt/pool/main/l/linux-headers/linux-headers_5.15.0_arm64.deb":      "\x00deb-content-linux",
		"pypi/wheels/boto3-1.35.0-py3-none-any.whl":                                  "fake-wheel-boto3",
		"pypi/wheels/django-5.0.0-py3-none-any.whl":                                  "fake-wheel-django",
		"repos/netbox/netbox-v4.5.5.bundle":                                          "fake-bundle",
		"binaries/awscli-v2/2.0.0/awscli.zip":                                        "fake-binary",
	})

	cfg := &config.Config{
		Bucket:      "test-bucket",
		Region:      "us-west-2",
		ManifestDir: "manifests",
		AptCodename: "noble",
	}

	srv := server.New(cfg, store, storage.NewSingle(mock), ":0", nil)
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

func TestAptPackagesMultiLineDescription(t *testing.T) {
	// A Description carrying embedded newlines (as produced by deb822 parsing)
	// must emit with Debian continuation-line formatting.
	store := manifest.NewLocalStore(t.TempDir())
	ctx := context.Background()
	_ = store.AddVersion(ctx, manifest.TypeApt, "bash", manifest.VersionEntry{
		Version:    "5.2.21",
		SourceName: "bash",
		Metadata: map[string]string{
			"Package":      "bash",
			"Architecture": "amd64",
			"Section":      "shells",
			"Priority":     "required",
			"Description":  "GNU Bourne Again SHell\nLong paragraph one.\n\nLong paragraph two.",
		},
	})
	mock := memStore(map[string]string{
		"packages/apt/pool/main/b/bash/bash_5.2.21_amd64.deb": "fake",
	})
	cfg := &config.Config{Bucket: "test", Region: "us-west-2", ManifestDir: "manifests", AptCodename: "noble"}
	srv := server.New(cfg, store, storage.NewSingle(mock), ":0", nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/apt/dists/noble/main/binary-amd64/Packages")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	want := "Description: GNU Bourne Again SHell\n Long paragraph one.\n .\n Long paragraph two.\n"
	if !strings.Contains(s, want) {
		t.Errorf("Packages missing correctly-formatted Description body:\n%s", s)
	}
}

func TestAptPackagesCanonicalFieldExtras(t *testing.T) {
	// Non-canonical fields (e.g., Built-Using) should still be emitted so no
	// upstream metadata silently drops on the floor.
	store := manifest.NewLocalStore(t.TempDir())
	ctx := context.Background()
	_ = store.AddVersion(ctx, manifest.TypeApt, "odd-pkg", manifest.VersionEntry{
		Version:    "1.0",
		SourceName: "odd-pkg",
		Metadata: map[string]string{
			"Architecture":   "amd64",
			"Section":        "misc",
			"Priority":       "optional",
			"Built-Using":    "golang-1.21 (= 1.21.0-1)",
			"Python-Version": ">= 3.10",
		},
	})
	mock := memStore(map[string]string{
		"packages/apt/pool/main/o/odd-pkg/odd-pkg_1.0_amd64.deb": "fake",
	})
	cfg := &config.Config{Bucket: "test", Region: "us-west-2", ManifestDir: "manifests", AptCodename: "noble"}
	srv := server.New(cfg, store, storage.NewSingle(mock), ":0", nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/apt/dists/noble/main/binary-amd64/Packages")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	for _, want := range []string{"Built-Using: golang-1.21", "Python-Version: >= 3.10"} {
		if !strings.Contains(s, want) {
			t.Errorf("Packages missing extra field %q:\n%s", want, s)
		}
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
	mock := memStore(map[string]string{
		"packages/apt/pool/main/e/evil-pkg/evil-pkg_1.0_amd64.deb": "fake",
	})
	cfg := &config.Config{Bucket: "test", Region: "us-west-2", ManifestDir: "manifests", AptCodename: "noble"}
	srv := server.New(cfg, store, storage.NewSingle(mock), ":0", nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/apt/dists/noble/main/binary-amd64/Packages")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	// Injection would produce a line that *begins* with "Evil-Field:". The
	// substring can legitimately appear inside a sanitized Maintainer value.
	if strings.Contains(string(body), "\nEvil-Field:") {
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

// TestAPIPackageVersion exercises the new scoped endpoint. The scoped
// response must be a valid PackageManifest (top-level fields intact, single
// matching version).
func TestAPIPackageVersion(t *testing.T) {
	ts, _ := newTestServer(t)
	tests := []struct {
		name     string
		path     string
		wantCode int
		wantVer  string
	}{
		{"known version by Version field", "/api/v1/packages/apt/amazon-efs-utils/2.4.2", http.StatusOK, "2.4.2"},
		{"known version by Ref field", "/api/v1/packages/git/netbox/v4.5.5", http.StatusOK, ""},
		{"unknown version on real package", "/api/v1/packages/apt/amazon-efs-utils/99.99", http.StatusNotFound, ""},
		{"unknown package", "/api/v1/packages/apt/does-not-exist/1.0.0", http.StatusNotFound, ""},
		{"unknown type", "/api/v1/packages/bogus/foo/1.0.0", http.StatusNotFound, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Get(ts.URL + tc.path)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantCode {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.wantCode)
			}
			if tc.wantCode != http.StatusOK {
				return
			}
			var pm manifest.PackageManifest
			if err := json.NewDecoder(resp.Body).Decode(&pm); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if pm.Name == "" {
				t.Error("scoped response missing top-level name")
			}
			if pm.Type == "" {
				t.Error("scoped response missing top-level type")
			}
			if len(pm.Versions) != 1 {
				t.Fatalf("scoped response has %d versions, want 1", len(pm.Versions))
			}
			if tc.wantVer != "" && pm.Versions[0].Version != tc.wantVer {
				t.Errorf("version = %q, want %q", pm.Versions[0].Version, tc.wantVer)
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

	// The probe must resolve against objects that exist. The mock store holds
	// pool objects and no dists/ tree, which is what a healthy install looks
	// like.
	entries, ok := result["s3_entries"].([]interface{})
	if !ok || len(entries) != 1 {
		t.Fatalf("s3_entries = %v, want one probe row", result["s3_entries"])
	}
	probe, _ := entries[0].(map[string]interface{})
	if got := probe["s3_key"]; got != "packages/apt/pool/" {
		t.Errorf("s3_key = %v, want packages/apt/pool/", got)
	}
	if probe["in_s3"] != true {
		t.Errorf("in_s3 = %v, want true", probe["in_s3"])
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
	mock.Seed("packages/apt/pool/main/t/test-large/test-large_1.0_amd64.deb", large)

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

// ---- Real local backend ----------------------------------------------------

// newLocalBackedServer builds a Server over storage.Local on a temp dir. The
// rest of the suite runs against storage.Memory; this one exercises the backend
// that actually ships as the default, so the filesystem's own semantics
// (prefix listing, streamed reads, missing-key handling) are in the path.
func newLocalBackedServer(t *testing.T) *httptest.Server {
	t.Helper()

	store := manifest.NewLocalStore(t.TempDir())
	ctx := t.Context()
	_ = store.AddVersion(ctx, manifest.TypeApt, "amazon-efs-utils", manifest.VersionEntry{
		Version:      "2.4.2",
		SourceName:   "amazon-efs-utils",
		ArtifactSize: 16,
		Metadata: map[string]string{
			"Architecture": "amd64",
			"Section":      "utils",
			"Priority":     "optional",
		},
		Description: "Amazon EFS mount helper",
	})
	_ = store.AddVersion(ctx, manifest.TypePypi, "boto3", manifest.VersionEntry{})

	objects := storage.NewLocal(t.TempDir())
	seed := map[string]string{
		"packages/apt/pool/main/a/amazon-efs-utils/amazon-efs-utils_2.4.2_amd64.deb": "\x00deb-content-efs",
		"pypi/wheels/boto3-1.35.0-py3-none-any.whl":                                  "fake-wheel-boto3",
	}
	for key, body := range seed {
		if err := objects.Put(ctx, key, []byte(body)); err != nil {
			t.Fatalf("seed %s: %v", key, err)
		}
	}

	cfg := &config.Config{
		StorageBackend: "local",
		ManifestDir:    "manifests",
		AptCodename:    "noble",
	}
	srv := server.New(cfg, store, storage.NewSingle(objects), ":0", nil)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func TestServeOverLocalBackend(t *testing.T) {
	ts := newLocalBackedServer(t)

	get := func(path string) (*http.Response, string) {
		t.Helper()
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp, string(body)
	}

	// Streamed read straight off the filesystem.
	deb := "/apt/pool/main/a/amazon-efs-utils/amazon-efs-utils_2.4.2_amd64.deb"
	resp, body := get(deb)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET %s status = %d, want 200", deb, resp.StatusCode)
	}
	if body != "\x00deb-content-efs" {
		t.Errorf("deb body = %q, want the seeded bytes", body)
	}
	if got, want := resp.Header.Get("Content-Length"), "16"; got != want {
		t.Errorf("Content-Length = %q, want %q", got, want)
	}

	// A missing key is a 404, not a 502 — Local returns (nil, nil).
	if resp, _ := get("/apt/pool/main/a/amazon-efs-utils/nope_9.9.9_amd64.deb"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing deb status = %d, want 404", resp.StatusCode)
	}

	// Index generation walks the pool prefix on disk.
	resp, packages := get("/apt/dists/noble/main/binary-amd64/Packages")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET Packages status = %d, want 200", resp.StatusCode)
	}
	for _, want := range []string{"Package: amazon-efs-utils", "Version: 2.4.2", "Filename: pool/main/a/amazon-efs-utils/amazon-efs-utils_2.4.2_amd64.deb"} {
		if !strings.Contains(packages, want) {
			t.Errorf("Packages missing %q:\n%s", want, packages)
		}
	}

	// PEP 503 index derives package names from a prefix list.
	resp, index := get("/pypi/simple/")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /pypi/simple/ status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(index, ">boto3<") {
		t.Errorf("pypi index missing boto3:\n%s", index)
	}
}

// ---- APT multi-suite -------------------------------------------------------

// newMultiSuiteServer serves noble and jammy from one flat pool. The fixture
// covers the four cases that distinguish a per-suite index from a global one:
// the same package at a different version in each suite, an arch-all package
// in both, an entry naming no suites at all, and an architecture present in
// noble only.
func newMultiSuiteServer(t *testing.T) *httptest.Server {
	t.Helper()

	store := manifest.NewLocalStore(t.TempDir())
	ctx := t.Context()
	add := func(name string, ve manifest.VersionEntry) {
		t.Helper()
		if err := store.AddVersion(ctx, manifest.TypeApt, name, ve); err != nil {
			t.Fatalf("AddVersion %s@%s: %v", name, ve.Version, err)
		}
	}
	add("hello", manifest.VersionEntry{
		Version:  "2.10-noble1",
		Suites:   []string{"noble"},
		Metadata: map[string]string{"Architecture": "amd64"},
	})
	add("hello", manifest.VersionEntry{
		Version:  "2.10-jammy1",
		Suites:   []string{"jammy"},
		Metadata: map[string]string{"Architecture": "amd64"},
	})
	add("bodega-config", manifest.VersionEntry{
		Version:  "1.0.0",
		Suites:   []string{"noble", "jammy"},
		Metadata: map[string]string{"Architecture": "all"},
	})
	add("legacy-tool", manifest.VersionEntry{
		Version:  "0.9.0",
		Metadata: map[string]string{"Architecture": "amd64"},
	})
	add("noble-only-kmod", manifest.VersionEntry{
		Version:  "1.2.3",
		Suites:   []string{"noble"},
		Metadata: map[string]string{"Architecture": "riscv64"},
	})

	mock := memStore(map[string]string{
		"packages/apt/pool/main/h/hello/hello_2.10-noble1_amd64.deb":                 "\x00deb",
		"packages/apt/pool/main/h/hello/hello_2.10-jammy1_amd64.deb":                 "\x00deb",
		"packages/apt/pool/main/b/bodega-config/bodega-config_1.0.0_all.deb":         "\x00deb",
		"packages/apt/pool/main/l/legacy-tool/legacy-tool_0.9.0_amd64.deb":           "\x00deb",
		"packages/apt/pool/main/n/noble-only-kmod/noble-only-kmod_1.2.3_riscv64.deb": "\x00deb",
	})

	cfg := &config.Config{
		Bucket:      "test-bucket",
		Region:      "us-west-2",
		ManifestDir: "manifests",
		AptCodename: "noble",
		AptSuites:   []string{"noble", "jammy"},
	}
	ts := httptest.NewServer(server.New(cfg, store, storage.NewSingle(mock), ":0", nil).Handler())
	t.Cleanup(ts.Close)
	return ts
}

// aptGet fetches path and returns the status code and body.
func aptGet(t *testing.T, ts *httptest.Server, path string) (int, string) {
	t.Helper()
	resp, err := http.Get(ts.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// debField returns the value of field in the Packages stanza for pkg.
func debField(packages, pkg, field string) string {
	for _, stanza := range strings.Split(packages, "\n\n") {
		if !strings.Contains(stanza, "Package: "+pkg+"\n") {
			continue
		}
		for _, line := range strings.Split(stanza, "\n") {
			if v, ok := strings.CutPrefix(line, field+": "); ok {
				return v
			}
		}
	}
	return ""
}

func TestAptSuitesPartitionPackages(t *testing.T) {
	ts := newMultiSuiteServer(t)

	status, noble := aptGet(t, ts, "/apt/dists/noble/main/binary-amd64/Packages")
	if status != http.StatusOK {
		t.Fatalf("noble Packages status = %d, want 200", status)
	}
	status, jammy := aptGet(t, ts, "/apt/dists/jammy/main/binary-amd64/Packages")
	if status != http.StatusOK {
		t.Fatalf("jammy Packages status = %d, want 200", status)
	}

	if v := debField(noble, "hello", "Version"); v != "2.10-noble1" {
		t.Errorf("noble hello Version = %q, want 2.10-noble1", v)
	}
	if v := debField(jammy, "hello", "Version"); v != "2.10-jammy1" {
		t.Errorf("jammy hello Version = %q, want 2.10-jammy1", v)
	}
	if strings.Contains(noble, "2.10-jammy1") {
		t.Errorf("noble Packages leaked the jammy version:\n%s", noble)
	}
	if strings.Contains(jammy, "2.10-noble1") {
		t.Errorf("jammy Packages leaked the noble version:\n%s", jammy)
	}

	// An entry naming no suites belongs to the default suite and nowhere else.
	if debField(noble, "legacy-tool", "Version") != "0.9.0" {
		t.Errorf("legacy-tool missing from the default suite:\n%s", noble)
	}
	if strings.Contains(jammy, "legacy-tool") {
		t.Errorf("legacy-tool with no suites must not appear in jammy:\n%s", jammy)
	}

	// One pool object, two suites: the Filename must be identical.
	nf := debField(noble, "bodega-config", "Filename")
	jf := debField(jammy, "bodega-config", "Filename")
	if nf == "" || jf == "" {
		t.Fatalf("bodega-config missing from a suite: noble=%q jammy=%q", nf, jf)
	}
	if nf != jf {
		t.Errorf("shared package Filename differs: noble=%q jammy=%q", nf, jf)
	}
	if want := "pool/main/b/bodega-config/bodega-config_1.0.0_all.deb"; nf != want {
		t.Errorf("bodega-config Filename = %q, want %q", nf, want)
	}
}

func TestAptSuiteArchitectures(t *testing.T) {
	ts := newMultiSuiteServer(t)

	for _, tc := range []struct{ suite, want string }{
		{"noble", "Architectures: amd64 riscv64"},
		{"jammy", "Architectures: amd64"},
	} {
		status, body := aptGet(t, ts, "/apt/dists/"+tc.suite+"/Release")
		if status != http.StatusOK {
			t.Fatalf("%s Release status = %d, want 200", tc.suite, status)
		}
		if !strings.Contains(body, tc.want+"\n") {
			t.Errorf("%s Release missing %q:\n%s", tc.suite, tc.want, body)
		}
		for _, want := range []string{"Suite: " + tc.suite, "Codename: " + tc.suite} {
			if !strings.Contains(body, want+"\n") {
				t.Errorf("%s Release missing %q:\n%s", tc.suite, want, body)
			}
		}
	}
}

func TestAptUnservedSuite404s(t *testing.T) {
	ts := newMultiSuiteServer(t)
	for _, path := range []string{
		"/apt/dists/bookworm/Release",
		"/apt/dists/bookworm/InRelease",
		"/apt/dists/bookworm/main/binary-amd64/Packages",
		"/apt/dists/bookworm/main/binary-amd64/Packages.gz",
	} {
		if status, _ := aptGet(t, ts, path); status != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want 404 for an unserved suite", path, status)
		}
	}
}

// ---- APT index snapshot ----------------------------------------------------

// newSnapshotServer serves one suite and permits mutations from localhost, so
// a test can drive both the direct-store write (a hand-edited manifest) and
// the mutation-API write (which rebuilds).
func newSnapshotServer(t *testing.T) (*httptest.Server, *manifest.Store) {
	t.Helper()

	store := manifest.NewLocalStore(t.TempDir())
	if err := store.AddVersion(t.Context(), manifest.TypeApt, "hello", manifest.VersionEntry{
		Version: "2.10-3build1",
		Metadata: map[string]string{
			"Architecture": "amd64",
			"_pool_path":   "pool/main/h/hello/hello_2.10-3build1_amd64.deb",
		},
	}); err != nil {
		t.Fatalf("AddVersion hello: %v", err)
	}

	mock := memStore(map[string]string{
		"packages/apt/pool/main/h/hello/hello_2.10-3build1_amd64.deb": "\x00deb",
	})
	cfg := &config.Config{
		Bucket:          "test-bucket",
		Region:          "us-west-2",
		ManifestDir:     "manifests",
		AptCodename:     "noble",
		AdminPermitCIDR: []string{"127.0.0.0/8", "::1/128"},
	}
	ts := httptest.NewServer(server.New(cfg, store, storage.NewSingle(mock), ":0", nil).Handler())
	t.Cleanup(ts.Close)
	return ts, store
}

// releaseDigest returns the SHA256 and size Release records for an index path.
func releaseDigest(t *testing.T, release, indexPath string) (string, int) {
	t.Helper()
	for _, line := range strings.Split(release, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[2] != indexPath {
			continue
		}
		size, err := strconv.Atoi(fields[1])
		if err != nil {
			t.Fatalf("Release size for %s is not a number: %q", indexPath, fields[1])
		}
		return fields[0], size
	}
	t.Fatalf("Release records no SHA256 for %s:\n%s", indexPath, release)
	return "", 0
}

// TestAptReleaseDigestsSurviveAMutation is the regression test for the Hash
// Sum mismatch race. apt fetches Release and Packages in two requests and
// checks the second against the digest in the first, so a write landing
// between them used to hand the client bytes Release never vouched for.
func TestAptReleaseDigestsSurviveAMutation(t *testing.T) {
	ts, store := newSnapshotServer(t)

	status, release := aptGet(t, ts, "/apt/dists/noble/Release")
	if status != http.StatusOK {
		t.Fatalf("Release status = %d, want 200", status)
	}
	wantHash, wantSize := releaseDigest(t, release, "main/binary-amd64/Packages")

	// The write apt cannot see coming: a manifest edit with no SIGHUP, which
	// is what a mutation landing between the two fetches looks like.
	if err := store.AddVersion(t.Context(), manifest.TypeApt, "latecomer", manifest.VersionEntry{
		Version: "1.0.0",
		Metadata: map[string]string{
			"Architecture": "amd64",
			"_pool_path":   "pool/main/l/latecomer/latecomer_1.0.0_amd64.deb",
		},
	}); err != nil {
		t.Fatalf("AddVersion latecomer: %v", err)
	}

	status, packages := aptGet(t, ts, "/apt/dists/noble/main/binary-amd64/Packages")
	if status != http.StatusOK {
		t.Fatalf("Packages status = %d, want 200", status)
	}
	sum := sha256.Sum256([]byte(packages))
	if got := hex.EncodeToString(sum[:]); got != wantHash {
		t.Errorf("Packages SHA256 = %s, Release recorded %s; a client reports this as Hash Sum mismatch", got, wantHash)
	}
	if len(packages) != wantSize {
		t.Errorf("Packages size = %d, Release recorded %d", len(packages), wantSize)
	}
	if strings.Contains(packages, "latecomer") {
		t.Error("Packages served a generation newer than the Release that digests it")
	}

	// Same contract for the gzip variant, which Release digests separately.
	wantGzHash, wantGzSize := releaseDigest(t, release, "main/binary-amd64/Packages.gz")
	status, gzBody := aptGet(t, ts, "/apt/dists/noble/main/binary-amd64/Packages.gz")
	if status != http.StatusOK {
		t.Fatalf("Packages.gz status = %d, want 200", status)
	}
	gzSum := sha256.Sum256([]byte(gzBody))
	if got := hex.EncodeToString(gzSum[:]); got != wantGzHash {
		t.Errorf("Packages.gz SHA256 = %s, Release recorded %s", got, wantGzHash)
	}
	if len(gzBody) != wantGzSize {
		t.Errorf("Packages.gz size = %d, Release recorded %d", len(gzBody), wantGzSize)
	}
}

// TestAptMutationAPIRebuildsIndex covers the other half: a snapshot that never
// refreshes is the same stale-index defect, only slower.
func TestAptMutationAPIRebuildsIndex(t *testing.T) {
	ts, _ := newSnapshotServer(t)

	body := `{"name":"newcomer","type":"apt","versions":[{"version":"3.0.0","metadata":{"Architecture":"amd64","_pool_path":"pool/main/n/newcomer/newcomer_3.0.0_amd64.deb"}}]}`
	resp, err := http.Post(ts.URL+"/api/v1/packages/apt", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/v1/packages/apt: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		got, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST status = %d, want 201: %s", resp.StatusCode, got)
	}

	status, packages := aptGet(t, ts, "/apt/dists/noble/main/binary-amd64/Packages")
	if status != http.StatusOK {
		t.Fatalf("Packages status = %d, want 200", status)
	}
	if !strings.Contains(packages, "Package: newcomer\n") {
		t.Errorf("Packages does not carry the entry the mutation API just created:\n%s", packages)
	}

	// And Release still vouches for exactly those bytes.
	_, release := aptGet(t, ts, "/apt/dists/noble/Release")
	wantHash, _ := releaseDigest(t, release, "main/binary-amd64/Packages")
	sum := sha256.Sum256([]byte(packages))
	if got := hex.EncodeToString(sum[:]); got != wantHash {
		t.Errorf("after rebuild, Packages SHA256 = %s, Release recorded %s", got, wantHash)
	}
}

// TestAptReleaseValidUntil pins the widened window. A cached Release expires
// in place, and past Valid-Until every client fails apt update at once,
// including with [trusted=yes], since Acquire::Check-Valid-Until is
// independent of trust.
func TestAptReleaseValidUntil(t *testing.T) {
	ts, _ := newSnapshotServer(t)
	_, release := aptGet(t, ts, "/apt/dists/noble/Release")

	field := func(name string) time.Time {
		t.Helper()
		for _, line := range strings.Split(release, "\n") {
			v, ok := strings.CutPrefix(line, name+": ")
			if !ok {
				continue
			}
			parsed, err := time.Parse(time.RFC1123Z, v)
			if err != nil {
				t.Fatalf("%s is not RFC1123Z: %q", name, v)
			}
			return parsed
		}
		t.Fatalf("Release has no %s:\n%s", name, release)
		return time.Time{}
	}

	if window := field("Valid-Until").Sub(field("Date")); window != 14*24*time.Hour {
		t.Errorf("Valid-Until - Date = %v, want 336h0m0s", window)
	}
	if remaining := time.Until(field("Valid-Until")); remaining < 12*24*time.Hour {
		t.Errorf("Release is valid for only %v from now", remaining)
	}
}

// TestAptVersionlessEntryNotPublished pins caveat #44's server half: an entry
// with no version reaches no index, because no CLI verb can address it to
// hide, freeze or remove it afterwards.
func TestAptVersionlessEntryNotPublished(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	ctx := t.Context()
	for _, ve := range []manifest.VersionEntry{
		{SourceName: "hello", Metadata: map[string]string{
			"Architecture": "amd64", "Package": "hello", "Version": "2.10-3build1",
			"_pool_path": "pool/main/h/hello/hello_2.10-3build1_amd64.deb",
		}},
		{Version: "2.10-3build1", SourceName: "hello", Metadata: map[string]string{
			"Architecture": "amd64", "_pool_path": "pool/main/h/hello/hello_2.10-3build1_amd64.deb",
		}},
	} {
		if err := store.AddVersion(ctx, manifest.TypeApt, "hello", ve); err != nil {
			t.Fatalf("AddVersion: %v", err)
		}
	}

	cfg := &config.Config{Bucket: "b", Region: "r", ManifestDir: "manifests", AptCodename: "noble"}
	mock := memStore(map[string]string{})
	ts := httptest.NewServer(server.New(cfg, store, storage.NewSingle(mock), ":0", nil).Handler())
	t.Cleanup(ts.Close)

	_, packages := aptGet(t, ts, "/apt/dists/noble/main/binary-amd64/Packages")
	if got := strings.Count(packages, "Package: hello\n"); got != 1 {
		t.Errorf("hello appears in %d stanzas, want 1:\n%s", got, packages)
	}
}

// TestAptStanzaFieldsAreNotDuplicated pins caveat #43. deb822 does not define
// a repeated field, so a metadata copy scraped from upstream landing beside
// bodega's own value leaves which one wins to a parser's choice, and in
// direct-url and source-build modes the two disagree.
func TestAptStanzaFieldsAreNotDuplicated(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	if err := store.AddVersion(t.Context(), manifest.TypeApt, "hello", manifest.VersionEntry{
		Version:      "2.10-3build1",
		ArtifactSize: 26006,
		Metadata: map[string]string{
			"Architecture": "amd64",
			"_pool_path":   "pool/main/h/hello/hello_2.10-3build1_amd64.deb",
			"_md5":         "aaaa",
			"_sha1":        "bbbb",
			"_sha256":      "cccc",
			// The upstream scrape, naming upstream's pool path and digests.
			"Filename": "pool/main/h/hello/upstream_2.10-3build1_amd64.deb",
			"Size":     "999",
			"MD5sum":   "dddd",
			"SHA1":     "eeee",
			"SHA256":   "ffff",
			"Origin":   "Ubuntu",
		},
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	cfg := &config.Config{Bucket: "b", Region: "r", ManifestDir: "manifests", AptCodename: "noble"}
	ts := httptest.NewServer(server.New(cfg, store, storage.NewSingle(memStore(map[string]string{})), ":0", nil).Handler())
	t.Cleanup(ts.Close)

	_, packages := aptGet(t, ts, "/apt/dists/noble/main/binary-amd64/Packages")
	for _, field := range []string{"Filename", "Size", "MD5sum", "SHA1", "SHA256"} {
		if got := strings.Count(packages, "\n"+field+": "); got != 1 {
			t.Errorf("%s appears %d times in the stanza, want 1:\n%s", field, got, packages)
		}
	}
	if strings.Contains(packages, "Origin: ") {
		t.Errorf("Origin belongs to Release and names the wrong repository in a stanza:\n%s", packages)
	}
	// bodega's own values are the ones that survive.
	if !strings.Contains(packages, "Filename: pool/main/h/hello/hello_2.10-3build1_amd64.deb\n") {
		t.Errorf("Filename is not bodega's pool path:\n%s", packages)
	}
	if !strings.Contains(packages, "SHA256: cccc\n") {
		t.Errorf("SHA256 is not bodega's recorded digest:\n%s", packages)
	}
}
