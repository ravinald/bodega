package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/dirhash"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// prefetchFixture is an install whose upstreams are one loopback stub serving
// lodash 4.17.21 for npm and example.com/mod v1.0.0 for gomod, and whose OSV
// database names minimist 1.2.0 for npm.
type prefetchFixture struct {
	dir, adbPath, manifests string
	tarball, modZip         []byte
	h1                      string
}

func newPrefetchFixture(t *testing.T, osvAction string) *prefetchFixture {
	t.Helper()
	f := &prefetchFixture{dir: t.TempDir()}
	f.tarball = npmTarball(t, `{"name":"lodash","version":"4.17.21"}`)
	f.modZip, f.h1 = moduleZip(t, "example.com/mod", "v1.0.0")

	mux := http.NewServeMux()
	mux.HandleFunc("/lodash/-/lodash-4.17.21.tgz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(f.tarball) })
	mux.HandleFunc("/example.com/mod/@v/v1.0.0.info", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Version":"v1.0.0","Time":"2020-01-01T00:00:00Z"}`))
	})
	mux.HandleFunc("/example.com/mod/@v/v1.0.0.mod", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("module example.com/mod\n"))
	})
	mux.HandleFunc("/example.com/mod/@v/v1.0.0.zip", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(f.modZip) })
	stub := httptest.NewServer(mux)
	t.Cleanup(stub.Close)

	export := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		zf, _ := zw.Create("GHSA-test-0001.json")
		_ = json.NewEncoder(zf).Encode(map[string]any{
			"id": "GHSA-test-0001",
			"affected": []map[string]any{{
				"package":  map[string]string{"name": "minimist", "ecosystem": "npm"},
				"versions": []string{"1.2.0"},
			}},
		})
		_ = zw.Close()
		_, _ = w.Write(buf.Bytes())
	}))
	t.Cleanup(export.Close)
	osvDir := filepath.Join(f.dir, "osv")
	db := policy.NewOSVDatabase(osvDir)
	db.ExportBase = export.URL
	if _, err := db.Sync(t.Context(), "npm"); err != nil {
		t.Fatalf("sync: %v", err)
	}

	f.adbPath = filepath.Join(f.dir, "audit.db")
	f.manifests = filepath.Join(f.dir, "manifests")
	body := fmt.Sprintf(`{
  "storage_backend": "local",
  "storage_path": %q,
  "manifest_dir": %q,
  "build_root": %q,
  "audit_db": %q,
  "log_dir": %q,
  "osv_db_dir": %q,
  "npm_upstream": %q,
  "gomod_upstream": %q,
  "allow_plaintext": true
}`, filepath.Join(f.dir, "storage"), f.manifests, filepath.Join(f.dir, "build"), f.adbPath, f.dir, osvDir, stub.URL, stub.URL)
	path := filepath.Join(f.dir, "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(config.EnvConfigFile, path)

	adb := f.open(t)
	defer adb.Close()
	// The seeded age gates date versions against the public registries.
	for _, eco := range audit.DefaultAgeEcosystems() {
		if _, err := adb.DeleteAgePolicy(t.Context(), eco); err != nil {
			t.Fatalf("delete seeded age policy: %v", err)
		}
	}
	if err := adb.SetOSVPolicy(t.Context(), audit.OSVPolicy{Ecosystem: manifest.TypeNpm, Action: osvAction}); err != nil {
		t.Fatalf("set osv policy: %v", err)
	}
	return f
}

func (f *prefetchFixture) open(t *testing.T) *audit.DB {
	t.Helper()
	adb, err := audit.Open(f.adbPath)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	return adb
}

func (f *prefetchFixture) write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(f.dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// prefetch runs the command's body and returns its exit status and results.
func (f *prefetchFixture) prefetch(t *testing.T, dryRun bool, paths ...string) (int, []prefetchResult, error) {
	t.Helper()
	var out bytes.Buffer
	code, err := runPrefetch(t.Context(), &globalFlags{}, paths, "", dryRun, true, &out)
	var rows []prefetchResult
	if out.Len() > 0 {
		if jerr := json.Unmarshal(out.Bytes(), &rows); jerr != nil {
			t.Fatalf("parse --json output %q: %v", out.String(), jerr)
		}
	}
	return code, rows, err
}

func npmTarball(t *testing.T, packageJSON string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "package/package.json", Mode: 0o644, Size: int64(len(packageJSON))}); err != nil {
		t.Fatal(err)
	}
	_, _ = tw.Write([]byte(packageJSON))
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func moduleZip(t *testing.T, mod, version string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string]string{"go.mod": "module " + mod + "\n", "a.go": "package mod\n"} {
		w, _ := zw.Create(mod + "@" + version + "/" + name)
		_, _ = w.Write([]byte(body))
	}
	_ = zw.Close()
	p := filepath.Join(t.TempDir(), "mod.zip")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	h1, err := dirhash.HashZip(p, dirhash.Hash1)
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), h1
}

func sri512(b []byte) string {
	sum := sha512.Sum512(b)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

func packageLock(integrity string) string {
	return fmt.Sprintf(`{"lockfileVersion": 3, "packages": {
  "": {"name": "app"},
  "node_modules/lodash": {"version": "4.17.21", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", "integrity": %q}
}}`, integrity)
}

func TestPrefetchNpmAdmitsFetchesAndPins(t *testing.T) {
	f := newPrefetchFixture(t, policy.ActionBlock)
	lock := f.write(t, "package-lock.json", packageLock(sri512(f.tarball)))

	code, rows, err := f.prefetch(t, false, lock)
	if err != nil || code != 0 {
		t.Fatalf("prefetch = %d, %v; want 0, nil (rows %+v)", code, err, rows)
	}
	if len(rows) != 1 || rows[0].Decision != audit.AdmissionAdmitted || rows[0].Fetch != "fetched" ||
		rows[0].Digest == nil || rows[0].Digest.Status != digestMatch {
		t.Fatalf("rows = %+v; want lodash admitted, fetched and its sha512 matched", rows)
	}

	store := manifest.NewLocalStore(f.manifests)
	pm, err := store.GetPackage(t.Context(), manifest.TypeNpm, "lodash")
	if err != nil || pm == nil || len(pm.Versions) != 1 || pm.Versions[0].Version != "4.17.21" {
		t.Fatalf("stored manifest = %+v, %v; want lodash 4.17.21", pm, err)
	}
	adb := f.open(t)
	defer adb.Close()
	pin, err := adb.GetChecksum(t.Context(), manifest.NpmTarballKey("lodash", "4.17.21"))
	sum := sha256.Sum256(f.tarball)
	if err != nil || pin == nil || pin.Value != hex.EncodeToString(sum[:]) {
		t.Fatalf("pin = %+v, %v; want the tarball's sha256", pin, err)
	}
	if adm, _ := adb.Admissions(t.Context(), audit.AdmissionFilter{PkgType: manifest.TypeNpm, PkgName: "lodash"}); len(adm) == 0 {
		t.Error("no admission row was written")
	}

	// A second run admits again and fetches nothing new: the version is held.
	if code, _, err := f.prefetch(t, false, lock); err != nil || code != 0 {
		t.Errorf("second prefetch = %d, %v; want 0, nil", code, err)
	}
}

func TestPrefetchNpmDigestMismatch(t *testing.T) {
	f := newPrefetchFixture(t, policy.ActionBlock)
	lock := f.write(t, "package-lock.json", packageLock(sri512([]byte("other bytes"))))

	code, rows, err := f.prefetch(t, false, lock)
	if err != nil || code != exitBlocked {
		t.Fatalf("prefetch = %d, %v; want %d", code, err, exitBlocked)
	}
	r := rows[0]
	if r.Decision != prefetchMismatch || r.Digest == nil || r.Digest.Status != digestMismatch {
		t.Fatalf("row = %+v; want a mismatch", r)
	}
	want512 := sha512.Sum512(f.tarball)
	for _, s := range []string{"lodash@4.17.21", "sha512:" + hex.EncodeToString(want512[:]), lock, manifest.NpmTarballKey("lodash", "4.17.21")} {
		if !strings.Contains(r.Reason, s) {
			t.Errorf("reason %q does not name %q", r.Reason, s)
		}
	}
}

func TestPrefetchCargoDigestMismatchAgainstPin(t *testing.T) {
	f := newPrefetchFixture(t, policy.ActionBlock)
	adb := f.open(t)
	key := manifest.CargoCrateKey("serde", "1.0.190")
	if err := adb.StoreChecksum(t.Context(), key, manifest.TypeCargo, "serde", "1.0.190", "sha256", strings.Repeat("a", 64), "build"); err != nil {
		t.Fatal(err)
	}
	adb.Close()
	lock := f.write(t, "Cargo.lock", `[[package]]
name = "serde"
version = "1.0.190"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "`+strings.Repeat("b", 64)+`"
`)
	code, rows, err := f.prefetch(t, true, lock)
	if err != nil || code != exitBlocked {
		t.Fatalf("prefetch = %d, %v; want %d", code, err, exitBlocked)
	}
	d := rows[0].Digest
	if rows[0].Decision != prefetchMismatch || d.Lockfile != "sha256:"+strings.Repeat("b", 64) ||
		d.Bodega != "sha256:"+strings.Repeat("a", 64) || !strings.Contains(d.BodegaSource, key) || !strings.Contains(d.LockfileSource, "line 1") {
		t.Fatalf("row = %+v digest %+v; want both digests and both sources", rows[0], d)
	}
}

func TestPrefetchGoSumComparesH1(t *testing.T) {
	f := newPrefetchFixture(t, policy.ActionBlock)
	sum := f.write(t, "go.sum", "example.com/mod v1.0.0 "+f.h1+"\nexample.com/mod v1.0.0/go.mod h1:unused=\n")

	code, rows, err := f.prefetch(t, false, sum)
	if err != nil || code != 0 {
		t.Fatalf("prefetch = %d, %v; want 0 (rows %+v)", code, err, rows)
	}
	if len(rows) != 1 || rows[0].Digest == nil || rows[0].Digest.Status != digestMatch || rows[0].Digest.Bodega != f.h1 {
		t.Fatalf("rows = %+v; want the module's h1 computed over the fetched zip and matched", rows)
	}
}

func TestPrefetchRequirementsComparesEveryPinnedFile(t *testing.T) {
	f := newPrefetchFixture(t, policy.ActionBlock)
	adb := f.open(t)
	good, bad := strings.Repeat("1", 64), strings.Repeat("2", 64)
	if err := adb.StoreChecksum(t.Context(), manifest.PypiWheelKey("six-1.16.0-py2.py3-none-any.whl"), manifest.TypePypi, "six", "1.16.0", "sha256", good, "build"); err != nil {
		t.Fatal(err)
	}
	adb.Close()

	match := f.write(t, "requirements.txt", "six==1.16.0 --hash=sha256:"+good+"\n")
	if code, rows, err := f.prefetch(t, true, match); err != nil || code != 0 || rows[0].Digest.Status != digestMatch {
		t.Fatalf("prefetch = %d, %v, %+v; want a match", code, err, rows)
	}
	other := f.write(t, "requirements-other.txt", "six==1.16.0 --hash=sha256:"+bad+"\n")
	code, rows, err := f.prefetch(t, true, other)
	if err != nil || code != exitBlocked || rows[0].Decision != prefetchMismatch {
		t.Fatalf("prefetch = %d, %v, %+v; want a mismatch: the pinned wheel is not among the listed hashes", code, err, rows)
	}
}

func TestPrefetchBlockedExitsTwo(t *testing.T) {
	f := newPrefetchFixture(t, policy.ActionBlock)
	lock := f.write(t, "package-lock.json", `{"lockfileVersion": 2, "packages": {
  "node_modules/minimist": {"version": "1.2.0", "resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.0.tgz"}
}}`)
	code, rows, err := f.prefetch(t, false, lock)
	if err != nil || code != exitBlocked {
		t.Fatalf("prefetch = %d, %v; want %d", code, err, exitBlocked)
	}
	if rows[0].Decision != audit.AdmissionPolicyBlocked || len(rows[0].Failing) == 0 || rows[0].Failing[0].Check != audit.CheckOSV {
		t.Fatalf("row = %+v; want policy_blocked naming the osv check", rows[0])
	}
	if pm, _ := manifest.NewLocalStore(f.manifests).GetPackage(t.Context(), manifest.TypeNpm, "minimist"); pm != nil {
		t.Error("a blocked version was written to the manifest store")
	}
}

func TestPrefetchUnsupportedExitsOne(t *testing.T) {
	f := newPrefetchFixture(t, policy.ActionBlock)
	lock := f.write(t, "package-lock.json", `{"lockfileVersion": 3, "packages": {
  "node_modules/x": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/x/x.git#abc"}
}}`)
	code, rows, err := f.prefetch(t, true, lock)
	if err == nil || code != 0 || rows[0].Decision != prefetchUnsupported {
		t.Fatalf("prefetch = %d, %v, %+v; want an error (exit 1) and the entry unsupported", code, err, rows)
	}
}

func TestPrefetchDryRunWritesNothing(t *testing.T) {
	f := newPrefetchFixture(t, policy.ActionBlock)
	lock := f.write(t, "package-lock.json", packageLock(sri512(f.tarball)))
	before := installState(t, f)

	code, rows, err := f.prefetch(t, true, lock)
	if err != nil || code != 0 {
		t.Fatalf("prefetch --dry-run = %d, %v; want 0", code, err)
	}
	if rows[0].Decision != audit.AdmissionAdmitted || rows[0].Fetch != "" || rows[0].Digest.Status != digestNotCompared {
		t.Fatalf("row = %+v; want admitted, nothing fetched, and the digest not compared since nothing is held", rows[0])
	}
	if after := installState(t, f); after != before {
		t.Fatalf("dry run changed the install:\nbefore %s\nafter  %s", before, after)
	}
}

// installState summarizes everything a prefetch writes: manifests, build
// root, admission rows, pins and audit events.
func installState(t *testing.T, f *prefetchFixture) string {
	t.Helper()
	var files []string
	for _, root := range []string{f.manifests, filepath.Join(f.dir, "build")} {
		_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				files = append(files, p)
			}
			return nil
		})
	}
	adb := f.open(t)
	defer adb.Close()
	ctx := context.Background()
	adm, err := adb.Admissions(ctx, audit.AdmissionFilter{})
	if err != nil {
		t.Fatal(err)
	}
	pins, err := adb.ListChecksums(ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}
	events, err := adb.Query(ctx, audit.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("files=%v admissions=%d pins=%d events=%d", files, len(adm), len(pins), len(events))
}
