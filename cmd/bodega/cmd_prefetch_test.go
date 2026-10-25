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
	"io"
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
// lodash 4.17.21 and minimist 1.2.0 for npm and example.com/mod v1.0.0 for
// gomod, and whose OSV database names minimist 1.2.0 in an advisory and
// evil-pkg 1.0.0 in an advisory and a malware record.
type prefetchFixture struct {
	dir, adbPath, manifests string
	upstream                string
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
	minimist := npmTarball(t, `{"name":"minimist","version":"1.2.0"}`)
	mux.HandleFunc("/minimist/-/minimist-1.2.0.tgz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(minimist) })
	mux.HandleFunc("/example.com/mod/@v/v1.0.0.info", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Version":"v1.0.0","Time":"2020-01-01T00:00:00Z"}`))
	})
	mux.HandleFunc("/example.com/mod/@v/v1.0.0.mod", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("module example.com/mod\n"))
	})
	mux.HandleFunc("/example.com/mod/@v/v1.0.0.zip", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(f.modZip) })
	// Load holds npm_upstream and gomod_upstream to https, so the stub is a
	// TLS server and the default transport trusts it for the test.
	stub := httptest.NewTLSServer(mux)
	t.Cleanup(stub.Close)
	f.upstream = stub.URL
	orig := http.DefaultTransport
	http.DefaultTransport = stub.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = orig })

	export := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for id, pkg := range map[string][2]string{
			"GHSA-test-0001": {"minimist", "1.2.0"},
			"GHSA-test-0002": {"evil-pkg", "1.0.0"},
			"MAL-test-0001":  {"evil-pkg", "1.0.0"},
		} {
			zf, _ := zw.Create(id + ".json")
			_ = json.NewEncoder(zf).Encode(map[string]any{
				"id": id,
				"affected": []map[string]any{{
					"package":  map[string]string{"name": pkg[0], "ecosystem": "npm"},
					"versions": []string{pkg[1]},
				}},
			})
		}
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

// minimistLock is a v3 lockfile naming minimist 1.2.0, the version the OSV
// database flags, with no integrity to compare.
const minimistLock = `{"lockfileVersion": 3, "packages": {
  "": {"name": "app"},
  "node_modules/minimist": {"version": "1.2.0", "resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.0.tgz"}
}}`

// storeBaseline stores npm name@version marked baseline, as `bodega pkg
// import --baseline` leaves it.
func storeBaseline(t *testing.T, f *prefetchFixture, name, version string) {
	t.Helper()
	store := manifest.NewLocalStore(f.manifests)
	pm := &manifest.PackageManifest{ConfigVersion: manifest.CurrentConfigVersion, Type: manifest.TypeNpm, Name: name,
		Versions: []manifest.VersionEntry{{Version: version, URL: f.upstream, Mode: manifest.ModeProxy, Baseline: true, BaselineAt: "2026-10-01T00:00:00Z"}}}
	if err := store.SavePackage(t.Context(), pm); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveIndex(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestPrefetchHonorsStoredBaseline(t *testing.T) {
	f := newPrefetchFixture(t, policy.ActionBlock)
	storeBaseline(t, f, "minimist", "1.2.0")
	lock := f.write(t, "package-lock.json", minimistLock)

	before := installState(t, f)
	code, rows, err := f.prefetch(t, true, lock)
	if err != nil || code != 0 || rows[0].Decision != audit.AdmissionAdmitted {
		t.Fatalf("prefetch --dry-run = %d, %v, %+v; want minimist admitted as baseline", code, err, rows)
	}
	if c := failingCheck(rows[0], audit.CheckOSV); c.Status != audit.CheckBaseline {
		t.Errorf("dry-run failing = %+v; want the osv check shown as admitted past by the baseline mark", rows[0].Failing)
	}
	if after := installState(t, f); after != before {
		t.Fatalf("dry run changed the install:\nbefore %s\nafter  %s", before, after)
	}

	code, rows, err = f.prefetch(t, false, lock)
	if err != nil || code != 0 || rows[0].Decision != audit.AdmissionAdmitted {
		t.Fatalf("prefetch = %d, %v, %+v; want minimist admitted as baseline, as pkg import --merge admits it", code, err, rows)
	}
	if c := failingCheck(rows[0], audit.CheckOSV); c.Status != audit.CheckBaseline {
		t.Errorf("failing = %+v; want the osv check shown as admitted past by the baseline mark", rows[0].Failing)
	}
	adb := f.open(t)
	defer adb.Close()
	adm, err := adb.Admissions(t.Context(), audit.AdmissionFilter{PkgType: manifest.TypeNpm, PkgName: "minimist"})
	if err != nil || len(adm) == 0 {
		t.Fatalf("admissions = %+v, %v; want the prefetch's row", adm, err)
	}
	var osv string
	for _, c := range adm[0].Checks {
		if c.Check == audit.CheckOSV {
			osv = c.Status
		}
	}
	if adm[0].Decision != audit.AdmissionAdmitted || osv != audit.CheckBaseline {
		t.Errorf("admission = %s with osv %q; want admitted with osv baseline", adm[0].Decision, osv)
	}
	pm, _ := manifest.NewLocalStore(f.manifests).GetPackage(t.Context(), manifest.TypeNpm, "minimist")
	if pm == nil || len(pm.Versions) != 1 || !pm.Versions[0].Baseline {
		t.Errorf("stored minimist = %+v; want the one version, still marked baseline", pm)
	}
}

func failingCheck(r prefetchResult, check string) audit.AdmissionCheck {
	for _, c := range r.Failing {
		if c.Check == check {
			return c
		}
	}
	return audit.AdmissionCheck{}
}

// gemPrefetchFixture is newPrefetchFixture with rubygems_upstream pointed at
// a stub serving gem files under /gems/. rubygems_upstream must be https, so
// the stub is a TLS server and the default transport, which the builder's
// download goes through, trusts it for the length of the test.
func gemPrefetchFixture(t *testing.T, gems map[string][]byte) *prefetchFixture {
	t.Helper()
	f := newPrefetchFixture(t, policy.ActionBlock)
	stub := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := gems[strings.TrimPrefix(r.URL.Path, "/gems/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(stub.Close)
	orig := http.DefaultTransport
	http.DefaultTransport = stub.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = orig })

	path := os.Getenv(config.EnvConfigFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["rubygems_upstream"] = stub.URL
	raw, _ = json.Marshal(cfg)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func gemfileLock(checksums string) string {
	return `GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.16.7-x86_64-linux)
      racc (~> 1.4)
    rack (3.1.8)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  nokogiri
  rack
` + checksums + `
BUNDLED WITH
   2.6.2
`
}

func gemChecksums(rack, nokogiri []byte) string {
	return "\nCHECKSUMS\n  nokogiri (1.16.7-x86_64-linux) sha256=" + sha256Hex(nokogiri) + "\n  rack (3.1.8) sha256=" + sha256Hex(rack) + "\n"
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestImportLockfileGemfileFetchesAndPins drives `bodega pkg import --lockfile`
// end to end: the lockfile's specs become entries, each gem is fetched from
// rubygems_upstream and pinned under the key the /rubygems/gems/ route reads,
// and the CHECKSUMS digest agrees with the pin.
func TestImportLockfileGemfileFetchesAndPins(t *testing.T) {
	rack, nokogiri := []byte("rack 3.1.8 gem"), []byte("nokogiri 1.16.7 x86_64-linux gem")
	f := gemPrefetchFixture(t, map[string][]byte{"rack-3.1.8.gem": rack, "nokogiri-1.16.7-x86_64-linux.gem": nokogiri})
	lock := f.write(t, "Gemfile.lock", gemfileLock(gemChecksums(rack, nokogiri)))

	cmd := newImportCmd(&globalFlags{})
	cmd.SetArgs([]string{"--lockfile", lock})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("pkg import --lockfile: %v", err)
	}

	store := manifest.NewLocalStore(f.manifests)
	adb := f.open(t)
	defer adb.Close()
	for name, want := range map[string]struct {
		version string
		body    []byte
	}{"rack": {"3.1.8", rack}, "nokogiri": {"1.16.7-x86_64-linux", nokogiri}} {
		pm, err := store.GetPackage(t.Context(), manifest.TypeRubygems, name)
		if err != nil || pm == nil || len(pm.Versions) != 1 || pm.Versions[0].Version != want.version {
			t.Fatalf("stored %s = %+v, %v; want %s", name, pm, err, want.version)
		}
		if cs := pm.Versions[0].Checksum; cs == nil || cs.Value != sha256Hex(want.body) {
			t.Errorf("%s checksum = %+v; want the fetched gem's sha256", name, cs)
		}
		pin, err := adb.GetChecksum(t.Context(), manifest.RubygemsGemKey(name, want.version))
		if err != nil || pin == nil || pin.Value != sha256Hex(want.body) {
			t.Errorf("%s pin = %+v, %v", name, pin, err)
		}
	}

	cmd = newImportCmd(&globalFlags{})
	cmd.SetArgs([]string{"--lockfile", lock, "--merge"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--lockfile") {
		t.Errorf("--lockfile with --merge = %v; want a refusal naming --lockfile", err)
	}
}

// TestPrefetchGemfileLockRefusesADisagreeingChecksum is requirement 2's
// refusal: the gem fetched cleanly, and the lockfile's CHECKSUMS names other
// bytes, so the run answers no.
func TestPrefetchGemfileLockRefusesADisagreeingChecksum(t *testing.T) {
	rack, nokogiri := []byte("rack 3.1.8 gem"), []byte("nokogiri 1.16.7 x86_64-linux gem")
	f := gemPrefetchFixture(t, map[string][]byte{"rack-3.1.8.gem": rack, "nokogiri-1.16.7-x86_64-linux.gem": nokogiri})
	lock := f.write(t, "Gemfile.lock", gemfileLock(gemChecksums([]byte("other bytes"), nokogiri)))

	code, rows, err := f.prefetch(t, false, lock)
	if err != nil || code != exitBlocked {
		t.Fatalf("prefetch = %d, %v; want %d (rows %+v)", code, err, exitBlocked, rows)
	}
	byName := map[string]prefetchResult{}
	for _, r := range rows {
		byName[r.Name] = r
	}
	r := byName["rack"]
	if r.Decision != prefetchMismatch || r.Digest == nil || r.Digest.Bodega != "sha256:"+sha256Hex(rack) ||
		!strings.Contains(r.Reason, manifest.RubygemsGemKey("rack", "3.1.8")) {
		t.Errorf("rack = %+v digest %+v; want a mismatch naming the fetched digest and its key", r, r.Digest)
	}
	if n := byName["nokogiri"]; n.Decision != audit.AdmissionAdmitted || n.Digest == nil || n.Digest.Status != digestMatch {
		t.Errorf("nokogiri = %+v digest %+v; want its matching checksum admitted", n, n.Digest)
	}
}

// A lockfile Bundler wrote before 2.5 has no CHECKSUMS, so nothing is
// compared, and the result says so rather than reporting a match.
func TestPrefetchGemfileLockWithoutChecksums(t *testing.T) {
	f := gemPrefetchFixture(t, map[string][]byte{"rack-3.1.8.gem": []byte("r"), "nokogiri-1.16.7-x86_64-linux.gem": []byte("n")})
	lock := f.write(t, "Gemfile.lock", gemfileLock(""))

	code, rows, err := f.prefetch(t, false, lock)
	if err != nil || code != 0 || len(rows) != 2 {
		t.Fatalf("prefetch = %d, %v, %d rows; want 0 and two admitted gems", code, err, len(rows))
	}
	for _, r := range rows {
		if r.Fetch != "fetched" || r.Digest == nil || r.Digest.Status != digestNotCompared {
			t.Errorf("%s = %+v digest %+v; want fetched and not compared", r.Name, r, r.Digest)
		}
	}
}

// mavenPrefetchFixture is gemPrefetchFixture for maven_upstream: a TLS stub
// in the repository layout, answering each file's .sha256 from its bytes.
func mavenPrefetchFixture(t *testing.T, files map[string][]byte) *prefetchFixture {
	t.Helper()
	f := newPrefetchFixture(t, policy.ActionBlock)
	stub := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if base, ok := strings.CutSuffix(p, ".sha256"); ok {
			if body, found := files[base]; found {
				_, _ = w.Write([]byte(sha256Hex(body)))
				return
			}
		}
		body, ok := files[p]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(stub.Close)
	orig := http.DefaultTransport
	http.DefaultTransport = stub.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = orig })

	path := os.Getenv(config.EnvConfigFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["maven_upstream"] = stub.URL
	raw, _ = json.Marshal(cfg)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

const (
	slf4jPOM = "org/slf4j/slf4j-api/2.0.13/slf4j-api-2.0.13.pom"
	slf4jJar = "org/slf4j/slf4j-api/2.0.13/slf4j-api-2.0.13.jar"
	bomPOM   = "org/springframework/boot/spring-boot-dependencies/3.3.0/spring-boot-dependencies-3.3.0.pom"
	epollPOM = "io/netty/netty-transport-native-epoll/4.1.110.Final/netty-transport-native-epoll-4.1.110.Final.pom"
	epollJar = "io/netty/netty-transport-native-epoll/4.1.110.Final/netty-transport-native-epoll-4.1.110.Final.jar"
	epollX86 = "io/netty/netty-transport-native-epoll/4.1.110.Final/netty-transport-native-epoll-4.1.110.Final-linux-x86_64.jar"
)

func mavenPrefetchFiles() map[string][]byte {
	return map[string][]byte{
		slf4jPOM: []byte(`<project><artifactId>slf4j-api</artifactId></project>`),
		slf4jJar: []byte("slf4j-api 2.0.13 jar"),
		bomPOM:   []byte(`<project><artifactId>spring-boot-dependencies</artifactId><packaging>pom</packaging></project>`),
		epollPOM: []byte(`<project><artifactId>netty-transport-native-epoll</artifactId></project>`),
		epollJar: []byte("epoll jar"),
		epollX86: []byte("epoll linux-x86_64 jar"),
	}
}

// TestImportLockfileGradleFetchesAndPins drives `bodega pkg import --lockfile`
// over a gradle.lockfile end to end: each pin becomes a proxy-mode entry, its
// files are fetched from maven_upstream and checked against the upstream's
// .sha256, and every file is pinned under the key the /maven/ route reads.
func TestImportLockfileGradleFetchesAndPins(t *testing.T) {
	files := mavenPrefetchFiles()
	f := mavenPrefetchFixture(t, files)
	lock := f.write(t, "gradle.lockfile", "# This is a Gradle generated file for dependency locking.\n"+
		"org.slf4j:slf4j-api:2.0.13=compileClasspath,runtimeClasspath\n"+
		"org.springframework.boot:spring-boot-dependencies:3.3.0=compileClasspath,runtimeClasspath\n"+
		"empty=annotationProcessor\n")

	cmd := newImportCmd(&globalFlags{})
	cmd.SetArgs([]string{"--lockfile", lock})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("pkg import --lockfile: %v", err)
	}

	store := manifest.NewLocalStore(f.manifests)
	adb := f.open(t)
	defer adb.Close()
	for name, want := range map[string]struct{ main, ext string }{
		"org.slf4j:slf4j-api":                               {slf4jJar, "jar"},
		"org.springframework.boot:spring-boot-dependencies": {bomPOM, "pom"},
	} {
		pm, err := store.GetPackage(t.Context(), manifest.TypeMaven, name)
		if err != nil || pm == nil || len(pm.Versions) != 1 {
			t.Fatalf("stored %s = %+v, %v", name, pm, err)
		}
		ve := pm.Versions[0]
		if ve.Mode != manifest.ModeProxy || ve.Metadata[manifest.MetaMavenExtension] != want.ext {
			t.Errorf("%s entry = %+v; want proxy mode and the %s packaging recorded", name, ve, want.ext)
		}
		if cs := ve.Checksum; cs == nil || cs.Value != sha256Hex(files[want.main]) {
			t.Errorf("%s checksum = %+v; want the sha256 of %s", name, cs, want.main)
		}
		pin, err := adb.GetChecksum(t.Context(), manifest.MavenKey(want.main))
		if err != nil || pin == nil || pin.Value != sha256Hex(files[want.main]) {
			t.Errorf("%s pin = %+v, %v; want it under %s", name, pin, err, manifest.MavenKey(want.main))
		}
	}
}

// A dependency:list output file carries no name prefetch recognizes, so its
// header identifies it; the classifier it resolved is fetched beside the jar.
// A second list naming the same version with another classifier folds it in
// rather than being dropped as a version already held.
func TestPrefetchMavenDependencyListFetchesClassifiers(t *testing.T) {
	files := mavenPrefetchFiles()
	f := mavenPrefetchFixture(t, files)
	first := f.write(t, "deps.txt", "\nThe following files have been resolved:\n"+
		"   io.netty:netty-transport-native-epoll:jar:4.1.110.Final:runtime -- module io.netty.transport.epoll [auto]\n")
	code, rows, err := f.prefetch(t, false, first)
	if err != nil || code != 0 || len(rows) != 1 || rows[0].Fetch != "fetched" {
		t.Fatalf("prefetch = %d, %v, %+v; want epoll admitted and fetched", code, err, rows)
	}
	second := f.write(t, "runtime-deps.txt", "\nThe following files have been resolved:\n"+
		"   io.netty:netty-transport-native-epoll:jar:linux-x86_64:4.1.110.Final:runtime\n")
	if code, rows, err := f.prefetch(t, false, second); err != nil || code != 0 || len(rows) != 1 {
		t.Fatalf("second prefetch = %d, %v, %+v", code, err, rows)
	}

	store := manifest.NewLocalStore(f.manifests)
	pm, err := store.GetPackage(t.Context(), manifest.TypeMaven, "io.netty:netty-transport-native-epoll")
	if err != nil || pm == nil || len(pm.Versions) != 1 {
		t.Fatalf("stored epoll = %+v, %v", pm, err)
	}
	if got := pm.Versions[0].Classifiers; len(got) != 1 || got[0] != "linux-x86_64" {
		t.Errorf("classifiers = %v; want the second list's linux-x86_64 folded into the held version", got)
	}
	adb := f.open(t)
	defer adb.Close()
	pin, err := adb.GetChecksum(t.Context(), manifest.MavenKey(epollX86))
	if err != nil || pin == nil || pin.Value != sha256Hex(files[epollX86]) {
		t.Errorf("classifier pin = %+v, %v; want the linux-x86_64 jar pinned under its own key", pin, err)
	}
}
