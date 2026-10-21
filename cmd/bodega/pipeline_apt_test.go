package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/manifest"
)

// aptBuildScript builds widget_<version>_all.deb in the clone from the
// description in DESC. The fixed timestamps make the build reproducible, as
// dpkg-buildpackage is through the changelog date, so a rebuild at an
// unchanged ref yields the bytes already in the pool.
const aptBuildScript = `set -e
v=$1
rm -rf stage
mkdir -p stage/DEBIAN
printf 'Package: widget\nVersion: %s\nArchitecture: all\nMaintainer: bodega <admin@example.com>\nDescription: %s\n' "$v" "$(cat DESC)" > stage/DEBIAN/control
touch -t 202001010000 stage stage/DEBIAN stage/DEBIAN/control
SOURCE_DATE_EPOCH=1577836800 dpkg-deb --build --root-owner-group stage "widget_${v}_all.deb" >/dev/null
rm -rf stage
`

// aptNonReproducibleBuildScript is aptBuildScript with random bytes in the
// description and no pinned timestamps, so no two builds match.
const aptNonReproducibleBuildScript = `set -e
v=$1
rm -rf stage
mkdir -p stage/DEBIAN
printf 'Package: widget\nVersion: %s\nArchitecture: all\nMaintainer: bodega <admin@example.com>\nDescription: %s %s\n' "$v" "$(cat DESC)" "$(od -An -N8 -tx8 /dev/urandom | tr -d ' ')" > stage/DEBIAN/control
dpkg-deb --build --root-owner-group stage "widget_${v}_all.deb" >/dev/null
rm -rf stage
`

// aptBuildUpstream is a git repository whose tags ra and rb carry build.sh
// with two different descriptions, so the two refs build different bytes
// under one .deb filename.
func aptBuildUpstream(t *testing.T) string {
	t.Helper()
	return aptBuildUpstreamWith(t, aptBuildScript)
}

func aptBuildUpstreamWith(t *testing.T, script string) string {
	t.Helper()
	for _, tool := range []string{"git", "dpkg-deb"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not installed")
		}
	}
	dir := filepath.Join(t.TempDir(), "upstream")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) {
		t.Helper()
		full := append([]string{"-C", dir, "-c", "user.email=e2e@bodega.test", "-c", "user.name=bodega"}, args...)
		if out, err := exec.Command("git", full...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git("-c", "init.defaultBranch=main", "init", "-q")
	write("build.sh", script)
	for _, ref := range []string{"ra", "rb"} {
		write("DESC", "built at "+ref+"\n")
		git("add", "build.sh", "DESC")
		git("commit", "-q", "-m", ref)
		git("tag", ref)
	}
	return dir
}

// aptCascade is a build root, manifest store and audit database that persist
// across ensurePackagedApt calls, the way they do across `bodega package apt`
// runs.
type aptCascade struct {
	cfg   *builder.Config
	store *manifest.Store
	db    *audit.DB
	out   bytes.Buffer
}

func newAptCascade(t *testing.T, versions ...manifest.VersionEntry) *aptCascade {
	t.Helper()
	dir := t.TempDir()
	db, err := audit.Open(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	c := &aptCascade{store: manifest.NewLocalStore(filepath.Join(dir, "manifests")), db: db}
	c.cfg = &builder.Config{BuildRoot: filepath.Join(dir, "build"), AuditDB: db, Stdout: &c.out}
	c.save(t, versions...)
	return c
}

func (c *aptCascade) save(t *testing.T, versions ...manifest.VersionEntry) {
	t.Helper()
	pm, err := c.store.GetPackage(t.Context(), manifest.TypeApt, "widget")
	if err != nil || pm == nil {
		pm = &manifest.PackageManifest{Type: manifest.TypeApt, Name: "widget"}
	}
	pm.Versions = versions
	if err := c.store.SavePackage(t.Context(), pm); err != nil {
		t.Fatalf("SavePackage: %v", err)
	}
}

func (c *aptCascade) entry(t *testing.T, version string) manifest.VersionEntry {
	t.Helper()
	pm, err := c.store.GetPackage(t.Context(), manifest.TypeApt, "widget")
	if err != nil || pm == nil {
		t.Fatalf("GetPackage: %v", err)
	}
	for _, ve := range pm.Versions {
		if ve.Version == version {
			return ve
		}
	}
	t.Fatalf("widget has no version %s", version)
	return manifest.VersionEntry{}
}

// run drives the cascade once and returns that run's output only.
func (c *aptCascade) run(t *testing.T) (*builder.Summary, string) {
	t.Helper()
	c.out.Reset()
	s := ensurePackagedApt(c.cfg, c.store, "widget")
	return s, c.out.String()
}

func (c *aptCascade) poolFile(version string) string {
	return filepath.Join(c.cfg.BuildRoot, "apt-repo", "pool", "main", "w", "widget", "widget_"+version+"_all.deb")
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func aptSourceEntry(upstream, version, ref string) manifest.VersionEntry {
	return manifest.VersionEntry{Version: version, URL: upstream, Ref: ref, BuildCmd: "sh build.sh " + version}
}

func TestEnsurePackagedAptSkipsPackagedVersion(t *testing.T) {
	upstream := aptBuildUpstream(t)
	c := newAptCascade(t, aptSourceEntry(upstream, "1.0", "ra"))

	if s, out := c.run(t); s.HasFailures() || !strings.Contains(out, ">>> [apt] package widget") {
		t.Fatalf("first run did not package widget: %+v\n%s", s.Results, out)
	}
	if _, err := os.Stat(c.poolFile("1.0")); err != nil {
		t.Fatalf("first run left no pool file: %v", err)
	}

	s, out := c.run(t)
	if s.HasFailures() {
		t.Fatalf("second run failed: %+v\n%s", s.Results, out)
	}
	if strings.Contains(out, ">>> [apt] package") {
		t.Errorf("a version already packaged was packaged again:\n%s", out)
	}
}

func TestEnsurePackagedAptRefChangeKeepsPoolAndRecord(t *testing.T) {
	upstream := aptBuildUpstream(t)
	c := newAptCascade(t, aptSourceEntry(upstream, "1.0", "ra"))

	if s, out := c.run(t); s.HasFailures() {
		t.Fatalf("packaging at ra failed: %+v\n%s", s.Results, out)
	}
	atRA := sha256File(t, c.poolFile("1.0"))
	key := manifest.AptKey("pool/main/w/widget/widget_1.0_all.deb")

	moved := c.entry(t, "1.0")
	moved.Ref = "rb"
	c.save(t, moved)
	s, out := c.run(t)
	if !s.HasFailures() {
		t.Fatalf("a ref change that built other bytes under version 1.0 was packaged:\n%s", out)
	}
	for _, want := range []string{"Re-fetching widget", "Running: sh build.sh 1.0", "ref rb", atRA} {
		if !strings.Contains(out, want) {
			t.Errorf("the run's output does not say %q:\n%s", want, out)
		}
	}

	if got := sha256File(t, c.poolFile("1.0")); got != atRA {
		t.Errorf("the pool file is sha256 %s after the refusal, want the build from ra %s", got, atRA)
	}
	ve := c.entry(t, "1.0")
	if ve.Checksum == nil || ve.Checksum.Value != atRA {
		t.Errorf("the stored checksum is %+v, want %s", ve.Checksum, atRA)
	}
	if ve.Metadata["_sha256"] != atRA {
		t.Errorf("the stored _sha256 is %q, want %s", ve.Metadata["_sha256"], atRA)
	}
	if pin, err := c.db.GetChecksum(t.Context(), key); err != nil || pin == nil || pin.Value != atRA {
		t.Errorf("the pin for %s reads %+v (%v), want %s", key, pin, err, atRA)
	}
}

func TestEnsurePackagedAptSecondVersion(t *testing.T) {
	upstream := aptBuildUpstream(t)
	x := aptSourceEntry(upstream, "1.0", "ra")
	c := newAptCascade(t, x)

	if s, out := c.run(t); s.HasFailures() {
		t.Fatalf("packaging 1.0 failed: %+v\n%s", s.Results, out)
	}
	xBefore := sha256File(t, c.poolFile("1.0"))

	c.save(t, c.entry(t, "1.0"), aptSourceEntry(upstream, "2.0", "rb"))
	s, out := c.run(t)
	if s.HasFailures() {
		t.Fatalf("adding version 2.0 failed: %+v\n%s", s.Results, out)
	}
	if got := sha256File(t, c.poolFile("1.0")); got != xBefore {
		t.Errorf("1.0's pool file changed from %s to %s", xBefore, got)
	}
	if _, err := os.Stat(c.poolFile("2.0")); err != nil {
		t.Errorf("2.0 has no pool file: %v", err)
	}
	// PackageApt covers every version of the package and prints one header
	// per version, so one run over 1.0 and 2.0 prints two.
	if n := strings.Count(out, ">>> [apt] package widget"); n != 2 {
		t.Errorf("the package stage printed %d version headers, want 2 from one run:\n%s", n, out)
	}
}

func TestEnsurePackagedAptSecondVersionNonReproducible(t *testing.T) {
	upstream := aptBuildUpstreamWith(t, aptNonReproducibleBuildScript)
	c := newAptCascade(t, aptSourceEntry(upstream, "1.0", "ra"))

	if s, out := c.run(t); s.HasFailures() {
		t.Fatalf("packaging 1.0 failed: %+v\n%s", s.Results, out)
	}
	xPool := sha256File(t, c.poolFile("1.0"))
	key := manifest.AptKey("pool/main/w/widget/widget_1.0_all.deb")

	c.save(t, c.entry(t, "1.0"), aptSourceEntry(upstream, "2.0", "rb"))
	s, out := c.run(t)
	if s.HasFailures() {
		t.Fatalf("adding version 2.0 failed: %+v\n%s", s.Results, out)
	}
	if strings.Contains(out, "Running: sh build.sh 1.0") {
		t.Errorf("adding 2.0 rebuilt the packaged 1.0:\n%s", out)
	}
	if got := sha256File(t, c.poolFile("1.0")); got != xPool {
		t.Errorf("1.0's pool file changed from %s to %s", xPool, got)
	}
	ve := c.entry(t, "1.0")
	if ve.Checksum == nil || ve.Checksum.Value != xPool {
		t.Errorf("1.0's stored checksum is %+v, want %s", ve.Checksum, xPool)
	}
	if ve.Metadata["_sha256"] != xPool {
		t.Errorf("1.0's stored _sha256 is %q, want %s", ve.Metadata["_sha256"], xPool)
	}
	if pin, err := c.db.GetChecksum(t.Context(), key); err != nil || pin == nil || pin.Value != xPool {
		t.Errorf("the pin for %s reads %+v (%v), want %s", key, pin, err, xPool)
	}
	if _, err := os.Stat(c.poolFile("2.0")); err != nil {
		t.Errorf("2.0 has no pool file: %v", err)
	}

	s, out = c.run(t)
	if s.HasFailures() {
		t.Fatalf("third run failed: %+v\n%s", s.Results, out)
	}
	for _, header := range []string{">>> [apt] build", ">>> [apt] package"} {
		if strings.Contains(out, header) {
			t.Errorf("third run over packaged versions printed %q:\n%s", header, out)
		}
	}
}
