package tui

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// pinEnv is a scratch build root, manifest store and audit database wired the
// way `bodega shell` wires them: the database the shell command opened, and a
// config.Config naming the same roots the TUI reads.
func pinEnv(t *testing.T, pm *manifest.PackageManifest) (*config.Config, *manifest.Store, *audit.DB, string) {
	t.Helper()
	dir := t.TempDir()
	root := filepath.Join(dir, "build")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := audit.Open(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store := manifest.NewLocalStore(filepath.Join(dir, "manifests"))
	if err := store.SavePackage(t.Context(), pm); err != nil {
		t.Fatalf("SavePackage: %v", err)
	}
	return &config.Config{BuildRoot: root, ManifestDir: filepath.Join(dir, "manifests")}, store, db, root
}

// TestTUIFetchPinsChecksum drives the TUI's own fetch path, which builds its
// builder.Config in builderCfg rather than taking the CLI's. NewConfig leaves
// AuditDB to the caller, so before that config carried one, pinChecksum
// returned at its nil guard: the manifest got the digest, the checksum cache
// `pkg checksum list` reads got nothing, and an operator who only ever used
// the interactive UI saw "No cached checksums" after a full pipeline.
//
// The chart is already on disk, so FetchHelm takes the "already fetched,
// skipping" path and the fetch never leaves the machine.
func TestTUIFetchPinsChecksum(t *testing.T) {
	pm := &manifest.PackageManifest{
		Type:     manifest.TypeHelm,
		Name:     "podinfo",
		Versions: []manifest.VersionEntry{{Version: "6.7.0", URL: "https://example.invalid/podinfo-6.7.0.tgz"}},
	}
	cfg, store, db, root := pinEnv(t, pm)

	body := []byte("chart bytes")
	chart := filepath.Join(root, "charts", "podinfo", "6.7.0", "podinfo-6.7.0.tgz")
	if err := os.MkdirAll(filepath.Dir(chart), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(chart, body, 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := runFetch(&buf, cfg, store, db, []string{manifest.TypeHelm}); err != nil {
		t.Fatalf("runFetch: %v\n%s", err, buf.String())
	}

	rows, err := db.ListChecksums(t.Context(), manifest.TypeHelm, "podinfo")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("a TUI fetch recorded %d checksum rows, want 1\n%s", len(rows), buf.String())
	}
	if rows[0].PkgVersion != "6.7.0" || rows[0].Value != builder.ComputeBytesSHA256(body) {
		t.Errorf("row is %+v, want the digest of the chart on disk at version 6.7.0", rows[0])
	}
	if rows[0].S3Key != manifest.HelmChartKey("podinfo", "6.7.0") {
		t.Errorf("row keyed on %q, not the object key the proxy verifies against", rows[0].S3Key)
	}
}

// TestTUIFullPipelinePinsAptAtPackageTime covers the type whose pool key does
// not exist at fetch time. apt's artifact lives at _pool_path, which PackageApt
// writes when it copies the .deb into pool/, so the pin is made from the
// package stage — a different builder.Config than the fetch stage's, reached
// through runFullPipeline rather than runFetch.
func TestTUIFullPipelinePinsAptAtPackageTime(t *testing.T) {
	if _, err := exec.LookPath("dpkg-deb"); err != nil {
		t.Skip("dpkg-deb is required to produce a .deb whose control data PackageApt can read")
	}
	const debName = "hello-tui_1.0_all.deb"
	pm := &manifest.PackageManifest{
		Type: manifest.TypeApt,
		Name: "hello-tui",
		Versions: []manifest.VersionEntry{{
			Version: "1.0",
			URL:     "https://example.invalid/" + debName,
		}},
	}
	cfg, store, db, root := pinEnv(t, pm)

	// Stage the .deb where CheckAptStage looks, so FetchApt skips the download.
	dest := filepath.Join(root, "sources", "hello-tui", debName)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatal(err)
	}
	writeDeb(t, dest, "hello-tui", "1.0")

	msg := executeStage(StageAll, manifest.TypeApt, "hello-tui", cfg, store, nil, db)()
	out, ok := msg.(cmdOutputMsg)
	if !ok {
		t.Fatalf("executeStage returned %T, want cmdOutputMsg", msg)
	}
	if out.err != nil {
		t.Fatalf("full pipeline: %v\n%s", out.err, out.output)
	}

	rows, err := db.ListChecksums(t.Context(), manifest.TypeApt, "hello-tui")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("the TUI full pipeline recorded %d checksum rows for apt, want 1\n%s", len(rows), out.output)
	}
	want := manifest.AptKey("pool/main/h/hello-tui/" + debName)
	if rows[0].S3Key != want {
		t.Errorf("row keyed on %q, want the pool key %q", rows[0].S3Key, want)
	}
	if rows[0].PkgVersion != "1.0" {
		t.Errorf("row is %+v, want version 1.0", rows[0])
	}
}

// writeDeb builds a minimal installable .deb at dest. PackageApt reads its
// control data with dpkg-deb, so a hand-rolled ar archive would not do.
func writeDeb(t *testing.T, dest, name, version string) {
	t.Helper()
	staging := filepath.Join(t.TempDir(), name)
	debian := filepath.Join(staging, "DEBIAN")
	if err := os.MkdirAll(debian, 0o755); err != nil {
		t.Fatal(err)
	}
	control := "Package: " + name + "\nVersion: " + version +
		"\nArchitecture: all\nMaintainer: bodega <admin@cow.org>\nDescription: fixture\n"
	if err := os.WriteFile(filepath.Join(debian, "control"), []byte(control), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("dpkg-deb", "--build", "--root-owner-group", staging, dest)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("dpkg-deb --build: %v\n%s", err, out)
	}
}
