package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// uploadEnv is a scratch install: a local storage backend, an empty build root
// and an audit database at the path the command opens for itself. Nothing is
// fetched, so `build upload` has to run the whole cascade to have anything to
// place.
type uploadEnv struct {
	manifestDir string
	auditDB     string
	buildRoot   string
}

func newUploadEnv(t *testing.T) *uploadEnv {
	t.Helper()
	dir := t.TempDir()
	env := &uploadEnv{
		manifestDir: filepath.Join(dir, "manifests"),
		auditDB:     filepath.Join(dir, "audit.db"),
		buildRoot:   filepath.Join(dir, "build"),
	}
	for _, d := range []string{env.manifestDir, env.buildRoot, filepath.Join(dir, "storage")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	body := fmt.Sprintf(`{
  "storage_backend": "local",
  "storage_path": %q,
  "manifest_dir": %q,
  "build_root": %q,
  "audit_db": %q,
  "log_dir": %q,
  "allow_plaintext": true,
  "apt_codename": "noble"
}`, filepath.Join(dir, "storage"), env.manifestDir, env.buildRoot, env.auditDB, dir)
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(config.EnvConfigFile, path)
	return env
}

func (e *uploadEnv) seed(t *testing.T, pm *manifest.PackageManifest) {
	t.Helper()
	ctx := context.Background()
	store := manifest.NewLocalStore(e.manifestDir)
	if err := store.LoadIndex(ctx); err != nil {
		t.Fatalf("load index: %v", err)
	}
	pm.ConfigVersion = manifest.CurrentConfigVersion
	if err := store.SavePackage(ctx, pm); err != nil {
		t.Fatalf("seed %s/%s: %v", pm.Type, pm.Name, err)
	}
	if err := store.SaveIndex(ctx); err != nil {
		t.Fatalf("save index: %v", err)
	}
}

// checksums reads the audit database back off disk. The command opened its own
// handle and closed it, so this asserts against what landed rather than against
// an in-process cache.
func (e *uploadEnv) checksums(t *testing.T, typ, name string) []audit.StoredChecksum {
	t.Helper()
	db, err := audit.Open(e.auditDB)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.ListChecksums(context.Background(), typ, name)
	if err != nil {
		t.Fatalf("list checksums: %v", err)
	}
	return rows
}

// runUpload drives the command the way a shell does, capturing os.Stdout
// because the cascade prints there rather than to the command's own writer.
func runUpload(t *testing.T, args ...string) string {
	t.Helper()
	cmd := newUploadCmd(&globalFlags{})
	cmd.SetArgs(args)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true

	stdout, stderr := os.Stdout, os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout, os.Stderr = w, w
	execErr := cmd.Execute()
	_ = w.Close()
	os.Stdout, os.Stderr = stdout, stderr
	var printed bytes.Buffer
	_, _ = printed.ReadFrom(r)

	got := printed.String() + out.String()
	if execErr != nil {
		t.Fatalf("bodega build upload: %v\n%s", execErr, got)
	}
	return got
}

// TestUploadCascadePinsAFirstFetch covers the route a fresh install actually
// takes: `build upload` with nothing fetched yet, which reaches the network
// through ensureUploadable rather than through `build fetch`. That cascade ran
// under a builder.Config whose AuditDB was never assigned, so every digest it
// computed stopped at pinChecksum's nil guard and `pkg checksum list` printed
// "No cached checksums." after a complete pipeline.
func TestUploadCascadePinsAFirstFetch(t *testing.T) {
	body := []byte("#!/bin/sh\necho hello\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	env := newUploadEnv(t)
	env.seed(t, &manifest.PackageManifest{
		Type: manifest.TypeBinary,
		Name: "hello-binary",
		Versions: []manifest.VersionEntry{{
			Version:  "1.0.0",
			URL:      srv.URL + "/hello-binary",
			Filename: "hello-binary",
		}},
	})

	out := runUpload(t, manifest.TypeBinary)

	rows := env.checksums(t, manifest.TypeBinary, "hello-binary")
	if len(rows) != 1 {
		t.Fatalf("the upload cascade recorded %d checksum rows, want 1\n%s", len(rows), out)
	}
	want := manifest.BinaryKey("hello-binary", "1.0.0", "hello-binary")
	if rows[0].S3Key != want {
		t.Errorf("row keyed on %q, not the object key %q the proxy verifies against", rows[0].S3Key, want)
	}
	if rows[0].Value != builder.ComputeBytesSHA256(body) {
		t.Errorf("row holds %q, want the digest of the bytes the fetch downloaded", rows[0].Value)
	}
	if rows[0].PkgVersion != "1.0.0" {
		t.Errorf("row is %+v, want version 1.0.0", rows[0])
	}
}

// TestUploadCascadePinsDirectAptAtPackageTime covers the type whose row is made
// one stage later. apt is keyed on _pool_path, which PackageApt writes when it
// copies the .deb into pool/, so the pin the fetch could not make is made by
// the package stage of the same cascade.
func TestUploadCascadePinsDirectAptAtPackageTime(t *testing.T) {
	if _, err := exec.LookPath("dpkg-deb"); err != nil {
		t.Skip("dpkg-deb is required to produce a .deb whose control data PackageApt can read")
	}
	const debName = "hello-upload_1.0_all.deb"
	deb := filepath.Join(t.TempDir(), debName)
	writeUploadDeb(t, deb, "hello-upload", "1.0")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, deb)
	}))
	defer srv.Close()

	env := newUploadEnv(t)
	env.seed(t, &manifest.PackageManifest{
		Type: manifest.TypeApt,
		Name: "hello-upload",
		Versions: []manifest.VersionEntry{{
			Version: "1.0",
			URL:     srv.URL + "/" + debName,
		}},
	})

	out := runUpload(t, manifest.TypeApt)

	rows := env.checksums(t, manifest.TypeApt, "hello-upload")
	if len(rows) != 1 {
		t.Fatalf("the upload cascade recorded %d checksum rows for apt, want 1\n%s", len(rows), out)
	}
	want := manifest.AptKey("pool/main/h/hello-upload/" + debName)
	if rows[0].S3Key != want {
		t.Errorf("row keyed on %q, want the pool key %q", rows[0].S3Key, want)
	}
	if rows[0].PkgVersion != "1.0" {
		t.Errorf("row is %+v, want version 1.0", rows[0])
	}
}

// writeUploadDeb builds a minimal installable .deb at dest. PackageApt reads
// its control data with dpkg-deb, so a hand-rolled ar archive would not do.
func writeUploadDeb(t *testing.T, dest, name, version string) {
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
	if out, err := exec.Command("dpkg-deb", "--build", "--root-owner-group", staging, dest).CombinedOutput(); err != nil {
		t.Fatalf("dpkg-deb --build: %v\n%s", err, out)
	}
}
