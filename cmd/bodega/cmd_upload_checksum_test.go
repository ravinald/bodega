package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	got, err := runUploadResult(t, args...)
	if err != nil {
		t.Fatalf("bodega build upload: %v\n%s", err, got)
	}
	return got
}

// runUploadResult is runUpload for a caller that expects the command to fail.
func runUploadResult(t *testing.T, args ...string) (string, error) {
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

	return printed.String() + out.String(), execErr
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
	if rows[0].ObjectKey != want {
		t.Errorf("row keyed on %q, not the object key %q the proxy verifies against", rows[0].ObjectKey, want)
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
	if rows[0].ObjectKey != want {
		t.Errorf("row keyed on %q, want the pool key %q", rows[0].ObjectKey, want)
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
		"\nArchitecture: all\nMaintainer: bodega <admin@example.com>\nDescription: fixture\n"
	if err := os.WriteFile(filepath.Join(debian, "control"), []byte(control), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("dpkg-deb", "--build", "--root-owner-group", staging, dest).CombinedOutput(); err != nil {
		t.Fatalf("dpkg-deb --build: %v\n%s", err, out)
	}
}

// A file in the DISTDIR is not evidence of admission. Upload holds each one to
// the current distinfo and fails the command, uploading nothing, when any is
// unlisted, wrong, repinned or restricted, or when there is no tree at all.
func TestUploadDistfilesHoldsTheDistdirToDistinfo(t *testing.T) {
	const good, wrong = "pcpustat source bytes", "PCPUSTAT SOURCE BYTES"
	for _, tc := range []struct {
		name     string
		tree     bool
		pinned   string // bytes the tree pins
		onDisk   string
		frozen   bool
		makefile string
		wantErr  string // "" means the upload succeeds
	}{
		{name: "no ports tree", onDisk: good, wantErr: "cascade for distfiles failed"},
		{name: "wrong body, refetch fails", tree: true, pinned: good, onDisk: wrong, wantErr: "cascade for distfiles failed"},
		{name: "wrong body, frozen", tree: true, pinned: good, onDisk: wrong, frozen: true, wantErr: "does not match distinfo"},
		{name: "tree repinned, frozen", tree: true, pinned: wrong, onDisk: good, frozen: true, wantErr: "does not match distinfo"},
		{name: "restricted since the fetch", tree: true, pinned: good, onDisk: good, makefile: "RESTRICTED=\tno\n", wantErr: "cascade for distfiles failed"},
		{name: "restricted since the fetch, frozen", tree: true, pinned: good, onDisk: good, frozen: true, makefile: "RESTRICTED=\tno\n", wantErr: "forbids redistributing"},
		{name: "admitted", tree: true, pinned: good, onDisk: good},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newUploadEnv(t)
			cfgPath := os.Getenv(config.EnvConfigFile)
			b, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			extra := `"distfiles_upstream": "http://127.0.0.1:1/",`
			if tc.tree {
				tree := t.TempDir()
				sum := sha256.Sum256([]byte(tc.pinned))
				writeFile(t, tree, "Mk/bsd.licenses.db.mk", "")
				writeFile(t, tree, "sysutils/pcpustat/Makefile", "DIST_SUBDIR=\tpcpustat\n"+tc.makefile)
				writeFile(t, tree, "sysutils/pcpustat/distinfo", fmt.Sprintf("SHA256 (pcpustat/1.6.tar.bz2) = %x\nSIZE (pcpustat/1.6.tar.bz2) = %d\n", sum, len(tc.pinned)))
				extra += fmt.Sprintf(" %q: %q,", "distfiles_ports_tree", tree)
			}
			b = bytes.Replace(b, []byte(`"apt_codename"`), []byte(extra+` "apt_codename"`), 1)
			if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
				t.Fatal(err)
			}
			e.seed(t, &manifest.PackageManifest{Type: manifest.TypeDistfiles, Name: "pcpustat/1.6.tar.bz2", Versions: []manifest.VersionEntry{{Frozen: tc.frozen}}})
			writeFile(t, e.buildRoot, "distfiles/@"+emptyEnvironmentDigest(t)+"/pcpustat/1.6.tar.bz2", tc.onDisk)

			out, err := runUploadResult(t, manifest.TypeDistfiles)
			stored := filepath.Join(filepath.Dir(e.buildRoot), "storage", "distfiles", "pcpustat", "1.6.tar.bz2")
			got, readErr := os.ReadFile(stored)
			if tc.wantErr == "" {
				if err != nil || string(got) != good {
					t.Fatalf("upload: %v, stored %q (%v)\n%s", err, got, readErr, out)
				}
				leftovers, _ := filepath.Glob(filepath.Join(e.buildRoot, ".bodega-distfiles-upload-*"))
				if len(leftovers) != 0 {
					t.Errorf("pin directory left behind: %v", leftovers)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error()+out, tc.wantErr) {
				t.Fatalf("upload: %v, want an error naming %q\n%s", err, tc.wantErr, out)
			}
			if readErr == nil {
				t.Fatalf("stored %q after the command refused", got)
			}
		})
	}
}

// A DISTDIR that cannot be created fails every selected entry, and the command
// exits nonzero rather than reporting zero failures for work it never did.
func TestFetchDistfilesFailsTheCommandWhenTheDistdirCannotBeCreated(t *testing.T) {
	e := newUploadEnv(t)
	e.seed(t, &manifest.PackageManifest{Type: manifest.TypeDistfiles, Name: "pcpustat/1.6.tar.bz2", Versions: []manifest.VersionEntry{{}}})
	cfgPath := os.Getenv(config.EnvConfigFile)
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	tree := t.TempDir()
	writeFile(t, tree, "Mk/bsd.licenses.db.mk", "")
	writeFile(t, tree, "sysutils/pcpustat/distinfo", "SHA256 (pcpustat/1.6.tar.bz2) = 3bc1906f8d4865bb02c59f2f752e79b08433bc1aa447d78ea3de1a0d02c45e64\nSIZE (pcpustat/1.6.tar.bz2) = 5135\n")
	b = bytes.Replace(b, []byte(`"apt_codename"`), []byte(fmt.Sprintf(`"distfiles_upstream": "http://127.0.0.1:1/", "distfiles_ports_tree": %q, "apt_codename"`, tree)), 1)
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	writeFile(t, e.buildRoot, "distfiles", "a regular file where the DISTDIR belongs")

	cmd := newFetchCmd(&globalFlags{})
	cmd.SetArgs([]string{manifest.TypeDistfiles})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	stdout := os.Stdout
	devnull, _ := os.Open(os.DevNull)
	os.Stdout = devnull
	err = cmd.Execute()
	os.Stdout = stdout
	_ = devnull.Close()
	if err == nil || !strings.Contains(err.Error(), "1 fetch(es) failed") {
		t.Fatalf("build fetch distfiles: %v, want it to fail naming one failed fetch", err)
	}
}
