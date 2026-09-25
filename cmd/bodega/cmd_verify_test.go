package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// verifyEnv is a scratch install whose manifest store the CLI resolves through
// $BODEGA_CONFIG_FILE. It returns the manifest directory.
func verifyEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	body := `{"storage_backend":"local","storage_path":"` + dir + `","manifest_dir":"` + dir +
		`","log_dir":"` + dir + `","allow_plaintext":true,"apt_codename":"noble"}`
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(config.EnvConfigFile, cfgPath)
	return dir
}

func runVerify(t *testing.T) (string, error) {
	t.Helper()
	cmd := newVerifyCmd(&globalFlags{})
	cmd.SetArgs(nil)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	err := cmd.Execute()
	return out.String(), err
}

// TestVerifyFailsOnTamperedManifest is B54's headline defect: editing a
// manifest by hand and running `pkg verify` printed "All manifests passed
// integrity check" and exited 0. It fails on a tree where the sidecar is never
// written, because there is nothing for verify to compare against.
func TestVerifyFailsOnTamperedManifest(t *testing.T) {
	dir := verifyEnv(t)
	store := manifest.NewLocalStore(dir)
	pm := &manifest.PackageManifest{
		Type:        manifest.TypeBinary,
		Name:        "hello-binary",
		Description: "a fixture",
		Versions:    []manifest.VersionEntry{{Version: "1.0.0", URL: "https://example.invalid/hello"}},
	}
	if err := store.SavePackage(t.Context(), pm); err != nil {
		t.Fatalf("SavePackage: %v", err)
	}
	if err := store.SaveIndex(t.Context()); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}

	if out, err := runVerify(t); err != nil {
		t.Fatalf("a clean store failed verification: %v\n%s", err, out)
	}

	path := filepath.Join(dir, "binary", "hello-binary", "manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(data), "a fixture", "tampered", 1)
	if tampered == string(data) {
		t.Fatal("the edit changed nothing, so this would verify a store nobody tampered with")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := runVerify(t)
	if err == nil {
		t.Fatalf("pkg verify exited 0 on an edited manifest:\n%s", out)
	}
	if !strings.Contains(out, "hello-binary") {
		t.Errorf("the failure does not name the edited package:\n%s", out)
	}
	if strings.Contains(out, "All ") && strings.Contains(out, "passed integrity check") {
		t.Errorf("a failing run still declared every manifest passed:\n%s", out)
	}
}

// TestVerifyDoesNotPassAnUnverifiableManifest covers the summary line that
// cannot be true twice: a run that reports a manifest it could not check must
// not also declare that every manifest passed, and must exit non-zero.
func TestVerifyDoesNotPassAnUnverifiableManifest(t *testing.T) {
	dir := verifyEnv(t)
	store := manifest.NewLocalStore(dir)
	pm := &manifest.PackageManifest{
		Type:     manifest.TypeCargo,
		Name:     "itoa",
		Versions: []manifest.VersionEntry{{Version: "1.0.11"}},
	}
	if err := store.SavePackage(t.Context(), pm); err != nil {
		t.Fatalf("SavePackage: %v", err)
	}
	if err := store.SaveIndex(t.Context()); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "cargo", "itoa", "manifest.json.md5")); err != nil {
		t.Fatal(err)
	}

	out, err := runVerify(t)
	if err == nil {
		t.Fatalf("pkg verify exited 0 with a manifest it could not verify:\n%s", out)
	}
	if !strings.Contains(out, manifest.IntegrityUnverifiable) {
		t.Errorf("no UNVERIFIABLE row for the sidecar-less manifest:\n%s", out)
	}
	if strings.Contains(out, "passed integrity check") {
		t.Errorf("the run declared manifests passed while reporting one it could not check:\n%s", out)
	}
	// The cargo manifest is on disk, so nothing may report it missing. The
	// old walk built <manifestDir>/cargo.json from AllTypes and printed
	// "cargo    MISSING (no manifest file)" against a store holding
	// cargo/itoa/manifest.json.
	if strings.Contains(out, "MISSING") {
		t.Errorf("a manifest on disk was reported MISSING:\n%s", out)
	}
}

// TestVerifyReportsAnEscapingBinaryFilename is the upgrade path for B93: a
// manifest written before filenames were checked still carries one the fetch
// now refuses, and verify is where an operator finds it before a fetch does.
func TestVerifyReportsAnEscapingBinaryFilename(t *testing.T) {
	dir := verifyEnv(t)
	store := manifest.NewLocalStore(dir)
	pm := &manifest.PackageManifest{
		Type:     manifest.TypeBinary,
		Name:     "tool",
		Versions: []manifest.VersionEntry{{Version: "1.0.0", URL: "https://example.invalid/tool", Filename: "placeholder"}},
	}
	if err := store.SavePackage(t.Context(), pm); err != nil {
		t.Fatalf("SavePackage: %v", err)
	}
	if err := store.SaveIndex(t.Context()); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}
	mpath := filepath.Join(dir, manifest.TypeBinary, "tool", "manifest.json")
	data, err := os.ReadFile(mpath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mpath, []byte(strings.Replace(string(data), `"placeholder"`, `"../../../../escaped"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := runVerify(t)
	if err == nil {
		t.Fatalf("verify exited 0 on an escaping binary filename:\n%s", out)
	}
	if !strings.Contains(out, "INVALID") || !strings.Contains(out, "binary/tool@1.0.0") {
		t.Errorf("verify did not name the version carrying the filename:\n%s", out)
	}
}

// TestVerifyReportsUnindexedBinaryFilename stores a manifest the index does
// not list, with a matching sidecar so an MD5 mismatch cannot stand in for the
// filename check. Walking the index skipped it and verify exited 0.
func TestVerifyReportsUnindexedBinaryFilename(t *testing.T) {
	dir := verifyEnv(t)
	store := manifest.NewLocalStore(dir)
	if err := store.SaveIndex(t.Context()); err != nil {
		t.Fatal(err)
	}
	pm := &manifest.PackageManifest{
		Type:     manifest.TypeBinary,
		Name:     "tool",
		Versions: []manifest.VersionEntry{{Version: "1.0.0", URL: "https://example.invalid/tool", Filename: "placeholder"}},
	}
	if err := store.SavePackage(t.Context(), pm); err != nil {
		t.Fatalf("SavePackage: %v", err)
	}
	mpath := filepath.Join(dir, manifest.TypeBinary, "tool", "manifest.json")
	data, err := os.ReadFile(mpath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mpath, []byte(strings.Replace(string(data), `"placeholder"`, `"../../../../escaped"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RestampMD5(t.Context(), ""); err != nil {
		t.Fatal(err)
	}

	out, err := runVerify(t)
	if err == nil {
		t.Fatalf("verify exited 0 on an unindexed escaping binary filename:\n%s", out)
	}
	if !strings.Contains(out, "INVALID") || !strings.Contains(out, "binary/tool@1.0.0") {
		t.Errorf("verify did not name the version carrying the filename:\n%s", out)
	}
}

func TestVerifyReportsUnparseableBinaryManifest(t *testing.T) {
	dir := verifyEnv(t)
	store := manifest.NewLocalStore(dir)
	if err := store.SaveIndex(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, manifest.TypeBinary, "tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, manifest.TypeBinary, "tool", "manifest.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RestampMD5(t.Context(), ""); err != nil {
		t.Fatal(err)
	}

	out, err := runVerify(t)
	if err == nil {
		t.Fatalf("verify exited 0 on a binary manifest it could not parse:\n%s", out)
	}
	if !strings.Contains(out, "UNCHECKED") || !strings.Contains(out, "binary/tool/manifest.json") {
		t.Errorf("verify did not name the manifest it could not check:\n%s", out)
	}
}
