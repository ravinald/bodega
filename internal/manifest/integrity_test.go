package manifest_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

func TestWriteAndReadMD5File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	data := []byte(`{"hello":"world"}` + "\n")

	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := manifest.WriteMD5File(path, data); err != nil {
		t.Fatalf("WriteMD5File: %v", err)
	}

	stored, err := manifest.ReadMD5File(path)
	if err != nil {
		t.Fatalf("ReadMD5File: %v", err)
	}
	if len(stored) != 32 {
		t.Errorf("expected 32-char MD5 hex, got %q", stored)
	}
}

func TestVerifyMD5_Match(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	data := []byte(`{"key":"value"}`)

	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := manifest.WriteMD5File(path, data); err != nil {
		t.Fatal(err)
	}

	ok, err := manifest.VerifyMD5(path, data)
	if err != nil {
		t.Fatalf("VerifyMD5: %v", err)
	}
	if !ok {
		t.Error("expected VerifyMD5 to return true for matching content")
	}
}

func TestVerifyMD5_Mismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	original := []byte(`{"key":"value"}`)
	modified := []byte(`{"key":"DIFFERENT"}`)

	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := manifest.WriteMD5File(path, original); err != nil {
		t.Fatal(err)
	}

	ok, err := manifest.VerifyMD5(path, modified)
	if err != nil {
		t.Fatalf("VerifyMD5: %v", err)
	}
	if ok {
		t.Error("expected VerifyMD5 to return false for mismatched content")
	}
}

func TestVerifyMD5_NoCompanionFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new.json")
	data := []byte(`[]`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	// No .md5 file — should return true (first-time write allowed).
	ok, err := manifest.VerifyMD5(path, data)
	if err != nil {
		t.Fatalf("VerifyMD5: %v", err)
	}
	if !ok {
		t.Error("expected VerifyMD5 to return true when no .md5 file exists")
	}
}

func TestForceUpdateMD5(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "git.json")
	data := []byte(`[{"name":"x","url":"y","ref":"z"}]` + "\n")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	// Write a wrong MD5.
	if err := os.WriteFile(path+".md5", []byte("wrong\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := manifest.ForceUpdateMD5(dir, "git"); err != nil {
		t.Fatalf("ForceUpdateMD5: %v", err)
	}

	ok, err := manifest.VerifyMD5(path, data)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected VerifyMD5 to pass after ForceUpdateMD5")
	}
}
