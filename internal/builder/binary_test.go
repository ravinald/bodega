package builder

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHumanBytes(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1048576, "1.0 MiB"},
		{1073741824, "1.0 GiB"},
	}
	for _, tt := range tests {
		got := humanBytes(tt.input)
		if got != tt.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestVerifySHA256_Match(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.bin")
	content := []byte("hello bootstrap")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	// Compute expected sum.
	sum, err := fileSHA256(path)
	if err != nil {
		t.Fatalf("fileSHA256: %v", err)
	}
	if err := verifySHA256(path, sum); err != nil {
		t.Errorf("verifySHA256: unexpected error: %v", err)
	}
}

func TestVerifySHA256_Mismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.bin")
	if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := verifySHA256(path, "0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Error("expected error on SHA-256 mismatch, got nil")
	}
}

func TestFileSHA256_NonExistent(t *testing.T) {
	_, err := fileSHA256("/nonexistent/path/file.bin")
	if err == nil {
		t.Error("expected error for nonexistent file, got nil")
	}
}
