package builder

import (
	"testing"
)

func TestExtractGPGKeyID(t *testing.T) {
	// Sample output from gpg --list-keys --keyid-format long
	sample := `pub   rsa4096/ABCDEF1234567890 2025-01-01 [SC]
      DEADBEEFDEADBEEFDEADBEEFDEADBEEF12345678
uid           [ultimate] Bodega Package Signing <bodega@localhost>
`
	got := extractGPGKeyID(sample)
	if got != "ABCDEF1234567890" {
		t.Errorf("extractGPGKeyID = %q, want %q", got, "ABCDEF1234567890")
	}
}

func TestExtractGPGKeyID_Empty(t *testing.T) {
	got := extractGPGKeyID("no key here")
	if got != "" {
		t.Errorf("extractGPGKeyID of empty input = %q, want \"\"", got)
	}
}

func TestIndexOf(t *testing.T) {
	tests := []struct {
		s, sub string
		want   int
	}{
		{"hello world", "world", 6},
		{"hello", "hello", 0},
		{"hello", "xyz", -1},
		{"", "x", -1},
		{"abc", "", 0},
	}
	for _, tt := range tests {
		got := indexOf(tt.s, tt.sub)
		if got != tt.want {
			t.Errorf("indexOf(%q, %q) = %d, want %d", tt.s, tt.sub, got, tt.want)
		}
	}
}

func TestSplitLines(t *testing.T) {
	input := "line1\nline2\nline3"
	got := splitLines(input)
	if len(got) != 3 {
		t.Errorf("splitLines: expected 3 lines, got %d: %v", len(got), got)
	}
	if got[0] != "line1" || got[1] != "line2" || got[2] != "line3" {
		t.Errorf("splitLines: unexpected result: %v", got)
	}
}
