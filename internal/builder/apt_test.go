package builder

import (
	"testing"
)

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
