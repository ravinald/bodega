package main

import (
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ravinald/bodega/internal/manifest"
)

// capture runs f with stdout redirected and returns what it printed.
func capture(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		done <- b.String()
	}()
	f()
	_ = w.Close()
	os.Stdout = orig
	return <-done
}

// The whole dashboard is one rectangle. Any line that is not the same width as
// the others is a border that does not line up, which is what a reader sees
// before they see anything else on the screen.
func TestDashboardRendersOneRectangle(t *testing.T) {
	m := globalMetrics{
		DepEdges: 3,
		Orphans:  1,
		Types: []typeMetrics{
			{Type: manifest.TypeBinary, Packages: 2, Versions: 2, Present: 1, StorageB: 1432},
			{Type: manifest.TypeGit, Packages: 1, Versions: 1, Present: 1, StorageB: 178500},
			{Type: manifest.TypeCargo, Packages: 1, Versions: 1, Present: 1, StorageB: 10547},
		},
		Backends: []backendMetrics{
			{Name: "default", Present: 8, Missing: 1, StorageB: 266854},
		},
		Fetches24h: 284,
		Creates24h: 127,
	}

	out := capture(t, func() { printGlobalDashboard(m) })
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < 10 {
		t.Fatalf("dashboard rendered %d lines, want the full box", len(lines))
	}

	want := utf8.RuneCountInString(lines[0])
	for i, l := range lines {
		if got := utf8.RuneCountInString(l); got != want {
			t.Errorf("line %d is %d columns, want %d\n%s", i, got, want, l)
		}
	}
}

// The inner tables sit inside the outer box with their own borders. A row
// wider than its box is what the byte-length measurement produced, and it
// reads as the inner box having no right edge.
func TestDashboardInnerBoxesFitTheOuterOne(t *testing.T) {
	m := globalMetrics{
		Types:    []typeMetrics{{Type: manifest.TypeNpm, Packages: 1, Versions: 1, Present: 1, StorageB: 3584}},
		Backends: []backendMetrics{{Name: "default", Present: 1, StorageB: 3584}},
	}
	out := capture(t, func() { printGlobalDashboard(m) })

	for _, l := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if !strings.ContainsAny(l, "┌└│") {
			continue
		}
		if strings.Contains(l, "┐│") || strings.Contains(l, "┘│") {
			t.Errorf("an inner border touches the outer one with no padding:\n%s", l)
		}
	}
}

func TestBoxHelpersRenderTheWidthTheyAreGiven(t *testing.T) {
	for _, w := range []int{20, 46, 52, 80} {
		cases := map[string]string{
			"boxTop":      boxTop("bodega status", w),
			"boxBottom":   boxBottom(w),
			"boxEmpty":    boxEmpty(w),
			"boxRow":      boxRow(w, "  Packages 9"),
			"innerTop":    innerTop("By Type", w),
			"innerBottom": innerBottom(w),
		}
		for name, got := range cases {
			if n := utf8.RuneCountInString(got); n != w+2 {
				t.Errorf("%s(%d) rendered %d columns, want %d: %q", name, w, n, w+2, got)
			}
		}
	}
}

// boxRow's padding is the one that took content carrying box-drawing runes,
// which is where len() and column count disagree by two per rune.
func TestBoxRowPadsContentCarryingBoxRunes(t *testing.T) {
	content := "  " + innerTop("By Type", 41)
	got := boxRow(52, content)
	if n := utf8.RuneCountInString(got); n != 54 {
		t.Errorf("boxRow padded a row of box runes to %d columns, want 54: %q", n, got)
	}
}
