package builder

import (
	"testing"
)

func TestParseAptCacheDepends_Direct(t *testing.T) {
	output := `curl
  Depends: libc6
  Depends: libcurl4t64
  Depends: zlib1g
  PreDepends: dpkg
  Suggests: libcurl4-doc
  Recommends: ca-certificates
`
	names := parseAptCacheDepends(output, "curl")
	expected := []string{"dpkg", "libc6", "libcurl4t64", "zlib1g"}

	if len(names) != len(expected) {
		t.Fatalf("expected %d deps, got %d: %v", len(expected), len(names), names)
	}
	for i, name := range names {
		if name != expected[i] {
			t.Errorf("dep[%d]: expected %q, got %q", i, expected[i], name)
		}
	}
}

func TestParseAptCacheDepends_Recursive(t *testing.T) {
	output := `curl
  Depends: libc6
  Depends: libcurl4t64
libc6
  Depends: libgcc-s1
  PreDepends: <libc-any>
libcurl4t64
  Depends: libc6
  Depends: libssl3t64
libgcc-s1
  Depends: gcc-14-base
`
	names := parseAptCacheDepends(output, "curl")
	expected := []string{"gcc-14-base", "libc6", "libcurl4t64", "libgcc-s1", "libssl3t64"}

	if len(names) != len(expected) {
		t.Fatalf("expected %d deps, got %d: %v", len(expected), len(names), names)
	}
	for i, name := range names {
		if name != expected[i] {
			t.Errorf("dep[%d]: expected %q, got %q", i, expected[i], name)
		}
	}
}

func TestParseAptCacheDepends_VirtualPackages(t *testing.T) {
	output := `myapp
  Depends: <libc-dev>
  Depends: libfoo
  PreDepends: <awk>
  Depends: libbar
`
	names := parseAptCacheDepends(output, "myapp")
	expected := []string{"libbar", "libfoo"}

	if len(names) != len(expected) {
		t.Fatalf("expected %d deps, got %d: %v", len(expected), len(names), names)
	}
	for i, name := range names {
		if name != expected[i] {
			t.Errorf("dep[%d]: expected %q, got %q", i, expected[i], name)
		}
	}
}

func TestParseAptCacheDepends_Empty(t *testing.T) {
	names := parseAptCacheDepends("", "pkg")
	if len(names) != 0 {
		t.Errorf("expected empty, got %v", names)
	}
}

func TestParseAptCacheDepends_NoDeps(t *testing.T) {
	output := `base-files
`
	names := parseAptCacheDepends(output, "base-files")
	if len(names) != 0 {
		t.Errorf("expected empty, got %v", names)
	}
}

func TestParseAptCacheDepends_Deduplication(t *testing.T) {
	// libc6 appears both as a header (recursive) and as a Depends line.
	output := `curl
  Depends: libc6
  Depends: libssl3
libc6
  Depends: libgcc-s1
libssl3
  Depends: libc6
`
	names := parseAptCacheDepends(output, "curl")
	// libc6 should appear only once despite being referenced multiple times.
	count := 0
	for _, n := range names {
		if n == "libc6" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected libc6 exactly once, got %d in %v", count, names)
	}
}

func TestIsVirtualPkg(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"<libc-dev>", true},
		{"<awk>", true},
		{"libc6", false},
		{"", false},
		{"<>", true},
		{"<partial", false},
		{"partial>", false},
	}
	for _, tt := range tests {
		if got := isVirtualPkg(tt.name); got != tt.want {
			t.Errorf("isVirtualPkg(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}
