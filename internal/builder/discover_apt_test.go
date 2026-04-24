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

func TestParseAptShowOutput(t *testing.T) {
	output := `Package: python3
Version: 3.12.3-0ubuntu2.1
Architecture: amd64
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Installed-Size: 92
Pre-Depends: python3-minimal (= 3.12.3-0ubuntu2.1)
Depends: python3.12 (>= 3.12.3-1~), libpython3-stdlib (= 3.12.3-0ubuntu2.1)
Section: python
Priority: important
Description: interactive high-level object-oriented language (default version)
 Python, the high-level, interactive object oriented language,
 includes an extensive class library with lots of goodies.
 .
 This package is a dependency package.

`
	ve := parseAptShowOutput(output, "python3")
	if ve == nil {
		t.Fatal("expected non-nil VersionEntry")
	}
	if ve.Version != "3.12.3-0ubuntu2.1" {
		t.Errorf("Version = %q, want %q", ve.Version, "3.12.3-0ubuntu2.1")
	}
	if ve.Platform != "linux/amd64" {
		t.Errorf("Platform = %q, want %q", ve.Platform, "linux/amd64")
	}
	if ve.Description != "interactive high-level object-oriented language (default version)" {
		t.Errorf("Description = %q", ve.Description)
	}
	if ve.SourceName != "python3" {
		t.Errorf("SourceName = %q, want %q", ve.SourceName, "python3")
	}
	// Check metadata fields.
	if ve.Metadata["Maintainer"] == "" {
		t.Error("expected Maintainer in Metadata")
	}
	if ve.Metadata["Installed-Size"] != "92" {
		t.Errorf("Installed-Size = %q, want %q", ve.Metadata["Installed-Size"], "92")
	}
	if ve.Metadata["Section"] != "python" {
		t.Errorf("Section = %q, want %q", ve.Metadata["Section"], "python")
	}
	if ve.Metadata["Priority"] != "important" {
		t.Errorf("Priority = %q, want %q", ve.Metadata["Priority"], "important")
	}
	if ve.Metadata["Architecture"] != "amd64" {
		t.Errorf("Architecture in Metadata = %q, want %q", ve.Metadata["Architecture"], "amd64")
	}
	if _, ok := ve.Metadata["Description-Full"]; !ok {
		t.Error("expected Description-Full in Metadata for multi-line description")
	}
}

func TestParseAptShowOutput_Empty(t *testing.T) {
	ve := parseAptShowOutput("", "pkg")
	if ve != nil {
		t.Errorf("expected nil for empty input, got %+v", ve)
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
