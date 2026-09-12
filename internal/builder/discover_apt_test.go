package builder

import (
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
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

// TestDropVersionlessAptEntries covers what a resolve leaves behind. Filling
// consumes one placeholder, and a resolve that finds its version already
// present fills none, so the sweep has to take every version-less entry rather
// than the first.
func TestDropVersionlessAptEntries(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	ctx := t.Context()
	for _, ve := range []manifest.VersionEntry{
		{SourceName: "hello"},
		{SourceName: "hello"},
		{Version: "1.0.0", SourceName: "hello"},
	} {
		if err := store.AddVersion(ctx, manifest.TypeApt, "hello", ve); err != nil {
			t.Fatalf("AddVersion: %v", err)
		}
	}

	n, err := DropVersionlessAptEntries(ctx, store, "hello")
	if err != nil {
		t.Fatalf("DropVersionlessAptEntries: %v", err)
	}
	if n != 2 {
		t.Errorf("dropped %d, want 2", n)
	}
	pm, err := store.GetPackage(ctx, manifest.TypeApt, "hello")
	if err != nil || pm == nil {
		t.Fatalf("GetPackage: %v", err)
	}
	if len(pm.Versions) != 1 || pm.Versions[0].Version != "1.0.0" {
		t.Errorf("versions = %+v, want only 1.0.0", pm.Versions)
	}
}

// TestDropVersionlessAptEntriesKeepsAStagedPackage pins the exception: a
// package with nothing resolved is a record its operator can still complete,
// and emptying it would discard their work with nothing to replace it.
func TestDropVersionlessAptEntriesKeepsAStagedPackage(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	ctx := t.Context()
	if err := store.AddVersion(ctx, manifest.TypeApt, "staged", manifest.VersionEntry{SourceName: "staged"}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	n, err := DropVersionlessAptEntries(ctx, store, "staged")
	if err != nil {
		t.Fatalf("DropVersionlessAptEntries: %v", err)
	}
	if n != 0 {
		t.Errorf("dropped %d entries from a package with nothing resolved, want 0", n)
	}
	pm, _ := store.GetPackage(ctx, manifest.TypeApt, "staged")
	if pm == nil || len(pm.Versions) != 1 {
		t.Error("the staged entry did not survive")
	}
}

// TestParseAptShowSourcePackage covers the three shapes a Source: field takes
// in a real jammy index. The OSV gate queries this name against an ecosystem
// keyed on source packages, so a version left on it turns every lookup for
// that package into a miss the gate reads as clean.
func TestParseAptShowSourcePackage(t *testing.T) {
	for _, tc := range []struct {
		name   string
		pkg    string
		stanza string
		want   string
	}{
		{
			// apt show libexpat1, ubuntu:22.04 container.
			name: "source differs from binary",
			pkg:  "libexpat1",
			stanza: `Package: libexpat1
Version: 2.4.7-1ubuntu0.7
Priority: important
Section: libs
Source: expat
Origin: Ubuntu
`,
			want: "expat",
		},
		{
			// apt show bash on the same container prints no Source: at all.
			// Debian policy omits it exactly when the two names are equal, so
			// its absence is an answer rather than a gap.
			name: "no Source line",
			pkg:  "bash",
			stanza: `Package: bash
Version: 5.1-6ubuntu1.1
Priority: required
Section: shells
`,
			want: "bash",
		},
		{
			// The jammy Packages indices carry 1500-odd of these: dpkg writes
			// the source version in parens when the binary does not share it.
			name: "source carries its own version",
			pkg:  "binutils-arm-none-eabi",
			stanza: `Package: binutils-arm-none-eabi
Version: 2.38-3ubuntu1+15build1
Section: devel
Source: binutils-arm-none-eabi (15build1)
`,
			want: "binutils-arm-none-eabi",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ve := parseAptShowOutput(tc.stanza, tc.pkg)
			if ve == nil {
				t.Fatal("stanza did not parse")
			}
			if ve.SourcePackage != tc.want {
				t.Errorf("SourcePackage = %q, want %q", ve.SourcePackage, tc.want)
			}
			if ve.SourceName != tc.pkg {
				t.Errorf("SourceName = %q, want %q: 'apt-get download' wants the binary name",
					ve.SourceName, tc.pkg)
			}
		})
	}
}

// `apt-cache depends` prints package names and drops every version relation,
// and "which release" is the whole of what a pin needs. The relation lives in
// the control stanza.
func TestParseAptRelationStanzasReadsTheDeclaredVersions(t *testing.T) {
	output := `Package: postgresql-14
Version: 14.9-0ubuntu0.22.04.1
Architecture: amd64
Pre-Depends: postgresql-common (>= 142), debconf (>= 0.5)
Depends: libpq5 (= 14.9), libssl3 (>= 3.0.0), libc6 | libc6-udeb, locales, python3:any (>= 3.12)
Description: object-relational SQL database

Package: postgresql-14
Version: 14.8-0ubuntu0.22.04.1
Depends: libpq5 (= 14.8)
`
	rels := parseAptRelationStanzas(output)

	// The candidate stanza alone. Merging the two would declare libpq5 at both
	// 14.9 and 14.8, and the pin would hold whichever was read last.
	if got := rels["libpq5"]; got.Operator != "=" || got.Version != "14.9" || got.Raw != "libpq5 (= 14.9)" {
		t.Errorf("libpq5 relation = %+v, want an exact 14.9 from the first stanza", got)
	}
	// A floor holds nothing still: the dependency may move upward whatever the
	// parent is pinned at.
	if got := rels["libssl3"]; got.Operator != ">=" || got.Version != "3.0.0" {
		t.Errorf("libssl3 relation = %+v, want the >= floor recorded as a floor", got)
	}
	if got, ok := rels["locales"]; !ok || got.Operator != "" || got.Version != "" {
		t.Errorf("locales relation = %+v (present=%v), want a dependency by name alone", got, ok)
	}
	// An alternative is another package the parent may be built against.
	if _, ok := rels["libc6-udeb"]; !ok {
		t.Error("an alternative dependency is dropped, so an edge to the one bodega cataloged is never written")
	}
	// The architecture qualifier names which build satisfies the dependency,
	// not which release.
	if got := rels["python3"]; got.Operator != ">=" || got.Version != "3.12" {
		t.Errorf("python3:any relation = %+v, want the qualifier stripped from the name", got)
	}
	// Pre-Depends is a hard dependency and belongs in the closure.
	if got := rels["postgresql-common"]; got.Operator != ">=" || got.Version != "142" {
		t.Errorf("Pre-Depends relation = %+v, want it read alongside Depends", got)
	}
	if len(rels) != 8 {
		t.Errorf("relations = %d, want 8: %+v", len(rels), rels)
	}
}

func TestParseAptRelationStanzasOnNothingToRead(t *testing.T) {
	for _, in := range []string{"", "Package: base-files\nVersion: 12ubuntu4\n", "not a stanza"} {
		if rels := parseAptRelationStanzas(in); rels != nil {
			t.Errorf("parseAptRelationStanzas(%q) = %+v, want nil", in, rels)
		}
	}
}

// A rebuild after the declared version moved must not leave both releases in
// the graph: the closure walk would answer with whichever edge the file listed
// first, which is an answer that depends on write order rather than on apt.
func TestAddAptEdgeReplacesThisParentsEarlierEdgeToTheSamePackage(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	store.AddEdge(manifest.DepEdge{Parent: "apt/postgresql-14", Child: "apt/libpq5@14.9"})
	store.AddEdge(manifest.DepEdge{Parent: "apt/pgbouncer", Child: "apt/libpq5@14.9"})

	addAptEdge(store, "postgresql-14", DiscoveredDep{
		Name: "libpq5", Version: "15.1", Constraint: manifest.ConstraintExact, RawSpec: "libpq5 (= 15.1)",
	})

	var children []string
	for _, e := range store.Edges() {
		if e.Parent == "apt/postgresql-14" {
			children = append(children, e.Child)
		}
	}
	if len(children) != 1 || children[0] != "apt/libpq5@15.1" {
		t.Errorf("postgresql-14 children = %v, want apt/libpq5@15.1 alone", children)
	}
	// Another parent's edge to the same package is somebody else's fact.
	for _, e := range store.Edges() {
		if e.Parent == "apt/pgbouncer" && e.Child == "apt/libpq5@14.9" {
			return
		}
	}
	t.Error("pgbouncer's own edge was removed, which no rebuild of postgresql-14 decides")
}
