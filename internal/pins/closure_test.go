package pins

import (
	"context"
	"io"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/entitle"
	"github.com/ravinald/bodega/internal/manifest"
)

// A node is not spelled one way: an apt parent is written "apt/nginx" and a
// language one "pypi/django@5.2.12". A walk that matched an exact reference
// would see one spelling's edges and report the other's packages as
// unreachable, which reads as a pin that implies nothing.
func TestSplitRefReadsBothSpellingsAndAnNpmScope(t *testing.T) {
	cases := []struct{ ref, typ, name, version string }{
		{"apt/nginx", "apt", "nginx", ""},
		{"pypi/django@5.2.12", "pypi", "django", "5.2.12"},
		{"npm/@babel/core", "npm", "@babel/core", ""},
		{"npm/@babel/core@7.24.0", "npm", "@babel/core", "7.24.0"},
		{"gomod/github.com/lib/pq@v1.10.9", "gomod", "github.com/lib/pq", "v1.10.9"},
		{"nonsense", "", "", ""},
		{"apt/", "", "", ""},
	}
	for _, c := range cases {
		typ, name, version := SplitRef(c.ref)
		if typ != c.typ || name != c.name || version != c.version {
			t.Errorf("SplitRef(%q) = (%q, %q, %q), want (%q, %q, %q)",
				c.ref, typ, name, version, c.typ, c.name, c.version)
		}
	}
}

// The closure is what the pin holds still, which is what the pinned package
// depends on. A cycle must terminate, and a package that depends on the pinned
// one is not in it: pinning postgres does not hold pgbouncer.
func TestClosureWalksDownwardAndTerminatesOnACycle(t *testing.T) {
	edges := []manifest.DepEdge{
		{Parent: "apt/postgresql-14", Child: "apt/libpq5@14.9"},
		{Parent: "apt/libpq5", Child: "apt/libssl3@3.0.2"},
		{Parent: "apt/libssl3", Child: "apt/postgresql-14"}, // the cycle
		{Parent: "apt/pgbouncer", Child: "apt/postgresql-14"},
		{Parent: "apt/nginx", Child: "apt/libpcre3@2.0.0"},
	}
	c := Of(edges, manifest.TypeApt, "postgresql-14", "14.9")
	var got []string
	for _, m := range c.Members {
		got = append(got, m.Ref())
	}
	want := []string{"apt/libpq5", "apt/libssl3"}
	if len(got) != len(want) {
		t.Fatalf("closure = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("closure = %v, want %v", got, want)
		}
	}
	if c.Members[1].Depth != 2 || c.Members[1].Via != "apt/libpq5" {
		t.Errorf("the transitive member does not carry the path it was reached by: %+v", c.Members[1])
	}
}

// A member the graph records no version for is in the closure and has nothing
// to pin to. Reporting it as a conflict would refuse a pin on the strength of
// a field the discoverer never filled in; extending the pin to it would mean
// choosing a version on the operator's behalf.
func TestClosureConflictsSkipAMemberWithNoRecordedVersion(t *testing.T) {
	edges := []manifest.DepEdge{
		{Parent: "apt/postgresql-14", Child: "apt/libpq5@14.9"},
		{Parent: "apt/postgresql-14", Child: "apt/libc6"},
	}
	c := Of(edges, manifest.TypeApt, "postgresql-14", "14.9")
	if len(c.Members) != 2 {
		t.Fatalf("closure = %d members, want 2", len(c.Members))
	}
	if len(c.Resolved()) != 1 || c.Resolved()[0].Name != "libpq5" {
		t.Fatalf("Resolved() = %+v, want libpq5 alone", c.Resolved())
	}

	p := entitle.New(&audit.ProfileDetail{
		Profile: audit.Profile{Name: "db"},
		Types: []audit.ProfileTypeRule{{
			Profile: "db", Type: manifest.TypeApt,
			Membership: audit.MembershipOpen, VersionDefault: audit.VersionFloating,
		}},
		Entries: []audit.ProfileEntry{{
			Profile: "db", Type: manifest.TypeApt, Name: "libpq5",
			Constraint: manifest.ConstraintExact, Version: "15.1",
		}},
	})
	conflicts := c.Conflicts(p)
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %+v, want the one the profile contradicts", conflicts)
	}
	if conflicts[0].Member.Name != "libpq5" {
		t.Errorf("the conflict names %s, want libpq5", conflicts[0].Member.Name)
	}
	if c.Conflicts(nil) != nil {
		t.Error("an unprofiled host has conflicts, which is a refusal nobody wrote")
	}
}

// A catalog holds more than one release of a package, and each release records
// its own children. Merging them would report a pin on 4.2.11 as holding
// 5.2.12's dependencies: packages that pin never implied, at versions nothing
// chose. --strict-closure then writes those as real pins, so the wrong answer
// is a frozen host rather than a misprinted table.
func TestClosureExpandsThePinnedReleaseAlone(t *testing.T) {
	edges := []manifest.DepEdge{
		{Parent: "pypi/django@4.2.11", Child: "pypi/sqlparse@0.4.4", RawSpec: "sqlparse>=0.3.1"},
		{Parent: "pypi/django@5.2.12", Child: "pypi/sqlparse@0.5.3", RawSpec: "sqlparse>=0.3.1"},
		{Parent: "pypi/django@5.2.12", Child: "pypi/asgiref@3.8.1", RawSpec: "asgiref>=3.8.1"},
	}
	want := map[string]string{"pypi/sqlparse": "0.4.4"}

	check := func(t *testing.T, label string, in []manifest.DepEdge) {
		t.Helper()
		c := Of(in, manifest.TypePypi, "django", "4.2.11")
		if len(c.Members) != len(want) {
			t.Fatalf("%s: closure = %+v, want sqlparse 0.4.4 alone", label, c.Members)
		}
		for _, m := range c.Members {
			v, ok := want[m.Ref()]
			if !ok {
				t.Errorf("%s: closure claims %s, which 4.2.11 does not depend on", label, m.Ref())
				continue
			}
			if m.Version != v {
				t.Errorf("%s: %s held at %q, want %q", label, m.Ref(), m.Version, v)
			}
		}
	}
	check(t, "forward", edges)

	// The answer cannot depend on the order graph.json happens to list edges in.
	reversed := make([]manifest.DepEdge, len(edges))
	for i, e := range edges {
		reversed[len(edges)-1-i] = e
	}
	check(t, "reversed", reversed)
}

// A member is expanded at the version it is held at. The next hop of a pin on
// django 4.2.11 is sqlparse 0.4.4's own children, not every release of
// sqlparse's.
func TestClosureCarriesEachMemberVersionToTheNextHop(t *testing.T) {
	edges := []manifest.DepEdge{
		{Parent: "pypi/django@4.2.11", Child: "pypi/sqlparse@0.4.4"},
		{Parent: "pypi/sqlparse@0.4.4", Child: "pypi/tzdata@2024.1"},
		{Parent: "pypi/sqlparse@0.5.3", Child: "pypi/typing-extensions@4.12.2"},
	}
	c := Of(edges, manifest.TypePypi, "django", "4.2.11")
	var got []string
	for _, m := range c.Members {
		got = append(got, m.Ref())
	}
	if len(got) != 2 || got[0] != "pypi/sqlparse" || got[1] != "pypi/tzdata" {
		t.Fatalf("closure = %v, want sqlparse and tzdata", got)
	}
}

// The writer and the closure reader must agree on how a node is spelled. A
// test that seeds the reference it wishes the discoverer produced proves
// nothing about the graph an operator actually has, so run the import and walk
// what it wrote.
//
// It lives here rather than beside the discoverer because entitle imports
// builder, so a builder test cannot reach this package.
func TestAptImportWritesEdgesThisPackageCanResolve(t *testing.T) {
	ctx := context.Background()
	store := manifest.NewLocalStore(t.TempDir())
	if err := store.AddVersion(ctx, manifest.TypeApt, "libpq5",
		manifest.VersionEntry{Version: "14.9"}); err != nil {
		t.Fatalf("seed libpq5: %v", err)
	}

	// What DiscoverAptDeps builds from `Depends: libpq5 (= 14.9), libssl3 (>= 3.0.0)`.
	// libpq5 is already cataloged, which is the common case for a library
	// several packages depend on, and its edge is written all the same.
	deps := []builder.DiscoveredDep{
		{
			Ecosystem: manifest.TypeApt, Name: "libpq5", RequiredBy: "apt/postgresql-14",
			Version: "14.9", Constraint: manifest.ConstraintExact, RawSpec: "libpq5 (= 14.9)",
			Exists: true,
		},
		{
			Ecosystem: manifest.TypeApt, Name: "libssl3", RequiredBy: "apt/postgresql-14",
			RawSpec: "libssl3 (>= 3.0.0)",
		},
	}
	builder.ImportAptDeps(ctx, store, "postgresql-14", deps, io.Discard)

	c := Of(store.Edges(), manifest.TypeApt, "postgresql-14", "14.9")
	if len(c.Members) != 2 {
		t.Fatalf("closure = %+v, want both dependencies", c.Members)
	}
	resolved := c.Resolved()
	if len(resolved) != 1 || resolved[0].Name != "libpq5" || resolved[0].Version != "14.9" {
		t.Fatalf("Resolved() = %+v, want libpq5 at 14.9; --strict-closure has nothing to pin to otherwise", resolved)
	}
	if resolved[0].RawSpec != "libpq5 (= 14.9)" {
		t.Errorf("the closure shows %q rather than the relation apt declared", resolved[0].RawSpec)
	}
	for _, m := range c.Members {
		if m.Name == "libssl3" && m.Version != "" {
			t.Errorf("a >= floor was recorded as holding %q still, which apt never declared", m.Version)
		}
	}

	// Feasibility can find something on an apt graph now: a profile holding
	// libpq5 elsewhere contradicts the pin, which is what the index-generation
	// check reports.
	p := entitle.New(&audit.ProfileDetail{
		Profile: audit.Profile{Name: "db"},
		Types: []audit.ProfileTypeRule{{
			Profile: "db", Type: manifest.TypeApt,
			Membership: audit.MembershipOpen, VersionDefault: audit.VersionFloating,
		}},
		Entries: []audit.ProfileEntry{{
			Profile: "db", Type: manifest.TypeApt, Name: "libpq5",
			Constraint: manifest.ConstraintExact, Version: "15.1",
		}},
	})
	if got := c.Conflicts(p); len(got) != 1 || got[0].Member.Name != "libpq5" {
		t.Errorf("conflicts = %+v, want the libpq5 the profile refuses", got)
	}
}
