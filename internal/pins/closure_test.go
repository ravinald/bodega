package pins

import (
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/entitle"
	"github.com/ravinald/bodega/internal/manifest"
)

// The two discoverers spell a node differently: apt writes "apt/nginx" and the
// language ones write "pypi/django@5.2.12". A walk that matched an exact
// reference would see one writer's edges and report the other's packages as
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
