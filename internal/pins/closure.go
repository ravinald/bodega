// Package pins is what bodega knows about a version pin: the decision an
// operator recorded, the advisories against the version they held, and the
// other packages that pin holds still.
//
// closure.go answers the third. A pin is never local: holding postgresql-14 at
// 14.9 holds everything 14.9 was built against, because a dependency edge
// names the version the parent needs and nothing about pinning the parent
// moves it. apt discovers that during an upgrade, as a growing set held back
// or a proposal to remove the package; bodega sits on the index and holds the
// graph, so it can say so before the operator commits.
//
// The walk runs downward, over the packages the pinned one depends on. Those
// are the ones that can no longer move past a version: the parent is the one
// holding them there. Walking upward would answer a different question —
// which packages are inconvenienced by the pin — and it is not the question an
// operator about to write one is asking.
package pins

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ravinald/bodega/internal/entitle"
	"github.com/ravinald/bodega/internal/manifest"
)

// Member is one package the pin reaches, and the edge it was reached by.
type Member struct {
	Type string
	Name string
	// Version is the version the edge names, empty when the edge names none.
	// A dependency declared without an equality relation has none: an apt
	// `>=` floor may move upward whatever the parent is pinned at, so the pin
	// reaches the package without holding any release of it still.
	Version string
	// Constraint and RawSpec are the edge's own, carried through so a report
	// can show the specifier an operator would recognize from the upstream
	// metadata rather than a version bodega derived.
	Constraint string
	RawSpec    string
	// Via is the closure member that depends on this one, as "type/name". It
	// is the pinned package itself at depth 1.
	Via   string
	Depth int
}

// Ref is the member as "type/name".
func (m Member) Ref() string { return m.Type + "/" + m.Name }

// Closure is one pin and every package it holds still.
type Closure struct {
	Type    string
	Name    string
	Version string
	Members []Member
}

// Ref is the pinned package as "type/name".
func (c Closure) Ref() string { return c.Type + "/" + c.Name }

// Conflict is one closure member the pin cannot be satisfied alongside: the
// pinned version needs a release of it that the profile refuses.
type Conflict struct {
	Member Member
	Reason string
}

// Of walks the dependency edges downward from one pinned package and returns
// every package it holds still.
//
// edges is the whole graph rather than a per-node lookup, because a node is
// not spelled one way: an apt parent is recorded as "apt/postgresql-14" and a
// language one as "pypi/django@5.2.12". A walk keyed on an exact reference
// sees one spelling's edges and reports the other's packages as unreachable,
// which reads as a pin that implies nothing.
//
// The version is part of the key, not noise to be stripped. A catalog holding
// two releases of one package records both releases' children under the same
// name, and a walk that merged them would report a pin on 4.2.11 as holding
// 5.2.12's dependencies — packages that pin never implied, at versions nothing
// chose. So a parent that records a version is matched on the version, and
// only a parent that records none applies to whatever release you pinned.
//
// Members come back sorted by reference, so a report and a test read the same
// order whatever order the graph was written in. A cycle terminates: a node
// already placed is never expanded twice.
func Of(edges []manifest.DepEdge, typ, name, version string) Closure {
	c := Closure{Type: typ, Name: name, Version: version}

	versioned := map[string][]manifest.DepEdge{}
	unversioned := map[string][]manifest.DepEdge{}
	for _, e := range edges {
		pt, pn, pv := SplitRef(e.Parent)
		if pn == "" {
			continue
		}
		if pv == "" {
			unversioned[pt+"/"+pn] = append(unversioned[pt+"/"+pn], e)
			continue
		}
		versioned[pt+"/"+pn+"@"+pv] = append(versioned[pt+"/"+pn+"@"+pv], e)
	}

	// A member carries its own version forward, so the next hop expands the
	// release that member is held at rather than every release of it.
	childrenOf := func(m Member) []manifest.DepEdge {
		if m.Version == "" {
			return unversioned[m.Ref()]
		}
		byVersion := versioned[m.Ref()+"@"+m.Version]
		if len(byVersion) == 0 {
			return unversioned[m.Ref()]
		}
		out := make([]manifest.DepEdge, 0, len(unversioned[m.Ref()])+len(byVersion))
		out = append(out, unversioned[m.Ref()]...)
		return append(out, byVersion...)
	}

	root := Member{Type: typ, Name: name, Version: version}
	seen := map[string]bool{root.Ref(): true}
	frontier := []Member{root}
	for depth := 1; len(frontier) > 0; depth++ {
		var next []Member
		for _, parent := range frontier {
			for _, e := range childrenOf(parent) {
				ct, cn, cv := SplitRef(e.Child)
				if cn == "" || seen[ct+"/"+cn] {
					continue
				}
				seen[ct+"/"+cn] = true
				m := Member{
					Type: ct, Name: cn, Version: cv,
					Constraint: e.Constraint, RawSpec: e.RawSpec,
					Via: parent.Ref(), Depth: depth,
				}
				c.Members = append(c.Members, m)
				next = append(next, m)
			}
		}
		frontier = next
	}
	sort.Slice(c.Members, func(i, j int) bool { return c.Members[i].Ref() < c.Members[j].Ref() })
	return c
}

// Conflicts reports the members whose required version the profile refuses.
//
// Only a member the graph records a version for can be answered: an edge that
// names a package and no release says nothing about which release the pin
// needs, and reporting it as a conflict would refuse a pin on the strength of
// a field the discoverer never filled in. Those members are still in the
// closure, and a report names them as unresolved rather than dropping them.
//
// A nil profile has no conflicts, which is the host nothing binds.
func (c Closure) Conflicts(p *entitle.Profile) []Conflict {
	if p == nil {
		return nil
	}
	var out []Conflict
	for _, m := range c.Members {
		if m.Version == "" {
			continue
		}
		d := p.Permits(m.Type, m.Name, m.Version)
		if d.Permitted || !d.Governed {
			continue
		}
		out = append(out, Conflict{
			Member: m,
			Reason: fmt.Sprintf("%s at %s needs %s, and the profile refuses it: %s",
				c.Ref(), c.Version, m.Ref()+" "+m.Version, d.Reason),
		})
	}
	return out
}

// Resolved returns the members the graph records a version for, which are the
// ones a strict extension has something to pin to.
func (c Closure) Resolved() []Member {
	var out []Member
	for _, m := range c.Members {
		if m.Version != "" {
			out = append(out, m)
		}
	}
	return out
}

// SplitRef parses a graph reference into its type, name and version. A
// reference carries a version wherever the writer knew one: every language
// discoverer, and apt where the dependency was declared with an equality
// relation. It carries none for an apt parent, or for a dependency declared as
// a floor.
//
// The version is split at the last '@' rather than the first, because an npm
// scope puts one inside the name: "npm/@babel/core@7.24.0" is one package at
// one version and splitting at the first '@' yields the scope as a version.
// An '@' that opens the name segment is the scope marker and never a version
// separator, which is what keeps "npm/@babel/core" from parsing as the package
// "npm/" at version "babel/core".
func SplitRef(ref string) (typ, name, version string) {
	slash := strings.Index(ref, "/")
	if slash <= 0 || slash == len(ref)-1 {
		return "", "", ""
	}
	typ, rest := ref[:slash], ref[slash+1:]
	if at := strings.LastIndex(rest, "@"); at > 0 {
		return typ, rest[:at], rest[at+1:]
	}
	return typ, rest, ""
}
