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
	// apt's discoverer records the dependency by name alone, so a member with
	// no version is a package the pin reaches without bodega knowing which
	// release of it the pin requires.
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
// edges is the whole graph rather than a per-node lookup, because the two
// writers spell a node differently: the apt discoverer records "apt/nginx" and
// the language discoverers record "pypi/django@5.2.12". A walk keyed on an
// exact reference sees one writer's edges and reports the other's packages as
// unreachable, which reads as a pin that implies nothing.
//
// Members come back sorted by reference, so a report and a test read the same
// order whatever order the graph was written in. A cycle terminates: a node
// already placed is never expanded twice.
func Of(edges []manifest.DepEdge, typ, name, version string) Closure {
	c := Closure{Type: typ, Name: name, Version: version}

	byParent := map[string][]manifest.DepEdge{}
	for _, e := range edges {
		pt, pn, _ := SplitRef(e.Parent)
		if pn == "" {
			continue
		}
		byParent[pt+"/"+pn] = append(byParent[pt+"/"+pn], e)
	}

	root := typ + "/" + name
	seen := map[string]bool{root: true}
	frontier := []string{root}
	for depth := 1; len(frontier) > 0; depth++ {
		var next []string
		for _, parent := range frontier {
			for _, e := range byParent[parent] {
				ct, cn, cv := SplitRef(e.Child)
				if cn == "" || seen[ct+"/"+cn] {
					continue
				}
				seen[ct+"/"+cn] = true
				c.Members = append(c.Members, Member{
					Type: ct, Name: cn, Version: cv,
					Constraint: e.Constraint, RawSpec: e.RawSpec,
					Via: parent, Depth: depth,
				})
				next = append(next, ct+"/"+cn)
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
// reference carries no version on the apt discoverer's edges and carries one
// on every other writer's.
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
