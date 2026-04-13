// Package manifest — graph.go manages the dependency graph stored in graph.json.
// The DependencyGraph tracks directed edges from parent packages to child packages,
// where both are identified by the canonical "type/name" string
// (e.g. "git/netbox" depends on "pypi/django").
package manifest

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const graphFile = "graph.json"

// loadGraph reads graph.json from the backend and deserialises it into g.
// Returns nil when the file does not exist (empty graph is valid).
func loadGraph(ctx context.Context, b Backend, g *DependencyGraph) error {
	data, err := b.Read(ctx, graphFile)
	if err != nil {
		return fmt.Errorf("read %s from %s: %w", graphFile, b.Label(), err)
	}
	if data == nil {
		// No graph file yet — start with an empty graph.
		return nil
	}
	if err := json.Unmarshal(data, g); err != nil {
		return fmt.Errorf("parse %s: %w", graphFile, err)
	}
	return nil
}

// saveGraph serialises g and writes it to the backend.
func saveGraph(ctx context.Context, b Backend, g *DependencyGraph) error {
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", graphFile, err)
	}
	data = append(data, '\n')
	if err := b.Write(ctx, graphFile, data); err != nil {
		return fmt.Errorf("write %s to %s: %w", graphFile, b.Label(), err)
	}
	return nil
}

// addEdge appends edge to g.Edges only when an identical edge does not already exist.
func addEdge(g *DependencyGraph, edge DepEdge) {
	for _, e := range g.Edges {
		if e.Parent == edge.Parent && e.Child == edge.Child {
			return // already present
		}
	}
	g.Edges = append(g.Edges, edge)
}

// removeEdge removes every edge whose Parent == parent and Child == child.
func removeEdge(g *DependencyGraph, parent, child string) {
	filtered := g.Edges[:0]
	for _, e := range g.Edges {
		if e.Parent != parent || e.Child != child {
			filtered = append(filtered, e)
		}
	}
	g.Edges = filtered
}

// parentsOf returns all edges in g where Child == child.
func parentsOf(g *DependencyGraph, child string) []DepEdge {
	var out []DepEdge
	for _, e := range g.Edges {
		if e.Child == child {
			out = append(out, e)
		}
	}
	return out
}

// childrenOf returns all edges in g where Parent == parent.
func childrenOf(g *DependencyGraph, parent string) []DepEdge {
	var out []DepEdge
	for _, e := range g.Edges {
		if e.Parent == parent {
			out = append(out, e)
		}
	}
	return out
}

// orphans returns the set of packages (as "type/name" strings) that appear in
// graph edges but don't exist in the store. These are broken references --
// a dependency was recorded but the package was deleted or never created.
func orphans(g *DependencyGraph) []string {
	// Collect all unique node references from edges.
	nodes := make(map[string]bool)
	for _, e := range g.Edges {
		// Edge parents/children use "type/name" or "type/name@version" format.
		// Extract the "type/name" portion for store lookup.
		nodes[edgeBaseName(e.Parent)] = true
		nodes[edgeBaseName(e.Child)] = true
	}
	// The caller (Store.Orphans) filters against the store.
	var out []string
	for node := range nodes {
		out = append(out, node)
	}
	sort.Strings(out)
	return out
}

// edgeBaseName extracts "type/name" from edge references like "type/name@version".
func edgeBaseName(ref string) string {
	if idx := strings.Index(ref, "@"); idx >= 0 {
		return ref[:idx]
	}
	return ref
}
