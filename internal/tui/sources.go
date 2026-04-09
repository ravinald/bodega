package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/scaleapi/bodega/internal/manifest"
	"github.com/scaleapi/bodega/internal/s3"
)

// TreeNode represents one row in the Sources pane tree.
type TreeNode struct {
	// Label is the display text (type header or "name@version").
	Label string
	// EntryType is "apt", "git", "pypi", or "binary". Empty for no specific entry.
	EntryType string
	// Name is the entry name; empty for type-group nodes.
	Name string
	// IsGroup is true for type-level headers.
	IsGroup bool
	// Expanded controls whether child nodes are shown (group nodes only).
	Expanded bool
	// InS3 indicates whether the primary artifact is present in S3.
	InS3 bool
	// Hidden mirrors the manifest entry's Hidden flag.
	Hidden bool
	// Frozen mirrors the manifest entry's Frozen flag.
	Frozen bool
	// Marked is true when the user has selected this entry for a batch operation.
	Marked bool
	// BaseApp is true for pypi nodes that represent a base_requirements entry
	// (i.e. a git repo whose requirements.txt drives the wheel build).
	BaseApp bool
	// Children holds the entry nodes that belong to this group.
	Children []TreeNode
}

// sourcesModel is the bubbletea model for the top-left Sources pane.
type sourcesModel struct {
	// flatList is the flattened, visible set of rows for keyboard navigation.
	flatList     []flatRow
	cursor       int
	scrollOffset int // first visible row index
	width        int
	height       int
	focused      bool
	// filter is the active search string.
	filter string
	// savedExpanded stores the expand/collapse state of all groups before filtering.
	// Restored when the filter is cleared.
	savedExpanded map[string]bool
}

// flatRow pairs a display string with the underlying node it represents.
type flatRow struct {
	display string // rendered line (unstyled)
	node    *TreeNode
	depth   int // 0 = type group, 1 = entry
}

// BuildTree constructs the root-level tree nodes from the manifest store and
// S3 statuses. Entries with the same name are grouped under an intermediate
// package node so the tree has three levels: type > package > version.
func BuildTree(store *manifest.Store, statuses []s3.EntryStatus) []TreeNode {
	s3map := make(map[string]bool, len(statuses))
	for _, st := range statuses {
		s3map[st.Type+"/"+st.Name] = st.InS3
	}

	var roots []TreeNode

	// Helper: group entries by name, producing intermediate package nodes
	// when there are multiple versions, or a direct entry when there's only one.
	type entryInfo struct {
		label     string // version label (ref, version, or full name)
		name      string // entry name for lookups
		versioned string // VersionedName for s3map
		platform  string // "linux/amd64", "any", or ""
		frozen    bool
	}

	platformSuffix := func(platform string) string {
		if platform == "" || platform == "any" {
			return ""
		}
		return " (" + platform + ")"
	}

	buildGroup := func(typeName string, entries []entryInfo) TreeNode {
		group := TreeNode{
			Label:     typeName + "/",
			EntryType: typeName,
			IsGroup:   true,
			Expanded:  false,
		}

		// Group entries by name.
		nameOrder := []string{}
		byName := make(map[string][]entryInfo)
		for _, e := range entries {
			if _, exists := byName[e.name]; !exists {
				nameOrder = append(nameOrder, e.name)
			}
			byName[e.name] = append(byName[e.name], e)
		}

		for _, name := range nameOrder {
			versions := byName[name]
			pkgNode := TreeNode{
				Label:     name,
				EntryType: typeName,
				IsGroup:   true,
				Expanded:  false,
			}
			for _, v := range versions {
				pkgNode.Children = append(pkgNode.Children, TreeNode{
					Label:     v.label + platformSuffix(v.platform),
					EntryType: typeName,
					Name:      v.name,
					InS3:      s3map[typeName+"/"+v.versioned],
					Frozen:    v.frozen,
				})
			}
			group.Children = append(group.Children, pkgNode)
		}
		return group
	}

	// apt
	var aptEntries []entryInfo
	for _, e := range store.Apt {
		aptEntries = append(aptEntries, entryInfo{
			label: e.Version, name: e.Name, versioned: e.VersionedName(), platform: e.Platform, frozen: e.Frozen,
		})
	}
	roots = append(roots, buildGroup(manifest.TypeApt, aptEntries))

	// git
	var gitEntries []entryInfo
	for _, e := range store.Git {
		gitEntries = append(gitEntries, entryInfo{
			label: e.Ref, name: e.Name, versioned: e.VersionedName(), platform: e.Platform, frozen: e.Frozen,
		})
	}
	roots = append(roots, buildGroup(manifest.TypeGit, gitEntries))

	// pypi
	pypiGroup := TreeNode{
		Label:     "pypi/",
		EntryType: manifest.TypePypi,
		IsGroup:   true,
		Expanded:  false,
	}
	var pypiEntries []entryInfo
	for _, pkg := range store.Pypi.Packages {
		ver := pkg.Version
		if ver == "" {
			ver = pkg.Name
		}
		pypiEntries = append(pypiEntries, entryInfo{
			label: ver, name: pkg.Name, versioned: pkg.Name, frozen: pkg.Frozen || store.Pypi.Frozen,
		})
	}
	// Pypi: group by base package name (strip version specifiers for grouping).
	nameOrder := []string{}
	byName := make(map[string][]entryInfo)
	for _, e := range pypiEntries {
		baseName := pkgBaseNameForGrouping(e.name)
		if _, exists := byName[baseName]; !exists {
			nameOrder = append(nameOrder, baseName)
		}
		byName[baseName] = append(byName[baseName], e)
	}
	for _, baseName := range nameOrder {
		versions := byName[baseName]
		pkgNode := TreeNode{
			Label:     baseName,
			EntryType: manifest.TypePypi,
			IsGroup:   true,
			Expanded:  false,
		}
		for _, v := range versions {
			pkgNode.Children = append(pkgNode.Children, TreeNode{
				Label:     v.label,
				EntryType: manifest.TypePypi,
				Name:      v.name,
				InS3:      s3map[manifest.TypePypi+"/wheels"],
				Frozen:    v.frozen,
				})
			}
		pypiGroup.Children = append(pypiGroup.Children, pkgNode)
	}
	roots = append(roots, pypiGroup)

	// binary
	var binEntries []entryInfo
	for _, e := range store.Binary {
		binEntries = append(binEntries, entryInfo{
			label: e.Version, name: e.Name, versioned: e.VersionedName(), platform: e.Platform, frozen: e.Frozen,
		})
	}
	roots = append(roots, buildGroup(manifest.TypeBinary, binEntries))

	// gomod
	var gomodEntries []entryInfo
	for _, e := range store.Gomod {
		gomodEntries = append(gomodEntries, entryInfo{
			label: e.Version, name: e.Name, versioned: e.VersionedName(), platform: e.Platform, frozen: e.Frozen,
		})
	}
	roots = append(roots, buildGroup(manifest.TypeGomod, gomodEntries))

	// helm
	var helmEntries []entryInfo
	for _, e := range store.Helm {
		helmEntries = append(helmEntries, entryInfo{
			label: e.Version, name: e.Name, versioned: e.VersionedName(), platform: e.Platform, frozen: e.Frozen,
		})
	}
	roots = append(roots, buildGroup(manifest.TypeHelm, helmEntries))

	// npm
	var npmEntries []entryInfo
	for _, e := range store.Npm {
		npmEntries = append(npmEntries, entryInfo{
			label: e.Version, name: e.Name, versioned: e.VersionedName(), platform: e.Platform, frozen: e.Frozen,
		})
	}
	roots = append(roots, buildGroup(manifest.TypeNpm, npmEntries))

	return roots
}

// pkgBaseNameForGrouping strips version specifiers from a pip package name
// for grouping purposes (e.g. "boto3==1.26.0" -> "boto3").
func pkgBaseNameForGrouping(name string) string {
	for i, r := range name {
		if r == '>' || r == '<' || r == '=' || r == '!' || r == '~' {
			return strings.TrimSpace(name[:i])
		}
	}
	// Strip extras like [security] for grouping.
	if idx := strings.IndexByte(name, '['); idx >= 0 {
		return name[:idx]
	}
	return name
}

// newSourcesModel creates the sources pane from a set of root tree nodes.
func newSourcesModel(roots []TreeNode) sourcesModel {
	m := sourcesModel{}
	m.flatList = flatten(roots, m.filter)
	return m
}

// Refresh rebuilds the tree from a fresh store and status list.
func (m *sourcesModel) Refresh(store *manifest.Store, statuses []s3.EntryStatus) {
	roots := BuildTree(store, statuses)
	m.flatList = flatten(roots, m.filter)
	if m.cursor >= len(m.flatList) && len(m.flatList) > 0 {
		m.cursor = len(m.flatList) - 1
	}
	m.ensureCursorVisible()
}

// Selected returns the tree node at the current cursor, or nil.
func (m *sourcesModel) Selected() *TreeNode {
	if m.cursor < 0 || m.cursor >= len(m.flatList) {
		return nil
	}
	return m.flatList[m.cursor].node
}

// CursorUp moves the cursor up one row.
func (m *sourcesModel) CursorUp() {
	if m.cursor > 0 {
		m.cursor--
		m.ensureCursorVisible()
	}
}

// CursorDown moves the cursor down one row.
func (m *sourcesModel) CursorDown() {
	if m.cursor < len(m.flatList)-1 {
		m.cursor++
		m.ensureCursorVisible()
	}
}

// ensureCursorVisible adjusts scrollOffset so the cursor is within the visible window.
func (m *sourcesModel) ensureCursorVisible() {
	visibleRows := m.height
	if visibleRows <= 0 {
		return
	}
	if m.cursor < m.scrollOffset {
		m.scrollOffset = m.cursor
	}
	if m.cursor >= m.scrollOffset+visibleRows {
		m.scrollOffset = m.cursor - visibleRows + 1
	}
}

// CursorToParent moves the cursor to the parent group of the current node.
// If on an expanded group, collapses it instead.
func (m *sourcesModel) CursorToParent() {
	if m.cursor < 0 || m.cursor >= len(m.flatList) {
		return
	}
	row := m.flatList[m.cursor]

	// If on an expanded group, collapse it.
	if row.node.IsGroup && row.node.Expanded {
		m.ToggleExpand()
		return
	}

	// Walk backwards to find the nearest group at a lower depth.
	targetDepth := row.depth - 1
	if targetDepth < 0 {
		return
	}
	for i := m.cursor - 1; i >= 0; i-- {
		if m.flatList[i].depth == targetDepth && m.flatList[i].node.IsGroup {
			m.cursor = i
			m.ensureCursorVisible()
			return
		}
	}
}

// CursorToFirstChild expands the current group and moves to its first child.
// If already expanded, just moves to the first child. No-op on leaf nodes.
func (m *sourcesModel) CursorToFirstChild() {
	if m.cursor < 0 || m.cursor >= len(m.flatList) {
		return
	}
	row := m.flatList[m.cursor]
	if !row.node.IsGroup {
		return
	}

	if !row.node.Expanded {
		m.ToggleExpand()
	}

	// After expansion, the first child is at cursor+1.
	if m.cursor+1 < len(m.flatList) && m.flatList[m.cursor+1].depth > row.depth {
		m.cursor++
		m.ensureCursorVisible()
	}
}

// CursorToEntry finds an entry by type and name, expands parent groups as
// needed, and moves the cursor to it. Returns true if found.
func (m *sourcesModel) CursorToEntry(entryType, name string) bool {
	// First, expand the relevant groups so the entry is visible.
	roots := m.roots()
	for i := range roots {
		if roots[i].EntryType == entryType {
			roots[i].Expanded = true
			for j := range roots[i].Children {
				if roots[i].Children[j].IsGroup {
					// Check if any child matches the name.
					for _, leaf := range roots[i].Children[j].Children {
						if leaf.Name == name {
							roots[i].Children[j].Expanded = true
							break
						}
					}
				}
			}
		}
	}
	m.flatList = flatten(roots, m.filter)

	// Now find the entry in the flat list.
	for i, row := range m.flatList {
		if !row.node.IsGroup && row.node.EntryType == entryType && row.node.Name == name {
			m.cursor = i
			m.ensureCursorVisible()
			return true
		}
	}
	return false
}

// ToggleExpand expands or collapses the selected group node.
func (m *sourcesModel) ToggleExpand() {
	row := m.flatList[m.cursor]
	if !row.node.IsGroup {
		return
	}
	row.node.Expanded = !row.node.Expanded
	// Rebuild the flat list preserving cursor on the toggled group.
	// Collect all roots from depth-0 rows.
	roots := m.roots()
	m.flatList = flatten(roots, m.filter)
	// Keep cursor in bounds.
	if m.cursor >= len(m.flatList) && len(m.flatList) > 0 {
		m.cursor = len(m.flatList) - 1
	}
}

// ToggleMark toggles the Marked flag on the current entry.
// If the cursor is on a group node, all descendants are toggled recursively.
func (m *sourcesModel) ToggleMark() {
	if m.cursor < 0 || m.cursor >= len(m.flatList) {
		return
	}
	node := m.flatList[m.cursor].node
	if node.IsGroup {
		// Count all leaf descendants to determine toggle direction.
		marked, total := countMarkedLeaves(node)
		newState := marked < total // if not all marked, mark all; otherwise unmark all
		setMarkedRecursive(node, newState)
	} else {
		node.Marked = !node.Marked
	}
}

// countMarkedLeaves counts marked and total leaf nodes under a group, recursively.
func countMarkedLeaves(node *TreeNode) (marked, total int) {
	for i := range node.Children {
		c := &node.Children[i]
		if c.IsGroup {
			m, t := countMarkedLeaves(c)
			marked += m
			total += t
		} else {
			total++
			if c.Marked {
				marked++
			}
		}
	}
	return
}

// setMarkedRecursive sets the Marked flag on all leaf descendants.
func setMarkedRecursive(node *TreeNode, state bool) {
	for i := range node.Children {
		c := &node.Children[i]
		if c.IsGroup {
			setMarkedRecursive(c, state)
		} else {
			c.Marked = state
		}
	}
}

// SelectAll marks all non-group entries. If all are already marked, unmarks all.
func (m *sourcesModel) SelectAll() {
	marked := 0
	total := 0
	for i := range m.flatList {
		if !m.flatList[i].node.IsGroup {
			total++
			if m.flatList[i].node.Marked {
				marked++
			}
		}
	}
	newState := marked < total
	roots := m.roots()
	for i := range roots {
		setMarkedRecursive(&roots[i], newState)
	}
}

// MarkedEntries returns all marked non-group nodes. If none are marked,
// returns the currently selected entry (if it's not a group).
func (m *sourcesModel) MarkedEntries() []*TreeNode {
	var marked []*TreeNode
	for i := range m.flatList {
		if !m.flatList[i].node.IsGroup && m.flatList[i].node.Marked {
			marked = append(marked, m.flatList[i].node)
		}
	}
	if len(marked) == 0 {
		sel := m.Selected()
		if sel != nil && !sel.IsGroup {
			marked = append(marked, sel)
		}
	}
	return marked
}

// ClearMarks unmarks all entries.
func (m *sourcesModel) ClearMarks() {
	for i := range m.flatList {
		m.flatList[i].node.Marked = false
	}
}

// SetFilter applies a substring filter and rebuilds the flat list.
// When a filter is first applied, the expand/collapse state is saved and all
// groups are expanded so matches are visible. When the filter is cleared, the
// previous state is restored.
func (m *sourcesModel) SetFilter(f string) {
	wasFiltering := m.filter != ""
	m.filter = f
	roots := m.roots()

	if f != "" && !wasFiltering {
		// Entering filter mode: save current expand state and expand everything.
		m.savedExpanded = snapshotExpanded(roots)
		setAllExpanded(roots, true)
	} else if f == "" && wasFiltering && m.savedExpanded != nil {
		// Leaving filter mode: restore saved expand state.
		restoreExpanded(roots, m.savedExpanded)
		m.savedExpanded = nil
	} else if f != "" {
		// Still filtering: keep everything expanded.
		setAllExpanded(roots, true)
	}

	m.flatList = flatten(roots, f)
	m.cursor = 0
	m.scrollOffset = 0
}

// snapshotExpanded captures the Expanded state of all group nodes.
func snapshotExpanded(nodes []TreeNode) map[string]bool {
	state := make(map[string]bool)
	var walk func([]TreeNode, string)
	walk = func(nodes []TreeNode, prefix string) {
		for i := range nodes {
			n := &nodes[i]
			if n.IsGroup {
				key := prefix + n.EntryType + "/" + n.Label
				state[key] = n.Expanded
				walk(n.Children, key+"/")
			}
		}
	}
	walk(nodes, "")
	return state
}

// restoreExpanded restores the Expanded state of all group nodes from a snapshot.
func restoreExpanded(nodes []TreeNode, state map[string]bool) {
	var walk func([]TreeNode, string)
	walk = func(nodes []TreeNode, prefix string) {
		for i := range nodes {
			n := &nodes[i]
			if n.IsGroup {
				key := prefix + n.EntryType + "/" + n.Label
				if expanded, ok := state[key]; ok {
					n.Expanded = expanded
				}
				walk(n.Children, key+"/")
			}
		}
	}
	walk(nodes, "")
}

// setAllExpanded sets the Expanded flag on all group nodes recursively.
func setAllExpanded(nodes []TreeNode, state bool) {
	for i := range nodes {
		if nodes[i].IsGroup {
			nodes[i].Expanded = state
			setAllExpanded(nodes[i].Children, state)
		}
	}
}

// roots collects the unique root group nodes from the current flat list.
func (m *sourcesModel) roots() []TreeNode {
	seen := make(map[string]bool)
	var roots []TreeNode
	for _, row := range m.flatList {
		if row.depth == 0 && !seen[row.node.EntryType] {
			seen[row.node.EntryType] = true
			roots = append(roots, *row.node)
		}
	}
	// If the flat list is empty (e.g., all filtered out) we still need the roots.
	// They are stored in-place via pointer, so the roots we got are already the
	// canonical ones.
	return roots
}

// flatten converts a slice of root nodes to a flat, ordered list of visible rows.
func flatten(roots []TreeNode, filter string) []flatRow {
	var rows []flatRow
	flattenNodes(roots, filter, 0, &rows)
	return rows
}

func flattenNodes(nodes []TreeNode, filter string, depth int, rows *[]flatRow) {
	for i := range nodes {
		n := &nodes[i]
		// For leaf nodes (non-group), apply the filter.
		if !n.IsGroup && filter != "" && !strings.Contains(strings.ToLower(n.Label), strings.ToLower(filter)) {
			continue
		}
		// For group nodes with a filter, skip if no children match.
		if n.IsGroup && filter != "" && len(n.Children) > 0 {
			hasMatch := false
			for _, c := range n.Children {
				if c.IsGroup || strings.Contains(strings.ToLower(c.Label), strings.ToLower(filter)) {
					hasMatch = true
					break
				}
			}
			if !hasMatch {
				continue
			}
		}
		*rows = append(*rows, flatRow{node: n, depth: depth})
		if n.IsGroup && n.Expanded {
			flattenNodes(n.Children, filter, depth+1, rows)
		}
	}
}

// View renders the sources pane content (without the outer border).
func (m sourcesModel) View() string {
	if len(m.flatList) == 0 {
		return dimStyle.Render("  (empty)")
	}

	var sb strings.Builder
	innerWidth := m.width - 4 // subtract border (2) + padding (2)
	if innerWidth < 1 {
		innerWidth = 1
	}

	// Determine visible window.
	visibleRows := m.height
	if visibleRows <= 0 {
		visibleRows = len(m.flatList)
	}
	start := m.scrollOffset
	if start < 0 {
		start = 0
	}
	end := start + visibleRows
	if end > len(m.flatList) {
		end = len(m.flatList)
	}

	for i := start; i < end; i++ {
		row := m.flatList[i]
		indent := strings.Repeat("  ", row.depth)
		var line string
		if row.node.IsGroup {
			// Group header row (type or package).
			expandMark := "v"
			if !row.node.Expanded {
				expandMark = ">"
			}
			if row.depth == 0 {
				// Top-level type group: show colored icon.
				icon := typeIcon(row.node.EntryType)
				label := fmt.Sprintf("%s %s %s", expandMark, icon, row.node.Label)
				line = lipgloss.NewStyle().
					Foreground(colorTypeLabel).
					Bold(true).
					Render(label)
			} else {
				// Package sub-group.
				line = indent + expandMark + " " + row.node.Label
			}
		} else {
			// Leaf entry row.
			icon := statusIcon(row.node.InS3, row.node.Frozen, row.node.Hidden)
			mark := " "
			if row.node.Marked {
				mark = "*"
			}
			line = indent + mark + icon + " " + row.node.Label
		}

		// Trim to available width.
		visible := lipgloss.Width(line)
		if visible > innerWidth {
			// Strip styling, truncate, re-apply only for plain text overflow.
			plain := stripAnsi(line)
			if len(plain) > innerWidth-1 {
				plain = plain[:innerWidth-1] + "~"
			}
			line = plain
		}

		if i == m.cursor && m.focused {
			line = selectedRowStyle.Width(innerWidth).Render(lipgloss.NewStyle().Render(stripAnsi(line)))
		}

		sb.WriteString(line)
		sb.WriteByte('\n')
	}

	return sb.String()
}

// sortedStringKeys returns the keys of m in sorted order.
func sortedStringKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// stripAnsi removes ANSI escape sequences from s, returning plain text.
// This is a lightweight implementation sufficient for our controlled output.
func stripAnsi(s string) string {
	var out strings.Builder
	inEsc := false
	for _, r := range s {
		switch {
		case r == '\x1b':
			inEsc = true
		case inEsc && r == 'm':
			inEsc = false
		case inEsc:
			// still inside escape sequence
		default:
			out.WriteRune(r)
		}
	}
	return out.String()
}
