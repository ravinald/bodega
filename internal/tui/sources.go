package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/manifest"
	"github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/s3"
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
	flatList []flatRow
	cursor   int
	width    int
	height   int
	focused  bool
	// filter is the active search string.
	filter string
}

// flatRow pairs a display string with the underlying node it represents.
type flatRow struct {
	display string // rendered line (unstyled)
	node    *TreeNode
	depth   int // 0 = type group, 1 = entry
}

// BuildTree constructs the root-level tree nodes from the manifest store and
// S3 statuses. Statuses are keyed by "type/name".
func BuildTree(store *manifest.Store, statuses []s3.EntryStatus) []TreeNode {
	s3map := make(map[string]bool, len(statuses))
	for _, st := range statuses {
		s3map[st.Type+"/"+st.Name] = st.InS3
	}

	var roots []TreeNode

	// apt
	aptGroup := TreeNode{
		Label:     "apt/",
		EntryType: manifest.TypeApt,
		IsGroup:   true,
		Expanded:  true,
	}
	for _, e := range store.Apt {
		aptGroup.Children = append(aptGroup.Children, TreeNode{
			Label:     e.VersionedName(),
			EntryType: manifest.TypeApt,
			Name:      e.Name,
			InS3:      s3map[manifest.TypeApt+"/"+e.Name],
			Frozen:    e.Frozen,
		})
	}
	roots = append(roots, aptGroup)

	// git
	gitGroup := TreeNode{
		Label:     "git/",
		EntryType: manifest.TypeGit,
		IsGroup:   true,
		Expanded:  true,
	}
	for _, e := range store.Git {
		gitGroup.Children = append(gitGroup.Children, TreeNode{
			Label:     e.VersionedName(),
			EntryType: manifest.TypeGit,
			Name:      e.Name,
			InS3:      s3map[manifest.TypeGit+"/"+e.Name],
			Frozen:    e.Frozen,
		})
	}
	roots = append(roots, gitGroup)

	// pypi — flat list of explicit packages (base app deps shown after build via dep graph)
	pypiGroup := TreeNode{
		Label:     "pypi/",
		EntryType: manifest.TypePypi,
		IsGroup:   true,
		Expanded:  true,
	}

	// Explicit packages from the manifest.
	for _, pkg := range store.Pypi.Packages {
		pypiGroup.Children = append(pypiGroup.Children, TreeNode{
			Label:     pkg.Name,
			EntryType: manifest.TypePypi,
			Name:      pkg.Name,
			InS3:      s3map[manifest.TypePypi+"/wheels"],
			Frozen:    pkg.Frozen || store.Pypi.Frozen,
		})
	}

	roots = append(roots, pypiGroup)

	// binary
	binGroup := TreeNode{
		Label:     "binary/",
		EntryType: manifest.TypeBinary,
		IsGroup:   true,
		Expanded:  true,
	}
	for _, e := range store.Binary {
		binGroup.Children = append(binGroup.Children, TreeNode{
			Label:     e.VersionedName(),
			EntryType: manifest.TypeBinary,
			Name:      e.Name,
			InS3:      s3map[manifest.TypeBinary+"/"+e.Name],
			Frozen:    e.Frozen,
		})
	}
	roots = append(roots, binGroup)

	// gomod
	gomodGroup := TreeNode{
		Label:     "gomod/",
		EntryType: manifest.TypeGomod,
		IsGroup:   true,
		Expanded:  true,
	}
	for _, e := range store.Gomod {
		gomodGroup.Children = append(gomodGroup.Children, TreeNode{
			Label:     e.VersionedName(),
			EntryType: manifest.TypeGomod,
			Name:      e.Name,
			InS3:      s3map[manifest.TypeGomod+"/"+e.Name],
			Frozen:    e.Frozen,
		})
	}
	roots = append(roots, gomodGroup)

	// helm
	helmGroup := TreeNode{
		Label:     "helm/",
		EntryType: manifest.TypeHelm,
		IsGroup:   true,
		Expanded:  true,
	}
	for _, e := range store.Helm {
		helmGroup.Children = append(helmGroup.Children, TreeNode{
			Label:     e.VersionedName(),
			EntryType: manifest.TypeHelm,
			Name:      e.Name,
			InS3:      s3map[manifest.TypeHelm+"/"+e.Name],
			Frozen:    e.Frozen,
		})
	}
	roots = append(roots, helmGroup)

	// npm
	npmGroup := TreeNode{
		Label:     "npm/",
		EntryType: manifest.TypeNpm,
		IsGroup:   true,
		Expanded:  true,
	}
	for _, e := range store.Npm {
		npmGroup.Children = append(npmGroup.Children, TreeNode{
			Label:     e.VersionedName(),
			EntryType: manifest.TypeNpm,
			Name:      e.Name,
			InS3:      s3map[manifest.TypeNpm+"/"+e.Name],
			Frozen:    e.Frozen,
		})
	}
	roots = append(roots, npmGroup)

	return roots
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
	}
}

// CursorDown moves the cursor down one row.
func (m *sourcesModel) CursorDown() {
	if m.cursor < len(m.flatList)-1 {
		m.cursor++
	}
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
// If the cursor is on a group node, all children in that group are toggled.
func (m *sourcesModel) ToggleMark() {
	if m.cursor < 0 || m.cursor >= len(m.flatList) {
		return
	}
	node := m.flatList[m.cursor].node
	if node.IsGroup {
		// Toggle all children to the opposite of the majority.
		marked := 0
		for i := range node.Children {
			if node.Children[i].Marked {
				marked++
			}
		}
		newState := marked < len(node.Children) // if less than all are marked, mark all
		for i := range node.Children {
			node.Children[i].Marked = newState
		}
		// Also update the flatList entries that point to these children.
		for i := range m.flatList {
			if m.flatList[i].node.EntryType == node.EntryType && !m.flatList[i].node.IsGroup {
				m.flatList[i].node.Marked = newState
			}
		}
	} else {
		node.Marked = !node.Marked
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
	for i := range m.flatList {
		if !m.flatList[i].node.IsGroup {
			m.flatList[i].node.Marked = newState
		}
	}
	// Also update the root tree children.
	roots := m.roots()
	for i := range roots {
		for j := range roots[i].Children {
			roots[i].Children[j].Marked = newState
		}
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
func (m *sourcesModel) SetFilter(f string) {
	m.filter = f
	roots := m.roots()
	m.flatList = flatten(roots, f)
	m.cursor = 0
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
	for i := range roots {
		r := &roots[i]
		rows = append(rows, flatRow{node: r, depth: 0})
		if r.Expanded {
			for j := range r.Children {
				child := &r.Children[j]
				if filter != "" && !strings.Contains(strings.ToLower(child.Label), strings.ToLower(filter)) {
					continue
				}
				rows = append(rows, flatRow{node: child, depth: 1})
			}
		}
	}
	return rows
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

	for i, row := range m.flatList {
		var line string
		if row.depth == 0 {
			// Group header row.
			icon := typeIcon(row.node.EntryType)
			expandMark := "v"
			if !row.node.Expanded {
				expandMark = ">"
			}
			label := fmt.Sprintf("%s %s %s", expandMark, icon, row.node.Label)
			line = lipgloss.NewStyle().
				Foreground(colorTypeLabel).
				Bold(true).
				Render(label)
		} else {
			// Entry row.
			icon := statusIcon(row.node.InS3, row.node.Frozen)
			mark := " "
			if row.node.Marked {
				mark = "*"
			}
			label := " " + mark + icon + " " + row.node.Label
			line = label
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
