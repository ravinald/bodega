package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/x/ansi"
)

// logPaneModel is the bubbletea model for the bottom Log pane.
// It is a read-only scrolling viewport that accumulates text output from
// background operations.
type logPaneModel struct {
	viewport viewport.Model
	focused  bool

	width  int
	height int

	outputLines []string // accumulated lines for the viewport

	// query is the active find/filter string, matched case-insensitively
	// against each line with its ANSI styling stripped. filterOnly hides
	// non-matching lines instead of scrolling to a match.
	query      string
	filterOnly bool

	display  []string // lines currently rendered, after any filter
	matches  []int    // indices into display that match query
	matchIdx int      // position within matches
}

// newLogPane creates a new log pane with default dimensions.
func newLogPane() logPaneModel {
	vp := viewport.New(80, 10)
	m := logPaneModel{
		viewport: vp,
	}
	m.appendLog(dimStyle.Render("Log pane — press Tab to switch focus, Up/Down to scroll, / to find, f to filter"))
	return m
}

// Focus marks the log pane as focused.
func (m *logPaneModel) Focus() {
	m.focused = true
}

// Blur removes focus from the log pane.
func (m *logPaneModel) Blur() {
	m.focused = false
}

// appendLog adds a line (or multiple newline-separated lines) to the log
// viewport and auto-scrolls to the bottom.
func (m *logPaneModel) appendLog(msg string) {
	m.outputLines = append(m.outputLines, strings.Split(msg, "\n")...)
	m.syncViewport()
}

// syncViewport rebuilds the rendered content and scrolls to the bottom. New
// output pulls the view down; a search moves it deliberately and calls
// setContent instead.
func (m *logPaneModel) syncViewport() {
	m.setContent()
	m.viewport.GotoBottom()
}

// setContent recomputes the displayed lines and the match set, then pushes
// them into the viewport without moving the scroll position.
func (m *logPaneModel) setContent() {
	m.display = m.display[:0]
	m.matches = m.matches[:0]

	needle := strings.ToLower(m.query)
	for _, line := range m.outputLines {
		hit := needle != "" && strings.Contains(strings.ToLower(ansi.Strip(line)), needle)
		if m.filterOnly && needle != "" && !hit {
			continue
		}
		if hit {
			m.matches = append(m.matches, len(m.display))
		}
		m.display = append(m.display, line)
	}

	if m.matchIdx >= len(m.matches) {
		m.matchIdx = 0
	}

	rendered := make([]string, len(m.display))
	copy(rendered, m.display)
	if len(m.matches) > 0 {
		cur := m.matches[m.matchIdx]
		// The line carries its own styling, which cannot be nested inside a
		// highlight without the inner reset ending it. Strip and re-render.
		rendered[cur] = logMatchStyle.Render(ansi.Strip(rendered[cur]))
	}
	m.viewport.SetContent(strings.Join(rendered, "\n"))
}

// SetSearch applies a find (filterOnly false) or filter (filterOnly true)
// query and scrolls to the first match.
func (m *logPaneModel) SetSearch(query string, filterOnly bool) {
	m.query = query
	m.filterOnly = filterOnly
	m.matchIdx = 0
	m.setContent()
	m.scrollToMatch()
}

// ClearSearch drops the query and returns the pane to the tail of the log.
func (m *logPaneModel) ClearSearch() {
	m.query = ""
	m.filterOnly = false
	m.matchIdx = 0
	m.syncViewport()
}

// Searching reports whether a query is active.
func (m *logPaneModel) Searching() bool { return m.query != "" }

// MatchCount returns the number of matching lines.
func (m *logPaneModel) MatchCount() int { return len(m.matches) }

// MatchPos returns the 1-based position of the current match, or 0 when there
// are none.
func (m *logPaneModel) MatchPos() int {
	if len(m.matches) == 0 {
		return 0
	}
	return m.matchIdx + 1
}

// MatchLine returns the display-line index of the current match, or -1.
func (m *logPaneModel) MatchLine() int {
	if len(m.matches) == 0 {
		return -1
	}
	return m.matches[m.matchIdx]
}

// NextMatch advances to the following match, wrapping at the end.
func (m *logPaneModel) NextMatch() {
	if len(m.matches) == 0 {
		return
	}
	m.matchIdx = (m.matchIdx + 1) % len(m.matches)
	m.setContent()
	m.scrollToMatch()
}

// PrevMatch steps back to the preceding match, wrapping at the start.
func (m *logPaneModel) PrevMatch() {
	if len(m.matches) == 0 {
		return
	}
	m.matchIdx = (m.matchIdx - 1 + len(m.matches)) % len(m.matches)
	m.setContent()
	m.scrollToMatch()
}

// scrollToMatch puts the current match on the first visible row.
func (m *logPaneModel) scrollToMatch() {
	if len(m.matches) == 0 {
		return
	}
	m.viewport.SetYOffset(m.matches[m.matchIdx])
}

// SetSize resizes the viewport. h is the full content height — no input row
// is reserved because this pane is read-only.
func (m *logPaneModel) SetSize(w, h int) {
	m.width = w
	m.height = h
	vpH := h
	if vpH < 1 {
		vpH = 1
	}
	m.viewport.Width = w
	m.viewport.Height = vpH
	m.setContent()
	if !m.Searching() {
		m.viewport.GotoBottom()
	}
}

// ScrollUp scrolls the viewport up by one line.
func (m *logPaneModel) ScrollUp() {
	m.viewport.ScrollUp(1)
}

// ScrollDown scrolls the viewport down by one line.
func (m *logPaneModel) ScrollDown() {
	m.viewport.ScrollDown(1)
}

func (m logPaneModel) View() string {
	return m.viewport.View()
}
