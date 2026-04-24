package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
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
}

// newLogPane creates a new log pane with default dimensions.
func newLogPane() logPaneModel {
	vp := viewport.New(80, 10)
	m := logPaneModel{
		viewport: vp,
	}
	m.appendLog(dimStyle.Render("Log pane — press Tab to switch focus, Up/Down to scroll"))
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
	for _, line := range strings.Split(msg, "\n") {
		m.outputLines = append(m.outputLines, line)
	}
	m.syncViewport()
}

// syncViewport pushes the accumulated output into the viewport model and
// scrolls to the bottom.
func (m *logPaneModel) syncViewport() {
	content := strings.Join(m.outputLines, "\n")
	m.viewport.SetContent(content)
	m.viewport.GotoBottom()
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
	m.syncViewport()
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
