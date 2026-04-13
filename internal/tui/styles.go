// Package tui implements the three-pane terminal UI for bodega shell.
// Pane layout: Sources (top-left, 40%) | Details (top-right, 60%)
//
//	Shell output + input (bottom, full width)
package tui

import "github.com/charmbracelet/lipgloss"

// colorScheme holds the palette used throughout the TUI.
var (
	colorFocusedBorder   = lipgloss.Color("33")  // bright blue
	colorUnfocusedBorder = lipgloss.Color("240") // dim gray
	colorSelected        = lipgloss.Color("33")
	colorSelectedBg      = lipgloss.Color("17") // dark blue bg
	colorGreen           = lipgloss.Color("42")
	colorRed             = lipgloss.Color("196")
	colorYellow          = lipgloss.Color("220")
	colorDim             = lipgloss.Color("240")
	colorBright          = lipgloss.Color("252")
	colorPrompt          = lipgloss.Color("33")
	colorTypeLabel       = lipgloss.Color("75")
)

// paneStyle returns a lipgloss.Style for a pane border, highlighted when focused.
func paneStyle(focused bool) lipgloss.Style {
	borderColor := colorUnfocusedBorder
	if focused {
		borderColor = colorFocusedBorder
	}
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(borderColor)
}

// titleStyle renders a pane title inline with the border.
func titleStyle(focused bool) lipgloss.Style {
	fg := colorUnfocusedBorder
	if focused {
		fg = lipgloss.Color("252")
	}
	return lipgloss.NewStyle().Foreground(fg).Bold(focused)
}

// selectedRowStyle highlights the currently selected tree row.
var selectedRowStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("255")).
	Background(colorSelectedBg).
	Bold(true)

// dimStyle is used for secondary / metadata text.
var dimStyle = lipgloss.NewStyle().Foreground(colorDim)

// keyStyle renders a detail-pane field key.
var keyStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("75")).
	Width(12)

// valueStyle renders a detail-pane field value.
var valueStyle = lipgloss.NewStyle().Foreground(colorBright)

// promptStyle renders the shell prompt.
var promptStyle = lipgloss.NewStyle().
	Foreground(colorPrompt).
	Bold(true)

// errorStyle renders error output in red.
var errorStyle = lipgloss.NewStyle().Foreground(colorRed)

// successStyle renders success output in green.
var successStyle = lipgloss.NewStyle().Foreground(colorGreen)

// statusIcon returns the icon for a tree-node status.
func statusIcon(inS3, frozen, hidden bool) string {
	switch {
	case hidden:
		return dimStyle.Render("~")
	case frozen:
		return lipgloss.NewStyle().Foreground(colorYellow).Render("*")
	case inS3:
		return lipgloss.NewStyle().Foreground(colorGreen).Render("+")
	default:
		return lipgloss.NewStyle().Foreground(colorRed).Render("-")
	}
}

// typeIcon returns the icon for a source type group.
func typeIcon(t string) string {
	switch t {
	case "apt":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Render("A")
	case "git":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("99")).Render("G")
	case "pypi":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("226")).Render("P")
	case "binary":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("41")).Render("B")
	case "gomod":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("81")).Render("M")
	case "helm":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("33")).Render("H")
	case "npm":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("N")
	default:
		return " "
	}
}

// popupStyle styles the help/confirm popup overlay.
var popupStyle = lipgloss.NewStyle().
	Border(lipgloss.RoundedBorder()).
	BorderForeground(colorFocusedBorder).
	Padding(1, 2).
	Background(lipgloss.Color("234"))

// buildMenuTitleStyle renders the title line in the build menu popup.
var buildMenuTitleStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("252")).
	Bold(true)

// buildMenuKeyStyle renders the bracketed key hint in the build menu.
var buildMenuKeyStyle = lipgloss.NewStyle().
	Foreground(colorFocusedBorder).
	Bold(true)

// formLabelStyle renders a field label in the form popup.
var formLabelStyle = lipgloss.NewStyle().
	Foreground(colorTypeLabel).
	Width(12)

// formValueStyle renders a field value in the form popup (unfocused).
var formValueStyle = lipgloss.NewStyle().Foreground(colorBright)

// formActiveValueStyle renders the currently focused field value in the form popup.
var formActiveValueStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("255"))

// formCursorStyle renders the character at the cursor position (inverted).
var formCursorStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("234")).
	Background(lipgloss.Color("255"))
