package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/lipgloss"
)

// popupKind identifies which popup is currently shown.
type popupKind int

const (
	popupNone      popupKind = iota
	popupHelp                // ? key
	popupConfirm             // destructive action confirmation
	popupBuildMenu           // B key — per-entry build stage picker
	popupForm                // c/E key — create or edit entry fields
)

// popupModel holds the state for the overlay popup.
type popupModel struct {
	kind    popupKind
	message string // used for confirm popup
	onYes   func() // callback executed when user presses Y (confirm)

	// pendingAsyncCmd is the tea.Cmd that should be dispatched after the popup
	// is dismissed by a confirming action (Y for confirm, stage key for build
	// menu). The app's handlePopupKey reads and clears this field.
	pendingAsyncCmd tea.Cmd

	// --- build menu popup ---
	buildTitle     string
	buildEntryType string
	buildEntryName string
	// onBuildSelect is called with the chosen BuildStage when the user selects
	// an option from the build menu. It returns the tea.Cmd to execute;
	// HandleBuildMenuKey assigns the result to pendingAsyncCmd on the receiver.
	onBuildSelect func(stage BuildStage) tea.Cmd

	// --- form popup ---
	formTitle  string
	formFields []formField
	formCursor int // index of the focused field
	prevCursor int // index of the previously focused field (before last navigation)
	// onFormSave is called with the completed field slice when the user presses Enter.
	onFormSave func(fields []formField)
	// onChange is called after every key or rune input. The hook may mutate
	// p.formFields to implement dynamic behaviors (type-based rebuilds, hints, etc.).
	// prevCursor holds the field index that was focused before any navigation.
	onChange func(p *popupModel)
	// validate is called when Enter is pressed. If it returns a non-empty string
	// the save is blocked and the message is displayed at the bottom of the form.
	validate func(fields []formField) string
	// validationError is the last error returned by validate.
	validationError string

	// --- inline select submenu ---
	selectOpen   bool // is the inline submenu currently displayed?
	selectCursor int  // cursor within the submenu options

	// --- raw JSON overlay ---
	jsonInput    bool           // is the raw JSON overlay open?
	jsonTitle    string         // title shown at the top of the JSON overlay
	jsonTextarea textarea.Model // bubbles textarea for JSON editing
	jsonError    string         // validation error shown at the bottom of the overlay
}

// formField represents a single labelled field in the form popup.
type formField struct {
	Label    string
	Value    string
	Checkbox bool     // if true, this is a toggle field (Value is "yes" or "no")
	Select   bool     // if true, Enter/Space opens inline submenu
	Options  []string // choices for Select fields
	Disabled bool     // greyed out, not editable
	Hint     string   // displayed below the field in dim text (not a separate field)
	cursor   int      // cursor position within Value (for text editing)
}

// Active returns true when a popup is displayed.
func (p *popupModel) Active() bool {
	return p.kind != popupNone
}

// dismiss hides the popup without any action.
func (p *popupModel) dismiss() {
	*p = popupModel{}
}

// confirm executes onYes and dismisses.
func (p *popupModel) confirm() {
	if p.onYes != nil {
		p.onYes()
	}
	p.dismiss()
}

// helpText is the content rendered inside the help popup.
const helpText = `Navigation:
  /          Filter / search
  ?          Toggle this help
  Ctrl+A     Select / deselect all packages
  Enter/Space Expand/collapse type group
  m          Mark / unmark package (or group)
  Tab        Switch focus: Sources <-> Log
  Up/Down    Navigate entries
  q          Quit

Entry management:
  c          Create new entry (form)
  C          Configure application settings
  D          Delete entry (with confirmation)
  E          Edit selected entry (form)
  F          Toggle freeze on entry

Build pipeline:
  B          Open build menu for marked package(s)
               A=All     B=Build  D=Deploy
               F=Fetch   P=Package  Esc=Cancel

S3 bucket operations:
  I          Initialise S3 bucket (with confirmation)
  R          Remove artifact from S3 (with confirmation)
  S          Sync all local artifacts to S3
  v          Verify manifest checksums

Log pane (Tab to focus):
  Tab / Esc  Return to Sources
  Up/Down    Scroll log
  q          Quit

Form editor:
  Enter      Save
  Esc        Cancel
  Space      Toggle checkbox / open select
  Tab        Next field
  Up/Down    Move between fields
  j          Open raw JSON editor`

// View renders the popup centered over the given screen dimensions.
func (p *popupModel) View(screenWidth, screenHeight int) string {
	if p.kind == popupNone {
		return ""
	}

	// JSON overlay takes priority when active.
	if p.kind == popupForm && p.jsonInput {
		return p.renderJSONOverlay(screenWidth, screenHeight)
	}

	var content string
	switch p.kind {
	case popupHelp:
		content = helpText

	case popupConfirm:
		content = p.message + "\n\n[Y] confirm   [N] cancel"

	case popupBuildMenu:
		content = p.renderBuildMenu()

	case popupForm:
		content = p.renderForm()
	}

	box := popupStyle.Render(content)
	lines := strings.Split(box, "\n")
	boxHeight := len(lines)
	boxWidth := 0
	for _, l := range lines {
		if w := lipgloss.Width(l); w > boxWidth {
			boxWidth = w
		}
	}

	// Center vertically and horizontally.
	topPad := (screenHeight - boxHeight) / 2
	if topPad < 0 {
		topPad = 0
	}
	leftPad := (screenWidth - boxWidth) / 2
	if leftPad < 0 {
		leftPad = 0
	}

	leftStr := strings.Repeat(" ", leftPad)
	topStr := strings.Repeat("\n", topPad)

	var sb strings.Builder
	sb.WriteString(topStr)
	for _, l := range lines {
		sb.WriteString(leftStr)
		sb.WriteString(l)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// renderBuildMenu renders the build stage picker content.
func (p *popupModel) renderBuildMenu() string {
	title := buildMenuTitleStyle.Render("Build: " + p.buildEntryName)

	items := []struct {
		key   string
		label string
	}{
		{"F", "Fetch source"},
		{"B", "Build from source"},
		{"P", "Package (create artifact)"},
		{"D", "Deploy (upload to S3)"},
		{"A", "All (full pipeline)"},
	}

	var sb strings.Builder
	sb.WriteString(title)
	sb.WriteString("\n\n")
	for _, item := range items {
		keyPart := buildMenuKeyStyle.Render("[" + item.key + "]")
		sb.WriteString("  " + keyPart + " " + item.label + "\n")
	}
	sb.WriteString("\n")
	sb.WriteString(dimStyle.Render("  Esc to cancel"))
	return sb.String()
}

// renderForm renders the form popup content with focusable labelled fields.
func (p *popupModel) renderForm() string {
	title := buildMenuTitleStyle.Render(p.formTitle)

	var sb strings.Builder
	sb.WriteString(title)
	sb.WriteString("\n\n")

	// Find the longest label to align colons.
	maxLabel := 0
	for _, f := range p.formFields {
		if len(f.Label) > maxLabel {
			maxLabel = len(f.Label)
		}
	}

	for i, f := range p.formFields {
		padded := f.Label + strings.Repeat(" ", maxLabel-len(f.Label))
		label := formLabelStyle.UnsetWidth().Render(padded + ":")

		if f.Disabled {
			// Dim label and value for disabled fields.
			label = dimStyle.Render(padded + ":")
		}

		var value string
		switch {
		case f.Checkbox:
			check := "[ ]"
			if f.Value == "yes" {
				check = "[x]"
			}
			if i == p.formCursor && !f.Disabled {
				value = formActiveValueStyle.Render(" " + check)
			} else if f.Disabled {
				value = dimStyle.Render(" " + check)
			} else {
				value = formValueStyle.Render(" " + check)
			}

		case f.Select:
			indicator := " ▾"
			if i == p.formCursor && !f.Disabled {
				value = formActiveValueStyle.Render(" " + f.Value + indicator)
			} else if f.Disabled {
				value = dimStyle.Render(" " + f.Value + indicator)
			} else {
				value = formValueStyle.Render(" " + f.Value + indicator)
			}

		default:
			if i == p.formCursor && !f.Disabled {
				runes := []rune(f.Value)
				cur := f.cursor
				if cur > len(runes) {
					cur = len(runes)
				}
				before := " " + string(runes[:cur])
				after := ""
				cursorChar := " "
				if cur < len(runes) {
					cursorChar = string(runes[cur])
					after = string(runes[cur+1:])
				}
				value = formValueStyle.Render(before) +
					formCursorStyle.Render(cursorChar) +
					formValueStyle.Render(after)
			} else if f.Disabled {
				value = dimStyle.Render(" " + f.Value)
			} else {
				value = formValueStyle.Render(" " + f.Value)
			}
		}

		sb.WriteString("  " + label + value + "\n")

		// Render hint below the field in dim text.
		if f.Hint != "" {
			hintPad := strings.Repeat(" ", maxLabel+4) // align under value
			sb.WriteString(hintPad + dimStyle.Render(f.Hint) + "\n")
		}

		// Render inline submenu when this select field is focused and open.
		if f.Select && i == p.formCursor && p.selectOpen {
			sb.WriteString(p.renderSelectMenu(f, maxLabel))
		}
	}

	sb.WriteString("\n")
	if p.validationError != "" {
		sb.WriteString(errorStyle.Render("  "+p.validationError) + "\n")
	}
	sb.WriteString(dimStyle.Render("  Tab=next  Space=toggle  Enter=save  Esc=cancel  j=JSON  ^T=defaults  ^R=reset"))
	return sb.String()
}

// renderSelectMenu renders the inline submenu for a Select field.
func (p *popupModel) renderSelectMenu(f formField, labelWidth int) string {
	var sb strings.Builder
	indent := strings.Repeat(" ", labelWidth+4)
	border := dimStyle.Render(strings.Repeat("─", 16))
	sb.WriteString(indent + border + "\n")
	for i, opt := range f.Options {
		prefix := "  "
		var rendered string
		if i == p.selectCursor {
			rendered = formActiveValueStyle.Render("> " + opt)
		} else {
			rendered = formValueStyle.Render(prefix + opt)
		}
		sb.WriteString(indent + rendered + "\n")
	}
	sb.WriteString(indent + border + "\n")
	return sb.String()
}

// OpenJSONOverlay initialises the textarea and opens the JSON overlay.
// If initialValue is non-empty, the textarea is pre-populated with it.
func (p *popupModel) OpenJSONOverlay(width, height int, initialValue string, title string) {
	ta := textarea.New()
	ta.Placeholder = "Paste or type JSON here..."
	ta.ShowLineNumbers = true
	ta.SetWidth(width * 70 / 100)
	ta.SetHeight(height/2 - 4)
	if initialValue != "" {
		ta.SetValue(initialValue)
	}
	ta.Focus()
	p.jsonTextarea = ta
	p.jsonInput = true
	p.jsonTitle = title
	p.jsonError = ""
}

// renderJSONOverlay renders the raw JSON input overlay using the textarea component.
func (p *popupModel) renderJSONOverlay(screenWidth, screenHeight int) string {
	titleText := "Raw JSON"
	if p.jsonTitle != "" {
		titleText = p.jsonTitle
	}
	title := buildMenuTitleStyle.Render(titleText + " — Ctrl+S to apply, Ctrl+T for template, Esc to discard")

	var sb strings.Builder
	sb.WriteString(title)
	sb.WriteString("\n\n")
	sb.WriteString(p.jsonTextarea.View())
	sb.WriteString("\n")
	if p.jsonError != "" {
		sb.WriteString("\n" + errorStyle.Render(p.jsonError))
	}

	content := sb.String()

	targetW := screenWidth * 80 / 100
	if targetW < 40 {
		targetW = 40
	}

	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorFocusedBorder).
		Padding(1, 2).
		Width(targetW)

	box := boxStyle.Render(content)
	lines := strings.Split(box, "\n")
	boxHeight := len(lines)
	boxWidth := 0
	for _, l := range lines {
		if w := lipgloss.Width(l); w > boxWidth {
			boxWidth = w
		}
	}

	topPad := (screenHeight - boxHeight) / 2
	if topPad < 0 {
		topPad = 0
	}
	leftPad := (screenWidth - boxWidth) / 2
	if leftPad < 0 {
		leftPad = 0
	}

	leftStr := strings.Repeat(" ", leftPad)
	topStr := strings.Repeat("\n", topPad)

	var out strings.Builder
	out.WriteString(topStr)
	for _, l := range lines {
		out.WriteString(leftStr)
		out.WriteString(l)
		out.WriteByte('\n')
	}
	return out.String()
}

// HandleFormKey processes a key event while the form popup is active.
// Returns true if the popup should be dismissed (saved or cancelled).
func (p *popupModel) HandleFormKey(key string) (dismiss bool) {
	// While the select submenu is open, route navigation to it.
	if p.selectOpen {
		return p.handleSelectMenuKey(key)
	}

	switch key {
	case "esc":
		p.dismiss()
		return true

	case "enter":
		// Validate before saving.
		if p.validate != nil {
			if msg := p.validate(p.formFields); msg != "" {
				p.validationError = msg
				return false
			}
		}
		p.validationError = ""
		if p.onFormSave != nil {
			p.onFormSave(p.formFields)
		}
		p.dismiss()
		return true

	case "tab", "shift+tab", "up", "down":
		if len(p.formFields) == 0 {
			return false
		}
		p.prevCursor = p.formCursor
		if key == "tab" || key == "down" {
			next := (p.formCursor + 1) % len(p.formFields)
			// Skip disabled fields.
			for next != p.formCursor && p.formFields[next].Disabled {
				next = (next + 1) % len(p.formFields)
			}
			p.formCursor = next
		} else {
			prev := (p.formCursor - 1 + len(p.formFields)) % len(p.formFields)
			for prev != p.formCursor && p.formFields[prev].Disabled {
				prev = (prev - 1 + len(p.formFields)) % len(p.formFields)
			}
			p.formCursor = prev
		}
		// Reset cursor to end of new field's value.
		if p.formCursor < len(p.formFields) {
			p.formFields[p.formCursor].cursor = len([]rune(p.formFields[p.formCursor].Value))
		}
		if p.onChange != nil {
			p.onChange(p)
		}

	case "left":
		if p.formCursor < len(p.formFields) && !p.formFields[p.formCursor].Checkbox && !p.formFields[p.formCursor].Select && !p.formFields[p.formCursor].Disabled {
			if p.formFields[p.formCursor].cursor > 0 {
				p.formFields[p.formCursor].cursor--
			}
		}

	case "right":
		if p.formCursor < len(p.formFields) && !p.formFields[p.formCursor].Checkbox && !p.formFields[p.formCursor].Select && !p.formFields[p.formCursor].Disabled {
			runes := []rune(p.formFields[p.formCursor].Value)
			if p.formFields[p.formCursor].cursor < len(runes) {
				p.formFields[p.formCursor].cursor++
			}
		}

	case "home":
		if p.formCursor < len(p.formFields) && !p.formFields[p.formCursor].Disabled {
			p.formFields[p.formCursor].cursor = 0
		}

	case "end":
		if p.formCursor < len(p.formFields) && !p.formFields[p.formCursor].Disabled {
			p.formFields[p.formCursor].cursor = len([]rune(p.formFields[p.formCursor].Value))
		}

	case " ":
		if p.formCursor >= len(p.formFields) || p.formFields[p.formCursor].Disabled {
			return false
		}
		f := &p.formFields[p.formCursor]
		if f.Checkbox {
			if f.Value == "yes" {
				f.Value = "no"
			} else {
				f.Value = "yes"
			}
			if p.onChange != nil {
				p.onChange(p)
			}
		} else if f.Select {
			p.openSelectMenu()
		}

	case "backspace":
		if p.formCursor < len(p.formFields) && !p.formFields[p.formCursor].Checkbox && !p.formFields[p.formCursor].Select && !p.formFields[p.formCursor].Disabled {
			f := &p.formFields[p.formCursor]
			runes := []rune(f.Value)
			if f.cursor > 0 && f.cursor <= len(runes) {
				f.Value = string(runes[:f.cursor-1]) + string(runes[f.cursor:])
				f.cursor--
			}
			if p.onChange != nil {
				p.onChange(p)
			}
		}
	}
	return false
}

// openSelectMenu initialises the submenu cursor to the currently selected option.
func (p *popupModel) openSelectMenu() {
	if p.formCursor >= len(p.formFields) {
		return
	}
	f := &p.formFields[p.formCursor]
	p.selectOpen = true
	p.selectCursor = 0
	// Position submenu cursor on the current value.
	for i, opt := range f.Options {
		if opt == f.Value {
			p.selectCursor = i
			break
		}
	}
}

// handleSelectMenuKey handles navigation within an open inline submenu.
// Returns true if the popup should be dismissed (which never happens here).
func (p *popupModel) handleSelectMenuKey(key string) (dismiss bool) {
	if p.formCursor >= len(p.formFields) {
		p.selectOpen = false
		return false
	}
	f := &p.formFields[p.formCursor]

	switch key {
	case "up", "k":
		if p.selectCursor > 0 {
			p.selectCursor--
		}
	case "down", "j":
		if p.selectCursor < len(f.Options)-1 {
			p.selectCursor++
		}
	case "enter", " ":
		if p.selectCursor < len(f.Options) {
			f.Value = f.Options[p.selectCursor]
		}
		p.selectOpen = false
		if p.onChange != nil {
			p.onChange(p)
		}
	case "esc":
		p.selectOpen = false
	}
	return false
}

// HandleFormRune appends a printable rune to the currently focused field.
// Checkbox and Select fields ignore rune input; Disabled fields are also skipped.
func (p *popupModel) HandleFormRune(r rune) {
	if p.formCursor >= len(p.formFields) {
		return
	}
	f := &p.formFields[p.formCursor]
	if f.Checkbox || f.Select || f.Disabled {
		return
	}
	runes := []rune(f.Value)
	if f.cursor >= len(runes) {
		f.Value += string(r)
	} else {
		f.Value = string(runes[:f.cursor]) + string(r) + string(runes[f.cursor:])
	}
	f.cursor++
	if p.onChange != nil {
		p.onChange(p)
	}
}

// HandleJSONOverlayKey processes a key event while the raw JSON overlay is open.
// Returns (dismissed bool, cmd tea.Cmd). The cmd may contain textarea commands
// (e.g., blink cursor) that must be returned to bubbletea.
func (p *popupModel) HandleJSONOverlayKey(msg tea.KeyMsg, applyFn func(buf string) string) (bool, tea.Cmd) {
	key := msg.String()
	switch key {
	case "esc":
		p.jsonInput = false
		p.jsonError = ""
		return true, nil
	case "ctrl+s":
		buf := p.jsonTextarea.Value()
		if errMsg := applyFn(buf); errMsg != "" {
			p.jsonError = errMsg
			return false, nil
		}
		p.jsonInput = false
		p.jsonError = ""
		return true, nil
	case "ctrl+t":
		// Insert a JSON template with all keys and empty values.
		entryType := ""
		for _, f := range p.formFields {
			if f.Label == "Type" {
				entryType = f.Value
				break
			}
		}
		tmpl := jsonTemplateForType(entryType)
		p.jsonTextarea.SetValue(tmpl)
		return false, nil
	default:
		// Forward all other keys to the textarea component.
		var cmd tea.Cmd
		p.jsonTextarea, cmd = p.jsonTextarea.Update(msg)
		return false, cmd
	}
}

// jsonTemplateForType returns a JSON template with all keys for the given entry type.
func jsonTemplateForType(entryType string) string {
	switch entryType {
	case "apt":
		return `{
  "name": "",
  "version": "",
  "source_name": "",
  "url": "",
  "build_cmd": "",
  "deb_glob": "",
  "checksum": null,
  "frozen": false
}`
	case "git":
		return `{
  "name": "",
  "url": "",
  "ref": "",
  "frozen": false
}`
	case "pypi":
		return `{
  "name": "",
  "required_by": [],
  "checksum": null,
  "frozen": false
}`
	case "binary":
		return `{
  "name": "",
  "version": "",
  "url": "",
  "sha256": null,
  "checksum": null,
  "filename": "",
  "frozen": false
}`
	default:
		return `{
  "name": "",
  "url": ""
}`
	}
}

// HandleBuildMenuKey maps a key press to a BuildStage and calls onBuildSelect.
// Returns true if the popup should be dismissed.
func (p *popupModel) HandleBuildMenuKey(key string) (dismiss bool) {
	var stage BuildStage
	switch key {
	case "f", "F":
		stage = StageFetch
	case "b", "B":
		stage = StageBuild
	case "p", "P":
		stage = StagePackage
	case "d", "D":
		stage = StageDeploy
	case "a", "A":
		stage = StageAll
	case "esc":
		p.dismiss()
		return true
	default:
		return false
	}
	if p.onBuildSelect != nil {
		// Store the returned command before dismiss() zeroes the struct.
		cmd := p.onBuildSelect(stage)
		p.pendingAsyncCmd = cmd
	}
	// Mark as dismissed by zeroing kind; pendingAsyncCmd is preserved so the
	// caller can read it after dismiss returns.
	p.kind = popupNone
	p.onBuildSelect = nil
	return true
}
