// Package tui provides the three-pane terminal UI for the reman shell command.
//
// Layout:
//
//	┌─ Sources ────────┬─ Details ─────────────────┐
//	│ tree view        │ metadata for selection     │
//	├──────────────────┴────────────────────────────┤
//	│ log output (read-only scrolling viewport)     │
//	└───────────────────────────────────────────────┘
package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/config"
	"github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/manifest"
	bos3 "github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/s3"
)

// focusTarget identifies which pane currently has keyboard focus.
type focusTarget int

const (
	focusSources focusTarget = iota
	focusLog
)

// s3StatusMsg carries async S3 status results back into the event loop.
type s3StatusMsg struct {
	statuses []bos3.EntryStatus
	err      error
}

// storeRefreshMsg signals that the manifest store was reloaded.
type storeRefreshMsg struct {
	store *manifest.Store
}

// appModel is the root bubbletea model that composes the three panes.
type appModel struct {
	sources  sourcesModel
	details  detailsModel
	log      logPaneModel
	popup    popupModel
	roots    []TreeNode
	focus    focusTarget
	statuses []bos3.EntryStatus

	cfg      *config.Config
	store    *manifest.Store
	s3client *bos3.Client

	width     int
	height    int
	logHeight int // configurable log pane height

	// filterMode is true when the user has pressed / in the Sources pane.
	filterMode  bool
	filterInput string

	quitting bool
}

// newAppModel constructs the initial application model.
func newAppModel(cfg *config.Config, store *manifest.Store, s3client *bos3.Client) appModel {
	logH := cfg.LogWindowHeight
	if logH <= 0 {
		logH = DefaultLogHeight
	}
	m := appModel{
		cfg:       cfg,
		store:     store,
		s3client:  s3client,
		focus:     focusSources,
		logHeight: logH,
	}
	m.sources = newSourcesModel(nil) // populated after S3 status arrives
	m.sources.focused = true
	m.details = newDetailsModel(store, cfg.BuildRoot)
	m.log = newLogPane()
	return m
}

// Init is the bubbletea Init method. It fires the initial S3 status check.
func (m appModel) Init() tea.Cmd {
	return m.fetchS3Status()
}

// fetchS3Status returns a command that checks S3 status for all types.
func (m appModel) fetchS3Status() tea.Cmd {
	if m.s3client == nil {
		return nil
	}
	store := m.store
	client := m.s3client
	return func() tea.Msg {
		statuses, err := bos3.CheckStatus(context.Background(), client, store, manifest.AllTypes)
		return s3StatusMsg{statuses: statuses, err: err}
	}
}

// Update handles all incoming messages.
func (m appModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.relayout()
		return m, nil

	case s3StatusMsg:
		if msg.err != nil {
			m.log.appendLog(errorStyle.Render("S3 status check failed: " + msg.err.Error()))
		}
		m.statuses = msg.statuses
		m.sources.Refresh(m.store, m.statuses)
		if m.sources.cursor == 0 && len(m.sources.flatList) > 0 {
			m.syncDetails()
		}
		return m, nil

	case storeRefreshMsg:
		m.store = msg.store
		m.details.store = msg.store
		m.sources.Refresh(m.store, m.statuses)
		m.syncDetails()
		return m, m.fetchS3Status()

	case cmdOutputMsg:
		if msg.err == errQuit {
			m.quitting = true
			return m, tea.Quit
		}
		if msg.output != "" {
			m.log.appendLog(msg.output)
		}
		if msg.err != nil {
			m.log.appendLog(errorStyle.Render("Error: " + msg.err.Error()))
		}
		if msg.refresh {
			cfg := m.cfg
			s3c := m.s3client
			return m, func() tea.Msg {
				var store *manifest.Store
				var err error
				if cfg.LocalConfig || s3c == nil {
					store, err = manifest.LoadAll(cfg.ManifestDir)
				} else {
					backend := &manifest.S3Backend{
						Prefix: "manifests/",
						GetFn:  s3c.GetObject,
						PutFn:  s3c.PutBytes,
						Label_: fmt.Sprintf("s3://%s/manifests/", cfg.Bucket),
					}
					store, err = manifest.LoadAllFromBackend(context.Background(), backend)
				}
				if err != nil {
					return cmdOutputMsg{err: fmt.Errorf("reload manifests: %w", err)}
				}
				return storeRefreshMsg{store: store}
			}
		}
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	return m, nil
}

// handleKey processes keyboard events, delegating to the focused pane.
func (m appModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.popup.Active() {
		return m.handlePopupKey(msg)
	}
	if m.filterMode {
		return m.handleFilterKey(msg)
	}

	switch msg.String() {
	case "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	case "tab":
		m = m.toggleFocus()
		return m, nil
	}

	if m.focus == focusSources {
		return m.handleSourcesKey(msg)
	}
	return m.handleLogKey(msg)
}

// handlePopupKey dispatches key events to the appropriate popup handler.
// For popups that carry an async command (confirm, build menu), the command
// is stored in popup.pendingAsyncCmd and returned here after dismissal so
// bubbletea can dispatch it.
func (m appModel) handlePopupKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	switch m.popup.kind {
	case popupBuildMenu:
		dismissed := m.popup.HandleBuildMenuKey(key)
		if dismissed {
			cmd := m.popup.pendingAsyncCmd
			m.popup.pendingAsyncCmd = nil
			return m, cmd
		}
		return m, nil

	case popupForm:
		// JSON overlay intercepts all input when active.
		if m.popup.jsonInput {
			applyFn := m.makeJSONApplyFn()
			dismissed, cmd := m.popup.HandleJSONOverlayKey(msg, applyFn)
			_ = dismissed
			return m, cmd
		}

		// Open JSON overlay on "j" key (before printable-rune handling).
		if key == "j" && !m.popup.selectOpen {
			initialJSON := formFieldsToJSON(m.popup.formFields)
			m.popup.OpenJSONOverlay(m.width, m.height, initialJSON, m.popup.formTitle)
			return m, nil
		}

		// Ctrl+T: load defaults into form fields.
		if key == "ctrl+t" && !m.popup.selectOpen {
			m.popup.formFields = configDefaultFields()
			if m.popup.onChange != nil {
				m.popup.onChange(&m.popup)
			}
			m.log.appendLog(dimStyle.Render("Config form populated with defaults"))
			return m, nil
		}

		// Ctrl+R: reset to defaults with confirmation.
		if key == "ctrl+r" && !m.popup.selectOpen {
			// Stash the current form state and show a confirm popup.
			// On confirm, populate defaults and save.
			m.popup = popupModel{
				kind:    popupConfirm,
				message: "Reset configuration to defaults? This will overwrite the config file.",
				onYes: func() {
					m.cfg.Bucket = ""
					m.cfg.Region = config.DefaultRegion
					m.cfg.BuildRoot = config.DefaultBuildRoot
					m.cfg.ManifestDir = "manifests"
					m.cfg.LogDir = config.DefaultLogDir
					m.cfg.LogWindowHeight = config.DefaultLogWindowHeight
					m.cfg.CustomPaths = false
					m.cfg.AptRoot = ""
					m.cfg.GitRoot = ""
					m.cfg.PypiRoot = ""
					m.cfg.BinaryRoot = ""
					if err := m.cfg.Save(); err != nil {
						m.log.appendLog(errorStyle.Render("Failed to save: " + err.Error()))
					} else {
						m.log.appendLog(successStyle.Render("Config reset to defaults and saved to " + config.ConfigPath()))
					}
				},
				pendingAsyncCmd: nil,
			}
			return m, nil
		}

		// Printable runes (not control keys) go to the active field.
		if len(msg.Runes) == 1 {
			isControl := key == "enter" || key == "tab" || key == "shift+tab" || key == "backspace" || key == "esc" ||
				key == "up" || key == "down" || key == "left" || key == "right" || key == "home" || key == "end"
			// Space is a control key on checkbox fields and Select fields.
			if key == " " && m.popup.formCursor < len(m.popup.formFields) {
				f := m.popup.formFields[m.popup.formCursor]
				if f.Checkbox || f.Select {
					isControl = true
				}
			}
			if !isControl {
				m.popup.HandleFormRune(msg.Runes[0])
				return m, nil
			}
		}
		dismissed := m.popup.HandleFormKey(key)
		if dismissed {
			return m, nil
		}
		return m, nil

	default:
		// popupConfirm and popupHelp.
		switch key {
		case "y", "Y":
			cmd := m.popup.pendingAsyncCmd
			m.popup.confirm() // calls onYes synchronously, then clears popup
			return m, tea.Batch(cmd, m.fetchS3Status())
		case "n", "N", "esc", "?":
			m.popup.dismiss()
		}
		return m, nil
	}
}

// handleFilterKey handles keypresses while the / filter is active.
func (m appModel) handleFilterKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "enter":
		m.filterMode = false
	case "backspace":
		if len(m.filterInput) > 0 {
			runes := []rune(m.filterInput)
			m.filterInput = string(runes[:len(runes)-1])
		}
		m.sources.SetFilter(m.filterInput)
	default:
		if len(msg.Runes) == 1 {
			m.filterInput += string(msg.Runes)
			m.sources.SetFilter(m.filterInput)
		}
	}
	m.syncDetails()
	return m, nil
}

// handleSourcesKey handles keypresses when Sources pane has focus.
func (m appModel) handleSourcesKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	node := m.sources.Selected()

	switch msg.String() {
	case "up", "k":
		m.sources.CursorUp()
		m.syncDetails()

	case "down", "j":
		m.sources.CursorDown()
		m.syncDetails()

	case "enter":
		m.sources.ToggleExpand()
		m.syncDetails()

	case "q":
		m.popup = popupModel{
			kind:    popupConfirm,
			message: "Quit reman?",
			onYes: func() {
				m.quitting = true
			},
			pendingAsyncCmd: tea.Quit,
		}
		return m, nil

	case "C":
		customVal := "no"
		if m.cfg.CustomPaths {
			customVal = "yes"
		}
		fields := []formField{
			{Label: "Bucket", Value: m.cfg.Bucket},
			{Label: "Region", Value: m.cfg.Region},
			{Label: "Build root", Value: m.cfg.BuildRoot},
			{Label: "Custom paths", Checkbox: true, Value: customVal},
		}
		if m.cfg.CustomPaths {
			fields = append(fields,
				formField{Label: "APT root", Value: m.cfg.AptRoot},
				formField{Label: "Git root", Value: m.cfg.GitRoot},
				formField{Label: "PyPI root", Value: m.cfg.PypiRoot},
				formField{Label: "Binary root", Value: m.cfg.BinaryRoot},
			)
		}
		fields = append(fields,
			formField{Label: "Manifest dir", Value: m.cfg.ManifestDir},
			formField{Label: "Log dir", Value: m.cfg.LogDir},
			formField{Label: "Log window height", Value: fmt.Sprintf("%d", m.cfg.LogWindowHeight)},
		)
		cfgRef := m.cfg // capture for closures
		p := popupModel{
			kind:       popupForm,
			formTitle:  "Configure reman (" + config.ConfigPath() + ")",
			formFields: fields,
			onChange: func(p *popupModel) {
				// When Custom paths is toggled, show/hide per-type fields.
				custom := fieldValue(p.formFields, "Custom paths") == "yes"
				hasPerType := false
				for _, f := range p.formFields {
					if f.Label == "APT root" {
						hasPerType = true
						break
					}
				}
				if custom && !hasPerType {
					buildRoot := fieldValue(p.formFields, "Build root")
					p.formFields = append(p.formFields,
						formField{Label: "APT root", Value: buildRoot},
						formField{Label: "Git root", Value: buildRoot},
						formField{Label: "PyPI root", Value: buildRoot},
						formField{Label: "Binary root", Value: buildRoot},
					)
				} else if !custom && hasPerType {
					var filtered []formField
					for _, f := range p.formFields {
						if f.Label != "APT root" && f.Label != "Git root" && f.Label != "PyPI root" && f.Label != "Binary root" {
							filtered = append(filtered, f)
						}
					}
					p.formFields = filtered
					if p.formCursor >= len(p.formFields) {
						p.formCursor = len(p.formFields) - 1
					}
				}
			},
			onFormSave: func(fields []formField) {
				cfgRef.Bucket = fieldValue(fields, "Bucket")
				cfgRef.Region = fieldValue(fields, "Region")
				cfgRef.BuildRoot = fieldValue(fields, "Build root")
				cfgRef.ManifestDir = fieldValue(fields, "Manifest dir")
				cfgRef.LogDir = fieldValue(fields, "Log dir")
				if h := fieldValue(fields, "Log window height"); h != "" {
					var v int
					if _, err := fmt.Sscanf(h, "%d", &v); err == nil && v > 0 {
						cfgRef.LogWindowHeight = v
					}
				}
				cfgRef.CustomPaths = fieldValue(fields, "Custom paths") == "yes"
				cfgRef.AptRoot = fieldValue(fields, "APT root")
				cfgRef.GitRoot = fieldValue(fields, "Git root")
				cfgRef.PypiRoot = fieldValue(fields, "PyPI root")
				cfgRef.BinaryRoot = fieldValue(fields, "Binary root")
				if err := cfgRef.Save(); err != nil {
					m.log.appendLog(errorStyle.Render("Failed to save config: " + err.Error()))
				} else {
					m.log.appendLog(successStyle.Render("Config saved to " + config.ConfigPath()))
				}
			},
		}
		m.popup = p
		return m, nil

	case "?":
		m.popup.kind = popupHelp

	case "/":
		m.filterMode = true
		m.filterInput = ""
		m.sources.SetFilter("")

	case " ":
		// Expand/collapse group (same as Enter).
		m.sources.ToggleExpand()
		m.syncDetails()

	case "m":
		// Toggle mark on current entry (or group children).
		m.sources.ToggleMark()

	case "ctrl+a":
		// Select/deselect all entries.
		m.sources.SelectAll()

	case "b", "B":
		// Open build menu for marked entries (or current entry if none marked).
		entries := m.sources.MarkedEntries()
		if len(entries) == 0 {
			return m, nil
		}

		cfg := m.cfg
		store := m.store
		s3client := m.s3client

		// Build a title showing what will be built.
		var title string
		if len(entries) == 1 {
			title = "Build: " + entries[0].Label
		} else {
			title = fmt.Sprintf("Build: %d selected package(s)", len(entries))
		}

		// Capture the entries for the closure.
		buildEntries := make([]struct{ typ, name string }, len(entries))
		for i, e := range entries {
			buildEntries[i] = struct{ typ, name string }{e.EntryType, e.Name}
		}

		p := popupModel{
			kind:       popupBuildMenu,
			buildTitle: title,
		}
		p.onBuildSelect = func(stage BuildStage) tea.Cmd {
			// Run entries sequentially to prevent log interleaving.
			var cmds []tea.Cmd
			for _, be := range buildEntries {
				cmds = append(cmds, executeStage(stage, be.typ, be.name, cfg, store, s3client))
			}
			m.sources.ClearMarks()
			return tea.Sequence(cmds...)
		}
		m.popup = p
		return m, nil

	case "S":
		if m.s3client == nil {
			m.log.appendLog(errorStyle.Render("sync requires a configured S3 bucket"))
			return m, nil
		}
		m.log.appendLog(dimStyle.Render("Syncing all artifacts to S3..."))
		return m, executeSyncAll(nil, m.cfg, m.store, m.s3client)

	case "I":
		if m.s3client == nil {
			m.log.appendLog(errorStyle.Render("init requires a configured S3 bucket"))
			return m, nil
		}
		m.popup = popupModel{
			kind:            popupConfirm,
			message:         fmt.Sprintf("Initialise S3 bucket s3://%s — are you sure?", m.cfg.Bucket),
			pendingAsyncCmd: executeInit(m.cfg, m.s3client),
		}
		return m, nil

	case "v":
		m.log.appendLog(dimStyle.Render("Verifying manifests..."))
		return m, executeVerify(m.cfg, m.store)

	case "c":
		m.popup = m.buildCreatePopup()

	case "E":
		if node == nil || node.IsGroup {
			return m, nil
		}
		m.popup = popupModel{
			kind:       popupForm,
			formTitle:  "Edit: " + node.EntryType + "/" + node.Name,
			formFields: buildEditFields(m.store, node),
			onFormSave: func(fields []formField) {
				m.log.appendLog(dimStyle.Render(
					"Edit saved in form — direct manifest editing not yet wired. Use the CLI to apply changes.",
				))
			},
		}

	case "D":
		if node == nil || node.IsGroup {
			return m, nil
		}
		m.popup = popupModel{
			kind:            popupConfirm,
			message:         fmt.Sprintf("Delete %s/%s from manifest — are you sure?", node.EntryType, node.Name),
			pendingAsyncCmd: executeDelete(node.EntryType, node.Name, m.store, m.s3client, m.cfg),
		}

	case "R":
		if node == nil || node.IsGroup {
			return m, nil
		}
		m.popup = popupModel{
			kind:            popupConfirm,
			message:         fmt.Sprintf("Remove %s/%s artifact from S3 — are you sure?", node.EntryType, node.Name),
			pendingAsyncCmd: executeRemoveFromS3(node.EntryType, node.Name, m.store, m.s3client, m.cfg),
		}

	case "F":
		if node == nil || node.IsGroup {
			return m, nil
		}
		return m, executeFreeze(node.EntryType, node.Name, m.store)
	}

	return m, nil
}

// handleLogKey handles keypresses when Log pane has focus.
func (m appModel) handleLogKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		m.log.ScrollUp()
	case "down", "j":
		m.log.ScrollDown()
	case "tab", "esc":
		m = m.toggleFocus()
	case "q":
		m.popup = popupModel{
			kind:    popupConfirm,
			message: "Quit reman?",
			onYes: func() {
				m.quitting = true
			},
			pendingAsyncCmd: tea.Quit,
		}
		return m, nil
	}
	return m, nil
}

// toggleFocus switches keyboard focus between Sources and Log panes.
func (m appModel) toggleFocus() appModel {
	if m.focus == focusSources {
		m.focus = focusLog
		m.sources.focused = false
		m.log.Focus()
	} else {
		m.focus = focusSources
		m.sources.focused = true
		m.log.Blur()
	}
	return m
}

// syncDetails pushes the currently selected tree node to the details pane.
func (m *appModel) syncDetails() {
	m.details.SetNode(m.sources.Selected())
}

// fieldValue returns the Value for the first form field whose Label matches key,
// or an empty string if not found.
func fieldValue(fields []formField, key string) string {
	for _, f := range fields {
		if f.Label == key {
			return f.Value
		}
	}
	return ""
}

// buildEditFields constructs a pre-populated form field slice from a tree node.
func buildEditFields(store *manifest.Store, node *TreeNode) []formField {
	switch node.EntryType {
	case manifest.TypeApt:
		e := store.FindApt(node.Name)
		if e == nil {
			return []formField{{Label: "Name", Value: node.Name}}
		}
		return []formField{
			{Label: "Name", Value: e.Name},
			{Label: "Version", Value: e.Version},
			{Label: "URL", Value: e.URL},
			{Label: "BuildCmd", Value: e.BuildCmd},
			{Label: "Validate source", Checkbox: true, Value: "yes"},
		}
	case manifest.TypeGit:
		e := store.FindGit(node.Name)
		if e == nil {
			return []formField{{Label: "Name", Value: node.Name}}
		}
		return []formField{
			{Label: "Name", Value: e.Name},
			{Label: "Ref", Value: e.Ref},
			{Label: "URL", Value: e.URL},
			{Label: "Validate source", Checkbox: true, Value: "yes"},
		}
	case manifest.TypeBinary:
		e := store.FindBinary(node.Name)
		if e == nil {
			return []formField{{Label: "Name", Value: node.Name}}
		}
		fields := []formField{
			{Label: "Name", Value: e.Name},
			{Label: "Version", Value: e.Version},
			{Label: "URL", Value: e.URL},
		}
		if e.Filename != "" {
			fields = append(fields, formField{Label: "Filename", Value: e.Filename})
		}
		fields = append(fields, formField{Label: "Validate source", Checkbox: true, Value: "yes"})
		return fields
	case manifest.TypePypi:
		return []formField{
			{Label: "Version", Value: store.Pypi.Version},
			{Label: "Validate source", Checkbox: true, Value: "yes"},
		}
	}
	return []formField{{Label: "Name", Value: node.Name}}
}

// --- Create form helpers ---

// buildCreatePopup constructs the initial popupModel for the "c" create flow.
// It starts with only the Type Select field; the onChange hook rebuilds the
// remaining fields when the user confirms a type selection.
func (m *appModel) buildCreatePopup() popupModel {
	store := m.store
	logPane := &m.log

	p := popupModel{
		kind:      popupForm,
		formTitle: "Create Entry",
		formFields: []formField{
			{
				Label:   "Type",
				Value:   manifest.TypeApt,
				Select:  true,
				Options: []string{manifest.TypeApt, manifest.TypeGit, manifest.TypePypi, manifest.TypeBinary},
			},
		},
	}

	// Expand to full field set for the default type immediately so the form is
	// useful without requiring the user to first open the submenu.
	p.formFields = rebuildCreateFields(manifest.TypeApt, p.formFields)

	p.onChange = func(pp *popupModel) {
		entryType := fieldValueFromSlice(pp.formFields, "Type")
		pp.formFields = rebuildCreateFields(entryType, pp.formFields)
		// Update checksum hint on every change.
		updateChecksumHint(pp.formFields)
	}

	p.validate = func(fields []formField) string {
		return validateCreateFields(fields)
	}

	p.onFormSave = func(fields []formField) {
		if err := saveCreateEntry(store, fields); err != nil {
			logPane.appendLog(errorStyle.Render("Create failed: " + err.Error()))
		} else {
			entryType := fieldValueFromSlice(fields, "Type")
			name := fieldValueFromSlice(fields, "Name")
			logPane.appendLog(successStyle.Render(
				fmt.Sprintf("Created %s/%s", entryType, name),
			))
		}
	}

	return p
}

// rebuildCreateFields returns a new field slice appropriate for entryType,
// carrying over any values already entered into matching fields from prev.
// The Type field (index 0) is always preserved as the first element.
func rebuildCreateFields(entryType string, prev []formField) []formField {
	prevValues := make(map[string]string, len(prev))
	for _, f := range prev {
		prevValues[f.Label] = f.Value
	}

	typeField := formField{
		Label:   "Type",
		Value:   entryType,
		Select:  true,
		Options: []string{manifest.TypeApt, manifest.TypeGit, manifest.TypePypi, manifest.TypeBinary},
	}

	restore := func(label, defaultVal string) string {
		if v, ok := prevValues[label]; ok && v != "" {
			return v
		}
		return defaultVal
	}

	switch entryType {
	case manifest.TypeGit:
		return []formField{
			typeField,
			{Label: "Name", Value: restore("Name", "")},
			{Label: "URL", Value: restore("URL", "")},
			{Label: "Ref", Value: restore("Ref", "")},
			{Label: "Frozen", Value: restore("Frozen", "no"), Checkbox: true},
		}

	case manifest.TypePypi:
		return []formField{
			typeField,
			{Label: "Name", Value: restore("Name", ""),
				Hint: "pip package specifier, e.g. boto3 or social-auth-core[openidconnect]"},
			{Label: "Required By", Value: restore("Required By", ""),
				Hint: "comma-separated, e.g. netbox,standalone"},
			{Label: "Frozen", Value: restore("Frozen", "no"), Checkbox: true},
		}

	case manifest.TypeBinary:
		latestVal := restore("Latest", "no")
		versionDisabled := latestVal == "yes"
		versionVal := restore("Version", "")
		if versionDisabled {
			versionVal = "latest"
		}
		checksumVal := restore("Checksum", "")
		return []formField{
			typeField,
			{Label: "Name", Value: restore("Name", "")},
			{Label: "Version", Value: versionVal, Disabled: versionDisabled},
			{Label: "URL", Value: restore("URL", "")},
			{Label: "Filename", Value: restore("Filename", ""),
				Hint: "leave empty to derive from URL"},
			{Label: "Checksum", Value: checksumVal,
				Hint: checksumHint(checksumVal)},
			{Label: "Latest", Value: latestVal, Checkbox: true},
			{Label: "Frozen", Value: restore("Frozen", "no"), Checkbox: true},
		}

	default: // manifest.TypeApt
		checksumVal := restore("Checksum", "")
		return []formField{
			typeField,
			{Label: "Name", Value: restore("Name", "")},
			{Label: "Version", Value: restore("Version", "")},
			{Label: "URL", Value: restore("URL", ""),
				Hint: "git repo URL for source build; leave empty for apt repo"},
			{Label: "Source Name", Value: restore("Source Name", ""),
				Hint: "upstream package name; defaults to Name"},
			{Label: "Build Cmd", Value: restore("Build Cmd", "")},
			{Label: "Deb Glob", Value: restore("Deb Glob", "")},
			{Label: "Checksum", Value: checksumVal,
				Hint: checksumHint(checksumVal)},
			{Label: "Frozen", Value: restore("Frozen", "no"), Checkbox: true},
		}
	}
}

// updateChecksumHint refreshes the Hint on any Checksum field based on its current Value.
func updateChecksumHint(fields []formField) {
	for i := range fields {
		if fields[i].Label == "Checksum" {
			fields[i].Hint = checksumHint(fields[i].Value)
		}
		// Handle Latest ↔ Version coupling for binary entries.
		if fields[i].Label == "Latest" {
			latestOn := fields[i].Value == "yes"
			for j := range fields {
				if fields[j].Label == "Version" {
					fields[j].Disabled = latestOn
					if latestOn {
						fields[j].Value = "latest"
					} else if fields[j].Value == "latest" {
						fields[j].Value = ""
					}
				}
			}
		}
		// Auto-fill Name from URL when cursor moved away from URL.
		if fields[i].Label == "URL" {
			urlVal := fields[i].Value
			if urlVal != "" {
				for j := range fields {
					if fields[j].Label == "Name" && fields[j].Value == "" {
						entryType := fieldValueFromSlice(fields, "Type")
						fields[j].Value = extractNameFromURL(urlVal, entryType)
						fields[j].cursor = len([]rune(fields[j].Value))
					}
				}
			}
		}
	}
}

// validateCreateFields returns a non-empty error message when the fields are not
// ready to be saved, or an empty string when everything is valid.
func validateCreateFields(fields []formField) string {
	entryType := fieldValueFromSlice(fields, "Type")
	if !isValidType(entryType) {
		return "select a valid type (apt/git/pypi/binary)"
	}
	name := fieldValueFromSlice(fields, "Name")
	if name == "" {
		return "Name is required"
	}
	switch entryType {
	case manifest.TypeGit:
		if fieldValueFromSlice(fields, "URL") == "" {
			return "URL is required for git entries"
		}
		if fieldValueFromSlice(fields, "Ref") == "" {
			return "Ref is required for git entries"
		}
	case manifest.TypeBinary:
		if fieldValueFromSlice(fields, "URL") == "" {
			return "URL is required for binary entries"
		}
	}
	// Block save if checksum is present but invalid.
	chk := fieldValueFromSlice(fields, "Checksum")
	if chk != "" && detectChecksumAlgorithm(chk) == "" {
		return "invalid checksum value"
	}
	return ""
}

// saveCreateEntry builds the appropriate manifest entry from fields and appends
// it to the store, then persists the manifest to disk.
func saveCreateEntry(store *manifest.Store, fields []formField) error {
	entryType := fieldValueFromSlice(fields, "Type")
	name := fieldValueFromSlice(fields, "Name")

	var chksum *manifest.Checksum
	if chkVal := fieldValueFromSlice(fields, "Checksum"); chkVal != "" {
		algo := detectChecksumAlgorithm(chkVal)
		if algo != "" {
			chksum = &manifest.Checksum{Algorithm: algo, Value: chkVal}
		}
	}

	frozen := fieldValueFromSlice(fields, "Frozen") == "yes"

	switch entryType {
	case manifest.TypeApt:
		entry := manifest.AptEntry{
			Name:       name,
			Version:    fieldValueFromSlice(fields, "Version"),
			URL:        fieldValueFromSlice(fields, "URL"),
			SourceName: fieldValueFromSlice(fields, "Source Name"),
			BuildCmd:   fieldValueFromSlice(fields, "Build Cmd"),
			DebGlob:    fieldValueFromSlice(fields, "Deb Glob"),
			Checksum:   chksum,
			Frozen:     frozen,
		}
		store.Apt = append(store.Apt, entry)
		return store.SaveApt()

	case manifest.TypeGit:
		entry := manifest.GitEntry{
			Name:   name,
			URL:    fieldValueFromSlice(fields, "URL"),
			Ref:    fieldValueFromSlice(fields, "Ref"),
			Frozen: frozen,
		}
		store.Git = append(store.Git, entry)
		return store.SaveGit()

	case manifest.TypePypi:
		var requiredBy []string
		if rb := fieldValueFromSlice(fields, "Required By"); rb != "" {
			for _, s := range strings.Split(rb, ",") {
				s = strings.TrimSpace(s)
				if s != "" {
					requiredBy = append(requiredBy, s)
				}
			}
		}
		entry := manifest.PypiPackage{
			Name:       name,
			RequiredBy: requiredBy,
			Checksum:   chksum,
			Frozen:     frozen,
		}
		store.Pypi.Packages = append(store.Pypi.Packages, entry)
		return store.SavePypi()

	case manifest.TypeBinary:
		entry := manifest.BinaryEntry{
			Name:     name,
			Version:  fieldValueFromSlice(fields, "Version"),
			URL:      fieldValueFromSlice(fields, "URL"),
			Filename: fieldValueFromSlice(fields, "Filename"),
			Checksum: chksum,
			Frozen:   frozen,
		}
		store.Binary = append(store.Binary, entry)
		return store.SaveBinary()

	default:
		return fmt.Errorf("unknown entry type %q", entryType)
	}
}

// makeJSONApplyFn returns the function passed to HandleJSONOverlayKey that
// parses the JSON buffer and populates the form fields from it.
func (m *appModel) makeJSONApplyFn() func(buf string) string {
	p := &m.popup
	return func(buf string) string {
		entryType := fieldValueFromSlice(p.formFields, "Type")
		switch entryType {
		case manifest.TypeApt:
			var e manifest.AptEntry
			if err := json.Unmarshal([]byte(buf), &e); err != nil {
				return "invalid JSON: " + err.Error()
			}
			p.formFields = rebuildCreateFields(entryType, p.formFields)
			setFieldValue(p.formFields, "Name", e.Name)
			setFieldValue(p.formFields, "Version", e.Version)
			setFieldValue(p.formFields, "URL", e.URL)
			setFieldValue(p.formFields, "Source Name", e.SourceName)
			setFieldValue(p.formFields, "Build Cmd", e.BuildCmd)
			setFieldValue(p.formFields, "Deb Glob", e.DebGlob)
			if e.Checksum != nil {
				setFieldValue(p.formFields, "Checksum", e.Checksum.Value)
			}
			if e.Frozen {
				setFieldValue(p.formFields, "Frozen", "yes")
			}

		case manifest.TypeGit:
			var e manifest.GitEntry
			if err := json.Unmarshal([]byte(buf), &e); err != nil {
				return "invalid JSON: " + err.Error()
			}
			p.formFields = rebuildCreateFields(entryType, p.formFields)
			setFieldValue(p.formFields, "Name", e.Name)
			setFieldValue(p.formFields, "URL", e.URL)
			setFieldValue(p.formFields, "Ref", e.Ref)
			if e.Frozen {
				setFieldValue(p.formFields, "Frozen", "yes")
			}

		case manifest.TypePypi:
			var e manifest.PypiPackage
			if err := json.Unmarshal([]byte(buf), &e); err != nil {
				return "invalid JSON: " + err.Error()
			}
			p.formFields = rebuildCreateFields(entryType, p.formFields)
			setFieldValue(p.formFields, "Name", e.Name)
			if len(e.RequiredBy) > 0 {
				setFieldValue(p.formFields, "Required By", strings.Join(e.RequiredBy, ", "))
			}
			if e.Checksum != nil {
				setFieldValue(p.formFields, "Checksum", e.Checksum.Value)
			}
			if e.Frozen {
				setFieldValue(p.formFields, "Frozen", "yes")
			}

		case manifest.TypeBinary:
			var e manifest.BinaryEntry
			if err := json.Unmarshal([]byte(buf), &e); err != nil {
				return "invalid JSON: " + err.Error()
			}
			p.formFields = rebuildCreateFields(entryType, p.formFields)
			setFieldValue(p.formFields, "Name", e.Name)
			setFieldValue(p.formFields, "Version", e.Version)
			setFieldValue(p.formFields, "URL", e.URL)
			setFieldValue(p.formFields, "Filename", e.Filename)
			if e.Checksum != nil {
				setFieldValue(p.formFields, "Checksum", e.Checksum.Value)
			}
			if e.Frozen {
				setFieldValue(p.formFields, "Frozen", "yes")
			}

		default:
			return fmt.Sprintf("unknown entry type %q — set Type field first", entryType)
		}
		updateChecksumHint(p.formFields)
		return ""
	}
}

// detectChecksumAlgorithm infers the hash algorithm from the hex string length.
// Returns "md5" (32), "sha1" (40), "sha256" (64), "sha512" (128), or "" for
// unrecognised input. The empty string is also returned for an empty input.
func detectChecksumAlgorithm(hex string) string {
	if hex == "" {
		return ""
	}
	for _, c := range hex {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return ""
		}
	}
	switch len(hex) {
	case 32:
		return "md5"
	case 40:
		return "sha1"
	case 64:
		return "sha256"
	case 128:
		return "sha512"
	default:
		return ""
	}
}

// checksumHint returns the appropriate Hint string for a Checksum field value.
func checksumHint(val string) string {
	if val == "" {
		return "(optional — auto-generated on build)"
	}
	algo := detectChecksumAlgorithm(val)
	if algo != "" {
		return "detected: " + algo
	}
	return "invalid checksum"
}

// extractNameFromURL derives a logical entry name from a URL and entry type.
// For git URLs it strips the .git suffix and returns the repo base name.
// For binary URLs it strips common archive suffixes.
// Returns an empty string when no sensible name can be derived.
func extractNameFromURL(rawURL, entryType string) string {
	seg := lastURLSegment(rawURL)
	if seg == "" {
		return ""
	}
	switch entryType {
	case manifest.TypeGit:
		seg = strings.TrimSuffix(seg, ".git")
	case manifest.TypeBinary, manifest.TypeApt:
		for _, ext := range []string{".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip", ".deb", ".rpm"} {
			if strings.HasSuffix(seg, ext) {
				seg = seg[:len(seg)-len(ext)]
				break
			}
		}
	}
	return seg
}

// fieldValueFromSlice is like fieldValue but operates on a plain slice (not the
// appModel — useful inside closures that do not have access to the receiver).
func fieldValueFromSlice(fields []formField, key string) string {
	for _, f := range fields {
		if f.Label == key {
			return f.Value
		}
	}
	return ""
}

// setFieldValue updates the Value of the first field whose Label matches key.
// It also resets the field's cursor to the end of the new value.
func setFieldValue(fields []formField, key, value string) {
	for i := range fields {
		if fields[i].Label == key {
			fields[i].Value = value
			fields[i].cursor = len([]rune(value))
			return
		}
	}
}

// configDefaultFields returns the config form fields populated with default values.
func configDefaultFields() []formField {
	return []formField{
		{Label: "Bucket", Value: ""},
		{Label: "Region", Value: config.DefaultRegion},
		{Label: "Build root", Value: config.DefaultBuildRoot},
		{Label: "Custom paths", Checkbox: true, Value: "no"},
		{Label: "Manifest dir", Value: "manifests"},
		{Label: "Log dir", Value: config.DefaultLogDir},
		{Label: "Log window height", Value: fmt.Sprintf("%d", config.DefaultLogWindowHeight)},
	}
}

// formFieldsToJSON builds a JSON object from the current form fields.
// Checkbox fields are omitted. Select/Disabled fields are included.
func formFieldsToJSON(fields []formField) string {
	m := make(map[string]string)
	for _, f := range fields {
		if f.Checkbox || f.Value == "" {
			continue
		}
		m[f.Label] = f.Value
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(data)
}

// DefaultLogHeight is the default number of content lines for the log pane.
const DefaultLogHeight = 12

// relayout recalculates pane dimensions from the terminal size.
func (m *appModel) relayout() {
	if m.width == 0 || m.height == 0 {
		return
	}

	border := paneStyle(false)
	frameW, frameH := border.GetFrameSize()

	availH := m.height - 1

	logContentH := m.logHeight
	if logContentH < 4 {
		logContentH = 4
	}
	logTotalH := logContentH + frameH

	topTotalH := availH - logTotalH
	if topTotalH < frameH+2 {
		topTotalH = frameH + 2
	}
	topContentH := topTotalH - frameH

	sourcesTotalW := m.width * 40 / 100
	if sourcesTotalW < 20+frameW {
		sourcesTotalW = 20 + frameW
	}
	detailsTotalW := m.width - sourcesTotalW

	sourcesContentW := sourcesTotalW - frameW
	detailsContentW := detailsTotalW - frameW
	logContentW := m.width - frameW

	m.sources.width = sourcesContentW
	m.sources.height = topContentH
	m.details.width = detailsContentW
	m.details.height = topContentH
	m.log.SetSize(logContentW, logContentH)
}

// View renders the full screen.
func (m appModel) View() string {
	if m.quitting {
		return ""
	}
	if m.width == 0 {
		return "Initialising..."
	}

	sourcesInner := m.sources.View()
	sourcesPane := paneStyle(m.focus == focusSources).
		Width(m.sources.width).
		Height(m.sources.height).
		Render(sourcesInner)
	sourcesTitle := titleStyle(m.focus == focusSources).Render(" Sources ")
	sourcesPane = overlayTitle(sourcesPane, sourcesTitle)

	if m.filterMode || m.filterInput != "" {
		filterIndicator := dimStyle.Render(" /" + m.filterInput)
		sourcesPane = overlayTitle(sourcesPane, sourcesTitle+filterIndicator)
	}

	detailsInner := m.details.View()
	detailsPane := paneStyle(false).
		Width(m.details.width).
		Height(m.details.height).
		Render(detailsInner)
	detailsTitle := titleStyle(false).Render(" Details ")
	detailsPane = overlayTitle(detailsPane, detailsTitle)

	topRow := lipgloss.JoinHorizontal(lipgloss.Top, sourcesPane, detailsPane)

	logInner := m.log.View()
	logPane := paneStyle(m.focus == focusLog).
		Width(m.log.width).
		Height(m.log.height).
		Render(logInner)
	logTitle := titleStyle(m.focus == focusLog).Render(" Log ")
	logPane = overlayTitle(logPane, logTitle)

	screen := lipgloss.JoinVertical(lipgloss.Left, topRow, logPane)

	if m.popup.Active() {
		popupView := m.popup.View(m.width, m.height)
		if popupView != "" {
			screen = overlayPopup(screen, popupView, m.width, m.height)
		}
	}

	return screen
}

// overlayTitle inserts a title string into the top border of a rendered box.
// It replaces runes starting at position 2 to preserve the multi-byte Unicode
// corner character (╭).
func overlayTitle(box, title string) string {
	lines := strings.Split(box, "\n")
	if len(lines) == 0 {
		return box
	}

	topRunes := []rune(stripAnsi(lines[0]))
	titleRuneLen := len([]rune(stripAnsi(title)))

	if titleRuneLen+3 > len(topRunes) {
		return box
	}

	insertAt := 2
	newTop := string(topRunes[:insertAt]) + title + string(topRunes[insertAt+titleRuneLen:])
	lines[0] = newTop
	return strings.Join(lines, "\n")
}

// overlayPopup places the popup string on top of the screen string.
func overlayPopup(screen, popup string, _, _ int) string {
	_ = screen
	return popup
}

// Run starts the bubbletea program with the given configuration.
func Run(cfg *config.Config, store *manifest.Store, s3client *bos3.Client) error {
	m := newAppModel(cfg, store, s3client)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
