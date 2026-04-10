// Package tui provides the three-pane terminal UI for the bodega shell command.
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
	"net/http"
	"os/exec"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/scaleapi/bodega/internal/audit"
	"github.com/scaleapi/bodega/internal/builder"
	"github.com/scaleapi/bodega/internal/config"
	"github.com/scaleapi/bodega/internal/manifest"
	bos3 "github.com/scaleapi/bodega/internal/s3"
	"github.com/scaleapi/bodega/internal/server"
)

// focusTarget identifies which pane currently has keyboard focus.
type focusTarget int

const (
	focusSources focusTarget = iota
	focusDetails
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
	logHeight int    // configurable log pane height
	logPath   string // session log file path for display

	// filterMode is true when the user has pressed / in the Sources pane.
	filterMode  bool
	filterInput string

	// lastCreated tracks the most recently created entry for post-save focus.
	lastCreatedType string
	lastCreatedName string

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
	m.details = newDetailsModel(store, cfg)
	m.log = newLogPane()
	m.logPath = cfg.LogDir
	return m
}

// Init is the bubbletea Init method. It fires the initial S3 status check.
func (m appModel) Init() tea.Cmd {
	return tea.Batch(m.fetchS3Status(), tea.EnableBracketedPaste)
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
				ctx := context.Background()
				var store *manifest.Store
				var err error
				if cfg.LocalConfig || s3c == nil {
					store = manifest.NewLocalStore(cfg.ManifestDir)
					err = store.LoadIndex(ctx)
				} else {
					backend := &manifest.S3Backend{
						Prefix:   "manifests/",
						GetFn:    s3c.GetObject,
						PutFn:    s3c.PutBytes,
						Label_:   fmt.Sprintf("s3://%s/manifests/", cfg.Bucket),
					}
					store = manifest.NewStore(backend)
					err = store.LoadIndex(ctx)
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
	case "ctrl+r":
		// Reload manifests from backend (S3 or disk).
		m.log.appendLog(dimStyle.Render("Reloading manifests..."))
		cfg := m.cfg
		s3c := m.s3client
		return m, func() tea.Msg {
			ctx := context.Background()
			var store *manifest.Store
			var err error
			if cfg.LocalConfig || s3c == nil {
				store = manifest.NewLocalStore(cfg.ManifestDir)
				err = store.LoadIndex(ctx)
			} else {
				backend := &manifest.S3Backend{
					Prefix:   "manifests/",
					GetFn:    s3c.GetObject,
					PutFn:    s3c.PutBytes,
					Label_:   fmt.Sprintf("s3://%s/manifests/", cfg.Bucket),
				}
				store = manifest.NewStore(backend)
				err = store.LoadIndex(ctx)
			}
			if err != nil {
				return cmdOutputMsg{err: fmt.Errorf("reload manifests: %w", err)}
			}
			return storeRefreshMsg{store: store}
		}
	case "tab":
		m = m.toggleFocus()
		return m, nil
	}

	switch m.focus {
	case focusSources:
		return m.handleSourcesKey(msg)
	case focusDetails:
		return m.handleDetailsKey(msg)
	default:
		return m.handleLogKey(msg)
	}
}

// handleDetailsKey handles keypresses when Details pane has focus.
func (m appModel) handleDetailsKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		m.details.ScrollUp()
	case "down", "j":
		m.details.ScrollDown()
	case "tab", "esc":
		m = m.toggleFocus()
	case "q":
		m.popup = popupModel{
			kind:    popupConfirm,
			message: "Quit bodega?",
			onYes: func() {
				m.quitting = true
			},
			pendingAsyncCmd: tea.Quit,
		}
		return m, nil
	}
	return m, nil
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

		// Bracketed paste: insert all runes at once.
		if msg.Paste && len(msg.Runes) > 0 {
			for _, r := range msg.Runes {
				m.popup.HandleFormRune(r)
			}
			return m, nil
		}

		// Printable runes (not control keys) go to the active field.
		if len(msg.Runes) == 1 {
			isControl := key == "enter" || key == "tab" || key == "shift+tab" || key == "backspace" || key == "esc" ||
				key == "up" || key == "down" || key == "left" || key == "right" || key == "home" || key == "end"
			// Space is a control key on checkbox, Select, and LabelSelect fields.
			if key == " " && m.popup.formCursor < len(m.popup.formFields) {
				f := m.popup.formFields[m.popup.formCursor]
				if f.Checkbox || f.Select || f.LabelSelect {
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
			// Refresh the sources tree in case the form modified the store
			// (create, edit). Harmless no-op if nothing changed.
			m.sources.Refresh(m.store, m.statuses)
			// Navigate to the newly created entry if one was just saved.
			if m.lastCreatedName != "" {
				m.sources.CursorToEntry(m.lastCreatedType, m.lastCreatedName)
				m.lastCreatedType = ""
				m.lastCreatedName = ""
			}
			m.syncDetails()
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
		if len(msg.Runes) > 0 {
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

	case "right", "l":
		m.sources.CursorToFirstChild()
		m.syncDetails()

	case "left", "h":
		m.sources.CursorToParent()
		m.syncDetails()

	case "q":
		m.popup = popupModel{
			kind:    popupConfirm,
			message: "Quit bodega?",
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
			formField{Label: "Deny list", Value: strings.Join(m.cfg.DenyList, ", "),
				Hint: "Comma-separated CIDRs (e.g. 10.0.0.5, 192.168.1.0/24, fd00::/8)"},
		)
		cfgRef := m.cfg // capture for closures
		p := popupModel{
			kind:       popupForm,
			formTitle:  "Configure bodega (" + config.ConfigPath() + ")",
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
			validate: func(fields []formField) string {
				if dl := fieldValue(fields, "Deny list"); dl != "" {
					var entries []string
					for _, s := range strings.Split(dl, ",") {
						if s = strings.TrimSpace(s); s != "" {
							entries = append(entries, s)
						}
					}
					if _, err := server.ParseDenyList(entries); err != nil {
						return err.Error()
					}
				}
				return ""
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
				if dl := fieldValue(fields, "Deny list"); dl != "" {
					var entries []string
					for _, s := range strings.Split(dl, ",") {
						if s = strings.TrimSpace(s); s != "" {
							entries = append(entries, s)
						}
					}
					cfgRef.DenyList = entries
				} else {
					cfgRef.DenyList = nil
				}
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

	case " ", "m":
		// Toggle selection on current entry (and all children recursively).
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
		p.onBuildSelect = func(stage BuildStage, force bool) tea.Cmd {
			// Run entries sequentially to prevent log interleaving.
			var cmds []tea.Cmd
			for _, be := range buildEntries {
				cmds = append(cmds, executeStage(stage, be.typ, be.name, cfg, store, s3client, force))
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

	case "L":
		m.popup = m.buildAuditPopup()
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
				ctx := context.Background()
				pm, err := m.store.GetPackage(ctx, node.EntryType, node.Name)
				if err != nil || pm == nil || len(pm.Versions) == 0 {
					m.log.appendLog(errorStyle.Render("Edit failed: could not load package"))
					return
				}
				ve := &pm.Versions[0]

				// Update fields common to all types.
				if v := fieldValueFromSlice(fields, "Version"); v != "" {
					ve.Version = v
				}
				if u := fieldValueFromSlice(fields, "Source URL"); u != "" {
					ve.URL = u
				} else if !fieldDisabled(fields, "Source URL") {
					ve.URL = ""
				}

				// Type-specific updates.
				switch node.EntryType {
				case manifest.TypeApt:
					ve.SourceName = fieldValueFromSlice(fields, "Package Name")
					ve.BuildCmd = fieldValueFromSlice(fields, "Build Cmd")
					ve.DebGlob = fieldValueFromSlice(fields, "Deb Glob")
					depPolicy := strings.ToLower(fieldValueFromSlice(fields, "Include Deps"))
					if depPolicy == "none" {
						depPolicy = ""
					}
					pm.DepPolicy = depPolicy
				case manifest.TypeGit:
					ve.Ref = fieldValueFromSlice(fields, "Ref")
				case manifest.TypeBinary:
					ve.Filename = fieldValueFromSlice(fields, "Filename")
				}

				if err := m.store.SavePackage(ctx, pm); err != nil {
					m.log.appendLog(errorStyle.Render("Edit failed: " + err.Error()))
					return
				}
				if err := m.store.SaveIndex(ctx); err != nil {
					m.log.appendLog(errorStyle.Render("Save index failed: " + err.Error()))
					return
				}
				m.log.appendLog(successStyle.Render(
					fmt.Sprintf("Updated %s/%s", node.EntryType, node.Name),
				))
			},
		}

	case "H":
		entries := m.sources.MarkedEntries()
		if len(entries) == 0 {
			return m, nil
		}
		for _, e := range entries {
			toggleHidden(m.store, e.EntryType, e.Name)
		}
		m.sources.Refresh(m.store, m.statuses)
		m.syncDetails()
		count := len(entries)
		if count == 1 {
			m.log.appendLog(dimStyle.Render(fmt.Sprintf("Toggled hidden on %s/%s", entries[0].EntryType, entries[0].Name)))
		} else {
			m.log.appendLog(dimStyle.Render(fmt.Sprintf("Toggled hidden on %d entries", count)))
		}

	case "d", "D":
		entries := m.sources.MarkedEntries()
		if len(entries) == 0 {
			return m, nil
		}
		var msg string
		if len(entries) == 1 {
			msg = fmt.Sprintf("Delete %s/%s from manifest?", entries[0].EntryType, entries[0].Name)
		} else {
			msg = fmt.Sprintf("Delete %d selected entries from manifests?", len(entries))
		}
		var cmds []tea.Cmd
		for _, e := range entries {
			cmds = append(cmds, executeDelete(e.EntryType, e.Name, m.store, m.s3client, m.cfg))
		}
		m.popup = popupModel{
			kind:            popupConfirm,
			message:         msg,
			pendingAsyncCmd: tea.Sequence(cmds...),
		}

	case "R":
		entries := m.sources.MarkedEntries()
		if len(entries) == 0 {
			return m, nil
		}
		var msg string
		if len(entries) == 1 {
			msg = fmt.Sprintf("Remove %s/%s artifact from S3?", entries[0].EntryType, entries[0].Name)
		} else {
			msg = fmt.Sprintf("Remove %d selected artifacts from S3?", len(entries))
		}
		var cmds []tea.Cmd
		for _, e := range entries {
			cmds = append(cmds, executeRemoveFromS3(e.EntryType, e.Name, m.store, m.s3client, m.cfg))
		}
		m.popup = popupModel{
			kind:            popupConfirm,
			message:         msg,
			pendingAsyncCmd: tea.Sequence(cmds...),
		}

	case "F":
		entries := m.sources.MarkedEntries()
		if len(entries) == 0 {
			return m, nil
		}
		var cmds []tea.Cmd
		for _, e := range entries {
			cmds = append(cmds, executeFreeze(e.EntryType, e.Name, m.store))
		}
		return m, tea.Sequence(cmds...)
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
			message: "Quit bodega?",
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
	m.sources.focused = false
	m.details.focused = false
	m.log.Blur()

	switch m.focus {
	case focusSources:
		m.focus = focusDetails
		m.details.focused = true
	case focusDetails:
		m.focus = focusLog
		m.log.Focus()
	default:
		m.focus = focusSources
		m.sources.focused = true
	}
	return m
}

// syncDetails pushes the currently selected tree node to the details pane.
func (m *appModel) syncDetails() {
	m.details.SetNode(m.sources.Selected())
}

// fieldValue returns the Value for the first form field whose Label matches key,
// or an empty string if not found.
// buildAuditPopup constructs a form popup for querying the audit trail.
func (m *appModel) buildAuditPopup() popupModel {
	logPane := &m.log
	cfg := m.cfg

	p := popupModel{
		kind:      popupForm,
		formTitle: "Audit Log Query",
		formFields: []formField{
			{Label: "Event type", Value: "", Select: true,
				Options: []string{"", "fetch", "build", "create", "delete", "cache"}},
			{Label: "Pkg type", Value: "", Select: true,
				Options: []string{"", "apt", "git", "pypi", "binary", "gomod", "helm", "npm"}},
			{Label: "Pkg name", Value: ""},
			{Label: "Client IP", Value: ""},
			{Label: "Limit", Value: "50"},
		},
	}

	p.onFormSave = func(fields []formField) {
		db, err := audit.Open(cfg.AuditDB)
		if err != nil {
			logPane.appendLog(errorStyle.Render("Could not open audit db: " + err.Error()))
			return
		}
		defer db.Close()

		limit := 50
		if l := fieldValue(fields, "Limit"); l != "" {
			if v, err := fmt.Sscanf(l, "%d", &limit); v != 1 || err != nil {
				limit = 50
			}
		}

		f := audit.Filter{
			EventType: audit.EventType(fieldValue(fields, "Event type")),
			PkgType:   fieldValue(fields, "Pkg type"),
			PkgName:   fieldValue(fields, "Pkg name"),
			ClientIP:  fieldValue(fields, "Client IP"),
			Limit:     limit,
		}

		ctx := context.Background()
		events, err := db.Query(ctx, f)
		if err != nil {
			logPane.appendLog(errorStyle.Render("Audit query failed: " + err.Error()))
			return
		}

		if len(events) == 0 {
			logPane.appendLog(dimStyle.Render("No matching audit events."))
			return
		}

		logPane.appendLog(dimStyle.Render(fmt.Sprintf("── Audit Log (%d events) ──", len(events))))
		logPane.appendLog(fmt.Sprintf("%-20s %-8s %-8s %-30s %-10s %-15s %s",
			"TIMESTAMP", "EVENT", "TYPE", "NAME", "STATUS", "CLIENT", "DURATION"))

		for _, ev := range events {
			dur := ""
			if ev.DurationMs > 0 {
				dur = fmt.Sprintf("%dms", ev.DurationMs)
			}
			ts := ev.Timestamp.Format("2006-01-02 15:04:05")
			name := ev.PkgName
			if ev.PkgVersion != "" {
				name += "@" + ev.PkgVersion
			}
			logPane.appendLog(fmt.Sprintf("%-20s %-8s %-8s %-30s %-10s %-15s %s",
				ts, ev.EventType, ev.PkgType, name, ev.Status, ev.ClientIP, dur))
		}
	}

	return p
}

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
	ctx := context.Background()
	pm, err := store.GetPackage(ctx, node.EntryType, node.Name)
	if err != nil || pm == nil || len(pm.Versions) == 0 {
		return []formField{{Label: "Name", Value: node.Name}}
	}
	ve := pm.Versions[0]
	switch node.EntryType {
	case manifest.TypeApt:
		// Determine mode from existing data.
		aptMode := "Package Name"
		buildFrom := "Git repo"
		if ve.URL != "" && ve.BuildCmd != "" {
			aptMode = "Source Build"
			buildFrom = "Git repo"
		} else if ve.URL != "" {
			aptMode = "Direct URL"
		} else if ve.BuildCmd != "" {
			aptMode = "Source Build"
			buildFrom = "apt-get source"
		}

		isPkgName := aptMode == "Package Name"
		isDirectURL := aptMode == "Direct URL"
		isSourceBuild := aptMode == "Source Build"
		isBuildFromGit := isSourceBuild && buildFrom == "Git repo"
		isBuildFromAptSrc := isSourceBuild && buildFrom == "apt-get source"

		depPolicy := "None"
		if pm.DepPolicy == "direct" {
			depPolicy = "Direct"
		} else if pm.DepPolicy == "transitive" {
			depPolicy = "Transitive"
		}

		return []formField{
			{Label: "Apt Mode", Value: aptMode, Select: true,
				Options: []string{"Package Name", "Direct URL", "Source Build"}},
			{Label: "Build From", Value: buildFrom, Select: true,
				Options:  []string{"Git repo", "apt-get source"},
				Disabled: !isSourceBuild},
			{Label: "Name", Value: pm.Name},
			{Label: "Package Name", Value: ve.SourceName,
				Disabled: isDirectURL || isBuildFromGit},
			{Label: "Version", Value: ve.Version},
			{Label: "Source URL", Value: ve.URL,
				Disabled: isPkgName || isBuildFromAptSrc},
			{Label: "Build Cmd", Value: ve.BuildCmd,
				Disabled: !isBuildFromGit},
			{Label: "Deb Glob", Value: ve.DebGlob,
				Disabled: !isSourceBuild},
			{Label: "Include Deps", Value: depPolicy, Select: true,
				Disabled: !isPkgName,
				Options:  []string{"None", "Direct", "Transitive"}},
			{Label: "Skip validation", Checkbox: true, Value: "no"},
		}
	case manifest.TypeGit:
		return []formField{
			{Label: "Name", Value: pm.Name},
			{Label: "Ref", Value: ve.Ref},
			{Label: "Source URL", Value: ve.URL},
			{Label: "Validate source", Checkbox: true, Value: "yes"},
		}
	case manifest.TypeBinary:
		fields := []formField{
			{Label: "Name", Value: pm.Name},
			{Label: "Version", Value: ve.Version},
			{Label: "Source URL", Value: ve.URL},
		}
		if ve.Filename != "" {
			fields = append(fields, formField{Label: "Filename", Value: ve.Filename})
		}
		fields = append(fields, formField{Label: "Validate source", Checkbox: true, Value: "yes"})
		return fields
	case manifest.TypePypi:
		return []formField{
			{Label: "Name", Value: pm.Name},
			{Label: "Validate source", Checkbox: true, Value: "yes"},
		}
	}
	return []formField{{Label: "Name", Value: node.Name}}
}

// --- Create form helpers ---

// createTypeOptions is the alphabetically sorted list of types for the create form,
// with a placeholder prompt as the first entry.
var createTypeOptions = []string{
	"Select...",
	manifest.TypeApt,
	manifest.TypeBinary,
	manifest.TypeGit,
	manifest.TypeGomod,
	manifest.TypeHelm,
	manifest.TypeNpm,
	manifest.TypePypi,
}

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
				Value:   "Select...",
				Select:  true,
				Options: createTypeOptions,
			},
		},
	}

	// Don't expand fields yet -- user must select a type first.

	p.onChange = func(pp *popupModel) {
		entryType := fieldValueFromSlice(pp.formFields, "Type")
		pp.formFields = rebuildCreateFields(entryType, pp.formFields)
		// Update checksum hint on every change.
		updateChecksumHint(pp.formFields)

		// Auto-fill Name from Source URL when navigating away from it.
		if pp.prevCursor != pp.formCursor &&
			pp.prevCursor < len(pp.formFields) &&
			pp.formFields[pp.prevCursor].Label == "Source URL" {
			urlVal := fieldValueFromSlice(pp.formFields, "Source URL")
			if urlVal != "" && strings.Contains(urlVal, "://") {
				nameVal := fieldValueFromSlice(pp.formFields, "Name")
				if nameVal == "" {
					derived := extractNameFromURL(urlVal, entryType)
					for i := range pp.formFields {
						if pp.formFields[i].Label == "Name" {
							pp.formFields[i].Value = derived
							pp.formFields[i].cursor = len([]rune(derived))
							break
						}
					}
				}
			}
		}

		// Auto-fill Name from Package Name when navigating away from it.
		if pp.prevCursor != pp.formCursor &&
			pp.prevCursor < len(pp.formFields) &&
			pp.formFields[pp.prevCursor].Label == "Package Name" {
			pkgName := fieldValueFromSlice(pp.formFields, "Package Name")
			if pkgName != "" {
				nameVal := fieldValueFromSlice(pp.formFields, "Name")
				if nameVal == "" {
					for i := range pp.formFields {
						if pp.formFields[i].Label == "Name" {
							pp.formFields[i].Value = pkgName
							pp.formFields[i].cursor = len([]rune(pkgName))
							break
						}
					}
				}
			}
		}
	}

	p.validate = func(fields []formField) string {
		if msg := validateCreateFields(fields); msg != "" {
			return msg
		}
		entryType := fieldValueFromSlice(fields, "Type")
		name := fieldValueFromSlice(fields, "Name")
		ctx := context.Background()
		pm, _ := store.GetPackage(ctx, entryType, name)
		if pm != nil {
			return fmt.Sprintf("%s/%s already exists", entryType, name)
		}
		return ""
	}

	p.onFormSave = func(fields []formField) {
		if err := saveCreateEntry(store, fields); err != nil {
			logPane.appendLog(errorStyle.Render("Create failed: " + err.Error()))
		} else {
			entryType := fieldValueFromSlice(fields, "Type")
			name := fieldValueFromSlice(fields, "Name")
			if name == "" {
				name = extractNameFromURL(fieldValueFromSlice(fields, "Source URL"), entryType)
			}
			if name == "" {
				if pkgName := fieldValueFromSlice(fields, "Package Name"); pkgName != "" {
					name = pkgName
				}
			}
			m.lastCreatedType = entryType
			m.lastCreatedName = name
			logPane.appendLog(successStyle.Render(
				fmt.Sprintf("Created %s/%s", entryType, name),
			))

			// Apt post-create: resolve concrete version + dependency discovery.
			if entryType == manifest.TypeApt {
				aptMode := fieldValueFromSlice(fields, "Apt Mode")
				pkgName := fieldValueFromSlice(fields, "Package Name")

				// Auto-resolve concrete version when * (any) is used.
				if aptMode == "Package Name" && pkgName != "" {
					version := fieldValueFromSlice(fields, "Version")
					if version == "*" || version == "" {
						ctx := context.Background()
						var resolveBuf strings.Builder
						builder.ResolveAndCreateConcreteVersion(ctx, store, pkgName, &resolveBuf)
						if resolveBuf.Len() > 0 {
							logPane.appendLog(dimStyle.Render(strings.TrimSpace(resolveBuf.String())))
						}
					}
				}

				// Dependency discovery.
				includeDeps := fieldValueFromSlice(fields, "Include Deps")
				if aptMode == "Package Name" && includeDeps != "None" {
					depth := "direct"
					if includeDeps == "Transitive" {
						depth = "transitive"
					}
					var buf strings.Builder
					deps := builder.DiscoverAptDeps(store, pkgName, depth, &buf)
					if buf.Len() > 0 {
						logPane.appendLog(dimStyle.Render(strings.TrimSpace(buf.String())))
					}
					if len(deps) > 0 {
						ctx := context.Background()
						var importBuf strings.Builder
						added := builder.ImportAptDeps(ctx, store, name, deps, &importBuf)
						if importBuf.Len() > 0 {
							logPane.appendLog(dimStyle.Render(strings.TrimSpace(importBuf.String())))
						}
						logPane.appendLog(successStyle.Render(
							fmt.Sprintf("Discovered %d deps for %s, added %d new entries", len(deps), pkgName, added),
						))
					} else {
						logPane.appendLog(dimStyle.Render("No dependencies found for " + pkgName))
					}
				}
			}
		}
	}

	return p
}

// rebuildCreateFields returns a new field slice appropriate for entryType,
// carrying over any values already entered into matching fields from prev.
// The Type field (index 0) is always preserved as the first element.
func rebuildCreateFields(entryType string, prev []formField) []formField {
	prevValues := make(map[string]string, len(prev))
	prevCursors := make(map[string]int, len(prev))
	prevLabelSelect := make(map[string]string, len(prev))
	for _, f := range prev {
		prevValues[f.Label] = f.Value
		prevCursors[f.Label] = f.cursor
		if f.LabelSelect {
			prevLabelSelect[f.Label] = f.LabelSelectValue
		}
	}

	typeField := formField{
		Label:   "Type",
		Value:   entryType,
		Select:  true,
		Options: createTypeOptions,
	}

	// If no type selected yet, just return the type field alone.
	if entryType == "Select..." || entryType == "" {
		return []formField{typeField}
	}

	restore := func(label, defaultVal string) string {
		if v, ok := prevValues[label]; ok && v != "" {
			return v
		}
		return defaultVal
	}

	restoreCursors := func(fields []formField) []formField {
		for i := range fields {
			if c, ok := prevCursors[fields[i].Label]; ok {
				fields[i].cursor = c
			}
		}
		return fields
	}

	switch entryType {
	case manifest.TypeGit:
		return restoreCursors([]formField{
			typeField,
			{Label: "Name", Value: restore("Name", ""),
				Hint: "leave blank to derive from Source URL"},
			{Label: "Source URL", Value: restore("Source URL", "")},
			{Label: "Ref", Value: restore("Ref", "")},
			{Label: "Skip validation", Value: restore("Skip validation", "no"), Checkbox: true,
				Hint: "skip URL/ref reachability check"},
			{Label: "Auto-import deps", Value: restore("Auto-import deps", "yes"), Checkbox: true,
				Hint: "auto-import discovered dependencies; disable for interactive review"},
		})

	case manifest.TypePypi:
		modeVal := restore("Mode", "hosted")
		isProxy := modeVal == "proxy"
		constraintVal := prevLabelSelect["Version"]
		if constraintVal == "" {
			constraintVal = "exact (=)"
		}
		if !isProxy {
			constraintVal = "exact (=)"
		}
		versionDisabled := constraintVal == "latest (*)"
		versionVal := restore("Version", "")
		if versionDisabled {
			versionVal = "*"
		}
		return restoreCursors([]formField{
			typeField,
			{Label: "Mode", Value: modeVal, Select: true,
				Options: []string{"hosted", "proxy"},
				Hint: "hosted = build wheels locally; proxy = fetch from upstream PyPI on demand"},
			{Label: "Name", Value: restore("Name", ""),
				Hint: "pip package specifier, e.g. boto3 or social-auth-core[openidconnect]"},
			{Label: "Version", Value: versionVal, Disabled: versionDisabled,
				LabelSelect: true, LabelSelectValue: constraintVal,
				LabelSelectOptions: []string{"exact (=)", "compatible (^)", "patch (~)", "latest (*)"},
				Hint: "e.g. 1.6.1 (leave blank for latest)"},
			{Label: "Required By", Value: restore("Required By", ""),
				Hint: "comma-separated, e.g. netbox,standalone"},
		})

	case manifest.TypeBinary:
		latestVal := restore("Latest", "no")
		versionDisabled := latestVal == "yes"
		versionVal := restore("Version", "")
		if latestVal == "yes" {
			versionVal = "latest"
		}
		checksumVal := restore("Checksum", "")
		return restoreCursors([]formField{
			typeField,
			{Label: "Name", Value: restore("Name", ""),
				Hint: "leave blank to derive from Source URL"},
			{Label: "Version", Value: versionVal, Disabled: versionDisabled,
				LabelSelect: true, LabelSelectValue: "exact (=)",
				LabelSelectOptions: []string{"exact (=)", "compatible (^)", "patch (~)", "latest (*)"}},
			{Label: "Source URL", Value: restore("Source URL", "")},
			{Label: "Filename", Value: restore("Filename", ""),
				Hint: "leave empty to derive from Source URL"},
			{Label: "Checksum", Value: checksumVal,
				Hint: checksumHint(checksumVal)},
			{Label: "Latest", Value: latestVal, Checkbox: true},
			{Label: "Skip validation", Value: restore("Skip validation", "no"), Checkbox: true,
				Hint: "skip URL reachability check"},
		})

	case manifest.TypeGomod:
		modeVal := restore("Mode", "hosted")
		isProxy := modeVal == "proxy"
		constraintVal := prevLabelSelect["Version"]
		if constraintVal == "" {
			constraintVal = "exact (=)"
		}
		if !isProxy {
			constraintVal = "exact (=)"
		}
		versionDisabled := constraintVal == "latest (*)"
		versionVal := restore("Version", "")
		if versionDisabled {
			versionVal = "*"
		}
		checksumVal := restore("Checksum", "")
		return restoreCursors([]formField{
			typeField,
			{Label: "Mode", Value: modeVal, Select: true,
				Options: []string{"hosted", "proxy"},
				Hint: "hosted = S3 only; proxy = fetch from upstream on cache miss"},
			{Label: "Name", Value: restore("Name", ""),
				Hint: "module path, e.g. github.com/aws/aws-sdk-go-v2"},
			{Label: "Version", Value: versionVal, Disabled: versionDisabled,
				LabelSelect: true, LabelSelectValue: constraintVal,
				LabelSelectOptions: []string{"exact (=)", "compatible (^)", "patch (~)", "latest (*)"},
				Hint: "e.g. v1.30.0"},
			{Label: "Source URL", Value: restore("Source URL", ""),
				Hint: "upstream GOPROXY URL; leave empty for proxy.golang.org"},
			{Label: "Checksum", Value: checksumVal,
				Hint: checksumHint(checksumVal)},
			{Label: "Skip validation", Value: restore("Skip validation", "no"), Checkbox: true,
				Hint: "skip URL reachability check"},
		})

	case manifest.TypeHelm:
		modeVal := restore("Mode", "hosted")
		isProxy := modeVal == "proxy"
		constraintVal := prevLabelSelect["Version"]
		if constraintVal == "" {
			constraintVal = "exact (=)"
		}
		if !isProxy {
			constraintVal = "exact (=)"
		}
		versionDisabled := constraintVal == "latest (*)"
		versionVal := restore("Version", "")
		if versionDisabled {
			versionVal = "*"
		}
		checksumVal := restore("Checksum", "")
		return restoreCursors([]formField{
			typeField,
			{Label: "Mode", Value: modeVal, Select: true,
				Options: []string{"hosted", "proxy"},
				Hint: "hosted = S3 only; proxy = fetch from upstream on cache miss"},
			{Label: "Name", Value: restore("Name", ""),
				Hint: "chart name, e.g. ingress-nginx"},
			{Label: "Version", Value: versionVal, Disabled: versionDisabled,
				LabelSelect: true, LabelSelectValue: constraintVal,
				LabelSelectOptions: []string{"exact (=)", "compatible (^)", "patch (~)", "latest (*)"}},
			{Label: "Source URL", Value: restore("Source URL", ""),
				Hint: "chart repo URL or direct .tgz download URL"},
			{Label: "App Version", Value: restore("App Version", "")},
			{Label: "Checksum", Value: checksumVal,
				Hint: checksumHint(checksumVal)},
			{Label: "Skip validation", Value: restore("Skip validation", "no"), Checkbox: true,
				Hint: "skip URL reachability check"},
		})

	case manifest.TypeNpm:
		modeVal := restore("Mode", "hosted")
		isProxy := modeVal == "proxy"
		constraintVal := prevLabelSelect["Version"]
		if constraintVal == "" {
			constraintVal = "exact (=)"
		}
		if !isProxy {
			constraintVal = "exact (=)"
		}
		versionDisabled := constraintVal == "latest (*)"
		versionVal := restore("Version", "")
		if versionDisabled {
			versionVal = "*"
		}
		checksumVal := restore("Checksum", "")
		return restoreCursors([]formField{
			typeField,
			{Label: "Mode", Value: modeVal, Select: true,
				Options: []string{"hosted", "proxy"},
				Hint: "hosted = S3 only; proxy = fetch from upstream on cache miss"},
			{Label: "Name", Value: restore("Name", ""),
				Hint: "package name, e.g. lodash or @scope/pkg"},
			{Label: "Version", Value: versionVal, Disabled: versionDisabled,
				LabelSelect: true, LabelSelectValue: constraintVal,
				LabelSelectOptions: []string{"exact (=)", "compatible (^)", "patch (~)", "latest (*)"}},
			{Label: "Source URL", Value: restore("Source URL", ""),
				Hint: "upstream registry URL; leave empty for registry.npmjs.org"},
			{Label: "Checksum", Value: checksumVal,
				Hint: checksumHint(checksumVal)},
			{Label: "Skip validation", Value: restore("Skip validation", "no"), Checkbox: true,
				Hint: "skip URL reachability check"},
		})

	default: // manifest.TypeApt
		aptMode := restore("Apt Mode", "Package Name")
		buildFrom := restore("Build From", "Git repo")
		versionVal := restore("Version", "")
		checksumVal := restore("Checksum", "")
		constraintVal := prevLabelSelect["Version"]
		if constraintVal == "" {
			constraintVal = "exact (=)"
		}

		isPkgName := aptMode == "Package Name"
		isDirectURL := aptMode == "Direct URL"
		isSourceBuild := aptMode == "Source Build"
		isBuildFromGit := isSourceBuild && buildFrom == "Git repo"
		isBuildFromAptSrc := isSourceBuild && buildFrom == "apt-get source"

		var nameHint string
		switch {
		case isPkgName:
			nameHint = "leave blank to derive from Package Name"
		case isDirectURL, isBuildFromGit:
			nameHint = "leave blank to derive from Source URL"
		case isBuildFromAptSrc:
			nameHint = "leave blank to derive from Package Name"
		}

		return restoreCursors([]formField{
			typeField,
			{Label: "Apt Mode", Value: aptMode, Select: true,
				Options: []string{"Package Name", "Direct URL", "Source Build"},
				Hint: "how to acquire the .deb package"},
			{Label: "Build From", Value: buildFrom, Select: true,
				Options:  []string{"Git repo", "apt-get source"},
				Disabled: !isSourceBuild,
				Hint:     "clone a git repo or rebuild official source package"},
			{Label: "Name", Value: restore("Name", ""),
				Hint: nameHint},
			{Label: "Package Name", Value: restore("Package Name", ""),
				Disabled: isDirectURL || isBuildFromGit,
				Hint:     "upstream apt package name, e.g. nginx"},
			{Label: "Version", Value: versionVal,
				LabelSelect: true, LabelSelectValue: constraintVal,
				LabelSelectOptions: []string{"exact (=)", "compatible (^)", "patch (~)", "latest (*)"}},
			{Label: "Source URL", Value: restore("Source URL", ""),
				Disabled: isPkgName || isBuildFromAptSrc,
				Hint:     "URL to .deb file or git repo"},
			{Label: "Build Cmd", Value: restore("Build Cmd", ""),
				Disabled: !isBuildFromGit,
				Hint:     "shell command to produce a .deb"},
			{Label: "Deb Glob", Value: restore("Deb Glob", ""),
				Disabled: !isSourceBuild,
				Hint:     "glob pattern to find .deb after build"},
			{Label: "Include Deps", Value: restore("Include Deps", "None"), Select: true,
				Disabled: !isPkgName,
				Options:  []string{"None", "Direct", "Transitive"},
				Hint:     "auto-discover and add apt dependencies"},
			{Label: "Checksum", Value: checksumVal,
				Disabled: isPkgName,
				Hint:     checksumHint(checksumVal)},
			{Label: "Skip validation", Value: restore("Skip validation", "no"), Checkbox: true,
				Hint: "skip reachability/existence checks"},
		})
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
				if fields[j].Label == "Version" && fields[j].LabelSelect {
					fields[j].Disabled = latestOn
					if latestOn {
						fields[j].Value = "latest"
					} else if fields[j].Value == "latest" {
						fields[j].Value = ""
					}
				}
			}
		}
		// Handle Mode ↔ Constraint coupling: constraint only active in proxy mode.
		if fields[i].Label == "Mode" && fields[i].Select {
			isProxy := fields[i].Value == "proxy"
			for j := range fields {
				if fields[j].Label == "Version" && fields[j].LabelSelect {
					if !isProxy {
						fields[j].LabelSelectValue = "equals"
						fields[j].Disabled = false
						if fields[j].Value == "*" {
							fields[j].Value = ""
						}
					}
				}
			}
		}
		// Handle Constraint ↔ Version coupling and dynamic hint.
		if fields[i].Label == "Version" && fields[i].LabelSelect {
			anyOn := fields[i].LabelSelectValue == "latest (*)"
			// Don't override if Latest is also active.
			latestOn := false
			for _, f := range fields {
				if f.Label == "Latest" && f.Value == "yes" {
					latestOn = true
					break
				}
			}
			if !latestOn {
				fields[i].Disabled = anyOn
				if anyOn {
					fields[i].Value = "*"
				} else if fields[i].Value == "*" {
					fields[i].Value = ""
				}
			}
			// Update hint based on selected constraint.
			switch fields[i].LabelSelectValue {
			case "exact (=)":
				fields[i].Hint = "only this exact version"
			case "compatible (^)":
				fields[i].Hint = "same major, any minor/patch (^5.2 = 5.2.0 to 5.x.x)"
			case "patch (~)":
				fields[i].Hint = "same major.minor, any patch (~5.2 = 5.2.0 to 5.2.x)"
			case "latest (*)":
				fields[i].Hint = "all available versions"
			}
		}
		// Note: Name auto-fill from URL is handled in the onChange callback
		// of buildCreatePopup, triggered only when navigating away from the URL field.
	}
}

// validateCreateFields returns a non-empty error message when the fields are not
// ready to be saved, or an empty string when everything is valid.
func validateCreateFields(fields []formField) string {
	entryType := fieldValueFromSlice(fields, "Type")
	if !isValidType(entryType) {
		return "select a valid type"
	}
	name := fieldValueFromSlice(fields, "Name")
	if name == "" {
		// Allow blank if we can derive from URL or Package Name.
		url := fieldValueFromSlice(fields, "Source URL")
		if url != "" {
			name = extractNameFromURL(url, entryType)
		}
		if name == "" {
			pkgName := fieldValueFromSlice(fields, "Package Name")
			if pkgName != "" {
				name = pkgName
			}
		}
		if name == "" {
			return "Name is required"
		}
	}
	switch entryType {
	case manifest.TypeApt:
		aptMode := fieldValueFromSlice(fields, "Apt Mode")
		switch aptMode {
		case "Package Name":
			if fieldValueFromSlice(fields, "Package Name") == "" {
				return "Package Name is required"
			}
		case "Direct URL":
			if fieldValueFromSlice(fields, "Source URL") == "" {
				return "Source URL is required for direct URL mode"
			}
		case "Source Build":
			buildFrom := fieldValueFromSlice(fields, "Build From")
			if buildFrom == "Git repo" && fieldValueFromSlice(fields, "Source URL") == "" {
				return "Source URL is required for git source build"
			}
			if buildFrom == "apt-get source" && fieldValueFromSlice(fields, "Package Name") == "" {
				return "Package Name is required for apt-get source build"
			}
		}
	case manifest.TypeGit:
		if fieldValueFromSlice(fields, "Source URL") == "" {
			return "Source URL is required for git entries"
		}
		if fieldValueFromSlice(fields, "Ref") == "" {
			return "Ref is required for git entries"
		}
	case manifest.TypeBinary:
		if fieldValueFromSlice(fields, "Source URL") == "" {
			return "Source URL is required for binary entries"
		}
	case manifest.TypeGomod:
		if fieldValueFromSlice(fields, "Version") == "" {
			return "Version is required for gomod entries"
		}
	case manifest.TypeHelm:
		if fieldValueFromSlice(fields, "Version") == "" {
			return "Version is required for helm entries"
		}
		if fieldValueFromSlice(fields, "Source URL") == "" {
			return "Source URL is required for helm entries"
		}
	case manifest.TypeNpm:
		if fieldValueFromSlice(fields, "Version") == "" {
			return "Version is required for npm entries"
		}
	}
	// Block save if checksum is present but invalid.
	chk := fieldValueFromSlice(fields, "Checksum")
	if chk != "" && detectChecksumAlgorithm(chk) == "" {
		return "invalid checksum value"
	}

	// Remote reachability checks (skipped when "Skip validation" is toggled).
	if fieldValueFromSlice(fields, "Skip validation") != "yes" {
		if msg := validateRemote(entryType, fields); msg != "" {
			return msg
		}
	}
	return ""
}

// validateRemote checks that remote resources (URLs, git refs) are reachable.
func validateRemote(entryType string, fields []formField) string {
	switch entryType {
	case manifest.TypeGit:
		url := fieldValueFromSlice(fields, "Source URL")
		ref := fieldValueFromSlice(fields, "Ref")
		return validateGitRef(url, ref)
	case manifest.TypeBinary:
		url := fieldValueFromSlice(fields, "Source URL")
		return validateURLReachable(url)
	case manifest.TypeApt:
		aptMode := fieldValueFromSlice(fields, "Apt Mode")
		switch aptMode {
		case "Direct URL":
			return validateURLReachable(fieldValueFromSlice(fields, "Source URL"))
		case "Source Build":
			buildFrom := fieldValueFromSlice(fields, "Build From")
			if buildFrom == "Git repo" {
				return validateURLReachable(fieldValueFromSlice(fields, "Source URL"))
			}
			// apt-get source: validate source package exists.
			pkgName := fieldValueFromSlice(fields, "Package Name")
			if pkgName != "" {
				return builder.ValidateAptSource(pkgName)
			}
		case "Package Name":
			pkgName := fieldValueFromSlice(fields, "Package Name")
			if pkgName != "" {
				return builder.ValidateAptPackage(pkgName)
			}
		}
	case manifest.TypeHelm:
		url := fieldValueFromSlice(fields, "Source URL")
		return validateURLReachable(url)
	case manifest.TypeGomod:
		url := fieldValueFromSlice(fields, "Source URL")
		if url != "" {
			return validateURLReachable(url)
		}
	case manifest.TypeNpm:
		url := fieldValueFromSlice(fields, "Source URL")
		if url != "" {
			return validateURLReachable(url)
		}
	}
	return ""
}

// validateGitRef uses git ls-remote to verify the URL is reachable and the ref
// exists. Returns an error message or empty string on success.
func validateGitRef(url, ref string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "git", "ls-remote", "--refs", url).CombinedOutput()
	if err != nil {
		return fmt.Sprintf("cannot reach %s: %v", url, err)
	}
	// ls-remote output: "<sha>\t<refname>\n" per line.
	// Match ref against tag refs, branch refs, or exact ref names.
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		remoteName := parts[1]
		// Match tags: refs/tags/v1.0.0
		if remoteName == "refs/tags/"+ref || remoteName == "refs/heads/"+ref || remoteName == ref {
			return ""
		}
	}
	return fmt.Sprintf("ref %q not found in %s", ref, url)
}

// validateURLReachable sends an HTTP HEAD request to verify the URL is reachable.
func validateURLReachable(url string) string {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Head(url)
	if err != nil {
		return fmt.Sprintf("cannot reach %s: %v", url, err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Sprintf("Source URL returned %d: %s", resp.StatusCode, url)
	}
	return ""
}

// toggleHidden flips the Hidden flag on all versions of a manifest entry and saves.
func toggleHidden(store *manifest.Store, entryType, name string) {
	ctx := context.Background()
	pm, err := store.GetPackage(ctx, entryType, name)
	if err != nil || pm == nil {
		return
	}
	// Determine new state: if all hidden, unhide; otherwise hide all.
	allHidden := len(pm.Versions) > 0
	for _, ve := range pm.Versions {
		if !ve.Hidden {
			allHidden = false
			break
		}
	}
	newState := !allHidden
	for i := range pm.Versions {
		pm.Versions[i].Hidden = newState
	}
	_ = store.SavePackage(ctx, pm)
}

// constraintToManifest maps the form dropdown value to a manifest constant.
// Returns "" for "equals" (the default, omitted from JSON).
func constraintToManifest(formVal string) string {
	switch formVal {
	case "latest (*)":
		return manifest.ConstraintAny
	case "compatible (^)":
		return manifest.ConstraintCompatible
	case "patch (~)":
		return manifest.ConstraintPatch
	default:
		return "" // "exact (=)" → omit
	}
}

// saveCreateEntry builds the appropriate manifest VersionEntry from fields and
// adds it to the store via AddVersion, then persists the index.
func saveCreateEntry(store *manifest.Store, fields []formField) error {
	ctx := context.Background()
	entryType := fieldValueFromSlice(fields, "Type")
	name := fieldValueFromSlice(fields, "Name")
	if name == "" {
		name = extractNameFromURL(fieldValueFromSlice(fields, "Source URL"), entryType)
	}
	if name == "" {
		if pkgName := fieldValueFromSlice(fields, "Package Name"); pkgName != "" {
			name = pkgName
		}
	}

	var chksum *manifest.Checksum
	if chkVal := fieldValueFromSlice(fields, "Checksum"); chkVal != "" {
		algo := detectChecksumAlgorithm(chkVal)
		if algo != "" {
			chksum = &manifest.Checksum{Algorithm: algo, Value: chkVal}
		}
	}

	version := fieldValueFromSlice(fields, "Version")
	constraint := constraintToManifest(labelSelectValue(fields, "Version"))
	mode := fieldValueFromSlice(fields, "Mode")
	if mode == manifest.ModeHosted {
		mode = "" // omit default
	}

	ve := manifest.VersionEntry{
		Version:           version,
		URL:               fieldValueFromSlice(fields, "Source URL"),
		Mode:              mode,
		VersionConstraint: constraint,
		Checksum:          chksum,
	}

	switch entryType {
	case manifest.TypeApt:
		aptMode := fieldValueFromSlice(fields, "Apt Mode")
		switch aptMode {
		case "Package Name":
			ve.URL = ""
			ve.SourceName = fieldValueFromSlice(fields, "Package Name")
			ve.BuildCmd = ""
			ve.DebGlob = ""
		case "Direct URL":
			ve.SourceName = ""
			ve.BuildCmd = ""
			ve.DebGlob = ""
		case "Source Build":
			buildFrom := fieldValueFromSlice(fields, "Build From")
			if buildFrom == "Git repo" {
				ve.SourceName = ""
				ve.BuildCmd = fieldValueFromSlice(fields, "Build Cmd")
			} else {
				// apt-get source
				ve.URL = ""
				ve.SourceName = fieldValueFromSlice(fields, "Package Name")
				ve.BuildCmd = "dpkg-buildpackage -us -uc"
			}
			ve.DebGlob = fieldValueFromSlice(fields, "Deb Glob")
		}

	case manifest.TypeGit:
		ve.Ref = fieldValueFromSlice(fields, "Ref")
		ve.URL = fieldValueFromSlice(fields, "Source URL")
		ve.Version = "" // git uses Ref not Version

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
		ve.RequiredBy = requiredBy

	case manifest.TypeBinary:
		ve.Filename = fieldValueFromSlice(fields, "Filename")

	case manifest.TypeHelm:
		ve.AppVersion = fieldValueFromSlice(fields, "App Version")

	case manifest.TypeGomod, manifest.TypeNpm:
		// nothing extra

	default:
		return fmt.Errorf("unknown entry type %q", entryType)
	}

	if err := store.AddVersion(ctx, entryType, name, ve); err != nil {
		return err
	}

	// Save dep policy on the package manifest if set.
	if entryType == manifest.TypeApt {
		depPolicy := strings.ToLower(fieldValueFromSlice(fields, "Include Deps"))
		if depPolicy != "" && depPolicy != "none" {
			if pm, err := store.GetPackage(ctx, entryType, name); err == nil && pm != nil {
				pm.DepPolicy = depPolicy
				_ = store.SavePackage(ctx, pm)
			}
		}
	}

	return store.SaveIndex(ctx)
}

// makeJSONApplyFn returns the function passed to HandleJSONOverlayKey that
// parses the JSON buffer (as a PackageManifest) and populates the form fields from it.
func (m *appModel) makeJSONApplyFn() func(buf string) string {
	p := &m.popup
	return func(buf string) string {
		entryType := fieldValueFromSlice(p.formFields, "Type")
		// Parse as a PackageManifest and extract first VersionEntry.
		var pm manifest.PackageManifest
		if err := json.Unmarshal([]byte(buf), &pm); err != nil {
			// Also try parsing as a plain VersionEntry map for convenience.
			return "invalid JSON: " + err.Error()
		}
		p.formFields = rebuildCreateFields(entryType, p.formFields)
		setFieldValue(p.formFields, "Name", pm.Name)

		if len(pm.Versions) > 0 {
			ve := pm.Versions[0]
			setFieldValue(p.formFields, "Version", ve.Version)
			setFieldValue(p.formFields, "Source URL", ve.URL)
			if ve.Ref != "" {
				setFieldValue(p.formFields, "Ref", ve.Ref)
			}
			if ve.Filename != "" {
				setFieldValue(p.formFields, "Filename", ve.Filename)
			}
			if ve.SourceName != "" {
				setFieldValue(p.formFields, "Source Name", ve.SourceName)
			}
			if ve.BuildCmd != "" {
				setFieldValue(p.formFields, "Build Cmd", ve.BuildCmd)
			}
			if ve.DebGlob != "" {
				setFieldValue(p.formFields, "Deb Glob", ve.DebGlob)
			}
			if len(ve.RequiredBy) > 0 {
				setFieldValue(p.formFields, "Required By", strings.Join(ve.RequiredBy, ", "))
			}
			if ve.Checksum != nil {
				setFieldValue(p.formFields, "Checksum", ve.Checksum.Value)
			}
			if ve.Frozen {
				setFieldValue(p.formFields, "Frozen", "yes")
			}
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
	switch entryType {
	case manifest.TypeGit:
		// For git URLs, extract org/repo: https://github.com/org/repo.git -> org/repo
		rawURL = strings.TrimSuffix(rawURL, ".git")
		rawURL = strings.TrimSuffix(rawURL, "/")
		parts := strings.Split(rawURL, "/")
		if len(parts) >= 2 {
			return parts[len(parts)-2] + "/" + parts[len(parts)-1]
		}
		if len(parts) >= 1 {
			return parts[len(parts)-1]
		}
		return ""
	case manifest.TypeGomod:
		// Go module paths are already the name: github.com/aws/aws-sdk-go-v2
		return rawURL
	case manifest.TypeNpm:
		// npm: last segment or @scope/name
		seg := lastURLSegment(rawURL)
		return seg
	default:
		seg := lastURLSegment(rawURL)
		if seg == "" {
			return ""
		}
		// Strip common archive extensions for binary/apt.
		for _, ext := range []string{".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip", ".deb", ".rpm"} {
			if strings.HasSuffix(seg, ext) {
				seg = seg[:len(seg)-len(ext)]
				break
			}
		}
		return seg
	}
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

// fieldDisabled returns true if the named field exists and is disabled.
func fieldDisabled(fields []formField, key string) bool {
	for _, f := range fields {
		if f.Label == key {
			return f.Disabled
		}
	}
	return false
}

// labelSelectValue returns the LabelSelectValue of the first LabelSelect field with the given label.
func labelSelectValue(fields []formField, label string) string {
	for _, f := range fields {
		if f.Label == label && f.LabelSelect {
			return f.LabelSelectValue
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

	sourcesTotalW := m.width * 30 / 100
	if sourcesTotalW < 20+frameW {
		sourcesTotalW = 20 + frameW
	}
	detailsTotalW := m.width - sourcesTotalW

	sourcesContentW := sourcesTotalW - frameW
	detailsContentW := detailsTotalW - frameW
	logContentW := m.width - frameW

	m.sources.width = sourcesContentW
	m.sources.height = topContentH
	m.details.SetSize(detailsContentW, topContentH)
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
	detailsPane := paneStyle(m.focus == focusDetails).
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
	logLabel := " Log "
	if m.logPath != "" {
		logLabel = " Log - " + m.logPath + " "
	}
	logTitle := titleStyle(m.focus == focusLog).Render(logLabel)
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
