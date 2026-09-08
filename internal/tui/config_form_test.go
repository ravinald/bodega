package tui

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// openConfigForm loads the config file at path with the given --region override
// and returns the model and the config popup the "C" key opens on it.
func openConfigForm(t *testing.T, path, flagRegion string) (appModel, *config.Config) {
	t.Helper()
	t.Setenv(config.EnvConfigFile, path)
	t.Setenv(config.EnvRegion, "")

	cfg, err := config.Load("", "", flagRegion, "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	m := newAppModel(cfg, nil, nil, nil, nil)
	next, _ := m.handleSourcesKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("C")})
	am, ok := next.(appModel)
	if !ok {
		t.Fatalf("handleSourcesKey returned %T, want appModel", next)
	}
	if am.popup.kind != popupForm {
		t.Fatalf("popup kind = %v, want the config form", am.popup.kind)
	}
	return am, cfg
}

// typeInto replaces a form field's contents by hand: focus it, clear it a
// keystroke at a time, then type the value. Setting Value directly would skip
// the edited flag, which is the thing under test.
func typeInto(t *testing.T, p *popupModel, label, value string) {
	t.Helper()
	idx := -1
	for i, f := range p.formFields {
		if f.Label == label {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatalf("no %q field in the config form", label)
	}
	p.formCursor = idx
	p.formFields[idx].cursor = len([]rune(p.formFields[idx].Value))
	for range p.formFields[idx].Value {
		p.HandleFormKey("backspace")
	}
	for _, r := range value {
		p.HandleFormRune(r)
	}
}

// TestConfigFormPinsAnEditedField drives the real loader and saver. `bodega
// --region us-west-2 shell` prefills the form with us-west-2, so an operator
// setting the field to that value produces no diff against the resolved config
// and Save wrote nothing while the TUI said it had. The reload is the assertion
// that matters: it is what the next process sees.
func TestConfigFormPinsAnEditedField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"region": "us-east-1"}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	am, _ := openConfigForm(t, path, "us-west-2")
	if got := fieldValue(am.popup.formFields, "Region"); got != "us-west-2" {
		t.Fatalf("Region field prefilled with %q, want the resolved us-west-2", got)
	}
	typeInto(t, &am.popup, "Region", "us-west-2")
	am.popup.onFormSave(am.popup.formFields)

	reloaded, err := config.Load("", "", "", "", false, false)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Region != "us-west-2" {
		t.Errorf("region after save = %q, want us-west-2", reloaded.Region)
	}
}

// TestConfigFormLeavesPrefilledFieldsAlone is the other half, and is #82: a
// save the operator did not edit must not record every resolved value as a
// setting, or a flag typed once is pinned forever.
func TestConfigFormLeavesPrefilledFieldsAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	before := []byte(`{"region": "us-east-1"}`)
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	am, _ := openConfigForm(t, path, "us-west-2")
	am.popup.onFormSave(am.popup.formFields)

	reloaded, err := config.Load("", "", "", "", false, false)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Region != "us-east-1" {
		t.Errorf("region after an untouched save = %q, want the file's us-east-1", reloaded.Region)
	}
	if reloaded.ManifestDir != config.DefaultManifestDir(reloaded.StoragePath) {
		t.Errorf("manifest_dir after an untouched save = %q, want the built-in", reloaded.ManifestDir)
	}
}

// TestConfigFormReportsWhatItWrote pins the message. "Config saved" after a
// save that wrote nothing is the report #183 was filed on.
func TestConfigFormReportsWhatItWrote(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"region": "us-east-1"}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	am, _ := openConfigForm(t, path, "us-west-2")
	am.popup.onFormSave(am.popup.formFields)
	if got := lastLogLine(t, &am); !strings.Contains(got, "No changes to save") {
		t.Errorf("untouched save logged %q, want it to say nothing was written", got)
	}

	typeInto(t, &am.popup, "Region", "us-west-2")
	am.popup.onFormSave(am.popup.formFields)
	if got := lastLogLine(t, &am); !strings.Contains(got, "region") {
		t.Errorf("edited save logged %q, want it to name region", got)
	}
}

func lastLogLine(t *testing.T, m *appModel) string {
	t.Helper()
	if len(m.log.outputLines) == 0 {
		t.Fatal("nothing reached the log pane")
	}
	return m.log.outputLines[len(m.log.outputLines)-1]
}

// TestAuditQueryOpensResultsTable drives the whole L path: the query form saves,
// and the results replace it with the table popup. The form's onFormSave closes
// over the popup the builder returned, not the copy the app is driving, so the
// hand-off only works through the shared nextPopup pointer.
func TestAuditQueryOpensResultsTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	adb, err := audit.Open(dbPath)
	if err != nil {
		t.Fatalf("open audit DB: %v", err)
	}
	if err := adb.Record(context.Background(), audit.Event{
		EventType: "serve_fetch",
		PkgType:   "apt",
		PkgName:   "dists/jammy-updates/InRelease",
		Status:    "success",
		ClientIP:  "172.233.223.16",
	}); err != nil {
		t.Fatalf("record event: %v", err)
	}
	adb.Close()

	m := newAppModel(&config.Config{AuditDB: dbPath}, manifest.NewLocalStore(t.TempDir()), nil, nil, nil)
	m.width, m.height = 140, 40
	m.popup = m.buildAuditPopup()

	next, _ := m.handlePopupKey(tea.KeyMsg{Type: tea.KeyEnter})
	am, ok := next.(appModel)
	if !ok {
		t.Fatalf("handlePopupKey returned %T, want appModel", next)
	}
	if am.popup.kind != popupAuditTable {
		t.Fatalf("popup kind = %v after the query saved, want the results table", am.popup.kind)
	}
	if got := len(am.popup.auditTable.Rows()); got != 1 {
		t.Errorf("table holds %d rows, want 1", got)
	}
	if !strings.Contains(am.popup.View(140, 40), "dists/jammy-updates/InRelease") {
		t.Error("the recorded event is missing from the rendered table")
	}

	next, _ = am.handlePopupKey(tea.KeyMsg{Type: tea.KeyEscape})
	am = next.(appModel)
	if am.popup.kind != popupNone {
		t.Errorf("esc left popup kind %v, want popupNone", am.popup.kind)
	}
}

// TestJSONEditPopupEscClears covers the raw-JSON edit popup opened by E. It has
// no form behind the textarea, so closing the overlay has to close the popup
// too; leaving the kind set renders an empty box that eats every key.
func TestJSONEditPopupEscClears(t *testing.T) {
	cfg, err := config.Load("", "", "", "", false, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	m := newAppModel(cfg, manifest.NewLocalStore(t.TempDir()), nil, nil, nil)
	m.width, m.height = 120, 40
	m.popup = popupModel{kind: popupJSONEdit, editType: "apt", editName: "nginx"}
	m.popup.OpenJSONOverlay(m.width, m.height, "{}", "Edit: apt/nginx")

	next, _ := m.handlePopupKey(tea.KeyMsg{Type: tea.KeyEscape})
	am, ok := next.(appModel)
	if !ok {
		t.Fatalf("handlePopupKey returned %T, want appModel", next)
	}
	if am.popup.kind != popupNone {
		t.Errorf("popup kind = %v after esc, want popupNone", am.popup.kind)
	}
	if v := am.popup.View(m.width, m.height); v != "" {
		t.Errorf("popup still renders after esc:\n%s", v)
	}
}

// TestConfigFormResetLeavesKeysOutsideTheFormAlone drives Ctrl+R the way a
// keystroke reaches it. The reset assigns eleven fields; Save writes only what
// differs from the resolved config, so every other key in the file survives —
// including an admin_permit_cidr of 0.0.0.0/0, which the old "Config reset to
// defaults and saved to <path>" line told the operator was gone (#227).
func TestConfigFormResetLeavesKeysOutsideTheFormAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	seeded := `{
  "region": "us-east-1",
  "build_root": "/srv/build",
  "custom_paths": true,
  "apt_root": "/srv/apt",
  "admin_permit_cidr": ["0.0.0.0/0"],
  "token": "seeded-token",
  "deny_list": ["10.0.0.5/32"],
  "audit_db": "/srv/audit.db",
  "discover_mode": "observe",
  "apt_codename": "jammy",
  "tls_cert": "/srv/tls/cert.pem",
  "tls_key": "/srv/tls/key.pem"
}`
	if err := os.WriteFile(path, []byte(seeded), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	am, _ := openConfigForm(t, path, "")
	next, _ := am.handlePopupKey(tea.KeyMsg{Type: tea.KeyCtrlR})
	am, ok := next.(appModel)
	if !ok {
		t.Fatalf("handlePopupKey returned %T, want appModel", next)
	}
	if am.popup.kind != popupConfirm {
		t.Fatalf("ctrl+r left popup kind %v, want the confirm", am.popup.kind)
	}
	if strings.Contains(am.popup.message, "config file") {
		t.Errorf("confirm prompt %q promises the config file; the reset reaches this form's fields alone", am.popup.message)
	}
	if am.popup.onYes == nil {
		t.Fatal("the reset confirm carries no onYes")
	}
	am.popup.onYes()

	keys := savedConfigKeys(t, path)
	for k, want := range map[string]string{ //nolint:gosec // G101: the seeded token is the value under test, not a credential
		"admin_permit_cidr": `["0.0.0.0/0"]`,
		"token":             `"seeded-token"`,
		"deny_list":         `["10.0.0.5/32"]`,
		"audit_db":          `"/srv/audit.db"`,
		"discover_mode":     `"observe"`,
		"apt_codename":      `"jammy"`,
		"tls_cert":          `"/srv/tls/cert.pem"`,
		"tls_key":           `"/srv/tls/key.pem"`,
	} {
		got, ok := keys[k]
		if !ok {
			t.Errorf("reset dropped %q, which the form does not edit", k)
			continue
		}
		if got != want {
			t.Errorf("reset rewrote %q to %s, want %s", k, got, want)
		}
	}

	for _, k := range allConfigFormKeys() {
		if got, ok := keys[k]; ok {
			t.Errorf("reset left %q = %s in the file; the form's keys go absent, and absent is what means \"use the default\"", k, got)
		}
	}

	line := lastLogLine(t, &am)
	for _, phrase := range []string{"Config reset to defaults", "config file"} {
		if strings.Contains(line, phrase) {
			t.Errorf("reset logged %q, which claims more than it wrote", line)
		}
	}
	for _, key := range []string{"region", "build_root", "custom_paths", "apt_root"} {
		if !strings.Contains(line, key) {
			t.Errorf("reset logged %q, want it to name %s", line, key)
		}
	}
	if !strings.Contains(line, "Removed") {
		t.Errorf("reset logged %q; the keys left the file, so the line says removed", line)
	}
}

// TestConfigFormResetClearsAKeyAFlagPinsToItsDefault drives the case the seeded
// test above cannot reach. Save diffs against the resolved baseline, and a flag
// feeds that baseline, so `--region us-west-2` where us-west-2 is also the
// built-in default makes assigning the default a diff of zero: the reset was a
// no-op and the log line said the fields were already at their defaults while
// the file went on naming us-east-1 (#265).
func TestConfigFormResetClearsAKeyAFlagPinsToItsDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	seeded := `{
  "region": "us-east-1",
  "token": "seeded-token"
}`
	if err := os.WriteFile(path, []byte(seeded), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	am, _ := openConfigForm(t, path, config.DefaultRegion)
	next, _ := am.handlePopupKey(tea.KeyMsg{Type: tea.KeyCtrlR})
	am, ok := next.(appModel)
	if !ok {
		t.Fatalf("handlePopupKey returned %T, want appModel", next)
	}
	if am.popup.onYes == nil {
		t.Fatal("the reset confirm carries no onYes")
	}
	am.popup.onYes()

	keys := savedConfigKeys(t, path)
	if got, ok := keys["region"]; ok {
		t.Errorf("region after the reset = %s, want the key gone; the next Load reads it as a setting", got)
	}
	if got, want := keys["token"], `"seeded-token"`; got != want { //nolint:gosec // G101: the seeded token is the value under test, not a credential
		t.Errorf("reset rewrote token to %s, want %s", got, want)
	}
	if line := lastLogLine(t, &am); !strings.Contains(line, "region") {
		t.Errorf("reset logged %q, want it to name the region it removed", line)
	}
}

// TestConfigFormSaveAfterResetWritesARetypedKey pins Clear to one write. The
// reset removes region; an operator who then types one in and saves has to get
// it, or the reset would go on deleting the key for the life of the process.
func TestConfigFormSaveAfterResetWritesARetypedKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"region": "us-east-1"}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	am, cfg := openConfigForm(t, path, config.DefaultRegion)
	next, _ := am.handlePopupKey(tea.KeyMsg{Type: tea.KeyCtrlR})
	am, ok := next.(appModel)
	if !ok {
		t.Fatalf("handlePopupKey returned %T, want appModel", next)
	}
	am.popup.onYes()
	if got, ok := savedConfigKeys(t, path)["region"]; ok {
		t.Fatalf("the reset left region = %s in the file", got)
	}

	// The same *config.Config, so the same snapshot the reset cleared.
	next, _ = newAppModel(cfg, nil, nil, nil, nil).handleSourcesKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("C")})
	am, ok = next.(appModel)
	if !ok {
		t.Fatalf("handleSourcesKey returned %T, want appModel", next)
	}
	typeInto(t, &am.popup, "Region", "eu-central-1")
	am.popup.onFormSave(am.popup.formFields)

	if got, want := savedConfigKeys(t, path)["region"], `"eu-central-1"`; got != want {
		t.Errorf("region after a retype and save = %s, want %s", got, want)
	}
}

// savedConfigKeys reads a config file back as top-level keys with their values
// compacted, so a test can assert on what survived a write.
func savedConfigKeys(t *testing.T, path string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal saved config: %v", err)
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		var buf bytes.Buffer
		if err := json.Compact(&buf, v); err != nil {
			t.Fatalf("compact %q: %v", k, err)
		}
		out[k] = buf.String()
	}
	return out
}
