package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ravinald/bodega/internal/config"
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
	if reloaded.ManifestDir != defaultManifestDirFor(reloaded.StoragePath) {
		t.Errorf("manifest_dir after an untouched save = %q, want the built-in", reloaded.ManifestDir)
	}
}

// defaultManifestDirFor mirrors the built-in the config package resolves, which
// is unexported there.
func defaultManifestDirFor(storagePath string) string {
	if storagePath == "" {
		storagePath = config.DefaultStoragePath
	}
	return filepath.Join(storagePath, "manifests")
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
