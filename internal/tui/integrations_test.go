package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/integration"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

type formDouble struct{}

func (formDouble) Lookup(context.Context, integration.Query) (integration.Answer, error) {
	return integration.Answer{Reason: "clean"}, nil
}

func init() {
	integration.Register(integration.Descriptor{
		Type: "form-double", DisplayName: "Form double", VendorURL: "https://vendor.example.test/", Cost: integration.CostPaid,
		Ecosystems: []string{manifest.TypeNpm, manifest.TypePypi}, DataSent: "The purl of every version, with the account token.",
		DefaultAction: policy.ActionWarn, Flags: integration.FlagRisk,
		Fields: []integration.Field{
			{Key: "endpoint", Label: "Endpoint", Kind: integration.KindURL, Default: "https://api.vendor.example.test/", Help: "Where queries go."},
			{Key: "max_batch", Label: "Max batch", Kind: integration.KindInt, Default: "5", Min: 1, Max: 5, Help: "Packages per request."},
			{Key: "strict", Label: "Strict", Kind: integration.KindBool, Help: "Treat a low score as flagged."},
			{Key: "tier", Label: "Tier", Kind: integration.KindEnum, Default: "free", Options: []string{"free", "team"}, Help: "Account tier."},
			{Key: "api_token", Label: "API token", Kind: integration.KindString, Secret: true, Required: true, Help: "The vendor's API token."},
		},
		Probe: integration.Query{Ecosystem: manifest.TypeNpm, Name: "lodash", Version: "4.17.21"},
		New:   func(*integration.Instance) (integration.Checker, error) { return formDouble{}, nil },
	})
}

const integrationFormConfig = `{
  "_comment_region": "kept as written",
  "region": "eu-west-1",
  "deny_list": ["10.0.0.0/8",   "192.168.0.0/16"]
}
`

func formFieldNamed(t *testing.T, p *popupModel, label string) formField {
	t.Helper()
	for _, f := range p.formFields {
		if f.Label == label {
			return f
		}
	}
	t.Fatalf("no %q field; fields: %+v", label, p.formFields)
	return formField{}
}

func pressPopupKey(m appModel, k tea.KeyMsg) appModel {
	next, _ := m.handlePopupKey(k)
	return next.(appModel)
}

// G lists every registered type; choosing one opens a form generated from
// its descriptor, whose save runs the shared validator, writes only this
// instance under integrations, and stores a masked secret the way
// `bodega integration secret` does.
func TestIntegrationFormFromDescriptor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(integrationFormConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.EnvConfigFile, path)
	t.Setenv(config.EnvRegion, "")
	t.Setenv(integration.CredentialsEnv, "")
	t.Setenv("BODEGA_FORM_DOUBLE_API_TOKEN", "")
	cfg, err := config.Load("", "", "", "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	m := newAppModel(cfg, nil, nil, nil, nil)
	next, _ := m.handleSourcesKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("G")})
	m = next.(appModel)
	if m.popup.kind != popupChoice || m.popup.choiceFor != choiceIntegration {
		t.Fatalf("G opened %v", m.popup.kind)
	}
	idx := -1
	for i, k := range m.popup.choiceKeys {
		if k == "form-double" {
			idx = i
		}
	}
	if idx < 0 {
		t.Fatalf("picker keys %v lack form-double", m.popup.choiceKeys)
	}
	if row := m.popup.choices[idx]; !strings.Contains(row, "Form double") || !strings.Contains(row, "paid") ||
		!strings.Contains(row, "npm,pypi") || !strings.Contains(row, "not configured") {
		t.Errorf("picker row %q", row)
	}
	m.popup.choiceCursor = idx
	m = pressPopupKey(m, tea.KeyMsg{Type: tea.KeyEnter})
	p := &m.popup
	if p.kind != popupForm || !p.integrationForm {
		t.Fatalf("Enter opened %v", p.kind)
	}
	if !strings.Contains(p.formNote, "The purl of every version, with the account token.") {
		t.Errorf("the data sentence is not on the form before saving: %q", p.formNote)
	}

	// Kinds drive the input, and help sits under each field.
	if f := formFieldNamed(t, p, "Strict"); !f.Checkbox || f.Value != "no" {
		t.Errorf("bool field = %+v", f)
	}
	if f := formFieldNamed(t, p, "Tier"); !f.Select || strings.Join(f.Options, ",") != "free,team" || f.Value != "free" {
		t.Errorf("enum field = %+v", f)
	}
	if f := formFieldNamed(t, p, "Endpoint"); f.Checkbox || f.Select || !strings.Contains(f.Hint, "Where queries go.") {
		t.Errorf("url field = %+v", f)
	}
	if f := formFieldNamed(t, p, "API token"); !f.Secret || f.Value != "" {
		t.Errorf("secret field = %+v", f)
	}
	if f := formFieldNamed(t, p, integrationNameLabel); f.Value != "form-double" || f.Disabled {
		t.Errorf("new instance name = %+v", f)
	}

	// 'j' types into a text field here rather than opening the raw-JSON
	// overlay the config form binds it to.
	p.formCursor = 2 // Endpoint
	p.formFields[2].cursor = len(p.formFields[2].Value)
	m = pressPopupKey(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	p = &m.popup
	if p.jsonInput || !strings.HasSuffix(formFieldNamed(t, p, "Endpoint").Value, "j") {
		t.Errorf("j: overlay %v, endpoint %q", p.jsonInput, formFieldNamed(t, p, "Endpoint").Value)
	}
	typeInto(t, p, "Endpoint", "https://api.vendor.example.test/")

	// The secret is masked on screen and kept out of the JSON view.
	typeInto(t, p, "API token", "sk-live-777")
	screen := p.renderForm()
	if strings.Contains(screen, "sk-live-777") || !strings.Contains(screen, "***********") {
		t.Errorf("the secret is not masked:\n%s", screen)
	}
	if strings.Contains(formFieldsToJSON(p.formFields), "sk-live-777") {
		t.Error("the raw-JSON view carries the secret")
	}

	// The shared validator stops a bad value and keeps the form open.
	typeInto(t, p, "Max batch", "9")
	if dismissed := p.HandleFormKey("enter"); dismissed || !strings.Contains(p.validationError, "integrations.form-double.max_batch: want a whole number from 1 to 5") {
		t.Fatalf("out-of-range save: dismissed %v, error %q", dismissed, p.validationError)
	}
	typeInto(t, p, "Max batch", "3")
	for i := range p.formFields {
		if p.formFields[i].Label == integrationEnabledLabel {
			p.formCursor = i
		}
	}
	p.HandleFormKey(" ")
	if dismissed := p.HandleFormKey("enter"); !dismissed {
		t.Fatalf("valid save kept the form open: %q", p.validationError)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "sk-live-777") {
		t.Fatalf("the secret reached the config file:\n%s", got)
	}
	if !strings.HasPrefix(string(got), strings.TrimSuffix(integrationFormConfig, "\n}\n")) {
		t.Errorf("keys the form does not own changed:\n%s", got)
	}
	entries, err := integration.FileEntries()
	if err != nil {
		t.Fatal(err)
	}
	e := entries["form-double"]
	if e["enabled"] != true || e["max_batch"] != 3.0 {
		t.Errorf("saved entry = %v", e)
	}
	for _, k := range []string{"endpoint", "tier", "strict"} {
		if _, set := e[k]; set {
			t.Errorf("%s left at its default was written: %v", k, e)
		}
	}
	file, _ := e["api_token_file"].(string)
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("api_token_file %q: %v %v", file, info, err)
	}
	if b, _ := os.ReadFile(file); strings.TrimSpace(string(b)) != "sk-live-777" {
		t.Errorf("stored secret = %q", b)
	}
	if _, err := config.Load("", "", "", "", false, false); err != nil {
		t.Errorf("the saved file no longer loads: %v", err)
	}

	// Reopened, the form edits the existing instance and keeps the stored
	// secret when the masked field is left empty.
	m = newAppModel(cfg, nil, nil, nil, nil)
	pp, err := m.openIntegrationForm("form-double")
	if err != nil {
		t.Fatal(err)
	}
	if f := formFieldNamed(t, &pp, integrationNameLabel); !f.Disabled {
		t.Error("an existing instance's name is editable")
	}
	if f := formFieldNamed(t, &pp, "Max batch"); f.Value != "3" {
		t.Errorf("reopened max batch = %q", f.Value)
	}
	if msg := validateIntegrationForm(mustLookup(t, "form-double"), e, pp.formFields); msg != "" {
		t.Errorf("reopened form does not validate: %s", msg)
	}
}

func mustLookup(t *testing.T, typ string) *integration.Descriptor {
	t.Helper()
	d, ok := integration.Lookup(typ)
	if !ok {
		t.Fatalf("%s not registered", typ)
	}
	return d
}
