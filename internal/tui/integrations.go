package tui

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/integration"
)

// Labels of the two fields every integration form carries ahead of the
// descriptor's own.
const (
	integrationNameLabel    = "Instance"
	integrationEnabledLabel = "Enabled"
)

// buildIntegrationPicker lists every registered integration type with its
// cost, ecosystems and whether an instance of it is configured and enabled.
func buildIntegrationPicker() (popupModel, error) {
	entries, err := integration.FileEntries()
	if err != nil {
		return popupModel{}, err
	}
	var labels, keys []string
	for _, d := range integration.Types() {
		state := "not configured"
		var names []string
		for _, n := range integration.SortedNames(entries) {
			if t, _ := entries[n]["type"].(string); t == d.Type {
				on, _ := entries[n]["enabled"].(bool)
				names = append(names, n+" "+map[bool]string{true: "enabled", false: "disabled"}[on])
			}
		}
		if len(names) > 0 {
			state = strings.Join(names, ", ")
		}
		labels = append(labels, fmt.Sprintf("%-20s %-9s %-12s %s", d.DisplayName, d.Cost, strings.Join(d.Ecosystems, ","), state))
		keys = append(keys, d.Type)
	}
	return popupModel{kind: popupChoice, choiceTitle: "Integrations (Enter to configure)", choices: labels,
		choiceKeys: keys, choiceFor: choiceIntegration}, nil
}

// openIntegrationForm opens the form for the first configured instance of
// typeName, or for a new one named after the type when there is none.
func (m appModel) openIntegrationForm(typeName string) (popupModel, error) {
	d, ok := integration.Lookup(typeName)
	if !ok {
		return popupModel{}, fmt.Errorf("unknown integration type %q", typeName)
	}
	entries, err := integration.FileEntries()
	if err != nil {
		return popupModel{}, err
	}
	name, entry, others := typeName, config.Integration{"type": typeName, "enabled": false}, 0
	existing := false
	for _, n := range integration.SortedNames(entries) {
		if t, _ := entries[n]["type"].(string); t != typeName {
			continue
		}
		if existing {
			others++
			continue
		}
		name, entry, existing = n, entries[n], true
	}
	return m.integrationForm(d, name, entry, existing, others), nil
}

// integrationFields generates a form's fields from a descriptor: a bool is a
// checkbox, an enum a choice list, a secret a masked field left empty, and
// every other kind a text field holding the value the file has, or the
// default. Each field's help text is its hint.
func integrationFields(d *integration.Descriptor, name string, entry config.Integration, existing bool) []formField {
	enabled, _ := entry["enabled"].(bool)
	fields := []formField{
		{Label: integrationNameLabel, Value: name, Disabled: existing, key: "",
			Hint: "lowercase letters, digits, '_' and '-'; the check is recorded as integration:<instance>"},
		{Label: integrationEnabledLabel, Value: yesNoValue(enabled), Checkbox: true, key: "enabled"},
	}
	for _, f := range d.Fields {
		ff := formField{Label: f.Label, key: f.Key, Hint: f.Help}
		v, set := entry[f.Key]
		switch {
		case f.Secret:
			ff.Secret = true
			ff.Hint += " Typed here, it is stored the way `bodega integration secret` stores it; leave empty to keep the stored one."
		case set:
			ff.Value = integration.FormatValue(v)
		default:
			ff.Value = f.Default
		}
		switch f.Kind {
		case integration.KindBool:
			ff.Checkbox = true
			b, _ := integration.ParseText(f, ff.Value)
			on, _ := b.(bool)
			ff.Value = yesNoValue(on)
		case integration.KindEnum:
			ff.Select = true
			ff.Options = append([]string(nil), f.Options...)
		}
		if f.Default != "" && !f.Secret {
			ff.Hint += " Default: " + f.Default + "."
		}
		fields = append(fields, ff)
	}
	return fields
}

func yesNoValue(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// integrationEntry turns a form's fields back into a config entry, starting
// from base so a key the form does not show (a <key>_file path) is kept. It
// returns the instance name and the secrets typed, by key. A field the file
// does not set and the form leaves at its default stays unset, so a later
// change to the default reaches it.
func integrationEntry(d *integration.Descriptor, base config.Integration, fields []formField) (string, config.Integration, map[string]string, error) {
	entry := config.Integration{}
	for k, v := range base {
		entry[k] = v
	}
	entry["type"] = d.Type
	secrets := map[string]string{}
	name := ""
	for _, ff := range fields {
		switch {
		case ff.Label == integrationNameLabel && ff.key == "":
			name = strings.TrimSpace(ff.Value)
			continue
		case ff.Secret:
			if ff.Value != "" {
				secrets[ff.key] = ff.Value
			}
			continue
		}
		text := ff.Value
		if ff.Checkbox {
			text = map[string]string{"yes": "true", "no": "false"}[ff.Value]
		}
		if f, ok := d.Field(ff.key); ok {
			_, inFile := base[ff.key]
			unset := text == f.Default || (f.Kind == integration.KindBool && f.Default == "" && text == "false")
			if unset && !inFile {
				continue
			}
		}
		if err := integration.SetText(entry, d, ff.key, text); err != nil {
			return name, nil, nil, fmt.Errorf("integrations.%s.%w", name, err)
		}
	}
	return name, entry, secrets, nil
}

// validateIntegrationForm runs the validator config.Load runs. An instance
// being enabled in the same save that stores its secret is checked as
// disabled, because the secret only exists once the save writes it.
func validateIntegrationForm(d *integration.Descriptor, base config.Integration, fields []formField) string {
	name, entry, secrets, err := integrationEntry(d, base, fields)
	if err != nil {
		return err.Error()
	}
	if len(secrets) > 0 {
		entry["enabled"] = false
	}
	if _, err := integration.ValidateInstance(name, entry); err != nil {
		return err.Error()
	}
	return ""
}

// saveIntegrationForm stores any typed secret through integration.WriteSecret,
// the path `bodega integration secret` takes, then writes the entry. Only
// this instance under the integrations key changes in the config file.
func saveIntegrationForm(d *integration.Descriptor, base config.Integration, fields []formField) (string, error) {
	name, entry, secrets, err := integrationEntry(d, base, fields)
	if err != nil {
		return "", err
	}
	if len(secrets) > 0 {
		probe := config.Integration{}
		for k, v := range entry {
			probe[k] = v
		}
		probe["enabled"] = false
		inst, err := integration.ValidateInstance(name, probe)
		if err != nil {
			return "", err
		}
		for key, value := range secrets {
			path, err := integration.WriteSecret(inst, key, strings.NewReader(value))
			if err != nil {
				return "", fmt.Errorf("store %s: %w", key, err)
			}
			entry[key+"_file"] = path
		}
	}
	return integration.SaveEntry(name, entry)
}

// integrationForm builds the form popup for one instance.
func (m appModel) integrationForm(d *integration.Descriptor, name string, base config.Integration, existing bool, others int) popupModel {
	note := fmt.Sprintf("%s, %s, covers %s. Sends: %s", d.VendorURL, d.Cost, strings.Join(d.Ecosystems, ", "), d.DataSent)
	if others > 0 {
		note += fmt.Sprintf(" %d more instance(s) of this type are configured; edit those with `bodega integration set`.", others)
	}
	note += " Enter saves, Ctrl+T tests with one real query, Esc cancels."
	title := "Integration: " + d.DisplayName
	if !existing {
		title += " (new)"
	}
	log := m.log
	adb := m.auditDB
	return popupModel{
		kind:            popupForm,
		integrationForm: true,
		formTitle:       title,
		formNote:        note,
		formFields:      integrationFields(d, name, base, existing),
		validate:        func(fields []formField) string { return validateIntegrationForm(d, base, fields) },
		onFormSave: func(fields []formField) {
			path, err := saveIntegrationForm(d, base, fields)
			if err != nil {
				log.appendLog(errorStyle.Render("Integration not saved: " + err.Error()))
				return
			}
			log.appendLog(successStyle.Render("Saved integration " + fieldValue(fields, integrationNameLabel) + " to " + path +
				"; a running bodega serve picks it up when it restarts"))
		},
		onTest: func(fields []formField) tea.Cmd {
			name, entry, _, err := integrationEntry(d, base, fields)
			if err != nil {
				return func() tea.Msg { return cmdOutputMsg{err: err} }
			}
			var store integration.Store
			if adb != nil {
				store = adb
			}
			return func() tea.Msg {
				var buf bytes.Buffer
				err := integration.RunTest(context.Background(), &buf, name, entry, store)
				return cmdOutputMsg{output: "Test " + name + ":\n" + strings.TrimRight(buf.String(), "\n"), err: err}
			}
		},
	}
}
