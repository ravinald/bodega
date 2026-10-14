package integration

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/ravinald/bodega/internal/config"
)

// ConfigKey is the config file key every instance lives under.
const ConfigKey = "integrations"

// FileEntries reads the integrations block from the config file in force,
// as written, without validating it: `show` and a repair by the CLI both
// need to read a block that no longer loads.
func FileEntries() (map[string]config.Integration, error) {
	raw, ok, err := config.FileKey(ConfigKey)
	if err != nil || !ok {
		return map[string]config.Integration{}, err
	}
	var out map[string]config.Integration
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("%s in %s: want an object of instance name to settings: %w", ConfigKey, config.ConfigPath(), err)
	}
	if out == nil {
		out = map[string]config.Integration{}
	}
	return out, nil
}

// SaveEntry validates entry as instance name and writes it into the config
// file's integrations block, leaving every other instance's bytes and every
// other config key as the file has them. It returns the path written.
func SaveEntry(name string, entry config.Integration) (string, error) {
	if _, err := ValidateInstance(name, entry); err != nil {
		return "", err
	}
	return writeEntry(name, entry)
}

// RemoveEntry deletes an instance from the integrations block, and the block
// itself when it is left empty.
func RemoveEntry(name string) (string, error) {
	return writeEntry(name, nil)
}

func writeEntry(name string, entry config.Integration) (string, error) {
	raw, ok, err := config.FileKey(ConfigKey)
	if err != nil {
		return "", err
	}
	block := map[string]json.RawMessage{}
	if ok {
		if err := json.Unmarshal(raw, &block); err != nil {
			return "", fmt.Errorf("%s in %s: want an object of instance name to settings: %w", ConfigKey, config.ConfigPath(), err)
		}
	}
	if entry == nil {
		if _, ok := block[name]; !ok {
			return "", fmt.Errorf("no integration instance %q in %s", name, config.ConfigPath())
		}
		delete(block, name)
	} else {
		b, err := json.Marshal(entry)
		if err != nil {
			return "", err
		}
		block[name] = b
	}
	if len(block) == 0 {
		return config.SetFileKey(ConfigKey, nil)
	}
	return config.SetFileKey(ConfigKey, block)
}

// SetText parses text as d's field key and sets it on entry. An empty text
// on a field with a default removes the key, so the default applies again.
func SetText(entry config.Integration, d *Descriptor, key, text string) error {
	if key == "enabled" {
		v, err := ParseText(Field{Key: key, Kind: KindBool}, text)
		if err != nil {
			return fmt.Errorf("enabled: %w", err)
		}
		entry[key] = v
		return nil
	}
	if key == "type" {
		return fmt.Errorf("type: an instance's type is fixed when it is added; remove it and add another")
	}
	f, ok := d.Field(key)
	if !ok {
		if base, isFile := strings.CutSuffix(key, secretFileSuffix); isFile {
			if bf, ok := d.Field(base); ok && bf.Secret {
				entry[key] = text
				return nil
			}
		}
		return fmt.Errorf("%s: unknown key for type %s (accepted: %s)", key, d.Type, acceptedKeys(d))
	}
	if f.Secret {
		return fmt.Errorf("%s: a secret is never written in the config file; use `bodega integration secret`", key)
	}
	if text == "" {
		delete(entry, key)
		return nil
	}
	v, err := ParseText(f, text)
	if err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	entry[key] = v
	return nil
}

// SortedNames returns an integrations block's instance names, sorted.
func SortedNames(entries map[string]config.Integration) []string {
	names := make([]string, 0, len(entries))
	for n := range entries {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// DocTable renders the registered types as the Markdown table docs/usage.md
// carries, padded the way prettier pads one, so a test can fail when the
// documentation and the registry disagree.
func DocTable() string {
	rows := [][]string{{"Type", "Name", "Cost", "Ecosystems", "Default action", "What leaves the host"}}
	for _, d := range Types() {
		rows = append(rows, []string{"`" + d.Type + "`", "[" + d.DisplayName + "](" + d.VendorURL + ")", string(d.Cost),
			strings.Join(d.Ecosystems, ", "), d.DefaultAction, d.DataSent})
	}
	widths := make([]int, len(rows[0]))
	for _, r := range rows {
		for i, c := range r {
			widths[i] = max(widths[i], len([]rune(c)), 3)
		}
	}
	var sb strings.Builder
	line := func(cells []string) {
		sb.WriteString("|")
		for i, c := range cells {
			sb.WriteString(" " + c + strings.Repeat(" ", widths[i]-len([]rune(c))) + " |")
		}
		sb.WriteString("\n")
	}
	line(rows[0])
	sep := make([]string, len(widths))
	for i, w := range widths {
		sep[i] = strings.Repeat("-", w)
	}
	line(sep)
	for _, r := range rows[1:] {
		line(r)
	}
	return sb.String()
}
