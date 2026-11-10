package clientconf

import (
	"fmt"
	"path"
	"reflect"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"

	"github.com/ravinald/bodega/internal/manifest"
)

// lineRules is how one line-oriented format spells a setting and continues
// its value, which is what tells a setting of the host's from the tail of
// one the plan replaces.
type lineRules struct {
	// key names the setting a line gives, "" for a line that gives none.
	key func(line string) string
	// indent says a line indented deeper than the key above it continues
	// that key's value, as Python's ConfigParser and dnf read one. A line at
	// the key's own indentation is the next key.
	indent bool
	// backslash says a line ending in a backslash runs on into the next.
	backslash bool
}

var (
	plainRules = lineRules{key: settingKey}
	// pip lowercases a key and reads _ as -, and ConfigParser takes a colon
	// for the equals sign.
	pipRules = lineRules{indent: true, key: func(line string) string {
		t := strings.TrimSpace(line)
		if t == "" || strings.ContainsRune("#;[", rune(t[0])) {
			return ""
		}
		i := strings.IndexAny(t, "=:")
		if i < 0 {
			return ""
		}
		return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(t[:i])), "_", "-")
	}}
	dnfRules   = lineRules{key: settingKey, indent: true}
	slashRules = lineRules{key: settingKey, backslash: true}
	makeRules  = lineRules{backslash: true, key: func(line string) string {
		if m := makeAssignment.FindStringSubmatch(line); m != nil {
			return m[1]
		}
		return ""
	}}
	fieldRules = lineRules{indent: true, key: func(line string) string {
		if line == "" || strings.ContainsRune("# \t", rune(line[0])) {
			return ""
		}
		name, _, ok := strings.Cut(line, ":")
		if !ok {
			return ""
		}
		return strings.ToLower(name)
	}}
)

// makeAssignment is a make variable assignment under any of its operators,
// which all name the one variable: an = left beside the plan's ?= would win.
var makeAssignment = regexp.MustCompile(`^([A-Za-z0-9_.{}()$-]+)[ \t]*[:+?!]?=`)

// fileKind is how an existing file of one client takes a plan's settings and
// keeps its own. The zero kind is a file written whole: one NewChange merged
// already, or a document that holds nothing but what the plan renders (a key,
// a script).
type fileKind struct {
	// rules merges a file of sectioned key and value lines.
	rules *lineRules
	// blocks merges a file of named entries, each replaced as a unit.
	blocks func(old, planned []string) []string
	// holds reports how merged fails to read as planned sets it, for a
	// format a line merge can leave saying something else.
	holds func(merged, planned []byte) error
}

func kindOf(rec PlanRecord) fileKind {
	name := path.Base(rec.Path)
	switch rec.System {
	case manifest.TypeNpm, manifest.TypeGomod:
		// .npmrc and go's env file take no continuation; the environment
		// files NodeMirror writes take a backslash.
		if name == ".npmrc" || name == "env" {
			return fileKind{rules: &plainRules}
		}
		return fileKind{rules: &slashRules}
	case manifest.TypePypi:
		return fileKind{rules: &pipRules}
	case manifest.TypeGit:
		return fileKind{rules: &slashRules}
	case manifest.TypeRpm:
		if strings.HasSuffix(name, ".repo") {
			return fileKind{rules: &dnfRules}
		}
	case manifest.TypeCargo:
		return fileKind{rules: &plainRules, holds: tomlHolds}
	case manifest.TypeOCI:
		switch {
		case name == "hosts.toml":
			return fileKind{rules: &plainRules, holds: tomlHolds}
		case OCIRuntimeOf(rec.Path) == RuntimePodman:
			return fileKind{blocks: mergeRegistries, holds: registriesHold}
		}
	case manifest.TypeRubygems:
		return fileKind{blocks: func(old, planned []string) []string { return mergeYAML(old, planned, "") }, holds: yamlHolds("")}
	case manifest.TypeHelm:
		return fileKind{blocks: func(old, planned []string) []string { return mergeYAML(old, planned, "repositories") }, holds: yamlHolds("repositories")}
	case manifest.TypeApt:
		if strings.HasSuffix(name, ".sources") {
			return fileKind{blocks: mergeDeb822}
		}
	case manifest.TypeFreeBSD:
		if strings.HasSuffix(name, ".conf") {
			return fileKind{blocks: mergeUCL}
		}
	case manifest.TypeDistfiles:
		if name == "make.conf" {
			return fileKind{blocks: mergeMakeConf}
		}
	}
	return fileKind{}
}

// merge returns old with planned's settings in it, and an error when the
// result would not read as planned sets it.
func (k fileKind) merge(old, planned []byte) ([]byte, error) {
	var lines []string
	switch {
	case k.rules != nil:
		lines = mergeSettings(splitBody(old), splitBody(planned), *k.rules)
	case k.blocks != nil:
		lines = k.blocks(splitBody(old), splitBody(planned))
	default:
		return planned, nil
	}
	merged := joinBody(lines)
	if k.holds != nil {
		if err := k.holds(merged, planned); err != nil {
			return nil, err
		}
	}
	return merged, nil
}

// block is a run of lines that stays or goes together. id names an entry a
// plan can replace, and is "" for the lines between entries.
type block struct {
	id    string
	lines []string
}

// replaceBlocks puts each of planned's entries where old holds the entry of
// that id, dropping a second old entry of the same id, and adds the entries
// old lacks at the end, after a blank line when gap is set. Every other line
// of old stays where it was.
func replaceBlocks(old, planned []block, gap bool) []string {
	byID := map[string][]string{}
	var order []string
	for _, b := range planned {
		if b.id == "" {
			continue
		}
		if _, ok := byID[b.id]; !ok {
			order = append(order, b.id)
		}
		byID[b.id] = b.lines
	}
	placed := map[string]bool{}
	var out []string
	for _, b := range old {
		lines, ok := byID[b.id]
		switch {
		case b.id == "" || !ok:
			out = append(out, b.lines...)
		case !placed[b.id]:
			placed[b.id] = true
			out = append(out, lines...)
		}
	}
	for _, id := range order {
		if placed[id] {
			continue
		}
		if gap && len(out) > 0 && strings.TrimSpace(out[len(out)-1]) != "" {
			out = append(out, "")
		}
		out = append(out, byID[id]...)
	}
	return out
}

// splitEntries cuts lines into blocks. starts reports whether an entry opens
// at line i, and ends the index past its last line. The comment lines
// directly above an entry belong to it, and the blank lines below it do not.
func splitEntries(lines []string, starts func(i int) bool, ends func(i int) int, id func(entry []string) string) []block {
	var out []block
	filler := func(from, to int) {
		if from < to {
			out = append(out, block{lines: lines[from:to]})
		}
	}
	last := 0
	for i := 0; i < len(lines); {
		if !starts(i) {
			i++
			continue
		}
		end := ends(i)
		for end > i+1 && strings.TrimSpace(lines[end-1]) == "" {
			end--
		}
		lead := i
		for lead > last && strings.HasPrefix(strings.TrimSpace(lines[lead-1]), "#") {
			lead--
		}
		filler(last, lead)
		out = append(out, block{id: id(lines[i:end]), lines: lines[lead:end]})
		i, last = end, end
	}
	filler(last, len(lines))
	return out
}

func tomlHeader(line string) string {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "[") {
		return ""
	}
	if i := strings.Index(t, "#"); i > 0 {
		t = strings.TrimSpace(t[:i])
	}
	return strings.Join(strings.Fields(t), "")
}

type registriesDoc struct {
	Registry []map[string]any `toml:"registry"`
}

func registryID(r map[string]any) string {
	for _, key := range []string{"prefix", "location"} {
		if s, _ := r[key].(string); s != "" {
			return s
		}
	}
	return ""
}

// mergeRegistries merges a containers-registries.conf drop-in: each
// [[registry]] the plan renders, with the tables under it, replaces the
// host's entry for that prefix, and the host's other registries, its other
// tables and its top-level keys stay.
func mergeRegistries(old, planned []string) []string {
	split := func(lines []string) []block {
		return splitEntries(lines,
			func(i int) bool { return tomlHeader(lines[i]) == "[[registry]]" },
			func(i int) int {
				end := i + 1
				for end < len(lines) {
					if h := tomlHeader(lines[end]); h != "" && !strings.HasPrefix(h, "[[registry.") && !strings.HasPrefix(h, "[registry.") {
						break
					}
					end++
				}
				return end
			},
			func(entry []string) string {
				var doc registriesDoc
				if _, err := toml.Decode(strings.Join(entry, "\n"), &doc); err != nil || len(doc.Registry) != 1 {
					return ""
				}
				return registryID(doc.Registry[0])
			})
	}
	return replaceBlocks(split(old), split(planned), true)
}

func registriesHold(merged, planned []byte) error {
	var m, p registriesDoc
	if _, err := toml.Decode(string(merged), &m); err != nil {
		return err
	}
	if _, err := toml.Decode(string(planned), &p); err != nil {
		return err
	}
	for _, want := range p.Registry {
		n := 0
		for _, have := range m.Registry {
			if registryID(have) != registryID(want) {
				continue
			}
			if n++; !reflect.DeepEqual(have, want) {
				return fmt.Errorf("the registry %q would keep settings the plan does not give it", registryID(want))
			}
		}
		if n != 1 {
			return fmt.Errorf("the registry %q would be defined %d times", registryID(want), n)
		}
	}
	return nil
}

// tomlHolds reports the first of planned's values merged does not read the
// same, or that merged does not decode at all.
func tomlHolds(merged, planned []byte) error {
	var m, p map[string]any
	if _, err := toml.Decode(string(merged), &m); err != nil {
		return err
	}
	if _, err := toml.Decode(string(planned), &p); err != nil {
		return err
	}
	return treeHolds(m, p, "")
}

func treeHolds(have, want map[string]any, at string) error {
	for key, w := range want {
		h, ok := have[key]
		sub, isTable := w.(map[string]any)
		switch hsub, _ := h.(map[string]any); {
		case !ok:
			return fmt.Errorf("%s%s would not be set", at, key)
		case isTable && hsub != nil:
			if err := treeHolds(hsub, sub, at+key+"."); err != nil {
				return err
			}
		case !reflect.DeepEqual(h, w):
			return fmt.Errorf("%s%s would read %v, not the plan's %v", at, key, h, w)
		}
	}
	return nil
}

// yamlTopKey is the key a line opens at the top level of a YAML mapping, "" for
// any other line.
func yamlTopKey(line string) string {
	if line == "" || strings.ContainsRune(" \t#-", rune(line[0])) || line == "..." {
		return ""
	}
	if i := strings.Index(line, ": "); i > 0 {
		return line[:i]
	}
	if key, ok := strings.CutSuffix(strings.TrimRight(line, " "), ":"); ok {
		return key
	}
	return ""
}

// mergeYAML merges a YAML mapping key by key at its top level: each key the
// plan renders replaces the host's, and the host's other keys stay. Under
// the key named items, a sequence of named entries, the host's entries the
// plan does not name are kept after the plan's.
func mergeYAML(old, planned []string, items string) []string {
	split := func(lines []string) []block {
		return splitEntries(lines,
			func(i int) bool { return yamlTopKey(lines[i]) != "" },
			func(i int) int {
				end := i + 1
				for end < len(lines) && yamlTopKey(lines[end]) == "" && lines[end] != "---" && lines[end] != "..." {
					end++
				}
				return end
			},
			func(entry []string) string { return yamlTopKey(entry[0]) })
	}
	was, now := split(old), split(planned)
	if items != "" {
		for i, b := range now {
			if b.id != items {
				continue
			}
			for _, o := range was {
				if o.id == items {
					now[i].lines = append(b.lines[:len(b.lines):len(b.lines)], yamlOtherItems(o.lines, b.lines)...)
				}
			}
		}
	}
	return replaceBlocks(was, now, false)
}

// yamlOtherItems is each sequence item of old whose name no item of planned
// carries, indented as planned's items are.
func yamlOtherItems(old, planned []string) []string {
	names, indent := map[string]bool{}, -1
	for i := 0; i < len(planned); {
		end := yamlItemEnd(planned, i)
		if end == i {
			i++
			continue
		}
		if indent < 0 {
			indent = leadingSpaces(planned[i])
		}
		names[yamlItemField(planned[i:end], "name")] = true
		i = end
	}
	var out []string
	for i := 0; i < len(old); {
		end := yamlItemEnd(old, i)
		if end == i {
			i++
			continue
		}
		if item := old[i:end]; !names[yamlItemField(item, "name")] {
			shift := leadingSpaces(item[0])
			if indent < 0 {
				indent = shift
			}
			for _, l := range item {
				out = append(out, strings.Repeat(" ", indent)+l[min(shift, leadingSpaces(l)):])
			}
		}
		i = end
	}
	return out
}

// yamlHolds checks merged gives each top-level key the value planned gives
// it, and under items at least planned's entries.
func yamlHolds(items string) func(merged, planned []byte) error {
	return func(merged, planned []byte) error {
		var m, p map[string]any
		if err := yaml.Unmarshal(merged, &m); err != nil {
			return err
		}
		if err := yaml.Unmarshal(planned, &p); err != nil {
			return err
		}
		for key, want := range p {
			have := m[key]
			if key != items {
				if !reflect.DeepEqual(have, want) {
					return fmt.Errorf("%s would read %v, not the plan's %v", key, have, want)
				}
				continue
			}
			haveItems, _ := have.([]any)
			wantItems, _ := want.([]any)
			for _, w := range wantItems {
				found := false
				for _, h := range haveItems {
					found = found || reflect.DeepEqual(h, w)
				}
				if !found {
					return fmt.Errorf("%s would not hold the plan's entry %v", key, w)
				}
			}
		}
		return nil
	}
}

// mergeDeb822 merges an apt .sources file: the plan's stanza replaces the
// host's stanza for the same URIs, and the host's other stanzas stay. A
// stanza is replaced whole because its fields are one source's definition: a
// Trusted: yes kept beside the plan's Signed-By: would turn verification off.
func mergeDeb822(old, planned []string) []string {
	split := func(lines []string) []block {
		return splitEntries(lines,
			func(i int) bool { return fieldRules.key(lines[i]) != "" },
			func(i int) int {
				end := i + 1
				for end < len(lines) && strings.TrimSpace(lines[end]) != "" {
					end++
				}
				return end
			},
			func(entry []string) string {
				for _, l := range entry {
					if fieldRules.key(l) == "uris" {
						return strings.Join(strings.Fields(l[len("uris:"):]), " ")
					}
				}
				return ""
			})
	}
	return replaceBlocks(split(old), split(planned), true)
}

var (
	uclObject = regexp.MustCompile(`^\s*("[^"]*"|[A-Za-z0-9_.-]+)\s*[:=]?\s*\{`)
	uclString = regexp.MustCompile(`"(\\.|[^"\\])*"`)
)

// mergeUCL merges a pkg repository file: each object the plan renders
// replaces the host's object of that tag, and the host's other objects stay.
// The comment block a plan opens the file with is replaced when the host's
// file opens with the same line, since it describes the objects under it.
func mergeUCL(old, planned []string) []string {
	split := func(lines []string) []block {
		return splitEntries(lines,
			func(i int) bool { return uclObject.MatchString(lines[i]) },
			func(i int) int {
				depth := 0
				for end := i; end < len(lines); end++ {
					bare := uclString.ReplaceAllString(lines[end], "")
					if c := strings.Index(bare, "#"); c >= 0 {
						bare = bare[:c]
					}
					if depth += strings.Count(bare, "{") - strings.Count(bare, "}"); depth <= 0 {
						return end + 1
					}
				}
				return len(lines)
			},
			func(entry []string) string { return strings.Trim(uclObject.FindStringSubmatch(entry[0])[1], `"`) })
	}
	was, now := split(old), split(planned)
	if len(was) > 0 && len(now) > 0 && was[0].id == "" && now[0].id == "" && was[0].lines[0] == now[0].lines[0] {
		was[0].lines = now[0].lines
	}
	return replaceBlocks(was, now, true)
}

// mergeMakeConf merges make.conf: each variable the plan assigns replaces the
// host's assignment of it under any operator, and every other line the plan
// renders (the .include of the distfiles check) ends the file, where it sees
// every assignment above it.
func mergeMakeConf(old, planned []string) []string {
	out := mergeSettings(old, planned, makeRules)
	for _, l := range planned {
		if makeRules.key(l) != "" || strings.TrimSpace(l) == "" || strings.HasPrefix(l, "#") {
			continue
		}
		kept := out[:0:0]
		for _, o := range out {
			if strings.TrimSpace(o) != strings.TrimSpace(l) {
				kept = append(kept, o)
			}
		}
		out = append(kept, l)
	}
	return out
}
