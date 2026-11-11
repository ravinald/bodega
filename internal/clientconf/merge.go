package clientconf

import (
	"fmt"
	"maps"
	"path"
	"reflect"
	"regexp"
	"slices"
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
	// An npmrc names an option the way npm's own reader decodes the line, so
	// a quoted name is the option it spells and a name is matched exactly.
	npmRules = lineRules{key: npmKey}
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
// already, or a document that holds nothing but the one value the plan
// renders (a key).
type fileKind struct {
	// block merges a file bodega renders as one block, which a person may
	// have written lines of their own around.
	block func(old, planned []byte) ([]byte, error)
	// rules merges a file of sectioned key and value lines.
	rules *lineRules
	// blocks merges a file of named entries, each taking the plan's fields
	// and keeping its own.
	blocks func(old, planned []string) []string
	// holds reports how merged fails to read as planned sets it, for a
	// format a line merge can leave saying something else.
	holds func(merged, planned []byte) error
	// keeps reports what of old merged no longer gives that the plan did not
	// set: holds reads the plan's side of a merge, and this reads the
	// host's, so a merger that drops what it does not follow is refused
	// rather than trusted.
	keeps func(old, merged, planned []byte) error
	// unread returns the first line of a body that opens a section in a form
	// the merge does not match sections by, "" for none. The client reads
	// such a section, so a setting under it can outrank or duplicate the
	// plan's without the merge seeing it.
	unread func(lines []string) string
}

var plainSection = regexp.MustCompile(`^\[[^\[\]]+\]$`)

// strayHeader is unread for a format whose sections open on a line holding
// [name] and nothing else.
func strayHeader(rules lineRules) func(lines []string) string {
	return func(lines []string) string {
		scan := lineScan{rules: rules, keyIndent: -1}
		for _, l := range lines {
			if scan.continues(l) {
				continue
			}
			t := strings.TrimSpace(l)
			switch {
			case strings.HasPrefix(t, "[") && !plainSection.MatchString(t):
				return t
			case strings.HasPrefix(t, "["):
				scan.keyIndent = -1
			case rules.key(l) != "":
				scan.keyIndent = indentOf(l)
			}
		}
		return ""
	}
}

// gitUnread is unread for a git config file.
func gitUnread(lines []string) string {
	if _, unread := gitCAInfos(lines, "", ""); len(unread) > 0 {
		return unread[0]
	}
	return ""
}

// linesKeep reports the first line of old that merged dropped without the
// plan setting its key: a header, a comment, or a setting of the host's own.
// A setting the plan gives goes with the lines continuing it.
func linesKeep(old, merged, planned []string, rules lineRules) error {
	left := map[string]int{}
	for _, l := range merged {
		left[l]++
	}
	set := map[string]bool{}
	for _, l := range planned {
		if k := rules.key(l); k != "" {
			set[k] = true
		}
	}
	scan := lineScan{rules: rules, keyIndent: -1}
	replaced := false
	for _, l := range old {
		cont := scan.continues(l)
		t := strings.TrimSpace(l)
		k := ""
		if !cont {
			switch k = rules.key(l); {
			case strings.HasPrefix(t, "["):
				scan.keyIndent = -1
			case k != "":
				scan.keyIndent = indentOf(l)
			}
		}
		if left[l] > 0 {
			left[l]--
			if k != "" {
				replaced = false
			}
			continue
		}
		switch {
		case t == "", cont && replaced:
		case k != "" && set[k]:
			replaced = true
		default:
			return fmt.Errorf("the merge would drop the line %q, which the plan does not set", t)
		}
	}
	return nil
}

func kindOf(rec PlanRecord) fileKind {
	name := path.Base(rec.Path)
	switch rec.System {
	case manifest.TypeGomod:
		return fileKind{rules: &plainRules, unread: strayHeader(plainRules)}
	case manifest.TypeNpm:
		// An npmrc takes no continuation, under whatever name the
		// environment gives it; the environment files NodeMirror writes take
		// a backslash.
		if rec.Path == NodeMirrorSystemPath || rec.Path == NodeMirrorUserPath {
			return fileKind{rules: &slashRules}
		}
		return fileKind{rules: &npmRules, unread: strayHeader(npmRules)}
	case manifest.TypePypi:
		return fileKind{rules: &pipRules, unread: strayHeader(pipRules)}
	case manifest.TypeGit:
		return fileKind{rules: &slashRules, unread: gitUnread}
	case manifest.TypeRpm:
		if strings.HasSuffix(name, ".repo") {
			return fileKind{rules: &dnfRules, unread: strayHeader(dnfRules)}
		}
	case manifest.TypeCargo:
		return fileKind{rules: &plainRules, holds: tomlHolds, keeps: tomlKeeps}
	case manifest.TypeOCI:
		switch {
		case name == "hosts.toml":
			return fileKind{rules: &plainRules, holds: tomlHolds, keeps: tomlKeeps}
		case OCIRuntimeOf(rec.Path) == RuntimePodman:
			return fileKind{blocks: mergeRegistries, holds: registriesHold, keeps: registriesKeep}
		}
	case manifest.TypeMaven:
		if rec.Path == GradleInitPath {
			return fileKind{block: mergeGradleInit}
		}
	case manifest.TypeRubygems:
		return fileKind{blocks: func(old, planned []string) []string { return mergeYAML(old, planned, "") }, holds: yamlHolds(""), keeps: yamlKeeps("")}
	case manifest.TypeHelm:
		return fileKind{blocks: func(old, planned []string) []string { return mergeYAML(old, planned, "repositories") }, holds: yamlHolds("repositories"), keeps: yamlKeeps("repositories")}
	case manifest.TypeApt:
		if strings.HasSuffix(name, ".sources") {
			return fileKind{blocks: mergeDeb822}
		}
	case manifest.TypeFreeBSD:
		if strings.HasSuffix(name, ".conf") {
			return fileKind{blocks: mergeUCL, holds: uclHolds, keeps: uclKeeps}
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
	if k.unread != nil {
		if line := k.unread(splitBody(old)); line != "" {
			return nil, fmt.Errorf("the line %q opens a section in a form this merge does not match sections by", line)
		}
	}
	switch {
	case k.block != nil:
		return k.block(old, planned)
	case k.rules != nil:
		lines = mergeSettings(splitBody(old), splitBody(planned), *k.rules)
		if err := linesKeep(splitBody(old), lines, splitBody(planned), *k.rules); err != nil {
			return nil, err
		}
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
	if k.keeps != nil {
		if err := k.keeps(old, merged, planned); err != nil {
			return nil, err
		}
	}
	return merged, nil
}

// treeKeeps reports the first value of old, a decoded document, that merged
// gives differently and planned does not set. Tables are walked; anything
// else, a list included, is one value.
func treeKeeps(old, merged, planned map[string]any, at string) error {
	for key, o := range old {
		m, ok := merged[key]
		p, set := planned[key]
		osub, isTable := o.(map[string]any)
		msub, _ := m.(map[string]any)
		switch {
		case isTable && msub != nil:
			psub, _ := p.(map[string]any)
			if err := treeKeeps(osub, msub, psub, at+key+"."); err != nil {
				return err
			}
		case set, ok && reflect.DeepEqual(o, m):
		default:
			return fmt.Errorf("the merge would not keep %s%s, which the plan does not set", at, key)
		}
	}
	return nil
}

// tomlKeeps is keeps for a TOML file merged setting by setting.
func tomlKeeps(old, merged, planned []byte) error {
	var o, m, p map[string]any
	if _, err := toml.Decode(string(old), &o); err != nil {
		return fmt.Errorf("the file as it stands does not read as TOML: %w", err)
	}
	if _, err := toml.Decode(string(merged), &m); err != nil {
		return err
	}
	if _, err := toml.Decode(string(planned), &p); err != nil {
		return err
	}
	return treeKeeps(o, m, p, "")
}

// registriesKeep is keeps for a containers-registries.conf drop-in: every
// top-level key and every registry the plan does not name reads as it did,
// and a registry the plan names keeps its own keys and its other mirrors in
// their order. insecure in the plan's own mirror is the plan's to give.
func registriesKeep(old, merged, planned []byte) error {
	var o, m, p map[string]any
	if _, err := toml.Decode(string(old), &o); err != nil {
		return fmt.Errorf("the file as it stands does not read as TOML: %w", err)
	}
	if _, err := toml.Decode(string(merged), &m); err != nil {
		return err
	}
	if _, err := toml.Decode(string(planned), &p); err != nil {
		return err
	}
	tables := func(v any) []map[string]any {
		list, _ := v.([]map[string]any)
		return list
	}
	byID := func(list []map[string]any, id string) map[string]any {
		for _, r := range list {
			if registryID(r) == id {
				return r
			}
		}
		return nil
	}
	location := func(r map[string]any) string { s, _ := r["location"].(string); return s }
	rest := func(doc map[string]any) map[string]any {
		out := maps.Clone(doc)
		delete(out, "registry")
		return out
	}
	if err := treeKeeps(rest(o), rest(m), rest(p), ""); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, r := range tables(o["registry"]) {
		id := registryID(r)
		want := byID(tables(p["registry"]), id)
		if want == nil {
			if !slices.ContainsFunc(tables(m["registry"]), func(h map[string]any) bool { return reflect.DeepEqual(h, r) }) {
				return fmt.Errorf("the merge would not keep the registry %q as the host wrote it", id)
			}
			continue
		}
		// A second entry of one prefix is a second definition of the one
		// registry, which containers/image refuses; the merge keeps the first.
		if seen[id] {
			continue
		}
		seen[id] = true
		have := byID(tables(m["registry"]), id)
		planned := func(loc string) map[string]any {
			for _, w := range tables(want["mirror"]) {
				if location(w) == loc {
					return w
				}
			}
			return nil
		}
		for key, v := range r {
			if _, set := want[key]; set || key == "mirror" {
				continue
			}
			if !reflect.DeepEqual(have[key], v) {
				return fmt.Errorf("the merge would not keep %s of the registry %q", key, id)
			}
		}
		var was, now []map[string]any
		for _, om := range tables(r["mirror"]) {
			w := planned(location(om))
			if w == nil {
				was = append(was, om)
				continue
			}
			hm := byID(tables(have["mirror"]), location(om))
			for key, v := range om {
				if _, set := w[key]; set || key == "insecure" {
					continue
				}
				if !reflect.DeepEqual(hm[key], v) {
					return fmt.Errorf("the merge would not keep %s of the mirror %q of the registry %q", key, location(om), id)
				}
			}
		}
		for _, hm := range tables(have["mirror"]) {
			if planned(location(hm)) == nil {
				now = append(now, hm)
			}
		}
		if !reflect.DeepEqual(was, now) {
			return fmt.Errorf("the merge would not keep the other mirrors of the registry %q in the order the host tries them", id)
		}
	}
	return nil
}

// yamlKeeps is keeps for a YAML mapping merged key by key: every top-level
// key the plan does not render reads as it did, and under items every entry
// the plan does not name is still there, while the entry the plan names keeps
// each field the plan does not give it. caFile is the plan's to remove from
// its own entry, and a second entry of the plan's name is a second definition
// of the one repository, which the merge drops.
func yamlKeeps(items string) func(old, merged, planned []byte) error {
	return func(old, merged, planned []byte) error {
		var o, m, p map[string]any
		if err := yaml.Unmarshal(old, &o); err != nil {
			return fmt.Errorf("the file as it stands does not read as YAML: %w", err)
		}
		if err := yaml.Unmarshal(merged, &m); err != nil {
			return err
		}
		if err := yaml.Unmarshal(planned, &p); err != nil {
			return err
		}
		named := func(v any, name any) map[string]any {
			list, _ := v.([]any)
			for _, e := range list {
				if em, _ := e.(map[string]any); em != nil && reflect.DeepEqual(em["name"], name) {
					return em
				}
			}
			return nil
		}
		for key, was := range o {
			if _, set := p[key]; !set {
				if !reflect.DeepEqual(m[key], was) {
					return fmt.Errorf("the merge would not keep %s, which the plan does not set", key)
				}
				continue
			}
			if key != items {
				continue
			}
			list, isList := was.([]any)
			if !isList && was != nil {
				return fmt.Errorf("%s is not a sequence of entries, so what it holds cannot be kept entry by entry", key)
			}
			seen := map[any]bool{}
			for _, e := range list {
				em, _ := e.(map[string]any)
				var want map[string]any
				if name, ok := em["name"].(string); ok {
					want = named(p[key], name)
				}
				if want == nil {
					now, _ := m[key].([]any)
					if !slices.ContainsFunc(now, func(h any) bool { return reflect.DeepEqual(h, e) }) {
						return fmt.Errorf("the merge would not keep the entry %v of %s", e, key)
					}
					continue
				}
				if seen[em["name"]] {
					continue
				}
				seen[em["name"]] = true
				have := named(m[key], em["name"])
				for field, v := range em {
					if _, set := want[field]; set || field == "caFile" {
						continue
					}
					if !reflect.DeepEqual(have[field], v) {
						return fmt.Errorf("the merge would not keep %s of the entry %v of %s", field, em["name"], key)
					}
				}
			}
		}
		return nil
	}
}

// block is a run of lines that stays or goes together. id names an entry a
// plan can replace, and is "" for the lines between entries.
type block struct {
	id    string
	lines []string
}

// mergeBlocks merges each of planned's entries into the entry of old with
// that id, through merge, which sets the plan's fields and keeps the entry's
// others. Entries sharing an id pair off in order; an old entry left without
// a partner while the plan names its id is dropped, as a second definition of
// the one source. The entries old lacks are added at the end, after a blank
// line when gap is set. Every other line of old stays where it was.
func mergeBlocks(old, planned []block, gap bool, merge func(old, planned []string) []string) []string {
	byID := map[string][][]string{}
	var order []string
	for _, b := range planned {
		if b.id == "" {
			continue
		}
		if _, ok := byID[b.id]; !ok {
			order = append(order, b.id)
		}
		byID[b.id] = append(byID[b.id], b.lines)
	}
	placed := map[string]int{}
	var out []string
	for _, b := range old {
		queue, ok := byID[b.id]
		switch n := placed[b.id]; {
		case b.id == "" || !ok:
			out = append(out, b.lines...)
		case n < len(queue):
			placed[b.id]++
			out = append(out, merge(b.lines, queue[n])...)
		}
	}
	for _, id := range order {
		for _, lines := range byID[id][min(placed[id], len(byID[id])):] {
			if gap && len(out) > 0 && strings.TrimSpace(out[len(out)-1]) != "" {
				out = append(out, "")
			}
			out = append(out, lines...)
		}
	}
	return out
}

// settings groups the lines of a body into its settings, each with the lines
// continuing it, in order. Lines giving no key are left out.
func settings(lines []string, rules lineRules) (keys []string, byKey map[string][]string) {
	byKey = map[string][]string{}
	scan := lineScan{rules: rules, keyIndent: -1}
	current := ""
	for _, l := range lines {
		if scan.continues(l) {
			if current != "" {
				byKey[current] = append(byKey[current], l)
			}
			continue
		}
		if current = rules.key(l); current == "" {
			continue
		}
		scan.keyIndent = indentOf(l)
		if _, ok := byKey[current]; !ok {
			keys = append(keys, current)
		}
		byKey[current] = []string{l}
	}
	return keys, byKey
}

// setFields sets each setting of planned in the one entry lines holds: a
// setting of the same key is replaced where it stands, with the lines
// continuing it, a second line of that key is dropped, and a setting the
// entry lacks follows its last line. drop names further settings of the
// entry to remove, by key and line, for a field that cannot stand beside the
// plan's. Every other line stays: the entry's other settings, its comments
// and their order.
func setFields(lines, planned []string, rules lineRules, drop func(key, line string) bool) []string {
	keys, byKey := settings(planned, rules)
	placed := map[string]bool{}
	var out []string
	scan := lineScan{rules: rules, keyIndent: -1}
	dropping := false
	for _, l := range lines {
		if scan.continues(l) {
			if !dropping {
				out = append(out, l)
			}
			continue
		}
		if k := rules.key(l); k != "" {
			scan.keyIndent = indentOf(l)
			set, ok := byKey[k]
			switch dropping = ok || drop != nil && drop(k, l); {
			case ok && !placed[k]:
				placed[k] = true
				out = append(out, set...)
				continue
			case dropping:
				continue
			}
		}
		out = append(out, l)
	}
	end := len(out)
	for end > 0 && strings.TrimSpace(out[end-1]) == "" {
		end--
	}
	var more []string
	for _, k := range keys {
		if !placed[k] {
			more = append(more, byKey[k]...)
		}
	}
	return slices.Insert(out, end, more...)
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
// [[registry]] the plan renders joins the host's entry for that prefix field
// by field, and the host's other registries, its other tables and its
// top-level keys stay.
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
	return mergeBlocks(split(old), split(planned), true, mergeRegistry)
}

// tomlTables cuts one [[registry]] entry into the lines of the registry
// itself and each table under it, a table opening at its header.
func tomlTables(entry []string) [][]string {
	out := [][]string{nil}
	for i, l := range entry {
		if h := tomlHeader(l); i > 0 && h != "" && h != "[[registry]]" {
			out = append(out, nil)
		}
		out[len(out)-1] = append(out[len(out)-1], l)
	}
	return out
}

// tomlStringOf is the string the table's lines give key, "" for none.
func tomlStringOf(table []string, key string) string {
	for _, l := range table {
		if plainRules.key(l) != key {
			continue
		}
		var doc map[string]any
		if _, err := toml.Decode(l, &doc); err == nil {
			s, _ := doc[key].(string)
			return s
		}
	}
	return ""
}

// mergeRegistry sets the plan's keys in the host's registry entry and keeps
// its others: the entry's own policy keys, and its other mirrors, which stay
// in the order the host tries them. The plan's mirror joins the mirror table
// of the same location, or leads the mirrors when there is none, since the
// plan's is the one tried first. insecure in bodega's own mirror table is the
// plan's to give, so one the plan does not render is removed: it is what a
// plaintext plan wrote there, and it turns verification off.
func mergeRegistry(old, planned []string) []string {
	was, now := tomlTables(old), tomlTables(planned)
	was[0] = setFields(was[0], now[0], plainRules, nil)
	for _, table := range now[1:] {
		header, location := tomlHeader(table[0]), tomlStringOf(table, "location")
		_, sets := settings(table, plainRules)
		at, first := -1, -1
		for i, have := range was[1:] {
			if tomlHeader(have[0]) != header {
				continue
			}
			if first < 0 {
				first = i + 1
			}
			if at < 0 && tomlStringOf(have, "location") == location {
				at = i + 1
			}
		}
		switch {
		case at >= 0:
			was[at] = setFields(was[at], table, plainRules, func(key, _ string) bool {
				_, planned := sets["insecure"]
				return key == "insecure" && !planned
			})
		case first >= 0:
			was = slices.Insert(was, first, append(slices.Clone(table), ""))
		default:
			if last := was[len(was)-1]; strings.TrimSpace(last[len(last)-1]) != "" {
				was[len(was)-1] = append(last, "")
			}
			was = append(was, table)
		}
	}
	return slices.Concat(was...)
}

// registriesHold checks merged defines each registry the plan names once,
// with every key the plan gives it and each of the plan's mirrors, and that
// no mirror of the plan's carries an insecure the plan did not set.
func registriesHold(merged, planned []byte) error {
	var m, p registriesDoc
	if _, err := toml.Decode(string(merged), &m); err != nil {
		return err
	}
	if _, err := toml.Decode(string(planned), &p); err != nil {
		return err
	}
	mirrors := func(r map[string]any) []map[string]any {
		list, _ := r["mirror"].([]map[string]any)
		return list
	}
	for _, want := range p.Registry {
		id, n := registryID(want), 0
		for _, have := range m.Registry {
			if registryID(have) != id {
				continue
			}
			n++
			for key, w := range want {
				if key != "mirror" && !reflect.DeepEqual(have[key], w) {
					return fmt.Errorf("the registry %q would read %s as %v, not the plan's %v", id, key, have[key], w)
				}
			}
			for _, wm := range mirrors(want) {
				if !slices.ContainsFunc(mirrors(have), func(hm map[string]any) bool {
					for key, w := range wm {
						if !reflect.DeepEqual(hm[key], w) {
							return false
						}
					}
					_, planned := wm["insecure"]
					_, kept := hm["insecure"]
					return planned || !kept
				}) {
					return fmt.Errorf("the registry %q would not hold the plan's mirror %v", id, wm["location"])
				}
			}
		}
		if n != 1 {
			return fmt.Errorf("the registry %q would be defined %d times", id, n)
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
// the key named items, a sequence of named entries, the plan's entry joins
// the host's entry of that name field by field, and the host's other entries
// stay where they were.
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
	return mergeBlocks(split(old), split(planned), false, func(was, now []string) []string {
		if items == "" || yamlTopKey(now[len(now)-len(dropLead(now))]) != items {
			return now
		}
		return mergeYAMLItems(was, now)
	})
}

// dropLead is a block's lines without the comment lines that lead it.
func dropLead(lines []string) []string {
	for len(lines) > 1 && strings.HasPrefix(strings.TrimSpace(lines[0]), "#") {
		lines = lines[1:]
	}
	return lines
}

// yamlItemRules reads the fields of one sequence item once its dash is
// blanked: a line nested deeper than a field continues it.
var yamlItemRules = lineRules{indent: true, key: func(line string) string {
	t := strings.TrimSpace(line)
	if t == "" || t[0] == '#' {
		return ""
	}
	if i := strings.Index(t, ":"); i > 0 && (i == len(t)-1 || t[i+1] == ' ') {
		return strings.Trim(t[:i], `"'`)
	}
	return ""
}}

// yamlItems cuts the lines of a sequence into what stands above its first
// item and its items, each with the lines between it and the next.
func yamlItems(lines []string) (head []string, items [][]string) {
	for i := 0; i < len(lines); {
		end := yamlItemEnd(lines, i)
		switch {
		case end > i:
			items = append(items, lines[i:end:end])
			i = end
			continue
		case len(items) == 0:
			head = append(head, lines[i])
		default:
			items[len(items)-1] = append(items[len(items)-1], lines[i])
		}
		i++
	}
	return head, items
}

// mergeYAMLItems merges the plan's named items into the host's sequence. An
// item of the plan's name takes the plan's fields and keeps its own, apart
// from caFile: the plan's clients verify through the system trust store, and
// a caFile left on bodega's entry would have helm read that file in its
// place. A second host item of one name is dropped, and an item the host
// lacks is added last, indented as the host's are.
func mergeYAMLItems(old, planned []string) []string {
	head, was := yamlItems(old)
	_, now := yamlItems(planned)
	if len(was) == 0 {
		// Nothing to keep under the key, and its own line may spell an empty
		// sequence in a form no item can follow.
		return append(slices.Clone(old[:len(old)-len(dropLead(old))]), dropLead(planned)...)
	}
	// column is where an item's fields start, and blank the item with its
	// dash blanked so the first field reads as the rest do.
	column := func(item []string) int {
		t := strings.TrimLeft(item[0], " ")
		return len(item[0]) - len(t) + 1 + len(t[1:]) - len(strings.TrimLeft(t[1:], " "))
	}
	blank := func(item []string) []string {
		dash := leadingSpaces(item[0])
		return append([]string{item[0][:dash] + " " + item[0][dash+1:]}, item[1:]...)
	}
	reindent := func(item []string, to int) []string {
		from := column(item)
		out := make([]string, len(item))
		for i, l := range blank(item) {
			out[i] = strings.Repeat(" ", to) + l[min(from, leadingSpaces(l)):]
		}
		return out
	}
	used := map[int]bool{}
	out := slices.Clone(head)
	for _, item := range was {
		name := yamlItemField(item, "name")
		at := slices.IndexFunc(now, func(p []string) bool { return yamlItemField(p, "name") == name })
		switch {
		case at < 0:
			out = append(out, item...)
			continue
		case used[at], strings.TrimSpace(item[0]) == "-":
			// A dash alone on its line opens a form this merge does not edit;
			// dropping the item leaves the decode check to refuse the file.
			continue
		}
		used[at] = true
		dash, col := leadingSpaces(item[0]), column(item)
		_, sets := settings(reindent(now[at], col), yamlItemRules)
		merged := setFields(blank(item), reindent(now[at], col), yamlItemRules, func(key, _ string) bool {
			_, planned := sets["caFile"]
			return key == "caFile" && !planned
		})
		// The first field takes the dash back, whichever field that now is.
		for i, l := range merged {
			if yamlItemRules.key(l) != "" {
				merged[i] = l[:dash] + "-" + l[dash+1:]
				break
			}
		}
		out = append(out, merged...)
	}
	for at, item := range now {
		if used[at] {
			continue
		}
		col := column(was[0])
		added := reindent(item, col)
		dash := leadingSpaces(was[0][0])
		added[0] = added[0][:dash] + "-" + added[0][dash+1:]
		out = append(out, added...)
	}
	return out
}

// yamlHolds checks merged gives each top-level key the value planned gives
// it, and under items an entry of each of planned's names carrying every
// field planned gives that entry.
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
				wm, _ := w.(map[string]any)
				n := 0
				for _, h := range haveItems {
					hm, _ := h.(map[string]any)
					if wm == nil || hm == nil || !reflect.DeepEqual(hm["name"], wm["name"]) {
						continue
					}
					n++
					for field, v := range wm {
						if !reflect.DeepEqual(hm[field], v) {
							return fmt.Errorf("%s would give the entry %v the %s %v, not the plan's %v", key, wm["name"], field, hm[field], v)
						}
					}
				}
				if n != 1 {
					return fmt.Errorf("%s would hold the plan's entry %v %d times", key, w, n)
				}
			}
		}
		return nil
	}
}

// mergeDeb822 merges an apt .sources file. A stanza is one or more sources,
// each a type at a URI for a suite, so the URIs alone do not name it: a
// deb-src stanza, or one for another suite, at bodega's URIs is a different
// source than the plan's and stays as it is. The plan's stanza joins every
// host stanza that already gives one of its sources (the same URIs, a type
// and a suite in common) field by field, and is added last when none does.
// Two host stanzas giving the same source can differ in what they filter by,
// such as Architectures, so both take the plan's fields and neither is
// dropped.
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
			func(entry []string) string { return strings.Join(stanzaWords(entry, "uris"), " ") })
	}
	// shares reports whether two stanzas name a value of field in common. A
	// stanza without the field is one apt does not read, and takes the
	// plan's.
	shares := func(a, b []string, field string) bool {
		x, y := stanzaWords(a, field), stanzaWords(b, field)
		return len(x) == 0 || len(y) == 0 || slices.ContainsFunc(x, func(w string) bool { return slices.Contains(y, w) })
	}
	now := split(planned)
	placed := make([]bool, len(now))
	var out []string
	for _, b := range split(old) {
		lines := b.lines
		for i, p := range now {
			if b.id != "" && p.id == b.id && shares(lines, p.lines, "types") && shares(lines, p.lines, "suites") {
				placed[i] = true
				lines = mergeStanza(lines, p.lines)
			}
		}
		out = append(out, lines...)
	}
	for i, p := range now {
		if placed[i] || p.id == "" {
			continue
		}
		if len(out) > 0 && strings.TrimSpace(out[len(out)-1]) != "" {
			out = append(out, "")
		}
		out = append(out, p.lines...)
	}
	return out
}

// stanzaWords is the words a deb822 stanza gives field, over the lines
// continuing it.
func stanzaWords(entry []string, field string) []string {
	_, byKey := settings(entry, fieldRules)
	lines := byKey[field]
	if len(lines) == 0 {
		return nil
	}
	_, first, _ := strings.Cut(lines[0], ":")
	return strings.Fields(first + " " + strings.Join(lines[1:], " "))
}

// stanzaUnion is the plan's line for field carrying the host's words ahead
// of any the plan adds, so a stanza that gives more types or suites than the
// plan's keeps them.
func stanzaUnion(old, planned []string, field string) []string {
	_, byKey := settings(planned, fieldRules)
	if len(byKey[field]) == 0 {
		return nil
	}
	words := stanzaWords(old, field)
	for _, w := range stanzaWords(planned, field) {
		if !slices.Contains(words, w) {
			words = append(words, w)
		}
	}
	name, _, _ := strings.Cut(byKey[field][0], ":")
	return []string{name + ": " + strings.Join(words, " ")}
}

// mergeStanza sets the plan's fields in the host's stanza and keeps its
// others, such as Architectures. Types and Suites are what the stanza was
// matched by, and keep the values the host gives beyond the plan's: narrowing
// them would delete a source the plan never named. Two fields cannot stand beside the plan's
// and are removed on their own: a Trusted: yes beside the plan's Signed-By
// would turn off the verification that key is for, and an Enabled: no would
// leave the source the plan configures unread.
func mergeStanza(old, planned []string) []string {
	keys, sets := settings(planned, fieldRules)
	says := func(line, word string) bool {
		_, v, _ := strings.Cut(line, ":")
		return strings.EqualFold(strings.TrimSpace(v), word)
	}
	var plan []string
	for _, key := range keys {
		if key == "types" || key == "suites" {
			plan = append(plan, stanzaUnion(old, planned, key)...)
			continue
		}
		plan = append(plan, sets[key]...)
	}
	return setFields(old, plan, fieldRules, func(key, line string) bool {
		_, signed := sets["signed-by"]
		return key == "trusted" && signed && says(line, "yes") || key == "enabled" && says(line, "no")
	})
}

var uclObject = regexp.MustCompile(`^\s*("[^"]*"|[A-Za-z0-9_.-]+)\s*[:=]?\s*\{`)

// uclField is one field of a UCL object: its key and where the key through
// the end of its value stands in the object's text.
type uclField struct {
	key        string
	start, end int
}

// uclFields lists the fields of the first object text opens, with the index
// of that object's closing brace, and false for text this reader does not
// follow to that brace. Strings, comments and nested objects and arrays are
// stepped over whole, so a brace or a separator inside one ends nothing.
func uclFields(text string) (fields []uclField, closing int, ok bool) {
	// skip steps over the string, comment or bracketed value opening at i and
	// returns the index after it, or i itself when none opens there.
	var skip func(i int) int
	skip = func(i int) int {
		switch c := text[i]; {
		case c == '"' || c == '\'':
			for j := i + 1; j < len(text); j++ {
				switch text[j] {
				case '\\':
					j++
				case c:
					return j + 1
				}
			}
			return len(text)
		case c == '#':
			if end := strings.IndexByte(text[i:], '\n'); end >= 0 {
				return i + end
			}
			return len(text)
		case strings.HasPrefix(text[i:], "/*"):
			if end := strings.Index(text[i+2:], "*/"); end >= 0 {
				return i + end + 4
			}
			return len(text)
		case c == '{' || c == '[':
			for j := i + 1; j < len(text); {
				if text[j] == '}' || text[j] == ']' {
					return j + 1
				}
				if next := skip(j); next > j {
					j = next
				} else {
					j++
				}
			}
			return len(text)
		}
		return i
	}
	i := 0
	for i < len(text) && text[i] != '{' {
		if next := skip(i); next > i {
			i = next
		} else {
			i++
		}
	}
	for i++; i < len(text); {
		switch c := text[i]; {
		case c == '}':
			return fields, i, true
		case strings.ContainsRune(" \t\r\n,;", rune(c)):
			i++
			continue
		case c == '#' || strings.HasPrefix(text[i:], "/*"):
			i = skip(i)
			continue
		}
		f := uclField{start: i}
		if next := skip(i); next > i {
			f.key, i = strings.Trim(text[f.start:next], `"'`), next
		} else {
			for i < len(text) && !strings.ContainsRune(" \t\r\n:={[,;}", rune(text[i])) {
				i++
			}
			f.key = text[f.start:i]
		}
		if f.key == "" {
			return nil, 0, false
		}
		for i < len(text) && (text[i] == ' ' || text[i] == '\t') {
			i++
		}
		if i < len(text) && (text[i] == ':' || text[i] == '=') {
			for i++; i < len(text) && (text[i] == ' ' || text[i] == '\t'); i++ {
			}
		}
		if i >= len(text) {
			return nil, 0, false
		}
		if next := skip(i); next > i && text[i] != '#' {
			i = next
		} else {
			for i < len(text) && !strings.ContainsRune("\n,;}#", rune(text[i])) {
				// ${ABI} in a bare value is a variable, not the object's end.
				if end := strings.IndexByte(text[i:], '}'); strings.HasPrefix(text[i:], "${") && end > 0 {
					i += end
				}
				i++
			}
		}
		f.end = len(strings.TrimRight(text[:i], " \t\r"))
		fields = append(fields, f)
	}
	return nil, 0, false
}

func uclEntries(lines []string) []block {
	return splitEntries(lines,
		func(i int) bool { return uclObject.MatchString(lines[i]) },
		func(i int) int {
			if _, closing, ok := uclFields(strings.Join(lines[i:], "\n")); ok {
				return i + strings.Count(strings.Join(lines[i:], "\n")[:closing], "\n") + 1
			}
			return len(lines)
		},
		func(entry []string) string { return strings.Trim(uclObject.FindStringSubmatch(entry[0])[1], `"`) })
}

// mergeUCL merges a pkg repository file: each object the plan renders joins
// the host's object of that tag field by field, and the host's other objects
// stay. The comment block a plan opens the file with is replaced when the
// host's file opens with the same line, since it describes the objects under
// it.
func mergeUCL(old, planned []string) []string {
	was, now := uclEntries(old), uclEntries(planned)
	if len(was) > 0 && len(now) > 0 && was[0].id == "" && now[0].id == "" && was[0].lines[0] == now[0].lines[0] {
		was[0].lines = now[0].lines
	}
	return mergeBlocks(was, now, true, mergeUCLObject)
}

// mergeUCLObject sets the plan's fields in the host's object and keeps its
// others, such as priority, editing the object's text in place so its layout
// and comments stay. A field the object lacks goes before its closing brace:
// on a line of its own where the object's fields have theirs, and after a
// comma where the object is written on one line. An object this reader does
// not follow is returned as it is, for uclHolds to refuse.
func mergeUCLObject(old, planned []string) []string {
	text, plan := strings.Join(old, "\n"), strings.Join(planned, "\n")
	have, closing, ok := uclFields(text)
	want, _, planOK := uclFields(plan)
	if !ok || !planOK {
		return old
	}
	var missing []string
	edits := map[int]string{}
	for _, w := range want {
		at := slices.IndexFunc(have, func(f uclField) bool { return f.key == w.key })
		if at < 0 {
			missing = append(missing, plan[w.start:w.end])
			continue
		}
		edits[at] = plan[w.start:w.end]
	}
	if len(missing) > 0 {
		last := strings.Index(text, "{") + 1
		if len(have) > 0 {
			last = have[len(have)-1].end
		}
		tail := text[last:closing]
		switch nl := strings.LastIndex(tail, "\n"); {
		case nl >= 0 && len(have) > 0:
			line := text[:have[0].start]
			indent := line[strings.LastIndex(line, "\n")+1:]
			if strings.TrimSpace(indent) != "" {
				indent = "  "
			}
			sep := ""
			if rest := strings.TrimLeft(tail, " \t"); !strings.HasPrefix(rest, ",") && !strings.HasPrefix(rest, ";") {
				sep = ","
			}
			at := last + nl + 1
			text = text[:last] + sep + text[last:at] + indent + strings.Join(missing, ",\n"+indent) + "\n" + text[at:]
		case len(have) > 0:
			text = text[:last] + ", " + strings.Join(missing, ", ") + text[last:]
		default:
			text = text[:last] + " " + strings.Join(missing, ", ") + " " + strings.TrimLeft(text[last:], " \t")
		}
	}
	for at := len(have) - 1; at >= 0; at-- {
		if edit, ok := edits[at]; ok {
			text = text[:have[at].start] + edit + text[have[at].end:]
		}
	}
	return strings.Split(text, "\n")
}

// uclHolds checks merged holds an object of each tag the plan renders, once,
// giving every field the plan gives it the plan's value.
func uclHolds(merged, planned []byte) error {
	objects := func(body []byte) map[string][]string {
		out := map[string][]string{}
		for _, b := range uclEntries(splitBody(body)) {
			if b.id != "" {
				out[b.id] = append(out[b.id], strings.Join(b.lines, "\n"))
			}
		}
		return out
	}
	have := objects(merged)
	for tag, texts := range have {
		for _, text := range texts {
			if _, _, ok := uclFields(text); !ok {
				return fmt.Errorf("the object %s is written in a form that cannot be followed to its closing brace", tag)
			}
		}
	}
	for tag, texts := range objects(planned) {
		if len(have[tag]) != len(texts) {
			return fmt.Errorf("the object %s would be defined %d times", tag, len(have[tag]))
		}
		for i, plan := range texts {
			want, _, _ := uclFields(plan)
			got, _, _ := uclFields(have[tag][i])
			for _, w := range want {
				if !slices.ContainsFunc(got, func(f uclField) bool {
					return f.key == w.key && have[tag][i][f.start:f.end] == plan[w.start:w.end]
				}) {
					return fmt.Errorf("the object %s would not read %s as the plan sets it", tag, plan[w.start:w.end])
				}
			}
		}
	}
	return nil
}

// uclKeeps is keeps for a pkg repository file: an object the plan does not
// render reads as it did, and one it renders keeps every field the plan does
// not give it.
func uclKeeps(old, merged, planned []byte) error {
	objects := func(body []byte) map[string][]string {
		out := map[string][]string{}
		for _, b := range uclEntries(splitBody(body)) {
			if b.id != "" {
				out[b.id] = append(out[b.id], strings.Join(dropLead(b.lines), "\n"))
			}
		}
		return out
	}
	have, plan := objects(merged), objects(planned)
	for tag, texts := range objects(old) {
		if len(plan[tag]) == 0 {
			if !slices.Equal(have[tag], texts) {
				return fmt.Errorf("the merge would not keep the object %s as the host wrote it", tag)
			}
			continue
		}
		if len(have[tag]) == 0 {
			return fmt.Errorf("the merge would drop the object %s", tag)
		}
		was, _, _ := uclFields(texts[0])
		now, _, _ := uclFields(have[tag][0])
		want, _, _ := uclFields(plan[tag][0])
		for _, f := range was {
			if slices.ContainsFunc(want, func(w uclField) bool { return w.key == f.key }) {
				continue
			}
			if !slices.ContainsFunc(now, func(n uclField) bool {
				return n.key == f.key && have[tag][0][n.start:n.end] == texts[0][f.start:f.end]
			}) {
				return fmt.Errorf("the merge would not keep %s of the object %s", f.key, tag)
			}
		}
	}
	return nil
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

// PipOptions reads a pip configuration file into "section.option", the
// option lowercased with _ read as -, each to the value pip takes for it. It
// walks the file with the scan the merge edits one with, so a line the merge
// treats as the tail of another setting is never read here as a setting of
// its own: a deeper-indented line continues the option above it, a colon
// delimits as an equals sign does, and the last assignment of an option wins.
func PipOptions(data []byte) map[string]string {
	out := map[string]string{}
	scan := lineScan{rules: pipRules, keyIndent: -1}
	section, current := "", ""
	for _, l := range splitBody(data) {
		t := strings.TrimSpace(l)
		if scan.continues(l) {
			if current != "" && !strings.ContainsRune("#;", rune(t[0])) {
				out[current] = strings.TrimSpace(out[current] + "\n" + t)
			}
			continue
		}
		if strings.HasPrefix(t, "[") {
			section, current, scan.keyIndent = "", "", -1
			if end := strings.LastIndex(t, "]"); end > 0 {
				section = t[1:end]
			}
			continue
		}
		key := pipRules.key(l)
		if key == "" {
			continue
		}
		scan.keyIndent = indentOf(l)
		current = section + "." + strings.TrimPrefix(key, "--")
		out[current] = strings.TrimSpace(t[strings.IndexAny(t, "=:")+1:])
	}
	return out
}
