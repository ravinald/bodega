package clientconf

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"unicode"

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
	// that key's value, as Python's ConfigParser reads one. A line at
	// the key's own indentation is the next key.
	indent bool
	// runsOn lexes one physical line the way the format's own reader does
	// and reports whether its value runs on into the next line. open is the
	// state the line above left: a line reached with it set is the tail of
	// that line's value, never a setting or a comment of its own. Nil is a
	// format with no such continuation.
	runsOn func(line string, open lineOpen) lineOpen
}

// lineOpen is what a line left open for the one under it: a value running on,
// and the quote it was inside, 0 for none.
type lineOpen struct {
	on    bool
	quote byte
}

// oddSlashRunsOn is continuation as systemd's environment.d reads it: a line
// ending in an odd number of backslashes joins the next, and a comment is no
// exception, since the reader joins lines before it looks for one.
func oddSlashRunsOn(line string, _ lineOpen) lineOpen {
	line = strings.TrimSuffix(line, "\r")
	n := len(line) - len(strings.TrimRight(line, `\`))
	return lineOpen{on: n%2 == 1}
}

// shRunsOn is continuation as sh reads a profile script: a backslash before
// the newline joins the next line outside single quotes, an open quote
// carries the newline into its string, and a comment, which a # opening a
// word starts, runs to the end of its line and joins nothing.
func shRunsOn(line string, open lineOpen) lineOpen {
	line = strings.TrimSuffix(line, "\r")
	quote, word := open.quote, open.on && open.quote == 0
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
		case c == '\\':
			if i++; i >= len(line) {
				return lineOpen{on: true, quote: quote}
			}
		case quote == '"':
			if c == '"' {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '#' && !word:
			return lineOpen{}
		}
		word = quote != 0 || c != ' ' && c != '\t' && c != ';' && c != '&' && c != '|' && c != '(' && c != ')'
	}
	return lineOpen{on: quote != 0, quote: quote}
}

// gitRunsOn is continuation as git's config reader takes it (parse_value in
// config.c, git 2.47): only a value continues, on a backslash before the
// newline, inside quotes or out. A comment, which a # or ; outside quotes
// opens anywhere on a line, runs to the end of that line and continues
// nothing, and neither does a section header or a name with no value.
func gitRunsOn(line string, open lineOpen) lineOpen {
	line = strings.TrimSuffix(line, "\r")
	rest, quoted := line, open.quote != 0
	if !open.on {
		rest = strings.TrimLeft(rest, " \t")
		for strings.HasPrefix(rest, "[") {
			end := gitHeaderEnd(rest)
			if end < 0 {
				return lineOpen{}
			}
			rest = strings.TrimLeft(rest[end:], " \t")
		}
		i := 0
		for i < len(rest) && (rest[i] == '-' || rest[i] >= '0' && rest[i] <= '9' || rest[i] >= 'a' && rest[i] <= 'z' || rest[i] >= 'A' && rest[i] <= 'Z') {
			i++
		}
		rest = strings.TrimLeft(rest[i:], " \t")
		if i == 0 || !strings.HasPrefix(rest, "=") {
			return lineOpen{}
		}
		rest = rest[1:]
	}
	for i := 0; i < len(rest); i++ {
		switch c := rest[i]; {
		case c == '\\':
			if i++; i >= len(rest) {
				q := byte(0)
				if quoted {
					q = '"'
				}
				return lineOpen{on: true, quote: q}
			}
		case c == '"':
			quoted = !quoted
		case !quoted && (c == '#' || c == ';'):
			return lineOpen{}
		}
	}
	return lineOpen{}
}

// gitHeaderEnd is the offset past the ] closing the section header s opens
// with, -1 when the line does not close it. A ] inside the quoted subsection
// closes nothing.
func gitHeaderEnd(s string) int {
	quoted := false
	for i := 1; i < len(s); i++ {
		switch c := s[i]; {
		case quoted && c == '\\':
			i++
		case c == '"':
			quoted = !quoted
		case !quoted && c == ']':
			return i + 1
		}
	}
	return -1
}

var (
	plainRules = lineRules{key: settingKey}
	// An npmrc names an option the way npm's own reader decodes the line, so
	// a quoted name is the option it spells and a name is matched exactly.
	npmRules = lineRules{key: npmKey}
	// ConfigParser takes a colon for the equals sign, and pip names the
	// option it reads through pipName, so the merge replaces --cert when the
	// plan sets cert.
	pipRules = lineRules{indent: true, key: func(line string) string {
		if raw := pipRawKey(line); raw != "" {
			return pipName(raw)
		}
		return ""
	}}
	gitRules   = lineRules{key: settingKey, runsOn: gitRunsOn}
	shRules    = lineRules{key: settingKey, runsOn: shRunsOn}
	envdRules  = lineRules{key: settingKey, runsOn: oddSlashRunsOn}
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

// fileKind is how an existing file of one client takes a plan's settings and
// keeps its own. The zero kind is a file written whole: one NewChange merged
// already, or a document that holds nothing but the one value the plan
// renders (a key).
type fileKind struct {
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
		// environment gives it; the two files NodeMirror writes each continue
		// a line as their own reader does, sh and systemd.
		switch rec.Path {
		case NodeMirrorSystemPath:
			return fileKind{rules: &shRules}
		case NodeMirrorUserPath:
			return fileKind{rules: &envdRules}
		}
		return fileKind{rules: &npmRules, unread: strayHeader(npmRules)}
	case manifest.TypePypi:
		return fileKind{rules: &pipRules, unread: strayHeader(pipRules)}
	case manifest.TypeGit:
		return fileKind{rules: &gitRules, unread: gitUnread, holds: gitHolds, keeps: gitKeeps}
	case manifest.TypeOCI:
		if name == "hosts.toml" {
			return fileKind{rules: &plainRules, holds: tomlHolds, keeps: tomlKeeps}
		}
	case manifest.TypeHelm:
		return fileKind{blocks: func(old, planned []string) []string { return mergeYAML(old, planned, "repositories") }, holds: yamlHolds("repositories"), keeps: yamlKeeps("repositories")}
	case manifest.TypeApt:
		if strings.HasSuffix(name, ".sources") {
			return fileKind{blocks: mergeDeb822}
		}
	}
	return fileKind{}
}

// whole reports a file no editor here reads: bodega renders it and writes it
// whole.
func (k fileKind) whole() bool { return k.rules == nil && k.blocks == nil }

// keepWhole is the merge for such a file when the host already holds one
// that differs from planned. With no editor for the format, the only lines
// known to be bodega's are planned's own, so the host's file is kept as it
// stands when it holds planned intact, with whatever its owner wrote around
// it, and is replaced when it is blank. Any other difference is an error for
// the caller to refuse: it may be an older rendering or an edit, and writing
// planned over it would delete lines nothing here can show bodega wrote.
func keepWhole(old, planned []byte) ([]byte, error) {
	switch {
	case len(bytes.TrimSpace(old)) == 0:
		return planned, nil
	case holdsLines(old, bytes.TrimRight(planned, "\n")):
		return old, nil
	}
	return nil, errors.New("it differs from the file bodega renders in lines this command cannot show are bodega's own")
}

// holdsLines reports whether block sits in data as a run of whole lines.
func holdsLines(data, block []byte) bool {
	for from := 0; ; {
		at := bytes.Index(data[from:], block)
		if at < 0 {
			return false
		}
		at += from
		end := at + len(block)
		if (at == 0 || data[at-1] == '\n') && (end == len(data) || data[end] == '\n') {
			return true
		}
		from = at + 1
	}
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

// pipHeader is the section a stripped pip configuration line opens, as
// configparser's SECTCRE matches one: a [ first, then at least one character,
// then the last ] on the line, whatever follows it.
func pipHeader(t string) (section string, ok bool) {
	if !strings.HasPrefix(t, "[") {
		return "", false
	}
	end := strings.LastIndex(t, "]")
	if end < 2 {
		return "", false
	}
	return t[1:end], true
}

// pipOption splits a stripped pip configuration line at its first = or :, as
// configparser's OPTCRE does with those two delimiters and no valueless
// options. raw is the name as ConfigParser stores it, lowercased and
// otherwise as written, which is empty for a line opening with a delimiter.
func pipOption(t string) (raw, value string, ok bool) {
	i := strings.IndexAny(t, "=:")
	if i < 0 {
		return "", "", false
	}
	return strings.ToLower(strings.TrimSpace(t[:i])), strings.TrimSpace(t[i+1:]), true
}

func pipComment(t string) bool { return t != "" && (t[0] == '#' || t[0] == ';') }

// pipRawKey is the option name a pip configuration line assigns as
// ConfigParser stores it, or "" for a line assigning none.
func pipRawKey(line string) string {
	t := strings.TrimSpace(line)
	if _, header := pipHeader(t); header || t == "" || pipComment(t) {
		return ""
	}
	raw, _, _ := pipOption(t)
	return raw
}

// pipName is pip's _normalize_name (pip 26.2.1, configuration.py): _ reads as
// - and a leading -- is dropped, so "--cert" and "cert" are one option.
func pipName(raw string) string {
	return strings.TrimPrefix(strings.ReplaceAll(strings.ToLower(raw), "_", "-"), "--")
}

// pipItem is one option of a pip configuration file, under the name
// ConfigParser stores it by.
type pipItem struct{ raw, value string }

// pipFile is a pip configuration file as RawConfigParser reads one.
type pipFile struct {
	// sections holds each section's options in the order the file first
	// assigns them, DEFAULT among them, and order the sections other than
	// DEFAULT in the order the file declares them.
	sections map[string][]pipItem
	order    []string
}

// readPipFile reads a pip configuration file the way pip does, and returns
// the error pip refuses the whole file with. It ports RawConfigParser._read
// (CPython 3.12, Lib/configparser.py) as pip constructs the parser: strict,
// delimiters = and :, full-line comments # and ;, no inline comments, no
// valueless options, and empty lines kept inside values.
//
// Every line is one of five things, decided in this order. A blank line or a
// comment changes nothing, wherever it is indented. A line indented deeper
// than the option above it continues that option's value; a section header
// leaves no option to continue, so a line indented under one is read as any
// other. A section header opens its section, and a second header of one name
// is an error, DEFAULT excepted. Anything else above the first header is an
// error. What remains must be an option: a non-empty name, a delimiter, a
// value, with a name assigned twice in one section an error. A line that is
// none of these is an error, never an unrelated setting.
func readPipFile(data []byte) (pipFile, error) {
	f := pipFile{sections: map[string][]pipItem{}}
	declared := map[string]bool{}
	values := map[string][][]string{}
	section, inSection := "", false
	current, indent := -1, 0
	var first error
	fail := func(n int, format string, args ...any) {
		if first == nil {
			first = fmt.Errorf("line %d: %s", n, fmt.Sprintf(format, args...))
		}
	}
	// Python opens the file with universal newlines.
	text := strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(string(data))
	for n, l := range strings.Split(text, "\n") {
		n++
		t := strings.TrimSpace(l)
		if pipComment(t) {
			continue
		}
		if t == "" {
			if current >= 0 {
				values[section][current] = append(values[section][current], "")
			}
			continue
		}
		at := len(l) - len(strings.TrimLeftFunc(l, unicode.IsSpace))
		if current >= 0 && at > indent {
			values[section][current] = append(values[section][current], t)
			continue
		}
		indent = at
		if name, ok := pipHeader(t); ok {
			if name != "DEFAULT" && declared[name] {
				return f, fmt.Errorf("line %d: section %q already exists", n, name)
			}
			if !declared[name] && name != "DEFAULT" {
				f.order = append(f.order, name)
			}
			declared[name] = true
			section, inSection, current = name, true, -1
			continue
		}
		if !inSection {
			return f, fmt.Errorf("line %d: %q sits above every section header", n, t)
		}
		raw, value, ok := pipOption(t)
		if !ok {
			fail(n, "%q is neither a section header nor an option with a = or : after its name", t)
			continue
		}
		if raw == "" {
			fail(n, "%q assigns a value to no option name", t)
		}
		items := f.sections[section]
		if slices.ContainsFunc(items, func(it pipItem) bool { return it.raw == raw }) {
			return f, fmt.Errorf("line %d: option %q in section %q already exists", n, raw, section)
		}
		f.sections[section] = append(items, pipItem{raw: raw})
		values[section] = append(values[section], []string{value})
		// configparser continues an option only under a non-empty name.
		if current = len(items); raw == "" {
			current = -1
		}
	}
	for name, items := range f.sections {
		for i := range items {
			items[i].value = strings.TrimRightFunc(strings.Join(values[name][i], "\n"), unicode.IsSpace)
		}
	}
	return f, first
}

// PipLoadError is why pip cannot load a configuration file, or nil when it
// can: readPipFile's verdict. pip aborts on such a file, so no option in it
// is policy, whichever line the error is on.
func PipLoadError(data []byte) error {
	_, err := readPipFile(data)
	return err
}

// PipOptions reads a pip configuration file into "section.option", the
// option named as pipName names it, each to the value pip takes for it. The
// lines are readPipFile's, so what PipLoadError judges and what is read here
// are one reading of the file, and a file pip refuses to load gives no option
// at all.
//
// The rest ports pip's _load_file over RawConfigParser: [DEFAULT] is no
// section of its own but is inherited by every section the file declares,
// a section's own option replacing the default of the same raw name in the
// default's place; pip then walks each section's items in that order,
// normalizing names, and the last item of one normalized name wins.
func PipOptions(data []byte) map[string]string {
	out := map[string]string{}
	f, err := readPipFile(data)
	if err != nil {
		return out
	}
	for _, name := range f.order {
		merged := slices.Clone(f.sections["DEFAULT"])
		for _, it := range f.sections[name] {
			if k := slices.IndexFunc(merged, func(d pipItem) bool { return d.raw == it.raw }); k >= 0 {
				merged[k].value = it.value
			} else {
				merged = append(merged, it)
			}
		}
		for _, it := range merged {
			out[name+"."+pipName(it.raw)] = it.value
		}
	}
	return out
}
