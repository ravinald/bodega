package host

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

const (
	aptSourcesList = "/etc/apt/sources.list"
	aptSourcesDir  = "/etc/apt/sources.list.d"
)

// aptSourcePaths lists the sources files apt reads, unrooted, in the order
// it reads them: sources.list, then sources.list.d's .list and .sources files.
func aptSourcePaths(root string) []string {
	paths := []string{aptSourcesList}
	entries, err := os.ReadDir(filepath.Join(root, aptSourcesDir))
	if err != nil {
		return paths
	}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || (!strings.HasSuffix(n, ".list") && !strings.HasSuffix(n, ".sources")) {
			continue
		}
		paths = append(paths, filepath.Join(aptSourcesDir, n))
	}
	return paths
}

// AptSource is one enabled source apt reads: a deb822 stanza or a one-line
// entry.
type AptSource struct {
	// File is the sources file, unrooted.
	File string
	// Line is the stanza's first field line, or the entry's own line,
	// counted from 1.
	Line   int
	Deb822 bool
	URIs   []string
	// Public is the public archive host the source names, directly or
	// through the mirror list a mirror+file URI points at, and empty for
	// any other source.
	Public string
	// SetsEnabled says the stanza carries an Enabled field of its own.
	SetsEnabled bool
}

// AptSources returns every enabled source under root by the rules the
// apt-sources check reads them with. A mirror list it cannot read is an
// error: the source behind it can be neither kept nor disabled on a guess.
func AptSources(root string) ([]AptSource, error) {
	var out []AptSource
	for _, p := range aptSourcePaths(root) {
		data, err := os.ReadFile(filepath.Join(root, p))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		deb822 := strings.HasSuffix(p, ".sources")
		entries := oneLineEntries(string(data))
		if deb822 {
			entries = deb822Stanzas(string(data))
		}
		for _, e := range entries {
			if !e.enabled {
				continue
			}
			s := AptSource{File: p, Line: e.line, Deb822: deb822, URIs: e.uris, SetsEnabled: e.setsEnabled}
			for _, uri := range e.uris {
				pub, err := aptPublicHost(root, uri)
				if err != nil {
					return nil, fmt.Errorf("%s line %d: %w", p, e.line, err)
				}
				if pub != "" {
					s.Public = pub
					break
				}
			}
			out = append(out, s)
		}
	}
	return out, nil
}

func aptPublicHost(root, uri string) (string, error) {
	mirror, ok := aptMirrorFile(uri)
	if !ok {
		return publicHost(uri, publicUpstreams["apt"]), nil
	}
	mirrors, err := aptMirrorURIs(filepath.Join(root, mirror))
	if err != nil {
		return "", fmt.Errorf("could not read apt mirror list %s, named by %s: %w", mirror, uri, err)
	}
	for _, m := range mirrors {
		if h := publicHost(m, publicUpstreams["apt"]); h != "" {
			return h, nil
		}
	}
	return "", nil
}

const aptCommentPrefix = "# "

// AptEdit takes sources in one file out of apt's path, and puts them back.
// Each unit carries the lines it replaced and the lines it wrote, at the
// position it wrote them, so Revert can prove a file still holds doctor's
// edit before changing it: a line number alone matches whatever an operator
// has since moved under it.
type AptEdit struct {
	Path   string    `json:"path"`
	Deb822 bool      `json:"deb822"`
	Units  []AptUnit `json:"units"`
}

// AptUnit is one source disabled: a deb822 stanza, from its first field line
// to the blank line that ends it, or a one-line entry. Line counts from 1 in
// the file as it was before this edit; Before and After keep their line
// endings.
type AptUnit struct {
	Line   int      `json:"line"`
	Before []string `json:"before"`
	After  []string `json:"after"`
}

// DisableAptSources plans the edit that disables the sources at lines, as
// AptSource.Line reports them, in path under root. A deb822 stanza gets an
// Enabled: no line at its head, or each Enabled field it already carries set
// to no; a one-line entry is commented out.
func DisableAptSources(root, path string, deb822 bool, lines []int) (AptEdit, error) {
	e := AptEdit{Path: path, Deb822: deb822}
	file, text, err := e.read(root)
	if err != nil {
		return e, err
	}
	for _, l := range slices.Sorted(slices.Values(lines)) {
		i := l - 1
		if i >= len(text) || strings.TrimSpace(text[i]) == "" {
			return e, fmt.Errorf("%s has no source at line %d; re-run doctor to plan against the file as it is now", file, l)
		}
		end := i + 1
		for deb822 && end < len(text) && strings.TrimSpace(text[end]) != "" {
			end++
		}
		before := slices.Clone(text[i:end])
		e.Units = append(e.Units, AptUnit{Line: l, Before: before, After: aptDisabled(deb822, before)})
	}
	return e, nil
}

// aptDisabled is what a unit reads once disabled.
func aptDisabled(deb822 bool, before []string) []string {
	if !deb822 {
		return []string{aptCommentPrefix + before[0]}
	}
	after := slices.Clone(before)
	set := false
	for i, line := range after {
		if line == "" || line[0] == '#' || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "enabled") {
			continue
		}
		after[i] = name + ": no" + value[len(strings.TrimRight(value, "\r\n")):]
		set = true
	}
	if !set {
		after = append([]string{"Enabled: no\n"}, after...)
	}
	return after
}

func (e AptEdit) kind() string {
	if e.Deb822 {
		return "deb822"
	}
	return "one-line"
}

// Lines are the lines, before the edit, of the sources it disables.
func (e AptEdit) Lines() []int {
	out := make([]int, len(e.Units))
	for i, u := range e.Units {
		out[i] = u.Line
	}
	return out
}

// String is the edit's row in doctor's output.
func (e AptEdit) String() string {
	nums := make([]string, len(e.Units))
	for i, l := range e.Lines() {
		nums[i] = strconv.Itoa(l)
	}
	return e.kind() + " " + e.Path + " " + strings.Join(nums, ",")
}

// Name is the edit as the record --restore-apt-sources reads stores it.
func (e AptEdit) Name() string {
	b, err := json.Marshal(e)
	if err != nil {
		panic(err) // strings, ints and bools always marshal
	}
	return string(b)
}

// ParseAptEdit reads a name Name wrote. It accepts only a path apt reads
// sources from, and only units whose After is what disabling their Before
// writes, so a record edited by hand can point the restore at no other file
// and no other change.
func ParseAptEdit(s string) (AptEdit, error) {
	var e AptEdit
	d := json.NewDecoder(strings.NewReader(s))
	d.DisallowUnknownFields()
	if err := d.Decode(&e); err != nil {
		return AptEdit{}, fmt.Errorf("%q is not an apt source edit doctor recorded: %v", s, err)
	}
	ext := ".list"
	if e.Deb822 {
		ext = ".sources"
	}
	inDir := filepath.Dir(e.Path) == aptSourcesDir && strings.HasSuffix(e.Path, ext)
	if filepath.Clean(e.Path) != e.Path || !(inDir || (!e.Deb822 && e.Path == aptSourcesList)) {
		return AptEdit{}, fmt.Errorf("%q names %s, which is not a %s apt sources file", s, e.Path, e.kind())
	}
	if len(e.Units) == 0 {
		return AptEdit{}, fmt.Errorf("%q records no source", s)
	}
	next := 1
	for _, u := range e.Units {
		if u.Line < next || len(u.Before) == 0 || (!e.Deb822 && len(u.Before) != 1) ||
			slices.ContainsFunc(u.Before, func(l string) bool { return strings.Contains(strings.TrimSuffix(l, "\n"), "\n") }) ||
			!slices.Equal(u.After, aptDisabled(e.Deb822, u.Before)) {
			return AptEdit{}, fmt.Errorf("%q: unit at line %d is not one doctor writes (units ascend from line 1, never overlap, and each After disables its Before)", s, u.Line)
		}
		next = u.Line + len(u.Before)
	}
	return e, nil
}

// Apply makes the edit to the file under root, provided every source still
// reads as it did when the edit was planned; otherwise nothing changes.
func (e AptEdit) Apply(root string) error {
	path, lines, err := e.read(root)
	if err != nil {
		return err
	}
	for _, u := range e.Units {
		if !aptLinesAt(lines, u.Line-1, u.Before) {
			return fmt.Errorf("%s changed at line %d since doctor planned the edit; nothing in it was changed. Re-run doctor to plan against the file as it is now", path, u.Line)
		}
	}
	for _, u := range slices.Backward(e.Units) {
		lines = slices.Replace(lines, u.Line-1, u.Line-1+len(u.Before), u.After...)
	}
	return e.write(path, lines)
}

// Revert undoes Apply, byte for byte, provided every line the edit wrote
// still reads as it wrote it, where it wrote it. Anything else is a file
// doctor can no longer prove it owns the edit in, so nothing is changed.
func (e AptEdit) Revert(root string) error {
	path, lines, err := e.read(root)
	if err != nil {
		return err
	}
	at := make([]int, len(e.Units))
	shift := 0
	for i, u := range e.Units {
		at[i] = u.Line - 1 + shift
		if !aptLinesAt(lines, at[i], u.After) {
			return fmt.Errorf("line %d of %s no longer reads as doctor left it (%q), so the file changed since and nothing in it was restored. "+
				"Restore the file by hand, then remove its entry from the record", at[i]+1, path, u.After[0])
		}
		shift += len(u.After) - len(u.Before)
	}
	for i, u := range slices.Backward(e.Units) {
		lines = slices.Replace(lines, at[i], at[i]+len(u.After), u.Before...)
	}
	return e.write(path, lines)
}

func aptLinesAt(lines []string, i int, want []string) bool {
	return i >= 0 && i+len(want) <= len(lines) && slices.Equal(lines[i:i+len(want)], want)
}

func (e AptEdit) read(root string) (string, []string, error) {
	path := filepath.Join(root, e.Path)
	data, err := os.ReadFile(path)
	if err != nil {
		return path, nil, fmt.Errorf("read %s: %w", path, err)
	}
	return path, strings.SplitAfter(string(data), "\n"), nil
}

func (e AptEdit) write(path string, lines []string) error {
	if err := os.WriteFile(path, []byte(strings.Join(lines, "")), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
