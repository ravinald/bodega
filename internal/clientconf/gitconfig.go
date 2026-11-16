package clientconf

import (
	"fmt"
	"slices"
	"strings"

	"github.com/ravinald/bodega/internal/plannedfs"
)

// GitEntry is one variable of a git configuration file.
type GitEntry struct {
	// Section and Name are lowercased, as git matches them. Subsection keeps
	// its case when the header quotes it and is lowercased in the dotted
	// [section.subsection] form, which Dotted reports.
	Section, Subsection, Name string
	Dotted                    bool
	// Value is the decoded value, and HasValue false for a name with no =,
	// which git reads as true where a boolean is asked for and refuses where
	// a string is.
	Value    string
	HasValue bool
	// Line is the line the name stands on, EndLine the last line its value
	// runs to, and HeaderLine the line of the section header it sits under,
	// 0 above the first header. All count from 1.
	Line, EndLine, HeaderLine int
}

// GitConfig is a git configuration file read whole, by git's own grammar: a
// port of git_parse_source, get_base_var, get_extended_base_var, get_value
// and parse_value from config.c at Git 2.54.0. The install's preflight, the
// check on what the editor wrote and the trust probe all read a git file
// through it, so a file git refuses to load is refused by each of them, for
// a line in any section, and none of them reads a value git would not.
type GitConfig struct {
	Entries []GitEntry
	// Headers lists every section header in file order, with Name left "",
	// so a section holding no variable is still seen.
	Headers []GitEntry
	// BadLine is the line git stops at with "bad config line N", 0 for a file
	// git loads.
	BadLine int
}

type gitSource struct {
	data []byte
	at   int
	line int
	eof  bool
}

// next is get_next_char: CRLF reads as a newline, and the end of the file as
// one more newline with eof set.
func (s *gitSource) next() byte {
	if s.at >= len(s.data) {
		s.eof = true
		s.line++
		return '\n'
	}
	c := s.data[s.at]
	s.at++
	if c == '\r' && s.at < len(s.data) && s.data[s.at] == '\n' {
		s.at++
		c = '\n'
	}
	if c == '\n' {
		s.line++
	}
	return c
}

// gitSpace is isspace under git's own ctype table, which leaves out the
// vertical tab and the form feed.
func gitSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func gitAlpha(c byte) bool { return c|0x20 >= 'a' && c|0x20 <= 'z' }

func gitKeyChar(c byte) bool { return gitAlpha(c) || c >= '0' && c <= '9' || c == '-' }

func gitLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 0x20
	}
	return c
}

// ParseGitConfig reads data as git loads a configuration file. What it holds
// up to a bad line is returned with BadLine set; git itself aborts there, so
// a caller owes that file a refusal, not a reading.
func ParseGitConfig(data []byte) GitConfig {
	var cfg GitConfig
	s := &gitSource{data: data, line: 1}
	if rest, ok := strings.CutPrefix(string(data), "\xef\xbb\xbf"); ok {
		s.at = len(data) - len(rest)
	} else if len(data) > 0 && data[0] == 0xef {
		// git does not tolerate a partial byte order mark.
		cfg.BadLine = 1
		return cfg
	}
	var section GitEntry
	comment := false
	for {
		c := s.next()
		switch {
		case c == '\n':
			if s.eof {
				return cfg
			}
			comment = false
		case comment, gitSpace(c):
		case c == '#' || c == ';':
			comment = true
		case c == '[':
			section = GitEntry{HeaderLine: s.line}
			if !s.header(&section) {
				cfg.BadLine = s.line
				return cfg
			}
			cfg.Headers = append(cfg.Headers, section)
		case !gitAlpha(c):
			cfg.BadLine = s.line
			return cfg
		default:
			e := section
			e.Line = s.line
			if !s.variable(&e, c) {
				cfg.BadLine = s.line
				return cfg
			}
			cfg.Entries = append(cfg.Entries, e)
		}
	}
}

// header is get_base_var and get_extended_base_var: the text after a [, up
// to its ]. A line ending inside the header is charged to that line, and a
// header naming nothing at all is refused.
func (s *gitSource) header(e *GitEntry) bool {
	var name []byte
	split := func() {
		e.Section = string(name)
		if base, sub, ok := strings.Cut(e.Section, "."); ok {
			e.Section, e.Subsection, e.Dotted = base, sub, true
		}
	}
	for {
		c := s.next()
		switch {
		case s.eof:
			return false
		case c == ']':
			split()
			return len(name) > 0
		case gitSpace(c):
			for {
				if c == '\n' {
					s.line--
					return false
				}
				if c = s.next(); !gitSpace(c) {
					break
				}
			}
			if c != '"' {
				return false
			}
			// git appends the quoted text to the name after a dot, so a dotted
			// base ahead of it joins the subsection.
			split()
			var sub []byte
			for {
				c := s.next()
				if c == '\n' {
					s.line--
					return false
				}
				if c == '"' {
					break
				}
				if c == '\\' {
					if c = s.next(); c == '\n' {
						s.line--
						return false
					}
				}
				sub = append(sub, c)
			}
			if e.Dotted {
				e.Subsection += "." + string(sub)
			} else {
				e.Subsection = string(sub)
			}
			return s.next() == ']'
		case !gitKeyChar(c) && c != '.':
			return false
		default:
			name = append(name, gitLower(c))
		}
	}
}

// variable is get_value and parse_value: a name opening with first, then
// nothing, or = and a value.
func (s *gitSource) variable(e *GitEntry, first byte) bool {
	name := []byte{gitLower(first)}
	var c byte
	for {
		if c = s.next(); s.eof || !gitKeyChar(c) {
			break
		}
		name = append(name, gitLower(c))
	}
	for c == ' ' || c == '\t' {
		c = s.next()
	}
	e.Name = string(name)
	if c == '\n' {
		e.EndLine = e.Line
		return true
	}
	if c != '=' {
		return false
	}
	var value []byte
	quote, comment := false, false
	trim := 0
	for {
		c := s.next()
		if c == '\n' {
			if quote {
				s.line--
				return false
			}
			if trim > 0 {
				value = value[:trim]
			}
			e.Value, e.HasValue, e.EndLine = string(value), true, s.line-1
			return true
		}
		if comment {
			continue
		}
		if gitSpace(c) && !quote {
			if trim == 0 {
				trim = len(value)
			}
			if len(value) > 0 {
				value = append(value, c)
			}
			continue
		}
		if !quote && (c == ';' || c == '#') {
			comment = true
			continue
		}
		trim = 0
		switch c {
		case '\\':
			switch c = s.next(); c {
			case '\n':
				continue
			case 't':
				c = '\t'
			case 'b':
				c = '\b'
			case 'n':
				c = '\n'
			case '\\', '"':
			default:
				return false
			}
			value = append(value, c)
		case '"':
			quote = !quote
		default:
			value = append(value, c)
		}
	}
}

// Key is the variable's full name as git prints it.
func (e GitEntry) Key() string {
	parts := []string{e.Section}
	if e.Subsection != "" {
		parts = append(parts, e.Subsection)
	}
	return strings.TrimPrefix(strings.Join(append(parts, e.Name), "."), ".")
}

// GitLoadError names the first of files git fetch and git clone do not run
// with, or doctor cannot tell so of, as a phrase a diagnostic can carry: a
// file git cannot parse, with the line it stops at, or one holding a variable
// GitConvertError or GitTLSUnmodeled names, with that line and its message.
// "" when git loads every one that can be read, converts each variable those
// commands read, and takes its TLS policy from nothing but the roots.
// git aborts on such a file whichever section the line sits in, so nothing
// else it holds is configuration git runs with.
func GitLoadError(files []string) string {
	for _, f := range files {
		data, err := plannedfs.ReadFile(f)
		if err != nil {
			continue
		}
		cfg := ParseGitConfig(data)
		if cfg.BadLine > 0 {
			return fmt.Sprintf("%s (bad config line %d, which git aborts every command on)", f, cfg.BadLine)
		}
		if line, msg := GitConvertError(cfg); msg != "" {
			return fmt.Sprintf("%s (line %d: %s)", f, line, msg)
		}
		if line, msg := GitTLSUnmodeled(cfg); msg != "" {
			return fmt.Sprintf("%s (line %d: %s)", f, line, msg)
		}
	}
	return ""
}

// gitLineKinds classifies each physical line of a body as the grammar reads
// it: a section header, the line a variable opens on, a line an earlier
// value runs on into, or none of them.
type gitLineKind int

const (
	gitLineOther gitLineKind = iota
	gitLineHeader
	gitLineVariable
	gitLineContinued
)

func (cfg GitConfig) lineKinds(n int) []gitLineKind {
	kinds := make([]gitLineKind, n)
	set := func(line int, k gitLineKind) {
		if line >= 1 && line <= n {
			kinds[line-1] = k
		}
	}
	for _, h := range cfg.Headers {
		set(h.HeaderLine, gitLineHeader)
	}
	for _, e := range cfg.Entries {
		if e.Line != e.HeaderLine {
			set(e.Line, gitLineVariable)
		}
		for l := e.Line + 1; l <= e.EndLine; l++ {
			set(l, gitLineContinued)
		}
	}
	return kinds
}

// gitEditorMisreads names the first line of a body the line editor would not
// take the way git's grammar does, "" when the two agree on every line:
// which lines are headers, which open a variable and under what name, and
// which continue a value. The editor replaces and keeps whole lines, so an
// edit built over a line it misreads could drop or keep the wrong setting.
func gitEditorMisreads(lines []string, cfg GitConfig) string {
	kinds := cfg.lineKinds(len(lines))
	names := map[int]string{}
	for _, e := range cfg.Entries {
		if e.HasValue {
			names[e.Line] = e.Name
		}
	}
	scan := lineScan{rules: gitRules, keyIndent: -1}
	for i, l := range lines {
		t := strings.TrimSpace(l)
		got := gitLineOther
		switch {
		case scan.continues(l):
			got = gitLineContinued
		case strings.HasPrefix(t, "["):
			got = gitLineHeader
		case settingKey(l) != "":
			got = gitLineVariable
		}
		want := kinds[i]
		// A name with no value is a line the editor keeps and never sets.
		if want == gitLineVariable && names[i+1] == "" {
			want = gitLineOther
		}
		if got != want || got == gitLineVariable && settingKey(l) != names[i+1] {
			return t
		}
	}
	return ""
}

// gitHolds reports how merged, a git file with a plan's settings merged in,
// fails to read as planned sets it under git's own grammar: a file git would
// refuse to load, or one where a variable planned gives is missing or holds
// another value.
func gitHolds(merged, planned []byte) error {
	m, p := ParseGitConfig(merged), ParseGitConfig(planned)
	if m.BadLine > 0 {
		return fmt.Errorf("git would refuse to load the result at line %d", m.BadLine)
	}
	for _, want := range p.Entries {
		if !slices.ContainsFunc(m.Entries, func(e GitEntry) bool {
			return e.Key() == want.Key() && e.Value == want.Value && e.HasValue == want.HasValue
		}) {
			return fmt.Errorf("the result does not give %s the value the plan sets", want.Key())
		}
	}
	return nil
}

// gitKeeps reports the first variable of old that merged no longer gives as
// old did and that planned does not set. http.sslCAInfo is the plan's under
// whatever URL a section scopes it to, since the CA setting goes into each
// section that would outrank the plan's; every other variable is the plan's
// only under the section and subsection planned gives it.
func gitKeeps(old, merged, planned []byte) error {
	owned := map[string]bool{}
	for _, e := range ParseGitConfig(planned).Entries {
		owned[e.Key()] = true
		if e.Section == "http" && e.Name == "sslcainfo" {
			owned["http.sslcainfo"] = true
		}
	}
	left := map[GitEntry]int{}
	plain := func(e GitEntry) GitEntry {
		e.Line, e.EndLine, e.HeaderLine = 0, 0, 0
		return e
	}
	for _, e := range ParseGitConfig(merged).Entries {
		left[plain(e)]++
	}
	for _, e := range ParseGitConfig(old).Entries {
		if owned[e.Key()] || owned[e.Section+"."+e.Name] {
			continue
		}
		if left[plain(e)] == 0 {
			return fmt.Errorf("the merge would not keep %s, which the plan does not set", e.Key())
		}
		left[plain(e)]--
	}
	return nil
}
