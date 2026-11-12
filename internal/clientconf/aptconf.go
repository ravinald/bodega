package clientconf

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// This file ports APT 3.0.3's configuration loader: ReadConfigFile and
// ReadConfigDir (apt-pkg/contrib/configuration.cc), ParseQuoteWord and
// ParseCWord (apt-pkg/contrib/strutl.cc), GetListOfFilesInDir
// (apt-pkg/contrib/fileutl.cc) and the load order of pkgInitConfig
// (apt-pkg/init.cc). apt fails every command when any file it loads has a
// syntax error, so the port answers for the whole file set or for none of it.

// AptOption is the value apt's configuration gives one option, and the file
// that gave it.
type AptOption struct{ Value, File string }

// AptConfig is apt's configuration tree flattened: each option under its
// lowercased name, scopes joined with "::", since apt matches names without
// regard to case. List items, which carry no name, are not kept.
type AptConfig map[string]AptOption

// Paths apt's configuration is loaded from, under its default Dir and
// Dir::Etc.
const (
	AptConfMainPath  = "/etc/apt/apt.conf"
	AptConfPartsPath = "/etc/apt/apt.conf.d"
)

const aptIncludeDepth = 10

// aptLayout is the options that say where apt reads its configuration from,
// with the value pkgInitConfig gives each before any file is read. A file
// that moves one changes the file set mid-load, which this port does not
// follow.
var aptLayout = map[string]string{
	"rootdir":         "",
	"dir":             "/",
	"dir::etc":        "etc/apt",
	"dir::etc::main":  "apt.conf",
	"dir::etc::parts": "apt.conf.d",
}

// LoadAptConfig reads apt's configuration as pkgInitConfig does, a later
// assignment replacing an earlier one: the file APT_CONFIG names, the
// apt.conf.d fragments apt accepts in name order, then apt.conf, each with
// its #include files where the directive stands. root is the directory the
// absolute paths sit under, "" for the host's own.
//
// The error is the first thing that stops apt loading the set, naming the
// file and line, or the first construct this port detects and does not
// interpret: a file that moves apt's configuration directory, a relative
// #include, #x-apt-configure-index, or a file that exists and cannot be read.
// The options read before an error are not returned, because apt runs with
// none of them.
func LoadAptConfig(root string, getenv func(string) string) (AptConfig, error) {
	l := aptLoader{root: root, conf: AptConfig{}}
	if getenv != nil {
		if f := getenv("APT_CONFIG"); f != "" && isRegular(f) {
			if err := l.file(f, 0); err != nil {
				return nil, err
			}
		}
	}
	if parts := filepath.Join(root, AptConfPartsPath); isDir(parts) {
		if err := l.dir(parts, 0); err != nil {
			return nil, err
		}
	}
	if f := filepath.Join(root, AptConfMainPath); isRegular(f) {
		if err := l.file(f, 0); err != nil {
			return nil, err
		}
	}
	return l.conf, nil
}

func isRegular(path string) bool {
	_, ok := regularFile(path)
	return ok
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

type aptLoader struct {
	root string
	conf AptConfig
}

func (l *aptLoader) file(name string, depth int) error {
	data, err := os.ReadFile(name)
	if err != nil {
		return fmt.Errorf("%s could not be read (%w), so what apt loads from it is unknown", name, err)
	}
	return l.parse(name, string(data), depth)
}

// dir reads the files of one configuration directory in the order
// GetListOfFilesInDir sorts them.
func (l *aptLoader) dir(dir string, depth int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("%s could not be read (%w), so what apt loads from it is unknown", dir, err)
	}
	var files []string
	for _, e := range entries {
		if path := filepath.Join(dir, e.Name()); aptPartAccepted(e.Name()) && isRegular(path) {
			files = append(files, path)
		}
	}
	sort.Strings(files)
	for _, f := range files {
		if err := l.file(f, depth); err != nil {
			return err
		}
	}
	return nil
}

// aptPartAccepted reports whether GetListOfFilesInDir(dir, "conf", true,
// true) keeps a file of this name: not hidden, no extension or .conf, only
// letters, digits, '_', '-', ':' and '.', and no trailing period.
func aptPartAccepted(name string) bool {
	if name == "" || name[0] == '.' || name[len(name)-1] == '.' {
		return false
	}
	if i := strings.LastIndexByte(name, '.'); i >= 0 && name[i+1:] != "conf" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == ':' || c == '.') {
			return false
		}
	}
	return true
}

// aptSpace is C's isspace in the locale apt parses under.
func aptSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
}

// aptQuoted reports whether offset i of line sits inside a quoted string, by
// the parity of the quotes before it, as ReadConfigFile counts them.
func aptQuoted(line string, i int) bool {
	return strings.Count(line[:i], `"`)%2 != 0
}

// aptStripComments removes the comments of one input line and returns what is
// left. inComment carries a /* */ comment across lines. A '#' outside quotes
// opens a comment wherever it stands, unless one of apt's directives follows.
func aptStripComments(line string, inComment *bool) string {
	if *inComment {
		end := strings.Index(line, "*/")
		if end < 0 {
			return ""
		}
		line = line[end+2:]
		*inComment = false
	}
	for start := 0; ; start++ {
		i := strings.Index(line[start:], "//")
		if i < 0 {
			break
		}
		start += i
		if !aptQuoted(line, start) {
			line = line[:start]
			break
		}
	}
	for start := 0; ; start++ {
		i := strings.IndexByte(line[start:], '#')
		if i < 0 {
			break
		}
		start += i
		rest := line[start+1:]
		if aptQuoted(line, start) || strings.HasPrefix(rest, "clear") || strings.HasPrefix(rest, "include") || strings.HasPrefix(rest, "x-apt-configure-index") {
			continue
		}
		line = line[:start]
		break
	}
	var fragment strings.Builder
	for start := 0; ; {
		i := strings.Index(line[start:], "/*")
		if i < 0 {
			break
		}
		start += i
		if aptQuoted(line, start) {
			start += 2
			continue
		}
		fragment.WriteString(line[:start])
		end := strings.Index(line[start+2:], "*/")
		if end < 0 {
			line = ""
			*inComment = true
			break
		}
		line = line[start+2+end+2:]
		start = 0
	}
	fragment.WriteString(line)
	return fragment.String()
}

// aptQuoteWord is ParseQuoteWord: one word off the front of s, a quoted or
// bracketed run inside it kept whole, with the quotes dropped and %XX
// decoded. ok is false with no word left or a quote or bracket left open.
func aptQuoteWord(s string) (word, rest string, ok bool) {
	c := 0
	for c < len(s) && s[c] == ' ' {
		c++
	}
	if c == len(s) {
		return "", s, false
	}
	for ; c < len(s) && !aptSpace(s[c]); c++ {
		if s[c] == '"' {
			end := strings.IndexByte(s[c+1:], '"')
			if end < 0 {
				return "", s, false
			}
			c += 1 + end
		}
		if s[c] == '[' {
			end := strings.IndexByte(s[c+1:], ']')
			if end < 0 {
				return "", s, false
			}
			c += 1 + end
		}
	}
	var res strings.Builder
	for i := 0; i < c; {
		if s[i] == '%' && i+2 < c && isHex(s[i+1]) && isHex(s[i+2]) {
			res.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 3
			continue
		}
		if s[i] != '"' {
			res.WriteByte(s[i])
		}
		i++
	}
	for c < len(s) && aptSpace(s[c]) {
		c++
	}
	return res.String(), s[c:], true
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= 'a':
		return c - 'a' + 10
	case c >= 'A':
		return c - 'A' + 10
	}
	return c - '0'
}

// aptCWord is ParseCWord: s read as a run of quoted strings, joined with one
// space where whitespace parts them. ok is false when anything stands outside
// the quotes, and then s is not consumed.
func aptCWord(s string) (word string, ok bool) {
	c := 0
	for c < len(s) && s[c] == ' ' {
		c++
	}
	if c == len(s) {
		return "", false
	}
	var res strings.Builder
	for ; c < len(s); c++ {
		if s[c] == '"' {
			for c++; c < len(s) && s[c] != '"'; c++ {
				res.WriteByte(s[c])
			}
			if c == len(s) {
				return "", false
			}
			continue
		}
		if c != 0 && aptSpace(s[c]) && aptSpace(s[c-1]) {
			continue
		}
		if !aptSpace(s[c]) {
			return "", false
		}
		res.WriteByte(' ')
	}
	return res.String(), true
}

// parse is ReadConfigFile over text. Statements are judged whole: every one
// ends at ';', '{' or '}', holds a tag and at most one value, and anything
// left at the end of the file is an error, whichever option it names.
func (l *aptLoader) parse(name, text string, depth int) error {
	syntax := func(line int, format string, args ...any) error {
		return fmt.Errorf("syntax error %s:%d: %s", name, line, fmt.Sprintf(format, args...))
	}
	var stack []string
	var parent, buffer string
	leave := func() {
		if len(stack) == 0 {
			parent = ""
			return
		}
		parent, stack = stack[len(stack)-1], stack[:len(stack)-1]
	}
	inComment := false
	lines := strings.Split(text, "\n")
	for n, raw := range lines {
		cur := n + 1
		input := strings.Trim(strings.ReplaceAll(raw, "\t", "        "), " \n\v\f\r")
		fragment := aptStripComments(input, &inComment)
		if fragment == "" {
			continue
		}
		inQuote := false
		start := 0
		for i := 0; i < len(fragment); i++ {
			c := fragment[i]
			if c == '"' {
				inQuote = !inQuote
			}
			if inQuote || (c != '{' && c != ';' && c != '}') {
				continue
			}
			lo, hi := start, i
			for lo != i && aptSpace(fragment[lo]) {
				lo++
			}
			for hi != lo && aptSpace(fragment[hi-1]) {
				hi--
			}
			if buffer != "" && hi != lo {
				buffer += " "
			}
			buffer += fragment[lo:hi]
			term := c
			start = i + 1

			if term == '{' && buffer == "" {
				return syntax(cur, "block starts with no name")
			}
			if buffer == "" {
				if term == '}' {
					leave()
				}
				continue
			}
			tag, pos, ok := aptQuoteWord(buffer)
			if !ok {
				return syntax(cur, "malformed tag")
			}
			noWord := false
			word, ok := aptCWord(pos)
			if ok {
				pos = ""
			} else if word, pos, ok = aptQuoteWord(pos); !ok {
				if term != '{' {
					word, tag = tag, ""
				} else {
					noWord = true
				}
			}
			if pos != "" {
				return syntax(cur, "extra junk after value")
			}
			if term == '{' {
				stack = append(stack, parent)
				if parent == "" {
					parent = tag
				} else {
					parent += "::" + tag
				}
				tag = ""
			}
			item := tag
			if parent != "" {
				item = parent
				if term != '{' || tag != "" {
					item = parent + "::" + tag
				}
			}
			switch {
			case strings.HasPrefix(tag, "#"):
				if parent != "" {
					return syntax(cur, "directives can only be done at the top level")
				}
				switch tag[1:] {
				case "clear":
					if err := l.clear(name, cur, word); err != nil {
						return err
					}
				case "include":
					if err := l.include(name, cur, word, depth); err != nil {
						return err
					}
				case "x-apt-configure-index":
					return fmt.Errorf("%s:%d holds #x-apt-configure-index, which this command detects and does not interpret", name, cur)
				default:
					return syntax(cur, "unsupported directive '%s'", tag[1:])
				}
			case tag == "" && !noWord && word == "#clear":
				return syntax(cur, "clear directive requires an option tree as argument")
			case !noWord:
				if err := l.set(name, cur, item, word); err != nil {
					return err
				}
			}
			buffer = ""
			if term == '}' {
				leave()
			}
		}
		rest := strings.TrimRight(strings.TrimLeft(fragment[start:], " \t"), " \t\n\r")
		if rest != "" && buffer != "" {
			buffer += " "
		}
		buffer += rest
	}
	if buffer != "" {
		return syntax(len(lines), "extra junk at end of file")
	}
	return nil
}

// aptKey is the flattened name of an option, and whether it has one: an empty
// component is a list item apt creates anew on every assignment, which no
// lookup by name reaches.
func aptKey(item string) (string, bool) {
	key := strings.ToLower(item)
	if key == "" {
		return "", false
	}
	for _, part := range strings.Split(key, "::") {
		if part == "" {
			return "", false
		}
	}
	return key, true
}

func aptMoved(file string, line int, key string) error {
	return fmt.Errorf("%s:%d sets %s, which moves where apt reads its configuration from; this command detects that and does not follow it", file, line, key)
}

func (l *aptLoader) set(file string, line int, item, value string) error {
	key, ok := aptKey(item)
	if !ok {
		return nil
	}
	if def, layout := aptLayout[key]; layout && value != def {
		return aptMoved(file, line, item)
	}
	l.conf[key] = AptOption{Value: value, File: file}
	return nil
}

// clear is Configuration::Clear(Name): the option's own value and everything
// under it.
func (l *aptLoader) clear(file string, line int, item string) error {
	key, ok := aptKey(item)
	if !ok {
		return nil
	}
	for layout := range aptLayout {
		if layout == key || strings.HasPrefix(layout, key+"::") {
			return aptMoved(file, line, "#clear "+item)
		}
	}
	for k := range l.conf {
		if k == key || strings.HasPrefix(k, key+"::") {
			delete(l.conf, k)
		}
	}
	return nil
}

// include follows #include as ReadConfigFile does: a name ending in '/' is a
// directory read like apt.conf.d, anything else one file, which must load.
func (l *aptLoader) include(file string, line int, target string, depth int) error {
	switch {
	case depth > aptIncludeDepth:
		return fmt.Errorf("syntax error %s:%d: too many nested includes", file, line)
	case !filepath.IsAbs(target):
		return fmt.Errorf("%s:%d includes %q, which apt resolves against the directory it is started in; this command detects that and does not follow it", file, line, target)
	}
	path := filepath.Join(l.root, target)
	var err error
	if len(target) > 2 && strings.HasSuffix(target, "/") {
		if err = l.dir(path, depth+1); err == nil && !isDir(path) {
			err = fmt.Errorf("%s is not a directory", path)
		}
	} else {
		err = l.file(path, depth+1)
	}
	if err != nil {
		return fmt.Errorf("%w (included from %s:%d)", err, file, line)
	}
	return nil
}

// aptBool is StringToBool in apt-pkg/contrib/strutl.cc at APT 3.0.3 (lines
// 844-871): 0 or 1 written as a whole number, one of apt's truth words in any
// case, and def for anything else. apt reads every boolean and integer
// option through it or through strtol the same way (Configuration::FindB and
// FindI, apt-pkg/contrib/configuration.cc, lines 471-496), so a value of the
// wrong type is the default and never an error.
func aptBool(text string, def bool) bool {
	if m := aptZeroOrOne.FindStringSubmatch(text); m != nil && !(m[1] == "-" && m[2] == "1") {
		return m[2] == "1"
	}
	switch strings.ToLower(text) {
	case "no", "false", "without", "off", "disable":
		return false
	case "yes", "true", "with", "on", "enable":
		return true
	}
	return def
}

// aptZeroOrOne is the whole of a string strtol reads in base 0 as 0 or 1.
var aptZeroOrOne = regexp.MustCompile(`^[ \t\n\v\f\r]*([+-]?)(?:0[xX])?0*([01])$`)

// HTTPSError is why apt's https method opens no TLS connection to host under
// this configuration, or nil when it does: UnwrapTLS and GetContextForHost in
// methods/connect.cc at APT 3.0.3 (lines 925-1004), up to the handshake.
// Acquire::AllowTLS read as false turns TLS off; IssuerCert and
// SslForceVersion are options apt no longer supports and stops on when
// either is set; and a client certificate, its key and a revocation list
// must each load. Each option is looked up for host first and then for every
// host, as CAInfo is. root is the directory absolute paths sit under.
//
// Whether a file that reads also parses is OpenSSL's to say, at the
// handshake. CAInfo is the trust store, and is read where trust is judged.
func (c AptConfig) HTTPSError(host, root string) error {
	if v := c["acquire::allowtls"]; v.Value != "" && !aptBool(v.Value, true) {
		return fmt.Errorf("TLS support has been disabled: Acquire::AllowTLS is false (%s)", v.File)
	}
	find := func(option string) AptOption {
		if v := c["acquire::https::"+strings.ToLower(host)+"::"+option]; v.Value != "" {
			return v
		}
		return c["acquire::https::"+option]
	}
	for _, option := range []string{"IssuerCert", "SslForceVersion"} {
		if v := find(strings.ToLower(option)); v.Value != "" {
			return fmt.Errorf("the option '%s' is not supported anymore (%s)", option, v.File)
		}
	}
	for _, f := range []struct{ option, what string }{
		{"SslCert", "Could not load client certificate"}, {"SslKey", "Could not load client or key"}, {"CrlFile", "Could not load custom certificate revocation list"},
	} {
		v := find(strings.ToLower(f.option))
		if v.Value == "" {
			continue
		}
		if !filepath.IsAbs(v.Value) {
			return fmt.Errorf("%s names the relative path %s (%s), which apt opens against the directory it is started in and doctor does not interpret", f.option, v.Value, v.File)
		}
		if _, err := os.ReadFile(filepath.Join(root, v.Value)); err != nil {
			return fmt.Errorf("%s (%s, %s option in %s): %w", f.what, v.Value, f.option, v.File, err)
		}
	}
	return nil
}
