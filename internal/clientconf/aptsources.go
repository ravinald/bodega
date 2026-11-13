package clientconf

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// AptSourcesList and AptSourcesParts are where apt reads its sources from
// with Dir::Etc left alone, which LoadAptConfig refuses a host that moves.
const (
	AptSourcesList  = "/etc/apt/sources.list"
	AptSourcesParts = "/etc/apt/sources.list.d"
)

// AptSourceEntry is one enabled source apt loads: a one-line entry or a
// deb822 stanza.
type AptSourceEntry struct {
	// File is the sources file and Entry the line of a one-line entry or
	// the number of a stanza, each counted from 1 as apt's errors count them.
	File  string
	Entry int
	// URIs are the entry's URIs as the file writes them.
	URIs []string
}

// aptSourceTypes are the types apt's Debian system registers: debSLTypeDeb
// and debSLTypeDebSrc in apt-pkg/deb/debmetaindex.cc.
var aptSourceTypes = []string{"deb", "deb-src"}

// LoadAptSources reads every source under root as APT 3.0.3 reads them:
// pkgSourceList::ReadMainList (apt-pkg/sourcelist.cc, lines 311-340) reads
// sources.list and then each sources.list.d file ending .list or .sources,
// ParseFileOldStyle and Type::ParseLine (lines 374-420 and 198-286) take a
// one-line file and ParseFileDeb822 and Type::ParseStanza (lines 427-460 and
// 98-190) a deb822 one, and FixupURI (lines 81-96) checks each URI. apt
// validates an entry's shape there and nothing of the URI past its colon:
// which method fetches it is settled when it is fetched.
//
// An error is one apt reports as it loads the lists, in apt's words after
// the "apt: " that opens it: a line
// with no type or an unknown one, an option that is not key=value, a missing
// URI, suite or component, a URI with no colon, a component on a suite that
// ends in a slash. apt then reads none of its sources ("The list of sources
// could not be read"), whichever file holds the entry, so no source in any
// file is one apt fetches from. The checks apt runs later, as it builds each
// index from an entry's options (Signed-By, conflicting options between two
// entries for one archive), are not read.
func LoadAptSources(root string) ([]AptSourceEntry, error) {
	var out []AptSourceEntry
	var firstErr error
	read := func(path string) {
		data, err := os.ReadFile(path)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("opening %s: %w", path, err)
			}
			return
		}
		entries, err := parseAptList(path, string(data))
		if filepath.Ext(path) == ".sources" {
			entries, err = parseAptDeb822(path, string(data))
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
		out = append(out, entries...)
	}
	if info, err := os.Stat(filepath.Join(root, AptSourcesList)); err == nil && info.Mode().IsRegular() {
		read(filepath.Join(root, AptSourcesList))
	}
	parts := filepath.Join(root, AptSourcesParts)
	names, err := os.ReadDir(parts)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("list %s: %w", parts, err)
	}
	var files []string
	for _, e := range names {
		// GetListOfFilesInDir: a name outside [A-Za-z0-9_.-], another
		// extension, or anything but a file is passed over without a word.
		name := e.Name()
		ext := filepath.Ext(name)
		if ext != ".list" && ext != ".sources" || strings.ContainsFunc(name, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.')
		}) {
			continue
		}
		if info, err := os.Stat(filepath.Join(parts, name)); err != nil || !info.Mode().IsRegular() {
			continue
		}
		files = append(files, filepath.Join(parts, name))
	}
	sort.Strings(files)
	for _, f := range files {
		read(f)
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// aptFixupURI is the check of Type::FixupURI: a URI is anything non-empty
// holding a colon.
func aptFixupURI(uri string) bool {
	return uri != "" && strings.Contains(uri, ":")
}

// parseAptList is ParseFileOldStyle with Type::ParseLine.
func parseAptList(file, text string) ([]AptSourceEntry, error) {
	var out []AptSourceEntry
	for n, line := range strings.Split(text, "\n") {
		n++
		malformed := func(what string) error {
			return fmt.Errorf("apt: Malformed entry %d in list file %s (%s)", n, file, what)
		}
		// A # outside an [option] block opens a comment.
		for at := 0; ; at++ {
			i := strings.IndexByte(line[at:], '#')
			if i < 0 {
				break
			}
			at += i
			if strings.Count(line[:at], "[") > strings.Count(line[:at], "]") {
				continue
			}
			line = line[:at]
			break
		}
		line = strings.Trim(line, " \t\r")
		if line == "" {
			continue
		}
		typ := line
		if i := strings.IndexAny(line, " \t\v"); i >= 0 {
			typ = line[:i]
		}
		if typ == "" || typ == line {
			return out, fmt.Errorf("apt: Malformed line %d in source list %s (type)", n, file)
		}
		if !slices.Contains(aptSourceTypes, typ) {
			return out, fmt.Errorf("apt: Type '%s' is not known on line %d in source list %s", typ, n, file)
		}
		buf, pos := line[len(typ):], 0
		skip := func() {
			for pos < len(buf) && aptSpace(buf[pos]) {
				pos++
			}
		}
		// word is ParseQuoteWord over what is left of the line.
		word := func() (string, bool) {
			w, rest, ok := aptQuoteWord(buf[pos:])
			if ok {
				pos = len(buf) - len(rest)
			}
			return w, ok
		}
		skip()
		if pos < len(buf) && buf[pos] == '[' {
			pos++
			skip()
			for pos >= len(buf) || buf[pos] != ']' {
				option, ok := word()
				if !ok {
					return out, malformed("[option] unparsable")
				}
				if len(option) < 3 {
					return out, malformed("[option] too short")
				}
				if option[len(option)-1] == ']' {
					for pos--; buf[pos] != ']'; pos-- {
					}
					option = option[:len(option)-1]
				}
				key, value, found := strings.Cut(option, "=")
				switch {
				case !found:
					return out, malformed("[option] not assignment")
				case key == "":
					return out, malformed("[option] no key")
				case value == "":
					return out, malformed("[option] no value")
				}
			}
			pos++
			skip()
		}
		uri, ok := word()
		if !ok {
			return out, malformed("URI")
		}
		dist, ok := word()
		if !ok {
			return out, malformed("Suite")
		}
		if !aptFixupURI(uri) {
			return out, malformed("URI parse")
		}
		_, more := word()
		switch absolute := dist != "" && dist[len(dist)-1] == '/'; {
		case absolute && more:
			return out, malformed("absolute Suite Component")
		case !absolute && !more:
			return out, malformed("Component")
		}
		out = append(out, AptSourceEntry{File: file, Entry: n, URIs: []string{uri}})
	}
	return out, nil
}

// parseAptDeb822 is ParseFileDeb822 with Type::ParseStanza, over a reading of
// the stanzas that takes the forms a sources file is written in: fields as
// "Name: value", a line opening with a space or tab continuing the field
// above it, a line opening with # a comment, and a blank line ending the
// stanza. A line that is none of those is one this reader does not place,
// and is refused rather than guessed at.
func parseAptDeb822(file, text string) ([]AptSourceEntry, error) {
	var out []AptSourceEntry
	stanza, n := map[string]string{}, 0
	last := ""
	multi := func(field string) []string { return AptWords(stanza[field]) }
	flush := func() error {
		defer func() { stanza, last = map[string]string{}, "" }()
		if len(stanza) == 0 {
			return nil
		}
		n++
		malformed := func(what string) error {
			return fmt.Errorf("apt: Malformed entry %d in sources file %s (%s)", n, file, what)
		}
		if _, ok := stanza["types"]; !ok {
			return fmt.Errorf("apt: Malformed stanza %d in source list %s (type)", n, file)
		}
		for _, typ := range multi("types") {
			if !slices.Contains(aptSourceTypes, typ) {
				return fmt.Errorf("apt: Type '%s' is not known on stanza %d in source list %s", typ, n, file)
			}
		}
		// StringToBool: only a spelling of "no" turns a stanza off.
		if slices.Contains([]string{"0", "no", "false", "without", "off", "disable"}, strings.ToLower(strings.TrimSpace(stanza["enabled"]))) {
			return nil
		}
		if len(multi("types")) == 0 {
			return nil
		}
		uris, suites, comps := multi("uris"), multi("suites"), multi("components")
		if len(uris) == 0 {
			return malformed("URI")
		}
		if len(suites) == 0 {
			return malformed("Suite")
		}
		for _, uri := range uris {
			if !aptFixupURI(uri) {
				return malformed("URI parse")
			}
			for _, s := range suites {
				switch absolute := s[len(s)-1] == '/'; {
				case absolute && len(comps) > 0:
					return malformed("absolute Suite Component")
				case !absolute && len(comps) == 0:
					return malformed("Component")
				}
			}
		}
		out = append(out, AptSourceEntry{File: file, Entry: n, URIs: uris})
		return nil
	}
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.TrimSpace(line) == "":
			if err := flush(); err != nil {
				return out, err
			}
		case line[0] == '#':
		case line[0] == ' ' || line[0] == '\t':
			if last == "" {
				return out, fmt.Errorf("line %d of %s continues a field where none is open, which this reader of apt's deb822 format does not place", i+1, file)
			}
			stanza[last] += "\n" + line
		default:
			name, value, ok := strings.Cut(line, ":")
			if !ok || name == "" || strings.ContainsAny(name, " \t") {
				return out, fmt.Errorf("line %d of %s is not a field, a continuation or a comment, which this reader of apt's deb822 format does not place", i+1, file)
			}
			last = strings.ToLower(name)
			stanza[last] = value
		}
	}
	if err := flush(); err != nil {
		return out, err
	}
	return out, nil
}

// AptURIHost is the host and port apt connects to for a source URI, as
// URI::CopyFrom (apt-pkg/contrib/strutl.cc, line 1637) splits it: the access method
// before the first colon, then for a method://host URI the host up to the
// next slash, with user:pass@ and the brackets of an IPv6 literal dropped
// and a trailing :port taken off. port is 0 for none. A transport wrapped
// around another, mirror+https or tor+https, connects as the inner one.
func AptURIHost(uri string) (access, host string, port int) {
	colon := strings.IndexByte(uri, ':')
	if colon < 0 {
		return "", "", 0
	}
	access = uri[:colon]
	if i := strings.LastIndexByte(access, '+'); i >= 0 {
		access = access[i+1:]
	}
	if !strings.HasPrefix(uri[colon:], "://") {
		return access, "", 0
	}
	rest := uri[colon+3:]
	end, bracket := 0, false
	for ; end < len(rest) && (rest[end] != '/' || bracket); end++ {
		if rest[end] == '[' {
			bracket = true
		}
		if bracket && rest[end] == ']' {
			bracket = false
		}
	}
	host = rest[:end]
	if at := strings.LastIndexByte(host, '@'); at >= 0 {
		host = host[at+1:]
	}
	portEnd := 0
	if strings.HasPrefix(host, "[") {
		close := strings.IndexByte(host, ']')
		if close < 0 {
			return access, "", 0
		}
		host = host[1:close] + host[close+1:]
		portEnd = close - 1
	}
	if pos := strings.LastIndexByte(host, ':'); pos >= 0 && pos >= portEnd {
		port, _ = strconv.Atoi(host[pos+1:])
		host = host[:pos]
	}
	return access, host, port
}

// AptWords splits the value of a sources field into words as apt 3.0.3 does:
// on the six characters isspace_ascii names and no others, so a no-break
// space stays inside the word it touches (apt-pkg/sourcelist.cc, which turns
// each into a space before VectorizeString).
func AptWords(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return strings.ContainsRune(" \t\n\v\f\r", r) })
}
