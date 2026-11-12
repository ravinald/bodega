package host

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// The gemrc reader below ports RubyGems 3.5.22, the release Ubuntu 26.04's
// ruby3.3 package (3.3.8) carries: Gem::ConfigFile#initialize and #load_file
// in lib/rubygems/config_file.rb, Gem::YAMLSerializer.load in
// lib/rubygems/yaml_serializer.rb, and Gem.sources in lib/rubygems.rb. That
// release reads gemrc with its own line-oriented loader rather than a YAML
// library, so a YAML parser would accept files gem reads differently.
//
// Doctor reads the files instead of running `gem sources --list` because
// nothing proves a gem found on PATH authentic and doctor often runs as root.
// Wherever gem itself would raise, discard a file, or build its source list
// from something other than a list of URLs, the reader returns an error and
// the row is unchecked.

// gemrcValue is one value Gem::YAMLSerializer.load stores: a nested mapping,
// a list of strings, or a string.
type gemrcValue struct {
	hash   map[string]*gemrcValue
	list   []string
	isList bool
	str    string
}

// gemrcSpace is Ruby's \s, which the loader's key pattern looks ahead for
// after a colon.
func gemrcSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\v' || b == '\f' || b == '\r'
}

// gemrcQuoted is the tail of both line patterns, (['"]?)(.*)\1$: the value
// loses its quotes only when it opens and closes with the same one.
func gemrcQuoted(rest string) (quote, val string) {
	if len(rest) >= 2 && (rest[0] == '\'' || rest[0] == '"') && rest[len(rest)-1] == rest[0] {
		return rest[:1], rest[1 : len(rest)-1]
	}
	return "", rest
}

// gemrcHashLine matches HASH_REGEX: leading spaces, a key holding no '#', a
// colon followed by whitespace or the end of the line, one optional space,
// and the value. Both the indentation and the key are greedy, so the key
// runs to the last such colon before any '#', and the indentation gives up
// spaces only when no key would otherwise match.
func gemrcHashLine(line string) (indent int, key, quote, val string, ok bool) {
	spaces := len(line) - len(strings.TrimLeft(line, " "))
	limit := len(line)
	if i := strings.IndexByte(line, '#'); i >= 0 {
		limit = i
	}
	for indent = spaces; indent >= 0; indent-- {
		for c := limit - 1; c > indent; c-- {
			if line[c] != ':' || (c+1 < len(line) && !gemrcSpace(line[c+1])) {
				continue
			}
			quote, val = gemrcQuoted(strings.TrimPrefix(line[c+1:], " "))
			return indent, line[indent:c], quote, val, true
		}
	}
	return 0, "", "", "", false
}

// gemrcArrayLine matches ARRAY_REGEX: leading spaces, "- ", and the value.
func gemrcArrayLine(line string) (val string, ok bool) {
	rest, ok := strings.CutPrefix(strings.TrimLeft(line, " "), "- ")
	if !ok {
		return "", false
	}
	_, val = gemrcQuoted(rest)
	return val, true
}

// gemrcStripComment is strip_comment: a '#' anywhere but the first byte ends
// the value.
func gemrcStripComment(val string) string {
	if i := strings.IndexByte(val, '#'); i > 0 {
		return strings.Trim(val[:i], " \t\n\v\f\r\x00")
	}
	return val
}

// loadGemrcYAML is Gem::YAMLSerializer.load. The errors are the inputs it
// raises on rather than loads.
func loadGemrcYAML(data string) (map[string]*gemrcValue, error) {
	if !utf8.ValidString(data) {
		return nil, errors.New("it is not valid UTF-8, which gem fails to load")
	}
	res := map[string]*gemrcValue{}
	stack := []map[string]*gemrcValue{res}
	var lastHash map[string]*gemrcValue
	lastEmptyKey := ""
	for n, line := range strings.Split(data, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if indent, key, quote, val, ok := gemrcHashLine(line); ok {
			val = gemrcStripComment(val)
			depth := indent / 2
			if depth >= len(stack) {
				return nil, fmt.Errorf("line %d is indented under no open mapping, which gem raises on", n+1)
			}
			switch {
			case quote == "" && val == "":
				h := map[string]*gemrcValue{}
				stack[depth][key] = &gemrcValue{hash: h}
				if depth+1 < len(stack) {
					stack[depth+1] = h
				} else {
					stack = append(stack, h)
				}
				lastEmptyKey, lastHash = key, stack[depth]
			case val == "[]":
				stack[depth][key] = &gemrcValue{isList: true}
			default:
				stack[depth][key] = &gemrcValue{str: val}
			}
			continue
		}
		if val, ok := gemrcArrayLine(line); ok {
			if lastHash == nil {
				return nil, fmt.Errorf("line %d is a list item under no key, which gem raises on", n+1)
			}
			v := lastHash[lastEmptyKey]
			if v == nil || !v.isList {
				v = &gemrcValue{isList: true}
				lastHash[lastEmptyKey] = v
			}
			v.list = append(v.list, gemrcStripComment(val))
		}
	}
	return res, nil
}

// gemrcSourcesSpellings are the raw top-level keys that end as :sources: the
// symbol itself, and the string key Gem::ConfigFile converts to it, which
// deep_transform_config_keys! also produces from a key with a trailing slash.
var gemrcSourcesSpellings = []string{":sources", "sources", "sources/"}

// gemrcConfigKey is the key deep_transform_config_keys! leaves, as to_s
// prints it.
func gemrcConfigKey(raw string) string {
	if strings.HasPrefix(raw, ":") {
		return raw[1:]
	}
	if strings.Contains(raw, "__") || strings.HasSuffix(raw, "/") {
		return strings.TrimSuffix(strings.ReplaceAll(raw, "__", "."), "/")
	}
	return raw
}

// loadGemrc is Gem::ConfigFile#load_file for one layer: nil for a file gem
// reads as empty, which a missing one is. gem warns and carries on without a
// file it cannot read or that holds a key with ": " in it; either is an
// error here, because the sources gem then runs with are not the ones the
// file states.
func loadGemrc(path string) (map[string]*gemrcValue, error) {
	if path == "" {
		return nil, nil
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%s is relative, so the file gem loads depends on the directory it runs in", path)
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	config, err := loadGemrcYAML(string(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	schemes := strings.NewReplacer("https://", "", "http://", "")
	for raw := range config {
		if strings.Contains(schemes.Replace(gemrcConfigKey(raw)), ": ") {
			return nil, fmt.Errorf("%s: gem discards the file over its key %q, which is not a YAML mapping key", path, raw)
		}
	}
	return config, nil
}

// gemrcEnv is what selects the gemrc files gem merges.
type gemrcEnv struct {
	lookupEnv func(string) (string, bool)
	home      string
	// system is SYSTEM_WIDE_CONFIG_FILE, gemrc under the sysconfdir Ruby
	// was built with.
	system string
}

// systemGemrc is the system gemrc of the platform's packaged Ruby. The
// directory is compiled into Ruby, so a Ruby built with another sysconfdir
// reads a file this does not name.
func systemGemrc(goos string) string {
	if goos == "freebsd" {
		return "/usr/local/etc/gemrc"
	}
	return "/etc/gemrc"
}

// gemrcFiles lists the files Gem::ConfigFile#initialize merges, later ones
// winning: the system gemrc, the user's, and each file $GEMRC names. A set
// $GEMRC, even an empty one, replaces the user's file with the variable's
// whole value read as one path.
func gemrcFiles(e gemrcEnv) ([]string, error) {
	files := []string{e.system}
	rc, set := e.lookupEnv("GEMRC")
	if set {
		files = append(files, rc)
		return append(files, strings.Split(rc, string(os.PathListSeparator))...), nil
	}
	if e.home == "" {
		return nil, errors.New("the home directory holding .gemrc is unknown")
	}
	user := filepath.Join(e.home, ".gemrc")
	switch _, err := os.Stat(user); {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist):
		configHome, ok := e.lookupEnv("XDG_CONFIG_HOME")
		if !ok {
			configHome = filepath.Join(e.home, ".config")
		}
		user = filepath.Join(configHome, "gem", "gemrc")
		if configHome == "" {
			user = "/gem/gemrc"
		}
	default:
		return nil, err
	}
	return append(files, user), nil
}

// gemSources resolves Gem.sources from the gemrc files without running gem.
// A layer that sets :sources replaces the list of every layer under it, and
// one that sets it to nothing restores the default.
func gemSources(e gemrcEnv) ([]string, error) {
	files, err := gemrcFiles(e)
	if err != nil {
		return nil, err
	}
	var sources *gemrcValue
	var from, spelling string
	for _, path := range files {
		config, err := loadGemrc(path)
		if err != nil {
			return nil, err
		}
		for _, raw := range gemrcSourcesSpellings {
			v, ok := config[raw]
			if !ok {
				continue
			}
			if spelling != "" && spelling != raw {
				return nil, fmt.Errorf("%s sets %s and %s sets %s; which one gem keeps depends on Ruby's hash order", from, spelling, path, raw)
			}
			sources, from, spelling = v, path, raw
		}
	}
	switch {
	case sources == nil,
		sources.isList && len(sources.list) == 0,
		sources.hash != nil && len(sources.hash) == 0,
		!sources.isList && sources.hash == nil && sources.str == "":
		return []string{"https://rubygems.org/"}, nil
	case !sources.isList:
		return nil, fmt.Errorf("%s sets %s to something other than a list", from, spelling)
	}
	for _, s := range sources.list {
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || strings.ContainsAny(s, " \t") {
			return nil, fmt.Errorf("%s lists the source %q, which is not an http or https URL", from, s)
		}
	}
	return sources.list, nil
}
