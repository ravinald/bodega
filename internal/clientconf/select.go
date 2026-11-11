package clientconf

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

// The functions here answer one question for a client that can take its
// trust from several places: which of them it reads. The plan that installs
// a CA and the probe that judges one both ask here, so a certificate is never
// installed into, or counted from, a place the client passes over.

// PipHost is the host a pip runs on.
type PipHost struct {
	GOOS string
	// Root is the directory pip's absolute paths sit under, "" for the
	// host's own. Home is used as given.
	Root, Home string
	Getenv     func(string) string
	// Prefix is the sys.prefix of the interpreter pip runs under, as pip
	// reports it, "" when it was not asked. VIRTUAL_ENV names it first.
	Prefix string
}

func (h PipHost) env(key string) string {
	if h.Getenv == nil {
		return ""
	}
	return h.Getenv(key)
}

// PipConfigFiles lists the configuration files pip loads, in the order it
// loads them, a later file's option replacing an earlier one's, and how many
// of them lead the list as the global files. They are pip's own
// get_configuration_files: the global files (under each XDG_CONFIG_DIRS entry
// and then /etc, or /Library/Application Support on macOS, which reads
// neither), the per-user files (~/.pip, then the XDG directory, which on macOS
// is ~/Library/Application Support/pip only when that directory exists), the
// interpreter's own sys.prefix/pip.conf, and last the file PIP_CONFIG_FILE
// names. When that file exists pip skips the per-user files, and when it is
// the null device pip loads no file at all.
//
// The prefix is VIRTUAL_ENV, else Prefix, else where the platform's packaged
// Python lives; an interpreter installed anywhere else has a pip.conf beside
// it that only asking pip finds.
func PipConfigFiles(h PipHost) (files []string, global int) {
	explicit := h.env("PIP_CONFIG_FILE")
	if explicit == os.DevNull {
		return nil, 0
	}
	if h.GOOS == OSDarwin {
		files = append(files, filepath.Join(h.Root, "/Library/Application Support/pip/pip.conf"))
	} else {
		dirs := h.env("XDG_CONFIG_DIRS")
		if dirs == "" {
			dirs = "/etc/xdg"
		}
		for _, d := range strings.Split(dirs, ":") {
			if d != "" {
				files = append(files, filepath.Join(h.Root, d, "pip", "pip.conf"))
			}
		}
		files = append(files, filepath.Join(h.Root, "/etc/pip.conf"))
	}
	global = len(files)
	skipUser := false
	if explicit != "" {
		_, err := os.Stat(explicit)
		skipUser = err == nil
	}
	if h.Home != "" && !skipUser {
		user := filepath.Join(h.Home, ".config", "pip")
		mac := filepath.Join(h.Home, "Library", "Application Support", "pip")
		switch info, err := os.Stat(mac); {
		case h.GOOS == OSDarwin && err == nil && info.IsDir():
			user = mac
		case h.GOOS != OSDarwin && h.env("XDG_CONFIG_HOME") != "":
			user = filepath.Join(h.env("XDG_CONFIG_HOME"), "pip")
		}
		files = append(files, filepath.Join(h.Home, ".pip", "pip.conf"), filepath.Join(user, "pip.conf"))
	}
	prefix := h.env("VIRTUAL_ENV")
	if prefix == "" {
		prefix = h.Prefix
	}
	if prefix == "" {
		switch h.GOOS {
		case OSLinux:
			prefix = filepath.Join(h.Root, "/usr")
		case OSFreeBSD:
			prefix = filepath.Join(h.Root, "/usr/local")
		}
	}
	if prefix != "" {
		files = append(files, filepath.Join(prefix, "pip.conf"))
	}
	if explicit != "" {
		files = append(files, explicit)
	}
	return files, global
}

// PodmanCertDir is the directory podman, buildah and CRI-O read CA
// certificates for the registry at hostPort from: the first that exists of
// the per-user certs.d, /etc/containers/certs.d and /etc/docker/certs.d, as
// containers/image picks it. The directories are not combined, so an existing
// one hides every one after it even when it is empty. "" when none exists,
// where those clients read no certificate of their own.
func PodmanCertDir(home, root, hostPort string) string {
	var dirs []string
	if home != "" {
		dirs = append(dirs, filepath.Join(home, ".config", "containers", "certs.d"))
	}
	dirs = append(dirs, filepath.Join(root, "/etc/containers/certs.d"), filepath.Join(root, "/etc/docker/certs.d"))
	for _, d := range dirs {
		full := filepath.Join(d, hostPort)
		if _, err := os.Stat(full); err == nil {
			return full
		}
	}
	return ""
}

// GitConfigFiles lists the configuration files git reads outside a
// repository, in the order it reads them: the system file, unless
// GIT_CONFIG_NOSYSTEM turns it off, then the per-user files, the XDG one
// ahead of ~/.gitconfig. GIT_CONFIG_SYSTEM and GIT_CONFIG_GLOBAL each name a
// file read in place of those. A repository's own config, the entries
// GIT_CONFIG_COUNT carries and files an [include] names are not listed;
// GitUnread reports the last two.
func GitConfigFiles(getenv func(string) string, home, root string) []string {
	env := func(key string) string {
		if getenv == nil {
			return ""
		}
		return getenv(key)
	}
	var files []string
	nosystem := strings.ToLower(env("GIT_CONFIG_NOSYSTEM"))
	switch {
	case nosystem != "" && !slices.Contains([]string{"0", "false", "no", "off"}, nosystem):
	case env("GIT_CONFIG_SYSTEM") != "":
		files = append(files, env("GIT_CONFIG_SYSTEM"))
	default:
		files = append(files, filepath.Join(root, "/etc/gitconfig"))
	}
	switch {
	case env("GIT_CONFIG_GLOBAL") != "":
		files = append(files, env("GIT_CONFIG_GLOBAL"))
	case home != "":
		xdg := env("XDG_CONFIG_HOME")
		if xdg == "" {
			xdg = filepath.Join(home, ".config")
		}
		files = append(files, filepath.Join(xdg, "git", "config"), filepath.Join(home, ".gitconfig"))
	}
	return files
}

// GitCA is one http.sslCAInfo a git configuration file sets.
type GitCA struct {
	// Value is the file it names and File the configuration file setting it.
	Value, File string
	// Header is the section's header as the file writes it, and Pattern the
	// URL it scopes the setting to, "" for a plain [http].
	Header, Pattern string
}

// gitSection is a section header as git reads one: the name, an optional
// quoted subsection, and after the closing bracket nothing but a # or ;
// comment. git also takes a setting on the header's own line and the dotted
// [section.subsection] form; neither is matched, and a file holding one is
// reported by gitCAInfos rather than read past.
var gitSection = regexp.MustCompile(`^\[\s*([A-Za-z0-9-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]\s*(?:[#;].*)?$`)

// gitCAInfos reads every http.sslCAInfo out of a git config body, in order,
// telling settings from continuation lines by the rule the merge edits the
// file with. unread lists each line that opens a section in a form this
// reader does not follow: what it scopes is unknown, so neither an edit nor a
// verdict can be built on the settings under it.
func gitCAInfos(lines []string, file, home string) (out []GitCA, unread []string) {
	scan := lineScan{rules: slashRules, keyIndent: -1}
	var header, pattern string
	inHTTP := false
	for _, l := range lines {
		if scan.continues(l) {
			continue
		}
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") {
			m := gitSection.FindStringSubmatch(t)
			if m == nil {
				unread = append(unread, t)
			}
			inHTTP = m != nil && strings.EqualFold(m[1], "http")
			if inHTTP {
				header, pattern = t, strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(m[2])
			}
			continue
		}
		if !inHTTP || slashRules.key(l) != "sslcainfo" {
			continue
		}
		_, raw, _ := strings.Cut(t, "=")
		v, whole := gitValue(raw)
		if !whole {
			// The value runs on into the next line, which this reader steps
			// over: what git reads there is not what stands on this line.
			unread = append(unread, t)
			continue
		}
		if rest, ok := strings.CutPrefix(v, "~/"); ok && home != "" {
			v = filepath.Join(home, rest)
		}
		out = append(out, GitCA{Value: v, File: file, Header: header, Pattern: pattern})
	}
	return out, unread
}

// gitValue reads the value of a setting from what follows its equals sign,
// as git does: quotes group and are dropped, a backslash escapes the next
// character, and outside quotes a # or ; opens a comment wherever it stands,
// not only after a space. whole is false for a value the line does not end,
// one a trailing backslash or an open quote carries on.
func gitValue(raw string) (value string, whole bool) {
	var sb strings.Builder
	quoted := false
	// kept is the length the value keeps once trailing blanks outside quotes
	// are dropped.
	kept := 0
	raw = strings.TrimLeft(raw, " \t")
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == '\\':
			if i++; i >= len(raw) {
				return "", false
			}
			switch raw[i] {
			case 'n':
				sb.WriteByte('\n')
			case 't':
				sb.WriteByte('\t')
			case 'b':
				sb.WriteByte('\b')
			default:
				sb.WriteByte(raw[i])
			}
			kept = sb.Len()
		case c == '"':
			quoted = !quoted
			kept = sb.Len()
		case !quoted && (c == '#' || c == ';'):
			return sb.String()[:kept], true
		default:
			sb.WriteByte(c)
			if quoted || c != ' ' && c != '\t' {
				kept = sb.Len()
			}
		}
	}
	return sb.String()[:kept], !quoted
}

// gitQuote writes value as a git config file reads it back: bare where git
// takes it whole, and quoted where a # or ; would open a comment or a blank
// at either end would be trimmed.
func gitQuote(value string) string {
	if !strings.ContainsAny(value, "#;\"\\\n\t") && value == strings.TrimSpace(value) {
		return value
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\t", `\t`).Replace(value) + `"`
}

// GitUnread names what in git's configuration this package does not follow,
// each as a phrase a diagnostic can carry: a section header in a form
// gitCAInfos does not read, by file, and the environment variables that hand
// git configuration no file holds. With any of them present, which
// http.sslCAInfo git applies cannot be told from the files.
func GitUnread(getenv func(string) string, files []string) []string {
	var out []string
	for _, key := range []string{"GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"} {
		if getenv != nil && getenv(key) != "" {
			out = append(out, "the environment's "+key+", which hands git settings no file holds")
		}
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if _, unread := gitCAInfos(splitBody(data), f, ""); len(unread) > 0 {
			out = append(out, fmt.Sprintf("the line %s in %s, which opens a section in a form other than [name] or [name \"subsection\"] or carries a value on past the line", unread[0], f))
		}
	}
	return append(out, GitIncludes(files)...)
}

// GitIncludes names each [include] and [includeIf] section the files hold,
// as a phrase a diagnostic can carry. git reads the files such a section
// names where the section stands, so a setting in one can outrank any this
// package reads, and none of them is opened here: a file holding one is
// refused by the install and left unchecked by the probe.
func GitIncludes(files []string) []string {
	var out []string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		scan := lineScan{rules: slashRules, keyIndent: -1}
		for _, l := range splitBody(data) {
			if scan.continues(l) {
				continue
			}
			m := gitSection.FindStringSubmatch(strings.TrimSpace(l))
			if m != nil && (strings.EqualFold(m[1], "include") || strings.EqualFold(m[1], "includeIf")) {
				out = append(out, fmt.Sprintf("the include section %s in %s, which has git read another file there", strings.TrimSpace(l), f))
				break
			}
		}
	}
	return out
}

// NpmOption is one top-level line of an npmrc as npm's ini reader decodes
// it. The decoding is npm/ini 6.0.0's, the reader npm 11 bundles: the name
// and the value are each trimmed, unquoted when quoted and cut at a ; or #
// outside quotes, and name[] is the array form of name. The install's
// preflight, the editor and the trust probe all read an npmrc through this
// one decoder, so no two of them can disagree about what a line says.
type NpmOption struct {
	// Line is the line's number in the file, from 1.
	Line int
	// Key is the option's decoded name, without the [] of an array form.
	Key string
	// Value is the decoded value, "" when Bare.
	Value string
	// Array says the line was written key[], which appends to a list.
	Array bool
	// Bare says the line holds no =, which npm reads as true.
	Bare bool
	// Unsure says why the line's name is not decoded with certainty, "" when
	// it is. Such a line could name any option, a CA or registry included.
	Unsure string
	// ValueUnsure says the same of the value alone.
	ValueUnsure string

	section bool
}

// isJSSpace is the whitespace JavaScript's String.prototype.trim and \s
// strip, which differs from unicode.IsSpace at U+FEFF and U+0085.
func isJSSpace(r rune) bool {
	return strings.ContainsRune("\t\n\v\f\r \u00a0\ufeff\u2028\u2029", r) || unicode.Is(unicode.Zs, r)
}

// npmUnsafe is npm/ini's unsafe(): the text a name or value decodes to. sure
// is false where JSON.parse would give something this port does not
// reproduce: a quoted number, list or object, or a lone surrogate escape.
func npmUnsafe(val string) (out string, sure bool) {
	val = strings.TrimFunc(val, isJSSpace)
	quoted := func(q string) bool { return strings.HasPrefix(val, q) && strings.HasSuffix(val, q) }
	if !quoted(`"`) && !quoted("'") {
		var b strings.Builder
		esc := false
	walk:
		for _, c := range val {
			switch {
			case esc:
				if !strings.ContainsRune(`\;#`, c) {
					b.WriteByte('\\')
				}
				b.WriteRune(c)
				esc = false
			case c == ';' || c == '#':
				break walk
			case c == '\\':
				esc = true
			default:
				b.WriteRune(c)
			}
		}
		if esc {
			b.WriteByte('\\')
		}
		return strings.TrimFunc(b.String(), isJSSpace), true
	}
	if val[0] == '\'' {
		// A lone quote is its own opening and closing quote.
		val = val[min(1, len(val)-1) : len(val)-1]
	}
	var parsed any
	if err := json.Unmarshal([]byte(val), &parsed); err != nil {
		return val, true
	}
	text, isString := parsed.(string)
	if !isString || strings.ContainsRune(text, unicode.ReplacementChar) {
		return val, false
	}
	return text, true
}

var npmSection = regexp.MustCompile(`^\[[^\]]*\]\s*$`)

// npmDecodeLine decodes one line of an npmrc, without its line ending. ok is
// false for a line npm's reader skips: a blank, a comment, one with nothing
// before its =.
func npmDecodeLine(line string) (o NpmOption, ok bool) {
	t := strings.TrimFunc(line, isJSSpace)
	if t == "" || t[0] == ';' || t[0] == '#' {
		return o, false
	}
	switch {
	case npmSection.MatchString(line):
		return NpmOption{section: true}, true
	case t[0] == '[':
		return NpmOption{Unsure: "opens with [ and is not a section header alone at the start of its line, so npm reads it as an option where a section reader sees a header"}, true
	case strings.ContainsAny(line, "\r\u2028\u2029"):
		return NpmOption{Unsure: "holds a line separator inside it, where npm's reader splits or drops the line"}, true
	}
	rawKey, rawValue, assigned := strings.Cut(line, "=")
	if rawKey == "" {
		return o, false
	}
	key, sure := npmUnsafe(rawKey)
	if o.Array = len(key) > 2 && strings.HasSuffix(key, "[]"); o.Array {
		key = strings.TrimSuffix(key, "[]")
	}
	switch {
	case !sure:
		return NpmOption{Unsure: "quotes its option name around something other than a plain string"}, true
	case strings.Contains(key, "${"):
		return NpmOption{Unsure: "takes part of its option name from a ${NAME} reference, which npm resolves from the environment"}, true
	case key == "__proto__":
		return o, false
	}
	o.Key, o.Bare = key, !assigned
	if assigned {
		if o.Value, sure = npmUnsafe(rawValue); !sure {
			o.ValueUnsure = "quotes its value around something other than a plain string"
		}
	}
	return o, true
}

// NpmOptions decodes the top-level options of the npmrc in data, in order,
// stopping at the first section header: npm reads the lines under one as a
// nested object and takes no option from them.
func NpmOptions(data []byte) []NpmOption {
	var out []NpmOption
	for i, line := range strings.Split(string(data), "\n") {
		o, ok := npmDecodeLine(strings.TrimRight(line, "\r"))
		if !ok {
			continue
		}
		if o.section {
			break
		}
		o.Line = i + 1
		out = append(out, o)
	}
	return out
}

// npmKey is the option a line of an npmrc sets, "" for a line that sets none
// or whose name is not decoded with certainty.
func npmKey(line string) string {
	o, ok := npmDecodeLine(strings.TrimRight(line, "\r"))
	if !ok || o.section {
		return ""
	}
	return o.Key
}

func npmFileOptions(path string) []NpmOption {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return NpmOptions(data)
}

// NpmInlineCA returns the first top-level ca or ca[] the npmrc at path
// assigns, "" when it assigns neither or cannot be read. npm keeps one CA
// list that ca and cafile both replace, in the order a file sets them, so a
// file holding either key beside cafile does not read the cafile alone.
func NpmInlineCA(path string) string {
	for _, o := range npmFileOptions(path) {
		switch {
		case o.Key == "ca" && o.Array:
			return "ca[]"
		case o.Key == "ca":
			return "ca"
		}
	}
	return ""
}

// NpmConfigFiles lists the npmrc files npm loads on this host, lowest
// priority first: the global one under root and the per-user one in home,
// each replaced by the file the environment names in its place, which npm
// then reads instead. A project's own .npmrc is not listed.
func NpmConfigFiles(getenv func(string) string, goos, home, root string) []string {
	env := func(key string) string {
		if getenv == nil {
			return ""
		}
		if v := getenv("npm_config_" + key); v != "" {
			return v
		}
		return getenv("NPM_CONFIG_" + strings.ToUpper(key))
	}
	files := []string{filepath.Join(root, "/etc/npmrc")}
	if goos == OSFreeBSD {
		files = append(files, filepath.Join(root, "/usr/local/etc/npmrc"))
	}
	if v := env("globalconfig"); v != "" {
		files = []string{v}
	}
	switch v := env("userconfig"); {
	case v != "":
		files = append(files, v)
	case home != "":
		files = append(files, filepath.Join(home, ".npmrc"))
	}
	return files
}

// NpmUnclassified names the first line of the npmrc at path that cannot be
// told apart from a registry or CA option, or that sets a registry in a form
// this package does not read, as a phrase a diagnostic can carry; "" when
// there is none or the file cannot be read. The phrase names the file, the
// line number and the option name where one decoded, never the value, which
// may be a credential. Which registry npm asks is unknown with such a line
// present, so the install refuses the host and the probe leaves npm
// unchecked before either decides npm does not reach bodega.
func NpmUnclassified(path string) string {
	for _, o := range npmFileOptions(path) {
		why := o.Unsure
		registry := o.Key == "registry" || strings.HasSuffix(o.Key, ":registry")
		switch {
		case why != "":
		case !registry:
			continue
		case o.Array:
			why = "sets " + o.Key + " in its list form, " + o.Key + "[]"
		case o.Bare:
			why = "names " + o.Key + " with no value"
		case o.ValueUnsure != "":
			why = "sets " + o.Key + " and " + o.ValueUnsure
		default:
			continue
		}
		return fmt.Sprintf("line %d of %s, which %s", o.Line, path, why)
	}
	return ""
}

// NpmUnread names what the npmrc at path holds that this package detects and
// does not interpret, as a phrase a diagnostic can carry, "" when it holds
// nothing of the kind or cannot be read: a line NpmUnclassified names, a ca
// or ca[] beside cafile, which replace one CA list in the order the file sets
// them, and a ca or cafile written with no value, as a list, with a ${NAME}
// reference or quoted around something other than a string. The install
// refuses a host with one in any npmrc npm loads, and the probe leaves npm
// unchecked.
func NpmUnread(path string) string {
	if unclassified := NpmUnclassified(path); unclassified != "" {
		return unclassified
	}
	inline, cafile := "", false
	for _, o := range npmFileOptions(path) {
		if o.Key != "ca" && o.Key != "cafile" {
			continue
		}
		why := o.ValueUnsure
		switch {
		case o.Bare:
			why = "gives it no value"
		case o.Key == "cafile" && o.Array:
			why = "writes it as a list, cafile[]"
		case strings.Contains(o.Value, "${"):
			why = "takes its value from a ${NAME} reference, which npm resolves from the environment"
		}
		if why != "" {
			return fmt.Sprintf("line %d of %s, which sets %s and %s", o.Line, path, o.Key, why)
		}
		if o.Key == "cafile" {
			cafile = true
		} else if inline == "" {
			if inline = "ca"; o.Array {
				inline = "ca[]"
			}
		}
	}
	if cafile && inline != "" {
		return fmt.Sprintf("%s beside cafile in %s, which replace npm's one CA list in the order the file sets them", inline, path)
	}
	return ""
}

// gitURL is a URL as git's urlmatch compares one: scheme and host lowercased,
// the scheme's default port dropped, and a path ending in a slash.
type gitURL struct {
	scheme, host, port, user, path string
}

func parseGitURL(s string) (gitURL, bool) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return gitURL{}, false
	}
	g := gitURL{scheme: strings.ToLower(u.Scheme), host: strings.ToLower(u.Hostname()), port: u.Port(), user: u.User.String()}
	if g.port == "443" && g.scheme == "https" || g.port == "80" && g.scheme == "http" {
		g.port = ""
	}
	g.path = strings.TrimRight(u.Path, "/") + "/"
	return g, true
}

// hostMatch reports whether pattern names host, a * standing for one label,
// and whether it does so without one.
func (g gitURL) hostMatch(pattern string) (match, exact bool) {
	if pattern == g.host {
		return true, true
	}
	want, have := strings.Split(pattern, "."), strings.Split(g.host, ".")
	if len(want) != len(have) {
		return false, false
	}
	for i := range want {
		if want[i] != "*" && want[i] != have[i] {
			return false, false
		}
	}
	return true, false
}

// under reports whether pattern scopes a setting to URLs at or below g on
// g's own host: the sections that outrank or tie with one scoped to g for
// some URL below it.
func (g gitURL) under(pattern string) bool {
	p, ok := parseGitURL(pattern)
	return ok && p.scheme == g.scheme && p.host == g.host && p.port == g.port && strings.HasPrefix(p.path, g.path)
}

// GitCAInfo resolves which http.sslCAInfo git applies to URLs under base, from
// the files in the order git reads them. own is the setting git picks for
// base itself, by urlmatch's rule: an exact host outranks a wildcard, then
// the longer path wins, a scoped section outranks a plain [http], and between
// equals the later one stands. Nil means git verifies base against its
// default store. narrower holds each setting scoped more tightly than base,
// to a path below it or to one user, which git reads in own's place for the
// URLs it covers.
func GitCAInfo(files []string, base, home string) (own *GitCA, narrower []GitCA) {
	b, ok := parseGitURL(base)
	if !ok {
		return nil, nil
	}
	ownRank := [3]int{-1}
	byPattern := map[string]GitCA{}
	var order []string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		cas, _ := gitCAInfos(splitBody(data), f, home)
		for _, ca := range cas {
			rank := [3]int{}
			if ca.Pattern != "" {
				p, ok := parseGitURL(ca.Pattern)
				if !ok || p.scheme != b.scheme || p.port != b.port {
					continue
				}
				match, exact := b.hostMatch(p.host)
				if !match {
					continue
				}
				if exact && b.under(ca.Pattern) && (p.user != "" || len(p.path) > len(b.path)) {
					if _, seen := byPattern[ca.Pattern]; !seen {
						order = append(order, ca.Pattern)
					}
					byPattern[ca.Pattern] = ca
					continue
				}
				if p.user != "" || !strings.HasPrefix(b.path, p.path) {
					continue
				}
				rank = [3]int{1, 0, len(p.path)}
				if exact {
					rank[1] = 1
				}
			}
			if slices.Compare(rank[:], ownRank[:]) >= 0 {
				ownRank, own = rank, &ca
			}
		}
	}
	for _, p := range order {
		narrower = append(narrower, byPattern[p])
	}
	return own, narrower
}

// gitShadowHeaders lists the headers of the [http "<url>"] sections of a git
// config body that set sslCAInfo for URLs at or below base: each is read in
// place of, or on equal terms with, the section a plan scopes to base.
func gitShadowHeaders(lines []string, base string) []string {
	b, ok := parseGitURL(base)
	if !ok {
		return nil
	}
	var out []string
	cas, _ := gitCAInfos(lines, "", "")
	for _, ca := range cas {
		if ca.Pattern != "" && b.under(ca.Pattern) && !slices.Contains(out, ca.Header) {
			out = append(out, ca.Header)
		}
	}
	return out
}
