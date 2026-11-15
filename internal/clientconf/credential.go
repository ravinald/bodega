package clientconf

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

// CredentialBegin and CredentialEnd fence the entry `bodega doctor
// --write-credentials` owns inside a file it shares with the operator. They
// live here rather than beside that writer because a plan applied over one of
// those files has to find the same fence, and the writer already imports this
// package.
//
//nolint:gosec // G101: comment markers around a credential, not one.
const (
	credentialBeginPrefix = "# BEGIN bodega credential"
	CredentialBegin       = credentialBeginPrefix + " — written by bodega doctor --write-credentials"
	CredentialEnd         = "# END bodega credential"
)

// KeepCredential returns planned with bodega's own credential carried over
// from existing, for the two plan files `--write-credentials` also writes:
// ~/.npmrc and helm's repositories.yaml. Every other system gets planned
// unchanged.
//
// The plan replaces a file whole, and its renderings hold no secret, so
// without this an apply after --write-credentials erases the token and every
// request npm or helm makes afterward arrives unattributed, with nothing
// reporting it. What is carried is the entry that writer owns, as it wrote it:
// the fenced block, and on npm a bare //host/npm/:_authToken= line npm's own
// rewrite left unfenced; on helm the repository item named bodega, when it
// carries a password. Placing it after the planned content is what
// --write-credentials does to the planned file, so the two commands converge
// on the same bytes in either order, and a second run of either changes
// nothing. Everything else in existing still goes, as the plan documents.
//
// The served setup script implements the same rule in awk, and a test holds
// the two to identical output.
func KeepCredential(system string, existing, planned []byte) []byte {
	if len(existing) == 0 {
		return planned
	}
	old := splitLines(string(existing))
	var kept, base []string
	switch system {
	case manifest.TypeNpm:
		kept = npmCredential(old)
		base = splitLines(string(planned))
	case manifest.TypeHelm:
		kept = helmCredential(old)
		base = withoutHelmBodega(splitLines(string(planned)))
	default:
		return planned
	}
	if len(kept) == 0 {
		return planned
	}
	return []byte(strings.Join(append(base, kept...), "\n") + "\n")
}

var npmTokenLine = regexp.MustCompile(`^//[^ \t]+/npm/:_authToken=`)

// npmCredential is every complete fenced block in lines, and outside them
// every line holding a token for a bodega npm route.
func npmCredential(lines []string) []string {
	var out []string
	for i := 0; i < len(lines); i++ {
		if isCredentialBegin(lines[i]) {
			j := i + 1
			for j < len(lines) && !isCredentialEnd(lines[j]) {
				j++
			}
			if j < len(lines) {
				out = append(out, lines[i:j+1]...)
				i = j
				continue
			}
		}
		if npmTokenLine.MatchString(strings.TrimSpace(lines[i])) {
			out = append(out, lines[i])
		}
	}
	return out
}

// helmCredential is the first repository item named bodega that carries a
// password, with the fence around it when one is there.
func helmCredential(lines []string) []string {
	for i := 0; i < len(lines); {
		end := yamlItemEnd(lines, i)
		if end == i {
			i++
			continue
		}
		item := lines[i:end]
		if yamlItemField(item, "name") == "bodega" && yamlItemHas(item, "password") {
			if i > 0 && end < len(lines) && isCredentialBegin(lines[i-1]) && isCredentialEnd(lines[end]) {
				return lines[i-1 : end+1]
			}
			return item
		}
		i = end
	}
	return nil
}

// withoutHelmBodega drops every repository item named bodega.
func withoutHelmBodega(lines []string) []string {
	var out []string
	for i := 0; i < len(lines); {
		end := yamlItemEnd(lines, i)
		if end == i {
			out = append(out, lines[i])
			i++
			continue
		}
		if yamlItemField(lines[i:end], "name") != "bodega" {
			out = append(out, lines[i:end]...)
		}
		i = end
	}
	return out
}

// yamlItemEnd returns the index past the sequence item opening at i: every
// following non-blank line indented deeper than its dash. It returns i when
// line i opens no item.
func yamlItemEnd(lines []string, i int) int {
	if !strings.HasPrefix(strings.TrimSpace(lines[i]), "-") {
		return i
	}
	indent := leadingSpaces(lines[i])
	end := i + 1
	for end < len(lines) && strings.TrimSpace(lines[end]) != "" && leadingSpaces(lines[end]) > indent {
		end++
	}
	return end
}

// yamlItemField returns key's unquoted value on the item's dash line or a
// line under it, or "" when the item has none.
func yamlItemField(item []string, key string) string {
	for _, l := range item {
		f := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "-"))
		if v, ok := strings.CutPrefix(f, key+":"); ok {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}

func yamlItemHas(item []string, key string) bool {
	for _, l := range item {
		if strings.HasPrefix(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "-")), key+":") {
			return true
		}
	}
	return false
}

func leadingSpaces(s string) int { return len(s) - len(strings.TrimLeft(s, " ")) }

func isCredentialBegin(l string) bool {
	return strings.HasPrefix(strings.TrimSpace(l), credentialBeginPrefix)
}

func isCredentialEnd(l string) bool {
	return strings.HasPrefix(strings.TrimSpace(l), CredentialEnd)
}

// splitLines splits s into lines, a final newline ending the last line rather
// than opening an empty one.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

// Redacted is what Redact prints in place of a secret.
const Redacted = "<redacted>"

var (
	httpUserinfo = regexp.MustCompile(`(?i)(https?://)[^/?# \t]*@`)
	urlUserinfo  = regexp.MustCompile(`://([^/:@ \t]+):[^/@ \t]+@`)
	authHeader   = regexp.MustCompile(`(?i)(authorization[ \t]*:[ \t]*(?:[a-z][a-z0-9._~+-]*[ \t]+)?)[^ \t].*$`)
	yamlKey      = regexp.MustCompile(`^[ \t]*(-[ \t]+)?([A-Za-z0-9_.-]+)[ \t]*:([ \t]|$)`)
	secretKey    = regexp.MustCompile(`(password|passwd|token|secret|_auth|_key)$|^apikey$`)
	xmlElement   = regexp.MustCompile(`<([A-Za-z_][A-Za-z0-9_.:-]*)>([^<]+)</([A-Za-z_][A-Za-z0-9_.:-]*)>`)
)

// Redact replaces every secret in a configuration file's text with Redacted,
// line by line:
//
//   - the whole userinfo of an http or https URL, user and password, empty
//     or not, up to the last @ before the path. A token can sit in either half
//     (GitHub's https://<token>:x-oauth-basic@ puts it in the user), and
//     telling a token from a username would be a guess whose misses print the
//     secret;
//   - the password of a user:pass@ URL of any other scheme, keeping the user.
//     An ssh:// or scp-style git@host: user is an account name and stays;
//   - everything after an Authorization: header name except the scheme
//     (Bearer, Basic), wherever the header sits in the line, as in git's
//     http.<url>.extraHeader;
//   - the text of an XML element opened and closed on one line, such as
//     settings.xml's <password>, whose name, case folded, ends in password,
//     passwd, passphrase, token, secret, _auth or _key, or is apikey;
//   - the value of a YAML `key: value` or an ini `key = value` whose key, case
//     folded, ends in password, passwd, token, secret, _auth or _key, or is
//     apikey.
//
// A diff is printed to a terminal and often to a CI log, and the file it reads
// may hold a credential bodega did not put there (a pip index URL with
// credentials in it), so the secret never reaches either.
//
// The served setup script redacts with the same rules in awk, and a test runs
// both over one table of lines.
func Redact(text string) string {
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		lines[i] = redactLine(l)
	}
	return strings.Join(lines, "\n")
}

func redactLine(l string) string {
	l = httpUserinfo.ReplaceAllString(l, "${1}"+Redacted+"@")
	l = urlUserinfo.ReplaceAllString(l, "://$1:"+Redacted+"@")
	l = authHeader.ReplaceAllString(l, "${1}"+Redacted)
	l = redactXMLElements(l)
	var head, key, rest string
	if m := yamlKey.FindStringSubmatchIndex(l); m != nil {
		head, key, rest = l[:m[1]], l[m[4]:m[5]], l[m[1]:]
	} else if eq := strings.IndexByte(l, '='); eq >= 0 {
		head, key, rest = l[:eq+1], strings.TrimSpace(l[:eq]), l[eq+1:]
	} else {
		return l
	}
	key = strings.Trim(strings.ToLower(key), `"'`)
	value := strings.TrimLeft(rest, " \t")
	if value == "" || !secretKey.MatchString(key) {
		return l
	}
	return head + rest[:len(rest)-len(value)] + Redacted
}

// redactXMLElements replaces the text of each secret-named element in l.
func redactXMLElements(l string) string {
	var sb strings.Builder
	last := 0
	for _, m := range xmlElement.FindAllStringSubmatchIndex(l, -1) {
		name := strings.ToLower(l[m[2]:m[3]])
		if name != strings.ToLower(l[m[6]:m[7]]) {
			continue
		}
		if !secretKey.MatchString(name) && !strings.HasSuffix(name, "passphrase") {
			continue
		}
		sb.WriteString(l[last:m[4]] + Redacted)
		last = m[5]
	}
	return sb.String() + l[last:]
}

// LocationWithheld stands in for a location whose authority cannot be
// rebuilt as a plain host and port, so no part of its text is printed.
const LocationWithheld = "<location withheld>"

var (
	schemeStart     = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*:`)
	printableEscape = regexp.MustCompile(`\\(?:u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8})|x([0-9A-Fa-f]{2})|(/))`)
	// cleanHost and cleanPort also take the <bodega> and {host} placeholders
	// remediation text writes in place of a real address.
	cleanHost = regexp.MustCompile(`^(?:\[[0-9A-Fa-f:.]+\]|(?:[\p{L}\p{N}._~-]|<[A-Za-z_]+>|\{[A-Za-z_]+\})*)$`)
	cleanPort = regexp.MustCompile(`^(?:[0-9]*|<[A-Za-z_]+>)$`)
)

// specialSchemes are the WHATWG special schemes, which npm's URL parser
// accepts with any run of slashes or backslashes, or none, before the
// authority.
var specialSchemes = map[string]bool{"http": true, "https": true, "ws": true, "wss": true, "ftp": true, "file": true}

// RedactLocations rewrites every location in text, as a diagnostic prints
// it, to scheme://host[:port]/path: userinfo becomes the Redacted marker,
// and query and fragment are dropped whole, so no credential survives whatever encoding a client
// decodes in them (a percent-escaped query key, a JSON-escaped userinfo).
// A line holding escapes for printable characters is read decoded when that
// reveals a location, because npm/ini, YAML, TOML and JSON strings all
// decode \u002f and its kin before the client sees a URL. An authority that
// is not a plain host and port after the userinfo goes prints as
// LocationWithheld. Only diagnostics pass through here; the bytes a client
// reads are never rewritten.
func RedactLocations(text string) string {
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		if d := decodePrintableEscapes(l); d != l && schemeStart.MatchString(d) {
			l = d
		}
		lines[i] = renderLine(l)
	}
	return strings.Join(lines, "\n")
}

// decodePrintableEscapes decodes \uXXXX, \UXXXXXXXX, \xXX and \/ wherever
// the result is printable ASCII other than a quote or backslash, leaving
// every other escape, and so the line's quoting, as it was.
func decodePrintableEscapes(l string) string {
	return printableEscape.ReplaceAllStringFunc(l, func(m string) string {
		if m == `\/` {
			return "/"
		}
		n, err := strconv.ParseUint(m[2:], 16, 32)
		if err != nil || n < 0x21 || n > 0x7e || n == '"' || n == '\'' || n == '\\' {
			return m
		}
		return string(rune(n))
	})
}

func renderLocations(l string) string {
	var sb strings.Builder
	last := 0
	for _, m := range schemeStart.FindAllStringIndex(l, -1) {
		if m[0] < last || (m[0] > 0 && isSchemeChar(l[m[0]-1])) {
			continue
		}
		scheme, after, ok := locationStart(l, m)
		if !ok {
			continue
		}
		token := tokenAt(l, after)
		trimmed := strings.TrimRight(token, `"'),;]>}`+"`")
		sb.WriteString(l[last:m[0]])
		if span := spannedUserinfo(l[after:], len(token)); span > 0 {
			sb.WriteString(LocationWithheld)
			last = after + span
			continue
		}
		sb.WriteString(rebuildLocation(scheme, trimmed, specialSchemes[scheme]))
		sb.WriteString(token[len(trimmed):])
		last = after + len(token)
	}
	return sb.String() + l[last:]
}

// locationStart reports whether the scheme match m in l opens a location,
// and where its authority begins. Any scheme followed by // qualifies. A
// special scheme also qualifies with any run of slashes and backslashes, or
// with none when an @ follows, because npm's WHATWG parser reads
// https:user:pass@host as an authority.
func locationStart(l string, m []int) (scheme string, after int, ok bool) {
	scheme = strings.ToLower(l[m[0] : m[1]-1])
	if !specialSchemes[scheme] {
		return scheme, m[1] + 2, strings.HasPrefix(l[m[1]:], "//")
	}
	after = m[1]
	for after < len(l) && (l[after] == '/' || l[after] == '\\') {
		after++
	}
	if after == m[1] && !strings.Contains(tokenAt(l, after), "@") {
		return scheme, after, false
	}
	return scheme, after, true
}

// spannedUserinfo is how far a userinfo holding whitespace runs into rest,
// the text after scheme://, or 0 when it holds none. WHATWG URL parsing
// percent-encodes a space in userinfo rather than ending the authority
// there, so npm reads https://u p:x@h/ as host h with password x, and an
// @ before the next path, query or fragment delimiter means the authority
// spans the whitespace.
func spannedUserinfo(rest string, token int) int {
	if strings.ContainsAny(rest[:token], "/?#\\") {
		return 0
	}
	end := len(rest)
	if i := strings.IndexAny(rest[token:], "/?#\\"); i >= 0 {
		end = token + i
	}
	if at := strings.LastIndexByte(rest[token:end], '@'); at >= 0 {
		return token + at + 1
	}
	return 0
}

// tokenAt is the run of l from i up to the next whitespace.
func tokenAt(l string, i int) string {
	j := i
	for j < len(l) && l[j] != ' ' && l[j] != '\t' && l[j] != '\r' {
		j++
	}
	return l[i:j]
}

func isSchemeChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '.' || c == '-'
}

// goListSetting matches a Go environment setting whose value the go command
// splits into a list, with the value that follows its =. Only these values
// are split: GOPROXY at commas and pipes (proxyList in
// cmd/go/internal/modfetch/proxy.go), the other four at commas
// (module.MatchPrefixPatterns). Every other location is one URL whatever
// punctuation its path, query or fragment holds, because its client reads
// it as one, and a comma in a pip query split off as a list member would
// print the credential after it.
var goListSetting = regexp.MustCompile(`(?:^|[^A-Za-z0-9_])(GOPROXY|GONOSUMDB|GOPRIVATE|GONOPROXY|GOINSECURE)=["']?([^ \t\r"']*)`)

// renderLine renders every location in l, splitting only the value of a Go
// list setting named in the line.
func renderLine(l string) string {
	var sb strings.Builder
	last := 0
	for _, m := range goListSetting.FindAllStringSubmatchIndex(l, -1) {
		sb.WriteString(renderLocations(l[last:m[4]]))
		sb.WriteString(RenderGoList(l[m[2]:m[3]], l[m[4]:m[5]]))
		last = m[5]
	}
	return sb.String() + renderLocations(l[last:])
}

// RenderGoList renders the value of the Go environment setting name as the
// go command splits it, each member that is a location rebuilt on its own
// and each other member (direct, off, a module path pattern) kept unless it
// carries userinfo, a query or a fragment, when it prints as
// LocationWithheld.
func RenderGoList(name, value string) string {
	seps := ","
	if name == "GOPROXY" {
		seps = ",|"
	}
	var sb strings.Builder
	for value != "" {
		member := value
		sep := ""
		if i := strings.IndexAny(value, seps); i >= 0 {
			member, sep, value = value[:i], value[i:i+1], value[i+1:]
		} else {
			value = ""
		}
		sb.WriteString(renderGoListMember(member))
		sb.WriteString(sep)
	}
	return sb.String()
}

func renderGoListMember(member string) string {
	if m := schemeStart.FindStringIndex(member); m != nil && m[0] == 0 {
		if scheme, after, ok := locationStart(member, m); ok {
			return rebuildLocation(scheme, member[after:], specialSchemes[scheme])
		}
	}
	if strings.ContainsAny(member, "@?#") {
		return LocationWithheld
	}
	return member
}

// rebuildLocation renders the part of a location after scheme:// with its
// userinfo replaced by the Redacted marker and its query and fragment gone. A special scheme ends its authority at
// a backslash as well, as WHATWG URL parsing does.
func rebuildLocation(scheme, rest string, special bool) string {
	stops := "/?#"
	if special {
		stops += "\\"
	}
	cut := len(rest)
	if i := strings.IndexAny(rest, stops); i >= 0 {
		cut = i
	}
	authority, tail := rest[:cut], rest[cut:]
	userinfo := ""
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		authority, userinfo = authority[at+1:], Redacted+"@"
	}
	if i := strings.IndexAny(tail, "?#"); i >= 0 {
		tail = tail[:i]
	}
	// A path holding another authority with userinfo is a list this
	// renderer was not told to split; its second member's credential would
	// print as path text.
	if i := strings.Index(tail, "//"); i >= 0 && strings.Contains(tail[i:], "@") {
		return LocationWithheld
	}
	host, port := authority, ""
	if i := strings.LastIndexByte(authority, ':'); i >= 0 && !strings.HasSuffix(authority, "]") {
		host, port = authority[:i], authority[i:]
		port = port[1:]
	}
	if strings.Contains(host, "%") {
		if h, err := url.PathUnescape(host); err == nil {
			host = h
		}
	}
	if !cleanHost.MatchString(host) || !cleanPort.MatchString(port) {
		return LocationWithheld
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + userinfo + host + tail
}
