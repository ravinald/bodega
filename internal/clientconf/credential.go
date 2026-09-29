package clientconf

import (
	"regexp"
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
