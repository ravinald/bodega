package clientconf

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/ravinald/bodega/internal/plannedfs"
)

// The functions here answer, for a value that names where a client fetches
// from, what the client itself makes of that value when it comes to use it.
// A config reader accepts any string; the client's own check runs later, at
// the operation, and a value it refuses there is an endpoint nothing is
// fetched from. The plan that installs a CA and the probe that judges one
// both ask here, so neither certifies an endpoint its client rejects.

// NpmRegistry is one registry option of npm's effective configuration.
type NpmRegistry struct {
	// Option is "registry" or "@scope:registry", Value what it holds with
	// each ${NAME} reference resolved, and From the npmrc or the environment
	// variable that set it.
	Option, Value, From string
}

var npmEnvRef = regexp.MustCompile(`\$\{([^}]+)\}`)

// NpmRegistries lists the registries npm fetches from as its effective
// configuration names them: the default registry, which the environment's
// npm_config_registry (NPM_CONFIG_REGISTRY is the same option) gives ahead
// of every npmrc and the last npmrc to set it gives otherwise, and each
// scope's own registry. files are the npmrc files npm loads, lowest priority
// first. A registry named only in an npmrc the environment outranks is not
// one npm asks. Scoped registries set through the environment are not read:
// a variable of unknown name cannot be asked for.
func NpmRegistries(getenv func(string) string, files []string) []NpmRegistry {
	env := func(key string) string {
		if getenv == nil {
			return ""
		}
		return getenv(key)
	}
	var def NpmRegistry
	scoped := map[string]NpmRegistry{}
	var order []string
	for _, f := range files {
		data, err := plannedfs.ReadFile(f)
		if err != nil {
			continue
		}
		for _, o := range NpmOptions(data) {
			v := npmEnvRef.ReplaceAllStringFunc(o.Value, func(ref string) string { return env(ref[2 : len(ref)-1]) })
			switch {
			case o.Key == "registry":
				def = NpmRegistry{Option: o.Key, Value: v, From: f}
			case strings.HasSuffix(o.Key, ":registry"):
				if _, seen := scoped[o.Key]; !seen {
					order = append(order, o.Key)
				}
				scoped[o.Key] = NpmRegistry{Option: o.Key, Value: v, From: f}
			}
		}
	}
	// One option under either spelling. A caller leaves npm unchecked ahead
	// of this where the two disagree.
	if v, _ := NpmEnv(getenv, "registry"); v != "" {
		def = NpmRegistry{Option: "registry", Value: v, From: "the environment's npm_config_registry"}
	}
	var out []NpmRegistry
	if def.Value != "" {
		out = append(out, def)
	}
	for _, key := range order {
		if scoped[key].Value != "" {
			out = append(out, scoped[key])
		}
	}
	return out
}

// NpmRegistryURL is the URL npm fetches a registry value from, or the reason
// it fetches nothing or doctor cannot tell where. npm 11.20.0 accepts any
// string for the option and warns at most; the check is at the request:
// npm-registry-fetch 19.1.1 trims the value, appends the package path and
// hands the result to Node's WHATWG URL parser (lib/index.js, lines 42-48),
// which throws Invalid URL for a value with no scheme, and minipass-fetch
// 5.0.2 refuses a scheme other than http and https (lib/request.js, line
// 169, "Only HTTP(S) protocols are supported").
//
// That parser also accepts spellings net/url reads differently or not at
// all: http:host/path and http:///host/path both reach host, a backslash is
// a slash, and 0x7f.1 is 127.0.0.1. Rather than port it, this takes the one
// form the two parsers agree on, http(s)://[userinfo@]host[:port] followed
// by a path, with the host a DNS name, a dotted-quad IPv4 address or a
// bracketed IPv6 one, and refuses every other http(s) value as one doctor
// does not interpret. Any error leaves npm unchecked and the install refused.
func NpmRegistryURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	scheme, rest, found := strings.Cut(raw, ":")
	if !found || !urlScheme(scheme) {
		return nil, errors.New("is not a URL with a scheme, which npm fails every request on (Invalid URL)")
	}
	if scheme = strings.ToLower(scheme); scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("names the scheme %s, and npm fails every request to a registry that is not http or https (Only HTTP(S) protocols are supported)", scheme)
	}
	unread := errors.New("is not written as http(s)://host[:port]/path, and npm's URL parser sends other spellings somewhere doctor does not work out")
	for i := 0; i < len(raw); i++ {
		if raw[i] <= ' ' || raw[i] > '~' || raw[i] == '\\' {
			return nil, unread
		}
	}
	if !strings.HasPrefix(rest, "//") || strings.HasPrefix(rest, "///") {
		return nil, unread
	}
	authority := rest[2:]
	if i := strings.IndexAny(authority, "/?#"); i >= 0 {
		authority = authority[:i]
	}
	hostport := authority[strings.LastIndex(authority, "@")+1:]
	host, port := hostport, ""
	if strings.HasPrefix(hostport, "[") {
		end := strings.Index(hostport, "]")
		if end < 0 {
			return nil, unread
		}
		if _, err := netip.ParseAddr(hostport[1:end]); err != nil {
			return nil, unread
		}
		port = hostport[end+1:]
		if port != "" && !strings.HasPrefix(port, ":") {
			return nil, unread
		}
		port = strings.TrimPrefix(port, ":")
	} else {
		if i := strings.LastIndex(hostport, ":"); i >= 0 {
			host, port = hostport[:i], hostport[i+1:]
		}
		if host == "" {
			return nil, unread
		}
		for i := 0; i < len(host); i++ {
			c := host[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
				return nil, unread
			}
		}
		// The URL parser reads a host whose last label is a number as an
		// IPv4 address in any of inet_aton's forms. Only the dotted quad is
		// read the same way here.
		labels := strings.Split(strings.TrimSuffix(host, "."), ".")
		if last := labels[len(labels)-1]; last == "" || last[0] >= '0' && last[0] <= '9' {
			if addr, err := netip.ParseAddr(host); err != nil || !addr.Is4() {
				return nil, unread
			}
		}
	}
	if port != "" {
		if n, err := strconv.ParseUint(port, 10, 16); err != nil || strconv.FormatUint(n, 10) != port {
			return nil, unread
		}
	}
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Host, hostport) {
		return nil, unread
	}
	return u, nil
}

// urlScheme reports whether s is a URL scheme: a letter, then letters,
// digits, '+', '-' and '.'.
func urlScheme(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return s != ""
}

// NpmRegistryUnread names the first of regs npm fetches nothing from, or
// fetches from somewhere doctor does not work out, as a phrase a diagnostic
// can carry with any URL password redacted, "" when NpmRegistryURL reads
// every one. A registry that cannot be placed is no evidence that bodega is
// not the registry: the install refuses a host with one, and the probe
// leaves npm unchecked.
func NpmRegistryUnread(regs []NpmRegistry) string {
	for _, r := range regs {
		if _, err := NpmRegistryURL(r.Value); err != nil {
			return fmt.Sprintf("%s=%s from %s, which %v", r.Option, redactURLPassword(strings.TrimSpace(r.Value)), r.From, err)
		}
	}
	return ""
}

// PipCertPath is the bundle a pip cert setting names, as pip reads it: the
// option's type is "path", whose check (_path_option_check in
// pip/_internal/cli/cmdoptions.py at pip 26.2.1, lines 174-175, on the
// option at lines 407-411) is os.path.expanduser and
// nothing else, so a leading ~ is the home directory and no file has to
// exist. sure is false for a value pip resolves from what doctor does not
// have: ~name is another account's home, and a relative path is under the
// directory pip is started in.
func PipCertPath(raw, home string) (path string, sure bool) {
	switch {
	case raw == "~" || strings.HasPrefix(raw, "~/"):
		if home == "" {
			return raw, false
		}
		return home + raw[1:], true
	case strings.HasPrefix(raw, "~"):
		return raw, false
	}
	return raw, strings.HasPrefix(raw, "/")
}
