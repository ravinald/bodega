package clientconf

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// npmType is the type npm 11.20.0 declares an option with
// (@npmcli/config 10.13.0, lib/definitions/definitions.js), for the options
// some value can fail: one declared with String or Boolean among its types
// takes any value, and is not here.
type npmType struct {
	// kind is the type definition nopt validates against.
	kind npmKind
	// null and no say the declaration lists null and false, and words the
	// strings it lists.
	null, no bool
	words    []string
	// list says it lists Array: the value is split on blank lines and each
	// part validated.
	list bool
}

type npmKind uint8

const (
	// npmWords is a declaration of listed values alone.
	npmWords npmKind = iota
	npmNumber
	npmPath
	npmURL
	npmUmask
	// npmSemver, npmDate and npmAddress are validated by semver.valid,
	// Date.parse and against this host's network interfaces, none of which
	// this port carries whole.
	npmSemver
	npmDate
	npmAddress
)

// npmDefined holds every option npm 11.20.0 defines, as npm config ls -l
// lists them (@npmcli/config 10.13.0, lib/definitions/definitions.js). npm
// reads a value for each of these names and for no other, the credentials of
// npmUnscopedAuth and the scoped registries aside, so an object npm/ini
// builds on one of them is an object where npm expects a value.
var npmDefined = func() map[string]bool {
	out := map[string]bool{}
	for _, name := range strings.Fields(`
		access all allow-directory allow-file allow-git allow-remote allow-same-version allow-scripts
		allow-scripts-pending allow-scripts-pin also audit audit-level auth-type before bin-links
		browser bypass-2fa ca cache cache-max cache-min cafile call cert cidr color commit-hooks cpu
		dangerously-allow-all-scripts depth description dev diff diff-dst-prefix diff-ignore-all-space
		diff-name-only diff-no-prefix diff-src-prefix diff-text diff-unified dry-run editor
		engine-strict expect-result-count expect-results expires fetch-retries fetch-retry-factor
		fetch-retry-maxtimeout fetch-retry-mintimeout fetch-timeout force foreground-scripts
		format-package-lock fund git git-tag-version global global-style globalconfig heading
		https-proxy if-present ignore-scripts include include-attestations include-staged
		include-workspace-root init-author-email init-author-name init-author-url init-license
		init-module init-private init-type init-version init.author.email init.author.name
		init.author.url init.license init.module init.version install-links install-strategy json key
		legacy-bundling legacy-peer-deps libc link local-address location lockfile-version loglevel
		logs-dir logs-max long maxsockets message min-release-age min-release-age-exclude name node-gyp
		node-options noproxy npm-version offline omit omit-lockfile-registry-resolved only optional orgs
		orgs-permission os otp pack-destination package package-lock package-lock-only packages
		packages-all packages-and-scopes-permission parseable prefer-dedupe prefer-offline prefer-online
		prefix preid production progress provenance provenance-file proxy read-only rebuild-bundle
		registry replace-registry-host save save-bundle save-dev save-exact save-optional save-peer
		save-prefix save-prod sbom-format sbom-type scope scopes script-shell searchexclude searchlimit
		searchopts searchstaleness shell shrinkwrap sign-git-commit sign-git-tag strict-allow-scripts
		strict-peer-deps strict-ssl tag tag-version-prefix timing token-description umask unicode
		update-notifier usage user-agent userconfig version versions viewer which workspace workspaces
		workspaces-update yes
	`) {
		out[name] = true
	}
	return out
}()

// npmTypes is generated from that file's definitions. registry is left to
// NpmRegistryURL, which reads it as the request does, and cafile to NpmUnread,
// which also knows the empty one npm stops on.
var npmTypes = func() map[string]npmType {
	out := map[string]npmType{}
	words := func(null bool, list bool, keys string, values ...string) {
		for _, k := range strings.Fields(keys) {
			out[k] = npmType{kind: npmWords, null: null, list: list, words: values}
		}
	}
	kind := func(k npmKind, null bool, keys string) {
		for _, key := range strings.Fields(keys) {
			out[key] = npmType{kind: k, null: null}
		}
	}
	words(true, false, "access", "restricted", "public", "private")
	words(false, false, "allow-directory allow-file allow-git allow-remote", "all", "none", "root")
	words(true, false, "also", "dev", "development")
	words(true, false, "audit-level", "info", "low", "moderate", "high", "critical", "none")
	words(false, false, "auth-type", "legacy", "web")
	words(false, true, "include", "prod", "dev", "optional", "peer")
	words(false, false, "install-strategy", "hoisted", "nested", "shallow", "linked")
	words(false, false, "location", "global", "user", "project")
	words(true, false, "lockfile-version", "1", "2", "3")
	words(false, false, "loglevel", "silent", "error", "warn", "notice", "http", "info", "verbose", "silly")
	words(false, true, "omit", "dev", "optional", "peer")
	words(true, false, "only", "prod", "production")
	words(true, false, "orgs-permission", "read-only", "read-write", "no-access")
	words(true, false, "packages-and-scopes-permission", "read-only", "read-write", "read-write-stage-only", "no-access")
	words(false, false, "sbom-format", "cyclonedx", "spdx")
	words(false, false, "sbom-type", "library", "application", "framework")
	kind(npmNumber, false, "cache-max cache-min diff-unified fetch-retries fetch-retry-factor fetch-retry-maxtimeout fetch-retry-mintimeout fetch-timeout logs-max maxsockets searchlimit searchstaleness")
	kind(npmNumber, true, "depth expect-result-count expires min-release-age which")
	kind(npmPath, false, "cache globalconfig init-module init.module node-gyp prefix provenance-file userconfig")
	kind(npmPath, true, "logs-dir")
	kind(npmURL, true, "https-proxy")
	out["proxy"] = npmType{kind: npmURL, null: true, no: true}
	out["init-author-url"] = npmType{kind: npmURL, words: []string{""}}
	out["init.author.url"] = npmType{kind: npmURL, words: []string{""}}
	kind(npmUmask, false, "umask")
	kind(npmSemver, false, "init-version init.version")
	kind(npmDate, true, "before")
	kind(npmAddress, true, "local-address")
	return out
}()

// jsValue is a configuration value as npm holds it: one of JavaScript's
// true, false, null and undefined, or a string.
type jsValue struct {
	word string
	str  bool
}

var jsTrue, jsFalse, jsNull, jsUndefined = jsValue{word: "true"}, jsValue{word: "false"}, jsValue{word: "null"}, jsValue{word: "undefined"}

func jsTrim(s string) string { return strings.TrimFunc(s, isJSSpace) }

var (
	jsDecimal = regexp.MustCompile(`^[+-]?(Infinity|[0-9]+\.?[0-9]*([eE][+-]?[0-9]+)?|\.[0-9]+([eE][+-]?[0-9]+)?)$`)
	jsRadix   = regexp.MustCompile(`^0([xX][0-9a-fA-F]+|[oO][0-7]+|[bB][01]+)$`)
	// npmUmaskOctal and npmUmaskDecimal are the two forms parse in
	// @npmcli/config's lib/umask.js reads a string as.
	npmUmaskOctal   = regexp.MustCompile(`^0o?[0-7]+$`)
	npmUmaskDecimal = regexp.MustCompile(`^[1-9][0-9]*$`)
	npmPlainSemver  = regexp.MustCompile(`^(0|[1-9][0-9]{0,14})\.(0|[1-9][0-9]{0,14})\.(0|[1-9][0-9]{0,14})$`)
	// npmHostedURL is a URL Node's url.parse finds a host in whatever the
	// scheme: scheme://[userinfo@]host[:port], then nothing or a path.
	npmHostedURL = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://([^\s/?#@\\]*@)?([a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?|\[[0-9a-fA-F:.]+\])(:[0-9]{1,5})?([/?#][^\s\\]*)?$`)
)

// jsIsNaN is JavaScript's isNaN on a string: whether ToNumber makes no
// number of it. The empty string is 0.
func jsIsNaN(s string) bool {
	s = jsTrim(s)
	return s != "" && !jsDecimal.MatchString(s) && !jsRadix.MatchString(s)
}

// refuses reports whether npm warns "invalid config" for an option of this
// type holding v, and keeps the value as written for whatever reads the
// option next, or, with unread, whether this port cannot tell. It follows the
// value through parseField (lib/parse-field.js) and nopt 9.0.0's clean and
// validate (lib/nopt-lib.js, lines 61-178 and 180-254) with the type
// definitions in lib/type-defs.js of both packages. A value from a file
// arrives with its true, false and null already decoded by npm/ini; one from
// the environment arrives as the text it was set to.
func (t npmType) refuses(v jsValue) (invalid, unread bool) {
	if v.str {
		v.word = jsTrim(v.word)
		// parseField decodes the four words for a type that is none of
		// String, path and Number; clean decodes null where the type lists
		// it, and false where it lists false.
		switch decodes := t.kind != npmNumber && t.kind != npmPath; {
		case v.word == "null" && (decodes || t.null):
			v = jsNull
		case v.word == "false" && (decodes || t.no):
			v = jsFalse
		case v.word == "true" && decodes:
			v = jsTrue
		case v.word == "undefined" && decodes:
			v = jsUndefined
		}
	}
	// clean turns false into null for a type that lists null and not false.
	if v == jsFalse && t.null && !t.no {
		v = jsNull
	}
	if v == jsNull && t.null || v == jsFalse && t.no {
		return false, false
	}
	switch t.kind {
	case npmWords:
		return !v.str || !slices.Contains(t.words, v.word), false
	case npmNumber:
		// isNaN(true), isNaN(false) and isNaN(null) are all false.
		return v == jsUndefined || v.str && jsIsNaN(v.word), false
	case npmPath:
		return !v.str, false
	case npmURL:
		if !v.str {
			return true, false
		}
		if slices.Contains(t.words, v.word) {
			return false, false
		}
		return false, !npmHostedURL.MatchString(v.word)
	case npmUmask:
		if !v.str {
			return true, false
		}
		base := 0
		switch {
		case npmUmaskOctal.MatchString(v.word):
			base = 8
		case npmUmaskDecimal.MatchString(v.word):
			base = 10
		default:
			return true, false
		}
		n, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimPrefix(v.word, "0"), "o"), base, 32)
		return err != nil || n > 511, false
	case npmSemver:
		return false, !v.str || !npmPlainSemver.MatchString(v.word)
	}
	return false, true
}

// check is refuses for a value of the option, split as parseField splits a
// list type's.
func (t npmType) check(v jsValue) (invalid, unread bool) {
	// A list option set to a bare false or null is no list, and no warning.
	if t.list && (v == jsFalse || v == jsNull) {
		return false, false
	}
	if !t.list || !v.str {
		return t.refuses(v)
	}
	for _, part := range strings.Split(jsTrim(v.word), "\n\n") {
		if invalid, unread = t.refuses(jsValue{word: part, str: true}); invalid || unread {
			return invalid, unread
		}
	}
	return false, false
}

// npmUnscopedAuth are the credentials Config.validate (@npmcli/config
// 10.13.0, lib/index.js, lines 398-429) refuses outside a registry's own
// //host/: scope in a global, user or project npmrc: it throws
// ErrInvalidAuth, and every npm command that validates its configuration
// exits on that before any request.
var npmUnscopedAuth = []string{"_authtoken", "-authtoken", "_auth", "_authToken", "username", "_password"}

func npmWhy(key string, invalid bool) string {
	if invalid {
		return "sets " + key + " to a value npm reports as invalid config and still hands, as written, to whatever reads the option next"
	}
	return "sets " + key + " to a value npm validates in a way doctor does not interpret"
}

// NpmStartError names what the npmrc at path holds that stops npm before a
// request or leaves it running on a value it has itself reported invalid, as
// a phrase a diagnostic can carry, "" when it holds neither or cannot be
// read: an unscoped credential npm exits on with ERR_INVALID_AUTH, and an
// option whose value fails the type npm declares it with. npm warns about the
// second and keeps the value as written, so fetch-timeout=abc reaches the
// request and fails it there. The phrase names the file, the line and the
// option, never the value.
//
// The last line setting an option is the one npm keeps, as npm/ini keeps it.
func NpmStartError(path string) string {
	last := map[string]NpmOption{}
	var order []string
	for _, o := range npmFileOptions(path) {
		if o.Unsure != "" {
			continue
		}
		if _, seen := last[o.Key]; !seen {
			order = append(order, o.Key)
		}
		last[o.Key] = o
	}
	for _, key := range order {
		o := last[key]
		at := fmt.Sprintf("line %d of %s, which ", o.Line, path)
		// npm/ini has already decoded a file's true, false and null.
		v := jsValue{word: o.Value, str: true}
		switch {
		case o.Bare:
			v = jsTrue
		case o.Value == "true" || o.Value == "false" || o.Value == "null":
			v = jsValue{word: o.Value}
		}
		if slices.Contains(npmUnscopedAuth, key) {
			// Config.get's value is truthy: a list always is, and _auth is
			// a String, whose false clean has turned to null.
			falsy := v == jsFalse || v == jsNull || v.str && (v.word == "" || key != "_auth" && v.word == "undefined")
			if o.Array || !falsy {
				return at + "sets " + key + " outside a registry's own //host/: scope, which npm exits on with ERR_INVALID_AUTH before any request"
			}
			continue
		}
		t, typed := npmTypes[key]
		switch {
		// npm/ini takes a dotted name set to null for a section, not an
		// option.
		case !typed, v == jsNull && strings.Contains(key, "."):
			continue
		case o.Array && !t.list, o.ValueUnsure != "", strings.Contains(o.Value, "${"):
			return at + npmWhy(key, false)
		}
		if invalid, unread := t.check(v); invalid || unread {
			return at + npmWhy(key, invalid)
		}
	}
	return ""
}

// NpmEnvInvalid is NpmStartError's type check for the options the
// environment sets as npm_config_<name>, in either case: loadEnv
// (lib/index.js, lines 343-357) skips an empty one and hands the rest to
// parseField as text. The environment holds no credential ErrInvalidAuth
// looks for: validate reads those from the three npmrc files alone.
func NpmEnvInvalid(getenv func(string) string) string {
	if getenv == nil {
		return ""
	}
	keys := make([]string, 0, len(npmTypes))
	for key := range npmTypes {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		name := "npm_config_" + strings.ReplaceAll(key, "-", "_")
		for _, name := range []string{name, strings.ToUpper(name)} {
			val := getenv(name)
			if val == "" {
				continue
			}
			if strings.Contains(val, "${") {
				return "the environment's " + name + ", which " + npmWhy(key, false)
			}
			if invalid, unread := npmTypes[key].check(jsValue{word: val, str: true}); invalid || unread {
				return "the environment's " + name + ", which " + npmWhy(key, invalid)
			}
		}
	}
	return ""
}

// npmExclusive are the options npm 11.20.0 declares exclusive of one another
// (the exclusive lists in @npmcli/config's lib/definitions/definitions.js),
// each group holding every option of one such set.
var npmExclusive = [][]string{
	{"expect-result-count", "expect-results"},
	{"provenance", "provenance-file"},
	{"save-dev", "save-optional", "save-peer", "save-prod"},
}

// NpmExclusive names the first two options of one exclusive set that npm's
// configuration assigns together, as a phrase a diagnostic can carry, "" for
// none. Each is valid alone. Config's loader (@npmcli/config 10.13.0,
// lib/index.js, lines 587-603) throws as it meets the second, in whichever
// file or variable and whatever either is set to, false included, since it
// asks only whether the other was assigned ("--save-prod cannot be provided
// when using --save-dev"), and every npm command exits on that before it
// reads a registry. The environment's options are npm_config_<name> in
// either case, an empty one being no assignment.
func NpmExclusive(getenv func(string) string, files []string) string {
	from := map[string]string{}
	seen := map[string]bool{}
	for _, f := range files {
		if seen[f] {
			continue
		}
		seen[f] = true
		for _, o := range npmFileOptions(f) {
			if _, set := from[o.Key]; o.Key != "" && o.Unsure == "" && !set {
				from[o.Key] = fmt.Sprintf("line %d of %s", o.Line, f)
			}
		}
	}
	for _, set := range npmExclusive {
		var held []string
		for _, key := range set {
			name := "npm_config_" + strings.ReplaceAll(key, "-", "_")
			for _, name := range []string{name, strings.ToUpper(name)} {
				if _, inFile := from[key]; !inFile && getenv != nil && getenv(name) != "" {
					from[key] = "the environment's " + name
				}
			}
			if _, ok := from[key]; ok {
				held = append(held, key)
			}
		}
		if len(held) > 1 {
			return fmt.Sprintf("%s, which sets %s, beside %s, which sets %s: npm takes one of the two and exits on the pair before any request (--%s cannot be provided when using --%s)", from[held[0]], held[0], from[held[1]], held[1], held[1], held[0])
		}
	}
	return ""
}
