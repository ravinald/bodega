package clientconf

import (
	"cmp"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"sigs.k8s.io/yaml"
)

// A CA is certified for a client only under configuration whose effect on
// that client's startup and TLS handshake this package follows end to end.
// Each reader keeps one list of the settings it follows, below. Any other
// setting its documented files hold, set to other than the client's pinned
// default, is named by that reader's Uncertified function, and so is every
// setting that turns peer verification off: the CA install refuses before
// any write, and the trust probe leaves the client unchecked. Nothing here is
// a load error, so a configure that installs no CA is not judged by it.
//
// Git's list is gitHTTPModeled, containerd's containerdModeled and
// dockerd's dockerStartDefaults, each beside its reader.

// ModeledSetting is one setting a reader certifies a client under.
type ModeledSetting struct {
	Name string
	// Fails is how the client itself refuses a bad value, and which function
	// here carries that refusal, or why no value fails.
	Fails string
}

// Uncertified is the next step every refusal built on these lists carries.
const uncertifiedNextStep = "Remove the setting or return it to the client's default, or leave it and add the CA to that client's trust by hand as docs/usage.md describes under --ca-file"

func bodegaPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "http" {
		return "80"
	}
	return "443"
}

// namesBodega reports whether word, a host, host:port or URL as a client's
// bypass list writes one, covers bodega at u. A word naming no port covers
// every port of its host.
func namesBodega(word string, u *url.URL) bool {
	if i := strings.Index(word, "://"); i >= 0 {
		word = word[i+3:]
	}
	word, _, _ = strings.Cut(word, "/")
	if at := strings.LastIndex(word, "@"); at >= 0 {
		word = word[at+1:]
	}
	host, port := word, ""
	if h, p, err := net.SplitHostPort(word); err == nil {
		host, port = h, p
	}
	host = strings.Trim(host, "[]")
	if !strings.EqualFold(host, u.Hostname()) {
		return false
	}
	if port == "" {
		return true
	}
	// Clients parse the port as a number, so 08443 is 8443.
	n, err := strconv.Atoi(port)
	want, _ := strconv.Atoi(bodegaPort(u))
	return err == nil && n == want
}

// NamesBodega is namesBodega for the report path, which judges the same
// spellings of bodega's endpoint the install path refuses.
func NamesBodega(word string, u *url.URL) bool { return namesBodega(word, u) }

// NpmModeled is the npm options doctor certifies npm under at any value npm
// accepts. Every other option npm 11.20.0 defines must sit at npmDefaults.
// A name npm does not define is one it reads no value from, and the
// registry-scoped credentials (//host/:_authToken, :_auth, :username,
// :_password) authenticate a request after the handshake.
var NpmModeled = []ModeledSetting{
	{"registry", "NpmRegistryUnread: a value the request refuses or sends elsewhere"},
	{"@scope:registry", "NpmRegistryUnread, as registry"},
	{"cafile", "NpmUnread: an empty or list value npm stops on; a file that does not read leaves the CA list as it was, which the probe follows"},
	{"ca", "NpmUnread and NpmCAOf: a boolean, or null inside a list"},
	{"fund", "none: declared Boolean, and nopt takes any value for one"},
	{"audit", "none: declared Boolean"},
	{"save-exact", "none: declared Boolean"},
	{"progress", "none: declared Boolean"},
	{"loglevel", "NpmStartError: a word outside npm's eight levels"},
	{"fetch-retries", "NpmStartError: not a number"},
	{"fetch-retry-factor", "NpmStartError: not a number"},
	{"fetch-retry-mintimeout", "NpmStartError: not a number"},
	{"fetch-retry-maxtimeout", "NpmStartError: not a number"},
	{"fetch-timeout", "NpmStartError: not a number"},
}

// npmDefaults is the default npm 11.20.0 gives each option whose default is
// a boolean, a number, null or the empty string (@npmcli/config 10.13.0,
// lib/definitions/definitions.js), as an npmrc writes it. An option defined
// with any other default has none recorded, and is refused when set.
var npmDefaults = func() map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Fields(`
		_auth=null access=null all=false allow-same-version=false allow-scripts= also=null audit=true
		audit-level=null before=null bin-links=true browser=null bypass-2fa=false ca=null cache-max=Infinity
		cache-min=0 cafile=null call= cert=null cidr=null color=true commit-hooks=true cpu=null
		dangerously-allow-all-scripts=false depth=null description=true dev=false diff-ignore-all-space=false
		diff-name-only=false diff-no-prefix=false diff-text=false diff-unified=3 dry-run=false
		engine-strict=false expect-result-count=null expect-results=null expires=null fetch-retries=2
		fetch-retry-factor=10 fetch-retry-maxtimeout=60000 fetch-retry-mintimeout=10000 fetch-timeout=300000
		force=false foreground-scripts=false format-package-lock=true fund=true git-tag-version=true
		global=false globalconfig= global-style=false https-proxy=null if-present=false ignore-scripts=false
		include-staged=false include-workspace-root=false include-attestations=false init-author-email=
		init-author-name= init-author-url= init-private=false init.author.email= init.author.name=
		init.author.url= install-links=false json=false key=null legacy-bundling=false legacy-peer-deps=false
		libc=null link=false local-address=null lockfile-version=null logs-dir=null logs-max=10 long=false
		name=null maxsockets=15 min-release-age=null node-options=null noproxy= offline=false
		omit-lockfile-registry-resolved=false only=null orgs=null optional=null os=null otp=null
		package-lock=true package-lock-only=false parseable=false allow-scripts-pending=false
		allow-scripts-pin=true prefer-dedupe=false prefer-offline=false prefer-online=false prefix= preid=
		production=null progress=false provenance=false provenance-file=null proxy=null read-only=false
		rebuild-bundle=true save=true save-bundle=false save-dev=false save-exact=false save-optional=false
		save-peer=false save-prod=false sbom-format=null scope= scopes=null packages-all=false
		packages-and-scopes-permission=null orgs-permission=null password=null token-description=null
		script-shell=null searchexclude= searchlimit=20 searchopts= searchstaleness=900 shrinkwrap=true
		sign-git-commit=false sign-git-tag=false strict-peer-deps=false strict-allow-scripts=false
		strict-ssl=true timing=false umask=0 unicode=true update-notifier=true usage=false version=false
		versions=false which=null workspaces=null workspaces-update=true yes=null
	`) {
		name, value, _ := strings.Cut(kv, "=")
		out[name] = value
	}
	return out
}()

func npmIsModeled(key string) bool {
	return strings.HasSuffix(key, ":registry") || slices.ContainsFunc(NpmModeled, func(m ModeledSetting) bool { return m.Name == key })
}

// NpmUncertified names the first setting of npm's configuration that keeps
// doctor from certifying npm, as a phrase naming the file, the line and the
// option and never the value, "" for none. A strict-ssl other than true comes
// first, from any file or from npm_config_strict_ssl, with Node's own
// NODE_TLS_REJECT_UNAUTHORIZED=0 beside it: npm hands it to Node as
// rejectUnauthorized (make-fetch-happen, lib/options.js), and with it false
// npm accepts whatever certificate a server presents, so no CA decides
// anything. Which layer wins is not weighed: a file that turns verification
// off is refused whatever a later one sets. Then every option npm defines
// that NpmModeled does not hold, set to other than its default.
func NpmUncertified(getenv func(string) string, files []string) string {
	type at struct {
		o    NpmOption
		file string
	}
	var opts []at
	seen := map[string]bool{}
	for _, f := range files {
		if seen[f] {
			continue
		}
		seen[f] = true
		for _, o := range npmFileOptions(f) {
			if o.Key != "" && o.Unsure == "" {
				opts = append(opts, at{o, f})
			}
		}
	}
	const off = "npm then accepts any certificate a registry presents, so no CA decides what it trusts and none can be certified for it"
	for _, a := range opts {
		if a.o.Key == "strict-ssl" && !a.o.Bare && a.o.Value != "true" {
			return fmt.Sprintf("line %d of %s, which sets strict-ssl to other than true: %s", a.o.Line, a.file, off)
		}
	}
	if getenv != nil {
		for _, name := range []string{"npm_config_strict_ssl", "NPM_CONFIG_STRICT_SSL"} {
			if v := getenv(name); v != "" && v != "true" {
				return fmt.Sprintf("the environment's %s, which sets strict-ssl to other than true: %s", name, off)
			}
		}
	}
	// Node reads this one itself, for every TLS connection npm opens
	// (lib/_tls_wrap.js: rejectUnauthorized defaults to it not being "0").
	if getenv != nil && getenv("NODE_TLS_REJECT_UNAUTHORIZED") == "0" {
		return "the environment's NODE_TLS_REJECT_UNAUTHORIZED, which is 0: Node, and npm under it, then accepts any certificate a registry presents, so no CA decides what it trusts and none can be certified for it"
	}
	for _, a := range opts {
		key := a.o.Key
		if !npmDefined[key] || npmIsModeled(key) {
			continue
		}
		value := a.o.Value
		if a.o.Bare {
			value = "true"
		}
		if def, known := npmDefaults[key]; known && !a.o.Array && value == def {
			continue
		}
		return fmt.Sprintf("line %d of %s, which sets %s, an npm option doctor does not model, to other than npm's default: what it changes in how npm starts or connects is not something doctor interprets", a.o.Line, a.file, key)
	}
	return ""
}

// PipModeled is the pip install options doctor certifies pip under. Every
// other option pip install declares is refused when a file or its PIP_
// variable sets it to anything but the empty string, which pip reads as no
// setting. An option the parser does not declare is one pip skips.
var PipModeled = []ModeledSetting{
	{"index-url", "PipIndexURL: a location pip ignores or sends no TLS request to"},
	{"extra-index-url", "PipIndexURL, per word"},
	{"trusted-host", "none: an append of text; refused where a word names bodega"},
	{"timeout", "PipInstallError: not a float"},
	{"default-timeout", "PipInstallError, as timeout"},
	{"retries", "PipInstallError: not an integer"},
	{"cert", "PipCertPath, and a bundle that does not read verifies nothing, which the probe reports"},
	{"disable-pip-version-check", "PipInstallError: not a truth value"},
	{"no-cache-dir", "PipInstallError: not a truth value"},
	{"no-index", "PipInstallError: not a truth value; true is PipNoIndex's refusal"},
	{"no-compile", "PipInstallError: not a truth value; read after the download"},
	{"find-links", "none: an append of text, naming locations beside the index"},
	{"use-deprecated", "PipInstallError: a word outside pip's choices; legacy-certs is the bundle the probe then reads"},
}

// PipUncertified names the first setting of pip install's configuration that
// keeps doctor from certifying pip for bodega at u, as a phrase naming the
// option and where it is set, "" for none: a trusted-host naming bodega, for
// which pip mounts an adapter that verifies nothing (InsecureHTTPAdapter,
// pip/_internal/network/session.py at pip 26.2.1), then any declared option
// outside PipModeled. The groups are the ones pip converts: [global],
// [install] and the environment. client-cert, pypi-url and python have their
// own refusals, which their callers reach first.
func PipUncertified(layers []PipLayer, getenv func(string) string, u *url.URL) string {
	groups := pipGroups(layers, getenv)
	var all []pipSet
	for _, group := range []string{"global", "install", ":env:"} {
		for _, s := range groups[group] {
			if s.value != "" {
				all = append(all, s)
			}
		}
	}
	// trusted-host lifts verification for the commands of the section that
	// sets it, so every section counts, not only the ones pip install reads.
	for _, l := range layers {
		f, err := readPipFile(l.Data)
		if err != nil || u == nil {
			continue
		}
		for _, s := range f.settings() {
			if s.option == "trusted-host" && slices.ContainsFunc(pyFields(s.value), func(w string) bool { return namesBodega(w, u) }) {
				return fmt.Sprintf("trusted-host (%s under [%s], %s line %d), which names bodega's host: pip then verifies no certificate that host presents for that section's commands, so no CA decides what it trusts and none can be certified for it", s.raw, s.section, l.File, s.line)
			}
		}
	}
	for _, s := range all {
		if s.key == "trusted-host" && u != nil && slices.ContainsFunc(pyFields(s.value), func(w string) bool { return namesBodega(w, u) }) {
			return fmt.Sprintf("trusted-host (%s), which names bodega's host: pip then verifies no certificate that host presents, so no CA decides what it trusts and none can be certified for it", s.from)
		}
	}
	// A timeout converts as a float, then reaches urllib3's Timeout, which
	// rejects a value at or below zero before pip opens a connection
	// (util/timeout.py:130, as vendored by pip 26.2.1).
	for _, s := range all {
		if s.key != "timeout" && s.key != "default-timeout" || !pyFloat(s.value) {
			continue
		}
		if f, err := strconv.ParseFloat(strings.ReplaceAll(pyNumeral(s.value), "_", ""), 64); err == nil && f <= 0 {
			return fmt.Sprintf("%s (%s), which is at or below zero: pip's HTTP library refuses that timeout before it opens any connection", s.key, s.from)
		}
	}
	for _, s := range all {
		declared := slices.ContainsFunc(pipInstallOpts, func(o pipOpt) bool { return o.name == s.key })
		if !declared || slices.ContainsFunc(PipModeled, func(m ModeledSetting) bool { return m.Name == s.key }) {
			continue
		}
		return fmt.Sprintf("%s (%s), a pip install option doctor does not model: what it changes in how pip starts or connects is not something doctor interprets", s.key, s.from)
	}
	return ""
}

// GoEnvModeled is the assignments of the go env file doctor certifies the
// go command under. Any other assignment is refused unless its value is
// empty, which the go command reads as unset.
var GoEnvModeled = []ModeledSetting{
	{"GOPROXY", "GoProxyList: the list the go command refuses before it asks any proxy"},
	{"GOPRIVATE", "none: module.MatchPrefixPatterns passes over a glob path.Match refuses"},
	{"GONOPROXY", "none, as GOPRIVATE"},
	{"GONOSUMDB", "none, as GOPRIVATE"},
	{"GOSUMDB", "goSumdbModeled: off and the two databases the go command knows by name, none of which dbDial refuses; any other value is refused here"},
	{"GOINSECURE", "none, as GOPRIVATE; refused where a pattern matches bodega"},
	{"GOFLAGS", "goFlagsModeled: -mod=mod, -mod=readonly and -modcacherw, each a flag InitGOFLAGS knows and go mod download converts; any other argument is refused here"},
}

var (
	goSumdbModeled = []string{"off", "sum.golang.org", "sum.golang.google.cn"}
	// -modcacherw is a boolean flag, set through strconv.ParseBool.
	goFlagsModeled = []string{"-mod=mod", "-mod=readonly", "-modcacherw", "-modcacherw=true", "-modcacherw=false"}
)

// goInsecureHost reports whether a GOINSECURE pattern's first path element
// matches host: a module path below bodega's host, fetched directly as
// GONOPROXY or GOPRIVATE allow, is then fetched from that host without a
// verified certificate.
func goInsecureHost(globs, host string) bool {
	for _, glob := range strings.Split(globs, ",") {
		first, _, _ := strings.Cut(glob, "/")
		if ok, _ := path.Match(first, host); ok && first != "" {
			return true
		}
	}
	return false
}

// goMatchPrefixPatterns is module.MatchPrefixPatterns of golang.org/x/mod as
// go1.27.4 vendors it: a comma-separated list of globs, each matched against
// as many leading path elements of target as it has itself.
func goMatchPrefixPatterns(globs, target string) bool {
	for globs != "" {
		var glob string
		glob, globs, _ = strings.Cut(globs, ",")
		if glob = strings.TrimSuffix(glob, "/"); glob == "" {
			continue
		}
		n := strings.Count(glob, "/")
		prefix := target
		for i := 0; i < len(target); i++ {
			if target[i] == '/' {
				if n == 0 {
					prefix = target[:i]
					break
				}
				n--
			}
		}
		if n > 0 {
			continue
		}
		if matched, _ := path.Match(glob, prefix); matched {
			return true
		}
	}
	return false
}

// GoEnvUncertified names the first assignment of the go env file in data
// that keeps doctor from certifying the go command for bodega at u, as a
// phrase naming the file and the variable and never its value, "" for none.
// The file is read as cfg.readEnvFile reads it, the last assignment of a
// name standing.
//
// GOFLAGS is the go command's own arguments: base.InitGOFLAGS (go1.27.4,
// cmd/go/internal/base/goflags.go:27) exits on one it does not know before
// any request, and the flags it does know change what a command does. Three
// are followed, written with no quoting. GOINSECURE is refused where one of
// its patterns matches bodega's host, since it lifts the https requirement
// for what it matches.
func GoEnvUncertified(file string, data []byte, u *url.URL) string {
	set := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok || line[0] < 'A' || line[0] > 'Z' {
			continue
		}
		set[k] = v
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		val := set[key]
		why := ""
		switch {
		case val == "":
		case key == "GOFLAGS":
			if strings.ContainsAny(val, `'"`) {
				why = "which quotes an argument, a form doctor does not split as the go command does"
				break
			}
			for _, f := range goFlagsFields(val) {
				if !slices.Contains(goFlagsModeled, f) {
					why = "which holds an argument other than -mod=mod, -mod=readonly and -modcacherw: the go command exits on a flag it does not know before it asks any proxy, and doctor interprets no other flag it does"
					break
				}
			}
		case key == "GOSUMDB":
			if !slices.Contains(goSumdbModeled, val) {
				why = "which names a checksum database other than " + strings.Join(goSumdbModeled, ", ") + ": the key or URL it holds is one the go command verifies or connects to in a way doctor does not interpret"
			}
		case key == "GOINSECURE":
			if u != nil && (goMatchPrefixPatterns(val, u.Hostname()+strings.TrimRight(u.Path, "/")) || goInsecureHost(val, u.Hostname())) {
				why = "which holds a pattern matching bodega's host: the go command then fetches what it matches without requiring https or a verified certificate"
			}
		case !slices.ContainsFunc(GoEnvModeled, func(m ModeledSetting) bool { return m.Name == key }):
			why = "a go command setting doctor does not model: what it changes in how the go command starts or connects is not something doctor interprets"
		}
		if why != "" {
			return fmt.Sprintf("%s in %s, %s", key, file, why)
		}
	}
	return ""
}

// goFlagsFields splits GOFLAGS on the four bytes quoted.Split treats as
// separators (go1.27.4, cmd/internal/quoted/quoted.go:15-55). strings.Fields
// also splits on Unicode spaces, so a no-break space the go command keeps
// inside a flag, and exits on, would vanish here and admit the flag.
func goFlagsFields(val string) []string {
	return strings.FieldsFunc(val, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
}

// Uncertified is GoEnvUncertified for the user's go env file as this host
// has it, a planned file read as planned.
func (e GoEnv) Uncertified(u *url.URL) string {
	file := e.File()
	if file == "" {
		return ""
	}
	data, planned := e.Planned[file]
	if !planned {
		// An absent file assigns nothing, and GOROOT/go.env still applies.
		data, _ = os.ReadFile(file)
	}
	if u := GoEnvUncertified(file, data, u); u != "" {
		return u
	}
	// GOROOT/go.env supplies what the user's file does not assign. Only its
	// GOINSECURE is judged: a distribution's own file sets GOTOOLCHAIN and
	// GOSUMDB, which are its defaults rather than a host's choices.
	user := e.read(file)
	if _, set := user["GOINSECURE"]; set {
		return ""
	}
	if goroot := findGoroot(user["GOROOT"], e.env); goroot != "" {
		dist := filepath.Join(goroot, "go.env")
		if val := e.read(dist)["GOINSECURE"]; val != "" {
			return GoEnvUncertified(dist, []byte("GOINSECURE="+val+"\n"), u)
		}
	}
	return ""
}

// HelmModeled is the keys of a repositories.yaml doctor certifies helm
// under: every field of File and Entry at helm v4.3.0, which is what helm
// repo add writes. Any other key is refused, in whatever case: helm's decoder
// matches names without regard to it, and doctor's reading of a key is of
// the spelling here.
var HelmModeled = []ModeledSetting{
	{"apiVersion", "none: a string helm writes and does not read back"},
	{"generated", "ParseHelmFile: not an RFC 3339 time"},
	{"repositories", "ParseHelmFile and RepositoryError: a null member, a url with no getter"},
	{"name", "none: a string; two entries of the name a plan edits are refused by helmDuplicate"},
	{"url", "RepositoryError"},
	{"username", "none: sent as basic authentication after the handshake"},
	{"password", "none, as username"},
	{"pass_credentials_all", "ParseHelmFile: not a boolean"},
	{"certFile", "ClientTLSError: a pair that does not read or match"},
	{"keyFile", "ClientTLSError"},
	{"caFile", "ClientTLSError's caller: the root pool the probe verifies with"},
	{"insecure_skip_tls_verify", "ParseHelmFile: not a boolean; refused true on an entry at bodega"},
}

// HelmUncertified names the first thing in the repositories.yaml in data
// that keeps doctor from certifying helm for bodega at u, as a phrase naming
// the file and the key, "" for none or for a file that does not load, which
// LoadHelmFile reports: an entry at bodega's host with
// insecure_skip_tls_verify true, for which helm sets InsecureSkipVerify
// (internal/tlsutil/tls.go at helm v4.3.0), then a key outside HelmModeled.
func HelmUncertified(file string, data []byte, u *url.URL) string {
	doc, err := ParseHelmFile(data)
	if err != nil || doc == nil {
		return ""
	}
	for _, r := range doc.Repositories {
		if r == nil || !r.InsecureSkipTLSVerify || u == nil {
			continue
		}
		if namesBodega(r.URL, u) {
			return fmt.Sprintf("insecure_skip_tls_verify of the repository %s in %s, which is true: helm then accepts any certificate that repository presents, so no CA decides what it trusts and none can be certified for it", r.Name, file)
		}
	}
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return ""
	}
	known := func(key string) bool {
		return slices.ContainsFunc(HelmModeled, func(m ModeledSetting) bool { return m.Name == key })
	}
	unknown := func(key, where string) string {
		return fmt.Sprintf("the key %s %s %s, which is not one helm v4.3.0 writes and doctor holds no reading of", key, where, file)
	}
	for _, key := range sortedKeys(raw) {
		if !known(key) {
			return unknown(key, "at the top of")
		}
	}
	entries, _ := raw["repositories"].([]any)
	for _, e := range entries {
		em, _ := e.(map[string]any)
		for _, key := range sortedKeys(em) {
			if !known(key) {
				return unknown(key, "of a repository in")
			}
		}
	}
	return ""
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// HelmDuplicate names the first repository name that both planned and the
// repositories.yaml in data hold, and that data holds more than once, ""
// for none. helm loads such a file, and each entry of the name carries its
// own credentials: an edit by name cannot say which of them it means.
func HelmDuplicate(data, planned []byte) string {
	doc, err := ParseHelmFile(data)
	plan, perr := ParseHelmFile(planned)
	if err != nil || perr != nil || doc == nil || plan == nil {
		return ""
	}
	for _, p := range plan.Repositories {
		n := 0
		for _, r := range doc.Repositories {
			if p != nil && r != nil && r.Name == p.Name {
				n++
			}
		}
		if n > 1 {
			return p.Name
		}
	}
	return ""
}

// AptModeled is the options of apt's Acquire tree doctor certifies apt
// under, "<host>" standing for the scope apt's http and https methods look
// an option up under first. Every other option under Acquire is refused when
// set. apt reads each of these through Configuration::Find, FindB or FindI
// (apt-pkg/contrib/configuration.cc at APT 3.0.3, lines 448-496), which give
// the default for a value of the wrong type and never an error, so none but
// the proxies and CaInfo has a value apt stops on.
//
// The gate is the Acquire tree because that is what apt's acquire system and
// its methods read to open a connection. Options in apt's other trees
// (APT::Install-Recommends, APT::Get::Assume-Yes, DPkg, Unattended-Upgrade)
// are outside what doctor inspects.
var AptModeled = []ModeledSetting{
	{"acquire::http::proxy", "aptProxyRefused: a scheme apt's method stops on (\"Unsupported proxy configured\"); https, which opens a second TLS session, is refused here"},
	{"acquire::http::proxy::<host>", "aptProxyRefused"},
	{"acquire::https::proxy", "aptProxyRefused"},
	{"acquire::https::proxy::<host>", "aptProxyRefused"},
	{"acquire::https::cainfo", "none at load; a file that does not read verifies nothing, which the probe reports"},
	{"acquire::https::<host>::cainfo", "as CaInfo"},
	{"acquire::https::verify-peer", "none: FindB; refused where it reads false for bodega"},
	{"acquire::https::<host>::verify-peer", "none: FindB; refused where it reads false for bodega"},
	{"acquire::https::verify-host", "none: FindB; refused where it reads false for bodega"},
	{"acquire::https::<host>::verify-host", "none: FindB; refused where it reads false for bodega"},
	{"acquire::allowtls", "HTTPSError: false turns TLS off"},
	{"acquire::retries", "none: FindI"},
	{"acquire::http::timeout", "none: FindI"},
	{"acquire::https::timeout", "none: FindI"},
	{"acquire::http::pipeline-depth", "none: FindI"},
	{"acquire::http::user-agent-non-interactive", "none: FindB"},
	{"acquire::forceipv4", "none: FindB"},
	{"acquire::forceipv6", "none: FindB"},
	{"acquire::languages", "none: a list of index names"},
	{"acquire::gzipindexes", "none: FindB"},
	{"acquire::pdiffs", "none: FindB"},
	{"acquire::check-valid-until", "none: FindB, read after the fetch"},
	{"acquire::compressiontypes::*", "none: names of index compressions"},
	{"acquire::indextargets::*", "none: names of index files"},
	{"acquire::changelogs::*", "none: read by apt changelog alone"},
}

// aptHTTPSDedicated are the https options HTTPSError and TLSUnmodeled judge,
// each with a refusal of its own.
var aptHTTPSDedicated = []string{"sslcert", "sslkey", "crlfile", "issuercert", "sslforceversion"}

// aptModeledKey reports whether key, an option under acquire::, is on
// AptModeled, a host scope read as "<host>".
func aptModeledKey(key string) bool {
	match := func(pattern string) bool {
		if sub, ok := strings.CutSuffix(pattern, "::*"); ok {
			return key == sub || strings.HasPrefix(key, sub+"::")
		}
		if !strings.Contains(pattern, "<host>") {
			return key == pattern
		}
		before, after, _ := strings.Cut(pattern, "<host>")
		host, ok := strings.CutPrefix(key, before)
		if !ok {
			return false
		}
		host, ok = strings.CutSuffix(host, after)
		return ok && host != "" && !strings.Contains(host, "::")
	}
	return slices.ContainsFunc(AptModeled, func(m ModeledSetting) bool { return match(m.Name) })
}

// aptProxyRefused is why a proxy value keeps apt from being certified, ""
// for one doctor follows: empty and DIRECT, which are no proxy, and an http
// or socks5h proxy, through which apt opens the same TLS session with the
// server (methods/connect.cc and methods/http.cc at APT 3.0.3). apt stops on
// any other scheme but https, and to an https proxy it opens a TLS session of
// its own that no CA here is verified against.
func aptProxyRefused(value string) string {
	if value == "" || value == "DIRECT" {
		return ""
	}
	p, err := url.Parse(value)
	switch {
	case err != nil || p.Host == "":
		return "names a proxy doctor does not read as a URL with a host"
	case p.Scheme == "https":
		return "names an https proxy, to which apt opens a TLS session of its own that doctor does not verify"
	case p.Scheme != "http" && p.Scheme != "socks5h":
		return "names a proxy in a scheme apt's method stops on (Unsupported proxy configured)"
	}
	return ""
}

// Uncertified names the first option of apt's Acquire tree that keeps doctor
// from certifying apt for host, as a phrase naming the option and the file
// that set it, "" for none: Verify-Peer or Verify-Host read false for host,
// under which apt's https method skips the check (methods/connect.cc at APT
// 3.0.3), then a proxy doctor does not follow, then any option outside
// AptModeled. An option scoped to another host says nothing for this one.
func (c AptConfig) Uncertified(host string) string {
	host = strings.ToLower(host)
	for _, option := range []string{"Verify-Peer", "Verify-Host"} {
		if v := c.https(host, strings.ToLower(option)); v.Value != "" && !aptBool(v.Value, true) {
			return fmt.Sprintf("Acquire::https::%s (%s), which is false: apt then accepts a certificate it has not verified for bodega's host, so no CA decides what it trusts and none can be certified for it", option, v.File)
		}
	}
	keys := make([]string, 0, len(c))
	for k := range c {
		if strings.HasPrefix(k, "acquire::") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		v := c[key]
		rest := strings.TrimPrefix(strings.TrimPrefix(key, "acquire::https::"), "acquire::http::")
		scope, leaf, scoped := strings.Cut(rest, "::")
		method := rest != key
		switch {
		case method && scoped && scope != "proxy" && scope != host && !strings.Contains(leaf, "::"):
			// Scoped to another host.
			continue
		case method && slices.Contains(aptHTTPSDedicated, rest), method && scoped && scope == host && slices.Contains(aptHTTPSDedicated, leaf):
			continue
		case method && (rest == "proxy" || scoped && scope == "proxy"):
			if scoped && leaf != host {
				continue
			}
			if why := aptProxyRefused(v.Value); why != "" {
				return fmt.Sprintf("%s (%s), which %s", key, v.File, why)
			}
			continue
		case aptModeledKey(key):
			continue
		}
		return fmt.Sprintf("%s (%s), an option of apt's Acquire tree doctor does not model: what it changes in how apt connects is not something doctor interprets", key, v.File)
	}
	return ""
}

// SkipsVerify names the first host table of the hosts.toml that sends pulls
// to bodega, by is, with skip_verify true, "" for none: containerd then sets
// InsecureSkipVerify for that host (core/remotes/docker/config/hosts.go at
// containerd v2.2.0, line 243), so the ca beside it decides nothing.
func (f *ContainerdHostsFile) SkipsVerify(is func(key string) bool) string {
	if f == nil {
		return ""
	}
	for _, h := range f.Hosts {
		if h.SkipVerify != nil && *h.SkipVerify && is(h.Key) {
			// The top-level table's key is empty: its server comes from the
			// registry directory, and "" would read as no match.
			return cmp.Or(h.Key, "the registry's own server")
		}
	}
	return ""
}

// Insecure names the first insecure-registries entry of the daemon.json that
// covers bodega at u, "" for none: dockerd then sets InsecureSkipVerify for
// that endpoint, a mirror included (registry/registry.go at moby v28.5.2,
// line 35, over isSecureIndex), so no ca.crt under certs.d decides what it
// accepts. An entry is a host, a host and port, or a CIDR an address falls
// in. dockerd resolves a host name to test it against a CIDR; doctor resolves
// none, so a CIDR beside a bodega known by name is named as well.
func (d *DockerDaemonFile) Insecure(u *url.URL) string {
	if d == nil || u == nil {
		return ""
	}
	// dockerd adds 127.0.0.0/8 to the insecure registries whatever the file
	// says (registry/config.go at moby v28.5.2, newServiceConfig).
	for _, r := range d.InsecureRegistries {
		if _, network, err := net.ParseCIDR(r); err == nil {
			if ip := net.ParseIP(u.Hostname()); ip == nil || network.Contains(ip) {
				return r
			}
			continue
		}
		if namesBodega(r, u) {
			return r
		}
	}
	return ""
}
