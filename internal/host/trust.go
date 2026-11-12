package host

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"

	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/manifest"
)

// TrustProbe asks, for each doctor row whose client is configured for
// bodega, whether that client can verify the certificate bodega serves. A
// client pointed at bodega that refuses its certificate fetches nothing, and
// the row that judged its configuration alone reads OK.
//
// Every field stands in for part of the host, so a test supplies each.
type TrustProbe struct {
	// Root is the directory the /etc and /usr/local paths sit under, "" for
	// the host's own.
	Root      string
	Home      string
	GOOS      string
	Getenv    func(string) string
	ConfigDir func() (string, error)
	// Chain returns the certificates the server at hostport presents, leaf
	// first, without verifying them. Nil dials it.
	Chain func(hostport string) ([]*x509.Certificate, error)
	// System verifies a chain for dnsName against the operating system's
	// trust store. Nil uses the store this process reads.
	System func(chain []*x509.Certificate, dnsName string) error
	// Node lists the CA certificates the host's Node trusts by default, and
	// Pip names the bundle the host's pip reads when no setting names one:
	// neither is a file doctor can find, and doctor runs neither client to
	// ask. Nil, or an error, is a default nothing answers for, and the row
	// then says what it left unchecked.
	Node func() (NodeRoots, error)
	Pip  func() (PipDefault, error)
}

// NodeRoots is what a Node verifies a TLS client connection against when
// nothing in npm's configuration names a CA.
type NodeRoots struct {
	// PEM are the certificates Node lists: its effective defaults when
	// Effective is set, which already follow NODE_OPTIONS and
	// NODE_EXTRA_CA_CERTS, and otherwise the roots it bundles.
	PEM       []string
	Effective bool
	// OpenSSLDefault says this Node was built to read OpenSSL's default
	// store, as a distribution's package is, in place of the bundled roots.
	OpenSSLDefault bool
}

// PipDefault is the store a pip reads when no cert setting names a bundle.
type PipDefault struct {
	Version string
	// Truststore says this pip verifies through the operating system's store
	// (pip 24.2 and later on Python 3.10 and later).
	Truststore bool
	// Certifi is the bundle pip ships and reads otherwise, "" when the
	// installation carries none, as a distribution's pip patched onto the
	// system bundle does not.
	Certifi string
	// Prefix is the sys.prefix of the interpreter this pip runs under, whose
	// pip.conf it loads after the global and per-user files, "" when pip did
	// not say.
	Prefix string
}

// trustStore is one place a client, as this host configures it, takes trust
// anchors from when it connects to bodega.
type trustStore struct {
	// name is how a warning names the store.
	name string
	// system says the client also accepts what the operating system's store
	// accepts here. False is a store read in place of it: a setting that
	// replaces the client's defaults.
	system bool
	// files are the PEM files the store reads, and pem certificates a
	// setting carries inline.
	files []string
	pem   []string
	// unsure is why the system store verifying does not settle this store:
	// the client could not be asked whether it reads that store at all. The
	// row then keeps its status and says so.
	unsure string
	// resolve replaces the store with the client's default one. It runs only
	// once bodega has answered.
	resolve func() trustStore
	// blind is why nothing can be said about this store at all: the client
	// takes its configuration from an input this probe does not read, or is
	// told to read none. It names that input. No verification settles it.
	blind string
}

// trustRow is one doctor row's client.
type trustRow struct {
	// system is the --configure name the remediation carries.
	system string
	// stores resolves the stores the client reads for bodega at u, one per
	// route it reaches bodega by. None means the client's configuration
	// does not name bodega, and the row is left as its check wrote it.
	stores func(t TrustProbe, u *url.URL) []trustStore
}

const systemStoreName = "the system trust store"

// named is a CA file a client's setting names. replaces says the client
// reads it in place of the system trust store rather than beside it.
func named(file, setting string, replaces bool) *trustStore {
	if replaces {
		return &trustStore{name: fmt.Sprintf("%s, which %s names in place of the system trust store,", file, setting), files: []string{file}}
	}
	return &trustStore{name: fmt.Sprintf("%s, which %s adds to the system trust store", file, setting), files: []string{file}, system: true}
}

// envCA is the store an environment variable names in place of the system's.
func envCA(t TrustProbe, keys ...string) *trustStore {
	for _, key := range keys {
		if v := t.env(key); v != "" {
			return named(v, "the environment's "+key, true)
		}
	}
	return nil
}

// namesHost reports whether raw is a URL at host, port included.
func namesHost(raw, host string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && strings.EqualFold(u.Host, host)
}

// goStores is the system trust store when a proxy the go command can reach
// is at bodega's host. The list is the effective GOPROXY, resolved as the
// goproxy-env row resolves it: a non-empty value in the environment hides
// the go env file, so a file naming bodega under an environment that names
// another proxy configures nothing.
func goStores(t TrustProbe, u *url.URL) []trustStore {
	configDir := t.ConfigDir
	if configDir == nil {
		configDir = func() (string, error) { return "", errors.New("no user config directory") }
	}
	val, _, _, err := effectiveGoproxy(t.env, configDir)
	if err != nil {
		if t.ConfigDir == nil {
			return nil
		}
		return []trustStore{{blind: fmt.Sprintf("GOPROXY is unset in the environment and the go env file was not read (%v), so whether go fetches from bodega, and verifies its certificate, is unchecked", err)}}
	}
	if !slices.ContainsFunc(reachableProxies(val), func(entry string) bool { return namesHost(entry, u.Host) }) {
		return nil
	}
	return []trustStore{{name: systemStoreName, system: true}}
}

// trustRows maps a row's check name to its client.
var trustRows = map[string]trustRow{
	"apt-sources": {system: manifest.TypeApt, stores: aptStores},
	"goproxy-env": {system: manifest.TypeGomod, stores: goStores},
	// git and helm have no row in the report; these judge them after a CA
	// install, which answers for every client it configured.
	"git-config":                          {system: manifest.TypeGit, stores: gitStores},
	"helm-repos":                          {system: manifest.TypeHelm, stores: helmStores},
	"pip-config":                          {system: manifest.TypePypi, stores: pipStores},
	"npm-config":                          {system: manifest.TypeNpm, stores: npmStores},
	"oci-" + clientconf.RuntimeContainerd: {system: manifest.TypeOCI, stores: containerdStores},
	"oci-" + clientconf.RuntimeDocker: {system: manifest.TypeOCI, stores: func(t TrustProbe, u *url.URL) []trustStore {
		if !t.filesMention(u.Host, clientconf.DockerDaemonPath) {
			return nil
		}
		return []trustStore{certsDir(filepath.Join(t.Root, "/etc/docker/certs.d", u.Host))}
	}},
}

// aptStores is the store apt verifies bodega at u against: the file the
// effective Acquire::https::CAInfo names, which apt reads in place of the
// system trust store, and the system store with none set. The option scoped
// to bodega's own host outranks the unscoped one, and one scoped to another
// host says nothing here.
func aptStores(t TrustProbe, u *url.URL) []trustStore {
	if !t.filesMention(u.Host, "/etc/apt/sources.list", "/etc/apt/sources.list.d/*") {
		return nil
	}
	conf := t.aptConfig()
	for _, key := range []string{"acquire::https::" + strings.ToLower(u.Hostname()) + "::cainfo", "acquire::https::cainfo"} {
		if v := conf[key]; v.value != "" {
			return []trustStore{*named(v.value, "Acquire::https::CAInfo in "+v.file, true)}
		}
	}
	return []trustStore{{name: systemStoreName, system: true}}
}

// aptOption is the value apt's configuration ends up giving one option, and
// the file that gave it.
type aptOption struct{ value, file string }

var aptPartName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// aptConfig reads apt's configuration in the order apt loads it, a later
// assignment replacing an earlier one: the file APT_CONFIG names, then the
// apt.conf.d fragments in name order (those apt accepts: no extension, or
// .conf), then apt.conf. Keys are lowercased, since apt matches them without
// regard to case. #include is not followed.
func (t TrustProbe) aptConfig() map[string]aptOption {
	var files []string
	if v := t.env("APT_CONFIG"); v != "" {
		files = append(files, v)
	}
	parts, _ := filepath.Glob(filepath.Join(t.Root, "/etc/apt/apt.conf.d/*"))
	sort.Strings(parts)
	for _, f := range parts {
		name := filepath.Base(f)
		if ext := filepath.Ext(name); aptPartName.MatchString(name) && (ext == "" || ext == ".conf") {
			files = append(files, f)
		}
	}
	files = append(files, filepath.Join(t.Root, "/etc/apt/apt.conf"))
	out := map[string]aptOption{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		readAptConf(string(data), func(key, value string, clearTree bool) {
			if !clearTree {
				out[key] = aptOption{value, f}
				return
			}
			for k := range out {
				if k == key || strings.HasPrefix(k, key+"::") {
					delete(out, k)
				}
			}
		})
	}
	return out
}

// readAptConf walks one apt configuration file and calls set for each
// assignment, with the scopes around it joined into the key, and for each
// #clear. Comments (//, /* */ and a line opening with #) are dropped outside
// quotes, so a commented-out option assigns nothing.
func readAptConf(text string, set func(key, value string, clearTree bool)) {
	var scopes []string
	var stmt strings.Builder
	quoted, lineStart := false, true
	flush := func() (tag, word string) {
		fields := aptWords(stmt.String())
		stmt.Reset()
		if len(fields) > 0 {
			tag = fields[0]
		}
		if len(fields) > 1 {
			word = fields[1]
		}
		return tag, word
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		if quoted {
			quoted = c != '"'
			stmt.WriteByte(c)
			continue
		}
		atStart := lineStart
		lineStart = c == '\n' || lineStart && (c == ' ' || c == '\t')
		switch {
		case c == '"':
			quoted = true
			stmt.WriteByte(c)
		case c == '/' && strings.HasPrefix(text[i:], "//"), c == '#' && atStart && !strings.HasPrefix(text[i:], "#clear"):
			end := strings.IndexByte(text[i:], '\n')
			if end < 0 {
				return
			}
			i += end - 1
		case c == '/' && strings.HasPrefix(text[i:], "/*"):
			end := strings.Index(text[i+2:], "*/")
			if end < 0 {
				return
			}
			i += end + 3
		case c == '{':
			tag, _ := flush()
			scopes = append(scopes, strings.ToLower(tag))
		case c == '}':
			stmt.Reset()
			if len(scopes) > 0 {
				scopes = scopes[:len(scopes)-1]
			}
		case c == ';':
			tag, word := flush()
			if tag == "" {
				continue
			}
			clearTree := tag == "#clear"
			if clearTree {
				tag, word = word, ""
			}
			key := strings.ToLower(strings.Join(append(slices.Clone(scopes), tag), "::"))
			set(strings.Trim(key, ":"), word, clearTree)
		default:
			stmt.WriteByte(c)
		}
	}
}

// aptWords splits a statement into its words, a quoted run being one word
// with the quotes removed.
func aptWords(stmt string) []string {
	var out []string
	var word strings.Builder
	quoted, open := false, false
	for _, r := range stmt {
		switch {
		case r == '"':
			quoted, open = !quoted, true
		case !quoted && (r == ' ' || r == '\t' || r == '\n' || r == '\r'):
			if open {
				out = append(out, word.String())
				word.Reset()
				open = false
			}
		default:
			word.WriteRune(r)
			open = true
		}
	}
	if open {
		out = append(out, word.String())
	}
	return out
}

// certsDir is a certs.d directory for one registry host, whose *.crt files
// Docker adds to the system store.
func certsDir(dir string) trustStore {
	files, _ := filepath.Glob(filepath.Join(dir, "*.crt"))
	return trustStore{name: dir, system: true, files: files}
}

// home is the home directory on disk. Home names it as the host does, so it
// sits under Root with every other absolute path, unless it is already a
// directory inside Root: a caller that rooted it has said where it is.
func (t TrustProbe) home() string {
	if t.Home == "" || t.Root == "" {
		return t.Home
	}
	if rel, err := filepath.Rel(t.Root, t.Home); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return t.Home
	}
	return filepath.Join(t.Root, t.Home)
}

func (t TrustProbe) env(key string) string {
	if t.Getenv == nil {
		return ""
	}
	return t.Getenv(key)
}

// pipFiles lists the configuration files pip loads, in the order it loads
// them: clientconf.PipConfigFiles, which a CA install resolves the same way.
// The files checkPipConfig scans for a public index are a wider inventory and
// say nothing here, since it shows an operator files pip never opens. ask
// names the interpreter's prefix when VIRTUAL_ENV does not.
func pipFiles(t TrustProbe, ask func() (PipDefault, error)) []string {
	h := clientconf.PipHost{GOOS: t.GOOS, Root: t.Root, Getenv: t.Getenv}
	if t.Home != "" {
		h.Home = t.home()
	}
	if ask != nil && t.env("VIRTUAL_ENV") == "" {
		if d, err := ask(); err == nil {
			h.Prefix = d.Prefix
		}
	}
	files, _ := clientconf.PipConfigFiles(h)
	return files
}

// pipStores resolves the bundle pip verifies an install against. requests
// reads REQUESTS_CA_BUNDLE and then CURL_CA_BUNDLE ahead of the verify pip
// sets on its session, so either outranks every cert setting. Behind them
// comes cert: PIP_CERT, then the last file pip loads that sets it, a
// per-command section outranking [global] whichever file holds it. Any of
// these replaces pip's default, which is read only with none set: the system
// store through truststore, or on an older pip certifi's bundle, which holds
// no private CA whatever the system store holds. Which of the two is pip's
// own to say, so Pip asks it.
func pipStores(t TrustProbe, u *url.URL) []trustStore {
	var ask func() (PipDefault, error)
	if t.Pip != nil {
		ask = sync.OnceValues(t.Pip)
	}
	files := pipFiles(t, ask)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if err := clientconf.PipLoadError(data); err != nil {
			return []trustStore{{name: "pip's configuration", blind: fmt.Sprintf("pip refuses to load %s (%v) and aborts every command while it does, so whether pip reaches bodega or verifies its certificate is unchecked", f, err)}}
		}
	}
	if !pipReaches(t, files, u) {
		if t.env("PIP_CONFIG_FILE") != os.DevNull {
			return nil
		}
		// The null device turns every configuration file off. A file naming
		// bodega is then one pip was configured with and does not read.
		loaded := t
		loaded.Getenv = func(key string) string {
			if key == "PIP_CONFIG_FILE" {
				return ""
			}
			return t.env(key)
		}
		if !pipReaches(loaded, pipFiles(loaded, ask), u) {
			return nil
		}
		return []trustStore{{name: "pip's configuration", blind: fmt.Sprintf("the environment's PIP_CONFIG_FILE is %s, which tells pip to load no configuration file, so the pip.conf pointing at bodega is not read and whether pip reaches bodega or verifies its certificate is unchecked", os.DevNull)}}
	}
	for _, key := range []string{"REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"} {
		if v := t.env(key); v != "" {
			return []trustStore{{name: fmt.Sprintf("%s, which the environment's %s names and requests reads ahead of pip's cert setting and in place of the system trust store,", v, key), files: []string{v}}}
		}
	}
	var global, install [2]string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		vals := clientconf.PipOptions(data)
		if v, ok := vals["global.cert"]; ok {
			global = [2]string{v, f}
		}
		if v, ok := vals["install.cert"]; ok {
			install = [2]string{v, f}
		}
	}
	cert := global
	if install[0] != "" {
		cert = install
	}
	if v := t.env("PIP_CERT"); v != "" {
		cert = [2]string{v, "the environment's PIP_CERT"}
	}
	if cert[0] != "" {
		return []trustStore{{name: fmt.Sprintf("%s, which pip's cert setting names in %s in place of the system trust store,", cert[0], cert[1]), files: []string{cert[0]}}}
	}
	system := trustStore{name: systemStoreName + ", which pip reads while no cert setting names a bundle,", system: true}
	return []trustStore{{name: system.name, resolve: func() trustStore {
		reason := "pip is not asked on this host"
		if ask != nil {
			d, err := ask()
			legacy := strings.Contains(t.env("PIP_USE_DEPRECATED"), "legacy-certs")
			switch {
			case err != nil:
				reason = err.Error()
			case d.Certifi != "" && (legacy || !d.Truststore):
				return trustStore{name: fmt.Sprintf("%s, the certifi bundle pip %s reads in place of the system trust store while no cert setting names another,", d.Certifi, d.Version), files: []string{d.Certifi}}
			default:
				return system
			}
		}
		system.unsure = fmt.Sprintf("which bundle pip reads by default is not known (%s), and a pip before 24.2 reads certifi's, which the system trust store's answer says nothing about, so whether pip verifies bodega's certificate is unchecked while no cert setting names a bundle", reason)
		return system
	}}}
}

// sameHost reports whether raw is a URL at u's host and port, a scheme's
// default port standing for none.
func sameHost(raw string, u *url.URL) bool {
	p, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || p.Host == "" {
		return false
	}
	port := func(x *url.URL) string {
		if x.Port() == "" && x.Scheme == "https" {
			return "443"
		}
		if x.Port() == "" && x.Scheme == "http" {
			return "80"
		}
		return x.Port()
	}
	return strings.EqualFold(p.Hostname(), u.Hostname()) && port(p) == port(u)
}

// pipReaches reports whether pip install, as its effective configuration
// stands, fetches from bodega at u. pip merges its files in load order, a
// later file replacing an earlier one's option, then reads [global], the
// command's own section over it, and the environment over both. The cert
// pipStores selects follows the same order, so the endpoint and the CA judged
// together are the pair one pip install uses. A file that names bodega only
// in a comment, in an option a later file replaces, or under [global] while
// [install] sets its own index, configures nothing.
func pipReaches(t TrustProbe, files []string, u *url.URL) bool {
	merged := map[string]string{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for key, v := range clientconf.PipOptions(data) {
			merged[key] = v
		}
	}
	for option, env := range map[string]string{"index-url": "PIP_INDEX_URL", "extra-index-url": "PIP_EXTRA_INDEX_URL"} {
		v := t.env(env)
		if v == "" {
			v = merged["install."+option]
		}
		if v == "" {
			v = merged["global."+option]
		}
		if slices.ContainsFunc(strings.Fields(v), func(one string) bool { return sameHost(one, u) }) {
			return true
		}
	}
	return false
}

// nodeCAFlags reads the options that choose Node's root store. The last of
// --use-bundled-ca and --use-openssl-ca wins; --use-system-ca adds the
// system store to whichever it is.
func nodeCAFlags(t TrustProbe) (bundled, openssl, system bool) {
	for _, opt := range strings.Fields(t.env("NODE_OPTIONS")) {
		switch opt {
		case "--use-bundled-ca":
			bundled, openssl = true, false
		case "--use-openssl-ca":
			bundled, openssl = false, true
		case "--use-system-ca":
			system = true
		}
	}
	if t.env("NODE_USE_SYSTEM_CA") == "1" {
		system = true
	}
	return bundled, openssl, system
}

// npmLayer is what one source of npm's configuration, a file or the
// environment, says about CAs.
type npmLayer struct {
	from string
	// ca is the inline list and caSet whether the source assigns one at all.
	// Set with a nil list is npm's null, which clears the list a lower source
	// gave; a list holding only an empty string is still a list, and replaces
	// Node's defaults with no certificate.
	ca     []string
	caSet  bool
	cafile string
}

// npmFiles lists the npmrc files npm loads, lowest priority first.
func npmFiles(t TrustProbe) []string {
	home := ""
	if t.Home != "" {
		home = t.home()
	}
	return clientconf.NpmConfigFiles(t.Getenv, t.GOOS, home, t.Root)
}

// npmFileLayer reads the top-level ca, ca[] and cafile of an npmrc through
// clientconf.NpmOptions, the decoder the install reads the same file with,
// and clientconf.NpmCAOf, which keeps an absent ca, a null one and an empty
// one apart. A file clientconf.NpmUnread names never gets here: npmStores
// leaves npm unchecked first.
func npmFileLayer(path string) npmLayer {
	l := npmLayer{from: path}
	data, err := os.ReadFile(path)
	if err != nil {
		return l
	}
	opts := clientconf.NpmOptions(data)
	ca := clientconf.NpmCAOf(opts)
	l.caSet, l.ca = ca.Set, ca.List
	for _, o := range opts {
		if o.Key == "cafile" {
			l.cafile = o.Value
		}
	}
	return l
}

var npmEnvRef = regexp.MustCompile(`\$\{([^}]+)\}`)

// npmRegistries lists the registries npm fetches from as its effective
// configuration names them: the default registry, which the environment's
// npm_config_registry gives ahead of every npmrc and the last npmrc to set it
// gives otherwise, and each scope's own registry. A registry named only in an
// npmrc the environment outranks is not one npm asks. Scoped registries set
// through the environment are not read: a variable of unknown name cannot be
// asked for.
func npmRegistries(t TrustProbe, files []string) []string {
	def := ""
	scoped := map[string]string{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, o := range clientconf.NpmOptions(data) {
			v := npmEnvRef.ReplaceAllStringFunc(o.Value, func(ref string) string { return t.env(ref[2 : len(ref)-1]) })
			switch {
			case o.Key == "registry":
				def = v
			case strings.HasSuffix(o.Key, ":registry"):
				scoped[o.Key] = v
			}
		}
	}
	out := []string{def}
	// npm reads the variable under either spelling, so both are candidates.
	var env []string
	for _, key := range []string{"npm_config_registry", "NPM_CONFIG_REGISTRY"} {
		if v := t.env(key); v != "" {
			env = append(env, v)
		}
	}
	if len(env) > 0 {
		out = env
	}
	for _, v := range scoped {
		out = append(out, v)
	}
	return out
}

// npmStores resolves the CAs npm verifies its registry against. npm keeps
// one CA list: each source that sets ca replaces it, and each source whose
// cafile names a file npm can read replaces it with that file's certificates,
// applied from the lowest source to the highest; a cafile naming no readable
// file changes nothing. A ca of null is the one assignment that restores the
// defaults. An empty ca does not: npm hands Node a list holding no
// certificate, which verifies nothing, so the row warns. The sources are the global npmrc, the per-user one
// and then the environment. A list from any of them replaces Node's defaults,
// and NODE_EXTRA_CA_CERTS no longer adds to them.
//
// One source setting both is not resolved here, since the order npm applies
// the two in is the order that source set them, and neither is a line whose
// option cannot be told or a ca or cafile written in a form this reader does
// not take: each leaves npm unchecked, naming what clientconf.NpmUnread
// found, which the install refuses for the same files. A line that could set
// a registry is checked before the registries are, so it leaves npm unchecked
// whether or not another line names bodega.
//
// With none set npm verifies against Node's defaults: the Mozilla roots Node
// bundles, or OpenSSL's store under --use-openssl-ca and in a Node built that
// way, with the system store added under --use-system-ca, and
// NODE_EXTRA_CA_CERTS beside any of them. A private CA in the system store
// is in none of the bundled roots, so the system store's answer settles this
// row only where Node reads that store, and Node lists what it trusts.
func npmStores(t TrustProbe, u *url.URL) []trustStore {
	files := npmFiles(t)
	blind := func(what string) []trustStore {
		return []trustStore{{name: "npm's configuration", blind: fmt.Sprintf("npm reads %s, which doctor detects and does not interpret, so which CA list npm verifies bodega against and whether it verifies bodega's certificate is unchecked", what)}}
	}
	// A line that may set a registry leaves the registries npm asks unknown,
	// and a registry list that cannot be read is no evidence that bodega is
	// absent from it.
	for _, f := range files {
		if line := clientconf.NpmUnclassified(f); line != "" {
			return blind(line)
		}
	}
	if !slices.ContainsFunc(npmRegistries(t, files), func(r string) bool { return sameHost(r, u) }) {
		return nil
	}
	var layers []npmLayer
	for _, f := range files {
		if unread := clientconf.NpmUnread(f); unread != "" {
			return blind(unread)
		}
		layers = append(layers, npmFileLayer(f))
	}
	env := npmLayer{from: "the environment"}
	for _, key := range []string{"NPM_CONFIG_CAFILE", "npm_config_cafile"} {
		if v := t.env(key); v != "" {
			env.cafile, env.from = v, "the environment's "+key
		}
	}
	for _, key := range []string{"NPM_CONFIG_CA", "npm_config_ca"} {
		if v := t.env(key); v != "" {
			env.ca, env.caSet = []string{strings.ReplaceAll(v, `\n`, "\n")}, true
		}
	}
	if env.caSet && env.cafile != "" {
		return blind("npm_config_ca beside npm_config_cafile in the environment, which replace npm's one CA list in an order the environment does not record")
	}
	var store *trustStore
	for _, l := range append(layers, env) {
		switch {
		case !l.caSet:
		case l.ca == nil:
			store = nil
		default:
			store = &trustStore{name: fmt.Sprintf("npm's ca setting in %s, read in place of the roots Node bundles,", l.from), pem: l.ca}
		}
		if file := l.cafile; file != "" {
			if rest, ok := strings.CutPrefix(file, "~/"); ok {
				file = filepath.Join(t.home(), rest)
			}
			if data, err := os.ReadFile(file); err == nil && len(strings.TrimSpace(string(data))) > 0 {
				store = &trustStore{name: fmt.Sprintf("%s, which npm's cafile setting names in %s in place of the roots Node bundles,", file, l.from), files: []string{file}}
			}
		}
	}
	if store != nil {
		return []trustStore{*store}
	}
	var extra []string
	if v := t.env("NODE_EXTRA_CA_CERTS"); v != "" {
		extra = []string{v}
	}
	bundled, openssl, system := nodeCAFlags(t)
	standIn := systemStoreName + ", standing in for the roots Node bundles while no cafile setting names a file,"
	return []trustStore{{name: standIn, resolve: func() trustStore {
		reason := "node is not asked on this host"
		if t.Node != nil {
			roots, err := t.Node()
			switch {
			case err != nil:
				reason = err.Error()
			case openssl || roots.OpenSSLDefault && !bundled:
				return trustStore{name: systemStoreName + ", which this Node reads through OpenSSL in place of the roots it bundles,", system: true, files: extra, pem: roots.PEM}
			case roots.Effective:
				return trustStore{name: "the CA certificates Node trusts by default (the roots it bundles, with what NODE_OPTIONS and NODE_EXTRA_CA_CERTS add), read while no cafile setting names a file,", pem: roots.PEM, files: extra}
			default:
				return trustStore{name: "the roots Node bundles, read while no cafile setting names a file,", pem: roots.PEM, files: extra, system: system}
			}
		}
		switch {
		case openssl:
			return trustStore{name: systemStoreName + ", which Node reads under --use-openssl-ca,", system: true, files: extra}
		case bundled && !system:
			return trustStore{name: "the roots Node bundles, which --use-bundled-ca selects and which hold no private CA,", files: extra}
		case system:
			return trustStore{name: systemStoreName + ", which Node reads beside the roots it bundles under --use-system-ca,", system: true, files: extra}
		}
		return trustStore{name: standIn, system: true, files: extra,
			unsure: fmt.Sprintf("the CA certificates Node trusts by default are not known (%s), and a Node reads the roots it bundles unless it was built or told to read the system trust store, so whether npm verifies bodega's certificate is unchecked while no cafile setting, NODE_EXTRA_CA_CERTS or --use-system-ca in NODE_OPTIONS names what it reads", reason)}
	}}}
}

var gitInsteadOf = regexp.MustCompile(`(?mi)^\s*\[url\s+"([^"]+)"\]`)

// gitStores resolves what git verifies bodega at u against, for a host whose
// configuration rewrites a URL to it: the file the effective http.sslCAInfo
// names, which git reads in place of the system trust store. One store per
// setting git can pick for a URL under each rewritten prefix, since a section
// scoped to a longer URL outranks one scoped to bodega's base for the
// repositories below it. GIT_SSL_CAINFO outranks every file.
func gitStores(t TrustProbe, u *url.URL) []trustStore {
	files := clientconf.GitConfigFiles(t.Getenv, t.Home, t.Root)
	var prefixes []string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, m := range gitInsteadOf.FindAllSubmatch(data, -1) {
			if p, err := url.Parse(string(m[1])); err == nil && p.Host == u.Host && !slices.Contains(prefixes, string(m[1])) {
				prefixes = append(prefixes, string(m[1]))
			}
		}
	}
	// Ahead of everything else: with configuration this probe does not read,
	// neither "git is not pointed at bodega" nor any setting below is known.
	if unread := clientconf.GitUnread(t.Getenv, files); len(unread) > 0 {
		return []trustStore{{name: "git's configuration", blind: fmt.Sprintf("git takes configuration from %s, which doctor does not read, so which http.sslCAInfo git applies to bodega and whether it verifies bodega's certificate is unchecked", strings.Join(unread, "; and from "))}}
	}
	if len(prefixes) == 0 {
		return nil
	}
	if s := envCA(t, "GIT_SSL_CAINFO"); s != nil {
		return []trustStore{*s}
	}
	var out []trustStore
	system := false
	for _, prefix := range prefixes {
		own, narrower := clientconf.GitCAInfo(files, prefix, t.Home)
		if own == nil {
			system = true
		} else {
			narrower = append([]clientconf.GitCA{*own}, narrower...)
		}
		for _, ca := range narrower {
			s := *named(ca.Value, "http.sslCAInfo of "+ca.Header+" in "+ca.File, true)
			if !slices.ContainsFunc(out, func(o trustStore) bool { return o.name == s.name }) {
				out = append(out, s)
			}
		}
	}
	if system {
		out = append(out, trustStore{name: systemStoreName, system: true})
	}
	return out
}

// helmStores resolves what helm verifies bodega at u against: the caFile of
// each repository entry at that host, which helm reads in place of the system
// trust store, and that store for an entry naming none.
func helmStores(t TrustProbe, u *url.URL) []trustStore {
	path := t.env("HELM_REPOSITORY_CONFIG")
	if path == "" {
		dir := t.env("HELM_CONFIG_HOME")
		switch {
		case dir != "":
		case t.Home == "":
			return nil
		case t.GOOS == "darwin":
			dir = filepath.Join(t.Home, "Library", "Preferences", "helm")
		case t.env("XDG_CONFIG_HOME") != "":
			dir = filepath.Join(t.env("XDG_CONFIG_HOME"), "helm")
		default:
			dir = filepath.Join(t.Home, ".config", "helm")
		}
		path = filepath.Join(dir, "repositories.yaml")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc struct {
		Repositories []struct {
			Name   string `yaml:"name"`
			URL    string `yaml:"url"`
			CAFile string `yaml:"caFile"`
		} `yaml:"repositories"`
	}
	if yaml.Unmarshal(data, &doc) != nil {
		return nil
	}
	var out []trustStore
	for _, r := range doc.Repositories {
		if p, err := url.Parse(r.URL); err != nil || p.Host != u.Host {
			continue
		}
		s := trustStore{name: systemStoreName, system: true}
		if r.CAFile != "" {
			s = *named(r.CAFile, "caFile of the repository "+r.Name+" in "+path, true)
		}
		if !slices.ContainsFunc(out, func(o trustStore) bool { return o.name == s.name }) {
			out = append(out, s)
		}
	}
	return out
}

// containerdStores is one store per registry whose hosts.toml sends pulls to
// bodega: containerd adds the ca of that host table to the system store, and
// a ca set for docker.io verifies nothing for ghcr.io. The hosts.toml files
// are the ones containerd loads: under each root of the effective
// config_path, the first root holding a directory for the registry.
func containerdStores(t TrustProbe, u *url.URL) []trustStore {
	roots := []string{clientconf.ContainerdCertsDir}
	if data, err := os.ReadFile(filepath.Join(t.Root, clientconf.ContainerdConfigPath)); err == nil {
		if cfg, err := clientconf.ResolveContainerdConfig(t.Root, clientconf.ContainerdConfigPath, data); err == nil && cfg.ConfigPath != "" {
			roots = strings.Split(cfg.ConfigPath, ":")
		}
	}
	var out []trustStore
	seen := map[string]bool{}
	for _, r := range roots {
		if r == "" {
			continue
		}
		dirs, _ := filepath.Glob(filepath.Join(t.Root, r, "*"))
		for _, dir := range dirs {
			if info, err := os.Stat(dir); err != nil || !info.IsDir() || seen[filepath.Base(dir)] {
				continue
			}
			seen[filepath.Base(dir)] = true
			path := filepath.Join(dir, "hosts.toml")
			var doc struct {
				Host map[string]struct {
					CA any `toml:"ca"`
				} `toml:"host"`
			}
			if _, err := toml.DecodeFile(path, &doc); err != nil {
				continue
			}
			for name, table := range doc.Host {
				if !mirrorIsBodega(name, u.Host) {
					continue
				}
				var cas []string
				switch v := table.CA.(type) {
				case string:
					cas = []string{v}
				case []any:
					for _, e := range v {
						if s, ok := e.(string); ok {
							cas = append(cas, s)
						}
					}
				}
				for i, ca := range cas {
					if !filepath.IsAbs(ca) {
						cas[i] = filepath.Join(dir, ca)
					}
				}
				out = append(out, trustStore{name: "the ca of " + path, system: true, files: cas})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// filesMention reports whether a file matching one of the patterns, each
// under Root, names host.
func (t TrustProbe) filesMention(host string, patterns ...string) bool {
	for _, p := range patterns {
		files, _ := filepath.Glob(filepath.Join(t.Root, p))
		if mention(host, files...) {
			return true
		}
	}
	return false
}

// mention reports whether any of the files names host. A file that will not
// read names nothing: the row above this probe already reported on it.
func mention(host string, files ...string) bool {
	for _, f := range files {
		if data, err := os.ReadFile(f); err == nil && strings.Contains(string(data), host) {
			return true
		}
	}
	return false
}

// TrustState is what a probe could establish about one client.
type TrustState int

const (
	// TrustAbsent: nothing the client reads sends it to bodega.
	TrustAbsent TrustState = iota
	// TrustVerified: every store the client reads for bodega verifies the
	// certificate bodega serves.
	TrustVerified
	// TrustUnchecked: what the client reads could not be determined. It is
	// not a pass.
	TrustUnchecked
	// TrustFailed: a store the client reads does not verify the certificate.
	TrustFailed
)

// TrustVerdict is the outcome for one check's client, with the reason for
// one that is unchecked or failed.
type TrustVerdict struct {
	Check, System string
	State         TrustState
	Detail        string
}

// served dials base once and holds what it presented and how the system
// store judged it.
type served struct {
	t         TrustProbe
	u         *url.URL
	done      bool
	chain     []*x509.Certificate
	systemErr error
	err       error
}

func (s *served) get() error {
	if s.done {
		return s.err
	}
	s.done = true
	hostport := s.u.Host
	if s.u.Port() == "" {
		hostport = net.JoinHostPort(s.u.Hostname(), "443")
	}
	dial, system := s.t.Chain, s.t.System
	if dial == nil {
		dial = dialChain
	}
	if system == nil {
		system = VerifySystem
	}
	if s.chain, s.err = dial(hostport); s.err == nil && len(s.chain) == 0 {
		s.err = errors.New("the server presented no certificate")
	}
	if s.err == nil {
		s.systemErr = system(s.chain, s.u.Hostname())
	}
	return s.err
}

// weigh verifies the served chain against each store. failed names the
// stores that do not verify it, and unread the ones nothing could be said
// about, each with its reason.
func (s *served) weigh(stores []trustStore) (failed, unread []string) {
	for _, st := range stores {
		if st.blind != "" {
			unread = append(unread, st.blind)
			continue
		}
		if st.resolve != nil {
			st = st.resolve()
		}
		if st.system && s.systemErr == nil && st.unsure == "" {
			continue
		}
		pool := poolOf(st.files)
		for _, p := range st.pem {
			pool.AppendCertsFromPEM([]byte(p))
		}
		verr := verifyChain(s.chain, s.u.Hostname(), pool)
		if verr == nil {
			continue
		}
		if st.system && s.systemErr == nil {
			unread = append(unread, st.unsure)
			continue
		}
		switch {
		case !st.system:
			failed = append(failed, fmt.Sprintf("%s does not verify the certificate it serves (%v)", st.name, verr))
		case st.name == systemStoreName || strings.HasPrefix(st.name, systemStoreName+","):
			failed = append(failed, fmt.Sprintf("%s does not verify the certificate it serves (%v)", st.name, s.systemErr))
		default:
			failed = append(failed, fmt.Sprintf("neither %s nor %s verifies the certificate it serves (%v)", systemStoreName, st.name, s.systemErr))
		}
	}
	return failed, unread
}

// Apply returns findings with a warning on each row whose client is
// configured for bodega at base and cannot verify the certificate base
// serves, judged against the stores that client reads as this host
// configures it. The system trust store settles a store only where the
// client reads it there: a cafile or a cert bundle that replaces it is
// verified on its own. A row already warning keeps its finding and
// gains this one, since a client can both bypass bodega for one scope and
// refuse its certificate for the rest.
//
// A row whose client could not be judged warns too, naming the input that
// stood in the way: a store no command would list, a client that could not
// say which store it reads, configuration the environment turns off or
// supplies from where this probe does not look. Unchecked is not verified,
// and a row reading OK would say it was.
//
// The rows come back unchanged when base is not https, and when the server
// does not answer: an unreachable bodega is not a certificate nobody trusts.
func (t TrustProbe) Apply(findings []Finding, base string) []Finding {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return findings
	}
	srv := &served{t: t, u: u}
	out := make([]Finding, len(findings))
	for i, f := range findings {
		out[i] = f
		row, ok := trustRows[f.Check]
		if !ok || (f.Status != StatusOK && f.Status != StatusWarn) {
			continue
		}
		stores := row.stores(t, u)
		if len(stores) == 0 {
			continue
		}
		if srv.get() != nil {
			return findings
		}
		failed, unread := srv.weigh(stores)
		if len(failed)+len(unread) == 0 {
			continue
		}
		install := fmt.Sprintf("bodega doctor --configure %s --ca-file <CA certificate PEM> --apply --url %s", row.system, strings.TrimRight(base, "/"))
		detail := strings.Join(unread, "; ")
		remedy := "remove what keeps doctor from reading this client's trust (named above) and re-run doctor; where the client then refuses bodega's certificate, install the CA that issued it: " + install
		if len(failed) > 0 {
			detail = strings.TrimPrefix(detail+"; ", "; ") + fmt.Sprintf("configured for bodega at %s, and %s, so every fetch fails on the certificate", u.Host, strings.Join(failed, "; and "))
			remedy = "install the CA that issued bodega's certificate: " + install
		}
		out[i].Status = StatusWarn
		switch {
		case f.Status == StatusWarn:
			out[i].Detail = f.Detail + "; also " + detail
			out[i].Remediation = strings.TrimPrefix(f.Remediation+"; "+remedy, "; ")
		case len(failed) == 0:
			out[i].Detail = strings.TrimPrefix(f.Detail+"; "+detail, "; ")
			out[i].Remediation = remedy
		default:
			out[i].Detail, out[i].Remediation = detail, remedy
		}
	}
	return out
}

// Judge returns a verdict for the client of each named check, for a caller
// that owes one whether or not the client turns out to be configured: after
// a CA install, a client reading nothing that names bodega is a client the
// install did not reach, which Apply, reporting on rows, has no row to say.
// It errs when base is not https or its server does not answer, where
// nothing was judged.
func (t TrustProbe) Judge(checks []string, base string) ([]TrustVerdict, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("%s is not an https URL, so no client verifies a certificate there", base)
	}
	srv := &served{t: t, u: u}
	var out []TrustVerdict
	for _, check := range checks {
		row, ok := trustRows[check]
		if !ok {
			continue
		}
		v := TrustVerdict{Check: check, System: row.system}
		if stores := row.stores(t, u); len(stores) > 0 {
			if err := srv.get(); err != nil {
				return nil, fmt.Errorf("%s did not present a certificate to verify: %w", u.Host, err)
			}
			failed, unread := srv.weigh(stores)
			switch {
			case len(failed) > 0:
				v.State, v.Detail = TrustFailed, strings.Join(append(failed, unread...), "; ")
			case len(unread) > 0:
				v.State, v.Detail = TrustUnchecked, strings.Join(unread, "; ")
			default:
				v.State = TrustVerified
			}
		}
		out = append(out, v)
	}
	return out, nil
}

// poolOf reads the PEM files into a pool. A file that will not read, or
// holds no certificate, adds nothing, which leaves the chain unverified and
// the row warned.
func poolOf(files []string) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, f := range files {
		if data, err := os.ReadFile(f); err == nil {
			pool.AppendCertsFromPEM(data)
		}
	}
	return pool
}

// verifyChain verifies a served chain, leaf first, for dnsName against roots,
// or against the system trust store when roots is nil.
func verifyChain(chain []*x509.Certificate, dnsName string, roots *x509.CertPool) error {
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{DNSName: dnsName, Roots: roots, Intermediates: inter})
	return err
}

// VerifyServed verifies chain for dnsName against roots alone: the name, the
// lifetime, the constraints and each signature, as a client holding those
// roots would.
func VerifyServed(chain []*x509.Certificate, dnsName string, roots []*x509.Certificate) error {
	pool := x509.NewCertPool()
	for _, c := range roots {
		pool.AddCert(c)
	}
	return verifyChain(chain, dnsName, pool)
}

// VerifySystem verifies chain for dnsName against the operating system's
// trust store as this process loaded it.
func VerifySystem(chain []*x509.Certificate, dnsName string) error {
	return verifyChain(chain, dnsName, nil)
}

// dialChain completes a TLS handshake with hostport and returns what it
// presented. Verification is off for the handshake because the chain is the
// thing being measured: Apply verifies it against each store by hand, and
// nothing is sent over the connection.
func dialChain(hostport string) ([]*x509.Certificate, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", hostport,
		&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // see the comment above
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return conn.ConnectionState().PeerCertificates, nil
}

// TrustSystems maps each doctor row TrustProbe judges to the --configure
// system that installs a CA for its client.
func TrustSystems() map[string]string {
	out := make(map[string]string, len(trustRows))
	for check, row := range trustRows {
		out[check] = row.system
	}
	return out
}

// AskNode and AskPip are the answers doctor has for a host's Node and pip
// without running either: none. The roots a Node bundles and whether it was
// built onto OpenSSL's store are compiled into its binary, and which bundle a
// pip reads follows from its version and its interpreter. Starting node or
// pip to ask would run a program found on PATH, with whatever NODE_OPTIONS or
// a .pth file loads into it, under doctor's privileges, so a trust verdict
// never rests on one. The row says what it left unchecked instead.
func AskNode() (NodeRoots, error) {
	return NodeRoots{}, errors.New("doctor does not run node to list them")
}

func AskPip() (PipDefault, error) {
	return PipDefault{}, errors.New("doctor does not run pip to ask")
}
