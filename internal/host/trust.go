package host

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
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
	// DnfConf is dnf's main configuration file and DnfDirs the directories
	// it reads .repo files from when that file sets no reposdir. Empty reads
	// dnf's own, under Root.
	DnfConf string
	DnfDirs []string
	// Chain returns the certificates the server at hostport presents, leaf
	// first, without verifying them. Nil dials it.
	Chain func(hostport string) ([]*x509.Certificate, error)
	// System verifies a chain for dnsName against the operating system's
	// trust store. Nil uses the store this process reads.
	System func(chain []*x509.Certificate, dnsName string) error
	// JVM names the trust store of the JVM Maven and Gradle run on and lists
	// its certificates. Nil asks that JVM's keytool.
	JVM func() (name string, certs []*x509.Certificate, err error)
	// Node lists the CA certificates the host's Node trusts by default, and
	// Pip names the bundle the host's pip reads when no setting names one:
	// neither is a file doctor can find without asking. Nil is a host where
	// the client cannot be asked, and the row then says what it left
	// unchecked.
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
	// replaces the client's defaults, or a keystore.
	system bool
	// files are the PEM files the store reads, and pem certificates a
	// setting carries inline.
	files []string
	pem   []string
	// load names and lists a store only a command can read. It runs after
	// bodega has answered, so a host with nothing to verify starts no command.
	load func() (name string, certs []*x509.Certificate, err error)
	// unsure is why the system store verifying does not settle this store:
	// the client could not be asked whether it reads that store at all. The
	// row then keeps its status and says so.
	unsure string
	// resolve replaces the store with the one a command names. Like load it
	// runs only once bodega has answered.
	resolve func() trustStore
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

// systemOnly is the row of a client that verifies through the system trust
// store unless a setting of its own names another, configured when mentions
// says its configuration names host. own returns that other store, and nil
// for a client left on the system store.
func systemOnly(system string, mentions func(t TrustProbe, host string) bool, own func(t TrustProbe) *trustStore) trustRow {
	return trustRow{system: system, stores: func(t TrustProbe, u *url.URL) []trustStore {
		if !mentions(t, u.Host) {
			return nil
		}
		if own != nil {
			if s := own(t); s != nil {
				return []trustStore{*s}
			}
		}
		return []trustStore{{name: systemStoreName, system: true}}
	}}
}

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

var (
	gemCACert = regexp.MustCompile(`(?m)^:?ssl_ca_cert:\s*["']?([^"'\s#]+)`)
)

// firstMatch is the first capture of re in the files, and the file it is in.
func firstMatch(re *regexp.Regexp, files ...string) (value, file string) {
	for _, f := range files {
		if data, err := os.ReadFile(f); err == nil {
			if m := re.FindSubmatch(data); m != nil {
				return string(m[1]), f
			}
		}
	}
	return "", ""
}

// trustRows maps a row's check name to its client.
var trustRows = map[string]trustRow{
	"apt-sources": {system: manifest.TypeApt, stores: aptStores},
	"dnf-repos": {system: manifest.TypeRpm, stores: func(t TrustProbe, u *url.URL) []trustStore {
		// The repositories dnf loads, reposdir included, not a directory
		// scan: a .repo file dnf never reads configures nothing. One
		// store per repository, since sslcacert is set per repository.
		var out []trustStore
		for _, r := range t.dnfRepos() {
			if !r.Enabled || !slices.ContainsFunc(r.URLs, func(l string) bool { return strings.Contains(l, u.Host) }) {
				continue
			}
			s := trustStore{name: systemStoreName, system: true}
			if r.CACert != "" {
				s = *named(r.CACert, "sslcacert of ["+r.ID+"] in "+r.File, true)
			}
			if !slices.ContainsFunc(out, func(o trustStore) bool { return o.name == s.name }) {
				out = append(out, s)
			}
		}
		return out
	}},
	// pkg and fetch(1) verify through libfetch, which reads
	// SSL_CA_CERT_FILE in place of the system store when it is set.
	"pkg-repos": systemOnly(manifest.TypeFreeBSD, func(t TrustProbe, host string) bool {
		return t.filesMention(host, "/usr/local/etc/pkg/repos/*.conf")
	}, func(t TrustProbe) *trustStore { return envCA(t, "SSL_CA_CERT_FILE") }),
	"make-conf": systemOnly(manifest.TypeDistfiles, func(t TrustProbe, host string) bool {
		return t.filesMention(host, "/etc/make.conf")
	}, func(t TrustProbe) *trustStore { return envCA(t, "SSL_CA_CERT_FILE") }),
	"cargo-config": systemOnly(manifest.TypeCargo, func(t TrustProbe, host string) bool {
		return mention(host, filepath.Join(t.Home, ".cargo", "config.toml"), filepath.Join(t.Home, ".cargo", "config"))
	}, func(t TrustProbe) *trustStore {
		if s := envCA(t, "CARGO_HTTP_CAINFO"); s != nil {
			return s
		}
		// Cargo reads the file without the extension when both exist.
		for _, f := range []string{filepath.Join(t.Home, ".cargo", "config"), filepath.Join(t.Home, ".cargo", "config.toml")} {
			var doc struct {
				HTTP struct {
					CAInfo string `toml:"cainfo"`
				} `toml:"http"`
			}
			if _, err := toml.DecodeFile(f, &doc); err != nil {
				continue
			}
			if doc.HTTP.CAInfo != "" {
				return named(doc.HTTP.CAInfo, "http.cainfo in "+f, true)
			}
			break
		}
		return nil
	}),
	// gem adds ssl_ca_cert to OpenSSL's default paths; it replaces nothing.
	"rubygems": systemOnly(manifest.TypeRubygems, func(t TrustProbe, host string) bool {
		return mention(host, filepath.Join(t.Home, ".gemrc"), filepath.Join(t.Home, ".bundle", "config"))
	}, func(t TrustProbe) *trustStore {
		if v, f := firstMatch(gemCACert, filepath.Join(t.Home, ".gemrc")); v != "" {
			return named(v, "ssl_ca_cert in "+f, false)
		}
		return nil
	}),
	"composer": systemOnly(manifest.TypeComposer, func(t TrustProbe, host string) bool {
		return mention(host, filepath.Join(clientconf.HostComposerHome(t.Home), "config.json"))
	}, func(t TrustProbe) *trustStore {
		path := filepath.Join(clientconf.HostComposerHome(t.Home), "config.json")
		var doc struct {
			Config struct {
				CAFile string `json:"cafile"`
			} `json:"config"`
		}
		if data, err := os.ReadFile(path); err == nil && json.Unmarshal(data, &doc) == nil && doc.Config.CAFile != "" {
			return named(doc.Config.CAFile, "cafile in "+path, true)
		}
		return nil
	}),
	"goproxy-env": systemOnly(manifest.TypeGomod, func(t TrustProbe, host string) bool {
		if strings.Contains(t.env("GOPROXY"), host) {
			return true
		}
		if t.ConfigDir == nil {
			return false
		}
		file, err := goEnvFile(t.env, t.ConfigDir)
		return err == nil && file != "" && mention(host, file)
	}, nil),
	// git and helm have no row in the report; these judge them after a CA
	// install, which answers for every client it configured.
	"git-config":                          {system: manifest.TypeGit, stores: gitStores},
	"helm-repos":                          {system: manifest.TypeHelm, stores: helmStores},
	"pip-config":                          {system: manifest.TypePypi, stores: pipStores},
	"npm-config":                          {system: manifest.TypeNpm, stores: npmStores},
	"maven":                               {system: manifest.TypeMaven, stores: mavenStores},
	"oci-" + clientconf.RuntimeContainerd: {system: manifest.TypeOCI, stores: containerdStores},
	"oci-" + clientconf.RuntimeDocker: {system: manifest.TypeOCI, stores: func(t TrustProbe, u *url.URL) []trustStore {
		if !t.filesMention(u.Host, clientconf.DockerDaemonPath) {
			return nil
		}
		return []trustStore{certsDir(filepath.Join(t.Root, "/etc/docker/certs.d", u.Host))}
	}},
	"oci-" + clientconf.RuntimePodman: {system: manifest.TypeOCI, stores: func(t TrustProbe, u *url.URL) []trustStore {
		user := filepath.Join(t.Home, ".config", "containers")
		configured := t.filesMention(u.Host, "/etc/containers/registries.conf", "/etc/containers/registries.conf.d/*.conf")
		if !configured && t.Home != "" {
			drop, _ := filepath.Glob(filepath.Join(user, "registries.conf.d", "*.conf"))
			configured = mention(u.Host, append(drop, filepath.Join(user, "registries.conf"))...)
		}
		if !configured {
			return nil
		}
		// The one directory containers/image picks, not every candidate: an
		// existing per-user directory hides the system one even when it holds
		// no certificate.
		dir := clientconf.PodmanCertDir(t.Home, t.Root, u.Host)
		if dir == "" {
			return []trustStore{{name: systemStoreName + ", which podman reads alone while no certs.d directory exists for " + u.Host + ",", system: true}}
		}
		store := certsDir(dir)
		return []trustStore{store}
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
// Docker and podman add to the system store.
func certsDir(dir string) trustStore {
	files, _ := filepath.Glob(filepath.Join(dir, "*.crt"))
	return trustStore{name: dir, system: true, files: files}
}

// dnfRepos is every repository dnf loads on the host.
func (t TrustProbe) dnfRepos() []clientconf.YumRepo {
	conf, dirs := t.DnfConf, t.DnfDirs
	if conf == "" {
		conf = filepath.Join(t.Root, clientconf.DnfMainConf)
	}
	if dirs == nil {
		dirs = rooted(t.Root, clientconf.YumReposDirs)
	}
	loaded, err := clientconf.ReadDnfConfig(conf, dirs)
	if err != nil {
		return nil
	}
	return loaded.Repos
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
		h.Home = filepath.Join(t.Root, t.Home)
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
	if !mention(u.Host, files...) && !strings.Contains(t.env("PIP_INDEX_URL"), u.Host) {
		return nil
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
		system.unsure = fmt.Sprintf("pip could not say which bundle it reads (%s), and a pip before 24.2 reads certifi's, which the system trust store's answer says nothing about, so whether pip verifies bodega's certificate is unchecked", reason)
		return system
	}}}
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
	// ca is the inline list and caSet whether the source assigns one at all,
	// since an empty assignment clears the list a lower source gave.
	ca     []string
	caSet  bool
	cafile string
	// caLast says ca was first assigned after cafile, which is the order
	// npm applies the two in.
	caLast bool
}

// npmFiles lists the npmrc files npm loads, lowest priority first. An
// environment variable naming the global or the per-user file replaces the
// default path: npm then never opens the file it would have.
func npmFiles(t TrustProbe) []string {
	env := func(key string) string {
		if v := t.env("npm_config_" + key); v != "" {
			return v
		}
		return t.env("NPM_CONFIG_" + strings.ToUpper(key))
	}
	files := rooted(t.Root, npmPaths(t.GOOS, ""))
	if v := env("globalconfig"); v != "" {
		files = []string{v}
	}
	switch v := env("userconfig"); {
	case v != "":
		files = append(files, v)
	case t.Home != "":
		files = append(files, filepath.Join(t.Root, t.Home, ".npmrc"))
	}
	return files
}

// npmFileLayer reads the top-level ca, ca[] and cafile of an npmrc as npm's
// ini reader does: ca[] appends to a list, a plain ca replaces it, and a
// quoted value is unescaped.
func npmFileLayer(path string) npmLayer {
	l := npmLayer{from: path}
	data, err := os.ReadFile(path)
	if err != nil {
		return l
	}
	value := func(v string) string {
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = strings.ReplaceAll(v[1:len(v)-1], `\n`, "\n")
		}
		return v
	}
	fileSeen := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' && strings.HasSuffix(line, "]") {
			break
		}
		k, v, _ := strings.Cut(line, "=")
		switch k = strings.TrimSpace(k); k {
		case "cafile":
			l.cafile, fileSeen = value(v), true
		case "ca", "ca[]":
			if !l.caSet {
				l.caSet, l.caLast = true, fileSeen
			}
			if k == "ca" {
				l.ca = nil
			}
			if v = value(v); v != "" {
				l.ca = append(l.ca, v)
			}
		}
	}
	return l
}

// npmStores resolves the CAs npm verifies its registry against. npm keeps
// one CA list: each source that sets ca replaces it, and each source whose
// cafile names a file npm can read replaces it with that file's certificates,
// applied from the lowest source to the highest and inside one source in the
// order the two were first set. So a cafile after a ca[] in one npmrc drops
// the inline certificates, a ca after a cafile drops the file, and a cafile
// naming no readable file changes nothing. The sources are the global npmrc,
// the per-user one and then the environment. A list from any of them replaces
// Node's defaults, and NODE_EXTRA_CA_CERTS no longer adds to them.
//
// With none set npm verifies against Node's defaults: the Mozilla roots Node
// bundles, or OpenSSL's store under --use-openssl-ca and in a Node built that
// way, with the system store added under --use-system-ca, and
// NODE_EXTRA_CA_CERTS beside any of them. A private CA in the system store
// is in none of the bundled roots, so the system store's answer settles this
// row only where Node reads that store, and Node lists what it trusts.
func npmStores(t TrustProbe, u *url.URL) []trustStore {
	files := npmFiles(t)
	if !mention(u.Host, files...) {
		return nil
	}
	var layers []npmLayer
	for _, f := range files {
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
	var store *trustStore
	for _, l := range append(layers, env) {
		inline := func() {
			switch {
			case !l.caSet:
			case len(l.ca) == 0:
				store = nil
			default:
				store = &trustStore{name: fmt.Sprintf("npm's ca setting in %s, read in place of the roots Node bundles,", l.from), pem: l.ca}
			}
		}
		if !l.caLast {
			inline()
		}
		if file := l.cafile; file != "" {
			if rest, ok := strings.CutPrefix(file, "~/"); ok {
				file = filepath.Join(t.Root, t.Home, rest)
			}
			if data, err := os.ReadFile(file); err == nil && len(strings.TrimSpace(string(data))) > 0 {
				store = &trustStore{name: fmt.Sprintf("%s, which npm's cafile setting names in %s in place of the roots Node bundles,", file, l.from), files: []string{file}}
			}
		}
		if l.caLast {
			inline()
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
			unsure: fmt.Sprintf("node could not list the CA certificates it trusts (%s), and a Node reads the roots it bundles unless it was built or told to read the system trust store, so whether npm verifies bodega's certificate is unchecked", reason)}
	}}}
}

// mavenStores is the one store the JVM reads, for a host whose Maven mirror
// or Gradle init script names bodega.
func mavenStores(t TrustProbe, u *url.URL) []trustStore {
	if t.Home == "" {
		return nil
	}
	gradleHome := t.env("GRADLE_USER_HOME")
	if gradleHome == "" {
		gradleHome = filepath.Join(t.Home, ".gradle")
	}
	mirror, _, _ := mavenMirror(filepath.Join(t.Home, ".m2", "settings.xml"))
	repo, _ := gradleInitURL(filepath.Join(gradleHome, "init.d", "bodega.gradle"))
	if !strings.Contains(mirror, u.Host) && !strings.Contains(repo, u.Host) {
		return nil
	}
	jvm := t.JVM
	if jvm == nil {
		jvm = func() (string, []*x509.Certificate, error) {
			store, err := clientconf.ResolveJVMStore(t.env, exec.LookPath)
			if err != nil {
				return "the JVM trust store", nil, err
			}
			certs, err := store.Trusted()
			return store.Name(), certs, err
		}
	}
	return []trustStore{{name: "the JVM trust store", load: func() (string, []*x509.Certificate, error) {
		name, certs, err := jvm()
		return name + ", which Maven and Gradle read in place of the system trust store,", certs, err
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

// Apply returns findings with a warning on each row whose client is
// configured for bodega at base and cannot verify the certificate base
// serves, judged against the stores that client reads as this host
// configures it. The system trust store settles a store only where the
// client reads it there: a cafile, a cert bundle or a keystore that replaces
// it is verified on its own. A row already warning keeps its finding and
// gains this one, since a client can both bypass bodega for one scope and
// refuse its certificate for the rest.
//
// The rows come back unchanged when base is not https, and when the server
// does not answer: an unreachable bodega is not a certificate nobody trusts.
func (t TrustProbe) Apply(findings []Finding, base string) []Finding {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return findings
	}
	var chain []*x509.Certificate
	var systemErr error
	probed := false
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
		if !probed {
			probed = true
			hostport := u.Host
			if u.Port() == "" {
				hostport = net.JoinHostPort(u.Hostname(), "443")
			}
			dial, system := t.Chain, t.System
			if dial == nil {
				dial = dialChain
			}
			if system == nil {
				system = func(chain []*x509.Certificate, name string) error { return verifyChain(chain, name, nil) }
			}
			if chain, err = dial(hostport); err != nil || len(chain) == 0 {
				return findings
			}
			systemErr = system(chain, u.Hostname())
		}
		var failed, unread []string
		for _, s := range stores {
			if s.resolve != nil {
				s = s.resolve()
			}
			if s.system && systemErr == nil && s.unsure == "" {
				continue
			}
			pool := poolOf(s.files)
			for _, p := range s.pem {
				pool.AppendCertsFromPEM([]byte(p))
			}
			if s.load != nil {
				name, certs, err := s.load()
				s.name = name
				if err != nil {
					unread = append(unread, fmt.Sprintf("%s was not read (%v), so whether this client verifies bodega's certificate is unchecked", strings.TrimSuffix(s.name, ","), err))
					continue
				}
				for _, c := range certs {
					pool.AddCert(c)
				}
			}
			verr := verifyChain(chain, u.Hostname(), pool)
			if verr == nil {
				continue
			}
			if s.system && systemErr == nil {
				unread = append(unread, s.unsure)
				continue
			}
			switch {
			case !s.system:
				failed = append(failed, fmt.Sprintf("%s does not verify the certificate it serves (%v)", s.name, verr))
			case s.name == systemStoreName || strings.HasPrefix(s.name, systemStoreName+","):
				failed = append(failed, fmt.Sprintf("%s does not verify the certificate it serves (%v)", s.name, systemErr))
			default:
				failed = append(failed, fmt.Sprintf("neither %s nor %s verifies the certificate it serves (%v)", systemStoreName, s.name, systemErr))
			}
		}
		var detail, remedy string
		if len(failed) > 0 {
			detail = fmt.Sprintf("configured for bodega at %s, and %s, so every fetch fails on the certificate", u.Host, strings.Join(failed, "; and "))
			remedy = fmt.Sprintf("install the CA that issued bodega's certificate: bodega doctor --configure %s --ca-file <CA certificate PEM> --apply --url %s",
				row.system, strings.TrimRight(base, "/"))
			out[i].Status = StatusWarn
		}
		if len(unread) > 0 {
			detail = strings.Join(append(unread, detail), "; ")
			detail = strings.TrimSuffix(detail, "; ")
		}
		switch {
		case detail == "":
		case f.Status == StatusWarn:
			out[i].Detail = f.Detail + "; also " + detail
			if remedy != "" {
				out[i].Remediation = strings.TrimPrefix(f.Remediation+"; "+remedy, "; ")
			}
		case len(failed) == 0:
			out[i].Detail = strings.TrimPrefix(f.Detail+"; "+detail, "; ")
		default:
			out[i].Detail, out[i].Remediation = detail, remedy
		}
	}
	return out
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

// nodeRootsScript prints what this Node trusts by default. getCACertificates
// answers for the options and environment the process started with; a Node
// that predates it can only list the roots it bundles.
const nodeRootsScript = `const tls=require("tls");` +
	`const o={openssl:!!process.config.variables.openssl_use_def_ca_store,effective:!!tls.getCACertificates};` +
	`o.pem=o.effective?tls.getCACertificates("default"):tls.rootCertificates;` +
	`process.stdout.write(JSON.stringify(o))`

// AskNode asks the node on PATH, started in this process's environment as
// npm would start it, which CA certificates it trusts by default.
func AskNode() (NodeRoots, error) {
	path, err := exec.LookPath("node")
	if err != nil {
		return NodeRoots{}, errors.New("no node on PATH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "-e", nodeRootsScript).Output()
	if err != nil {
		return NodeRoots{}, fmt.Errorf("%s did not list them: %w", path, err)
	}
	var doc struct {
		PEM       []string `json:"pem"`
		Effective bool     `json:"effective"`
		OpenSSL   bool     `json:"openssl"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return NodeRoots{}, fmt.Errorf("%s printed no list: %w", path, err)
	}
	return NodeRoots{PEM: doc.PEM, Effective: doc.Effective, OpenSSLDefault: doc.OpenSSL}, nil
}

var pipVersionLine = regexp.MustCompile(`^pip (\d+)\.(\d+)\S* from (.+) \(python (\d+)\.(\d+)\)`)

// AskPip asks the pip on PATH for its version and where it is installed,
// which between them say what it verifies against with no cert setting.
func AskPip() (PipDefault, error) {
	for _, name := range []string{"pip3", "pip"} {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, path, "--version").Output()
		if err != nil {
			return PipDefault{}, fmt.Errorf("%s --version: %w", path, err)
		}
		d, err := pipDefaultFrom(string(out))
		if err != nil {
			return d, err
		}
		// config debug lists each file pip would load; the one under "site"
		// sits in the interpreter's prefix. A pip too old for the command
		// leaves the prefix unknown.
		if out, err := exec.CommandContext(ctx, path, "config", "debug").Output(); err == nil {
			d.Prefix = pipSitePrefix(string(out))
		}
		return d, nil
	}
	return PipDefault{}, errors.New("no pip on PATH")
}

// pipSitePrefix reads the directory of the site configuration file out of
// `pip config debug`, "" when the output names none.
func pipSitePrefix(debug string) string {
	lines := strings.Split(debug, "\n")
	for i, l := range lines[:max(len(lines)-1, 0)] {
		if strings.TrimSpace(l) != "site:" {
			continue
		}
		if file, _, ok := strings.Cut(strings.TrimSpace(lines[i+1]), ", exists:"); ok && filepath.IsAbs(file) {
			return filepath.Dir(file)
		}
	}
	return ""
}

// pipDefaultFrom reads a `pip --version` line. pip verifies through the
// system store by default from 24.2 on, where Python is 3.10 or later, and
// against the certifi bundle vendored beside it before that.
func pipDefaultFrom(version string) (PipDefault, error) {
	line, _, _ := strings.Cut(strings.TrimSpace(version), "\n")
	m := pipVersionLine.FindStringSubmatch(line)
	if m == nil {
		return PipDefault{}, fmt.Errorf("pip --version printed %q, which names no version and location", line)
	}
	n := func(s string) int { v, _ := strconv.Atoi(s); return v }
	major, minor, pyMajor, pyMinor := n(m[1]), n(m[2]), n(m[4]), n(m[5])
	d := PipDefault{
		Version:    m[1] + "." + m[2],
		Truststore: (major > 24 || major == 24 && minor >= 2) && (pyMajor > 3 || pyMajor == 3 && pyMinor >= 10),
	}
	bundle := filepath.Join(m[3], "_vendor", "certifi", "cacert.pem")
	if info, err := os.Stat(bundle); err == nil && info.Mode().IsRegular() {
		d.Certifi = bundle
	}
	return d, nil
}
