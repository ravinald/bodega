package host

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

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
// another proxy configures nothing. A list the go command refuses reaches
// nothing, bodega included, whatever its first entry names: the row keeps its
// obligation and is left unchecked.
func goStores(t TrustProbe, u *url.URL) []trustStore {
	configDir := t.ConfigDir
	if configDir == nil {
		configDir = func() (string, error) { return "", errors.New("no user config directory") }
	}
	set := effectiveGoproxy(t.env, configDir)
	if set.err != nil {
		return []trustStore{{name: "the go command's GOPROXY", blind: fmt.Sprintf("the go command refuses the GOPROXY list from %s (%v) before it asks any proxy, so whether go reaches bodega or verifies its certificate is unchecked", set.source, set.err)}}
	}
	if !slices.ContainsFunc(set.reached, func(entry string) bool { return namesHost(entry, u.Host) }) {
		return nil
	}
	return []trustStore{t.systemStore()}
}

// trustRows maps a row's check name to its client.
var trustRows = map[string]trustRow{
	"apt-sources": {system: manifest.TypeApt, stores: aptStores},
	"goproxy-env": {system: manifest.TypeGomod, stores: goStores},
	// Rows gives git and helm their row; no inventory check writes one.
	"git-config":                          {system: manifest.TypeGit, stores: gitStores},
	"helm-repos":                          {system: manifest.TypeHelm, stores: helmStores},
	"pip-config":                          {system: manifest.TypePypi, stores: pipStores},
	"npm-config":                          {system: manifest.TypeNpm, stores: npmStores},
	"oci-" + clientconf.RuntimeContainerd: {system: manifest.TypeOCI, stores: containerdStores},
	"oci-" + clientconf.RuntimeDocker:     {system: manifest.TypeOCI, stores: dockerStores},
}

// dockerStores is the certs.d directory dockerd reads for bodega at u when a
// registry-mirrors entry of the daemon.json it loads names that host. The
// file is loaded whole, as dockerd loads it: one dockerd refuses, over any
// key, is one it does not start with, so the mirror and the directory are
// settings nothing runs with and Docker Engine is left unchecked.
func dockerStores(t TrustProbe, u *url.URL) []trustStore {
	doc, err := clientconf.LoadDockerDaemonFile(filepath.Join(t.Root, clientconf.DockerDaemonPath))
	switch {
	case err != nil:
		return []trustStore{{name: "dockerd's configuration", blind: fmt.Sprintf("dockerd refuses to load its configuration (%v) and does not start, so whether dockerd reaches bodega or verifies its certificate is unchecked", err)}}
	case doc == nil || !slices.ContainsFunc(doc.Mirrors, func(m string) bool { return mirrorIsBodega(m, u.Host) }):
		return nil
	}
	if doc.TLSUnmodeled != "" {
		return []trustStore{{name: "dockerd's configuration", blind: fmt.Sprintf("dockerd's configuration sets %s, which has dockerd load TLS files for its own listeners as it starts and exit when they do not load, so whether dockerd runs to verify bodega's certificate is unchecked", doc.TLSUnmodeled)}}
	}
	dir := filepath.Join(t.Root, "/etc/docker/certs.d", u.Host)
	if err := clientconf.DockerCertsDirError(dir, ""); err != nil {
		return []trustStore{{name: dir, blind: fmt.Sprintf("dockerd does not load the certificates in %s (%v) and sends that host nothing while it cannot, so whether dockerd verifies bodega's certificate is unchecked", dir, err)}}
	}
	return []trustStore{certsDir(dir)}
}

// aptStores is the store apt verifies bodega at u against, for a host one of
// whose enabled sources names bodega's host and port: the file the
// effective Acquire::https::CAInfo names, which apt reads in place of the
// system trust store, and the system store with none set. The option scoped
// to bodega's own host outranks the unscoped one, and one scoped to another
// host says nothing here. The configuration is loaded whole, as apt loads it:
// a file apt refuses, over any statement, stops every apt command, so the
// options it holds are settings nothing runs with and apt is left unchecked.
func aptStores(t TrustProbe, u *url.URL) []trustStore {
	// The sources apt loads, read whole as apt reads them: an entry apt
	// refuses in any file leaves it reading none, so no source is one apt
	// fetches from and what the lists name says nothing about bodega.
	entries, err := clientconf.LoadAptSources(t.Root)
	if err != nil {
		return []trustStore{{name: "apt's sources", blind: fmt.Sprintf("apt does not read its sources (%v) and fails every command that needs them, so whether apt reaches bodega or verifies its certificate is unchecked", err)}}
	}
	wantPort := 443
	if p, err := strconv.Atoi(u.Port()); err == nil {
		wantPort = p
	}
	if !slices.ContainsFunc(entries, func(e clientconf.AptSourceEntry) bool {
		return slices.ContainsFunc(e.URIs, func(uri string) bool {
			access, host, port := clientconf.AptURIHost(uri)
			if port == 0 {
				port = map[string]int{"https": 443, "http": 80}[access]
			}
			return strings.EqualFold(host, u.Hostname()) && port == wantPort
		})
	}) {
		return nil
	}
	conf, err := clientconf.LoadAptConfig(t.Root, t.Getenv)
	if err != nil {
		return []trustStore{{name: "apt's configuration", blind: fmt.Sprintf("apt does not load its configuration (%v) and fails every command, so whether apt reaches bodega or verifies its certificate is unchecked", err)}}
	}
	if u.Scheme == "https" {
		if err := conf.HTTPSError(u.Hostname(), t.Root); err != nil {
			return []trustStore{{name: "apt's configuration", blind: fmt.Sprintf("apt's https method opens no TLS connection under this configuration (%v), so whether apt verifies bodega's certificate is unchecked", err)}}
		}
	}
	if u.Scheme == "https" {
		if unmodeled := conf.TLSUnmodeled(u.Hostname()); unmodeled != "" {
			return []trustStore{{name: "apt's configuration", blind: fmt.Sprintf("apt's configuration sets %s, so whether apt accepts bodega's certificate is unchecked", unmodeled)}}
		}
	}
	for _, key := range []string{"acquire::https::" + strings.ToLower(u.Hostname()) + "::cainfo", "acquire::https::cainfo"} {
		if v := conf[key]; v.Value != "" {
			return []trustStore{*named(v.Value, "Acquire::https::CAInfo in "+v.File, true)}
		}
	}
	return []trustStore{t.systemStore()}
}

// systemStore is the operating system's trust store as apt, the go command
// and helm read it: the store itself, or nothing doctor can speak for when
// the environment has the client's TLS library read another file in its
// place. Go's crypto/x509 takes no such variable on macOS.
func (t TrustProbe) systemStore() trustStore {
	if env := clientconf.SystemStoreEnv(t.Getenv); env != "" && t.GOOS != clientconf.OSDarwin {
		return trustStore{name: systemStoreName, blind: fmt.Sprintf("the client reads %s, so whether it verifies bodega's certificate is unchecked", env)}
	}
	return trustStore{name: systemStoreName, system: true}
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
	var layers []clientconf.PipLayer
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if err := clientconf.PipLoadError(data); err != nil {
			return []trustStore{{name: "pip's configuration", blind: fmt.Sprintf("pip refuses to load %s (%v) and aborts every command while it does, so whether pip reaches bodega or verifies its certificate is unchecked", f, err)}}
		}
		layers = append(layers, clientconf.PipLayer{File: f, Data: data})
	}
	if err := clientconf.PipInstallError(layers, t.Getenv); err != nil {
		return []trustStore{{name: "pip's configuration", blind: fmt.Sprintf("pip install exits while it converts its configured options, before any request: %v. Whether pip reaches bodega or verifies its certificate is unchecked", err)}}
	}
	// Ahead of asking whether an index names bodega: the alias is one, read
	// by pip and not here.
	if from := clientconf.PipIndexAlias(layers, t.Getenv); from != "" {
		return []trustStore{{name: "pip's configuration", blind: fmt.Sprintf("pip's configuration sets pypi-url (%s), a second name for index-url that doctor does not interpret, so which index pip install asks, and whether it reaches bodega or verifies its certificate, is unchecked", from)}}
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
	// An index naming bodega that pip install drops is no endpoint: no store
	// is verified against a host pip never contacts.
	if from := clientconf.PipNoIndex(layers, t.Getenv); from != "" {
		return []trustStore{{name: "pip's configuration", blind: fmt.Sprintf("pip is told to use no index (%s), and with no-index set pip install drops the index naming bodega before its first request, so pip does not reach bodega and whether it would verify bodega's certificate is unchecked", from)}}
	}
	if from := clientconf.PipClientCert(layers, t.Getenv); from != "" {
		return []trustStore{{name: "pip's configuration", blind: fmt.Sprintf("pip is given a client certificate (%s), which it loads into every connection and fails each request on when the file or its key does not load; doctor does not interpret it, so whether pip accepts bodega's certificate is unchecked", from)}}
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
		home := ""
		if t.Home != "" {
			home = t.home()
		}
		path, sure := clientconf.PipCertPath(cert[0], home)
		if !sure {
			return []trustStore{{name: "pip's configuration", blind: fmt.Sprintf("pip's cert setting in %s names %s, which pip resolves against another account's home directory or the directory it is started in, neither of which doctor knows, so which bundle pip verifies bodega against is unchecked", cert[1], cert[0])}}
		}
		cert[0] = path
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
// [install] sets its own index, configures nothing. Neither does a location
// pip ignores or sends no TLS request to, which clientconf.PipIndexURL tells.
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
		if slices.ContainsFunc(strings.Fields(v), func(one string) bool { return clientconf.PipIndexURL(one) != nil && sameHost(one, u) }) {
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
	// An unscoped credential ends npm before any request, and a value npm
	// itself reports invalid goes on, as written, to whatever reads it.
	wontStart := func(what string) []trustStore {
		return []trustStore{{name: "npm's configuration", blind: fmt.Sprintf("npm reads %s, so whether npm reaches bodega or verifies its certificate is unchecked", what)}}
	}
	// Two spellings of one option holding different values, or a line that
	// may set a registry, leave the registries npm asks unknown, and a registry
	// list that cannot be read is no evidence that bodega is absent from it.
	if conflict := clientconf.NpmEnvConflict(t.Getenv); conflict != "" {
		return blind(conflict)
	}
	for _, f := range files {
		if line := clientconf.NpmUnclassified(f); line != "" {
			return blind(line)
		}
	}
	// A registry npm refuses at the request, or sends somewhere this probe
	// does not work out, is no evidence that bodega is not the registry.
	regs := clientconf.NpmRegistries(t.Getenv, files)
	if unread := clientconf.NpmRegistryUnread(regs); unread != "" {
		return blind(unread)
	}
	if !slices.ContainsFunc(regs, func(r clientconf.NpmRegistry) bool { return sameHost(r.Value, u) }) {
		return nil
	}
	var layers []npmLayer
	for _, f := range files {
		if unread := clientconf.NpmUnread(f); unread != "" {
			return blind(unread)
		}
		if bad := clientconf.NpmStartError(f); bad != "" {
			return wontStart(bad)
		}
		layers = append(layers, npmFileLayer(f))
	}
	if bad := clientconf.NpmEnvInvalid(t.Getenv); bad != "" {
		return wontStart(bad)
	}
	if unmodeled := clientconf.NpmClientTLS(t.Getenv, files); unmodeled != "" {
		return blind(unmodeled)
	}
	if unmodeled := clientconf.NodeOptionsUnread(t.Getenv); unmodeled != "" {
		return blind(unmodeled)
	}
	env := npmLayer{from: "the environment"}
	if v, _ := clientconf.NpmEnv(t.Getenv, "cafile"); v != "" {
		env.cafile, env.from = v, "the environment's npm_config_cafile"
		if t.env("npm_config_cafile") == "" {
			env.from = "the environment's NPM_CONFIG_CAFILE"
		}
	}
	if v, _ := clientconf.NpmEnv(t.Getenv, "ca"); v != "" {
		env.ca, env.caSet = []string{strings.ReplaceAll(v, `\n`, "\n")}, true
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

// gitStores resolves what git verifies bodega at u against, for a host whose
// configuration rewrites a URL to it: the file the effective http.sslCAInfo
// names, which git reads in place of the system trust store. One store per
// setting git can pick for a URL under each rewritten prefix, since a section
// scoped to a longer URL outranks one scoped to bodega's base for the
// repositories below it. GIT_SSL_CAINFO outranks every file.
//
// Every file is read whole through clientconf.ParseGitConfig first. A file
// git refuses to load, for a line in any section, leaves git unchecked: git
// aborts on it, so nothing else it holds is configuration git runs with.
func gitStores(t TrustProbe, u *url.URL) []trustStore {
	// The environment that selects those files is converted first, as git
	// converts it: a value git stops on leaves every file unread.
	if bad := clientconf.GitEnvError(t.Getenv); bad != "" {
		return []trustStore{{name: "git's environment", blind: fmt.Sprintf("git does not start with %s, so whether git reaches bodega or verifies its certificate is unchecked", bad)}}
	}
	files := clientconf.GitConfigFiles(t.Getenv, t.Home, t.Root)
	if bad := clientconf.GitLoadError(files); bad != "" {
		return []trustStore{{name: "git's configuration", blind: fmt.Sprintf("git fetch and git clone do not run with %s: git stops on a variable it cannot convert, whichever section holds it, and doctor does not vouch for one it does not interpret, so whether git reaches bodega or verifies its certificate is unchecked", bad)}}
	}
	// A rewrite to a base git does not normalize is no evidence that git is
	// not sent to bodega, and no URL-scoped setting applies to it.
	if unread := clientconf.GitRewriteUnread(files); unread != "" {
		return []trustStore{{name: "git's configuration", blind: fmt.Sprintf("git rewrites URLs to %s, so whether git reaches bodega through it and which http.sslCAInfo it would verify bodega against is unchecked", unread)}}
	}
	wantPort := u.Port()
	if wantPort == "443" {
		wantPort = ""
	}
	var prefixes []string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, e := range clientconf.ParseGitConfig(data).Entries {
			if e.Section != "url" || e.Name != "insteadof" && e.Name != "pushinsteadof" {
				continue
			}
			// The base as git normalizes it, which is the URL it matches
			// [http "<url>"] sections against and the host curl is handed.
			host, port, ok := clientconf.GitURLHost(e.Subsection)
			if ok && host == strings.ToLower(u.Hostname()) && port == wantPort && !slices.Contains(prefixes, e.Subsection) {
				prefixes = append(prefixes, e.Subsection)
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
	if unmodeled := clientconf.GitEnvUnmodeled(t.Getenv); unmodeled != "" {
		return []trustStore{{name: "git's environment", blind: fmt.Sprintf("git reads %s, so whether git accepts bodega's certificate is unchecked", unmodeled)}}
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
//
// The file is loaded whole through clientconf.LoadHelmFile first. A file
// helm refuses to load, for any field of any entry, leaves helm unchecked:
// helm stops on it, so no url or caFile it holds is one helm runs with.
func helmStores(t TrustProbe, u *url.URL) []trustStore {
	path := clientconf.HelmRepositoryFile(t.Getenv, t.GOOS, t.Home)
	if path == "" {
		return nil
	}
	doc, err := clientconf.LoadHelmFile(path)
	if err != nil {
		return []trustStore{{name: "helm's configuration", blind: fmt.Sprintf("helm refuses to load its repository file (%v) and fails every command that reads it, so whether helm reaches bodega or verifies its certificate is unchecked", err)}}
	}
	if doc == nil {
		return nil
	}
	var out []trustStore
	for _, r := range doc.Repositories {
		if r == nil {
			continue
		}
		if p, err := url.Parse(r.URL); err != nil || p.Host != u.Host {
			continue
		}
		if err := r.ClientTLSError(r.CAFile != ""); err != nil {
			return []trustStore{{name: "helm's configuration", blind: fmt.Sprintf("helm builds no client for a repository at bodega in %s (%v), so whether helm verifies bodega's certificate is unchecked", path, err)}}
		}
		s := t.systemStore()
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
//
// A config.toml that cannot be read or does not resolve, and one that
// disables the CRI plugin, which is what reads hosts.toml, leave containerd
// unchecked: the certs.d directory a default install would read is no
// evidence about a containerd whose configuration says otherwise or cannot
// be told. Only a host with no config.toml, or one naming no config_path, is
// read at that default directory.
//
// Each hosts.toml is loaded whole through clientconf.LoadContainerdHostsFile.
// One containerd discards, for any field of any host, leaves containerd
// unchecked: it then pulls from the registry's own server, so no host or ca
// the file holds is one containerd runs with, and the roots of that fallback
// say nothing about bodega.
func containerdStores(t TrustProbe, u *url.URL) []trustStore {
	path := filepath.Join(t.Root, clientconf.ContainerdConfigPath)
	blind := func(why string) []trustStore {
		return []trustStore{{name: "containerd's configuration", blind: fmt.Sprintf("%s %s, so which hosts.toml files containerd reads, and whether it verifies bodega's certificate, is unchecked", path, why)}}
	}
	roots := []string{clientconf.ContainerdCertsDir}
	switch data, err := os.ReadFile(path); {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return blind(fmt.Sprintf("could not be read (%v)", err))
	default:
		cfg, err := clientconf.ResolveContainerdConfig(t.Root, clientconf.ContainerdConfigPath, data)
		switch {
		case err != nil:
			return blind(fmt.Sprintf("does not resolve (%v)", err))
		case cfg.CRIDisabled:
			return blind("disables the CRI plugin, which is what reads containerd's registry configuration")
		case cfg.Invalid != "":
			return blind(fmt.Sprintf("is one containerd refuses to load (%s)", cfg.Invalid))
		case cfg.ConfigPath != "":
			roots = strings.Split(cfg.ConfigPath, ":")
		}
	}
	var out []trustStore
	for _, path := range clientconf.ContainerdHostsFiles(t.Root, roots) {
		doc, err := clientconf.LoadContainerdHostsFile(path)
		if err != nil {
			return []trustStore{{name: "containerd's configuration", blind: fmt.Sprintf("containerd discards its registry configuration (%v) and pulls from the registry's own server instead, so whether containerd reaches bodega or verifies its certificate is unchecked", err)}}
		}
		if doc == nil {
			continue
		}
		if !slices.ContainsFunc(doc.Hosts, func(h clientconf.ContainerdRegistryHost) bool { return mirrorIsBodega(h.Key, u.Host) }) {
			continue
		}
		if err := doc.TLSError(""); err != nil {
			return []trustStore{{name: "containerd's configuration", blind: fmt.Sprintf("containerd cannot load a certificate %s names (%v) and resolves no host for that registry while it cannot, the bodega host included, so whether containerd reaches bodega or verifies its certificate is unchecked", path, err)}}
		}
		for _, h := range doc.Hosts {
			if mirrorIsBodega(h.Key, u.Host) {
				out = append(out, trustStore{name: "the ca of " + path, system: true, files: h.CA})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
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

// Rows returns a row for each client no inventory check reports on, git and
// helm, whose configuration sends it to bodega at base or could not be read
// far enough to tell. Apply then judges each as it does any other row. A
// client configured for somewhere else gets no row.
func (t TrustProbe) Rows(base string) []Finding {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil
	}
	var out []Finding
	for _, check := range []string{"git-config", "helm-repos"} {
		stores := trustRows[check].stores(t, u)
		if len(stores) == 0 {
			continue
		}
		f := Finding{Check: check, Status: StatusOK}
		if !slices.ContainsFunc(stores, func(s trustStore) bool { return s.blind != "" }) {
			f.Detail = "configured for bodega at " + u.Host
		}
		out = append(out, f)
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
