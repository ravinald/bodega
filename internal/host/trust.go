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
	"time"

	"github.com/BurntSushi/toml"

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
	aptCAInfo  = regexp.MustCompile(`(?i)\bCaInfo\s+"([^"]+)"`)
	gemCACert  = regexp.MustCompile(`(?m)^:?ssl_ca_cert:\s*["']?([^"'\s#]+)`)
	tomlCAInfo = regexp.MustCompile(`(?m)^\s*cainfo\s*=\s*["']([^"']+)["']`)
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
	"apt-sources": systemOnly(manifest.TypeApt, func(t TrustProbe, host string) bool {
		return t.filesMention(host, "/etc/apt/sources.list", "/etc/apt/sources.list.d/*")
	}, func(t TrustProbe) *trustStore {
		conf, _ := filepath.Glob(filepath.Join(t.Root, "/etc/apt/apt.conf.d/*"))
		if v, f := firstMatch(aptCAInfo, append([]string{filepath.Join(t.Root, "/etc/apt/apt.conf")}, conf...)...); v != "" {
			return named(v, "Acquire::https::CAInfo in "+f, true)
		}
		return nil
	}),
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
		if v, f := firstMatch(tomlCAInfo, filepath.Join(t.Home, ".cargo", "config.toml"), filepath.Join(t.Home, ".cargo", "config")); v != "" {
			return named(v, "http.cainfo in "+f, true)
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
		store := certsDir(filepath.Join(t.Root, "/etc/containers/certs.d", u.Host))
		if t.Home != "" {
			more, _ := filepath.Glob(filepath.Join(user, "certs.d", u.Host, "*.crt"))
			store.files = append(store.files, more...)
		}
		return []trustStore{store}
	}},
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

// iniValues reads the settings of an INI file as "section.key", both
// lowercased, each to every value the file gives it in order: npm reads a
// repeated ca[] as a list, where pip reads the last. A file with no sections
// keys them ".key", and a file that will not read sets nothing.
func iniValues(path string) map[string][]string {
	out := map[string][]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || line[0] == '#' || line[0] == ';':
		case line[0] == '[' && strings.HasSuffix(line, "]"):
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
		default:
			if k, v, ok := strings.Cut(line, "="); ok {
				key := section + "." + strings.ToLower(strings.TrimSpace(k))
				out[key] = append(out[key], strings.TrimSpace(v))
			}
		}
	}
	return out
}

func last(vals []string) string {
	if len(vals) == 0 {
		return ""
	}
	return vals[len(vals)-1]
}

// pipFiles lists the configuration files pip loads, in the order it loads
// them. PIP_CONFIG_FILE names one more, loaded last; when that file exists
// pip skips the per-user files, and when it is the null device pip loads no
// file at all.
func pipFiles(t TrustProbe) []string {
	global := pipPaths(t.GOOS, "")
	files := rooted(t.Root, pipPaths(t.GOOS, t.Home))
	explicit := t.env("PIP_CONFIG_FILE")
	switch explicit {
	case "":
	case os.DevNull:
		return nil
	default:
		if _, err := os.Stat(explicit); err == nil {
			files = append(files[:len(global):len(global)], explicit)
		}
	}
	return files
}

// pipStores resolves the bundle pip verifies an install against. cert, from
// the last file pip loads that sets it or from PIP_CERT, replaces pip's
// default; a per-command section outranks [global] whichever file holds it.
// With none set, requests falls back to REQUESTS_CA_BUNDLE and then
// CURL_CA_BUNDLE, and only then does pip read its default: the system store
// through truststore, or on an older pip certifi's bundle, which holds no
// private CA whatever the system store holds. Which of the two is pip's own
// to say, so Pip asks it.
func pipStores(t TrustProbe, u *url.URL) []trustStore {
	files := pipFiles(t)
	if !mention(u.Host, files...) && !strings.Contains(t.env("PIP_INDEX_URL"), u.Host) {
		return nil
	}
	var global, install [2]string
	for _, f := range files {
		vals := iniValues(f)
		if v := last(vals["global.cert"]); v != "" {
			global = [2]string{v, f}
		}
		if v := last(vals["install.cert"]); v != "" {
			install = [2]string{v, f}
		}
	}
	cert := global
	if install[0] != "" {
		cert = install
	}
	for _, key := range []string{"PIP_CERT", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"} {
		if v := t.env(key); v != "" && (key == "PIP_CERT" || cert[0] == "") {
			cert = [2]string{v, "the environment's " + key}
			break
		}
	}
	if cert[0] != "" {
		return []trustStore{{name: fmt.Sprintf("%s, which pip's cert setting names in %s in place of the system trust store,", cert[0], cert[1]), files: []string{cert[0]}}}
	}
	system := trustStore{name: systemStoreName + ", which pip reads while no cert setting names a bundle,", system: true}
	return []trustStore{{name: system.name, resolve: func() trustStore {
		reason := "pip is not asked on this host"
		if t.Pip != nil {
			d, err := t.Pip()
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

// npmStores resolves the CAs npm verifies its registry against. cafile or ca,
// from the last npmrc npm loads that sets one or from npm_config_cafile,
// replaces Node's defaults, and NODE_EXTRA_CA_CERTS no longer adds to them. A
// file's ca[] lines are one list, every entry trusted.
//
// With neither set npm verifies against Node's defaults: the Mozilla roots
// Node bundles, or OpenSSL's store under --use-openssl-ca and in a Node built
// that way, with the system store added under --use-system-ca, and
// NODE_EXTRA_CA_CERTS beside any of them. A private CA in the system store
// is in none of the bundled roots, so the system store's answer settles this
// row only where Node reads that store, and Node lists what it trusts.
func npmStores(t TrustProbe, u *url.URL) []trustStore {
	files := rooted(t.Root, npmPaths(t.GOOS, t.Home))
	if !mention(u.Host, files...) {
		return nil
	}
	unquote := func(v string) string { return strings.Trim(v, `"'`) }
	var cafile, from string
	var inline []string
	for _, f := range files {
		vals := iniValues(f)
		if v := unquote(last(vals[".cafile"])); v != "" {
			cafile, from = v, f
		}
		var list []string
		for _, v := range append(slices.Clone(vals[".ca[]"]), last(vals[".ca"])) {
			if v = unquote(v); v != "" {
				list = append(list, strings.ReplaceAll(v, `\n`, "\n"))
			}
		}
		if len(list) > 0 {
			inline, from = list, f
		}
	}
	for _, key := range []string{"npm_config_cafile", "NPM_CONFIG_CAFILE"} {
		if v := t.env(key); v != "" {
			cafile, from = v, "the environment's "+key
		}
	}
	if rest, ok := strings.CutPrefix(cafile, "~/"); ok {
		cafile = filepath.Join(t.Root, t.Home, rest)
	}
	switch {
	case cafile != "":
		return []trustStore{{name: fmt.Sprintf("%s, which npm's cafile setting names in %s in place of the roots Node bundles,", cafile, from), files: []string{cafile}, pem: inline}}
	case len(inline) > 0:
		return []trustStore{{name: fmt.Sprintf("npm's ca setting in %s, read in place of the roots Node bundles,", from), pem: inline}}
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
		return pipDefaultFrom(string(out))
	}
	return PipDefault{}, errors.New("no pip on PATH")
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
