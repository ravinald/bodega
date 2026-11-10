package host

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
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
// store alone, configured when mentions says its configuration names host.
func systemOnly(system string, mentions func(t TrustProbe, host string) bool) trustRow {
	return trustRow{system: system, stores: func(t TrustProbe, u *url.URL) []trustStore {
		if !mentions(t, u.Host) {
			return nil
		}
		return []trustStore{{name: systemStoreName, system: true}}
	}}
}

// trustRows maps a row's check name to its client.
var trustRows = map[string]trustRow{
	"apt-sources": systemOnly(manifest.TypeApt, func(t TrustProbe, host string) bool {
		return t.filesMention(host, "/etc/apt/sources.list", "/etc/apt/sources.list.d/*")
	}),
	"dnf-repos": systemOnly(manifest.TypeRpm, func(t TrustProbe, host string) bool {
		conf, dirs := t.DnfConf, t.DnfDirs
		if conf == "" {
			conf = filepath.Join(t.Root, clientconf.DnfMainConf)
		}
		if dirs == nil {
			dirs = rooted(t.Root, clientconf.YumReposDirs)
		}
		// The repositories dnf loads, reposdir included, not a directory
		// scan: a .repo file dnf never reads configures nothing.
		loaded, err := clientconf.ReadDnfConfig(conf, dirs)
		if err != nil {
			return false
		}
		for _, r := range loaded.Repos {
			if r.Enabled && slices.ContainsFunc(r.URLs, func(u string) bool { return strings.Contains(u, host) }) {
				return true
			}
		}
		return false
	}),
	"pkg-repos": systemOnly(manifest.TypeFreeBSD, func(t TrustProbe, host string) bool {
		return t.filesMention(host, "/usr/local/etc/pkg/repos/*.conf")
	}),
	"make-conf": systemOnly(manifest.TypeDistfiles, func(t TrustProbe, host string) bool {
		return t.filesMention(host, "/etc/make.conf")
	}),
	"cargo-config": systemOnly(manifest.TypeCargo, func(t TrustProbe, host string) bool {
		return mention(host, filepath.Join(t.Home, ".cargo", "config.toml"), filepath.Join(t.Home, ".cargo", "config"))
	}),
	"rubygems": systemOnly(manifest.TypeRubygems, func(t TrustProbe, host string) bool {
		return mention(host, filepath.Join(t.Home, ".gemrc"), filepath.Join(t.Home, ".bundle", "config"))
	}),
	"composer": systemOnly(manifest.TypeComposer, func(t TrustProbe, host string) bool {
		return mention(host, filepath.Join(clientconf.HostComposerHome(t.Home), "config.json"))
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
	}),
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

func (t TrustProbe) env(key string) string {
	if t.Getenv == nil {
		return ""
	}
	return t.Getenv(key)
}

// iniValues reads the settings of an INI file as "section.key", both
// lowercased, to its last value there; a file with no sections keys them
// ".key". A file that will not read sets nothing.
func iniValues(path string) map[string]string {
	out := map[string]string{}
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
				out[section+"."+strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
			}
		}
	}
	return out
}

// pipStores resolves the bundle pip verifies an install against. cert, from
// the last file pip loads that sets it or from PIP_CERT, replaces pip's
// default; a per-command section outranks [global] whichever file holds it.
// With none set, requests falls back to REQUESTS_CA_BUNDLE and then
// CURL_CA_BUNDLE, and only then does pip read its default: the system store
// through truststore, or certifi's bundle on an older pip, which doctor
// cannot tell from the system store.
func pipStores(t TrustProbe, u *url.URL) []trustStore {
	files := rooted(t.Root, pipPaths(t.GOOS, t.Home))
	if !mention(u.Host, files...) {
		return nil
	}
	var global, install [2]string
	for _, f := range files {
		vals := iniValues(f)
		if v := vals["global.cert"]; v != "" {
			global = [2]string{v, f}
		}
		if v := vals["install.cert"]; v != "" {
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
	if cert[0] == "" {
		return []trustStore{{name: systemStoreName + ", which pip reads while no cert setting names a bundle,", system: true}}
	}
	return []trustStore{{name: fmt.Sprintf("%s, which pip's cert setting names in %s in place of the system trust store,", cert[0], cert[1]), files: []string{cert[0]}}}
}

// npmStores resolves the CAs npm verifies its registry against. cafile or ca,
// from the last npmrc npm loads that sets one or from npm_config_cafile,
// replaces the roots Node bundles, and NODE_EXTRA_CA_CERTS no longer adds to
// them. With neither set npm reads those bundled roots plus
// NODE_EXTRA_CA_CERTS; doctor cannot read the bundle, and the system store
// stands in for it, both being the public roots.
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
		if v := unquote(vals[".cafile"]); v != "" {
			cafile, from = v, f
		}
		for _, key := range []string{".ca", ".ca[]"} {
			if v := unquote(vals[key]); v != "" {
				inline, from = append(inline, strings.ReplaceAll(v, `\n`, "\n")), f
			}
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
	store := trustStore{name: systemStoreName + ", standing in for the roots Node bundles while no cafile setting names a file,", system: true}
	if extra := t.env("NODE_EXTRA_CA_CERTS"); extra != "" {
		store.name, store.files = "NODE_EXTRA_CA_CERTS ("+extra+")", []string{extra}
	}
	return []trustStore{store}
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
			if s.system && systemErr == nil {
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
