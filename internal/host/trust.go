package host

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
}

// trustRow is one doctor row's client: how to tell it is configured for
// bodega, and where it reads CAs beside the system trust store.
type trustRow struct {
	// system is the --configure name the remediation carries.
	system string
	// mentions reports whether the client's configuration names host. Nil
	// means the row's own OK already says so.
	mentions func(t TrustProbe, host string) bool
	// own names the client's own CA setting and the PEM files it resolves
	// to on this host. Nil for a client that reads the system store alone.
	own func(t TrustProbe, host string) (name string, files []string)
}

// trustRows maps a row's check name to its client. Maven has no entry: the
// JVM reads a keystore, and its row is left as the check wrote it.
var trustRows = map[string]trustRow{
	"apt-sources": {system: manifest.TypeApt, mentions: func(t TrustProbe, host string) bool {
		return t.filesMention(host, "/etc/apt/sources.list", "/etc/apt/sources.list.d/*")
	}},
	"dnf-repos": {system: manifest.TypeRpm, mentions: func(t TrustProbe, host string) bool {
		return t.filesMention(host, "/etc/yum.repos.d/*.repo")
	}},
	"pkg-repos": {system: manifest.TypeFreeBSD, mentions: func(t TrustProbe, host string) bool {
		return t.filesMention(host, "/usr/local/etc/pkg/repos/*.conf")
	}},
	"make-conf": {system: manifest.TypeDistfiles, mentions: func(t TrustProbe, host string) bool {
		return t.filesMention(host, "/etc/make.conf")
	}},
	"cargo-config": {system: manifest.TypeCargo, mentions: func(t TrustProbe, host string) bool {
		return mention(host, filepath.Join(t.Home, ".cargo", "config.toml"), filepath.Join(t.Home, ".cargo", "config"))
	}},
	"rubygems": {system: manifest.TypeRubygems, mentions: func(t TrustProbe, host string) bool {
		return mention(host, filepath.Join(t.Home, ".gemrc"), filepath.Join(t.Home, ".bundle", "config"))
	}},
	"composer": {system: manifest.TypeComposer, mentions: func(t TrustProbe, host string) bool {
		return mention(host, filepath.Join(clientconf.HostComposerHome(t.Home), "config.json"))
	}},
	"goproxy-env": {system: manifest.TypeGomod, mentions: func(t TrustProbe, host string) bool {
		if strings.Contains(t.Getenv("GOPROXY"), host) {
			return true
		}
		file, err := goEnvFile(t.Getenv, t.ConfigDir)
		return err == nil && file != "" && mention(host, file)
	}},
	"pip-config": {
		system: manifest.TypePypi,
		mentions: func(t TrustProbe, host string) bool {
			return mention(host, rooted(t.Root, pipPaths(t.GOOS, t.Home))...)
		},
		own: func(t TrustProbe, _ string) (string, []string) {
			return "pip's cert setting", settingValues("cert", rooted(t.Root, pipPaths(t.GOOS, t.Home)))
		},
	},
	"npm-config": {
		system: manifest.TypeNpm,
		mentions: func(t TrustProbe, host string) bool {
			return mention(host, rooted(t.Root, npmPaths(t.GOOS, t.Home))...)
		},
		own: func(t TrustProbe, _ string) (string, []string) {
			return "npm's cafile setting", settingValues("cafile", rooted(t.Root, npmPaths(t.GOOS, t.Home)))
		},
	},
	"oci-" + clientconf.RuntimeDocker: {system: manifest.TypeOCI, own: func(t TrustProbe, host string) (string, []string) {
		dir := filepath.Join(t.Root, "/etc/docker/certs.d", host)
		files, _ := filepath.Glob(filepath.Join(dir, "*.crt"))
		return dir, files
	}},
	"oci-" + clientconf.RuntimePodman: {system: manifest.TypeOCI, own: func(t TrustProbe, host string) (string, []string) {
		dir := filepath.Join(t.Root, "/etc/containers/certs.d", host)
		files, _ := filepath.Glob(filepath.Join(dir, "*.crt"))
		return dir, files
	}},
	"oci-" + clientconf.RuntimeContainerd: {system: manifest.TypeOCI, own: func(t TrustProbe, host string) (string, []string) {
		dir := filepath.Join(t.Root, clientconf.ContainerdCertsDir)
		hosts, _ := filepath.Glob(filepath.Join(dir, "*", "hosts.toml"))
		var mentioning []string
		for _, h := range hosts {
			if mention(host, h) {
				mentioning = append(mentioning, h)
			}
		}
		return "the ca of each hosts.toml under " + dir, settingValues("ca", mentioning)
	}},
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

// settingValues collects the value every "key = value" line gives key across
// files, unquoted. It reads pip.conf, .npmrc and hosts.toml alike, since each
// writes a path setting on one line.
func settingValues(key string, files []string) []string {
	var out []string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			k, v, ok := strings.Cut(line, "=")
			if !ok || strings.TrimSpace(k) != key {
				continue
			}
			if v = strings.Trim(strings.TrimSpace(v), `"'`); v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// Apply returns findings with each OK row of a client configured for bodega
// at base turned into a warning when that client cannot verify the
// certificate base serves. A chain the system trust store verifies settles
// every row, since each of these clients reads that store or accepts what it
// accepts; a client's own setting is read only when it does not.
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
		if !ok || f.Status != StatusOK || (row.mentions != nil && !row.mentions(t, u.Host)) {
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
		if systemErr == nil {
			continue
		}
		verdict := "the system trust store does not verify"
		if row.own != nil {
			name, files := row.own(t, u.Host)
			if verifyChain(chain, u.Hostname(), poolOf(files)) == nil {
				continue
			}
			verdict = "neither the system trust store nor " + name + " verifies"
		}
		out[i].Status = StatusWarn
		out[i].Detail = fmt.Sprintf("configured for bodega at %s, and %s the certificate it serves (%v), so every fetch fails on the certificate",
			u.Host, verdict, systemErr)
		out[i].Remediation = fmt.Sprintf("install the CA that issued bodega's certificate: bodega doctor --configure %s --ca-file <CA certificate PEM> --apply --url %s",
			row.system, strings.TrimRight(base, "/"))
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
