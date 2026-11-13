package clientconf

import (
	"fmt"
	"slices"
	"strings"
)

// The functions here answer for what stands around a client's configuration
// files: an environment variable that selects which files the client loads or
// which roots it verifies with, and an option naming a TLS file other than
// the CA bundle a plan writes. A CA install and the trust verdict hold both
// to one rule. A selector is read by the client's own conversion, and a value
// the client stops on leaves the client unverified. A client certificate, a
// key, a revocation list or a second root store changes which server the
// client accepts in a way a root pool does not show, so a set one is refused
// and reported unchecked, by name, whether or not the file it names loads.
//
// Nothing here is consulted by a configure that installs no CA.

// GitEnvError is why git stops before it loads any configuration on the
// environment it is started in, as a phrase a diagnostic can carry, "" when
// it does not. git_config_system (config.c at Git 2.54.0, lines 1510-1513)
// reads GIT_CONFIG_NOSYSTEM through git_env_bool, which dies on a value
// git_parse_maybe_bool does not read:
// "fatal: bad boolean environment value 'maybe' for 'GIT_CONFIG_NOSYSTEM'".
func GitEnvError(getenv func(string) string) string {
	if getenv == nil {
		return ""
	}
	if v := getenv("GIT_CONFIG_NOSYSTEM"); v != "" && !gitBoolish(v) {
		return fmt.Sprintf("the environment's GIT_CONFIG_NOSYSTEM, set to %q: git reads it as a boolean before it loads any configuration and stops every command on a value that is none (bad boolean environment value)", v)
	}
	return ""
}

// gitNoSystem is git_config_system negated: GIT_CONFIG_NOSYSTEM read as git
// reads it, so 00 and 0k are false with 0, false, no and off. A value git
// dies on is GitEnvError's to report, and reads as unset here.
func gitNoSystem(getenv func(string) string) bool {
	if getenv == nil {
		return false
	}
	v := getenv("GIT_CONFIG_NOSYSTEM")
	return v != "" && gitBoolish(v) && gitTrue(v, true)
}

// gitTLSEnv is every variable Git 2.54.0 reads from the environment into the
// settings gitHTTPUnmodeled lists, with what each changes: http_init (http.c,
// lines 1403-1440) and get_curl_handle (lines 1089-1090 and 1105-1106). git
// tests most of them for presence alone, so any value counts; an empty one
// cannot be told from an unset one through the environment doctor is handed.
// GIT_SSL_CAINFO is not here: it names the roots, which the probe reads.
var gitTLSEnv = []struct{ name, effect string }{
	{"GIT_SSL_NO_VERIFY", "turns certificate verification off, so no CA decides what git accepts"},
	{"GIT_SSL_CERT", "has git present a client certificate"},
	{"GIT_SSL_KEY", "has git present a client key"},
	{"GIT_SSL_CERT_TYPE", "sets the format git reads its client certificate in"},
	{"GIT_SSL_KEY_TYPE", "sets the format git reads its client key in"},
	{"GIT_SSL_CERT_PASSWORD_PROTECTED", "has git ask for the password of a client certificate"},
	{"GIT_SSL_CAPATH", "adds a directory of CA certificates to the roots git verifies with"},
	{"GIT_SSL_VERSION", "holds the handshake to one TLS version"},
	{"GIT_SSL_CIPHER_LIST", "holds the handshake to the listed ciphers"},
	{"GIT_PROXY_SSL_CERT", "has git present a client certificate to an HTTPS proxy"},
	{"GIT_PROXY_SSL_KEY", "has git present a client key to an HTTPS proxy"},
	{"GIT_PROXY_SSL_CAINFO", "names the roots git verifies an HTTPS proxy with"},
	{"GIT_PROXY_SSL_CERT_PASSWORD_PROTECTED", "has git ask for the password of a proxy client certificate"},
}

// GitEnvUnmodeled is the first variable of the environment that constrains
// git's TLS handshake past the root pool, as a phrase naming it, "" for none:
// the environment's spelling of what GitTLSUnmodeled refuses in a file. The
// value is never repeated.
func GitEnvUnmodeled(getenv func(string) string) string {
	if getenv == nil {
		return ""
	}
	for _, e := range gitTLSEnv {
		if getenv(e.name) != "" {
			return fmt.Sprintf("the environment's %s, which %s: the CA roots doctor verifies bodega against do not show it and doctor does not interpret it", e.name, e.effect)
		}
	}
	return ""
}

// https is ConfigFind of apt's https method for one option: the value scoped
// to host, else the unscoped one. option is lowercase.
func (c AptConfig) https(host, option string) AptOption {
	if v := c["acquire::https::"+strings.ToLower(host)+"::"+option]; v.Value != "" {
		return v
	}
	return c["acquire::https::"+option]
}

// TLSUnmodeled is the first option that has apt's https method load a TLS
// file other than its roots for host, as a phrase naming the option and the
// file that set it, "" for none. GetContextForHost (methods/connect.cc at APT
// 3.0.3) parses each with OpenSSL and refuses the connection when one does
// not parse, and a CrlFile that does parse turns revocation checking on
// (X509_V_FLAG_CRL_CHECK). Neither outcome is one a root pool shows, so the
// option is refused set rather than read: a file that opens proves nothing
// about either.
func (c AptConfig) TLSUnmodeled(host string) string {
	for _, o := range []struct{ option, effect string }{
		{"SslCert", "has apt load a client certificate, and open no connection when OpenSSL does not parse it"},
		{"SslKey", "has apt load a client key, and open no connection when OpenSSL does not parse it or it does not match"},
		{"CrlFile", "has apt load a certificate revocation list, open no connection when OpenSSL does not parse it, and refuse a server certificate it lists or whose issuer it does not cover"},
	} {
		if v := c.https(host, strings.ToLower(o.option)); v.Value != "" {
			return fmt.Sprintf("Acquire::https::%s (%s), which %s: the CA roots doctor verifies bodega against do not show it and doctor does not interpret it", o.option, v.File, o.effect)
		}
	}
	return ""
}

// SystemStoreEnv is the first variable of the environment that has a client
// read another file or directory in place of the operating system's trust
// store, as a phrase naming it, "" for none. OpenSSL's default verify paths,
// which apt loads when no CaInfo is set, and Go's crypto/x509 on every Unix
// but macOS, which the go command and helm verify through, both read
// SSL_CERT_FILE and SSL_CERT_DIR ahead of the store update-ca-certificates
// rebuilds. An anchor installed there is then one the client never loads.
func SystemStoreEnv(getenv func(string) string) string {
	if getenv == nil {
		return ""
	}
	for _, name := range []string{"SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if getenv(name) != "" {
			return fmt.Sprintf("the environment's %s, which names what the client's TLS library reads in place of the system trust store: doctor installs into and verifies against that store, and does not interpret the variable", name)
		}
	}
	return ""
}

// PipClientCert is where pip install is given a client certificate, by the
// order it resolves every option in ([global], [install], PIP_CLIENT_CERT),
// "" when nothing sets one. pip hands the file to requests as the session's
// cert, and urllib3 loads it into the TLS context as the connection opens: a
// file that does not load, or a key that does not match, fails every request
// whichever CA is installed.
func PipClientCert(layers []PipLayer, getenv func(string) string) string {
	_, from := pipInstallValue(pipGroups(layers, getenv), "client-cert")
	return from
}

// NpmClientTLS is the first place npm is given a client certificate or key,
// as a phrase naming the option and its source and never the value, "" for
// none: cert and key, which hold PEM text, in a file or as npm_config_cert
// and npm_config_key, and a registry-scoped //host/:certfile or :keyfile.
// npm hands them to Node's TLS context, which throws on text that is no
// certificate or key. A scoped pair is refused whichever registry it names:
// matching its scope to bodega's URL is npm's own walk, which nothing here
// ports.
func NpmClientTLS(getenv func(string) string, files []string) string {
	seen := map[string]bool{}
	for _, f := range files {
		if seen[f] {
			continue
		}
		seen[f] = true
		for _, o := range npmFileOptions(f) {
			scoped := strings.HasSuffix(o.Key, ":certfile") || strings.HasSuffix(o.Key, ":keyfile")
			if !scoped && o.Key != "cert" && o.Key != "key" {
				continue
			}
			// null resets the option, and an empty value sets none.
			if !o.Bare && (o.Value == "null" || o.Value == "") {
				continue
			}
			return fmt.Sprintf("line %d of %s, which sets %s, a client certificate or key npm presents and Node refuses to start a connection on when it does not load", o.Line, f, o.Key)
		}
	}
	for _, key := range []string{"cert", "key"} {
		if v, _ := NpmEnv(getenv, key); v != "" {
			return fmt.Sprintf("the environment's npm_config_%s, a client certificate or key npm presents and Node refuses to start a connection on when it does not load", key)
		}
	}
	return ""
}

// nodeCAOptions are the NODE_OPTIONS entries that choose Node's root store,
// the only ones doctor reads.
var nodeCAOptions = []string{"--use-bundled-ca", "--use-openssl-ca", "--use-system-ca"}

// NodeOptionsUnread is why NODE_OPTIONS leaves the Node npm runs under
// unknown, "" when it holds nothing but the options that choose a root
// store. Node exits before npm starts on an option it does not allow there
// ("is not allowed in NODE_OPTIONS"), and one it does allow can load code or
// change what TLS accepts (--require, --tls-min-v1.3, --openssl-config).
// Telling those apart is Node's option table, which nothing here ports, so
// anything else is refused. The value is never repeated.
func NodeOptionsUnread(getenv func(string) string) string {
	if getenv == nil {
		return ""
	}
	for _, opt := range strings.Fields(getenv("NODE_OPTIONS")) {
		if !slices.Contains(nodeCAOptions, opt) {
			return "the environment's NODE_OPTIONS, which holds an option other than " + strings.Join(nodeCAOptions, ", ") + ": Node exits on one it does not allow there and changes what it loads or verifies on others, and doctor interprets those three alone"
		}
	}
	return ""
}
