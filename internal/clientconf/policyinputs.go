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

// Environ reads one variable of the environment a client starts in, and says
// whether the variable is set at all. Clients disagree about a variable set
// to the empty string: git reads no per-user file under an empty
// GIT_CONFIG_GLOBAL, helm takes an empty HELM_REPOSITORY_CONFIG for its
// repository file, OpenSSL loads an empty SSL_CERT_FILE in place of its
// default, while npm, pip and the go command read an empty variable as unset.
// Each reader applies its own client's rule, so the two states stay apart
// until the function that ports that rule.
type Environ func(key string) (value string, set bool)

// NewEnviron pairs getenv, which answers for a variable's value, with lookup,
// which says whether one getenv reads as empty is set. A nil getenv is an
// environment holding nothing, and a nil lookup one in which no variable is
// set to the empty string.
func NewEnviron(getenv func(string) string, lookup func(string) (string, bool)) Environ {
	return func(key string) (string, bool) {
		if getenv == nil {
			return "", false
		}
		if v := getenv(key); v != "" {
			return v, true
		}
		if lookup != nil {
			if v, ok := lookup(key); ok && v == "" {
				return "", true
			}
		}
		return "", false
	}
}

// GitEnvNoFile is the variable that has git read no file where it would read
// target, as a phrase a diagnostic can carry, "" when none does.
// git_global_config_paths (config.c at Git 2.54.0) takes GIT_CONFIG_GLOBAL
// whenever it is set and then looks at neither ~/.gitconfig nor the XDG file,
// so an empty value names a file git cannot open and git runs with no
// per-user configuration at all.
func GitEnvNoFile(env Environ) string {
	if v, set := env("GIT_CONFIG_GLOBAL"); set && v == "" {
		return "GIT_CONFIG_GLOBAL, which is set and empty: git reads the variable whenever it is set, in place of ~/.gitconfig and the XDG file, and an empty value names no file, so git runs with no per-user configuration"
	}
	return ""
}

// HelmEnvNoFile is GitEnvNoFile for helm: envOr (pkg/cli/environment.go at
// Helm v4.3.0, lines 174-179) reads HELM_REPOSITORY_CONFIG through
// os.LookupEnv, so a variable set and empty is the repository file's path,
// and helm loads no repository from it.
func HelmEnvNoFile(env Environ) string {
	if v, set := env("HELM_REPOSITORY_CONFIG"); set && v == "" {
		return "HELM_REPOSITORY_CONFIG, which is set and empty: helm reads the variable whenever it is set, in place of the repositories.yaml in its configuration directory, and an empty value names no file, so helm runs with no repository"
	}
	return ""
}

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
// tests them for presence (getenv, and set_from_env, which copies whatever
// value it finds), so one set and empty counts as one set to anything.
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
// value is never repeated. getenv cannot tell a variable set and empty from
// one unset; GitEnvUnmodeledIn can, and is what a plan and a verdict call.
func GitEnvUnmodeled(getenv func(string) string) string {
	return GitEnvUnmodeledIn(NewEnviron(getenv, nil))
}

// GitEnvUnmodeledIn is GitEnvUnmodeled over an environment that keeps
// presence. A GIT_SSL_CAINFO set and empty is named too: set_from_env has it
// replace http.sslCAInfo with an empty file name, which is neither the roots
// a file names nor git's default store.
func GitEnvUnmodeledIn(env Environ) string {
	for _, e := range gitTLSEnv {
		if _, set := env(e.name); set {
			return fmt.Sprintf("the environment's %s, which %s: the CA roots doctor verifies bodega against do not show it and doctor does not interpret it", e.name, e.effect)
		}
	}
	if v, set := env("GIT_SSL_CAINFO"); set && v == "" {
		return "the environment's GIT_SSL_CAINFO, which is set and empty and replaces http.sslCAInfo with an empty file name: which roots git's TLS library then reads is not something doctor interprets"
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
// getenv cannot tell a variable set and empty from one unset;
// SystemStoreEnvIn can, and is what a plan and a verdict call.
func SystemStoreEnv(getenv func(string) string) string {
	return SystemStoreEnvIn(NewEnviron(getenv, nil), false)
}

// SystemStoreEnvIn is SystemStoreEnv over an environment that keeps presence.
// openssl says the client verifies through OpenSSL, as apt does: its by_file
// and by_dir lookups take the variable whenever getenv returns one, so an
// empty value is loaded in place of the default file or directory. Go's
// crypto/x509 (root_unix.go) reads an empty one as unset.
func SystemStoreEnvIn(env Environ, openssl bool) string {
	for _, name := range []string{"SSL_CERT_FILE", "SSL_CERT_DIR"} {
		v, set := env(name)
		switch {
		case v != "":
			return fmt.Sprintf("the environment's %s, which names what the client's TLS library reads in place of the system trust store: doctor installs into and verifies against that store, and does not interpret the variable", name)
		case set && openssl:
			return fmt.Sprintf("the environment's %s, which is set and empty: OpenSSL reads the variable whenever it is set, in place of the system trust store's own path, and doctor does not interpret what it then loads", name)
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

// NodeOptionsArgs splits a NODE_OPTIONS value into arguments as Node v26.13.0
// does before it reads any of them as an option: ParseNodeOptionsEnvVar,
// src/node_options.cc:2548-2587, byte for byte. An ASCII space outside double
// quotes ends an argument and nothing else does, so a tab, a newline or a
// no-break space stays in the argument beside it. A double quote opens or
// closes a string and is dropped, and inside a string a backslash takes the
// next byte as it is. bad is the error Node exits on, "" for none.
func NodeOptionsArgs(value string) (args []string, bad string) {
	// Bytes, not runes: Node appends each char to the argument as it is.
	var raw [][]byte
	collect := func() []string {
		for _, arg := range raw {
			args = append(args, string(arg))
		}
		return args
	}
	inString, startNew := false, true
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c == '\\' && inString:
			if i+1 == len(value) {
				return collect(), "invalid value for NODE_OPTIONS (invalid escape)"
			}
			i++
			c = value[i]
		case c == ' ' && !inString:
			startNew = true
			continue
		case c == '"':
			inString = !inString
			continue
		}
		if startNew {
			raw, startNew = append(raw, nil), false
		}
		raw[len(raw)-1] = append(raw[len(raw)-1], c)
	}
	if inString {
		return collect(), "invalid value for NODE_OPTIONS (unterminated string)"
	}
	return collect(), ""
}

// NodeRoots is what NODE_OPTIONS and NODE_USE_SYSTEM_CA say about the root
// store of the Node npm runs under.
type NodeRoots struct {
	// Bundled is --use-bundled-ca, OpenSSL --use-openssl-ca, which reads
	// OpenSSL's store in place of the bundled roots, and System
	// --use-system-ca or NODE_USE_SYSTEM_CA=1, which adds the system store
	// to them.
	Bundled, OpenSSL, System bool
}

// NodeOptions reads the environment's NODE_OPTIONS once, for the refusal and
// for the root store alike. unread is why it leaves the Node npm runs under
// unknown or unable to start, "" when it holds nothing but options that
// choose a root store, in a combination Node starts on; the roots mean
// nothing beside a non-empty unread.
//
// The arguments are NodeOptionsArgs', never a broader split: Node exits
// before npm starts on an argument it does not allow there ("is not allowed
// in NODE_OPTIONS"), a flag with a tab after it among them, and one it does
// allow can load code or change what TLS accepts (--require, --tls-min-v1.3,
// --openssl-config). Telling those apart is Node's option table, which
// nothing here ports, so any argument but the three is refused, in whatever
// other spelling Node takes for it.
//
// The three that remain are each valid alone, and Node checks them together
// before any script loads (PerProcessOptions::CheckOptions, src/node_options.cc
// at Node v26.13.0): --use-openssl-ca reads OpenSSL's store in place of the
// bundled roots, so Node exits on it beside --use-bundled-ca ("either
// --use-openssl-ca or --use-bundled-ca can be used, not both") and beside
// --use-system-ca, which NODE_USE_SYSTEM_CA=1 also turns on, in any order.
// --use-bundled-ca with --use-system-ca is the one pair it starts on. The
// value is never repeated.
func NodeOptions(getenv func(string) string) (roots NodeRoots, unread string) {
	if getenv == nil {
		return roots, ""
	}
	opts, bad := NodeOptionsArgs(getenv("NODE_OPTIONS"))
	if bad != "" {
		return roots, "the environment's NODE_OPTIONS, which Node cannot split into options (" + bad + ") and exits on before npm starts"
	}
	for _, opt := range opts {
		if !slices.Contains(nodeCAOptions, opt) {
			return roots, "the environment's NODE_OPTIONS, which holds an option other than " + strings.Join(nodeCAOptions, ", ") + ": Node splits it on spaces alone, exits on an option it does not allow there and changes what it loads or verifies on others, and doctor interprets those three alone"
		}
	}
	roots = NodeRoots{
		Bundled: slices.Contains(opts, "--use-bundled-ca"),
		OpenSSL: slices.Contains(opts, "--use-openssl-ca"),
		System:  slices.Contains(opts, "--use-system-ca"),
	}
	// flag is the option Node's own message names, and beside how the
	// environment turned it on.
	flag, beside := "", ""
	switch {
	case !roots.OpenSSL:
	case roots.Bundled:
		flag, beside = "--use-bundled-ca", "--use-bundled-ca"
	case roots.System:
		flag, beside = "--use-system-ca", "--use-system-ca"
	case getenv("NODE_USE_SYSTEM_CA") == "1":
		flag, beside = "--use-system-ca", "NODE_USE_SYSTEM_CA=1, which turns --use-system-ca on"
	}
	if flag != "" {
		return roots, "the environment's NODE_OPTIONS, which holds --use-openssl-ca beside " + beside + ": Node takes one root store of the two and exits on the pair before npm starts (either --use-openssl-ca or " + flag + " can be used, not both)"
	}
	roots.System = roots.System || getenv("NODE_USE_SYSTEM_CA") == "1"
	return roots, ""
}

// NodeOptionsUnread is NodeOptions' refusal alone.
func NodeOptionsUnread(getenv func(string) string) string {
	_, unread := NodeOptions(getenv)
	return unread
}
