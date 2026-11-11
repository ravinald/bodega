package clientconf

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/manifest"
)

// SystemCA is the system a CA file is listed under when no one client owns
// it: the anchors in the operating system's trust store, and the copy the
// clients' own settings name.
const SystemCA = "ca"

// Where a private CA goes. Each client setting that takes a path names one
// copy: CASharedPath for a file under /etc, CAUserPath for a file in a home
// directory, which an account without root can write.
const (
	CASharedPath = "/usr/local/share/bodega/ca.pem"
	CAUserPath   = "~/.config/bodega/ca.pem"
)

// CA is a PEM file of CA certificates, checked.
type CA struct {
	Certs []*x509.Certificate
	// PEM holds the certificates alone, re-encoded, so nothing else the
	// operator's file carried is copied to a world-readable path.
	PEM []byte
}

// ParseCA reads every certificate in data and refuses a file doctor should
// not install: one with no certificate, one holding anything that is not a
// certificate (a private key would be copied where every account reads it),
// and one holding a certificate that is not a CA, which no client accepts as
// a trust anchor for another certificate.
func ParseCA(data []byte) (CA, error) {
	var ca CA
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return CA{}, fmt.Errorf("it holds a %q block, and a CA file holds certificates only; a key in it would be copied where every account on the host reads it", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return CA{}, fmt.Errorf("certificate %d does not parse: %w", len(ca.Certs)+1, err)
		}
		if !cert.BasicConstraintsValid || !cert.IsCA {
			return CA{}, fmt.Errorf("certificate %d (%s) is not a CA: its basic constraints do not set CA:TRUE, so no client trusts what it signs. "+
				"Pass the certificate that issued bodega's, not bodega's own", len(ca.Certs)+1, cert.Subject)
		}
		ca.Certs = append(ca.Certs, cert)
		ca.PEM = append(ca.PEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	if len(ca.Certs) == 0 {
		return CA{}, fmt.Errorf("it holds no PEM certificate; a CA file opens with -----BEGIN CERTIFICATE-----")
	}
	return ca, nil
}

// CAHost is the host a CA is installed on.
type CAHost struct {
	// Base is the URL clients reach bodega at.
	Base string
	Home string
	// Root is the directory the absolute paths sit under, "" for the host's
	// own. A test roots them in a scratch directory.
	Root string
	GOOS string
	// OSRelease is the content of /etc/os-release, which names the Linux
	// family whose trust store command applies.
	OSRelease []byte
	// JVM is the trust store of the JVM Maven and Gradle run on, and
	// JVMTrusted the certificates it holds now. The zero JVM is the cacerts
	// of the keytool on PATH, and a nil JVMTrusted an empty store.
	JVM        JVMStore
	JVMTrusted []*x509.Certificate
	// Getenv reads the environment the host's clients start in, which can
	// name a configuration file a client reads in place of, or after, the
	// one the plan writes. Nil is an environment naming none.
	Getenv func(string) string
	// PipPrefix is the sys.prefix of the interpreter pip runs under, "" when
	// pip was not asked: its pip.conf outranks the global and per-user files.
	PipPrefix string
}

// shadow is an existing configuration file, other than the one a plan
// writes, whose settings the client reads ahead of the plan's. whole says the
// client reads it for everything the plan sets, so it takes the plan's whole
// edit; otherwise only its CA setting outranks the plan's, and only that is
// corrected.
type shadow struct {
	path  string
	whole bool
}

func regularFile(path string) (os.FileInfo, bool) {
	info, err := os.Stat(path)
	return info, err == nil && info.Mode().IsRegular()
}

// shadows lists the files that would leave the client of rec on its old
// settings once the plan's file at target is written, resolved by the rules
// the client loads its configuration by. npm and git read the file an
// environment variable names in place of the per-user one, so the plan's file
// is then never opened. pip loads every file in PipConfigFiles, a later one
// replacing an earlier one's options and a command's own section outranking
// [global] from any file. git reads sslCAInfo from the section whose URL
// matches longest, whichever file holds it.
func (h CAHost) shadows(rec PlanRecord, target string, planned []byte) []shadow {
	env := func(keys ...string) string {
		for _, k := range keys {
			if h.Getenv == nil {
				break
			}
			if v := h.Getenv(k); v != "" {
				return v
			}
		}
		return ""
	}
	own, _ := os.Stat(target)
	same := func(path string, info os.FileInfo) bool {
		return path == target || own != nil && os.SameFile(info, own)
	}
	var out []shadow
	add := func(path string, whole bool) {
		if !slices.ContainsFunc(out, func(s shadow) bool { return s.path == path }) {
			out = append(out, shadow{path, whole})
		}
	}
	user := strings.HasPrefix(rec.Path, "~/")
	var sel string
	switch {
	case rec.System == manifest.TypeNpm && user:
		sel = env("npm_config_userconfig", "NPM_CONFIG_USERCONFIG")
	case rec.System == manifest.TypeNpm:
		sel = env("npm_config_globalconfig", "NPM_CONFIG_GLOBALCONFIG")
	case rec.System == manifest.TypeGit && user:
		sel = env("GIT_CONFIG_GLOBAL")
	case rec.System == manifest.TypeGit:
		sel = env("GIT_CONFIG_SYSTEM")
	}
	if sel != "" && sel != os.DevNull {
		if abs, err := filepath.Abs(sel); err == nil {
			if info, ok := regularFile(abs); ok && !same(abs, info) {
				add(abs, true)
			}
		}
	}
	switch rec.System {
	case manifest.TypeGit:
		for _, f := range GitConfigFiles(h.Getenv, h.Home, h.Root) {
			info, ok := regularFile(f)
			if !ok || same(f, info) {
				continue
			}
			if data, err := os.ReadFile(f); err == nil && len(gitShadowHeaders(splitBody(data), h.Base)) > 0 {
				add(f, false)
			}
		}
	case manifest.TypePypi:
		files, global := PipConfigFiles(PipHost{GOOS: h.GOOS, Root: h.Root, Home: h.Home, Getenv: h.Getenv, Prefix: h.PipPrefix})
		// A target pip's own list does not name is a global file under another
		// root, so it sits where the global files do.
		at := global - 1
		for i, f := range files {
			if info, ok := regularFile(f); ok && same(f, info) {
				at = i
			}
		}
		want := PipOptions(append(slices.Clone(planned), "\ncert = x\n"...))
		for i, f := range files {
			info, ok := regularFile(f)
			if !ok || same(f, info) {
				continue
			}
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			for key := range PipOptions(data) {
				section, option, _ := strings.Cut(key, ".")
				_, set := want["global."+option]
				switch {
				case i > at && set:
					add(f, true)
				case i < at && option == "cert" && section != "global":
					add(f, false)
				}
			}
		}
	}
	return out
}

// ignored is the error for a plan file the environment tells its client not
// to load, or to load settings beside that no file holds: writing the file
// would report an install the client never reads. An environment variable
// naming an existing file is not one of these; shadows gives that file the
// edit. It also refuses what this package detects and does not interpret: a
// git file with an include, and anything beside cafile that assigns npm's CA
// list.
func (h CAHost) ignored(rec PlanRecord, target string) error {
	env := func(key string) string {
		if h.Getenv == nil {
			return ""
		}
		return h.Getenv(key)
	}
	// selects is the error for a variable naming, in place of target, a file
	// the client finds nothing in.
	selects := func(client string, keys ...string) error {
		for _, key := range keys {
			v := env(key)
			if v == "" {
				continue
			}
			abs, err := filepath.Abs(v)
			if err == nil && abs == target {
				return nil
			}
			if _, ok := regularFile(abs); ok && err == nil && v != os.DevNull {
				return nil
			}
			return fmt.Errorf("%s: %s is set to %s, which is not a file %s reads settings from, and it reads that in place of %s, so it would load neither the settings nor the CA written there. "+
				"Unset %s or point it at a configuration file, then re-run", rec.System, key, v, client, target, key)
		}
		return nil
	}
	user := strings.HasPrefix(rec.Path, "~/")
	switch {
	case rec.System == manifest.TypePypi && env("PIP_CONFIG_FILE") == os.DevNull:
		return fmt.Errorf("%s: PIP_CONFIG_FILE is set to %s, which tells pip to load no configuration file, so it would read neither the index nor the CA written to %s. "+
			"Unset PIP_CONFIG_FILE, then re-run", rec.System, os.DevNull, target)
	case rec.System == manifest.TypeNpm && rec.Path != NodeMirrorSystemPath && rec.Path != NodeMirrorUserPath:
		// npm keeps one CA list, which ca, ca[] and cafile each replace, the
		// environment after every file. The install writes cafile alone, so
		// anything else assigning that list is refused rather than reordered.
		for _, key := range []string{"NPM_CONFIG_CA", "npm_config_ca"} {
			if env(key) != "" {
				return fmt.Errorf("%s: %s is set, and npm reads the certificates it holds in place of the cafile this command writes to %s, so npm would not verify bodega's certificate with the CA installed. "+
					"Nothing was written. Unset %s, then re-run", rec.System, key, target, key)
			}
		}
		installed, err := h.caTarget(rec.Path)
		if err != nil {
			return fmt.Errorf("%s: %w", rec.System, err)
		}
		for _, key := range []string{"NPM_CONFIG_CAFILE", "npm_config_cafile"} {
			v := env(key)
			if abs, err := filepath.Abs(v); v != "" && (err != nil || abs != installed) {
				return fmt.Errorf("%s: %s is set to %s, and npm reads that file in place of the cafile this command writes to %s, so npm would not verify bodega's certificate with the CA installed. "+
					"Nothing was written. Unset %s, or add the CA to that file yourself and re-run without --ca-file", rec.System, key, v, target, key)
			}
		}
		files := []string{target}
		if user {
			for _, key := range []string{"npm_config_userconfig", "NPM_CONFIG_USERCONFIG"} {
				if v := env(key); v != "" {
					files = append(files, v)
				}
			}
		}
		loaded := NpmConfigFiles(h.Getenv, h.GOOS, h.Home, h.Root)
		// A line that cannot be told apart from a registry or CA option is
		// refused in every file npm loads and every file this edit writes,
		// ahead of the checks below, which read only lines they can name.
		for _, f := range append(slices.Clone(files), loaded...) {
			if line := NpmUnclassified(f); line != "" {
				return fmt.Errorf("%s: npm reads %s, so which option that line sets, and with it which registry npm asks and which CA list it verifies one against, cannot be told. "+
					"Nothing was written. Write that line as a plain name=value with no ${NAME} in the name, or remove it, then re-run", rec.System, line)
			}
		}
		for _, f := range files {
			if key := NpmInlineCA(f); key != "" {
				return fmt.Errorf("%s: %s sets %s, and npm keeps one CA list that %s and cafile each replace in the order the file sets them, so the cafile this command writes there would not be read alone. "+
					"Nothing was written. Move the certificates %s holds into a file of your own named by cafile, or remove the key, then re-run", rec.System, f, key, key, key)
			}
		}
		// The other files npm loads keep their own CA settings, which the
		// check after the write reads beside the one written here.
		for _, f := range loaded {
			if slices.Contains(files, f) {
				continue
			}
			if unread := NpmUnread(f); unread != "" {
				return fmt.Errorf("%s: npm reads %s, which this command detects and does not interpret, so whether npm would verify bodega's certificate with the CA written to %s cannot be told. "+
					"Nothing was written. Leave that file one plain cafile naming a certificate file, or none, then re-run", rec.System, unread, target)
			}
		}
		if user {
			return selects("npm", "npm_config_userconfig", "NPM_CONFIG_USERCONFIG")
		}
	case rec.System == manifest.TypeGit:
		// The probe's own classifier over the probe's own file set, with the
		// file the plan edits beside it: a construct that leaves the verdict
		// unchecked after the write is refused before it.
		if unread := GitUnread(h.Getenv, append(GitConfigFiles(h.Getenv, h.Home, h.Root), target)); len(unread) > 0 {
			return fmt.Errorf("%s: git takes configuration from %s, which this command does not read, so a setting there could outrank the CA written to %s unseen. "+
				"Nothing was written. Unset the variable, move included settings into the file itself, or write the header as [name] or [name \"subsection\"] alone on its line and the value on one line, then re-run", rec.System, unread[0], target)
		}
		if user {
			return selects("git", "GIT_CONFIG_GLOBAL")
		}
	}
	return nil
}

// caTarget is where this host keeps the copy of the CA that a setting in the
// file a plan writes at planPath names: under the home directory for a
// per-user file, under Root otherwise.
func (h CAHost) caTarget(planPath string) (string, error) {
	if strings.HasPrefix(planPath, "~/") {
		return TargetPath(CAUserPath, h.Home)
	}
	target, err := TargetPath(CASharedPath, h.Home)
	if err != nil {
		return "", err
	}
	return filepath.Join(h.Root, target), nil
}

// CAInstall is a plan with a CA added to it.
type CAInstall struct {
	// Changes is the plan's changes with the CA setting merged into each
	// file a client reads one from, followed by the certificate files.
	Changes []Change
	// Step is the command that rebuilds the system trust store from the
	// anchors in Changes, or nil when the store the host's clients read
	// already holds every one of them.
	Step []string
	// Imports are the keytool commands that add to the JVM trust store each
	// certificate it lacks, run after Changes are written: each names a file
	// among them.
	Imports [][]string
	// Notes name what the operator still does by hand, one per system.
	Notes map[string]string
	// System lists the systems whose anchors went into the operating
	// system's trust store. For every other system the plan left that store
	// as it was.
	System []string
}

// systemStore is where one operating system family reads trust anchors, one
// certificate to a file, the command that rebuilds its store from them, and
// the files that command writes, which are what the host's clients read.
type systemStore struct {
	dir, ext string
	step     []string
	live     []string
}

// systemStoreFor resolves the trust store of the host. certctl before FreeBSD
// 14 reads only *.pem from its trust path, so that is the extension there,
// and before 15 it writes hashed links and no bundle, so both are read. Two
// certificates of one subject hash to one name and take suffixes .0 and .1,
// so every numbered entry is read, not the first.
func systemStoreFor(h CAHost) (systemStore, error) {
	if h.GOOS == OSFreeBSD {
		return systemStore{"/usr/local/share/certs", ".pem", []string{"certctl", "rehash"},
			[]string{"/etc/ssl/cert.pem", "/etc/ssl/certs/*.[0-9]*"}}, nil
	}
	if h.GOOS == OSLinux {
		for _, id := range osReleaseFamily(h.OSRelease) {
			switch id {
			case "debian", "ubuntu":
				return systemStore{"/usr/local/share/ca-certificates", ".crt", []string{"update-ca-certificates"},
					[]string{"/etc/ssl/certs/ca-certificates.crt"}}, nil
			case "rhel", "fedora", "centos":
				return systemStore{"/etc/pki/ca-trust/source/anchors", ".pem", []string{"update-ca-trust", "extract"},
					[]string{"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"}}, nil
			}
		}
	}
	return systemStore{}, fmt.Errorf("doctor installs into the system trust store on Debian and Ubuntu, the RHEL family and FreeBSD, and this host is none of them")
}

// holds reports whether the store the rebuild command last wrote under root
// carries every certificate. An anchor file in place proves nothing on its
// own: the command may have failed after the file was written.
func (s systemStore) holds(root string, certs []*x509.Certificate) bool {
	have := map[[sha256.Size]byte]bool{}
	for _, pattern := range s.live {
		files, _ := filepath.Glob(filepath.Join(root, pattern))
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
				have[sha256.Sum256(block.Bytes)] = true
			}
		}
	}
	for _, c := range certs {
		if !have[sha256.Sum256(c.Raw)] {
			return false
		}
	}
	return true
}

// JVMStore is the keystore a JVM reads its trust anchors from, and the
// keytool that reads and edits it. The JVM reads nothing else: neither the
// system trust store nor any setting in Maven's or Gradle's own files.
type JVMStore struct {
	// Keytool is the keytool of the JVM, "" for the one on PATH.
	Keytool string
	// Keystore is the file javax.net.ssl.trustStore names, or the JDK's
	// jssecacerts, and "" for the cacerts of the JDK Keytool belongs to.
	Keystore string
	// Password is javax.net.ssl.trustStorePassword, "" for the JDK's default.
	Password string
}

const jvmDefaultPassword = "changeit"

// ResolveJVMStore finds the trust store of the JVM Maven and Gradle start:
// the JDK at JAVA_HOME, or else the one whose keytool is on PATH, and the
// keystore a -Djavax.net.ssl.trustStore in JAVA_TOOL_OPTIONS or MAVEN_OPTS
// names. MAVEN_OPTS is read last because the JVM takes it after
// JAVA_TOOL_OPTIONS and the later definition wins. With no such property JSSE
// loads lib/security/jssecacerts when the JDK holds one and cacerts only
// otherwise, so a JDK with a jssecacerts never reads its cacerts.
func ResolveJVMStore(getenv func(string) string, lookPath func(string) (string, error)) (JVMStore, error) {
	var s JVMStore
	for _, opt := range strings.Fields(getenv("JAVA_TOOL_OPTIONS") + " " + getenv("MAVEN_OPTS")) {
		if v, ok := strings.CutPrefix(opt, "-Djavax.net.ssl.trustStore="); ok {
			s.Keystore = v
		}
		if v, ok := strings.CutPrefix(opt, "-Djavax.net.ssl.trustStorePassword="); ok {
			s.Password = v
		}
	}
	home := getenv("JAVA_HOME")
	if home != "" {
		s.Keytool = filepath.Join(home, "bin", "keytool")
	} else {
		path, err := lookPath("keytool")
		if err != nil {
			return JVMStore{}, fmt.Errorf("no keytool on PATH and JAVA_HOME is unset, so the JVM Maven and Gradle run on is not known; set JAVA_HOME to its JDK")
		}
		s.Keytool = path
		if real, err := filepath.EvalSymlinks(path); err == nil {
			home = filepath.Dir(filepath.Dir(real))
		}
	}
	if s.Keystore == "" {
		// The second directory is a JDK 8, whose JRE sits a level down.
		for _, dir := range []string{"lib/security", "jre/lib/security"} {
			jsse := filepath.Join(home, dir, "jssecacerts")
			if info, err := os.Stat(jsse); err == nil && info.Mode().IsRegular() {
				s.Keystore = jsse
				break
			}
		}
	}
	return s, nil
}

// Name is how a message names the store.
func (s JVMStore) Name() string {
	if s.Keystore != "" {
		return "the JVM trust store " + s.Keystore
	}
	return "the cacerts keystore of the JDK " + s.keytool() + " belongs to"
}

func (s JVMStore) keytool() string {
	if s.Keytool == "" {
		return "keytool"
	}
	return s.Keytool
}

func (s JVMStore) command(verb ...string) []string {
	cmd := append([]string{s.keytool()}, verb...)
	if s.Keystore != "" {
		cmd = append(cmd, "-keystore", s.Keystore)
	} else {
		cmd = append(cmd, "-cacerts")
	}
	pass := s.Password
	if pass == "" {
		pass = jvmDefaultPassword
	}
	return append(cmd, "-storepass", pass)
}

// ImportCommand adds the certificate in file to the store as alias.
func (s JVMStore) ImportCommand(alias, file string) []string {
	return append(s.command("-importcert", "-noprompt", "-trustcacerts"), "-alias", alias, "-file", file)
}

// Trusted lists the certificates the store holds, by running keytool.
func (s JVMStore) Trusted() ([]*x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := s.command("-list", "-rfc")
	out, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %w (%s). keytool lists a JDK's own cacerts from JDK 9 on, with the password %q unless -Djavax.net.ssl.trustStorePassword in MAVEN_OPTS names another",
			RedactJVMCommand(cmd), err, jvmDiagnostic(out, cmd), jvmDefaultPassword)
	}
	return ParseKeytoolList(out), nil
}

// RunJVMCommand runs a keytool command and returns what it said when it
// failed. Its output is captured, never passed through: a JVM opens with a
// banner echoing JAVA_TOOL_OPTIONS, which is where a keystore password sits.
func RunJVMCommand(cmd []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w (%s)", err, jvmDiagnostic(out, cmd))
	}
	return nil
}

var jvmSecret = regexp.MustCompile(`(?i)(pass(?:word|phrase)?[^\s=:]*[=:]\s*)\S+`)

// jvmDiagnostic is the first line of a failed keytool's output that is its
// own, with anything that reads as a password blanked. The JVM's "Picked up"
// banners are skipped whole: they print the environment, not the failure.
func jvmDiagnostic(out []byte, cmd []string) string {
	var secret string
	for i := 1; i < len(cmd); i++ {
		if cmd[i-1] == "-storepass" && cmd[i] != jvmDefaultPassword {
			secret = cmd[i]
		}
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "Picked up ") {
			continue
		}
		if secret != "" {
			line = strings.ReplaceAll(line, secret, "<trustStorePassword>")
		}
		return jvmSecret.ReplaceAllString(line, "${1}<redacted>")
	}
	return "it printed nothing of its own"
}

// ParseKeytoolList reads the certificates out of keytool -list -rfc output.
// An entry keytool prints that does not parse is no trust anchor and is left
// out.
func ParseKeytoolList(out []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	for block, rest := pem.Decode(out); block != nil; block, rest = pem.Decode(rest) {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil && block.Type == "CERTIFICATE" {
			certs = append(certs, cert)
		}
	}
	return certs
}

// RedactJVMCommand renders a keytool command for a message, without a
// keystore password an operator set: the JDK's default is public, any other
// is theirs.
func RedactJVMCommand(cmd []string) string {
	out := slices.Clone(cmd)
	for i := 1; i < len(out); i++ {
		if out[i-1] == "-storepass" && out[i] != jvmDefaultPassword {
			out[i] = "<trustStorePassword>"
		}
	}
	return strings.Join(out, " ")
}

// osReleaseFamily is ID followed by each ID_LIKE entry, the order os-release
// gives for "what this distribution is, then what it derives from".
func osReleaseFamily(data []byte) []string {
	var id string
	var like []string
	for _, line := range strings.Split(string(data), "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		switch key {
		case "ID":
			id = val
		case "ID_LIKE":
			like = strings.Fields(val)
		}
	}
	return append([]string{id}, like...)
}

// ownStoreSystems are the systems whose client reads a CA from its own
// setting. Every other system verifies through the system trust store, apart
// from Maven, whose JVM reads a keystore of its own.
var ownStoreSystems = []string{manifest.TypeNpm, manifest.TypePypi, manifest.TypeOCI, manifest.TypeGit}

// AddCA plans the install of ca for every system changes configures: the
// client's own setting merged into the file the plan already writes for npm,
// pip, git and containerd, a ca.crt in the directory Docker and podman read
// per registry host, an import into the JVM trust store for Maven and Gradle,
// and for every other system an anchor in the operating system's trust store.
//
// A client that reads an existing configuration file ahead of the plan's (a
// pip.conf pip loads later, npm's userconfig, GIT_CONFIG_GLOBAL, a git section
// scoped to a longer URL) gets the edit in that file too, as a change of its
// own: the plan's file alone would leave the client reading its old settings.
//
// Maven's settings.xml and Composer's config.json, which NewChange merges for
// any plan, are merged again here so bodega's own mirror and repository keep
// the fields the plan does not set.
//
// Every file the plan edits that already exists keeps what the plan does not
// set, whether its client reads a CA setting or the system store: kindOf
// names how each format takes the plan's settings, where a plan without a CA
// replaces the file whole.
//
// The certificate files follow the plan's own changes, because Apply writes
// last to first: a setting naming a CA file is written only after that file.
func AddCA(changes []Change, ca CA, h CAHost) (CAInstall, error) {
	base, err := url.Parse(h.Base)
	if err != nil || base.Host == "" {
		return CAInstall{}, fmt.Errorf("%q is not a URL with a host", h.Base)
	}
	if base.Scheme != "https" {
		return CAInstall{}, fmt.Errorf("%s is plain http, where no client verifies a certificate, so there is no CA to install", h.Base)
	}
	in := CAInstall{Changes: slices.Clone(changes), Notes: map[string]string{}}
	var files []Change
	// resolve turns a path as a plan writes it into this host's: ~/ under the
	// home directory, anything else under Root.
	resolve := func(path string) (string, error) {
		target, err := TargetPath(path, h.Home)
		if err != nil || strings.HasPrefix(path, "~/") {
			return target, err
		}
		return filepath.Join(h.Root, target), nil
	}
	addFile := func(system, target string, content []byte) error {
		if slices.ContainsFunc(files, func(c Change) bool { return c.Target == target }) {
			return nil
		}
		sum := sha256.Sum256(content)
		c, err := NewChange(PlanRecord{System: system, Action: PlanInstall, Path: target, SHA256: hex.EncodeToString(sum[:])}, content, h.Home)
		if err != nil {
			return err
		}
		files = append(files, c)
		return nil
	}
	// sharedPath is where the copy a setting in the file at planPath names
	// goes, and shared installs it.
	sharedPath := h.caTarget
	shared := func(planPath string) (string, error) {
		target, err := sharedPath(planPath)
		if err != nil {
			return "", err
		}
		return target, addFile(SystemCA, target, ca.PEM)
	}

	var system []string
	var selected []Change
	jvm := false
	for i, c := range in.Changes {
		rec := c.Record
		if err := h.ignored(rec, c.Target); err != nil {
			return CAInstall{}, err
		}
		if c.Existed && c.planned != nil {
			switch {
			case rec.System == manifest.TypeMaven && rec.Path == MavenSettingsPath:
				merged, err := mergeMavenMirror(c.Old, c.planned)
				if err != nil {
					return CAInstall{}, fmt.Errorf("%s: cannot merge bodega's mirror into %s: %w. "+
						"Write that mirror with plain <id>, <mirrorOf> and <url> elements, once, or move the file aside, then re-run", rec.System, c.Target, err)
				}
				c.New = merged
			case rec.System == manifest.TypeComposer:
				merged, err := mergeComposer(c.Old, c.planned, true)
				if err != nil {
					return CAInstall{}, fmt.Errorf("%s: cannot merge bodega's repository into %s: %w", rec.System, c.Target, err)
				}
				c.New = merged
			}
			in.Changes[i].New = c.New
		}
		// header and line are the CA setting and the section it belongs
		// under.
		kind := kindOf(rec)
		var header string
		var line func(caPath string) string
		switch {
		case rec.System == manifest.TypeMaven:
			// The JVM import is planned once for the system; each of its
			// records still goes on to the merge that keeps its own file.
			certs := ca.Certs
			if jvm {
				certs = nil
			}
			jvm = true
			for _, cert := range certs {
				if slices.ContainsFunc(h.JVMTrusted, func(have *x509.Certificate) bool { return bytes.Equal(have.Raw, cert.Raw) }) {
					continue
				}
				// The fingerprint keeps a rotated CA from colliding with the
				// alias of the one it replaces, which keytool refuses.
				sum := sha256.Sum256(cert.Raw)
				alias := "bodega-ca-" + hex.EncodeToString(sum[:6])
				dir, err := sharedPath(rec.Path)
				if err != nil {
					return CAInstall{}, fmt.Errorf("%s: %w", rec.System, err)
				}
				target := filepath.Join(filepath.Dir(dir), alias+".pem")
				if err := addFile(rec.System, target, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})); err != nil {
					return CAInstall{}, err
				}
				in.Imports = append(in.Imports, h.JVM.ImportCommand(alias, target))
			}
			if len(in.Imports) > 0 {
				in.Notes[rec.System] = "a JVM already running keeps the trust store it started with; stop Gradle's daemons (gradle --stop) and Maven's (mvnd --stop) once the import has run"
			}
		case !slices.Contains(ownStoreSystems, rec.System):
			if !slices.Contains(system, rec.System) {
				system = append(system, rec.System)
			}
		case rec.System == manifest.TypeNpm && rec.Path != NodeMirrorSystemPath && rec.Path != NodeMirrorUserPath:
			line = func(caPath string) string { return "cafile=" + caPath }
		case rec.System == manifest.TypePypi:
			header = "[global]"
			line = func(caPath string) string { return "cert = " + caPath }
		case rec.System == manifest.TypeGit:
			header = fmt.Sprintf("[http %q]", trim(h.Base)+"/")
			line = func(caPath string) string { return "\tsslCAInfo = " + gitQuote(caPath) }
		case rec.System == manifest.TypeOCI && strings.HasSuffix(rec.Path, "/hosts.toml"):
			header = "[host." + jsonString(trim(h.Base)) + "]"
			line = func(caPath string) string { return "  ca = " + jsonString(caPath) }
		case rec.System == manifest.TypeOCI && OCIRuntimeOf(rec.Path) == RuntimeDocker:
			// Docker reads certs.d beside daemon.json, keyed by the host and
			// port of the registry or mirror it is talking to.
			if err := addFile(rec.System, filepath.Join(filepath.Dir(c.Target), "certs.d", base.Host, "ca.crt"), ca.PEM); err != nil {
				return CAInstall{}, err
			}
		case rec.System == manifest.TypeOCI && OCIRuntimeOf(rec.Path) == RuntimePodman:
			// The one directory podman reads for this host, which hides the
			// others even when it is empty; with none yet, the certs.d two
			// levels above the drop-in, which then becomes that directory.
			dir := PodmanCertDir(h.Home, h.Root, base.Host)
			if dir == "" {
				dir = filepath.Join(filepath.Dir(filepath.Dir(c.Target)), "certs.d", base.Host)
			}
			if err := addFile(rec.System, filepath.Join(dir, "ca.crt"), ca.PEM); err != nil {
				return CAInstall{}, err
			}
		}
		// unreadSection refuses a file holding a section header the merge
		// does not match sections by, before any edit is built on it.
		unreadSection := func(target string, body []string) error {
			if kind.unread == nil {
				return nil
			}
			if stray := kind.unread(body); stray != "" {
				return fmt.Errorf("%s: %s holds the line %q, which opens a section in a form this merge does not match sections by, so a setting under it could outrank or repeat the plan's unseen. "+
					"Write the header as [name] alone on its line (git also takes [name \"subsection\"] and a trailing comment), or move the file aside, then re-run", rec.System, target, stray)
			}
			return nil
		}
		refuse := func(target string, err error) error {
			return fmt.Errorf("%s: %s with bodega's settings merged in would not read as the plan sets it (%w). "+
				"It holds a form this merge does not edit, such as a value spanning several lines or a table spelled another way; move the file aside and re-run to have it written whole", rec.System, target, err)
		}
		if line == nil {
			if c.Existed && !c.Unchanged() {
				merged, err := kind.merge(c.Old, c.New)
				if err != nil {
					return CAInstall{}, refuse(c.Target, err)
				}
				in.Changes[i].New = merged
			}
			continue
		}
		caPath, err := shared(rec.Path)
		if err != nil {
			return CAInstall{}, fmt.Errorf("%s: %w", rec.System, err)
		}
		set := []string{line(caPath)}
		// outranking lists the sections of body whose own CA setting the
		// client reads ahead of the one under header: for pip a command's
		// section, which outranks [global] (every section but [global] when
		// the file loads before the plan's), and for git a section scoped to
		// a URL at or below bodega's.
		outranking := func(body []string, earlier bool) []string {
			switch rec.System {
			case manifest.TypePypi:
				all := sectionsSetting(body, "cert", *kind.rules)
				if earlier {
					all = slices.DeleteFunc(all, func(s string) bool { return s == header })
				}
				return all
			case manifest.TypeGit:
				return gitShadowHeaders(body, h.Base)
			}
			return nil
		}
		// edit is the plan's file with the CA setting in it, merged into old
		// when the host holds a file there.
		edit := func(target string, old, planned []byte, existed bool) ([]byte, error) {
			body := splitBody(planned)
			if existed {
				if err := unreadSection(target, splitBody(old)); err != nil {
					return nil, err
				}
				// planned holds the plan's file and nothing of the host's but
				// a credential; the host's file is what the settings join.
				body = mergeSettings(splitBody(old), body, *kind.rules)
			}
			// A setting in a section leads it, so it reads beside the header
			// that scopes it; npm's file has no sections, and it ends the
			// file.
			body = setSection(body, header, set, *kind.rules, header != "")
			for _, other := range outranking(body, false) {
				if other != header {
					body = setSection(body, other, set, *kind.rules, false)
				}
			}
			merged := joinBody(body)
			if kind.holds != nil {
				if err := kind.holds(merged, planned); err != nil {
					return nil, refuse(target, err)
				}
			}
			if existed {
				// What the plan sets here is its file and the CA setting, under
				// whichever section carries one.
				sets := append(splitBody(planned), set...)
				if err := linesKeep(splitBody(old), body, sets, *kind.rules); err != nil {
					return nil, refuse(target, err)
				}
				if kind.keeps != nil {
					withCA := joinBody(setSection(splitBody(planned), header, set, *kind.rules, header != ""))
					if err := kind.keeps(old, merged, withCA); err != nil {
						return nil, refuse(target, err)
					}
				}
			}
			return merged, nil
		}
		if in.Changes[i].New, err = edit(c.Target, c.Old, c.New, c.Existed); err != nil {
			return CAInstall{}, err
		}
		// Each file this client reads ahead of the plan's takes the edit too,
		// or the client never reads what was installed. A file read in the
		// plan's place keeps its own credential: the one the plan carried
		// over belongs to the file it came from.
		for _, sh := range h.shadows(rec, c.Target, c.New) {
			if slices.ContainsFunc(selected, func(o Change) bool { return o.Target == sh.path }) {
				continue
			}
			old, err := os.ReadFile(sh.path)
			if err != nil {
				return CAInstall{}, fmt.Errorf("%s: read %s, which this client reads ahead of %s: %w", rec.System, sh.path, c.Target, err)
			}
			var merged []byte
			if sh.whole {
				planned := c.New
				if kept := npmCredential(splitLines(string(planned))); rec.System == manifest.TypeNpm && len(kept) > 0 {
					var lines []string
					for _, l := range splitLines(string(planned)) {
						if !slices.Contains(kept, l) {
							lines = append(lines, l)
						}
					}
					planned = joinBody(lines)
				}
				if merged, err = edit(sh.path, old, planned, true); err != nil {
					return CAInstall{}, err
				}
			} else {
				body := splitBody(old)
				if err := unreadSection(sh.path, body); err != nil {
					return CAInstall{}, err
				}
				for _, other := range outranking(body, true) {
					body = setSection(body, other, set, *kind.rules, false)
				}
				merged = joinBody(body)
			}
			also := rec
			also.Path = sh.path
			selected = append(selected, Change{Record: also, Target: sh.path, Old: old, Existed: true, New: merged})
		}
	}

	if len(system) > 0 {
		store, err := systemStoreFor(h)
		if err != nil {
			return CAInstall{}, fmt.Errorf("%s verify through the system trust store: %w.\n"+
				"  Add the CA to this host's store by hand, then re-run without --ca-file, or name only the systems that read their own: %s",
				strings.Join(system, ", "), err, strings.Join(append(slices.Clone(ownStoreSystems), manifest.TypeMaven), ", "))
		}
		before := len(files)
		for i, cert := range ca.Certs {
			name := "bodega-ca"
			if i > 0 {
				name = fmt.Sprintf("bodega-ca-%d", i+1)
			}
			one := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
			target, err := resolve(filepath.Join(store.dir, name+store.ext))
			if err != nil {
				return CAInstall{}, err
			}
			if err := addFile(SystemCA, target, one); err != nil {
				return CAInstall{}, err
			}
		}
		if slices.ContainsFunc(files[before:], func(c Change) bool { return !c.Unchanged() }) || !store.holds(h.Root, ca.Certs) {
			in.Step = store.step
		}
		in.System = system
	}
	in.Changes = append(append(in.Changes, selected...), files...)
	return in, nil
}

func splitBody(body []byte) []string {
	s := strings.TrimRight(string(body), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func joinBody(lines []string) []byte {
	return bytes.TrimLeft([]byte(strings.Join(lines, "\n")+"\n"), "\n")
}

// settingKey is the key of a "key = value" line of an INI, TOML or git
// config body, lowercased, and "" for a comment, a header or a blank line.
func settingKey(line string) string {
	t := strings.TrimSpace(line)
	if t == "" || strings.ContainsRune("#;[", rune(t[0])) {
		return ""
	}
	key, _, ok := strings.Cut(t, "=")
	if !ok {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(key))
}

// mergeSettings sets every setting of planned in old, section by section,
// and keeps every other line of old: its other settings, sections, comments
// and their order. planned's own comments are not carried.
func mergeSettings(old, planned []string, rules lineRules) []string {
	var headers []string
	bySection := map[string][]string{}
	header := ""
	for _, l := range planned {
		if t := strings.TrimSpace(l); strings.HasPrefix(t, "[") {
			header = t
			continue
		}
		if rules.key(l) == "" {
			continue
		}
		if _, ok := bySection[header]; !ok {
			headers = append(headers, header)
		}
		bySection[header] = append(bySection[header], l)
	}
	for _, h := range headers {
		old = setSection(old, h, bySection[h], rules, false)
	}
	return old
}

func indentOf(line string) int { return len(line) - len(strings.TrimLeft(line, " \t")) }

// lineScan walks a body telling the lines that open a setting from the lines
// that continue the one above.
type lineScan struct {
	rules lineRules
	// keyIndent is the indentation of the setting a deeper line continues,
	// -1 under a header before its first setting.
	keyIndent int
	slash     bool
}

// continues reports whether l continues the line above it.
func (s *lineScan) continues(l string) bool {
	t := strings.TrimSpace(l)
	cont := s.slash || s.rules.indent && s.keyIndent >= 0 && t != "" && indentOf(l) > s.keyIndent
	s.slash = s.rules.backslash && strings.HasSuffix(t, `\`)
	return cont
}

// sectionsSetting lists the headers of the sections of lines that set key.
func sectionsSetting(lines []string, key string, rules lineRules) []string {
	var out []string
	scan := lineScan{rules: rules, keyIndent: -1}
	header := ""
	for _, l := range lines {
		if scan.continues(l) {
			continue
		}
		if t := strings.TrimSpace(l); strings.HasPrefix(t, "[") {
			header, scan.keyIndent = t, -1
			continue
		}
		k := rules.key(l)
		if k == "" {
			continue
		}
		scan.keyIndent = indentOf(l)
		if k == key && !slices.Contains(out, header) {
			out = append(out, header)
		}
	}
	return out
}

// setSection sets the lines of set, each a setting, under header: every line
// in a section of that name giving one of their keys is dropped, with the
// lines continuing it, and set goes where the first of them stood. With none
// there it goes first in the section when lead is set, and after the
// section's last line otherwise. A body with no such section gains it at the
// end. An empty header is the lines above the first section, the whole body
// of a file that has none.
//
// Where indentation continues a value, set takes the indentation of the
// section's own settings: a setting written shallower than the one under it
// would swallow that one as its continuation.
//
// A key may repeat in set (git's insteadOf does), which is why the keys are
// replaced as a group rather than line by line.
func setSection(lines []string, header string, set []string, rules lineRules, lead bool) []string {
	keys := map[string]bool{}
	for _, l := range set {
		keys[rules.key(l)] = true
	}
	var out []string
	in := header == ""
	start, end, at := -1, -1, -1
	if in {
		start = 0
	}
	closeSection := func() {
		if !in || end >= 0 {
			return
		}
		for end = len(out); end > start && strings.TrimSpace(out[end-1]) == ""; end-- {
		}
	}
	scan := lineScan{rules: rules, keyIndent: -1}
	margin, dropping := "", false
	for _, l := range lines {
		if scan.continues(l) {
			if !dropping {
				out = append(out, l)
			}
			continue
		}
		if t := strings.TrimSpace(l); strings.HasPrefix(t, "[") {
			closeSection()
			in, dropping, scan.keyIndent = header != "" && t == header, false, -1
			out = append(out, l)
			if in && start < 0 {
				start = len(out)
			}
			continue
		}
		// A blank line or a comment opens nothing: the lines under it still
		// continue the setting above it.
		if k := rules.key(l); k != "" {
			if in && scan.keyIndent < 0 {
				margin = l[:indentOf(l)]
			}
			scan.keyIndent = indentOf(l)
			if dropping = in && keys[k]; dropping {
				if at < 0 {
					at = len(out)
				}
				continue
			}
		}
		out = append(out, l)
	}
	closeSection()
	if rules.indent && margin != "" {
		set = slices.Clone(set)
		for i, l := range set {
			set[i] = margin + strings.TrimLeft(l, " \t")
		}
	}
	if start < 0 {
		return append(append(out, header), set...)
	}
	if at < 0 {
		at = end
		if lead {
			at = start
		}
	}
	return slices.Insert(out, at, set...)
}
