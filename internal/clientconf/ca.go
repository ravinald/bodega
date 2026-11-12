package clientconf

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

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
	case rec.System == manifest.TypeHelm:
		// helm reads one repositories.yaml, which the environment can move.
		sel = HelmRepositoryFile(h.Getenv, h.GOOS, h.Home)
	case rec.System == manifest.TypeGomod:
		// GOENV=off reads no file, which the verdict reports; there is no
		// file to edit in its place.
		if sel = env("GOENV"); sel == "off" {
			sel = ""
		}
		if dir := env("XDG_CONFIG_HOME"); sel == "" && dir != "" && h.GOOS != OSDarwin {
			sel = filepath.Join(dir, "go", "env")
		}
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

// pipCommandIndex refuses a pip configuration pip cannot load, and one whose
// command section sets an index the plan does not. pip reads a command's own section ahead of
// [global] from every file it loads, so an [install] index-url anywhere keeps
// pip install on that index after the plan writes bodega's under [global],
// and the CA installed for bodega would certify an endpoint pip never asks.
func (h CAHost) pipCommandIndex(rec PlanRecord, target string, planned []byte) error {
	want := PipOptions(planned)
	files, _ := PipConfigFiles(PipHost{GOOS: h.GOOS, Root: h.Root, Home: h.Home, Getenv: h.Getenv, Prefix: h.PipPrefix})
	if !slices.Contains(files, target) {
		files = append(files, target)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if err := PipLoadError(data); err != nil {
			return fmt.Errorf("%s: pip refuses to load %s (%v), so it aborts before reading any index or cert this command would write, and the install could not be verified. Nothing was written. Fix %s so pip loads it, then re-run", rec.System, f, err, f)
		}
		for key, v := range PipOptions(data) {
			section, option, _ := strings.Cut(key, ".")
			if section == "global" || (option != "index-url" && option != "extra-index-url") {
				continue
			}
			if planned, ok := want["global."+option]; ok && strings.TrimSpace(v) != strings.TrimSpace(planned) {
				return fmt.Errorf("%s: %s sets %s = %s under [%s], and pip reads a command's own section ahead of the [global] index this command writes to %s, so pip %s would keep fetching from %s and the CA installed for bodega would verify an index pip does not use. "+
					"Nothing was written. Remove %s from [%s] or set it to %s, then re-run", rec.System, f, option, v, section, target, section, v, option, section, planned)
			}
		}
	}
	return nil
}

// ignored is the error for a plan file the environment tells its client not
// to load, or to load settings beside that no file holds: writing the file
// would report an install the client never reads. An environment variable
// naming an existing file is not one of these; shadows gives that file the
// edit. It also refuses what this package detects and does not interpret: a
// git file with an include, and anything beside cafile that assigns npm's CA
// list. And it refuses a file its client cannot load: git's, helm's
// repositories.yaml, and apt's configuration.
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
	if conflict := NpmEnvConflict(h.Getenv); rec.System == manifest.TypeNpm && conflict != "" {
		return fmt.Errorf("%s: npm reads %s, so which registry npm asks, which npmrc it loads and which CA list it verifies with cannot be told. "+
			"Nothing was written. Unset one of the two, or give both the same value, then re-run", rec.System, conflict)
	}
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
		// The probe's own classifier over every file npm loads and every file
		// this edit writes. A file the edit writes is not exempt: replacing a
		// cafile line npm would not have read as written is still an edit to
		// a construct this command detects and does not interpret.
		seen := map[string]bool{}
		for _, f := range append(slices.Clone(files), loaded...) {
			if seen[f] {
				continue
			}
			seen[f] = true
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
		files := append(GitConfigFiles(h.Getenv, h.Home, h.Root), target)
		if bad := GitLoadError(files); bad != "" {
			return fmt.Errorf("%s: git refuses to load %s and aborts every command that reads it, so it would read neither the rewrite nor the CA written to %s, and the install could not be verified. "+
				"Nothing was written. Fix that line so git loads the file (git config --file <file> --list names it), then re-run", rec.System, bad, target)
		}
		if unread := GitUnread(h.Getenv, files); len(unread) > 0 {
			return fmt.Errorf("%s: git takes configuration from %s, which this command does not read, so a setting there could outrank the CA written to %s unseen. "+
				"Nothing was written. Unset the variable, move included settings into the file itself, or write the header as [name] or [name \"subsection\"] alone on its line and the value on one line, then re-run", rec.System, unread[0], target)
		}
		if user {
			return selects("git", "GIT_CONFIG_GLOBAL")
		}
	case rec.System == manifest.TypeApt:
		// apt's whole configuration, loaded as apt loads it: a statement apt
		// refuses in any file stops every apt command, whichever option it
		// names, and a rebuilt system store does not change that.
		if _, err := LoadAptConfig(h.Root, h.Getenv); err != nil {
			return fmt.Errorf("%s: apt does not load its configuration (%w) and fails every command, so it would read neither the source written to %s nor the CA this command installs, and the install could not be verified. "+
				"Nothing was written. Repair what the error names (apt-config dump repeats a syntax error), then re-run", rec.System, err, target)
		}
	case rec.System == manifest.TypeHelm:
		// The file helm reads and the file the plan edits, each loaded whole
		// as helm loads it: a wrong type in a field no edit touches still
		// stops helm, and the merge would carry it into the rewrite.
		for _, f := range []string{HelmRepositoryFile(h.Getenv, h.GOOS, h.Home), target} {
			if f == "" {
				continue
			}
			if _, err := LoadHelmFile(f); err != nil {
				return fmt.Errorf("%s: helm refuses to load its repository file (%w) and fails every command that reads it, so it would read neither the repository nor the CA this command installs, and the install could not be verified. "+
					"Nothing was written. Fix that field so helm loads the file (helm repo update names it), then re-run", rec.System, err)
			}
		}
	}
	return nil
}

// dockerReads refuses a plan for Docker Engine on a host whose dockerd would
// not load its daemon.json, as the plan leaves it: dockerd does not start
// with that file, so a ca.crt under certs.d would report an install no pull
// uses.
func (h CAHost) dockerReads(changes []Change) error {
	if !slices.ContainsFunc(changes, func(c Change) bool {
		return c.Record.System == manifest.TypeOCI && OCIRuntimeOf(c.Record.Path) == RuntimeDocker
	}) {
		return nil
	}
	path := filepath.Join(h.Root, DockerDaemonPath)
	data, err := os.ReadFile(path)
	for _, c := range changes {
		if c.Record.System == manifest.TypeOCI && strings.HasSuffix(c.Record.Path, "/docker/daemon.json") {
			path, data, err = c.Target, c.New, nil
		}
	}
	switch {
	case os.IsNotExist(err):
		return nil
	case err == nil:
		_, err = ParseDockerDaemonFile(data)
	}
	if err != nil {
		return fmt.Errorf("%s: dockerd refuses to load %s (%w) and does not start, so it would use neither the mirror nor the CA this command installs, and the install could not be verified. "+
			"Nothing was written. Repair what the error names (dockerd --validate repeats it), then re-run", manifest.TypeOCI, path, err)
	}
	return nil
}

// containerdReads refuses a plan that writes containerd's hosts.toml on a
// host whose containerd would not read it: a config.toml, as the plan leaves
// it, that does not resolve, one that disables the CRI plugin, which is what
// reads the registry configuration, or a hosts.toml containerd discards. None
// is repaired here. Enabling a plugin its owner disabled is not this
// command's call, and a ca in a file nothing loads would report an install no
// pull uses.
func (h CAHost) containerdReads(changes []Change) error {
	if !slices.ContainsFunc(changes, func(c Change) bool {
		return c.Record.System == manifest.TypeOCI && OCIRuntimeOf(c.Record.Path) == RuntimeContainerd
	}) {
		return nil
	}
	path := filepath.Join(h.Root, ContainerdConfigPath)
	data, err := os.ReadFile(path)
	for _, c := range changes {
		if c.Record.System == manifest.TypeOCI && strings.HasSuffix(c.Record.Path, "/containerd/config.toml") {
			path, data, err = c.Target, c.New, nil
		}
	}
	var roots []string
	switch {
	case os.IsNotExist(err):
	case err != nil:
		return fmt.Errorf("%s: read %s, which says where containerd reads its registry configuration: %w. Run this command as an account that can read it", manifest.TypeOCI, path, err)
	default:
		eff, err := ResolveContainerdConfig("", path, data)
		switch {
		case err != nil:
			return fmt.Errorf("%s: containerd's configuration at %s does not resolve (%w), so which hosts.toml files containerd reads cannot be told and a CA written for it could not be verified. "+
				"Repair it, then re-run", manifest.TypeOCI, path, err)
		case eff.CRIDisabled:
			return fmt.Errorf("%s: %s disables containerd's CRI plugin (disabled_plugins), and that plugin is what reads hosts.toml and the ca this command writes there, so containerd would use neither and the install could not be verified. "+
				"Where this host pulls through containerd's CRI, remove the plugin from disabled_plugins, restart containerd and re-run; where only Docker Engine pulls here, add the CA to /etc/docker/certs.d/<bodega host>/ca.crt by hand", manifest.TypeOCI, path)
		case eff.Invalid != "":
			return fmt.Errorf("%s: containerd refuses to load its configuration at %s (%s) and does not start, so it would read neither hosts.toml nor the ca this command writes there, and the install could not be verified. "+
				"Nothing was written. Repair what the error names, then re-run", manifest.TypeOCI, path, eff.Invalid)
		case eff.ConfigPath != "":
			roots = strings.Split(eff.ConfigPath, ":")
		}
	}
	// Every hosts.toml containerd loads, and every one the plan edits, read
	// whole as containerd reads it, whether or not this plan changes it: a
	// wrong type in a field no edit touches makes containerd discard the
	// file, and the merge would carry that field into the rewrite.
	files := ContainerdHostsFiles(h.Root, roots)
	for _, c := range changes {
		if c.Record.System == manifest.TypeOCI && OCIRuntimeOf(c.Record.Path) == RuntimeContainerd && filepath.Base(c.Target) == "hosts.toml" && !slices.Contains(files, c.Target) {
			files = append(files, c.Target)
		}
	}
	for _, f := range files {
		if _, err := LoadContainerdHostsFile(f); err != nil {
			return fmt.Errorf("%s: containerd discards its registry configuration (%w) and pulls from the registry's own server instead, so it would use neither the bodega host nor the ca this command writes, and the install could not be verified. "+
				"Nothing was written. Fix that field so containerd loads the file (its log names the same error at each pull), then re-run", manifest.TypeOCI, err)
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

// roots reads every certificate in the files the rebuild command last wrote
// under root, which are what the host's clients verify against.
func (s systemStore) roots(root string) []*x509.Certificate {
	var out []*x509.Certificate
	for _, pattern := range s.live {
		files, _ := filepath.Glob(filepath.Join(root, pattern))
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
				if c, err := x509.ParseCertificate(block.Bytes); err == nil {
					out = append(out, c)
				}
			}
		}
	}
	return out
}

// holds reports whether the store the rebuild command last wrote under root
// carries every certificate. An anchor file in place proves nothing on its
// own: the command may have failed after the file was written.
func (s systemStore) holds(root string, certs []*x509.Certificate) bool {
	have := map[[sha256.Size]byte]bool{}
	for _, c := range s.roots(root) {
		have[sha256.Sum256(c.Raw)] = true
	}
	for _, c := range certs {
		if !have[sha256.Sum256(c.Raw)] {
			return false
		}
	}
	return true
}

// SystemRoots reads the operating system's trust store from the files its
// rebuild command writes, as they stand now. A process that loaded the store
// before a rebuild keeps the roots it loaded, so a verdict owed after one is
// reached against these. It errs on a host whose store doctor does not
// install into.
func SystemRoots(h CAHost) ([]*x509.Certificate, error) {
	store, err := systemStoreFor(h)
	if err != nil {
		return nil, err
	}
	return store.roots(h.Root), nil
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
// setting, and systemStoreSystems the ones whose client verifies through the
// operating system's trust store. Together they are every system a CA is
// installed for.
var (
	ownStoreSystems    = []string{manifest.TypeNpm, manifest.TypePypi, manifest.TypeOCI, manifest.TypeGit}
	systemStoreSystems = []string{manifest.TypeApt, manifest.TypeGomod, manifest.TypeHelm}
)

// CAUnsupported is the error for a plan record no CA is installed for, nil
// for one that is: a system outside the two lists above, and under oci the
// registries.conf podman, buildah and CRI-O read. Each of those clients
// selects its trust by rules this package does not port, so a CA written for
// one could report an install the client never reads. A record naming only a
// system answers for the system alone.
func CAUnsupported(rec PlanRecord) error {
	supported := strings.Join(systemStoreSystems, ", ") + ", " + strings.Join(ownStoreSystems, ", ")
	switch {
	case !slices.Contains(systemStoreSystems, rec.System) && !slices.Contains(ownStoreSystems, rec.System):
		return fmt.Errorf("%s: private-CA installation for %s is not supported; --ca-file installs a CA for %s. "+
			"Configure %s in a run without --ca-file, and add the CA to the trust store its client reads by hand",
			rec.System, rec.System, supported, rec.System)
	case rec.System == manifest.TypeOCI && OCIRuntimeOf(rec.Path) == RuntimePodman:
		return fmt.Errorf("%s: private-CA installation for podman, buildah and CRI-O is not supported, and this host's plan writes %s for them; under %s, --ca-file installs a CA for Docker Engine and containerd alone. "+
			"Configure %s in a run without --ca-file, and add the CA to the certs.d directory those clients read by hand",
			rec.System, rec.Path, rec.System, rec.System)
	}
	return nil
}

// AddCA plans the install of ca for every system changes configures: the
// client's own setting merged into the file the plan already writes for npm,
// pip, git and containerd, a ca.crt in the directory Docker reads per
// registry host, and for apt, go and helm an anchor in the operating system's
// trust store. A change for any other client is refused before an edit is
// built, as CAUnsupported words it.
//
// A client that reads an existing configuration file ahead of the plan's (a
// pip.conf pip loads later, npm's userconfig, GIT_CONFIG_GLOBAL, a git section
// scoped to a longer URL) gets the edit in that file too, as a change of its
// own: the plan's file alone would leave the client reading its old settings.
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
	for _, c := range changes {
		if err := CAUnsupported(c.Record); err != nil {
			return CAInstall{}, err
		}
	}
	if err := h.containerdReads(changes); err != nil {
		return CAInstall{}, err
	}
	if err := h.dockerReads(changes); err != nil {
		return CAInstall{}, err
	}
	in := CAInstall{Changes: slices.Clone(changes)}
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
	for i, c := range in.Changes {
		rec := c.Record
		if err := h.ignored(rec, c.Target); err != nil {
			return CAInstall{}, err
		}
		if rec.System == manifest.TypePypi {
			if err := h.pipCommandIndex(rec, c.Target, c.New); err != nil {
				return CAInstall{}, err
			}
		}
		// header and line are the CA setting and the section it belongs
		// under.
		kind := kindOf(rec)
		var header string
		var line func(caPath string) string
		switch {
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
			switch {
			case !c.Existed || c.Unchanged():
			case kind.whole() && bytes.Equal(c.New, c.planned):
				// No merger has kept this file's other lines: the plan's
				// rendering is all c.New holds.
				kept, err := keepWhole(c.Old, c.New)
				if err != nil {
					return CAInstall{}, fmt.Errorf("%s: %s is written whole and already exists: %w, so replacing it could delete what you added. "+
						"Move the file aside and re-run to have it written whole, then add your own lines back", rec.System, c.Target, err)
				}
				in.Changes[i].New = kept
			default:
				merged, err := kind.merge(c.Old, c.New)
				if err != nil {
					return CAInstall{}, refuse(c.Target, err)
				}
				in.Changes[i].New = merged
			}
			// A file the environment has this client read in place of the
			// plan's takes the same merge, whichever store the client
			// verifies through: its entry may name a CA that replaces the
			// system store, and the plan's file is never opened.
			for _, sh := range h.shadows(rec, c.Target, c.New) {
				if !sh.whole || kind.whole() || slices.ContainsFunc(selected, func(o Change) bool { return o.Target == sh.path }) {
					continue
				}
				old, err := os.ReadFile(sh.path)
				if err != nil {
					return CAInstall{}, fmt.Errorf("%s: read %s, which this client reads in place of %s: %w", rec.System, sh.path, c.Target, err)
				}
				planned := c.planned
				if planned == nil {
					planned = c.New
				}
				merged, err := kind.merge(old, planned)
				if err != nil {
					return CAInstall{}, refuse(sh.path, err)
				}
				also := rec
				also.Path = sh.path
				selected = append(selected, Change{Record: also, Target: sh.path, Old: old, Existed: true, New: merged})
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
				var sets []string
				for _, other := range outranking(body, true) {
					body = setSection(body, other, set, *kind.rules, false)
					sets = append(append(sets, other), set...)
				}
				merged = joinBody(body)
				want := joinBody(sets)
				if kind.holds != nil {
					if err := kind.holds(merged, want); err != nil {
						return CAInstall{}, refuse(sh.path, err)
					}
				}
				if kind.keeps != nil {
					if err := kind.keeps(old, merged, want); err != nil {
						return CAInstall{}, refuse(sh.path, err)
					}
				}
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
				strings.Join(system, ", "), err, strings.Join(ownStoreSystems, ", "))
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
	open      lineOpen
}

// continues reports whether l continues the line above it. Whether l in turn
// runs on is the format's own lexer's call, made on the line's tokens: the
// last character of a physical line says nothing where it sits in a comment.
func (s *lineScan) continues(l string) bool {
	t := strings.TrimSpace(l)
	cont := s.open.on || s.rules.indent && s.keyIndent >= 0 && t != "" && indentOf(l) > s.keyIndent
	if s.rules.runsOn != nil {
		s.open = s.rules.runsOn(l, s.open)
	}
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
