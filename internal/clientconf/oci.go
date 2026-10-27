package clientconf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/ravinald/bodega/internal/manifest"
)

// Container runtimes the oci system configures. Each reads its own file, so
// the plan carries one set per runtime and the host keeps the ones it runs.
const (
	RuntimeDocker     = "docker"
	RuntimeContainerd = "containerd"
	// RuntimePodman stands for podman, buildah and CRI-O, which all read
	// containers-registries.conf(5).
	RuntimePodman = "podman"
)

// Where each runtime reads its registry configuration on Linux.
const (
	DockerDaemonPath     = "/etc/docker/daemon.json"
	ContainerdConfigPath = "/etc/containerd/config.toml"
	ContainerdCertsDir   = "/etc/containerd/certs.d"
	// RegistriesConfDropIn sorts after the distribution's own drop-ins
	// (000-shortnames.conf, 001-rhel-shortnames.conf), and a later drop-in
	// replaces an earlier [[registry]] with the same prefix.
	RegistriesConfDropIn = "/etc/containers/registries.conf.d/99-bodega.conf"
)

// RuntimeBinaries names, per runtime, the commands whose presence on PATH
// says the host runs it. dockerd rather than docker: the CLI alone talks to
// a daemon elsewhere, whose daemon.json is not this host's.
var RuntimeBinaries = map[string][]string{
	RuntimeDocker:     {"dockerd"},
	RuntimeContainerd: {"containerd"},
	RuntimePodman:     {"podman", "buildah", "crio"},
}

// OCI file keys, the file= value /client/oci serves each one under. The
// daemon.json is the system's own file and has none.
const (
	OCIFileContainerdConfig = "containerd-config"
	OCIFileRegistriesConf   = "registries-conf"
	ociFileHostsPrefix      = "containerd-hosts."
)

// OCIHostsFileKey is the file= value of the containerd hosts.toml for registry.
func OCIHostsFileKey(registry string) string { return ociFileHostsPrefix + registry }

// OCIFileKeyValid reports whether key names an oci file /client/oci could
// serve, whether or not this server's oci_upstreams holds the registry.
func OCIFileKeyValid(key string) bool {
	if key == OCIFileContainerdConfig || key == OCIFileRegistriesConf {
		return true
	}
	reg, ok := strings.CutPrefix(key, ociFileHostsPrefix)
	return ok && manifest.OCIValidRegistryName(reg)
}

// OCIFile is one file of the oci plan: the runtime that reads it, and the
// key it is served under.
type OCIFile struct {
	Runtime string
	Key     string
	File
}

// OCIClient renders every file the oci system installs for base, one set
// per runtime, the registries taken from oci_upstreams (registry name to
// fetch URL). The order is the plan's: Docker, then containerd's hosts.toml
// per registry and its config.toml, then the registries.conf drop-in.
func OCIClient(base string, upstreams map[string]string) []OCIFile {
	names := make([]string, 0, len(upstreams))
	for name := range upstreams {
		names = append(names, name)
	}
	sort.Strings(names)
	out := []OCIFile{{Runtime: RuntimeDocker, File: DockerDaemon(base, names)}}
	for _, name := range names {
		out = append(out, OCIFile{Runtime: RuntimeContainerd, Key: OCIHostsFileKey(name), File: ContainerdHosts(base, name, upstreams[name])})
	}
	out = append(out,
		OCIFile{Runtime: RuntimeContainerd, Key: OCIFileContainerdConfig, File: ContainerdConfig(base)},
		OCIFile{Runtime: RuntimePodman, Key: OCIFileRegistriesConf, File: RegistriesConf(base, names)},
	)
	return out
}

// OCIRuntimeOf names the runtime that reads the file at p, or "" for a path
// no runtime here reads. It matches on the trailing directories rather than
// the whole path so a test can root the plan under a scratch home.
func OCIRuntimeOf(p string) string {
	switch {
	case strings.HasSuffix(p, "/docker/daemon.json"):
		return RuntimeDocker
	case strings.Contains(p, "/containerd/"):
		return RuntimeContainerd
	case strings.Contains(p, "/containers/registries.conf"):
		return RuntimePodman
	}
	return ""
}

// ociPlaintext is base's host and port when base is plaintext http, the form
// Docker's insecure-registries takes, and "" otherwise.
func ociPlaintext(base string) string {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "http" {
		return ""
	}
	return u.Host
}

// DockerDaemon renders the daemon.json keys bodega sets. dockerd stores a
// mirror with one trailing slash whatever it is given, so this is the form
// `docker info` prints back. MergeDockerDaemon writes them into a host's
// existing file. registries is what the other runtimes cover, for the note
// saying Docker Engine covers none of them but Docker Hub.
func DockerDaemon(base string, registries []string) File {
	b := trim(base)
	doc := []member{{"registry-mirrors", json.RawMessage("[" + jsonString(b+"/") + "]")}}
	var others []string
	for _, r := range registries {
		if r != "docker.io" {
			others = append(others, r)
		}
	}
	scope := "an image from any other registry"
	if len(others) > 0 {
		scope = "an image from " + strings.Join(others, " or ")
	}
	notes := []string{
		"Docker Engine's registry-mirrors covers Docker Hub only: " + scope + " still pulls from its own registry. " +
			"containerd's " + ContainerdCertsDir + "/<registry>/hosts.toml and podman's " + RegistriesConfDropIn + " route the rest through bodega",
		"An existing daemon.json keeps every other key; registry-mirrors is replaced, since a second mirror is one Docker may pull from instead of bodega",
	}
	if hp := ociPlaintext(b); hp != "" {
		doc = append(doc, member{"insecure-registries", json.RawMessage("[" + jsonString(hp) + "]")})
		notes = append(notes, "insecure-registries gains "+hp+", because bodega answers on plaintext http here and dockerd refuses an http mirror without it")
	}
	content, _ := indentJSON(doc)
	return File{
		System:  manifest.TypeOCI,
		Label:   "Docker daemon.json",
		Paths:   map[string]string{OSLinux: DockerDaemonPath},
		Content: string(content),
		Notes:   notes,
	}
}

// ContainerdHosts renders the hosts.toml for one registry: server is the
// upstream, so a reader of the file sees which registry it mirrors, and
// bodega is the one host containerd asks first. containerd appends /v2/ and
// names the registry with ?ns= itself, so the host is the bare base. The
// upstream's userinfo is dropped: it is bodega's credential for the
// registry, and this file is the client's.
func ContainerdHosts(base, registry, upstream string) File {
	b := trim(base)
	server := upstream
	if u, err := url.Parse(upstream); err == nil {
		u.User = nil
		server = strings.TrimRight(u.String(), "/")
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "server = %s\n\n[host.%s]\n  capabilities = [\"pull\", \"resolve\"]\n", jsonString(server), jsonString(b))
	if ociPlaintext(b) != "" {
		sb.WriteString("  skip_verify = true\n")
	}
	return File{
		System:  manifest.TypeOCI,
		Label:   "containerd hosts.toml (" + registry + ")",
		Scope:   registry,
		Paths:   map[string]string{OSLinux: path.Join(ContainerdCertsDir, registry, "hosts.toml")},
		Content: sb.String(),
	}
}

// ContainerdConfig renders the config.toml containerd's CRI plugin reads
// certs.d through. It is what a host with no config.toml gets; one with a
// file gains config_path alone (MergeContainerdConfig). Version 2 because
// containerd 1.5 and later read it and 2.x migrates it.
func ContainerdConfig(base string) File {
	notes := []string{
		"containerd reads " + ContainerdCertsDir + " only when config_path names it: an existing config.toml gains config_path where it has none, and is otherwise left as it is",
		"containerd falls back to each registry's own server when bodega does not answer; a host whose egress is closed sees bodega's error instead",
	}
	if ociPlaintext(base) != "" {
		notes = append(notes, "each hosts.toml sets skip_verify = true and names bodega as http://, because bodega answers on plaintext http here")
	}
	return File{
		System:  manifest.TypeOCI,
		Label:   "containerd config.toml",
		Paths:   map[string]string{OSLinux: ContainerdConfigPath},
		Content: "version = 2\n\n" + tomlHeaderText(containerdRegistryTable[2]) + "\n  config_path = " + jsonString(ContainerdCertsDir) + "\n",
		Notes:   notes,
	}
}

// RegistriesConf renders the drop-in podman, buildah and CRI-O read: one
// [[registry]] per registry, each with bodega as its mirror at
// <host>/<registry>, which bodega reads as the registry the request names.
// The mirror is tried first and the registry itself after, as with
// containerd.
func RegistriesConf(base string, registries []string) File {
	b := trim(base)
	mirror := strings.TrimPrefix(strings.TrimPrefix(b, "https://"), "http://")
	insecure := ociPlaintext(b) != ""
	var sb strings.Builder
	for i, r := range registries {
		if i > 0 {
			sb.WriteByte('\n')
		}
		fmt.Fprintf(&sb, "[[registry]]\nprefix = %s\nlocation = %s\n\n[[registry.mirror]]\nlocation = %s\n", jsonString(r), jsonString(r), jsonString(mirror+"/"+r))
		if insecure {
			sb.WriteString("insecure = true\n")
		}
	}
	notes := []string{"podman and buildah read the drop-in on their next run; CRI-O reads it on restart"}
	if insecure {
		notes = append(notes, "each mirror sets insecure = true, because bodega answers on plaintext http here")
	}
	return File{
		System:  manifest.TypeOCI,
		Label:   "registries.conf drop-in",
		Paths:   map[string]string{OSLinux: RegistriesConfDropIn},
		Content: sb.String(),
		Notes:   notes,
	}
}

// MergeDockerDaemon returns existing with planned's keys set: registry-mirrors
// replaced, and each insecure-registries entry added to the list the file
// already holds. Every other key keeps its value and its place. An empty
// existing file gets planned.
//
// A file that is not a JSON object is refused: dockerd will not start with
// it either, so it is the operator's to repair.
func MergeDockerDaemon(existing, planned []byte) ([]byte, error) {
	if len(bytes.TrimSpace(existing)) == 0 {
		return planned, nil
	}
	plan, err := objectMembers(planned)
	if err != nil {
		return nil, fmt.Errorf("the planned daemon.json: %w", err)
	}
	doc, err := objectMembers(existing)
	if err != nil {
		return nil, fmt.Errorf("it is not a JSON object dockerd can read (%w); repair it or move it aside, then re-run. Nothing was written", err)
	}
	for _, p := range plan {
		if p.key == "insecure-registries" {
			merged, err := unionStrings(lookup(doc, p.key), p.value)
			if err != nil {
				return nil, fmt.Errorf("its insecure-registries is not a list of strings (%w); repair it, then re-run. Nothing was written", err)
			}
			p.value = merged
		}
		doc = setMember(doc, p, false)
	}
	return indentJSON(doc)
}

// unionStrings is the JSON list have with every entry of add it lacks
// appended.
func unionStrings(have, add json.RawMessage) (json.RawMessage, error) {
	var a, b []string
	if have != nil {
		if err := json.Unmarshal(have, &a); err != nil {
			return nil, err
		}
	}
	if err := json.Unmarshal(add, &b); err != nil {
		return nil, err
	}
	out := have
	for _, s := range b {
		found := false
		for _, x := range a {
			found = found || x == s
		}
		if !found {
			a = append(a, s)
			out = nil
		}
	}
	if out != nil {
		return out, nil
	}
	parts := make([]string, len(a))
	for i, s := range a {
		parts[i] = jsonString(s)
	}
	return json.RawMessage("[" + strings.Join(parts, ",") + "]"), nil
}

// indentJSON writes doc as dockerd's documentation writes daemon.json: two
// spaces, a trailing newline.
func indentJSON(doc []member) ([]byte, error) {
	var out bytes.Buffer
	if err := json.Indent(&out, joinObject(doc), "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

// containerdRegistryTable is the key path of the CRI plugin's registry table
// per config.toml version. Version 1 names the plugin by its short id;
// containerd 1.x ignores the long name there.
var containerdRegistryTable = map[int][]string{
	1: {"plugins", "cri", "registry"},
	2: {"plugins", "io.containerd.grpc.v1.cri", "registry"},
	3: {"plugins", "io.containerd.cri.v1.images", "registry"},
}

// ContainerdRegistry is what a containerd config.toml says about the CRI
// plugin's registry table, read as containerd decodes it.
type ContainerdRegistry struct {
	Version int
	// ConfigPath is the colon-separated hosts directory list, "" when the
	// key is absent or empty: containerd reads no hosts.toml either way.
	ConfigPath string
	// Legacy names the first registry setting containerd refuses to start
	// with beside config_path (mirrors, configs.<host>.tls), "" for none.
	Legacy string
	// CRIDisabled is a disabled_plugins entry naming the CRI plugin, as
	// Docker's packaged config.toml carries: nothing then reads the table.
	CRIDisabled bool
	// Imports is the file's imports list as written.
	Imports []string
	// HasPlugin is whether the file holds the CRI plugin's table at all, and
	// SetsConfigPath whether its registry table names config_path, even "".
	HasPlugin      bool
	SetsConfigPath bool
}

// ReadContainerdConfig decodes a config.toml and reports its CRI registry
// settings. A file containerd could not load, or one in a format version
// this release does not know, is an error.
func ReadContainerdConfig(data []byte) (ContainerdRegistry, error) {
	return readContainerdConfig(data, 0)
}

// readContainerdConfig reads data as format version, or as the version it
// declares when version is 0. An imported file is read in its parent's
// format: one declaring another is refused, since containerd 2.x migrates
// each file on its own and doctor does not follow that.
func readContainerdConfig(data []byte, version int) (ContainerdRegistry, error) {
	var doc map[string]any
	if _, err := toml.Decode(string(data), &doc); err != nil {
		return ContainerdRegistry{}, err
	}
	r := ContainerdRegistry{Version: 1}
	if version != 0 {
		r.Version = version
	}
	if v, ok := doc["version"]; ok {
		n, ok := v.(int64)
		if !ok {
			return r, fmt.Errorf("version = %v is not a number", v)
		}
		if version != 0 && int(n) != version {
			return r, fmt.Errorf("it declares version = %d under a config.toml of version %d, a combination doctor does not judge", n, version)
		}
		r.Version = int(n)
	}
	path, ok := containerdRegistryTable[r.Version]
	if !ok {
		return r, fmt.Errorf("it declares version = %d, a config.toml format this release does not know", r.Version)
	}
	switch v := doc["imports"].(type) {
	case nil:
	case []any:
		for _, i := range v {
			s, ok := i.(string)
			if !ok {
				return r, fmt.Errorf("imports entry %v is not a string", i)
			}
			r.Imports = append(r.Imports, s)
		}
	default:
		return r, fmt.Errorf("imports = %v is not a list", v)
	}
	r.HasPlugin = tomlTable(doc, path[:2]) != nil
	if list, ok := doc["disabled_plugins"].([]any); ok {
		for _, p := range list {
			r.CRIDisabled = r.CRIDisabled || p == "cri" || p == "io.containerd.grpc.v1.cri" || p == path[1]
		}
	}
	table := tomlTable(doc, path)
	_, r.SetsConfigPath = table["config_path"]
	switch v := table["config_path"].(type) {
	case nil:
	case string:
		r.ConfigPath = v
	default:
		return r, fmt.Errorf("config_path = %v is not a string", v)
	}
	if m, ok := table["mirrors"].(map[string]any); ok && len(m) > 0 {
		r.Legacy = "mirrors"
	}
	if configs, ok := table["configs"].(map[string]any); ok && r.Legacy == "" {
		names := make([]string, 0, len(configs))
		for name := range configs {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if c, ok := configs[name].(map[string]any); ok && c["tls"] != nil {
				r.Legacy = "configs." + jsonString(name) + ".tls"
				break
			}
		}
	}
	return r, nil
}

// ContainerdEffective is the CRI registry configuration containerd runs
// with once config.toml and every file it imports are loaded.
type ContainerdEffective struct {
	ContainerdRegistry
	// Source is the file whose config_path containerd reads: the last one
	// loaded that sets it, or the main file when none does.
	Source string
}

// ResolveContainerdConfig loads data, the config.toml at path, and then each
// file its imports name, breadth first, as containerd's LoadConfig does: a
// relative import resolves against its parent's directory, a pattern holding
// "*" is globbed, and a file already loaded is skipped. Paths are host paths,
// read under root ("" for this host).
//
// containerd 1.x replaces a plugin's whole table with an import's, so an
// imported CRI table without config_path drops the main file's; 2.x merges
// key by key and keeps it. Where the two disagree the configuration is
// refused rather than guessed at. Disabling the CRI plugin or setting a
// legacy registry key in any loaded file counts.
func ResolveContainerdConfig(root, path string, data []byte) (ContainerdEffective, error) {
	main, err := ReadContainerdConfig(data)
	if err != nil {
		return ContainerdEffective{}, err
	}
	eff := ContainerdEffective{ContainerdRegistry: main, Source: path}
	replaced, replacedFrom := main.ConfigPath, path
	pending, err := containerdImports(root, path, main.Imports)
	if err != nil {
		return eff, err
	}
	loaded := map[string]bool{path: true}
	for len(pending) > 0 {
		p := pending[0]
		pending = pending[1:]
		if loaded[p] {
			continue
		}
		loaded[p] = true
		b, err := os.ReadFile(filepath.Join(root, p))
		if err != nil {
			return eff, fmt.Errorf("it imports %s, which could not be read (%w); containerd will not start while an import fails to load", p, err)
		}
		r, err := readContainerdConfig(b, main.Version)
		if err != nil {
			return eff, fmt.Errorf("its import %s cannot be judged: %w", p, err)
		}
		eff.CRIDisabled = eff.CRIDisabled || r.CRIDisabled
		if eff.Legacy == "" {
			eff.Legacy = r.Legacy
		}
		if r.HasPlugin {
			replaced, replacedFrom = r.ConfigPath, p
		}
		if r.SetsConfigPath {
			eff.ConfigPath, eff.Source = r.ConfigPath, p
		}
		next, err := containerdImports(root, p, r.Imports)
		if err != nil {
			return eff, err
		}
		pending = append(pending, next...)
	}
	if replaced != eff.ConfigPath {
		return eff, fmt.Errorf("its import %s carries the CRI plugin table without config_path, so containerd 1.x reads none and 2.x keeps %q from %s; doctor cannot tell which runs here. Set config_path in %s", replacedFrom, eff.ConfigPath, eff.Source, replacedFrom)
	}
	return eff, nil
}

// containerdImports resolves parent's imports to host paths in the order
// containerd loads them.
func containerdImports(root, parent string, imports []string) ([]string, error) {
	var out []string
	for _, p := range imports {
		p = filepath.Clean(p)
		if !filepath.IsAbs(p) {
			p = filepath.Join(filepath.Dir(parent), p)
		}
		if !strings.Contains(p, "*") {
			out = append(out, p)
			continue
		}
		matches, err := filepath.Glob(filepath.Join(root, p))
		if err != nil {
			return nil, fmt.Errorf("%s imports %q, which is not a pattern containerd can expand: %w", parent, p, err)
		}
		for _, m := range matches {
			if root != "" {
				m = string(filepath.Separator) + strings.TrimLeft(strings.TrimPrefix(m, filepath.Clean(root)), string(filepath.Separator))
			}
			out = append(out, m)
		}
	}
	return out, nil
}

// ContainerdEditEffective reports why config_path set to certs.d in merged,
// the config.toml at path, would not be the one containerd reads: an import
// that fails to load or cannot be judged, or one whose CRI table supersedes
// the main file's with a config_path that leaves certs.d out.
func ContainerdEditEffective(root, path string, merged []byte) error {
	eff, err := ResolveContainerdConfig(root, path, merged)
	if err != nil {
		return err
	}
	if eff.Source != path && !slices.Contains(strings.Split(eff.ConfigPath, ":"), ContainerdCertsDir) {
		return fmt.Errorf("its import %s sets config_path = %q, which containerd reads in place of this file's and which leaves out %s; add %s to config_path there, then re-run. Nothing was written", eff.Source, eff.ConfigPath, ContainerdCertsDir, ContainerdCertsDir)
	}
	return nil
}

// tomlTable walks doc down path, nil where a step is missing or not a table.
func tomlTable(doc map[string]any, path []string) map[string]any {
	for _, k := range path {
		next, ok := doc[k].(map[string]any)
		if !ok {
			return nil
		}
		doc = next
	}
	return doc
}

// MergeContainerdConfig returns existing with config_path set in the CRI
// plugin's registry table when it holds none, and existing unchanged when it
// holds one: a config_path the operator chose is theirs. An empty
// config_path counts as unset. An empty existing file gets planned.
//
// The edit is a line edit rather than a TOML round trip, which would drop
// every comment the file carries. Its result is decoded again and must equal
// existing in every key but this one, so a form the line edit misreads (an
// inline table, a dotted key it did not expect, a multi-line value) is
// refused rather than written. A file containerd would not load, or one
// whose registry table sets what containerd refuses beside config_path, is
// refused too: a restart would leave containerd down.
func MergeContainerdConfig(existing, planned []byte) ([]byte, error) {
	if len(bytes.TrimSpace(existing)) == 0 {
		return planned, nil
	}
	have, err := ReadContainerdConfig(existing)
	if err != nil {
		return nil, fmt.Errorf("containerd cannot load it as it stands (%w); repair it, or add config_path = %q to its CRI registry table by hand, then re-run. Nothing was written", err, ContainerdCertsDir)
	}
	if have.ConfigPath != "" {
		return existing, nil
	}
	table := containerdRegistryTable[have.Version]
	if have.Legacy != "" {
		return nil, fmt.Errorf("%s sets %s, which containerd refuses to start with beside config_path; move it into hosts.toml files under %s and remove it, then re-run. Nothing was written", tomlHeaderText(table), have.Legacy, ContainerdCertsDir)
	}
	out := setContainerdConfigPath(existing, table)
	if err := sameButConfigPath(existing, out, table); err != nil {
		return nil, fmt.Errorf("this release cannot edit the form its CRI registry table takes (%v); add config_path = %q to %s by hand, then re-run. Nothing was written", err, ContainerdCertsDir, tomlHeaderText(table))
	}
	return out, nil
}

// setContainerdConfigPath rewrites the value of config_path in table, keeping
// the key's spelling and the line's comment, or inserts the key under the
// table's header, or appends the table. Lines inside a multi-line string are
// skipped. What it gets wrong, sameButConfigPath catches.
func setContainerdConfigPath(existing []byte, table []string) []byte {
	lines := strings.Split(string(existing), "\n")
	value := jsonString(ContainerdCertsDir)
	want := append(append([]string{}, table...), "config_path")
	var current []string
	header, closing := -1, ""
	for i, line := range lines {
		if closing != "" {
			if strings.Contains(line, closing) {
				closing = ""
			}
			continue
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[[") {
			current = []string{"[["}
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			if keys, rest, ok := parseTOMLKey(trimmed[1:]); ok && strings.HasPrefix(rest, "]") {
				current = keys
				if slices.Equal(keys, table) {
					header = i
				}
			}
			continue
		}
		keys, rest, ok := parseTOMLKey(trimmed)
		if !ok || !strings.HasPrefix(rest, "=") {
			continue
		}
		v := strings.TrimLeft(rest[1:], " \t")
		for _, delim := range []string{`"""`, `'''`} {
			if strings.HasPrefix(v, delim) && !strings.Contains(v[3:], delim) {
				closing = delim
			}
		}
		if !slices.Equal(append(append([]string{}, current...), keys...), want) {
			continue
		}
		end := tomlStringEnd(v)
		if end < 0 {
			return existing
		}
		eq := len(line) - len(strings.TrimLeft(line, " \t")) + len(trimmed) - len(rest)
		lines[i] = line[:eq+1] + " " + value + v[end:]
		return []byte(strings.Join(lines, "\n"))
	}
	setting := "  config_path = " + value
	if header >= 0 {
		lines = append(lines[:header+1], append([]string{setting}, lines[header+1:]...)...)
		return []byte(strings.Join(lines, "\n"))
	}
	return []byte(strings.TrimRight(string(existing), "\n") + "\n\n" + tomlHeaderText(table) + "\n" + setting + "\n")
}

// sameButConfigPath reports why out is not existing with table's config_path
// set to certs.d: a decode error, the key not reading back, or any other key
// differing.
func sameButConfigPath(existing, out []byte, table []string) error {
	got, err := ReadContainerdConfig(out)
	if err != nil {
		return err
	}
	if got.ConfigPath != ContainerdCertsDir {
		return fmt.Errorf("config_path reads back as %q", got.ConfigPath)
	}
	var a, b map[string]any
	if _, err := toml.Decode(string(existing), &a); err != nil {
		return err
	}
	if _, err := toml.Decode(string(out), &b); err != nil {
		return err
	}
	dropKey(a, table, "config_path")
	dropKey(b, table, "config_path")
	if !reflect.DeepEqual(a, b) {
		return errors.New("the edit changed another key")
	}
	return nil
}

// dropKey deletes key from the table at path, then each table on the path
// the deletion left empty, so a table the edit created compares equal to its
// absence.
func dropKey(doc map[string]any, path []string, key string) {
	if len(path) == 0 {
		delete(doc, key)
		return
	}
	next, ok := doc[path[0]].(map[string]any)
	if !ok {
		return
	}
	dropKey(next, path[1:], key)
	if len(next) == 0 {
		delete(doc, path[0])
	}
}

// parseTOMLKey reads a dotted TOML key (bare, "basic" or 'literal' parts)
// from the start of s and returns its parts and what follows it.
func parseTOMLKey(s string) ([]string, string, bool) {
	var keys []string
	for {
		s = strings.TrimLeft(s, " \t")
		switch {
		case strings.HasPrefix(s, `"`):
			end := tomlStringEnd(s)
			if end < 0 {
				return nil, "", false
			}
			k, err := strconv.Unquote(s[:end])
			if err != nil {
				return nil, "", false
			}
			keys, s = append(keys, k), s[end:]
		case strings.HasPrefix(s, "'"):
			end := tomlStringEnd(s)
			if end < 0 {
				return nil, "", false
			}
			keys, s = append(keys, s[1:end-1]), s[end:]
		default:
			n := 0
			for n < len(s) && (s[n] == '_' || s[n] == '-' || s[n] >= '0' && s[n] <= '9' || s[n] >= 'a' && s[n] <= 'z' || s[n] >= 'A' && s[n] <= 'Z') {
				n++
			}
			if n == 0 {
				return nil, "", false
			}
			keys, s = append(keys, s[:n]), s[n:]
		}
		s = strings.TrimLeft(s, " \t")
		if !strings.HasPrefix(s, ".") {
			return keys, s, true
		}
		s = s[1:]
	}
}

// tomlStringEnd is the length of the single-line basic or literal string s
// opens with, or -1 when s opens with none.
func tomlStringEnd(s string) int {
	switch {
	case strings.HasPrefix(s, `"""`), strings.HasPrefix(s, `'''`):
		return -1
	case strings.HasPrefix(s, "'"):
		if end := strings.IndexByte(s[1:], '\''); end >= 0 {
			return end + 2
		}
	case strings.HasPrefix(s, `"`):
		for i := 1; i < len(s); i++ {
			switch s[i] {
			case '\\':
				i++
			case '"':
				return i + 1
			}
		}
	}
	return -1
}

// tomlHeaderText is the [table] header for path, quoting each part that is
// not a bare key.
func tomlHeaderText(path []string) string {
	parts := make([]string, len(path))
	for i, p := range path {
		parts[i] = p
		if keys, rest, ok := parseTOMLKey(p); !ok || rest != "" || len(keys) != 1 {
			parts[i] = jsonString(p)
		}
	}
	return "[" + strings.Join(parts, ".") + "]"
}
