package clientconf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

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
		Content: "version = 2\n\n" + containerdRegistryTable[2] + "\n  config_path = " + jsonString(ContainerdCertsDir) + "\n",
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

// containerdRegistryTable is the CRI plugin's registry table per config.toml
// version. Version 1 names the plugin by its short id; containerd 1.x
// ignores the long name there.
var containerdRegistryTable = map[int]string{
	1: "[plugins.cri.registry]",
	2: `[plugins."io.containerd.grpc.v1.cri".registry]`,
	3: `[plugins."io.containerd.cri.v1.images".registry]`,
}

var (
	containerdVersionRE    = regexp.MustCompile(`^\s*version\s*=\s*(\d+)\s*(#.*)?$`)
	containerdConfigPathRE = regexp.MustCompile(`^(\s*config_path\s*=\s*)(?:"(.*)"|'(.*)')\s*(#.*)?$`)
	tomlTableRE            = regexp.MustCompile(`^\s*\[`)
)

// MergeContainerdConfig returns existing with config_path set in the CRI
// plugin's registry table when no line sets one, and existing unchanged when
// one does: a config_path the operator chose is theirs, and certs.d is
// containerd's own default for it. An empty config_path counts as unset. An
// empty existing file gets planned.
//
// The edit is a line edit rather than a TOML round trip, which would drop
// every comment the file carries. The table is chosen by the file's version
// line: inserting a version line into a file without one would turn its
// short plugin names, which version 2 refuses, into a containerd that does
// not start.
func MergeContainerdConfig(existing, planned []byte) ([]byte, error) {
	if len(bytes.TrimSpace(existing)) == 0 {
		return planned, nil
	}
	lines := strings.Split(string(existing), "\n")
	version, inTop := 1, true
	for i, line := range lines {
		if tomlTableRE.MatchString(line) {
			inTop = false
		}
		if m := containerdVersionRE.FindStringSubmatch(line); m != nil && inTop {
			version, _ = strconv.Atoi(m[1])
		}
		if m := containerdConfigPathRE.FindStringSubmatch(line); m != nil {
			if m[2]+m[3] != "" {
				return existing, nil
			}
			lines[i] = m[1] + jsonString(ContainerdCertsDir)
			return []byte(strings.Join(lines, "\n")), nil
		}
	}
	table, ok := containerdRegistryTable[version]
	if !ok {
		return nil, fmt.Errorf("it declares version = %d, a config.toml format this release does not know; add config_path = %q to its CRI registry table by hand", version, ContainerdCertsDir)
	}
	setting := "  config_path = " + jsonString(ContainerdCertsDir)
	for i, line := range lines {
		if tomlHeader(line) == tomlHeader(table) {
			lines = append(lines[:i+1], append([]string{setting}, lines[i+1:]...)...)
			return []byte(strings.Join(lines, "\n")), nil
		}
	}
	out := strings.TrimRight(string(existing), "\n") + "\n\n" + table + "\n" + setting + "\n"
	return []byte(out), nil
}

// tomlHeader is a table header line with its comment, spacing and key
// quoting removed, so the spellings TOML treats as one table compare equal.
// Any other line is "".
func tomlHeader(line string) string {
	line, _, _ = strings.Cut(line, "#")
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "[") || strings.HasPrefix(line, "[[") {
		return ""
	}
	return strings.NewReplacer(" ", "", "\t", "", `"`, "", "'", "").Replace(line)
}
