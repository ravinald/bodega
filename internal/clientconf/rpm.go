package clientconf

import (
	"bufio"
	"bytes"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

// Where `bodega doctor --configure rpm` writes on a dnf host, and the route
// bodega's key is served at.
const (
	RpmRepoPath = "/etc/yum.repos.d/bodega.repo"
	RpmKeyPath  = "/etc/pki/rpm-gpg/RPM-GPG-KEY-bodega"
	RpmKeyRoute = "/rpm/bodega.gpg"
)

// DnfMainConf is dnf's main configuration file, which can define
// repositories itself and sets the reposdir dnf reads .repo files from.
const DnfMainConf = "/etc/dnf/dnf.conf"

// YumReposDirs are the directories dnf reads .repo files from when dnf.conf
// sets no reposdir, in dnf's own order.
var YumReposDirs = []string{"/etc/yum.repos.d", "/etc/yum/repos.d", "/etc/distro.repos.d"}

// RpmVendorRepo is one repository a distribution's own .repo files enable,
// and the rpm_upstreams key bodega serves the same content under.
type RpmVendorRepo struct {
	// Upstream is the rpm_upstreams key an operator names this repository
	// under, and the bodega-<Upstream> section the host file carries.
	Upstream string
	// ID is the vendor's repository id, with $basearch where the vendor's
	// id carries the architecture (RHEL's do).
	ID string
	// GPGKeys are the key files the vendor's .repo names, which verify the
	// vendor's package signatures. Packages pass through bodega unchanged,
	// so these keys still verify them.
	GPGKeys []string
}

// VendorID is the vendor's repository id on a basearch host.
func (r RpmVendorRepo) VendorID(basearch string) string {
	return strings.ReplaceAll(r.ID, "$basearch", basearch)
}

// RpmDistro is one release of a RHEL-family distribution, keyed by
// /etc/os-release ID and the major number of VERSION_ID.
type RpmDistro struct {
	ID    string
	Major string
	Repos []RpmVendorRepo
}

// Name is the distribution as os-release names it, for a plan's notes.
func (d RpmDistro) Name() string { return d.ID + " " + d.Major }

const pkiDir = "file:///etc/pki/rpm-gpg/"

func epel(major string) RpmVendorRepo {
	return RpmVendorRepo{Upstream: "epel", ID: "epel", GPGKeys: []string{pkiDir + "RPM-GPG-KEY-EPEL-" + major}}
}

func rhelFamily(id, major, prefix, vendorBase, vendorApp, key string) RpmDistro {
	keys := []string{pkiDir + key}
	return RpmDistro{ID: id, Major: major, Repos: []RpmVendorRepo{
		{Upstream: prefix + "-baseos", ID: vendorBase, GPGKeys: keys},
		{Upstream: prefix + "-appstream", ID: vendorApp, GPGKeys: keys},
		epel(major),
	}}
}

// rpmDistros is the table the client plan maps a host to its repositories
// through. Rocky and Alma name their repositories baseos and appstream; RHEL
// names them after the subscription content set, architecture included. EPEL
// is one repository named epel on all three.
var rpmDistros = []RpmDistro{
	rhelFamily("rocky", "9", "rocky", "baseos", "appstream", "RPM-GPG-KEY-Rocky-9"),
	rhelFamily("rocky", "10", "rocky", "baseos", "appstream", "RPM-GPG-KEY-Rocky-10"),
	rhelFamily("almalinux", "9", "alma", "baseos", "appstream", "RPM-GPG-KEY-AlmaLinux-9"),
	rhelFamily("almalinux", "10", "alma", "baseos", "appstream", "RPM-GPG-KEY-AlmaLinux-10"),
	rhelFamily("rhel", "9", "rhel", "rhel-9-for-$basearch-baseos-rpms", "rhel-9-for-$basearch-appstream-rpms", "RPM-GPG-KEY-redhat-release"),
	rhelFamily("rhel", "10", "rhel", "rhel-10-for-$basearch-baseos-rpms", "rhel-10-for-$basearch-appstream-rpms", "RPM-GPG-KEY-redhat-release"),
}

// RpmDistroFor finds the table row for an os-release ID and VERSION_ID. A
// minor release maps to its major: Rocky 9.4 reads the same repositories as
// Rocky 9.
func RpmDistroFor(id, versionID string) (RpmDistro, bool) {
	major, _, _ := strings.Cut(versionID, ".")
	for _, d := range rpmDistros {
		if d.ID == id && d.Major == major {
			return d, true
		}
	}
	return RpmDistro{}, false
}

// RpmDistroNames lists the table's rows as "rocky 9, rocky 10, ...", for a
// refusal naming what the table does cover.
func RpmDistroNames() string {
	names := make([]string, len(rpmDistros))
	for i, d := range rpmDistros {
		names[i] = d.Name()
	}
	return strings.Join(names, ", ")
}

var osReleaseValueRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// OSReleaseValueValid reports whether v is in os-release's alphabet for ID
// and VERSION_ID, which is what a plan request may carry for either.
func OSReleaseValueValid(v string) bool { return osReleaseValueRe.MatchString(v) }

// OSReleaseIDs reads ID and VERSION_ID out of an os-release file's content,
// unquoted. Either is empty when the file does not set it.
func OSReleaseIDs(data []byte) (id, versionID string) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		key, val, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		switch key {
		case "ID":
			id = val
		case "VERSION_ID":
			versionID = val
		}
	}
	return id, versionID
}

// RpmBasearch is dnf's $basearch for a GOARCH, or "" for one dnf does not
// run on.
func RpmBasearch(goarch string) string {
	switch goarch {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	case "ppc64le", "s390x":
		return goarch
	}
	return ""
}

// RpmHost renders /etc/yum.repos.d/bodega.repo for one distribution: a
// section for each of its repositories that configured names, in the table's
// order. dnf reads one gpgkey list for both checks, so each section names
// bodega's key, which signs repomd.xml, beside the vendor's keys, which
// signed the packages. kept is the repositories rendered; a repository
// configured does not name is left out, and a note says which, because the
// host's own copy of it stays enabled.
func RpmHost(base string, d RpmDistro, configured func(upstream string) bool) (f File, kept []RpmVendorRepo) {
	b := trim(base)
	var sb strings.Builder
	var missing []string
	for _, r := range d.Repos {
		if !configured(r.Upstream) {
			missing = append(missing, r.Upstream)
			continue
		}
		kept = append(kept, r)
		keys := append([]string{"file://" + RpmKeyPath}, r.GPGKeys...)
		fmt.Fprintf(&sb, "[bodega-%s]\nname=bodega %s\nbaseurl=%s/rpm/%s/$releasever/$basearch/\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey=%s\n\n",
			r.Upstream, r.Upstream, b, r.Upstream, strings.Join(keys, " "))
	}
	f = File{
		System:  manifest.TypeRpm,
		Label:   "dnf repositories",
		Scope:   d.Name(),
		Paths:   map[string]string{OSLinux: RpmRepoPath},
		Content: strings.TrimSuffix(sb.String(), "\n"),
	}
	if len(missing) > 0 {
		f.Notes = append(f.Notes, fmt.Sprintf("%s is left out: %s maps to it and rpm_upstreams on this server does not configure it, so the host's own repository for it stays enabled",
			strings.Join(missing, ", "), d.Name()))
	}
	return f, kept
}

// RpmHostUpstreams reads the rpm_upstreams keys back out of the bodega-<key>
// section headers of a file RpmHost rendered.
func RpmHostUpstreams(content []byte) []string {
	var out []string
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if name, ok := strings.CutPrefix(line, "[bodega-"); ok && strings.HasSuffix(name, "]") {
			out = append(out, strings.TrimSuffix(name, "]"))
		}
	}
	return out
}

// YumRepo is one repository section of dnf's configuration, as dnf reads it.
type YumRepo struct {
	ID      string
	File    string
	Enabled bool
	// URLs are every location dnf may fetch the repository's metadata from:
	// each baseurl, then mirrorlist and metalink. dnf prefers the last two
	// over baseurl when either is set.
	URLs []string
}

// DnfConfig is the repository configuration dnf loads on a host: the
// repository sections of its main file and of every .repo file in the
// reposdir that file sets, or in the default directories when it sets none.
type DnfConfig struct {
	Repos     []YumRepo
	ReposDirs []string
}

// ReadsDir reports whether dnf reads .repo files from dir.
func (c DnfConfig) ReadsDir(dir string) bool {
	return slices.ContainsFunc(c.ReposDirs, func(d string) bool { return filepath.Clean(d) == filepath.Clean(dir) })
}

// ReadDnfConfig reads dnf's repositories the way dnf's RepoReader does: the
// sections of mainConf other than [main] first, then each *.repo file in the
// effective reposdir, sorted by path. A mainConf or directory that does not
// exist contributes nothing, and an empty mainConf is not read. A repository
// id seen twice keeps its first definition, which is the one dnf loads.
func ReadDnfConfig(mainConf string, defaultDirs []string) (DnfConfig, error) {
	c := DnfConfig{ReposDirs: defaultDirs}
	var sections []iniSection
	if mainConf != "" {
		data, err := os.ReadFile(mainConf)
		switch {
		case err == nil:
			sections = parseDnfIni(data)
		case !os.IsNotExist(err):
			return DnfConfig{}, fmt.Errorf("read %s: %w", mainConf, err)
		}
	}
	for _, sec := range sections {
		if sec.name != "main" {
			continue
		}
		if v, ok := sec.values["reposdir"]; ok {
			c.ReposDirs = dnfList(v)
		}
	}
	add := func(path string, secs []iniSection) {
		for _, sec := range secs {
			if sec.name == "main" || slices.ContainsFunc(c.Repos, func(r YumRepo) bool { return r.ID == sec.name }) {
				continue
			}
			c.Repos = append(c.Repos, sec.repo(path))
		}
	}
	add(mainConf, sections)
	var files []string
	for _, dir := range c.ReposDirs {
		found, err := filepath.Glob(filepath.Join(dir, "*.repo"))
		if err != nil {
			return DnfConfig{}, err
		}
		files = append(files, found...)
	}
	slices.SortFunc(files, func(a, b string) int {
		return slices.Compare(strings.Split(strings.TrimSuffix(a, ".repo"), "/"), strings.Split(strings.TrimSuffix(b, ".repo"), "/"))
	})
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return DnfConfig{}, fmt.Errorf("read %s: %w", path, err)
		}
		add(path, parseDnfIni(data))
	}
	return c, nil
}

type iniSection struct {
	name   string
	values map[string]string
}

// repo reads a section as a repository. dnf looks options up by their exact
// name, and keeps an option's default when its value does not parse, so an
// enabled value dnf cannot read leaves the repository enabled.
func (s iniSection) repo(path string) YumRepo {
	r := YumRepo{ID: s.name, File: path, Enabled: true}
	if v, ok := s.values["enabled"]; ok {
		r.Enabled = !slices.Contains([]string{"0", "no", "false", "off"}, strings.ToLower(v))
	}
	r.URLs = dnfList(s.values["baseurl"])
	for _, k := range []string{"mirrorlist", "metalink"} {
		if v := strings.TrimSpace(s.values[k]); v != "" && v != "None" {
			r.URLs = append(r.URLs, v)
		}
	}
	return r
}

// dnfList splits a list option (baseurl, reposdir) on commas and whitespace,
// continuation lines included.
func dnfList(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' })
}

// parseDnfIni reads a dnf configuration file with libdnf's IniParser rules:
// a comment is a line opening with # or ; in its first column; a line
// opening with whitespace continues the value above it, joined by a newline;
// a value's trailing newlines go, and then one pair of matching quotes
// around it. A repeated section merges and a repeated key keeps its last
// value. Where IniParser rejects the whole file this reads what it can, so a
// malformed file is reported on rather than read as holding nothing.
func parseDnfIni(data []byte) []iniSection {
	var out []iniSection
	cur := -1
	key, val, inValue := "", "", false
	flush := func() {
		if !inValue {
			return
		}
		val = strings.TrimRight(val, "\n")
		if len(val) > 1 && val[0] == val[len(val)-1] && (val[0] == '"' || val[0] == '\'') {
			val = val[1 : len(val)-1]
		}
		out[cur].values[key] = val
		inValue = false
	}
	for _, line := range strings.Split(strings.TrimPrefix(string(data), "\uFEFF"), "\n") {
		if line == "" || line[0] == '#' || line[0] == ';' {
			flush()
			continue
		}
		start := strings.IndexFunc(line, func(r rune) bool { return r != ' ' && r != '\t' && r != '\r' })
		if start < 0 {
			if inValue {
				val += "\n"
			}
			continue
		}
		body := strings.TrimRight(line[start:], " \t\r")
		if inValue && (start == 0 || body[0] == '[') {
			flush()
		}
		switch {
		case body[0] == '[':
			end := sectionEnd(body)
			if end < 0 {
				continue
			}
			name := body[1:end]
			cur = slices.IndexFunc(out, func(s iniSection) bool { return s.name == name })
			if cur < 0 {
				out = append(out, iniSection{name: name, values: map[string]string{}})
				cur = len(out) - 1
			}
		case cur < 0:
		case start > 0:
			if inValue {
				val += "\n" + body
			}
		default:
			eq := strings.IndexByte(body, '=')
			if eq <= 0 {
				continue
			}
			key = strings.TrimRight(body[:eq], " \t")
			val = strings.TrimLeft(body[eq+1:], " \t")
			inValue = true
		}
	}
	flush()
	return out
}

// sectionEnd is the index of the ] closing a section header, skipping one
// that closes a [...] range inside the name, or -1 when there is none.
func sectionEnd(header string) int {
	inRange := false
	for i := 1; i < len(header); i++ {
		switch header[i] {
		case ']':
			if !inRange {
				return i
			}
			inRange = false
		case '[':
			inRange = true
		}
	}
	return -1
}

// RpmBypasses sorts the enabled repositories that cannot be shown to fetch
// through bodega. With base, around is every one any of whose URLs is not
// under base's /rpm/ route, or that has no URL at all. With no base there is
// no bodega to compare against: a URL whose path holds no /rpm/ segment
// cannot be bodega's rpm route and still lands in around, and a repository
// whose every URL might be is unverified rather than passed, whatever its id.
func RpmBypasses(repos []YumRepo, base string) (around, unverified []YumRepo) {
	prefix := ""
	if base != "" {
		prefix = stripScheme(trim(base)) + "/rpm/"
	}
	for _, r := range repos {
		if !r.Enabled {
			continue
		}
		bypass, maybe := len(r.URLs) == 0, false
		for _, u := range r.URLs {
			switch {
			case prefix != "" && !strings.HasPrefix(stripScheme(u), prefix):
				bypass = true
			case prefix == "" && !strings.Contains(urlPath(u), "/rpm/"):
				bypass = true
			case prefix == "":
				maybe = true
			}
		}
		switch {
		case bypass:
			around = append(around, r)
		case maybe:
			unverified = append(unverified, r)
		}
	}
	return around, unverified
}

func stripScheme(u string) string {
	return strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
}

// urlPath is u's path, or u itself when it does not parse as a URL.
func urlPath(u string) string {
	if p, err := url.Parse(u); err == nil {
		return p.Path
	}
	return u
}

// RpmDisableIDs names the vendor repositories `dnf config-manager
// --set-disabled` turns off once the host file holds bodega's copy of them:
// each one d maps to an upstream the file has a section for, that the host
// has, and that is still enabled. A vendor repository the host lacks is left
// out because config-manager refuses an id it cannot find, and one already
// disabled because there is nothing to change.
func RpmDisableIDs(d RpmDistro, upstreams []string, repos []YumRepo, basearch string) []string {
	var out []string
	for _, r := range d.Repos {
		if !slices.Contains(upstreams, r.Upstream) {
			continue
		}
		id := r.VendorID(basearch)
		if slices.ContainsFunc(repos, func(y YumRepo) bool { return y.ID == id && y.Enabled }) && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}
