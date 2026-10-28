package clientconf

import (
	"bufio"
	"bytes"
	"fmt"
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

// YumRepo is one repository section of a .repo file, as dnf reads it.
type YumRepo struct {
	ID      string
	File    string
	Enabled bool
	// URLs are every location dnf may fetch the repository's metadata from:
	// each baseurl, then mirrorlist and metalink. dnf prefers the last two
	// over baseurl when either is set.
	URLs []string
}

// ReadYumRepos reads every .repo file in dirs, skipping a directory that
// does not exist. A repository with no enabled line is enabled, as dnf
// treats it. A value continued on an indented line (a second baseurl) is
// read as part of the key above it.
func ReadYumRepos(dirs ...string) ([]YumRepo, error) {
	var out []YumRepo
	for _, dir := range dirs {
		files, err := filepath.Glob(filepath.Join(dir, "*.repo"))
		if err != nil {
			return nil, err
		}
		slices.Sort(files)
		for _, path := range files {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", path, err)
			}
			out = append(out, parseYumRepos(path, data)...)
		}
	}
	return out, nil
}

func parseYumRepos(path string, data []byte) []YumRepo {
	var out []YumRepo
	var cur *YumRepo
	lastKey := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, " \t\r")
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";"):
			continue
		case strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]"):
			out = append(out, YumRepo{ID: strings.TrimSpace(trimmed[1 : len(trimmed)-1]), File: path, Enabled: true})
			cur, lastKey = &out[len(out)-1], ""
			continue
		case cur == nil:
			continue
		case line[0] == ' ' || line[0] == '\t':
			if lastKey == "baseurl" {
				cur.URLs = append(cur.URLs, strings.Fields(trimmed)...)
			}
			continue
		}
		key, val, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		key, val = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(val)
		lastKey = key
		switch key {
		case "enabled":
			cur.Enabled = yumTrue(val)
		case "baseurl":
			cur.URLs = append(cur.URLs, strings.FieldsFunc(val, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })...)
		case "mirrorlist", "metalink":
			if val != "" {
				cur.URLs = append(cur.URLs, val)
			}
		}
	}
	return out
}

// yumTrue reads a dnf boolean. Anything dnf does not read as true is false.
func yumTrue(v string) bool {
	switch strings.ToLower(v) {
	case "1", "yes", "true", "on":
		return true
	}
	return false
}

// RpmBypasses returns every enabled repository that can fetch from anywhere
// but bodega: one any of whose URLs does not sit under base's /rpm/ route.
// With no base to compare, a repository counts as bodega's only when its id
// is one RpmHost writes.
func RpmBypasses(repos []YumRepo, base string) []YumRepo {
	prefix := ""
	if base != "" {
		prefix = strings.TrimPrefix(strings.TrimPrefix(trim(base), "https://"), "http://") + "/rpm/"
	}
	var out []YumRepo
	for _, r := range repos {
		if !r.Enabled {
			continue
		}
		if prefix == "" {
			if !strings.HasPrefix(r.ID, "bodega-") {
				out = append(out, r)
			}
			continue
		}
		for _, u := range r.URLs {
			if !strings.HasPrefix(strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://"), prefix) {
				out = append(out, r)
				break
			}
		}
		if len(r.URLs) == 0 && !strings.HasPrefix(r.ID, "bodega-") {
			out = append(out, r)
		}
	}
	return out
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
