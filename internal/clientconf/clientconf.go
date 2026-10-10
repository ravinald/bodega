// Package clientconf renders the configuration each package client reads to
// reach a bodega instance: the file's content, and where that file lives on
// each operating system a client runs.
//
// One renderer, for the reason internal/aptsources and internal/pkgrepos are
// one renderer each. The TUI built its client lines in Go and the web page
// built them again in JavaScript, and the two copies drifted together away
// from everything else: both appended a direct fallback to GOPROXY, which
// doctor flags as a bypass, and a [registries.bodega] cargo table that names a
// registry without redirecting crates.io to it. apt and FreeBSD pkg delegate
// to their own packages here rather than being rendered twice.
package clientconf

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/ravinald/bodega/internal/aptsources"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/pkgrepos"
)

// Operating systems a path is given for. A client of bodega runs on one of
// these, and each is a GOOS value so a caller can index by runtime.GOOS.
const (
	OSLinux   = "linux"
	OSFreeBSD = "freebsd"
	OSDarwin  = "darwin"
)

// File is one client configuration file.
//
// Paths maps an operating system to where the file belongs there, and holds
// only the systems the client runs on: apt has no darwin path, make.conf has
// only a freebsd one. A download link (a binary, a stored git bundle) is no
// file at all, so its Paths is empty and Content is the URL.
type File struct {
	System string `json:"system"`

	// Label names what Content is, for the row a pane shows it in. Most of
	// these are not URLs, and a row reading "Package URL" over a TOML table
	// sends an operator looking for something to curl.
	Label string `json:"label"`

	// Scope says which variant of a package this file configures, when a
	// package has several: the apt suite, the FreeBSD ABI, the git ref, the
	// filename the read API publishes for a binary entry. Empty when the file
	// is the same for every version.
	Scope string `json:"scope,omitempty"`

	Paths   map[string]string `json:"paths,omitempty"`
	Content string            `json:"content"`

	// Notes are the consequences of the form Content took, which an operator
	// has to read before installing it: apt's trust option, a placeholder
	// host standing in for an unset public_url.
	Notes []string `json:"notes,omitempty"`
}

// Path returns where the file belongs on goos, or "" when this client does
// not run there.
func (f File) Path(goos string) string { return f.Paths[goos] }

// everywhere is a Paths map naming one path for every client OS.
func everywhere(p string) map[string]string {
	return map[string]string{OSLinux: p, OSFreeBSD: p, OSDarwin: p}
}

// GoProxy is the GOPROXY value for base, with no direct entry after it: that
// fallback sends a module bodega does not hold straight to its VCS host,
// which is the bypass doctor's goproxy-env check exists to report.
func GoProxy(base string) string { return strings.TrimRight(base, "/") + "/go" }

// Pip renders pip's global index-url.
//
// /etc/pip.conf on FreeBSD too. pip's global search there is
// /etc/xdg/pip/pip.conf, /etc/pip.conf and sys.prefix/pip.conf, measured with
// `pip config debug` from py312-pip 23.3.2 on 15.1-RELEASE; nothing reads
// /usr/local/etc/pip.conf, so a file written there by the ports convention is
// silently ignored.
func Pip(base string) File {
	return File{
		System: manifest.TypePypi,
		Label:  "pip.conf",
		Paths: map[string]string{
			OSLinux:   "/etc/pip.conf",
			OSFreeBSD: "/etc/pip.conf",
			OSDarwin:  "/Library/Application Support/pip/pip.conf",
		},
		Content: fmt.Sprintf("[global]\nindex-url = %s/pypi/simple/\n", trim(base)),
	}
}

// Npm renders the registry line of a user .npmrc, the file `bodega doctor
// --write-credentials` writes the path-scoped token into. The trailing slash
// is what makes the registry match that token's //host/npm/ key.
func Npm(base string) File {
	return File{
		System:  manifest.TypeNpm,
		Label:   ".npmrc",
		Paths:   everywhere("~/.npmrc"),
		Content: fmt.Sprintf("registry=%s/npm/\n", trim(base)),
	}
}

// Cargo renders the source replacement that redirects crates.io to bodega's
// sparse index. A [registries.bodega] table alone names a second registry
// and leaves every crates.io dependency fetching from crates.io.
func Cargo(base string) File {
	return File{
		System: manifest.TypeCargo,
		Label:  "Cargo config",
		Paths:  everywhere("~/.cargo/config.toml"),
		Content: fmt.Sprintf("[source.crates-io]\nreplace-with = \"bodega\"\n\n[source.bodega]\nregistry = \"sparse+%s/cargo/\"\n",
			trim(base)),
	}
}

// Gomod renders the go env file `go env -w` writes, which the toolchain reads
// on every invocation, so no shell profile has to export anything.
func Gomod(base string) File {
	return File{
		System: manifest.TypeGomod,
		Label:  "Go env",
		Paths: map[string]string{
			OSLinux:   "~/.config/go/env",
			OSFreeBSD: "~/.config/go/env",
			OSDarwin:  "~/Library/Application Support/go/env",
		},
		Content: "GOPROXY=" + GoProxy(base) + "\n",
	}
}

// Helm renders a whole repositories.yaml registering bodega, at the path helm
// uses when neither HELM_REPOSITORY_CONFIG nor XDG_CONFIG_HOME is set. helm
// unmarshals the file into a struct, so the entry alone is not a file it
// reads: `helm repo list` over a bare sequence reports no repositories.
func Helm(base string) File {
	return File{
		System: manifest.TypeHelm,
		Label:  "repositories.yaml",
		Paths: map[string]string{
			OSLinux:   "~/.config/helm/repositories.yaml",
			OSFreeBSD: "~/.config/helm/repositories.yaml",
			OSDarwin:  "~/Library/Preferences/helm/repositories.yaml",
		},
		Content: HelmDocument(HelmRepository(base)),
	}
}

// HelmRepository renders bodega's item in the repositories list. extra are
// further keys of the same item, one "key: value" each, which is how `bodega
// doctor --write-credentials` attaches the credential without a second copy
// of the name and URL.
func HelmRepository(base string, extra ...string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "- name: bodega\n  url: %s/helm\n", trim(base))
	for _, kv := range extra {
		sb.WriteString("  " + kv + "\n")
	}
	return sb.String()
}

// HelmDocument wraps repository items in the keys helm's parser requires
// around them. The zero timestamp keeps two renders byte-identical; helm
// rewrites it on its own next write.
func HelmDocument(repositories string) string {
	return "apiVersion: \"\"\ngenerated: \"0001-01-01T00:00:00Z\"\nrepositories:\n" + repositories
}

// Git renders one url.<base>/git/<namespace>/.insteadOf per git_upstreams
// entry, sorted by namespace so two renders of one config are byte-identical.
// A clone of the upstream URL is then rewritten onto bodega's smart-HTTP
// route with nothing else in the client changed. Content is empty when no
// namespace is configured: there is no route to rewrite onto.
func Git(base string, upstreams map[string]config.GitUpstream) File {
	names := make([]string, 0, len(upstreams))
	for ns := range upstreams {
		names = append(names, ns)
	}
	sort.Strings(names)
	var sb strings.Builder
	for _, ns := range names {
		fmt.Fprintf(&sb, "[url \"%s/git/%s/\"]\n\tinsteadOf = %s\n", trim(base), ns, upstreams[ns].URL)
	}
	return File{
		System:  manifest.TypeGit,
		Label:   "Git config",
		Paths:   everywhere("~/.gitconfig"),
		Content: sb.String(),
	}
}

// DistfilesCheckPath is where the client check fetched from
// /distfiles/@environment.mk is installed, and what MakeConf includes.
const DistfilesCheckPath = "/usr/local/etc/bodega-distfiles.mk"

// MakeConf renders the ports distfiles sites. Both, because MASTER_SITE_BACKUP
// defaults to distcache.FreeBSD.org and is the last site do-fetch.sh tries.
// The .include is last so the check sees every assignment above it.
func MakeConf(base string) File {
	site := trim(base) + "/distfiles/@${BODEGA_DISTFILES_ENV}/${DIST_SUBDIR}/"
	return File{
		System: manifest.TypeDistfiles,
		Label:  "make.conf",
		Paths:  map[string]string{OSFreeBSD: "/etc/make.conf"},
		Content: "MASTER_SITE_OVERRIDE?= " + site + "\n" +
			"MASTER_SITE_BACKUP?= " + site + "\n" +
			".include \"" + DistfilesCheckPath + "\"\n",
	}
}

// AptSourcesPath is where a client installs the deb822 stanza.
const AptSourcesPath = "/etc/apt/sources.list.d/bodega.sources"

// Apt wraps a stanza aptsources rendered, with its notes. The caller renders
// it because only the caller knows the suite, the signing state and whether
// the codename is mirrored.
func Apt(src aptsources.Sources) File {
	return File{
		System:  manifest.TypeApt,
		Label:   "Sources",
		Scope:   src.Suite,
		Paths:   map[string]string{OSLinux: AptSourcesPath},
		Content: src.Deb822 + "\n",
		Notes:   src.Notes,
	}
}

// FreeBSD wraps a repository file pkgrepos rendered, overrides included.
func FreeBSD(repo pkgrepos.Repo) File {
	return File{
		System:  manifest.TypeFreeBSD,
		Label:   "Repository conf",
		Scope:   repo.ABI,
		Paths:   map[string]string{OSFreeBSD: pkgrepos.ClientConfPath},
		Content: repo.Conf,
	}
}

// BinaryLink is one binary entry's path under /binaries/, as
// manifest.BinaryLinkName resolves it. Filename is the name the read API
// publishes for the entry and becomes the file's Scope: two entries of one
// version on different backends share the version, and scoping by it would
// hand one entry's page the other's bytes.
type BinaryLink struct {
	Filename string
	Path     string
}

// NamespacedBinaryPath returns the path under /binaries/ that serves a binary
// entry named under a configured binary_upstreams key, and false for any other
// entry. That path is the name itself: the route hands /binaries/<ns>/<rest> to
// the namespace, which looks the entry up as "<ns>/<rest>", so the storage-key
// spelling BinaryLinkName composes for a hosted entry never reaches it.
func NamespacedBinaryPath(name string, upstreams map[string]config.BinaryUpstream) (string, bool) {
	ns, rest, ok := strings.Cut(name, "/")
	if !ok || rest == "" {
		return "", false
	}
	if _, configured := upstreams[ns]; !configured {
		return "", false
	}
	return name, true
}

// Binary renders a binary's download URL. A binary is fetched, not
// configured, so its File carries no path.
func Binary(base string, link BinaryLink) File {
	return File{
		System:  manifest.TypeBinary,
		Label:   "Package URL",
		Scope:   link.Filename,
		Content: trim(base) + "/binaries/" + link.Path,
	}
}

// GitBundle is one git entry version that `bodega build fetch git` stored.
type GitBundle struct {
	Name    string
	Ref     string
	Release bool
}

// GitBundleURL renders the download URL of a stored git entry: a bundle, or a
// tarball for a release. It sits beside Git rather than replacing it, because
// the bundle is served with no git_upstreams configured and the insteadOf
// rewrite is not.
func GitBundleURL(base string, b GitBundle) File {
	ext := ".bundle"
	if b.Release {
		ext = ".tar.gz"
	}
	sn := strings.ReplaceAll(b.Name, "/", "--")
	return File{
		System:  manifest.TypeGit,
		Label:   "Package URL",
		Scope:   b.Ref,
		Content: fmt.Sprintf("%s/git/%s/%s-%s%s", trim(base), sn, sn, b.Ref, ext),
	}
}

// SystemOsquery is the plan system that points osqueryd at an osquery source
// in server mode. It is no package type: the host installs osquery the way
// osquery's own guide says, and this system adds bodega's flags to the
// daemon that package installs.
const SystemOsquery = "osquery"

// OsqueryFlagsPaths is where each OS's osquery package reads its flags when
// nothing overrides it: the deb's /etc/default/osqueryd FLAG_FILE, and the
// sysutils/osquery rc script's osqueryd_flagfile default. setup.sh writes
// here only when the host names no other path; see osqueryFlagSources.
var OsqueryFlagsPaths = map[string]string{
	OSLinux:   "/etc/osquery/osquery.flags",
	OSFreeBSD: "/usr/local/etc/osquery/osquery.flags",
}

// osqueryFlagSources is where each OS's package names the flagfile its
// daemon reads, as the variable and either the file holding it or "sysrc"
// for rc.conf. Following it rather than OsqueryFlagsPaths alone means a host
// whose operator moved the flags gets bodega's flags where osqueryd reads
// them, not in a file nothing opens.
var osqueryFlagSources = map[string][2]string{
	OSLinux:   {"FLAG_FILE", "/etc/default/osqueryd"},
	OSFreeBSD: {"osqueryd_flagfile", "sysrc"},
}

// osquerySecretPaths sit beside the default flags file. setup.sh reads the
// path back out of the enroll_secret_path flag rather than holding a copy of
// this table.
var osquerySecretPaths = map[string]string{
	OSLinux:   "/etc/osquery/bodega.secret",
	OSFreeBSD: "/usr/local/etc/osquery/bodega.secret",
}

// osqueryCABundles are each OS's system trust store, so a private CA added
// with update-ca-certificates or certctl reaches osqueryd too. Left unset,
// osqueryd on Linux reads the Mozilla bundle frozen into its own package,
// which trusts no private CA and never changes with the host's.
var osqueryCABundles = map[string]string{
	OSLinux:   "/etc/ssl/certs/ca-certificates.crt",
	OSFreeBSD: "/etc/ssl/cert.pem",
}

// How setup.sh merges one OsqueryFlag into the host's flags file.
const (
	// OsqueryFlagSet is a flag bodega needs to work: every line setting it
	// is replaced by bodega's, and it is appended when absent.
	OsqueryFlagSet = "set"
	// OsqueryFlagDefault is the operator's flag: a line setting it is kept,
	// and bodega's value is appended only when none does.
	OsqueryFlagDefault = "default"
	// OsqueryFlagInclude adds Value to the comma-separated list a line
	// setting the flag already holds, last, when it is not there. It writes
	// nothing for an absent flag; a default for the same name does that.
	OsqueryFlagInclude = "include"
)

// OsqueryFlag is one flag bodega manages in osqueryd's flags file. Name has
// no leading dashes.
type OsqueryFlag struct {
	Rule  string
	Name  string
	Value string
}

// OsqueryFlags is the flag list for one server-mode source on goos, in the
// order setup.sh appends the ones a host's file lacks. osqueryd builds every
// URL as https://<tls_hostname><endpoint>, so the hostname carries
// public_url's port and the endpoints carry its path. It is nil when base or
// the endpoint does not parse.
//
// logger_plugin is merged rather than set because a deployed host may feed
// its filesystem log, osquery's default, to something else. host_identifier
// defaults to uuid because osquery's own default, hostname, changes when a
// host is renamed, and a shipper's mapping keys on it.
func OsqueryFlags(base string, src OsqueryPlan, goos string) []OsqueryFlag {
	b, err := url.Parse(base)
	if err != nil || b.Host == "" {
		return nil
	}
	ep, err := url.Parse(src.Endpoint)
	if err != nil || ep.Path == "" {
		return nil
	}
	path := strings.TrimRight(ep.Path, "/")
	set := func(name, value string) OsqueryFlag { return OsqueryFlag{OsqueryFlagSet, name, value} }
	out := []OsqueryFlag{set("tls_hostname", b.Host)}
	if b.Scheme == "https" {
		out = append(out, set("tls_server_certs", osqueryCABundles[goos]))
	}
	out = append(out,
		set("enroll_secret_path", osquerySecretPaths[goos]),
		set("enroll_tls_endpoint", path+"/enroll"),
		set("config_plugin", "tls"),
		set("config_tls_endpoint", path+"/config"),
	)
	if src.Interval > 0 {
		out = append(out, set("config_refresh", strconv.FormatInt(src.Interval, 10)))
	}
	return append(out,
		OsqueryFlag{OsqueryFlagDefault, "host_identifier", "uuid"},
		OsqueryFlag{OsqueryFlagDefault, "logger_plugin", "filesystem,tls"},
		OsqueryFlag{OsqueryFlagInclude, "logger_plugin", "tls"},
		set("logger_tls_endpoint", path+"/log"),
	)
}

// Osquery renders the osquery system's plan file for one server-mode
// source, one File per OS. It is no flags file but the instructions
// setup.sh merges into the host's, one tab-separated line each: first
// "from", the variable naming the flagfile and where it is set, then one
// "<rule> <name> <value>" per OsqueryFlag. Content is empty when base or the
// endpoint does not parse.
func Osquery(base string, src OsqueryPlan) []File {
	var out []File
	for _, goos := range []string{OSLinux, OSFreeBSD} {
		flags := OsqueryFlags(base, src, goos)
		if flags == nil {
			return nil
		}
		from := osqueryFlagSources[goos]
		var sb strings.Builder
		sb.WriteString("from\t" + from[0] + "\t" + from[1] + "\n")
		for _, f := range flags {
			sb.WriteString(f.Rule + "\t" + f.Name + "\t" + f.Value + "\n")
		}
		out = append(out, File{
			System:  SystemOsquery,
			Label:   "osquery flags",
			Scope:   src.Instance + " (" + goos + ")",
			Paths:   map[string]string{goos: OsqueryFlagsPaths[goos]},
			Content: sb.String(),
		})
	}
	return out
}

// Inputs are the facts a type's rendering needs beyond the base URL. Apt and
// FreeBSD arrive rendered, because their state differs between the running
// server and the TUI's view of the key files, and each resolves its own.
type Inputs struct {
	Base         string
	GitUpstreams map[string]config.GitUpstream
	GitBundles   []GitBundle
	Apt          []aptsources.Sources
	FreeBSD      []pkgrepos.Repo
	Binary       []BinaryLink
	// Osquery is the one server-mode source a host enrolls with: osqueryd
	// takes its config from exactly one server.
	Osquery *OsqueryPlan
}

// ForType renders every file a client of entryType installs. It is the one
// mapping from a package type to its renderer, so the TUI and the server
// cannot disagree about which file a type gets. A file with no content is
// left out.
func ForType(entryType string, in Inputs) []File {
	var out []File
	switch entryType {
	case manifest.TypePypi:
		out = append(out, Pip(in.Base))
	case manifest.TypeNpm:
		out = append(out, Npm(in.Base))
	case manifest.TypeCargo:
		out = append(out, Cargo(in.Base))
	case manifest.TypeGomod:
		out = append(out, Gomod(in.Base))
	case manifest.TypeHelm:
		out = append(out, Helm(in.Base))
	case manifest.TypeGit:
		out = append(out, Git(in.Base, in.GitUpstreams))
		for _, b := range in.GitBundles {
			out = append(out, GitBundleURL(in.Base, b))
		}
	case manifest.TypeDistfiles:
		out = append(out, MakeConf(in.Base))
	case manifest.TypeApt:
		for _, src := range in.Apt {
			out = append(out, Apt(src))
		}
	case manifest.TypeFreeBSD:
		for _, repo := range in.FreeBSD {
			out = append(out, FreeBSD(repo))
		}
	case manifest.TypeBinary:
		for _, l := range in.Binary {
			out = append(out, Binary(in.Base, l))
		}
	case SystemOsquery:
		if in.Osquery != nil {
			out = append(out, Osquery(in.Base, *in.Osquery)...)
		}
	}
	kept := out[:0]
	for _, f := range out {
		if f.Content != "" {
			kept = append(kept, f)
		}
	}
	return kept
}

func trim(base string) string { return strings.TrimRight(base, "/") }
