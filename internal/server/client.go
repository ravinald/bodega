package server

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/ravinald/bodega/internal/aptsources"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/entitle"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/pkgrepos"
)

const (
	planInstall = clientconf.PlanInstall
	planRefuse  = clientconf.PlanRefuse
	planSkip    = clientconf.PlanSkip
)

// planColumns is the order plan.txt writes a record's fields in. It is the
// contract a POSIX sh loop reads with IFS set to a tab, so a column is only
// ever appended.
var planColumns = []string{"identity", "profile", "match", "system", "action", "path", "url", "sha256", "reason"}

// planEmpty stands in for an empty field in plan.txt. A tab is IFS white
// space to sh's read, so two tabs in a row collapse into one separator and
// every column after an empty one would shift left.
const planEmpty = "-"

// planLiteralDash is a field whose value is planEmpty itself: a profile may be
// named "-", and a host bound to it must not read as a host with no profile.
// It is the octal escape printf %b decodes, so one decoding rule covers it and
// every other escape planEscaper writes.
const planLiteralDash = `\0055`

// planEscaper writes the characters that would end a plan.txt field or line
// as the escapes printf %b reads back. A backslash is escaped too, so a
// value that already holds one survives the round trip. Identity names are free
// text, so a tab or newline in one is an accepted value, not a malformed one.
var planEscaper = strings.NewReplacer(`\`, `\\`, "\t", `\t`, "\n", `\n`, "\r", `\r`)

type (
	planRecord = clientconf.PlanRecord
	clientPlan = clientconf.Plan
)

// planTSV writes records in planColumns order, one per line.
func planTSV(records []planRecord) string {
	var sb strings.Builder
	for _, rec := range records {
		for i, f := range rec.Fields() {
			if i > 0 {
				sb.WriteByte('\t')
			}
			sb.WriteString(planTSVField(f))
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

// planTSVField encodes one plan.txt field so a reader recovers the JSON
// value exactly: planEmpty alone is empty, and anything else holding a
// backslash decodes through printf %b.
func planTSVField(f string) string {
	switch f {
	case "":
		return planEmpty
	case planEmpty:
		return planLiteralDash
	}
	return planEscaper.Replace(f)
}

// clientQuery is what a host states about itself because the server cannot
// see it: its operating system, and where they apply its pkg ABI and apt
// codename.
type clientQuery struct {
	OS       string
	ABI      string
	Codename string
	// codenameParam is how Codename is written back into a URL the plan
	// hands out: a spelling that resolves to the same apt_upstreams key.
	// Empty writes Codename.
	codenameParam string
	// Release is the FreeBSD major release whose repository tags the pkg
	// overrides disable, for a host whose release is not the one its
	// repository is named for. Zero keeps the repository's own.
	Release int
	// Archives are the mirrored vendor codenames the plan adds a key and a
	// stanza for, beside the host's own distribution stanza.
	Archives []string
	// Archive selects one vendor archive's stanza on /client/apt, which is
	// the URL a plan's archive record names.
	Archive string
	// OSID and OSVersionID are /etc/os-release's ID and VERSION_ID, which
	// pick the dnf repositories a RHEL-family host reads.
	OSID        string
	OSVersionID string
	// Root says the plan is applied as root, which puts per-host files where
	// a per-user one would otherwise go: npm's node-gyp mirror.
	Root bool
	// File selects a system's companion file on /client/{system}, which is
	// the URL a plan's companion record names: clientFileNodeMirror,
	// clientFileBundler or clientFileGradle.
	File string
}

// Companion files, each served on its own system's route alone.
const (
	// clientFileNodeMirror is npm's NODEJS_ORG_MIRROR file on /client/npm.
	clientFileNodeMirror = "node-mirror"
	// clientFileBundler is Bundler's mirror file on /client/rubygems.
	clientFileBundler = "bundler"
	// clientFileGradle is Gradle's init script on /client/maven.
	clientFileGradle = "gradle"
)

var (
	clientABIRe      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._-]{0,63}$`)
	clientCodenameRe = regexp.MustCompile(`^(?:(?:[A-Za-z][A-Za-z0-9_-]*)?/)?[a-z0-9][a-z0-9.+-]{0,63}$`)
)

func parseClientQuery(r *http.Request) (clientQuery, error) {
	v := r.URL.Query()
	q := clientQuery{OS: v.Get("os"), ABI: v.Get("abi"), Codename: v.Get("codename"),
		OSID: v.Get("os_id"), OSVersionID: v.Get("os_version_id")}
	switch q.OS {
	case clientconf.OSLinux, clientconf.OSFreeBSD:
	case "":
		return q, fmt.Errorf("os is required: the server cannot see which operating system this host runs.\n" +
			"  Pass os=linux or os=freebsd, for example /client/plan?os=linux&codename=noble")
	default:
		return q, fmt.Errorf("os=%q is not one this server configures. Accepted: linux, freebsd", q.OS)
	}
	if q.ABI != "" && !clientABIRe.MatchString(q.ABI) {
		return q, fmt.Errorf("abi=%q is not a pkg ABI. Pass what `pkg config abi` prints, for example FreeBSD:15:amd64", q.ABI)
	}
	if q.Codename != "" && !clientCodenameRe.MatchString(q.Codename) {
		return q, fmt.Errorf("codename=%q is not an apt suite name. Pass VERSION_CODENAME from /etc/os-release, for example noble", q.Codename)
	}
	for _, kv := range [][2]string{{"os_id", q.OSID}, {"os_version_id", q.OSVersionID}} {
		if kv[1] != "" && !clientconf.OSReleaseValueValid(kv[1]) {
			return q, fmt.Errorf("%s=%q is not an os-release value. Pass ID and VERSION_ID from /etc/os-release, for example os_id=rocky&os_version_id=9.4", kv[0], kv[1])
		}
	}
	if raw := v.Get("release"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 99 {
			return q, fmt.Errorf("release=%q is not a FreeBSD major release. Pass the major number alone, for example release=14", raw)
		}
		q.Release = n
	}
	for _, c := range strings.Split(v.Get("archives"), ",") {
		c = strings.TrimSpace(c)
		if c == "" || slices.Contains(q.Archives, c) {
			continue
		}
		if !clientCodenameRe.MatchString(c) {
			return q, fmt.Errorf("archives=%q names %q, which is not an apt suite name. Pass the mirrored codenames comma-separated, for example archives=stable", v.Get("archives"), c)
		}
		q.Archives = append(q.Archives, c)
	}
	if q.Archive = v.Get("archive"); q.Archive != "" && !clientCodenameRe.MatchString(q.Archive) {
		return q, fmt.Errorf("archive=%q is not an apt suite name", q.Archive)
	}
	switch raw := v.Get("root"); raw {
	case "", "0":
	case "1":
		q.Root = true
	default:
		return q, fmt.Errorf("root=%q is not 0 or 1. Pass root=1 when the plan is applied as root", raw)
	}
	switch q.File = v.Get("file"); {
	case q.File == "", q.File == clientFileNodeMirror, q.File == clientFileBundler, q.File == clientFileGradle:
	case clientconf.OCIFileKeyValid(q.File):
	default:
		return q, fmt.Errorf("file=%q names no companion file. Accepted: %s, %s, %s, %s, %s, %s",
			q.File, clientFileNodeMirror, clientFileBundler, clientFileGradle,
			clientconf.OCIFileContainerdConfig, clientconf.OCIFileRegistriesConf, clientconf.OCIHostsFileKey("<registry>"))
	}
	return q, nil
}

// resolveAptQuery rewrites the apt suites a query names, codename, archives
// and archive alike, to the apt_upstreams keys they resolve to
// (config.ResolveAptSuite), so the plan compares one spelling of each. A
// bare codename mirrored in several named archives is refused here.
func (s *Server) resolveAptQuery(q clientQuery) (clientQuery, error) {
	var err error
	if q.Codename, err = s.resolveAptSourceSuite(q.Codename); err != nil {
		return q, fmt.Errorf("codename=: %w", err)
	}
	q.codenameParam = s.aptSuiteParam(q.Codename)
	if q.Archive, err = s.cfg.ResolveAptSuite(q.Archive); err != nil {
		return q, fmt.Errorf("archive=: %w", err)
	}
	archives := make([]string, 0, len(q.Archives))
	for _, c := range q.Archives {
		key, err := s.cfg.ResolveAptSuite(c)
		if err != nil {
			return q, fmt.Errorf("archives=: %w", err)
		}
		if !slices.Contains(archives, key) {
			archives = append(archives, key)
		}
	}
	q.Archives = archives
	return q, nil
}

// resolveAptSourceSuite is config.ResolveAptSuite for the suite a host's
// own stanza names, which may also be a generated suite. Generated suites
// live at the default archive root, so /{codename} names one, and a bare
// codename both generated and mirrored in a named archive names neither:
// resolving it to the mirror would move a host that named the generated
// suite onto a vendor's publisher the moment that vendor is added.
func (s *Server) resolveAptSourceSuite(name string) (string, error) {
	codename, rooted := strings.CutPrefix(name, "/")
	if !s.aptGeneratedSuite(codename) {
		return s.cfg.ResolveAptSuite(name)
	}
	mirrors := s.cfg.AptKeysMirroring(codename)
	if rooted || len(mirrors) == 0 {
		return codename, nil
	}
	qualified := []string{"/" + codename}
	for _, key := range mirrors {
		qualified = append(qualified, s.cfg.AptQualifiedName(key))
	}
	return "", fmt.Errorf("apt codename %q is generated at the default archive and mirrored in %d other archives, so it names none of them: write one of %s (/%s is the generated suite, served at /apt/dists/%s/)",
		codename, len(mirrors), strings.Join(qualified, ", "), codename, codename)
}

// aptGeneratedSuite reports whether suite is one this server generates
// rather than mirrors. Load keeps the two sets disjoint.
func (s *Server) aptGeneratedSuite(suite string) bool {
	return suite != "" && !strings.Contains(suite, "/") && s.cfg.ServesAptSuite(suite) && !s.cfg.MirrorsAptCodename(suite)
}

// aptSuiteParam is how a URL names an apt_upstreams key: the key itself when
// it resolves back to itself, and {archive}/{codename} when the bare codename
// is mirrored in other archives too. A generated suite sharing its codename
// with a mirror is /{codename}, the spelling resolveAptSourceSuite reads back
// as the generated one.
func (s *Server) aptSuiteParam(key string) string {
	if s.aptGeneratedSuite(key) {
		if len(s.cfg.AptKeysMirroring(key)) > 0 {
			return "/" + key
		}
		return key
	}
	if back, err := s.cfg.ResolveAptSuite(key); err == nil && back == key {
		return key
	}
	return s.cfg.AptQualifiedName(key)
}

// aptSourceKey is the apt_upstreams key a rendered sources block serves, or
// its suite when no key mirrors it.
func (s *Server) aptSourceKey(src aptsources.Sources) string {
	if key, ok := s.cfg.AptSuiteAt(src.Archive, src.Suite); ok {
		return key
	}
	return src.Suite
}

// checkAptArchives refuses a named archive this server cannot configure: one
// it does not mirror, or mirrors with no vendor key, since a stanza naming a
// Signed-By: file nothing serves fails every "apt update".
func (s *Server) checkAptArchives(q clientQuery) error {
	names := q.Archives
	if q.Archive != "" {
		names = append(slices.Clone(names), q.Archive)
	}
	var bad []string
	for _, c := range names {
		if _, ok := s.cfg.AptSigningKeyFor(c); !ok {
			bad = append(bad, c)
		}
	}
	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf("this server cannot configure the apt archive %s: an archive is a codename apt_upstreams mirrors with signing_key_url and signing_key_fingerprint set.\n"+
		"  Archives it configures: %s", strings.Join(bad, ", "), aptKeyedList(s.cfg))
}

// encode is the query string a plan's file URLs carry, so /client/{system}
// renders for the same host facts the plan was built from.
func (q clientQuery) encode() string {
	v := url.Values{"os": {q.OS}}
	if q.ABI != "" {
		v.Set("abi", q.ABI)
	}
	if q.codenameParam != "" {
		v.Set("codename", q.codenameParam)
	} else if q.Codename != "" {
		v.Set("codename", q.Codename)
	}
	if q.Release != 0 {
		v.Set("release", strconv.Itoa(q.Release))
	}
	if q.OSID != "" {
		v.Set("os_id", q.OSID)
	}
	if q.OSVersionID != "" {
		v.Set("os_version_id", q.OSVersionID)
	}
	if q.Root {
		v.Set("root", "1")
	}
	return v.Encode()
}

// clientHost is a /client/ request resolved: the facts it stated and who the
// server decided it is.
type clientHost struct {
	q       clientQuery
	match   identityMatch
	profile *entitle.Profile
	base    string
}

// planFile is one system's outcome for one host: the file and where it goes,
// or the reason there is none. url is set on a companion file another route
// already serves (the apt keyring, the distfiles check); a system's own file
// is served at /client/{system}.
type planFile struct {
	system  string
	action  string
	path    string
	content []byte
	url     string
	reason  string
}

// admitClient is the first question every /client/ route asks, and writes
// the refusal itself when the answer is no: does this host resolve to an
// identity. It runs before the query or the system name is read, so an
// unknown address learns the command that admits it and nothing about which
// values this server accepts. clientMiddleware asks it first on the served
// chain, before the router can answer; the handlers ask again for a mux
// reached without that chain.
//
// An unidentified host is refused outright rather than handed the
// unprofiled plan. The plan names the profile and every path it writes, and
// the fleet-wide answer is the one a host outside the binding table would
// reach anyway by reading the docs; serving it here would make /client/ the
// route that tells an unknown address which profiles exist.
func (s *Server) admitClient(w http.ResponseWriter, r *http.Request, subject string) (identityMatch, bool) {
	m := identityMatchOf(r)
	if m.Identity == "" {
		s.writeClientError(w, r, subject, http.StatusForbidden, audit.DenialClientUnidentified, unidentifiedText(r))
		return m, false
	}
	return m, true
}

// clientHostFor reads the host facts an admitted request states, and writes
// the 400 itself when they are malformed and the 403 when the host's profile
// refuses a vendor archive they name (aptArchiveRefused). m is the binding IdentityMiddleware
// resolved, the same one profileFor reads the identity from, so the plan's
// profile and the rule it reports describe one resolution.
func (s *Server) clientHostFor(w http.ResponseWriter, r *http.Request, subject string, m identityMatch) (*clientHost, bool) {
	q, err := parseClientQuery(r)
	if err == nil {
		q, err = s.resolveAptQuery(q)
	}
	if err == nil {
		err = s.checkAptArchives(q)
	}
	if err != nil {
		s.writeClientError(w, r, subject, http.StatusBadRequest, "", err.Error())
		return nil, false
	}
	h := &clientHost{q: q, match: m, profile: s.profileFor(r), base: s.publicBase(r)}
	names := q.Archives
	if q.Archive != "" {
		names = append(slices.Clone(names), q.Archive)
	}
	for _, c := range names {
		if s.aptArchiveRefused(h.profile, c) {
			reason, next := aptArchiveRefusalText(h.profile, c)
			s.writeClientErrorFor(w, r, subject, h, http.StatusForbidden, audit.DenialProfileMembership,
				reason+"\n  "+strings.TrimSuffix(strings.ToUpper(next[:1])+next[1:], ".")+"\n")
			return nil, false
		}
	}
	return h, true
}

// unidentifiedText is the 403 body for a host no binding names. It gives the
// address the server saw, because the fix is a binding on that address, and
// says which of the two commands applies: a forwarded address with no
// trusted_proxies answer can be bound all day and still name nobody.
func unidentifiedText(r *http.Request) string {
	ip := ClientIP(r)
	var sb strings.Builder
	fmt.Fprintf(&sb, "this host (%s) resolves to no identity, and /client/ configures only a host the server can name.\n", ip)
	if !cidrAddressTrusted(r) {
		sb.WriteString("  The address came from a forwarded header this server does not yet believe. Name the proxy first:\n" +
			"    bodega acl proxies add <proxy-cidr>\n")
	}
	fmt.Fprintf(&sb, "  Bind this address:  bodega identity bind cidr %s <name>\n", hostPrefix(ip))
	sb.WriteString("  Or bind its token:  bodega identity bind token <token-id> <name>\n")
	sb.WriteString("  Then give the name a profile, if it needs one:  bodega profile bind <profile> <name>\n")
	return sb.String()
}

// hostPrefix is the single-address CIDR for ip, or a placeholder when ip does
// not parse.
func hostPrefix(ip string) string {
	switch {
	case strings.Contains(ip, ":"):
		return ip + "/128"
	case ip != "":
		return ip + "/32"
	}
	return "<cidr>"
}

// clientSystems is the order a plan lists systems in: every type bodega
// serves, in the build order the rest of the tree uses, then osquery, which
// configures a daemon rather than a package client.
func clientSystems() []string {
	return append(slices.Clone(manifest.AllTypes), clientconf.SystemOsquery)
}

// planFor renders every system's outcome for h.
func (s *Server) planFor(r *http.Request, h *clientHost) []planFile {
	var out []planFile
	for _, sys := range clientSystems() {
		out = append(out, s.planSystem(r, h, sys)...)
	}
	return out
}

// planSystem renders one system for h: its file first, then any companion
// file the first needs to work, or a single refusal or skip.
//
// The profile is asked first, so a system the profile excludes reads as a
// refusal on every operating system rather than as a skip that hides it.
func (s *Server) planSystem(r *http.Request, h *clientHost, sys string) []planFile {
	if reason := h.profile.Excludes(sys); reason != "" {
		return []planFile{{system: sys, action: planRefuse, reason: reason}}
	}
	one := func(f clientconf.File) []planFile {
		path := f.Path(h.q.OS)
		if path == "" {
			return []planFile{{system: sys, action: planSkip, reason: fmt.Sprintf("%s has no %s path on %s", f.Label, sys, h.q.OS)}}
		}
		return []planFile{{system: sys, action: planInstall, path: path, content: []byte(f.Content)}}
	}
	switch sys {
	case manifest.TypePypi, manifest.TypeCargo, manifest.TypeGomod, manifest.TypeHelm:
		return one(clientconf.ForType(sys, clientconf.Inputs{Base: h.base})[0])
	case manifest.TypeNpm:
		return s.planNpm(h, one)
	case manifest.TypeRubygems:
		return planRubygems(h, one)
	case manifest.TypeMaven:
		return s.planMaven(h, one)
	case manifest.TypeComposer:
		return planComposer(h, one)
	case manifest.TypeOCI:
		return s.planOCI(h)
	case manifest.TypeGit:
		return s.planGit(h, one)
	case manifest.TypeDistfiles:
		return s.planDistfiles(h, one)
	case manifest.TypeApt:
		return s.planApt(r, h, one)
	case manifest.TypeRpm:
		return s.planRpm(h, one)
	case manifest.TypeFreeBSD:
		return s.planFreeBSD(r, h, one)
	case manifest.TypeBinary:
		return []planFile{{system: sys, action: planSkip,
			reason: "binary entries are downloaded by URL, not configured, so there is no client file"}}
	case clientconf.SystemOsquery:
		return s.planOsquery(h, one)
	}
	return []planFile{{system: sys, action: planSkip, reason: "no client file is rendered for " + sys}}
}

// planGit renders the insteadOf rewrites for the namespaces the profile
// covers. A namespace the profile refuses would rewrite a clone onto a route
// that answers 403, which fails later and less legibly than no rewrite.
func (s *Server) planGit(h *clientHost, one func(clientconf.File) []planFile) []planFile {
	if len(s.cfg.GitUpstreams) == 0 {
		return []planFile{{system: manifest.TypeGit, action: planSkip,
			reason: "this server configures no git_upstreams namespace, so there is no route to rewrite a clone onto"}}
	}
	covered := map[string]config.GitUpstream{}
	for ns, up := range s.cfg.GitUpstreams {
		if h.profile.Covers(manifest.TypeGit, ns).Permitted {
			covered[ns] = up
		}
	}
	if len(covered) == 0 {
		return []planFile{{system: manifest.TypeGit, action: planRefuse,
			reason: fmt.Sprintf("profile %q covers none of the git namespaces this server rewrites", h.profile.Name())}}
	}
	return one(clientconf.Git(h.base, covered))
}

// planNpm renders .npmrc and, when a nodejs.org namespace is open, the file
// pointing node-gyp at it: the profile.d script under root=1, the user's
// environment.d file otherwise. Why the second file is missing, when the
// operator would expect it, rides on the .npmrc record's reason, because a
// skip record would make --configure npm refuse the registry line with it.
func (s *Server) planNpm(h *clientHost, one func(clientconf.File) []planFile) []planFile {
	npmrc := clientconf.Npm(h.base, s.cfg.BinaryUpstreams)
	out := one(npmrc)
	notes := npmrc.Notes
	mirror := clientconf.NodeMirror(h.base, s.cfg.BinaryUpstreams, h.q.Root)
	switch path := mirror.Path(h.q.OS); {
	case mirror.Content == "":
	case path == "":
		notes = append(notes, "node-gyp is left pointing at nodejs.org: nothing on "+h.q.OS+" reads a per-user environment file. Re-run as root to install "+clientconf.NodeMirrorSystemPath)
	default:
		v, _ := url.ParseQuery(h.q.encode())
		v.Set("file", clientFileNodeMirror)
		out = append(out, planFile{system: manifest.TypeNpm, action: planInstall, path: path,
			content: []byte(mirror.Content), url: h.base + "/client/" + manifest.TypeNpm + "?" + v.Encode()})
	}
	if out[0].action == planInstall {
		out[0].reason = strings.Join(notes, ". ")
	}
	return out
}

// planRubygems renders ~/.gemrc and Bundler's mirror. Both, because gem
// reads only the first and Bundler only the second, so a host handed one
// still installs from rubygems.org through the other.
func planRubygems(h *clientHost, one func(clientconf.File) []planFile) []planFile {
	files := clientconf.Rubygems(h.base)
	out := one(files[0])
	bundler := one(files[1])
	if bundler[0].action == planInstall {
		v, _ := url.ParseQuery(h.q.encode())
		v.Set("file", clientFileBundler)
		bundler[0].url = h.base + "/client/" + manifest.TypeRubygems + "?" + v.Encode()
	}
	return append(out, bundler...)
}

// planMaven renders Maven's settings.xml and Gradle's init script. Both,
// because Maven reads no init script and Gradle no settings.xml mirror. How
// each project's wrapper is pointed at bodega rides on the settings.xml
// record's reason: the property is in a file the project commits, which the
// plan does not write.
func (s *Server) planMaven(h *clientHost, one func(clientconf.File) []planFile) []planFile {
	files := clientconf.Maven(h.base, s.cfg.BinaryUpstreams)
	out := one(files[0])
	if out[0].action == planInstall {
		out[0].reason = strings.Join(files[0].Notes, ". ")
	}
	gradle := one(files[1])
	if gradle[0].action == planInstall {
		v, _ := url.ParseQuery(h.q.encode())
		v.Set("file", clientFileGradle)
		gradle[0].url = h.base + "/client/" + manifest.TypeMaven + "?" + v.Encode()
	}
	return append(out, gradle...)
}

// planComposer renders Composer's global config.json. Where it lands and
// that it is merged ride on the record's reason, since the path is the
// default Composer picks and a host's COMPOSER_HOME moves it.
func planComposer(h *clientHost, one func(clientconf.File) []planFile) []planFile {
	f := clientconf.Composer(h.base)
	out := one(f)
	if out[0].action == planInstall {
		out[0].reason = strings.Join(f.Notes, ". ")
	}
	return out
}

// planOCI renders every container runtime's file: Docker's daemon.json,
// containerd's hosts.toml per oci_upstreams registry and its config.toml,
// and the registries.conf drop-in podman, buildah and CRI-O read. The server
// cannot see which runtimes a host runs, so the plan carries all of them and
// the host keeps the ones it finds. Each runtime's notes ride on one record
// of its own, so a host that drops a runtime drops its notes with it.
func (s *Server) planOCI(h *clientHost) []planFile {
	if h.q.OS != clientconf.OSLinux {
		return []planFile{{system: manifest.TypeOCI, action: planSkip,
			reason: "container runtimes are configured on Linux, not " + h.q.OS}}
	}
	if len(s.cfg.OCIUpstreams) == 0 {
		return []planFile{{system: manifest.TypeOCI, action: planSkip,
			reason: "this server configures no oci_upstreams registry, so there is nothing to mirror"}}
	}
	var out []planFile
	for _, f := range clientconf.OCIClient(h.base, s.cfg.OCIUpstreams) {
		pf := planFile{system: manifest.TypeOCI, action: planInstall, path: f.Path(h.q.OS),
			content: []byte(f.Content), reason: strings.Join(f.Notes, ". ")}
		if f.Key != "" {
			v, _ := url.ParseQuery(h.q.encode())
			v.Set("file", f.Key)
			pf.url = h.base + "/client/" + manifest.TypeOCI + "?" + v.Encode()
		}
		out = append(out, pf)
	}
	return out
}

// planDistfiles renders make.conf and the client check it includes. The two
// go together: make fails on a missing .include, so a host handed the first
// without the second cannot build any port at all.
func (s *Server) planDistfiles(h *clientHost, one func(clientconf.File) []planFile) []planFile {
	if h.q.OS != clientconf.OSFreeBSD {
		return []planFile{{system: manifest.TypeDistfiles, action: planSkip,
			reason: "ports distfiles are fetched by the FreeBSD ports tree, which does not run on " + h.q.OS}}
	}
	if s.distinfo == nil {
		return []planFile{{system: manifest.TypeDistfiles, action: planSkip,
			reason: "this server has no distfiles_ports_tree configured, so it admits no distfile"}}
	}
	check, err := s.distinfo.ClientCheck()
	if err != nil {
		return []planFile{{system: manifest.TypeDistfiles, action: planSkip,
			reason: "the distfiles client check is not ready yet, so make.conf would include a file that does not exist: " + err.Error()}}
	}
	out := one(clientconf.MakeConf(h.base))
	return append(out, planFile{
		system: manifest.TypeDistfiles, action: planInstall, path: clientconf.DistfilesCheckPath,
		content: check, url: h.base + "/distfiles/" + clientCheckPath,
	})
}

// planApt picks the one stanza this host installs, by the rule
// aptHostSources applies for /api/v1/status, narrowed by the codename the
// host states. A signed stanza brings the keyring its Signed-By: names.
//
// A mirrored base and its pockets are one choice, rendered as one stanza, and
// so are a profile's filtered codenames over them. A stock host already runs
// packages from -updates and -security, so a stanza naming the base alone
// cannot install a -dev package whose runtime half is newer than the release,
// and the host stops receiving security fixes with nothing to report it.
func (s *Server) planApt(r *http.Request, h *clientHost, one func(clientconf.File) []planFile) []planFile {
	skip := func(reason string) []planFile {
		return []planFile{{system: manifest.TypeApt, action: planSkip, reason: reason}}
	}
	refuse := func(reason string) []planFile {
		return []planFile{{system: manifest.TypeApt, action: planRefuse, reason: reason}}
	}
	if h.q.OS != clientconf.OSLinux {
		return skip("apt runs on Debian-family Linux, not " + h.q.OS)
	}
	st := s.aptStatusFor(r)
	var src *aptsources.Sources
	if base, _ := h.profile.AptScope(); base != "" {
		if h.q.Codename != "" && h.q.Codename != base {
			return refuse(fmt.Sprintf("profile %q scopes apt to %s, and this host reports %s", h.profile.Name(), base, h.q.Codename))
		}
		if _, unresolved := s.aptPocketsOf(base); len(unresolved) > 0 {
			return refuse(fmt.Sprintf("profile %q scopes apt to %s: %s", h.profile.Name(), base, s.aptUnresolvedPocketsReason(base, unresolved)))
		}
		suites, missing := s.aptProfileHostSuites(h.profile)
		if len(suites) == 0 {
			return refuse(fmt.Sprintf("profile %q scopes apt to %s and no filtered codename answers for it yet; the index rebuild has not produced one", h.profile.Name(), base))
		}
		if len(missing) > 0 {
			return refuse(fmt.Sprintf("profile %q scopes apt to %s, and this server mirrors %s with no filtered codename for the profile: the rebuild withdrew it, and the server log names why (a codename another profile also derives, or an upstream read that failed). A host reading %s alone would stop receiving the updates and security fixes those pockets publish",
				h.profile.Name(), base, strings.Join(missing, ", "), strings.Join(suites, " ")))
		}
		rendered := s.aptStanzas(r, suites, false)
		src = &rendered
	} else {
		filtered := map[string]bool{}
		for _, key := range st.Filtered {
			filtered[key] = true
		}
		var choices []aptsources.Sources
		var keys, names, unplaced []string
		for _, served := range st.Sources {
			if served.Suite == "" || filtered[config.AptSuiteKey(served.Archive, served.Suite)] {
				continue
			}
			key := s.aptSourceKey(served)
			reason := ""
			if served.Mirrored || s.aptMirrorRewritten(key) {
				if _, ok := s.aptPocketBase(key); ok {
					continue
				}
				pockets, unresolved := s.aptPocketsOf(key)
				if len(pockets) > 0 {
					served = s.aptPocketStanza(r, key, pockets)
				}
				if len(unresolved) > 0 {
					reason = s.aptUnresolvedPocketsReason(key, unresolved)
				}
			}
			choices = append(choices, served)
			unplaced = append(unplaced, reason)
			keys = append(keys, key)
			names = append(names, s.aptSuiteParam(key))
		}
		switch {
		case len(choices) == 0:
			return skip("this server serves no apt suite")
		case h.q.Codename != "":
			if base, ok := s.aptPocketBase(h.q.Codename); ok {
				return skip(fmt.Sprintf("%s is a pocket of %s, and pockets are configured together with their base: name %s with %s", h.q.Codename, base, base, clientconf.AptSuiteRemedy(base)))
			}
			for i := range choices {
				if keys[i] == h.q.Codename {
					if unplaced[i] != "" {
						return refuse(unplaced[i])
					}
					src = &choices[i]
				}
			}
			if src == nil {
				return skip(fmt.Sprintf("this server serves no apt suite named %s. It serves %s: name one with %s", h.q.Codename, strings.Join(names, ", "), clientconf.AptSuiteRemedy("<suite>")))
			}
		case len(choices) == 1:
			if unplaced[0] != "" {
				return refuse(unplaced[0])
			}
			src = &choices[0]
		default:
			return skip(clientconf.AptSuiteChoiceReason(names))
		}
	}
	out := one(clientconf.Apt(*src))
	// A mirrored stanza carries Signed: true for the upstream signature, but
	// names no Signed-By:, so apt verifies it with the distro keyring and
	// bodega's would sit unread.
	if src.Signed && !src.Mirrored {
		ring := s.aptSign.Load().ring()
		if len(ring) == 0 {
			return skip("the stanza names bodega's keyring and no apt signing key is loaded to serve it")
		}
		out = append(out, planFile{
			system: manifest.TypeApt, action: planInstall, path: aptsources.ClientKeyringPath,
			content: ring, url: h.base + aptsources.KeyringRoute,
		})
	}
	return append(out, s.planAptArchives(r, h, aptStanzaSources(src.Deb822))...)
}

// aptSourcePair is one archive apt indexes: a URI and a suite read from it.
// apt keys its per-archive options on this pair, so two stanzas naming one
// pair with different Signed-By: values conflict, and the same suite under
// another URI is another archive.
type aptSourcePair struct{ uri, suite string }

// aptStanzaSources reads every (URI, suite) pair a rendered block names, each
// URI with the trailing slash apt adds to it. A block bodega rendered always
// parses; one that does not names no pair.
func aptStanzaSources(deb822 string) map[aptSourcePair]bool {
	out := map[aptSourcePair]bool{}
	entries, _ := clientconf.AptStanzaEntries(deb822)
	for _, e := range entries {
		for _, uri := range e.URIs {
			for _, suite := range e.Suites {
				out[aptSourcePair{strings.TrimSuffix(uri, "/") + "/", suite}] = true
			}
		}
	}
	return out
}

// planAptArchives renders each vendor archive the host named: its stanza,
// then the key that stanza's Signed-By: names, in the order Apply relies on
// to write the key first. The key's digest is over the bytes the key route
// serves, so a key that cannot be fetched or fails its fingerprint check
// refuses the whole system rather than installing a stanza apt cannot verify.
//
// An archive already on the host's own stanza, at the same URI and suite, is
// refused: two stanzas naming one archive with different Signed-By: values
// stop every "apt update" with "Conflicting values set for option
// Signed-By". The same codename under another archive root is another
// archive, with its own key.
func (s *Server) planAptArchives(r *http.Request, h *clientHost, onHost map[aptSourcePair]bool) []planFile {
	var out []planFile
	for _, c := range h.q.Archives {
		f := s.aptArchiveFile(h, c)
		pairs := aptStanzaSources(f.Content)
		for pair := range pairs {
			if onHost[pair] {
				return []planFile{{system: manifest.TypeApt, action: planRefuse,
					reason: fmt.Sprintf("%s (suite %s at %s) is already on this host's apt stanza, so a second stanza for it would conflict on Signed-By; drop it from archives", s.aptSuiteParam(c), pair.suite, pair.uri)}}
			}
		}
		for pair := range pairs {
			onHost[pair] = true
		}
		armored, status := s.aptVendorKey(r, c)
		if armored == nil {
			return []planFile{{system: manifest.TypeApt, action: planSkip,
				reason: fmt.Sprintf("the vendor key for %s could not be served (%d %s); the server log names why", c, status, http.StatusText(status))}}
		}
		v, _ := url.ParseQuery(h.q.encode())
		v.Set("archive", s.aptSuiteParam(c))
		out = append(out,
			planFile{system: manifest.TypeApt, action: planInstall, path: f.Path(clientconf.OSLinux),
				content: []byte(f.Content), url: h.base + "/client/" + manifest.TypeApt + "?" + v.Encode()},
			planFile{system: manifest.TypeApt, action: planInstall, path: clientconf.AptArchiveKeyPath(c),
				content: armored, url: h.base + aptVendorKeyRoute + c + ".asc"})
	}
	return out
}

func (s *Server) aptArchiveFile(h *clientHost, codename string) clientconf.File {
	return clientconf.AptArchiveIn(h.base, s.cfg.AptArchiveOf(codename), codename, s.cfg.AptComponentsFor(codename))
}

// aptPocketBase names the mirrored base a mirrored suite is a pocket of. A
// pocket whose base this server does not mirror belongs to nothing and stays a
// choice of its own. It is the inverse of aptMirroredPockets: a suite is a
// pocket of base exactly when base lists it.
func (s *Server) aptPocketBase(suite string) (string, bool) {
	if !s.cfg.MirrorsAptCodename(suite) {
		return "", false
	}
	archive := s.cfg.AptArchiveOf(suite)
	var base string
	clientconf.AptPocketBase(config.AptCodenameOf(suite), func(codename string) bool {
		if key, ok := s.cfg.AptSuiteAt(archive, codename); ok {
			base = key
			return true
		}
		if keys := s.cfg.AptKeysMirroring(codename); len(keys) == 1 {
			base = keys[0]
			return true
		}
		return false
	})
	if base == "" || !slices.Contains(s.aptMirroredPockets(base), suite) {
		return "", false
	}
	return base, true
}

// aptMirroredPockets lists the apt_upstreams keys of the pockets of base this
// server mirrors, in clientconf.AptPockets order. A pocket aptPocketsOf could
// not place is not among them; a caller building what a host reads asks
// aptPocketsOf, which names it.
func (s *Server) aptMirroredPockets(base string) []string {
	pockets, _ := s.aptPocketsOf(base)
	return pockets
}

// aptPocketsOf lists the apt_upstreams keys of the pockets of base this server
// mirrors, in clientconf.AptPockets order, and separately the mirrored pockets
// that may be base's but cannot be placed.
//
// A pocket is a suite of base's distribution, which is not always base's
// archive: Debian publishes trixie-security under its own root, so an
// operator lists it in an archive of its own. The pocket in base's own
// archive is the one read. A pocket in another archive is read only while
// base is the one key mirroring its codename and the pocket's archive holds
// no base of that codename, since otherwise a vendor's noble would claim
// Ubuntu's noble-security, or Ubuntu's noble a vendor's.
//
// Such a pocket that fails that test is unresolved, not absent. The
// configuration still serves it and nothing here can say whose it is, so a
// host plan that dropped it would install a base without its security fixes
// the moment a vendor of the same codename was added beside it.
func (s *Server) aptPocketsOf(base string) (pockets, unresolved []string) {
	archive, codename := s.cfg.AptArchiveOf(base), config.AptCodenameOf(base)
	sole := len(s.cfg.AptKeysMirroring(codename)) == 1
	clientconf.AptPockets(codename, func(pocket string) bool {
		if key, ok := s.cfg.AptSuiteAt(archive, pocket); ok {
			pockets = append(pockets, key)
			return true
		}
		var found []string
		for _, key := range s.cfg.AptKeysMirroring(pocket) {
			if _, home := s.cfg.AptSuiteAt(s.cfg.AptArchiveOf(key), codename); !home {
				found = append(found, key)
			}
		}
		switch {
		case len(found) == 0:
			return false
		case sole && len(found) == 1:
			pockets = append(pockets, found[0])
			return true
		}
		unresolved = append(unresolved, found...)
		return false
	})
	return pockets, unresolved
}

// aptUnresolvedPocketsReason refuses a host plan for base over the pockets
// aptPocketsOf could not place.
func (s *Server) aptUnresolvedPocketsReason(base string, unresolved []string) string {
	names := make([]string, len(unresolved))
	for i, key := range unresolved {
		names[i] = s.aptSuiteParam(key)
	}
	bases := s.cfg.AptKeysMirroring(config.AptCodenameOf(base))
	for i, key := range bases {
		bases[i] = s.aptSuiteParam(key)
	}
	return fmt.Sprintf("this server mirrors %s under an archive root apart from %s and cannot tell which of %s it is a pocket of, so a host reading %s alone would stop receiving the updates and security fixes it publishes. Move it into the archive of its base in apt_archives",
		strings.Join(names, ", "), s.aptSuiteParam(base), strings.Join(bases, ", "), s.aptSuiteParam(base))
}

// aptPocketStanza renders a mirrored base and its pockets as one choice, in
// as few stanzas as aptStanzas allows. A group the rebuild rewrote to drop a
// hidden version is rewritten whole (apt_hide.go), so its stanzas are
// bodega-signed and each suite names what its generated Release declares.
func (s *Server) aptPocketStanza(r *http.Request, base string, pockets []string) aptsources.Sources {
	return s.aptStanzas(r, append([]string{base}, pockets...), !s.aptMirrorRewritten(base))
}

// aptStanzas renders suites as one sources block: a stanza per archive root
// and distinct Components: line, the suites in the order they are named.
//
// apt reads a stanza's one URIs: and one Components: line for every suite on
// it. A suite under another archive's root answers 404 at the root the stanza
// names, and a component a suite does not publish stops "apt-get update" on
// the Packages file it cannot fetch, which is what a hide did to a pocket
// whose apt_upstreams entry lists fewer components than its base (#337): the
// rebuilt Release declares that pocket's own list, not the union.
//
// A mirrored suite's components are what its upstreams declare; a generated
// one's are what its generated Release declares.
func (s *Server) aptStanzas(r *http.Request, suites []string, mirrored bool) aptsources.Sources {
	type group struct {
		archive    string
		components []string
		suites     []string
	}
	var groups []*group
	for _, suite := range suites {
		archive := s.aptSuiteArchive(suite)
		components := s.aptServedComponents([]string{suite})
		if mirrored {
			components = aptsources.MirroredComponentList(s.cfg.AptComponentsFor(suite))
		}
		i := slices.IndexFunc(groups, func(g *group) bool {
			return g.archive == archive && componentsKey(g.components) == componentsKey(components)
		})
		if i < 0 {
			groups = append(groups, &group{archive: archive, components: components})
			i = len(groups) - 1
		}
		groups[i].suites = append(groups[i].suites, config.AptCodenameOf(suite))
	}
	parts := make([]aptsources.Sources, len(groups))
	for i, g := range groups {
		one := s.aptSourcesState(r)
		one.Suites, one.Components, one.Mirrored, one.Archive = g.suites, g.components, mirrored, g.archive
		parts[i] = aptsources.Render(one)
	}
	return aptsources.Join(parts)
}

// planRpm renders bodega.repo for the repositories this host's distribution
// reads, then bodega's key, which every section's gpgkey names first, in the
// order Apply relies on to write the key first. Disabling the vendor's own
// repositories is the host's step, not a file: only the host can see which of
// them it has enabled.
func (s *Server) planRpm(h *clientHost, one func(clientconf.File) []planFile) []planFile {
	skip := func(reason string) []planFile {
		return []planFile{{system: manifest.TypeRpm, action: planSkip, reason: reason}}
	}
	if h.q.OS != clientconf.OSLinux {
		return skip("dnf runs on RHEL-family Linux, not " + h.q.OS)
	}
	if h.q.OSID == "" || h.q.OSVersionID == "" {
		return skip(fmt.Sprintf("the repositories depend on this host's distribution, and it stated os_id=%q os_version_id=%q. bodega doctor sends ID and VERSION_ID from /etc/os-release; a direct request passes os_id=rocky&os_version_id=9.4",
			h.q.OSID, h.q.OSVersionID))
	}
	d, ok := clientconf.RpmDistroFor(h.q.OSID, h.q.OSVersionID)
	if !ok {
		return skip(fmt.Sprintf("this host's /etc/os-release reads ID=%s VERSION_ID=%s, which the rpm client table does not name, so nothing on it is changed. The table names %s",
			h.q.OSID, h.q.OSVersionID, clientconf.RpmDistroNames()))
	}
	key := s.aptSign.Load().pub()
	if len(key) == 0 {
		return skip("every section sets repo_gpgcheck=1, and this server holds no signing key to sign repomd.xml with; an operator runs `bodega apt key generate`")
	}
	f, kept := clientconf.RpmHost(h.base, d, func(up string) bool { _, ok := s.cfg.RpmUpstreams[up]; return ok })
	if len(kept) == 0 {
		names := make([]string, len(d.Repos))
		for i, r := range d.Repos {
			names[i] = r.Upstream
		}
		return skip(fmt.Sprintf("%s reads %s, and rpm_upstreams on this server configures none of them", d.Name(), strings.Join(names, ", ")))
	}
	out := one(f)
	out[0].reason = strings.Join(f.Notes, ". ")
	return append(out, planFile{system: manifest.TypeRpm, action: planInstall, path: clientconf.RpmKeyPath,
		content: key, url: h.base + clientconf.RpmKeyRoute})
}

// planFreeBSD picks this host's repository by ABI, the same choice `bodega
// doctor --write-pkg-repo` makes, from freeBSDStatusFor: that is where a
// profile that governs freebsd turns the stanza into the profile's filtered
// view, signed by bodega.
//
// bodega's own fingerprint is not in the plan. The stanza names it and says
// to deliver it out of band, because a fingerprint fetched from the server it
// authenticates authenticates nothing.
func (s *Server) planFreeBSD(r *http.Request, h *clientHost, one func(clientconf.File) []planFile) []planFile {
	skip := func(reason string) []planFile {
		return []planFile{{system: manifest.TypeFreeBSD, action: planSkip, reason: reason}}
	}
	if h.q.OS != clientconf.OSFreeBSD {
		return skip("pkg repositories configure FreeBSD, not " + h.q.OS)
	}
	if h.q.ABI == "" {
		return skip("the repository depends on this host's ABI: pass abi=<what `pkg config abi` prints>")
	}
	st := s.freeBSDStatusFor(r)
	var match []pkgrepos.Repo
	others := map[string]bool{}
	for _, repo := range st.Repos {
		if repo.ABI == h.q.ABI {
			match = append(match, repo)
			continue
		}
		others[repo.ABI] = true
	}
	switch {
	case len(match) == 1 && h.q.Release != 0 && h.q.Release != match[0].Release:
		repo, err := match[0].WithRelease(h.q.Release)
		if err != nil {
			return skip(err.Error())
		}
		return one(clientconf.FreeBSD(repo))
	case len(match) == 1:
		return one(clientconf.FreeBSD(match[0]))
	case len(match) > 1:
		names := make([]string, 0, len(match))
		for _, m := range match {
			names = append(names, m.Repo)
		}
		return skip(fmt.Sprintf("this server serves %d pkg repositories for %s (%s), so which one this host reads is the operator's decision: hide the others with `bodega pkg hide freebsd <repo>`",
			len(match), h.q.ABI, strings.Join(names, ", ")))
	}
	for _, ref := range st.Refused {
		if ref.ABI != h.q.ABI {
			continue
		}
		// Only a refusal that quotes no entry field is shown: the rest can
		// carry an upstream URL's credential, and this host is not an admin.
		if ref.public {
			return skip(fmt.Sprintf("this server serves %s for %s and will not render configuration for it: %s", ref.Repo, ref.ABI, ref.Error))
		}
		return skip(fmt.Sprintf("this server serves %s for %s and will not render configuration for it; `bodega doctor` on the server names why", ref.Repo, ref.ABI))
	}
	if len(others) == 0 {
		return skip("this server serves no pkg repository")
	}
	abis := make([]string, 0, len(others))
	for a := range others {
		abis = append(abis, a)
	}
	sort.Strings(abis)
	return skip(fmt.Sprintf("this server serves no pkg repository for %s. It serves %s", h.q.ABI, strings.Join(abis, ", ")))
}

// records turns a plan into what both encodings carry.
func (h *clientHost) records(files []planFile) []planRecord {
	out := make([]planRecord, 0, len(files))
	for _, f := range files {
		rec := planRecord{
			Identity: h.match.Identity,
			Profile:  h.profile.Name(),
			Match:    h.match.String(),
			System:   f.system,
			Action:   f.action,
			Reason:   f.reason,
		}
		if f.action == planInstall {
			sum := sha256.Sum256(f.content)
			rec.Path = f.path
			rec.SHA256 = hex.EncodeToString(sum[:])
			rec.URL = f.url
			if rec.URL == "" {
				rec.URL = h.base + "/client/" + f.system + "?" + h.q.encode()
			}
		}
		out = append(out, rec)
	}
	return out
}

// handleClientPlan serves GET /client/plan, the plan as JSON.
func (s *Server) handleClientPlan(w http.ResponseWriter, r *http.Request) {
	s.serveClientPlan(w, r, "plan", false)
}

// handleClientPlanText serves GET /client/plan.txt, the same records
// tab-separated for a sh loop.
func (s *Server) handleClientPlanText(w http.ResponseWriter, r *http.Request) {
	s.serveClientPlan(w, r, "plan.txt", true)
}

func (s *Server) serveClientPlan(w http.ResponseWriter, r *http.Request, subject string, text bool) {
	m, ok := s.admitClient(w, r, subject)
	if !ok {
		return
	}
	h, ok := s.clientHostFor(w, r, subject, m)
	if !ok {
		return
	}
	records := h.records(s.planFor(r, h))
	w.Header().Set("Cache-Control", "no-store")
	if text {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(planTSV(records)))
	} else {
		writeJSON(w, http.StatusOK, clientPlan{Records: records, Osquery: s.osqueryPlan(h)})
	}
	noteClient(r, subject, h, "", "")
}

// clientSetupScript is GET /client/setup.sh: one POSIX sh script, the same
// bytes for every host, that applies whatever /client/plan.txt says. Every
// per-host decision lives in the plan, so the script can be checked against
// the one digest /api/v1/status and docs/usage.md publish.
//
//go:embed client_setup.sh
var clientSetupScript []byte

// clientSetupSHA256 is the digest an operator compares the script against
// before piping it anywhere near a root shell.
var clientSetupSHA256 = func() string {
	sum := sha256.Sum256(clientSetupScript)
	return hex.EncodeToString(sum[:])
}()

// handleClientSetup serves GET /client/setup.sh. It sits behind the same
// admission as the plan: a host that could not fetch a plan has no use for
// the script, and the source is in the repository for anyone reviewing it.
func (s *Server) handleClientSetup(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.admitClient(w, r, "setup.sh"); !ok {
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(clientSetupScript)
	noteClient(r, "setup.sh", nil, "", "")
}

// osqueryShipScript is GET /client/osquery-ship.sh: the POSIX sh shipper
// that forwards osqueryd's results log to an osquery source in shipper mode.
// It is the same bytes for every host and takes its endpoint and token as
// arguments, so one digest covers it.
//
//go:embed osquery_ship.sh
var osqueryShipScript []byte

// osqueryShipSHA256 is the digest /api/v1/status publishes for the shipper.
var osqueryShipSHA256 = func() string {
	sum := sha256.Sum256(osqueryShipScript)
	return hex.EncodeToString(sum[:])
}()

// handleOsqueryShip serves GET /client/osquery-ship.sh behind the same
// admission as setup.sh.
func (s *Server) handleOsqueryShip(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.admitClient(w, r, "osquery-ship.sh"); !ok {
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(osqueryShipScript)
	noteClient(r, "osquery-ship.sh", nil, "", "")
}

// handleClientSystem serves GET /client/{system}: that system's file,
// rendered for this host. A system's companion files (the apt keyring, the
// distfiles check) keep the routes that already serve them.
func (s *Server) handleClientSystem(w http.ResponseWriter, r *http.Request) {
	sys := r.PathValue("system")
	m, ok := s.admitClient(w, r, sys)
	if !ok {
		return
	}
	known := false
	for _, t := range clientSystems() {
		known = known || t == sys
	}
	if !known {
		s.writeClientError(w, r, sys, http.StatusNotFound, "",
			fmt.Sprintf("no client system named %q. Systems: %s\n", sys, strings.Join(clientSystems(), ", ")))
		return
	}
	h, ok := s.clientHostFor(w, r, sys, m)
	if !ok {
		return
	}
	if h.q.Archive != "" {
		s.serveClientAptArchive(w, r, h, sys)
		return
	}
	switch h.q.File {
	case clientFileNodeMirror:
		s.serveClientNodeMirror(w, r, h, sys)
		return
	case clientFileBundler:
		s.serveClientBundler(w, r, h, sys)
		return
	case clientFileGradle:
		s.serveClientGradle(w, r, h, sys)
		return
	case "":
	default:
		s.serveClientOCIFile(w, r, h, sys)
		return
	}
	files := s.planSystem(r, h, sys)
	f := files[0]
	switch f.action {
	case planRefuse:
		s.writeClientErrorFor(w, r, sys, h, http.StatusForbidden, audit.DenialClientExcluded, f.reason+"\n")
		return
	case planSkip:
		s.writeClientErrorFor(w, r, sys, h, http.StatusNotFound, "", f.reason+"\n")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(f.content)
	noteClient(r, sys, h, "", "")
}

// serveClientAptArchive serves the stanza a plan's archive record names. The
// profile is asked first, as planSystem asks it, so a host whose profile
// excludes apt is refused the vendor stanza as it is refused its own.
func (s *Server) serveClientAptArchive(w http.ResponseWriter, r *http.Request, h *clientHost, sys string) {
	if sys != manifest.TypeApt {
		s.writeClientErrorFor(w, r, sys, h, http.StatusBadRequest, "", "archive= selects an apt vendor archive's stanza, and applies to /client/apt alone\n")
		return
	}
	if reason := h.profile.Excludes(sys); reason != "" {
		s.writeClientErrorFor(w, r, sys, h, http.StatusForbidden, audit.DenialClientExcluded, reason+"\n")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(s.aptArchiveFile(h, h.q.Archive).Content))
	noteClient(r, sys, h, "", "")
}

// serveClientOCIFile serves the containerd or registries.conf file a plan's
// oci record names, asking the profile first as planSystem does.
func (s *Server) serveClientOCIFile(w http.ResponseWriter, r *http.Request, h *clientHost, sys string) {
	if sys != manifest.TypeOCI {
		s.writeClientErrorFor(w, r, sys, h, http.StatusBadRequest, "", "file="+h.q.File+" selects a container runtime's file, and applies to /client/oci alone\n")
		return
	}
	if reason := h.profile.Excludes(sys); reason != "" {
		s.writeClientErrorFor(w, r, sys, h, http.StatusForbidden, audit.DenialClientExcluded, reason+"\n")
		return
	}
	for _, f := range clientconf.OCIClient(h.base, s.cfg.OCIUpstreams) {
		if f.Key == h.q.File && f.Path(h.q.OS) != "" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(f.Content))
			noteClient(r, sys, h, "", "")
			return
		}
	}
	s.writeClientErrorFor(w, r, sys, h, http.StatusNotFound, "",
		"file="+h.q.File+" names no oci file this server renders for "+h.q.OS+": the registry is not a key of oci_upstreams, or the runtime is not configured there\n")
}

// serveClientNodeMirror serves the NODEJS_ORG_MIRROR file a plan's npm
// companion record names, asking the profile first as planSystem does.
func (s *Server) serveClientNodeMirror(w http.ResponseWriter, r *http.Request, h *clientHost, sys string) {
	if sys != manifest.TypeNpm {
		s.writeClientErrorFor(w, r, sys, h, http.StatusBadRequest, "", "file="+clientFileNodeMirror+" selects npm's node-gyp mirror file, and applies to /client/npm alone\n")
		return
	}
	if reason := h.profile.Excludes(sys); reason != "" {
		s.writeClientErrorFor(w, r, sys, h, http.StatusForbidden, audit.DenialClientExcluded, reason+"\n")
		return
	}
	f := clientconf.NodeMirror(h.base, s.cfg.BinaryUpstreams, h.q.Root)
	if f.Content == "" || f.Path(h.q.OS) == "" {
		s.writeClientErrorFor(w, r, sys, h, http.StatusNotFound, "",
			"this server has no binary_upstreams namespace on https://nodejs.org/ in open mode, or this host has no path for the file, so there is no node-gyp mirror file to serve\n")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(f.Content))
	noteClient(r, sys, h, "", "")
}

// serveClientBundler serves the Bundler mirror file a plan's rubygems
// companion record names, asking the profile first as planSystem does.
func (s *Server) serveClientBundler(w http.ResponseWriter, r *http.Request, h *clientHost, sys string) {
	if sys != manifest.TypeRubygems {
		s.writeClientErrorFor(w, r, sys, h, http.StatusBadRequest, "", "file="+clientFileBundler+" selects Bundler's mirror file, and applies to /client/rubygems alone\n")
		return
	}
	if reason := h.profile.Excludes(sys); reason != "" {
		s.writeClientErrorFor(w, r, sys, h, http.StatusForbidden, audit.DenialClientExcluded, reason+"\n")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	//nolint:gosec // G705: a YAML file served as text/plain, never HTML; the one interpolated value is this server's own base URL.
	_, _ = w.Write([]byte(clientconf.Rubygems(h.base)[1].Content))
	noteClient(r, sys, h, "", "")
}

// serveClientGradle serves the Gradle init script a plan's maven companion
// record names, asking the profile first as planSystem does.
func (s *Server) serveClientGradle(w http.ResponseWriter, r *http.Request, h *clientHost, sys string) {
	if sys != manifest.TypeMaven {
		s.writeClientErrorFor(w, r, sys, h, http.StatusBadRequest, "", "file="+clientFileGradle+" selects Gradle's init script, and applies to /client/maven alone\n")
		return
	}
	if reason := h.profile.Excludes(sys); reason != "" {
		s.writeClientErrorFor(w, r, sys, h, http.StatusForbidden, audit.DenialClientExcluded, reason+"\n")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	//nolint:gosec // G705: a Groovy script served as text/plain, never HTML; the one interpolated value is this server's own base URL.
	_, _ = w.Write([]byte(clientconf.Maven(h.base, s.cfg.BinaryUpstreams)[1].Content))
	noteClient(r, sys, h, "", "")
}

func (s *Server) writeClientError(w http.ResponseWriter, r *http.Request, subject string, status int, denial, body string) {
	s.writeClientErrorFor(w, r, subject, nil, status, denial, body)
}

func (s *Server) writeClientErrorFor(w http.ResponseWriter, r *http.Request, subject string, h *clientHost, status int, denial, body string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, strings.TrimRight(body, "\n"), status)
	noteClient(r, subject, h, denial, body)
}

// clientAudit is what a /client/ handler knows about its own response and
// the router does not: the subject, the host it resolved, and why it
// refused. clientMiddleware writes the row from it once the response is
// out. A response nothing annotated came from the router itself (a method
// the route does not take, a path it cannot match, a path it cleaned and
// redirected), and is recorded all the same.
type clientAudit struct {
	subject string
	host    *clientHost
	denial  string
	reason  string
	// recorded is set when a middleware between this one and the mux wrote
	// its own denied row for the response, so it is not written twice.
	recorded bool
}

func clientAuditOf(r *http.Request) *clientAudit {
	n, _ := r.Context().Value(clientAuditKey).(*clientAudit)
	return n
}

// noteClient hands the response's audit facts to clientMiddleware. A
// request that did not come through it (a test driving the mux directly)
// has nowhere to put them, and records nothing.
func noteClient(r *http.Request, subject string, h *clientHost, denial, reason string) {
	if n := clientAuditOf(r); n != nil {
		n.subject, n.host, n.denial, n.reason = subject, h, denial, reason
	}
}

// isClientPath reports whether path is one clientMiddleware answers for. It
// is the raw request path, before the mux cleans it, so /client//plan counts
// as the /client/ request it was sent as.
func isClientPath(path string) bool {
	return path == "/client" || strings.HasPrefix(path, "/client/")
}

// clientPathSubject is the audit subject for a /client/ response no handler
// named, taken from the raw path.
func clientPathSubject(r *http.Request) string {
	return strings.TrimPrefix(r.URL.Path, "/client/")
}

// clientMiddleware is the /client/ boundary: it admits the host and writes one
// audit row per response. It sits inside IdentityMiddleware, so both read the
// binding that request resolved, and outside the mutation gate and the mux, so
// an unidentified host gets the admission refusal before either can answer
// with a bare 403, a 405, a 404 or a redirect, and their answers to an
// identified host are rows too rather than responses that left no trace. The
// deny list is further out, refuses with its own repair, and writes its own
// row.
//
// AuditMiddleware cannot write these rows: it records a 2xx alone and parses
// a package out of the path, and neither fits a route whose refusals are the
// half an operator is looking for.
func (s *Server) clientMiddleware(next http.Handler) http.Handler {
	admit := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if identityMatchOf(r).Identity == "" {
			s.writeClientError(w, r, clientPathSubject(r), http.StatusForbidden, audit.DenialClientUnidentified, unidentifiedText(r))
			return
		}
		next.ServeHTTP(w, r)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isClientPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if s.auditDB == nil {
			admit.ServeHTTP(w, r)
			return
		}
		n := &clientAudit{}
		rec := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		r = r.WithContext(context.WithValue(r.Context(), clientAuditKey, n))
		admit.ServeHTTP(rec, r)
		if !n.recorded {
			s.recordClient(r, n, rec.statusCode)
		}
	})
}

// maxClientSubject bounds a /client/ row's name. The longest name a served
// response carries is osquery-ship.sh; anything longer is a caller's path.
const maxClientSubject = 64

// recordClient writes the audit row for one /client/ response. A served plan
// or file is a serve_fetch row, which is the row a package download writes,
// so `bodega audit events --type serve_fetch` shows which hosts pulled which
// plan. A 403 is a denied row, beside every other refusal. Anything else is a
// serve_fetch row with status failure and the reason in details, because a
// host that asked and got nothing is still a host that asked.
//
// No header is copied into the row, the Authorization header least of all.
func (s *Server) recordClient(r *http.Request, n *clientAudit, status int) {
	details := map[string]string{}
	subject, reason := n.subject, n.reason
	if subject == "" {
		subject = clientPathSubject(r)
		reason = fmt.Sprintf("the router answered %d %s before any /client/ handler ran", status, http.StatusText(status))
		details["method"] = r.Method
		details["path"] = truncateField(r.URL.Path, maxDetailField)
	}
	// A handler's subject is the raw {system} segment, and the admission
	// refusal's is the raw path: both are whatever an anonymous caller sent.
	subject = truncateField(subject, maxClientSubject)
	// The stated os rides in the version column, so one query separates the
	// FreeBSD hosts' plans from the Linux ones.
	ev := audit.Event{
		EventType:  audit.EventServeFetch,
		PkgType:    "client",
		PkgName:    subject,
		PkgVersion: truncateField(r.URL.Query().Get("os"), 16),
		ClientIP:   ClientIP(r),
		Identity:   Identity(r),
		UserAgent:  truncateField(r.UserAgent(), maxDetailField),
		Status:     "success",
	}
	if h := n.host; h != nil && h.profile != nil {
		details["profile"] = h.profile.Name()
	}
	if h := n.host; h != nil && h.match.Kind != "" {
		details["match"] = h.match.String()
	}
	if status != http.StatusOK {
		details["http_status"] = fmt.Sprint(status)
		details["reason"] = truncateField(strings.TrimSpace(reason), maxDetailField)
		ev.Status = "failure"
		if n.denial != "" {
			ev.EventType, ev.Status = audit.EventDenied, n.denial
		}
	}
	if b, err := json.Marshal(details); err == nil {
		ev.Details = string(b)
	}
	ctx, cancel := auditContext(r)
	defer cancel()
	if err := s.auditDB.Record(ctx, ev); err != nil {
		s.logger.Error("audit write failed, /client/ response not recorded, still serving",
			"subject", subject, "status", status, "error", err)
	}
}
