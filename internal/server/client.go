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
	// Release is the FreeBSD major release whose repository tags the pkg
	// overrides disable, for a host whose release is not the one its
	// repository is named for. Zero keeps the repository's own.
	Release int
}

var (
	clientABIRe      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._-]{0,63}$`)
	clientCodenameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]{0,63}$`)
)

func parseClientQuery(r *http.Request) (clientQuery, error) {
	v := r.URL.Query()
	q := clientQuery{OS: v.Get("os"), ABI: v.Get("abi"), Codename: v.Get("codename")}
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
	if raw := v.Get("release"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 99 {
			return q, fmt.Errorf("release=%q is not a FreeBSD major release. Pass the major number alone, for example release=14", raw)
		}
		q.Release = n
	}
	return q, nil
}

// encode is the query string a plan's file URLs carry, so /client/{system}
// renders for the same host facts the plan was built from.
func (q clientQuery) encode() string {
	v := url.Values{"os": {q.OS}}
	if q.ABI != "" {
		v.Set("abi", q.ABI)
	}
	if q.Codename != "" {
		v.Set("codename", q.Codename)
	}
	if q.Release != 0 {
		v.Set("release", strconv.Itoa(q.Release))
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
// the 400 itself when they are malformed. m is the binding IdentityMiddleware
// resolved, the same one profileFor reads the identity from, so the plan's
// profile and the rule it reports describe one resolution.
func (s *Server) clientHostFor(w http.ResponseWriter, r *http.Request, subject string, m identityMatch) (*clientHost, bool) {
	q, err := parseClientQuery(r)
	if err != nil {
		s.writeClientError(w, r, subject, http.StatusBadRequest, "", err.Error())
		return nil, false
	}
	return &clientHost{q: q, match: m, profile: s.profileFor(r), base: s.publicBase(r)}, true
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
// serves, in the build order the rest of the tree uses.
func clientSystems() []string { return manifest.AllTypes }

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
	case manifest.TypePypi, manifest.TypeNpm, manifest.TypeCargo, manifest.TypeGomod, manifest.TypeHelm:
		return one(clientconf.ForType(sys, clientconf.Inputs{Base: h.base})[0])
	case manifest.TypeGit:
		return s.planGit(h, one)
	case manifest.TypeDistfiles:
		return s.planDistfiles(h, one)
	case manifest.TypeApt:
		return s.planApt(r, h, one)
	case manifest.TypeFreeBSD:
		return s.planFreeBSD(r, h, one)
	case manifest.TypeBinary:
		return []planFile{{system: sys, action: planSkip,
			reason: "binary entries are downloaded by URL, not configured, so there is no client file"}}
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
func (s *Server) planApt(r *http.Request, h *clientHost, one func(clientconf.File) []planFile) []planFile {
	skip := func(reason string) []planFile {
		return []planFile{{system: manifest.TypeApt, action: planSkip, reason: reason}}
	}
	if h.q.OS != clientconf.OSLinux {
		return skip("apt runs on Debian-family Linux, not " + h.q.OS)
	}
	st := s.aptStatusFor(r)
	var src *aptsources.Sources
	if base, _ := h.profile.AptScope(); base != "" {
		if h.q.Codename != "" && h.q.Codename != base {
			return []planFile{{system: manifest.TypeApt, action: planRefuse,
				reason: fmt.Sprintf("profile %q scopes apt to %s, and this host reports %s", h.profile.Name(), base, h.q.Codename)}}
		}
		if st.Host == nil {
			return []planFile{{system: manifest.TypeApt, action: planRefuse,
				reason: fmt.Sprintf("profile %q scopes apt to %s and no filtered codename answers for it yet; the index rebuild has not produced one", h.profile.Name(), base)}}
		}
		src = st.Host
	} else {
		filtered := map[string]bool{}
		for _, c := range st.Filtered {
			filtered[c] = true
		}
		var choices []aptsources.Sources
		var names []string
		for _, served := range st.Sources {
			if served.Suite == "" || filtered[served.Suite] {
				continue
			}
			choices = append(choices, served)
			names = append(names, served.Suite)
		}
		switch {
		case len(choices) == 0:
			return skip("this server serves no apt suite")
		case h.q.Codename != "":
			for i := range choices {
				if choices[i].Suite == h.q.Codename {
					src = &choices[i]
				}
			}
			if src == nil {
				return skip(fmt.Sprintf("this server serves no apt suite named %s. It serves %s", h.q.Codename, strings.Join(names, ", ")))
			}
		case len(choices) == 1:
			src = &choices[0]
		default:
			return skip(fmt.Sprintf("this server serves %d apt suites (%s), so which one this host reads is its own fact: pass codename=<suite>",
				len(choices), strings.Join(names, ", ")))
		}
	}
	out := one(clientconf.Apt(*src))
	if src.Signed {
		ring := s.aptSign.Load().ring()
		if len(ring) == 0 {
			return skip("the stanza names bodega's keyring and no apt signing key is loaded to serve it")
		}
		out = append(out, planFile{
			system: manifest.TypeApt, action: planInstall, path: aptsources.ClientKeyringPath,
			content: ring, url: h.base + aptsources.KeyringRoute,
		})
	}
	return out
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
