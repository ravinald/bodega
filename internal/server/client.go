package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/ravinald/bodega/internal/aptsources"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/entitle"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/pkgrepos"
)

// Plan actions. install is a file to write; refuse is a system the host's
// profile excludes; skip is a system with nothing to install on this host,
// for a reason that is not the profile's: the wrong operating system, nothing
// configured on the server, or a choice only the operator can make.
const (
	planInstall = "install"
	planRefuse  = "refuse"
	planSkip    = "skip"
)

// planColumns is the order plan.txt writes a record's fields in. It is the
// contract a POSIX sh loop reads with IFS set to a tab, so a column is only
// ever appended.
var planColumns = []string{"identity", "profile", "match", "system", "action", "path", "url", "sha256", "reason"}

// planEmpty stands in for an empty field in plan.txt. A tab is IFS white
// space to sh's read, so two tabs in a row collapse into one separator and
// every column after an empty one would shift left.
const planEmpty = "-"

// planRecord is one line of a client plan: one file for one system, or the
// reason a system has none. The host's identity rides on every record rather
// than on a header line, so a loop reading plan.txt needs one case, not two.
type planRecord struct {
	Identity string `json:"identity"`
	Profile  string `json:"profile"`
	Match    string `json:"match"`
	System   string `json:"system"`
	Action   string `json:"action"`
	Path     string `json:"path"`
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
	Reason   string `json:"reason"`
}

// clientPlan is GET /client/plan. The records are plan.txt's lines, field
// for field, so a tool can switch encodings without reinterpreting anything.
type clientPlan struct {
	Records []planRecord `json:"records"`
}

func (p planRecord) fields() []string {
	return []string{p.Identity, p.Profile, p.Match, p.System, p.Action, p.Path, p.URL, p.SHA256, p.Reason}
}

// planTSV writes records in planColumns order, one per line.
func planTSV(records []planRecord) string {
	var sb strings.Builder
	for _, rec := range records {
		for i, f := range rec.fields() {
			if i > 0 {
				sb.WriteByte('\t')
			}
			if f == "" {
				f = planEmpty
			}
			sb.WriteString(f)
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

// planField strips what would break a plan.txt line. Every value is the
// server's own, but an identity or a reason quoting an operator's config is
// not something this route gets to trust to be one line.
func planField(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, s)
}

// clientQuery is what a host states about itself because the server cannot
// see it: its operating system, and where they apply its pkg ABI and apt
// codename.
type clientQuery struct {
	OS       string
	ABI      string
	Codename string
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
		return q, fmt.Errorf("codename=%q is not an apt suite name. Pass what `lsb_release -cs` prints, for example noble", q.Codename)
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

// resolveClient answers the two questions every /client/ route asks first,
// and writes the response itself when either answer is no: are the stated
// host facts well formed, and does this host resolve to an identity.
//
// An unidentified host is refused outright rather than handed the
// unprofiled plan. The plan names the profile and every path it writes, and
// the fleet-wide answer is the one a host outside the binding table would
// reach anyway by reading the docs; serving it here would make /client/ the
// route that tells an unknown address which profiles exist.
func (s *Server) resolveClient(w http.ResponseWriter, r *http.Request, subject string) (*clientHost, bool) {
	q, err := parseClientQuery(r)
	if err != nil {
		s.writeClientError(w, r, subject, http.StatusBadRequest, "", err.Error())
		return nil, false
	}
	m := s.identityMatchFor(r)
	if id := Identity(r); m.Identity != id {
		// The binding table reloaded between the middleware and here. The
		// middleware's answer decided the profile, so it decides the plan,
		// and the match is left unnamed rather than reported as a row that no
		// longer names this host.
		m = identityMatch{Identity: id}
	}
	if m.Identity == "" {
		s.writeClientError(w, r, subject, http.StatusForbidden, audit.DenialClientUnidentified, unidentifiedText(r))
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
			Identity: planField(h.match.Identity),
			Profile:  planField(h.profile.Name()),
			Match:    planField(h.match.String()),
			System:   f.system,
			Action:   f.action,
			Reason:   planField(f.reason),
		}
		if f.action == planInstall {
			sum := sha256.Sum256(f.content)
			rec.Path = planField(f.path)
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
	h, ok := s.resolveClient(w, r, subject)
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
		writeJSON(w, http.StatusOK, clientPlan{Records: records})
	}
	s.recordClient(r, subject, h, http.StatusOK, "", "")
}

// handleClientSystem serves GET /client/{system}: that system's file,
// rendered for this host. A system's companion files (the apt keyring, the
// distfiles check) keep the routes that already serve them.
func (s *Server) handleClientSystem(w http.ResponseWriter, r *http.Request) {
	sys := r.PathValue("system")
	known := false
	for _, t := range clientSystems() {
		known = known || t == sys
	}
	if !known {
		s.writeClientError(w, r, sys, http.StatusNotFound, "",
			fmt.Sprintf("no client system named %q. Systems: %s\n", sys, strings.Join(clientSystems(), ", ")))
		return
	}
	h, ok := s.resolveClient(w, r, sys)
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
	s.recordClient(r, sys, h, http.StatusOK, "", "")
}

func (s *Server) writeClientError(w http.ResponseWriter, r *http.Request, subject string, status int, denial, body string) {
	s.writeClientErrorFor(w, r, subject, nil, status, denial, body)
}

func (s *Server) writeClientErrorFor(w http.ResponseWriter, r *http.Request, subject string, h *clientHost, status int, denial, body string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, strings.TrimRight(body, "\n"), status)
	s.recordClient(r, subject, h, status, denial, body)
}

// recordClient writes the audit row for one /client/ response. A served plan
// or file is a serve_fetch row, which is the row a package download writes,
// so `bodega audit events --type serve_fetch` shows which hosts pulled which
// plan. A 403 is a denied row, beside every other refusal. Anything else is a
// serve_fetch row with status failure and the reason in details, because a
// host that asked and got nothing is still a host that asked.
//
// Written here rather than by AuditMiddleware, which records a 2xx alone and
// parses a package out of the path; neither fits a route whose refusals are
// the half an operator is looking for.
func (s *Server) recordClient(r *http.Request, subject string, h *clientHost, status int, denial, reason string) {
	if s.auditDB == nil {
		return
	}
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
	details := map[string]string{}
	if h != nil && h.profile != nil {
		details["profile"] = h.profile.Name()
	}
	if h != nil && h.match.Kind != "" {
		details["match"] = h.match.String()
	}
	if status != http.StatusOK {
		details["http_status"] = fmt.Sprint(status)
		details["reason"] = truncateField(strings.TrimSpace(reason), maxDetailField)
		ev.Status = "failure"
		if denial != "" {
			ev.EventType, ev.Status = audit.EventDenied, denial
		}
	}
	if len(details) > 0 {
		if b, err := json.Marshal(details); err == nil {
			ev.Details = string(b)
		}
	}
	ctx, cancel := auditContext(r)
	defer cancel()
	if err := s.auditDB.Record(ctx, ev); err != nil {
		s.logger.Error("audit write failed, /client/ response not recorded, still serving",
			"subject", subject, "status", status, "error", err)
	}
}
