package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// The checks a refusal names. The same word goes in the X-Bodega-Refusal
// header, in every body, and in the docs, so the developer quoting it and the
// operator searching for it are using one vocabulary.
const (
	checkAllowList  = "allow-list"
	checkAge        = "age"
	checkOSV        = "osv"
	checkProfile    = "profile"
	checkHidden     = "hidden"
	checkFrozen     = "frozen"
	checkChecksum   = "checksum"
	checkConstraint = "constraint"
)

// refusalHeader carries the check and the incident on every refusal, so a
// client that prints neither body nor reason phrase still leaves both in a
// verbose log.
const refusalHeader = "X-Bodega-Refusal"

// statusLineClients are the types whose client shows the status line of a
// failed fetch and never its body: pip prints "403 Client Error: <phrase> for
// url", helm "failed to fetch <url> : 403 <phrase>", and apt "403 <phrase>
// [IP: ...]".
var statusLineClients = map[string]bool{
	manifest.TypePypi: true,
	manifest.TypeHelm: true,
	manifest.TypeApt:  true,
}

// refusalClientAPI selects the mutation API's own {"error": ...} body.
const refusalClientAPI = "api"

// maxReasonPhrase bounds the status line pip prints. Long enough for the
// summary sentence, short enough that no intermediary rejects the line.
const maxReasonPhrase = 400

// refusal is one answer bodega gives a client it will not serve, readable at
// the terminal of whoever hit it with no access to the server's journal.
//
// Every field a body carries is built by the server from the package the
// client named and the check that refused it. None is copied from an upstream
// URL, a storage key or a config value: those carry credentials, internal
// hostnames and bucket names, and the body goes to anyone who can reach the
// route. The incident is the bridge to everything withheld: the audit row the
// refusal wrote carries it in its details, beside the URL and the key.
type refusal struct {
	check    string
	pkgType  string
	name     string
	version  string
	reason   string // one sentence
	next     string // what the person refused does about it
	incident string
	status   int
	// client picks the body format. Empty means the format pkgType's own
	// client reads; refusalClientAPI is the mutation API's JSON.
	client string
}

// newIncident is audit.NewIncidentID, held in a variable so a test can pin
// the one value every rendered body depends on.
var newIncident = audit.NewIncidentID

func newRefusal(check, pkgType, name, version string, status int) *refusal {
	return &refusal{
		check:    check,
		pkgType:  pkgType,
		name:     name,
		version:  version,
		status:   status,
		incident: newIncident(),
	}
}

func (f *refusal) subject() string {
	s := f.pkgType
	if f.name != "" {
		s += "/" + f.name
	}
	if f.version != "" {
		s += "@" + f.version
	}
	return s
}

// summary is the first line of every body and the whole of the pypi reason
// phrase. The check and the incident lead, because some clients show one line
// and that line has to be the one an operator can search for.
func (f *refusal) summary() string {
	return fmt.Sprintf("bodega refused %s (%s, incident %s): %s", f.subject(), f.check, f.incident, f.reason)
}

func (f *refusal) text() string {
	return f.summary() + "\nNext step: " + f.next + "\n"
}

func (f *refusal) oneLine() string {
	return f.summary() + " Next step: " + f.next
}

func (f *refusal) headerValue() string {
	return f.check + "; incident=" + f.incident
}

// render picks the body each client prints. npm reads the "error" field of a
// JSON body into its own error line, and the mutation API answers every other
// error in that shape. cargo prints the body of a failed fetch whole, and its
// registry API spells errors as {"errors":[{"detail":...}]}. go prints a text
// body under "server response:". pip, helm and apt print only the status
// line, which write handles; their body is text for anything else reading it.
func (f *refusal) render() (contentType string, body []byte) {
	client := f.client
	if client == "" {
		client = f.pkgType
	}
	switch client {
	case manifest.TypeNpm, refusalClientAPI:
		return "application/json", jsonBody(map[string]string{"error": f.oneLine()})
	case manifest.TypeCargo:
		return "application/json", jsonBody(map[string][]map[string]string{"errors": {{"detail": f.oneLine()}}})
	}
	return "text/plain; charset=utf-8", []byte(f.text())
}

// jsonBody encodes without HTML escaping: the next step names commands with
// <placeholders>, and \u003c is what a person reading curl output gets
// otherwise.
func jsonBody(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return b.Bytes()
}

// write answers the request with the refusal. The status is the caller's; only
// the body and headers are this type's.
func (f *refusal) write(w http.ResponseWriter, r *http.Request) {
	ctype, body := f.render()
	if statusLineClients[f.pkgType] && f.client == "" && f.writeWithReasonPhrase(w, r, ctype, body) {
		return
	}
	h := w.Header()
	h.Set("Content-Type", ctype)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set(refusalHeader, f.headerValue())
	h.Del("Content-Length")
	w.WriteHeader(f.status)
	if r.Method != http.MethodHead {
		//nolint:gosec // G705: text/plain or JSON under nosniff, never HTML.
		_, _ = w.Write(body)
	}
}

// reasonPhrase is summary() reduced to what RFC 9112 permits in a status
// line: visible ASCII and spaces, bounded.
func (f *refusal) reasonPhrase() string {
	var b strings.Builder
	b.WriteString(http.StatusText(f.status))
	b.WriteString(" - ")
	for _, c := range f.summary() {
		if c < 0x20 || c > 0x7e {
			c = ' '
		}
		b.WriteRune(c)
	}
	s := b.String()
	if len(s) > maxReasonPhrase {
		s = s[:maxReasonPhrase]
	}
	return s
}

// writeWithReasonPhrase answers over the raw connection so the status line
// carries the refusal, for a client that never reads the body. net/http writes
// http.StatusText as the phrase with no way to override it. Only HTTP/1.x has
// a phrase to carry; HTTP/2 and a writer that cannot be hijacked fall back to
// the ordinary response, which still carries the header and the body.
func (f *refusal) writeWithReasonPhrase(w http.ResponseWriter, r *http.Request, ctype string, body []byte) bool {
	if r.ProtoMajor != 1 {
		return false
	}
	conn, buf, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	// The server's WriteTimeout no longer applies to a hijacked connection.
	_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	observeHijack(w, f.status)

	h := w.Header().Clone()
	h.Set("Content-Type", ctype)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set(refusalHeader, f.headerValue())
	h.Set("Content-Length", strconv.Itoa(len(body)))
	h.Set("Connection", "close")
	h.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	fmt.Fprintf(buf, "HTTP/1.1 %d %s\r\n", f.status, f.reasonPhrase())
	_ = h.Write(buf)
	_, _ = buf.WriteString("\r\n")
	if r.Method != http.MethodHead {
		_, _ = buf.Write(body)
	}
	_ = buf.Flush()
	return true
}

// hijackObserver is a wrapping writer that must learn the status of a
// response written past it on the raw connection: the request logger and the
// fetch auditor would otherwise record a 200, and a buffering writer would try
// to write its own response after the connection is gone.
type hijackObserver interface {
	observeHijack(status int)
}

func observeHijack(w http.ResponseWriter, status int) {
	for w != nil {
		if o, ok := w.(hijackObserver); ok {
			o.observeHijack(status)
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return
		}
		w = u.Unwrap()
	}
}

// allowListRefusal is the refusal for a candidate the upstream allow-list
// does not name. For the types whose rule is a package name the next step is
// the exact command; for the ones whose rule is a host or URL prefix it is
// not, because the candidate is an upstream URL and may carry a credential or
// an internal hostname. The operator reads it off the audit row instead.
func allowListRefusal(regType, candidate, name, version string) *refusal {
	f := newRefusal(checkAllowList, regType, name, version, http.StatusForbidden)
	switch regType {
	case manifest.TypeNpm, manifest.TypePypi, manifest.TypeCargo, manifest.TypeGomod:
		if f.name == "" {
			f.name = candidate
		}
		f.reason = fmt.Sprintf("%s %q is not on this server's upstream allow-list.", regType, candidate)
		f.next = fmt.Sprintf("ask an operator to run `bodega policy add %s %s` if it should be.", regType, candidate)
	default:
		f.reason = fmt.Sprintf("the upstream this %s request needs is not on this server's upstream allow-list.", regType)
		f.next = fmt.Sprintf("give an operator incident %s; its audit row names the upstream, and `bodega policy add %s <%s>` admits it.",
			f.incident, regType, policy.RuleKindForType(regType))
	}
	return f
}

// admitRefusal is the refusal for a manifest admission blocked by the
// allow-list, the age gate or the OSV gate. Its incident is the one admit
// wrote into the row it recorded.
func admitRefusal(typ, name string, res admitBlock) *refusal {
	var f *refusal
	switch res.check {
	case checkAge:
		f = ageRefusal(typ, name, res.version, res.details)
	case checkOSV:
		f = osvRefusal(typ, name, res.version, res.details)
	default:
		f = newRefusal(checkAllowList, typ, name, res.version, http.StatusForbidden)
		f.reason = fmt.Sprintf("%s %q is not on this server's upstream allow-list.", typ, name)
		f.next = fmt.Sprintf("`bodega policy add %s <%s>` admits it, then retry.", typ, policy.RuleKindForType(typ))
	}
	if res.incident != "" {
		f.incident = res.incident
	}
	return f
}

// admitBlock is the part of an admission verdict a refusal is built from.
type admitBlock struct {
	check    string
	version  string
	incident string
	details  map[string]any
}

// ageRefusal names when the version clears the gate, which is the one thing
// the person refused can plan around. d is the age check's own details.
func ageRefusal(typ, name, version string, d map[string]any) *refusal {
	f := newRefusal(checkAge, typ, name, version, http.StatusForbidden)
	published, _ := time.Parse(time.RFC3339, fmt.Sprint(d["published_at"]))
	minAge := time.Duration(anyInt64(d["min_age_seconds"])) * time.Second
	if published.IsZero() || minAge <= 0 {
		f.reason = "this version was published too recently for this server's minimum publish age."
		f.next = "pin an older version, or ask an operator about `bodega policy age list`."
		return f
	}
	f.reason = fmt.Sprintf("this version was published %s and this server holds new versions back for %s.",
		published.UTC().Format(time.DateOnly), policy.ShortDuration(minAge))
	f.next = fmt.Sprintf("the version becomes available on %s; pin an older version until then.",
		published.Add(minAge).UTC().Format(time.DateOnly))
	return f
}

// osvRefusal names the advisories by ID and nothing else from the check's
// details: the OSV reason string can carry the ecosystem query and a note
// about the local database, neither of which the client needs.
func osvRefusal(typ, name, version string, d map[string]any) *refusal {
	f := newRefusal(checkOSV, typ, name, version, http.StatusForbidden)
	var ids []string
	switch v := d["vulns"].(type) {
	case []string:
		ids = v
	case []any:
		for _, x := range v {
			ids = append(ids, fmt.Sprint(x))
		}
	}
	if len(ids) == 0 {
		f.reason = "this version has a known vulnerability record."
	} else {
		f.reason = "this version has known vulnerability records: " + strings.Join(ids, ", ") + "."
	}
	f.next = "pick a version without those records, or ask an operator to review `bodega policy osv list`."
	return f
}

func anyInt64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case float64:
		return int64(n)
	}
	return 0
}

func hiddenRefusal(typ, name, version string) *refusal {
	f := newRefusal(checkHidden, typ, name, version, http.StatusNotFound)
	f.reason = "an operator has hidden this " + hiddenWhat(version) + " on this server."
	cmd := "bodega pkg hide " + typ + " " + name
	if version != "" {
		cmd += " " + version
	}
	f.next = "ask an operator why; if it should be served again, `" + cmd + "` toggles the flag back."
	return f
}

func hiddenWhat(version string) string {
	if version != "" {
		return "version"
	}
	return "package"
}

func constraintRefusal(typ, name, version, constraint string) *refusal {
	f := newRefusal(checkConstraint, typ, name, version, http.StatusForbidden)
	f.reason = fmt.Sprintf("%s is outside the version_constraint %q this server holds %s to.", version, constraint, name)
	f.next = fmt.Sprintf("pick a version the constraint allows, or ask an operator to widen it with `bodega pkg edit %s %s`.", typ, name)
	return f
}

func frozenRefusal(typ, name string) *refusal {
	f := newRefusal(checkFrozen, typ, name, "", http.StatusForbidden)
	f.reason = "every version of this package is frozen, so it cannot be deleted."
	f.next = fmt.Sprintf("unfreeze it first with `bodega pkg freeze %s %s`, which toggles the flag.", typ, name)
	return f
}

// refuseHidden writes the row and answers a hidden package or version.
// 404 rather than 403, because hiding is quarantine: the version is withdrawn
// from this server, and a resolver should treat it as absent rather than as a
// fault to retry.
func (s *Server) refuseHidden(w http.ResponseWriter, r *http.Request, typ, name, version string) {
	f := hiddenRefusal(typ, name, version)
	recordDenialFor(s.auditDB, r, typ, name, version, audit.DenialHidden, map[string]string{"incident": f.incident})
	f.write(w, r)
}

// versionFromKey is the version a storage key names, for a refusal that has a
// key and nothing else to say which version was asked for. The key itself is
// never put in a body.
func versionFromKey(s3Key string) string {
	if s3Key == "" {
		return ""
	}
	_, _, v := manifest.ParseKey(s3Key)
	return v
}

// checksumMismatchError is verifyProxyChecksum's answer when the bytes
// disagree with the pinned digest, carrying the incident the mismatch row was
// written under so the refusal can hand the client the same one.
type checksumMismatchError struct {
	incident string
	msg      string
}

func (e *checksumMismatchError) Error() string { return e.msg }

// checksumRefusal answers 502, the status the gate has always answered: the
// fault is upstream's bytes, not the client's request. A digest that could
// not be read at all is refused the same way, under a fresh incident that
// only the server log carries, since the database that would hold the row is
// the thing that failed.
func checksumRefusal(regType, s3Key, name string, err error) *refusal {
	keyType, keyName, version := manifest.ParseKey(s3Key)
	typ := regType
	if typ == "" {
		typ = keyType
	}
	if name == "" {
		name = keyName
	}
	f := newRefusal(checkChecksum, typ, name, version, http.StatusBadGateway)
	var mm *checksumMismatchError
	if errors.As(err, &mm) {
		f.incident = mm.incident
		f.reason = "the bytes upstream served do not match the SHA-256 this server pinned on first fetch, so the upstream content may have been tampered with."
		f.next = fmt.Sprintf("do not route around it; give an operator incident %s, whose audit row holds both digests.", f.incident)
		return f
	}
	f.reason = "this server could not read the SHA-256 it pinned for this artifact, and it will not serve bytes it cannot verify."
	f.next = fmt.Sprintf("retry shortly; if it persists, give an operator incident %s from the server log.", f.incident)
	return f
}
