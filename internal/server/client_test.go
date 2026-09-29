package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/pkgrepos"
	"github.com/ravinald/bodega/internal/pkgsign"
)

// clientGet drives one /client/ request through the whole handler chain, so
// the identity middleware resolves the host the way it does in production.
func clientGet(t *testing.T, s *Server, token, path string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// clientProfile binds a host whose profile lists one pypi package and closes
// npm with nothing listed, so the plan carries both an install and a refusal.
func clientProfile(t *testing.T, s *Server) *profileFixture {
	t.Helper()
	return bindProfile(t, s, "web", "web-host",
		[]audit.ProfileTypeRule{
			closedRule(manifest.TypePypi, audit.VersionFloating, audit.ExpansionBlock),
			closedRule(manifest.TypeNpm, audit.VersionFloating, audit.ExpansionBlock),
		},
		[]audit.ProfileEntry{{Type: manifest.TypePypi, Name: "requests"}})
}

func planJSON(t *testing.T, s *Server, token, query string) []planRecord {
	t.Helper()
	code, body := clientGet(t, s, token, "/client/plan?"+query)
	if code != http.StatusOK {
		t.Fatalf("GET /client/plan?%s = %d: %s", query, code, body)
	}
	var out clientPlan
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("parse plan: %v\n%s", err, body)
	}
	return out.Records
}

func planRecordFor(records []planRecord, system string) []planRecord {
	var out []planRecord
	for _, r := range records {
		if r.System == system {
			out = append(out, r)
		}
	}
	return out
}

// Every /client/ route refuses a host no binding names, and the body gives the
// command that would admit it. A plan served to an unknown address would name
// the profiles and the paths this fleet uses.
func TestClientRoutesRefuseAnUnidentifiedHost(t *testing.T) {
	s := hostedServer(t)
	for _, path := range []string{"/client/plan?os=linux", "/client/plan.txt?os=linux", "/client/pypi?os=linux"} {
		code, body := clientGet(t, s, "", path)
		if code != http.StatusForbidden {
			t.Errorf("GET %s from an unbound host = %d, want 403", path, code)
		}
		if !strings.Contains(body, "bodega identity bind cidr 192.0.2.1/32") {
			t.Errorf("GET %s: the refusal does not name the binding that admits this host:\n%s", path, body)
		}
	}
	rows, err := s.auditDB.Query(context.Background(), audit.Filter{EventType: audit.EventDenied})
	if err != nil {
		t.Fatalf("query denials: %v", err)
	}
	n := 0
	for _, r := range rows {
		if r.Status == audit.DenialClientUnidentified && r.PkgType == "client" {
			n++
		}
	}
	if n != 3 {
		t.Errorf("client_unidentified rows = %d, want one per refused request: %+v", n, rows)
	}
}

// The plan needs the host's operating system, which the server cannot see.
func TestClientPlanRefusesAMissingOrUnknownOS(t *testing.T) {
	s := hostedServer(t)
	f := clientProfile(t, s)
	for _, q := range []string{"", "os=windows"} {
		code, body := clientGet(t, s, f.token, "/client/plan?"+q)
		if code != http.StatusBadRequest || !strings.Contains(body, "linux") || !strings.Contains(body, "freebsd") {
			t.Errorf("GET /client/plan?%s = %d %q, want 400 naming linux and freebsd", q, code, body)
		}
	}
}

// The plan names the host, its profile and the binding that matched, lists
// every system, and states a system the profile excludes as a refusal.
func TestClientPlanListsEverySystemAndRefusesWhatTheProfileExcludes(t *testing.T) {
	s := hostedServer(t)
	s.cfg.PublicURL = "https://bodega.internal"
	f := clientProfile(t, s)

	records := planJSON(t, s, f.token, "os=linux")
	for _, sys := range manifest.AllTypes {
		if len(planRecordFor(records, sys)) == 0 {
			t.Errorf("the plan has no record for %s", sys)
		}
	}
	for _, r := range records {
		if r.Identity != "web-host" || r.Profile != "web" || r.Match != "token:tok-web" {
			t.Fatalf("record %+v, want identity web-host, profile web, match token:tok-web", r)
		}
	}

	npm := planRecordFor(records, manifest.TypeNpm)
	if len(npm) != 1 || npm[0].Action != planRefuse || !strings.Contains(npm[0].Reason, `profile "web" is closed for npm`) {
		t.Errorf("npm = %+v, want one refusal naming the profile's rule", npm)
	}
	code, body := clientGet(t, s, f.token, "/client/npm?os=linux")
	if code != http.StatusForbidden || !strings.Contains(body, "closed for npm") {
		t.Errorf("GET /client/npm = %d %q, want 403 with the profile's reason", code, body)
	}
	profileDenial(t, s, audit.DenialClientExcluded)

	pypi := planRecordFor(records, manifest.TypePypi)
	want := clientconf.Pip("https://bodega.internal")
	if len(pypi) != 1 || pypi[0].Action != planInstall || pypi[0].Path != want.Path(clientconf.OSLinux) {
		t.Fatalf("pypi = %+v, want one install at %s", pypi, want.Path(clientconf.OSLinux))
	}
	if pypi[0].URL != "https://bodega.internal/client/pypi?os=linux" {
		t.Errorf("pypi url = %q", pypi[0].URL)
	}
	code, body = clientGet(t, s, f.token, "/client/pypi?os=linux")
	sum := sha256.Sum256([]byte(body))
	if code != http.StatusOK || body != want.Content || hex.EncodeToString(sum[:]) != pypi[0].SHA256 {
		t.Errorf("GET /client/pypi = %d %q, want the clientconf rendering whose SHA-256 the plan names", code, body)
	}

	for _, sys := range []string{manifest.TypeFreeBSD, manifest.TypeDistfiles, manifest.TypeBinary} {
		rec := planRecordFor(records, sys)
		if len(rec) != 1 || rec[0].Action != planSkip || rec[0].Reason == "" {
			t.Errorf("%s on linux = %+v, want one skip with a reason", sys, rec)
		}
	}
}

// plan.txt and the JSON plan are one set of records. The text side is read
// the way the served setup script reads it, by sh with IFS set to a tab, and
// decoded by the documented rule in sh itself, so a field that collapses,
// shifts or decodes to something else fails here rather than on a host.
//
// The hosts cover the values the empty-field marker could collide with: a
// profile literally named "-", a host with no profile at all, and an identity
// holding a tab, a backslash and the literal-dash escape.
func TestClientPlanTextAndJSONCarryIdenticalRecords(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh on PATH")
	}
	ctx := context.Background()
	s := hostedServer(t)
	s.cfg.PublicURL = "https://bodega.internal"
	f := clientProfile(t, s)
	dash := bindProfile(t, s, "-", "dash-host", nil, nil)
	odd := bindProfile(t, s, "odd", "a\tb\\c\\0055-", nil, nil)
	if err := s.auditDB.InsertToken(ctx, "tok-bare", "bare", audit.HashToken("bodega_ak_bare", s.pepper), "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.auditDB.AddIdentityBinding(ctx, audit.IdentityBinding{Kind: audit.BindToken, Key: "tok-bare", Identity: "bare-host"}); err != nil {
		t.Fatal(err)
	}
	s.refreshIdentities(ctx)

	loop := `tab=$(printf '\t')
dec() { case $1 in -) v= ;; *\\*) v=$(printf '%bx' "$1"); v=${v%x} ;; *) v=$1 ;; esac; }
while IFS=$tab read -r identity profile match system action path url sha256 reason; do
  for f in "$identity" "$profile" "$match" "$system" "$action" "$path" "$url" "$sha256" "$reason"; do
    dec "$f"; printf '%s\037' "$v"
  done
  printf '\036'
done`
	for _, host := range []struct{ name, token, profile string }{
		{"web-host", f.token, "web"},
		{"dash-host", dash.token, "-"},
		{"a\tb\\c\\0055-", odd.token, "odd"},
		{"bare-host", "bodega_ak_bare", ""},
	} {
		for _, q := range []string{"os=linux", "os=freebsd&abi=" + freeBSDABI} {
			records := planJSON(t, s, host.token, q)
			if records[0].Identity != host.name || records[0].Profile != host.profile {
				t.Fatalf("%s: JSON identity %q profile %q, want %q %q", host.name, records[0].Identity, records[0].Profile, host.name, host.profile)
			}
			code, text := clientGet(t, s, host.token, "/client/plan.txt?"+q)
			if code != http.StatusOK {
				t.Fatalf("GET /client/plan.txt?%s = %d: %s", q, code, text)
			}
			cmd := exec.Command(sh, "-c", loop)
			cmd.Stdin = strings.NewReader(text)
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("sh read loop: %v", err)
			}
			var fromText []planRecord
			for _, line := range strings.Split(strings.TrimSuffix(string(out), "\036"), "\036") {
				fs := strings.Split(strings.TrimSuffix(line, "\037"), "\037")
				if len(fs) != len(planColumns) {
					t.Fatalf("sh read %d fields from %q, want %d", len(fs), line, len(planColumns))
				}
				fromText = append(fromText, planRecord{Identity: fs[0], Profile: fs[1], Match: fs[2], System: fs[3], Action: fs[4], Path: fs[5], URL: fs[6], SHA256: fs[7], Reason: fs[8]})
			}
			if len(fromText) != len(records) {
				t.Fatalf("%s %s: plan.txt has %d records, the JSON plan %d", host.name, q, len(fromText), len(records))
			}
			for i := range records {
				if fromText[i] != records[i] {
					t.Errorf("%s %s record %d:\n text %+v\n json %+v", host.name, q, i, fromText[i], records[i])
				}
			}
		}
	}
}

// A profile named "-" and no profile at all are two plan.txt lines, not one.
func TestClientPlanTextTellsALiteralDashFromEmpty(t *testing.T) {
	for in, want := range map[string]string{"": "-", "-": `\0055`, "--": "--", `\-`: `\\-`, "a\tb\nc\r": `a\tb\nc\r`} {
		if got := planTSVField(in); got != want {
			t.Errorf("planTSVField(%q) = %q, want %q", in, got, want)
		}
	}
}

// A CIDR-bound host sends no credential, and the plan says so by naming the
// prefix that matched.
func TestClientPlanNamesTheCIDRThatMatched(t *testing.T) {
	s := hostedServer(t)
	bindProfileByCIDR(t, s, "lab", "lab-host", "192.0.2.0/24", nil, nil)
	records := planJSON(t, s, "", "os=linux")
	if len(records) == 0 || records[0].Match != "cidr:192.0.2.0/24" || records[0].Identity != "lab-host" {
		t.Fatalf("records = %+v, want identity lab-host matched by cidr:192.0.2.0/24", records)
	}
}

// The FreeBSD file is the profile's filtered view for a bound host: the conf
// /client/freebsd serves points at the catalogue built for its profile.
func TestClientFreeBSDFileIsTheProfileView(t *testing.T) {
	installPkgKey(t, pkgsign.KeyRSA)
	s := proxyingServer(t)
	s.loadPkgSigner()
	addVersion(t, s, manifest.TypeFreeBSD, "latest", manifest.VersionEntry{
		Version: freeBSDABI, URL: "https://pkg.example.org/" + freeBSDABI + "/latest", Mode: manifest.ModeProxy,
	})
	f := webProfile(t, s)

	q := "os=freebsd&abi=" + freeBSDABI
	rec := planRecordFor(planJSON(t, s, f.token, q), manifest.TypeFreeBSD)
	if len(rec) != 1 || rec[0].Action != planInstall || rec[0].Path != pkgrepos.ClientConfPath {
		t.Fatalf("freebsd = %+v, want one install at %s", rec, pkgrepos.ClientConfPath)
	}
	code, body := clientGet(t, s, f.token, "/client/freebsd?"+q)
	if code != http.StatusOK || !strings.Contains(body, pkgrepos.ProfilePath("web")+"/${ABI}/latest") {
		t.Errorf("GET /client/freebsd = %d, want the web profile's view:\n%s", code, body)
	}

	code, body = clientGet(t, s, f.token, "/client/freebsd?os=freebsd&abi=FreeBSD:13:amd64")
	if code != http.StatusNotFound || !strings.Contains(body, freeBSDABI) {
		t.Errorf("GET /client/freebsd for an ABI nothing serves = %d %q, want 404 naming what is served", code, body)
	}
}

// Every /client/ response lands in the audit trail: a served plan as the
// serve_fetch row a package download writes, naming the host.
func TestClientPlanIsAudited(t *testing.T) {
	s := hostedServer(t)
	f := clientProfile(t, s)
	planJSON(t, s, f.token, "os=linux")
	clientGet(t, s, f.token, "/client/plan.txt?os=linux")
	clientGet(t, s, f.token, "/client/apt?os=freebsd")

	rows, err := s.auditDB.Query(context.Background(), audit.Filter{EventType: audit.EventServeFetch, PkgType: "client"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	got := map[string]string{}
	for _, r := range rows {
		if r.Identity != "web-host" || r.PkgVersion == "" {
			t.Errorf("row %+v, want identity web-host and the stated os", r)
		}
		got[r.PkgName] = r.Status
	}
	if got["plan"] != "success" || got["plan.txt"] != "success" || got["apt"] != "failure" {
		t.Errorf("client rows by subject = %v, want plan and plan.txt success, apt failure", got)
	}
}

// The plan reports the binding IdentityMiddleware resolved, not one a second
// lookup finds after the table reloaded: the profile came from the first, so
// the rule named beside it has to as well.
func TestClientPlanKeepsTheBindingAcrossAReload(t *testing.T) {
	for name, reload := range map[string]*identitySet{
		"removed":  newIdentitySet(nil, nil),
		"rebound":  newIdentitySet([]audit.IdentityBinding{{Kind: audit.BindCIDR, Key: "192.0.2.0/24", Identity: "web-host"}}, nil),
		"reissued": newIdentitySet([]audit.IdentityBinding{{Kind: audit.BindCIDR, Key: "192.0.2.0/24", Identity: "other-host"}}, nil),
	} {
		t.Run(name, func(t *testing.T) {
			s := hostedServer(t)
			f := clientProfile(t, s)
			h := IdentityMiddleware(func(r *http.Request) identityMatch {
				m := s.identityMatchFor(r)
				s.storeIdentities(reload)
				return m
			})(s.mux)
			req := httptest.NewRequest(http.MethodGet, "/client/plan?os=linux", nil)
			req.Header.Set("Authorization", "Bearer "+f.token)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			var plan clientPlan
			if err := json.Unmarshal(rec.Body.Bytes(), &plan); err != nil || rec.Code != http.StatusOK || len(plan.Records) == 0 {
				t.Fatalf("GET /client/plan = %d %s", rec.Code, rec.Body.String())
			}
			r := plan.Records[0]
			if r.Identity != "web-host" || r.Profile != "web" || r.Match != "token:tok-web" {
				t.Errorf("record %+v, want web-host, profile web, token:tok-web: the resolution the middleware made", r)
			}
		})
	}
}

// An unbound host learns the command that admits it and nothing else: not
// which os values this server takes, not which system names exist.
// An identified host still gets the specific 400 or 404.
func TestClientAdmissionPrecedesValidation(t *testing.T) {
	s := hostedServer(t)
	f := clientProfile(t, s)
	for _, path := range []string{
		"/client/plan", "/client/plan?os=macos", "/client/plan?os=linux&abi=%21", "/client/plan?os=linux&codename=NOBLE",
		"/client/plan.txt", "/client/plan.txt?os=macos", "/client/plan.txt?os=freebsd&abi=%21",
		"/client/pypi", "/client/pypi?os=macos", "/client/pypi?os=linux&abi=%21", "/client/unknown?os=linux", "/client/unknown",
	} {
		code, body := clientGet(t, s, "", path)
		if code != http.StatusForbidden || !strings.Contains(body, "bodega identity bind") || strings.Contains(body, "Accepted") || strings.Contains(body, "Systems:") {
			t.Errorf("unbound GET %s = %d %q, want 403 naming the identity command alone", path, code, body)
		}
	}
	for path, want := range map[string]int{
		"/client/plan": http.StatusBadRequest, "/client/plan.txt?os=macos": http.StatusBadRequest,
		"/client/pypi?os=linux&abi=%21": http.StatusBadRequest, "/client/unknown?os=linux": http.StatusNotFound,
	} {
		if code, body := clientGet(t, s, f.token, path); code != want {
			t.Errorf("identified GET %s = %d %q, want %d", path, code, body, want)
		}
	}
}

// Every /client/ response writes exactly one fetch or denial row, whoever
// answered it: a handler, the mux, the mutation gate or the deny list. None
// of them carries the credential the request sent.
func TestClientEveryResponseIsAuditedOnce(t *testing.T) {
	cases := []struct {
		method, path string
		token, deny  bool
		status       int
	}{
		{"GET", "/client/plan?os=linux", true, false, http.StatusOK},
		{"GET", "/client/plan.txt?os=linux", true, false, http.StatusOK},
		{"GET", "/client/pypi?os=linux", true, false, http.StatusOK},
		{"GET", "/client/plan", true, false, http.StatusBadRequest},
		{"GET", "/client/npm?os=linux", true, false, http.StatusForbidden},
		{"GET", "/client/plan?os=linux", false, false, http.StatusForbidden},
		{"GET", "/client/unknown?os=linux", true, false, http.StatusNotFound},
		{"GET", "/client/apt?os=freebsd", true, false, http.StatusNotFound},
		{"PUT", "/client/plan?os=linux", true, false, http.StatusMethodNotAllowed},
		{"OPTIONS", "/client/pypi?os=linux", true, false, http.StatusMethodNotAllowed},
		{"GET", "/client/plan/?os=linux", true, false, http.StatusNotFound},
		{"GET", "/client//plan?os=linux", true, false, http.StatusTemporaryRedirect},
		{"POST", "/client/plan?os=linux", true, false, http.StatusForbidden},
		{"GET", "/client/plan?os=linux", true, true, http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s %s token=%t deny=%t", c.method, c.path, c.token, c.deny), func(t *testing.T) {
			ctx := context.Background()
			s := hostedServer(t)
			f := clientProfile(t, s)
			if c.deny {
				if _, err := s.auditDB.SeedACL(ctx, audit.ACLDeny, []string{"192.0.2.0/24"}, ""); err != nil {
					t.Fatal(err)
				}
				s.refreshACLs(ctx)
			}
			req := httptest.NewRequest(c.method, c.path, nil)
			if c.token {
				req.Header.Set("Authorization", "Bearer "+f.token)
			}
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, req)
			if rec.Code != c.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, c.status, rec.Body.String())
			}
			rows, err := s.auditDB.Query(ctx, audit.Filter{})
			if err != nil {
				t.Fatal(err)
			}
			n := 0
			for _, row := range rows {
				if row.EventType != audit.EventServeFetch && row.EventType != audit.EventDenied {
					continue
				}
				n++
				if strings.Contains(fmt.Sprintf("%+v", row), f.token) {
					t.Errorf("row carries the credential: %+v", row)
				}
			}
			if n != 1 {
				t.Errorf("fetch/denial rows = %d, want 1: %+v", n, rows)
			}
		})
	}
}

// clientDo is clientGet for any method, returning the audit rows the one
// response wrote.
func clientDo(t *testing.T, s *Server, token, method, path string) (*httptest.ResponseRecorder, []audit.StoredEvent) {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	rows, err := s.auditDB.Query(context.Background(), audit.Filter{})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	var out []audit.StoredEvent
	for _, row := range rows {
		if row.EventType == audit.EventServeFetch || row.EventType == audit.EventDenied {
			out = append(out, row)
		}
	}
	return rec, out
}

// Admission is decided before the mutation gate and the router, so no
// response they give first can stand in for the command that admits the host.
func TestClientAdmissionPrecedesTheRouter(t *testing.T) {
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/client/plan?os=linux"},
		{http.MethodGet, "/client/plan.txt?os=linux"},
		{http.MethodGet, "/client/pypi?os=linux"},
		{http.MethodGet, "/client/plan/?os=linux"},
		{http.MethodGet, "/client//plan?os=linux"},
		{http.MethodGet, "/client/"},
		{http.MethodGet, "/client"},
		{http.MethodOptions, "/client/plan?os=linux"},
		{http.MethodHead, "/client/plan?os=linux"},
		{http.MethodPost, "/client/plan?os=linux"},
		{http.MethodDelete, "/client/pypi?os=linux"},
	} {
		t.Run(c.method+c.path, func(t *testing.T) {
			s := hostedServer(t)
			rec, rows := clientDo(t, s, "", c.method, c.path)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403: %q", rec.Code, rec.Body.String())
			}
			if c.method != http.MethodHead && !strings.Contains(rec.Body.String(), "bodega identity bind cidr 192.0.2.1/32") {
				t.Errorf("the refusal does not name the binding that admits this host:\n%s", rec.Body.String())
			}
			if len(rows) != 1 || rows[0].Status != audit.DenialClientUnidentified {
				t.Errorf("audit rows = %+v, want one client_unidentified denial", rows)
			}
		})
	}
}

// An identified host still sees what the router says about a request it
// cannot serve.
func TestClientRouterAnswersAnIdentifiedHost(t *testing.T) {
	for _, c := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/client/plan/?os=linux", http.StatusNotFound},
		{http.MethodGet, "/client//plan?os=linux", http.StatusTemporaryRedirect},
		{http.MethodOptions, "/client/plan?os=linux", http.StatusMethodNotAllowed},
		{http.MethodGet, "/client/plan", http.StatusBadRequest},
	} {
		t.Run(c.method+c.path, func(t *testing.T) {
			s := hostedServer(t)
			f := clientProfile(t, s)
			rec, rows := clientDo(t, s, f.token, c.method, c.path)
			if rec.Code != c.want {
				t.Errorf("status = %d, want %d: %q", rec.Code, c.want, rec.Body.String())
			}
			if len(rows) != 1 {
				t.Errorf("audit rows = %d, want 1: %+v", len(rows), rows)
			}
		})
	}
}

// The deny list answers before identity is resolved, and on /client/ says
// which entry refused the host and the command that removes it.
func TestClientDenyListNamesTheACLCommand(t *testing.T) {
	for _, path := range []string{"/client/plan?os=linux", "/client/plan.txt?os=linux", "/client/pypi?os=linux"} {
		t.Run(path, func(t *testing.T) {
			s := hostedServer(t)
			f := clientProfile(t, s)
			if _, err := s.auditDB.SeedACL(context.Background(), audit.ACLDeny, []string{"192.0.2.0/24"}, ""); err != nil {
				t.Fatalf("add deny entry: %v", err)
			}
			s.refreshACLs(context.Background())
			for _, token := range []string{"", f.token} {
				rec, _ := clientDo(t, s, token, http.MethodGet, path)
				if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "bodega acl deny remove 192.0.2.0/24") {
					t.Errorf("token=%t: status=%d body=%q; want 403 naming the deny entry", token != "", rec.Code, rec.Body.String())
				}
			}
			rows, err := s.auditDB.Query(context.Background(), audit.Filter{EventType: audit.EventDenied})
			if err != nil {
				t.Fatalf("query denials: %v", err)
			}
			if len(rows) != 2 || rows[0].Status != audit.DenialDenyList || rows[1].Status != audit.DenialDenyList {
				t.Errorf("denial rows = %+v, want one deny_list row per request", rows)
			}
		})
	}
}

// The subject a row records is whatever the caller put in the path, so it is
// bounded whether a handler or the admission refusal supplied it.
func TestClientAuditSubjectIsBounded(t *testing.T) {
	long := strings.Repeat("x", 65536)
	for _, bound := range []bool{false, true} {
		t.Run(fmt.Sprintf("identified=%t", bound), func(t *testing.T) {
			s := hostedServer(t)
			token := ""
			if bound {
				token = clientProfile(t, s).token
			}
			rec, rows := clientDo(t, s, token, http.MethodGet, "/client/"+long+"?os=linux")
			want := http.StatusForbidden
			if bound {
				want = http.StatusNotFound
			}
			if rec.Code != want {
				t.Errorf("status = %d, want %d", rec.Code, want)
			}
			if len(rows) != 1 {
				t.Fatalf("audit rows = %d, want 1", len(rows))
			}
			if n := len(rows[0].PkgName); n > maxClientSubject+len("…") {
				t.Errorf("pkg_name is %d bytes, want at most %d", n, maxClientSubject+len("…"))
			}
		})
	}
	s := hostedServer(t)
	f := clientProfile(t, s)
	_, rows := clientDo(t, s, f.token, http.MethodGet, "/client/distfiles?os=freebsd")
	if len(rows) != 1 || rows[0].PkgName != "distfiles" {
		t.Errorf("a known system name must reach the row intact: %+v", rows)
	}
}

// The script's digest is published in two places an operator checks it
// against, and both have to be the digest of the bytes the route serves. A
// script edit that forgets docs/usage.md fails here rather than at a host
// whose operator was told the published digest is the one to trust.
func TestClientSetupScriptDigestIsPublished(t *testing.T) {
	s := hostedServer(t)
	f := clientProfile(t, s)

	code, body := clientGet(t, s, f.token, "/client/setup.sh")
	if code != http.StatusOK || body != string(clientSetupScript) || !strings.HasPrefix(body, "#!/bin/sh\n") {
		t.Fatalf("GET /client/setup.sh = %d, want the embedded script:\n%.200s", code, body)
	}
	sum := sha256.Sum256([]byte(body))
	served := hex.EncodeToString(sum[:])

	_, status := clientGet(t, s, f.token, "/api/v1/status")
	var st statusResponse
	if err := json.Unmarshal([]byte(status), &st); err != nil {
		t.Fatalf("parse status: %v", err)
	}
	if st.ClientSetupSHA256 != served {
		t.Errorf("/api/v1/status client_setup_sha256 = %q, want %s", st.ClientSetupSHA256, served)
	}

	usage, err := os.ReadFile("../../docs/usage.md")
	if err != nil {
		t.Fatalf("read docs/usage.md: %v", err)
	}
	if !strings.Contains(string(usage), "SHA-256 `"+served+"`") {
		t.Errorf("docs/usage.md does not publish the served script's digest. Write it as SHA-256 `%s`", served)
	}

	if code, _ := clientGet(t, s, "", "/client/setup.sh"); code != http.StatusForbidden {
		t.Errorf("GET /client/setup.sh from an unbound host = %d, want 403 like every /client/ route", code)
	}
}

// The script is POSIX sh, and it is the one file a host runs as root on the
// strength of a digest. Where shellcheck is installed it is held to -s sh.
func TestClientSetupScriptIsPOSIX(t *testing.T) {
	if _, err := exec.LookPath("shellcheck"); err != nil {
		t.Skip("shellcheck not installed; make harness runs it")
	}
	out, err := exec.Command("shellcheck", "-s", "sh", "client_setup.sh").CombinedOutput()
	if err != nil {
		t.Errorf("shellcheck -s sh client_setup.sh: %v\n%s", err, out)
	}
}

// release re-renders the pkg overrides for another major release, so a host
// running 14 against a repository named for 15 disables its own tags.
func TestClientPlanReleaseRerendersTheFreeBSDOverrides(t *testing.T) {
	installPkgKey(t, pkgsign.KeyRSA)
	s := proxyingServer(t)
	s.loadPkgSigner()
	addVersion(t, s, manifest.TypeFreeBSD, "latest", manifest.VersionEntry{
		Version: freeBSDABI, URL: "https://pkg.example.org/" + freeBSDABI + "/latest", Mode: manifest.ModeProxy,
	})
	f := webProfile(t, s)
	q := "os=freebsd&abi=" + freeBSDABI

	own := planRecordFor(planJSON(t, s, f.token, q), manifest.TypeFreeBSD)
	other := planRecordFor(planJSON(t, s, f.token, q+"&release=13"), manifest.TypeFreeBSD)
	if len(own) != 1 || len(other) != 1 || other[0].Action != planInstall {
		t.Fatalf("freebsd records = %+v / %+v, want one install each", own, other)
	}
	if own[0].SHA256 == other[0].SHA256 || !strings.Contains(other[0].URL, "release=13") {
		t.Errorf("release=13 record = %+v, want a different file served at a URL carrying release=13", other[0])
	}
	code, body := clientGet(t, s, f.token, "/client/freebsd?"+q+"&release=13")
	sum := sha256.Sum256([]byte(body))
	if code != http.StatusOK || hex.EncodeToString(sum[:]) != other[0].SHA256 {
		t.Errorf("GET /client/freebsd?...&release=13 = %d, and its digest does not match the plan's", code)
	}
	for _, bad := range []string{"0", "fifteen", "100"} {
		if code, body := clientGet(t, s, f.token, "/client/plan?"+q+"&release="+bad); code != http.StatusBadRequest || !strings.Contains(body, "major release") {
			t.Errorf("release=%s = %d %q, want 400 naming a major release", bad, code, body)
		}
	}
}
