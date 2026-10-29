package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ravinald/bodega/internal/aptsign"
	"github.com/ravinald/bodega/internal/aptsources"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/config"
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

// The npm plan is .npmrc plus, for an open nodejs.org namespace, the file
// setting NODEJS_ORG_MIRROR: profile.d under root=1, the user's environment.d
// file otherwise. A catalog namespace or a FreeBSD user gets the registry
// line alone and a note on its record. Every file the plan names is served
// at its URL with bytes its digest covers, and no file carries disturl.
func TestClientPlanNpmPointsNodeGypThroughNodeMirror(t *testing.T) {
	const registry = "registry=https://bodega.internal/npm/\n"
	open := map[string]config.BinaryUpstream{"node": {URL: "https://nodejs.org/", Mode: config.UpstreamModeOpen}}
	for _, tc := range []struct {
		name      string
		upstreams map[string]config.BinaryUpstream
		query     string
		want      map[string]string
		note      string
	}{
		{"open namespace, user", open, "os=linux",
			map[string]string{"~/.npmrc": registry, clientconf.NodeMirrorUserPath: "NODEJS_ORG_MIRROR=https://bodega.internal/binaries/node/dist\n"}, ""},
		{"open namespace, root", open, "os=linux&root=1",
			map[string]string{"~/.npmrc": registry, clientconf.NodeMirrorSystemPath: "export NODEJS_ORG_MIRROR='https://bodega.internal/binaries/node/dist'\n"}, ""},
		{"open namespace, freebsd root", open, "os=freebsd&root=1",
			map[string]string{"~/.npmrc": registry, clientconf.NodeMirrorSystemPath: "export NODEJS_ORG_MIRROR='https://bodega.internal/binaries/node/dist'\n"}, ""},
		{"open namespace, freebsd user", open, "os=freebsd",
			map[string]string{"~/.npmrc": registry}, "nothing on freebsd reads a per-user environment file"},
		{"catalog namespace", map[string]config.BinaryUpstream{"node": {URL: "https://nodejs.org/", Mode: config.UpstreamModeCatalog}}, "os=linux",
			map[string]string{"~/.npmrc": registry}, `binary_upstreams["node"] is in catalog mode`},
		{"no namespace", nil, "os=linux", map[string]string{"~/.npmrc": registry}, ""},
		{"other host", map[string]config.BinaryUpstream{"node": {URL: "https://mirror.example.com/", Mode: config.UpstreamModeOpen}}, "os=linux",
			map[string]string{"~/.npmrc": registry}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := hostedServer(t)
			s.cfg.PublicURL = "https://bodega.internal"
			s.cfg.BinaryUpstreams = tc.upstreams
			f := bindProfile(t, s, "open", "open-host", nil, nil)
			recs := planRecordFor(planJSON(t, s, f.token, tc.query), manifest.TypeNpm)
			if len(recs) != len(tc.want) {
				t.Fatalf("npm records = %+v, want %d", recs, len(tc.want))
			}
			if (tc.note == "") != (recs[0].Reason == "") || !strings.Contains(recs[0].Reason, tc.note) {
				t.Errorf(".npmrc reason = %q, want one holding %q", recs[0].Reason, tc.note)
			}
			for _, rec := range recs {
				want, ok := tc.want[rec.Path]
				if rec.Action != clientconf.PlanInstall || !ok {
					t.Fatalf("record %+v, want an install at one of %v", rec, tc.want)
				}
				u, err := url.Parse(rec.URL)
				if err != nil {
					t.Fatal(err)
				}
				code, body := clientGet(t, s, f.token, u.RequestURI())
				if code != http.StatusOK || body != want || strings.Contains(body, "disturl") {
					t.Fatalf("GET %s = %d %q, want %q", u.RequestURI(), code, body, want)
				}
				if _, err := clientconf.NewChange(rec, []byte(body), t.TempDir()); err != nil {
					t.Errorf("NewChange refused the served file: %v", err)
				}
			}
		})
	}
}

// A host E21 configured holds a disturl line in ~/.npmrc. The next apply of
// the npm plan drops it, keeps the credential, backs up the old file, and
// writes the environment file in its place.
func TestClientPlanNpmRemovesAnE21Disturl(t *testing.T) {
	s := hostedServer(t)
	s.cfg.PublicURL = "https://bodega.internal"
	s.cfg.BinaryUpstreams = map[string]config.BinaryUpstream{"node": {URL: "https://nodejs.org/", Mode: config.UpstreamModeOpen}}
	f := bindProfile(t, s, "open", "open-host", nil, nil)
	home := t.TempDir()
	old := "registry=https://bodega.internal/npm/\ndisturl=https://bodega.internal/binaries/node/dist\n//bodega.internal/npm/:_authToken=bodega_ak_npm\n" //nolint:gosec // G101: fixture token
	if err := os.WriteFile(home+"/.npmrc", []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	var changes []clientconf.Change
	for _, rec := range planRecordFor(planJSON(t, s, f.token, "os=linux"), manifest.TypeNpm) {
		u, _ := url.Parse(rec.URL)
		_, body := clientGet(t, s, f.token, u.RequestURI())
		c, err := clientconf.NewChange(rec, []byte(body), home)
		if err != nil {
			t.Fatal(err)
		}
		changes = append(changes, c)
	}
	if _, err := clientconf.Apply(changes, ".bodega-test"); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(home + "/.npmrc"); string(got) != "registry=https://bodega.internal/npm/\n//bodega.internal/npm/:_authToken=bodega_ak_npm\n" {
		t.Errorf(".npmrc after apply = %q, want the registry line and the credential", got)
	}
	if got, _ := os.ReadFile(home + "/.npmrc.bodega-test"); string(got) != old {
		t.Errorf("backup = %q, want the E21 file %q", got, old)
	}
	if got, _ := os.ReadFile(home + "/.config/environment.d/60-bodega-node.conf"); string(got) != "NODEJS_ORG_MIRROR=https://bodega.internal/binaries/node/dist\n" {
		t.Errorf("environment.d file = %q", got)
	}
}

// file= and root= are validated like every other host fact, and the mirror
// file is npm's alone.
func TestClientNodeMirrorRouteRefusals(t *testing.T) {
	s := hostedServer(t)
	s.cfg.BinaryUpstreams = map[string]config.BinaryUpstream{"node": {URL: "https://nodejs.org/", Mode: config.UpstreamModeOpen}}
	f := bindProfile(t, s, "open", "open-host", nil, nil)
	for path, want := range map[string]int{
		"/client/npm?os=linux&file=other":         http.StatusBadRequest,
		"/client/npm?os=linux&root=yes":           http.StatusBadRequest,
		"/client/pypi?os=linux&file=node-mirror":  http.StatusBadRequest,
		"/client/npm?os=freebsd&file=node-mirror": http.StatusNotFound,
		"/client/npm?os=linux&file=node-mirror":   http.StatusOK,
	} {
		if code, body := clientGet(t, s, f.token, path); code != want {
			t.Errorf("GET %s = %d %q, want %d", path, code, body, want)
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

// redactCases is every line the setup script's diff redacts or must leave
// alone. Redact and the script's awk redact() are two implementations kept in
// step by hand, so both run over this one table.
var redactCases = []struct{ in, want string }{ //nolint:gosec // G101: fixture secrets the test asserts are redacted
	{"registry=https://h/npm/", ""},
	{"  url: https://h/helm?a=b", ""},
	{"\tinsteadOf = https://github.com/", ""},
	{"MASTER_SITE_OVERRIDE?= https://h/distfiles/", ""},
	{"password:", ""},
	{"  pass_credentials_all: false", ""},
	{"//h:8080/npm/:_authToken=t", "//h:8080/npm/:_authToken=<redacted>"},
	{"  password:   t", "  password:   <redacted>"},
	{"- password: t", "- password: <redacted>"},
	{"token = \"t\"", "token = <redacted>"},
	{"x = https://u:p@h/ and ://a:b:c@d", "x = https://<redacted>@h/ and ://a:<redacted>@d"},
	{"\turl = https://user:pass@h/o/r", "\turl = https://<redacted>@h/o/r"},
	{"\turl = https://ghp_tok:@github.com/o/r", "\turl = https://<redacted>@github.com/o/r"},
	{"\turl = https://:ghp_tok@github.com/o/r", "\turl = https://<redacted>@github.com/o/r"},
	{"\turl = https://ghp_tok:x-oauth-basic@github.com/o/r", "\turl = https://<redacted>@github.com/o/r"},
	{"\turl = https://u:p@ss@h/o/r", "\turl = https://<redacted>@h/o/r"},
	{"\turl = ssh://git:p@h/o/r", "\turl = ssh://git:<redacted>@h/o/r"},
	{"\turl = https://github.com/o/r", ""},

	{`[url "https://ghp_SECRETONLYUSER@github.com/"]`, `[url "https://<redacted>@github.com/"]`},
	{"index-url = HTTP://tok@h/simple/ git+https://t2@g/r", "index-url = HTTP://<redacted>@h/simple/ git+https://<redacted>@g/r"},
	{"\turl = ssh://git@github.com/o/r", ""},
	{"\turl = git@github.com:o/r", ""},
	{"https://h/path@v1 https://h?q=a@b", ""},

	{"\textraHeader = Authorization: Bearer SECRETBEARER", "\textraHeader = Authorization: Bearer <redacted>"},
	{"\textraheader = authorization: Basic dXNlcjpwYXNz", "\textraheader = authorization: Basic <redacted>"},
	{"Authorization: SECRETNOSCHEME", "Authorization: <redacted>"},
	{"  - \"Proxy-Authorization:  Bearer  a b\"", "  - \"Proxy-Authorization:  Bearer  <redacted>"},
	{"Authorization:", ""},

	{"api_key = SECRETAPIKEY", "api_key = <redacted>"},
	{"ACCESS_KEY: k", "ACCESS_KEY: <redacted>"},
	{"apikey = k", "apikey = <redacted>"},
	{"ApiKey: k", "ApiKey: <redacted>"},
	{"keyring = /etc/keyring", ""},
	{"monkey: business", ""},
	{"keys = a,b", ""},
	{"apikeys = a", ""},

	{"      <password>SECRETXML</password>", "      <password><redacted></password>"},
	{"<server><id>corp</id><Passphrase>k</Passphrase></server>", "<server><id>corp</id><Passphrase><redacted></Passphrase></server>"},
	{"<s:password>p</s:password> <apiKey>k</apiKey>", "<s:password><redacted></s:password> <apiKey><redacted></apiKey>"},
	{"<password>a</passwd>", ""},
	{"<id>password</id> <url>https://h/maven/</url> <password/>", ""},
}

// Every row must come out of Redact and of the script's redact() the same,
// and as the row says. The awk runs under this host's sh and awk, so each CI
// platform checks its own.
func TestRedactMatchesTheSetupScript(t *testing.T) {
	src := string(clientSetupScript)
	start := strings.Index(src, "\nredact() {\n")
	end := strings.Index(src[start+1:], "\n}\n")
	if start < 0 || end < 0 {
		t.Fatal("no redact() function in client_setup.sh; the test cannot reach the script's rule")
	}
	dir := t.TempDir()
	fn, input := dir+"/redact.sh", dir+"/input"
	if err := os.WriteFile(fn, []byte(src[start+1:start+1+end+3]), 0o600); err != nil {
		t.Fatal(err)
	}
	var in []string
	for _, c := range redactCases {
		in = append(in, c.in)
	}
	if err := os.WriteFile(input, []byte(strings.Join(in, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sh", "-c", `. "$1" && redact "$2"`, "sh", fn, input).CombinedOutput()
	if err != nil {
		t.Fatalf("sh redact(): %v\n%s", err, out)
	}
	awk := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if len(awk) != len(redactCases) {
		t.Fatalf("redact() printed %d lines for %d rows:\n%s", len(awk), len(redactCases), out)
	}
	for i, c := range redactCases {
		want := c.want
		if want == "" {
			want = c.in
		}
		if got := clientconf.Redact(c.in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", c.in, got, want)
		}
		if awk[i] != want {
			t.Errorf("redact() of %q = %q, want %q", c.in, awk[i], want)
		}
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

// The served script and clientconf are two implementations of one apply: a
// host with the binary and a host without it must end holding the same bytes
// and see the same secrets redacted. The script runs here under this host's
// own sh and awk against a stand-in server, with uname answering Linux so the
// test runs on a developer's Mac too.
func TestSetupScriptKeepsCredentialsAndMatchesClientconf(t *testing.T) {
	for _, tool := range []string{"sh", "awk", "diff", "cmp"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not on PATH", tool)
		}
	}
	files := map[string]string{
		"npm":   clientconf.Npm("https://h", nil).Content,
		"helm":  clientconf.Helm("https://h").Content,
		"pypi":  clientconf.Pip("https://h").Content,
		"maven": clientconf.Maven("https://h", nil)[0].Content,
	}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	var records []planRecord
	for _, sys := range []string{"npm", "helm", "pypi", "maven"} {
		sum := sha256.Sum256([]byte(files[sys]))
		path := map[string]string{"npm": "~/.npmrc", "helm": "~/.config/helm/repositories.yaml", "pypi": "~/pip.conf", "maven": clientconf.MavenSettingsPath}[sys]
		records = append(records, planRecord{Identity: "t", Match: "cidr:127.0.0.1/32", System: sys, Action: clientconf.PlanInstall,
			Path: path, URL: srv.URL + "/client/" + sys, SHA256: hex.EncodeToString(sum[:])})
		body := files[sys]
		mux.HandleFunc("/client/"+sys, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) })
	}
	mux.HandleFunc("/client/plan.txt", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(planTSV(records))) })

	fence := func(s string) string {
		return clientconf.CredentialBegin + "\n" + s + "\n" + clientconf.CredentialEnd + "\n"
	}
	seed := map[string]string{ //nolint:gosec // G101: fixture tokens the test asserts are redacted, not credentials
		".npmrc": "color=false\n" + fence("//h/npm/:_authToken=bodega_ak_npm") + "//old/:_authToken=bodega_ak_other\n",
		".config/helm/repositories.yaml": clientconf.HelmDocument("- name: other\n  url: https://o\n  password: bodega_ak_otherhelm\n" +
			fence("- name: bodega\n  url: https://h/helm\n  username: bodega\n  password: bodega_ak_helm")),
		"pip.conf": "[global]\nindex-url = https://op:bodega_ak_pip@pypi.internal/simple/\n",
		".m2/settings.xml": "<?xml version=\"1.0\"?>\n<settings>\n  <!-- <mirrors></mirrors> — an example -->\n" +
			"  <servers>\n    <server>\n      <id>corp</id>\n      <password>bodega_ak_maven</password>\n    </server>\n  </servers>\n" +
			"  <mirrors>\n    <mirror><id>nexus</id><mirrorOf>central</mirrorOf><url>https://n/</url></mirror>\n  </mirrors>\n" +
			"  <profiles><profile><id>extra</id></profile></profiles>\n</settings>",
	}
	newHome := func() string {
		home := t.TempDir()
		for rel, content := range seed {
			p := home + "/" + rel
			if err := os.MkdirAll(p[:strings.LastIndex(p, "/")], 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return home
	}

	stub := t.TempDir()
	if err := os.WriteFile(stub+"/uname", []byte("#!/bin/sh\necho Linux\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := t.TempDir() + "/setup.sh"
	if err := os.WriteFile(script, clientSetupScript, 0o644); err != nil {
		t.Fatal(err)
	}
	runScript := func(home string, apply bool) string {
		args := []string{script, "--url", srv.URL, "--allow-plaintext"}
		if apply {
			args = append(args, "--apply")
		}
		cmd := exec.Command("sh", args...)
		cmd.Env = []string{"HOME=" + home, "PATH=" + stub + ":" + os.Getenv("PATH"), "TMPDIR=" + os.TempDir()}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("sh setup.sh: %v\n%s", err, out)
		}
		return string(out)
	}

	scriptHome := newHome()
	dry := runScript(scriptHome, false)
	if strings.Contains(dry, "bodega_ak_") || !strings.Contains(dry, "<redacted>") {
		t.Errorf("the script's dry run prints a secret, or redacts nothing:\n%s", dry)
	}
	runScript(scriptHome, true)
	if again := runScript(scriptHome, true); !strings.Contains(again, "Nothing to change") {
		t.Errorf("a second --apply found something to change:\n%s", again)
	}

	goHome := newHome()
	var changes []clientconf.Change
	for _, rec := range records {
		c, err := clientconf.NewChange(rec, []byte(files[rec.System]), goHome)
		if err != nil {
			t.Fatal(err)
		}
		d, err := c.Diff()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(d, "bodega_ak_") {
			t.Errorf("clientconf's diff of %s prints a secret:\n%s", rec.System, d)
		}
		changes = append(changes, c)
	}
	if _, err := clientconf.Apply(changes, ".bak"); err != nil {
		t.Fatal(err)
	}

	for rel := range seed {
		fromScript, _ := os.ReadFile(scriptHome + "/" + rel)
		fromGo, _ := os.ReadFile(goHome + "/" + rel)
		if string(fromScript) != string(fromGo) {
			t.Errorf("%s differs between the script and clientconf:\nscript:\n%s\nclientconf:\n%s", rel, fromScript, fromGo)
		}
	}
	for rel, want := range map[string]string{".npmrc": "_authToken=bodega_ak_npm", ".config/helm/repositories.yaml": "password: bodega_ak_helm",
		".m2/settings.xml": "<password>bodega_ak_maven</password>"} {
		if got, _ := os.ReadFile(scriptHome + "/" + rel); !strings.Contains(string(got), want) {
			t.Errorf("%s lost bodega's credential after --apply:\n%s", rel, got)
		}
	}
}

// pocketServer mirrors two Ubuntu bases with their pockets beside one suite
// bodega generates and signs, the layout F68's live run found the plan
// configuring one pocket of.
func pocketServer(t *testing.T) (*Server, *profileFixture) {
	t.Helper()
	s := hostedServer(t)
	s.cfg.PublicURL = "http://bodega.example.com:8080"
	s.cfg.AptCodename = "local"
	s.cfg.AptSuites = []string{"local"}
	s.cfg.AptUpstreams = map[string][]config.AptUpstream{}
	for _, c := range []string{"noble", "noble-updates", "noble-security", "resolute", "resolute-updates", "resolute-security", "resolute-backports"} {
		s.cfg.AptUpstreams[c] = []config.AptUpstream{{URL: "https://archive.ubuntu.com/ubuntu"}}
	}
	own, err := aptsign.Generate("bodega", "bodega@example.invalid", aptsign.KeyEd25519)
	if err != nil {
		t.Fatalf("generate bodega key: %v", err)
	}
	pub, _ := own.PublicKey()
	ring, _ := own.Keyring()
	s.aptSign.Store(&aptSigning{signer: own, pubArmored: pub, keyring: ring})
	return s, clientProfile(t, s)
}

func aptPlanRecords(t *testing.T, s *Server, token, codename string) []planRecord {
	t.Helper()
	query := "os=linux"
	if codename != "" {
		query += "&codename=" + codename
	}
	return planRecordFor(planJSON(t, s, token, query), manifest.TypeApt)
}

// B144 R1, R2, R7: a base's pockets are one choice and one stanza, in Ubuntu's
// own order. A stanza naming resolute alone cannot install libpq-dev on a host
// already running libpq5 from -updates.
func TestClientAptPlanGroupsPocketsUnderTheirBase(t *testing.T) {
	s, f := pocketServer(t)
	recs := aptPlanRecords(t, s, f.token, "resolute")
	if len(recs) == 0 || recs[0].Action != planInstall || recs[0].Path != clientconf.AptSourcesPath {
		t.Fatalf("codename=resolute plan = %+v, want the sources file installed", recs)
	}
	code, body := clientGet(t, s, f.token, "/client/apt?os=linux&codename=resolute")
	if code != http.StatusOK {
		t.Fatalf("GET /client/apt = %d: %s", code, body)
	}
	want := "Types: deb\nURIs: http://bodega.example.com:8080/apt/\nSuites: resolute resolute-updates resolute-backports resolute-security\nComponents: " + aptsources.MirroredComponents + "\n"
	if body != want {
		t.Errorf("stanza =\n%s\nwant\n%s", body, want)
	}

	// noble has no backports mirrored, so its stanza leaves the pocket out.
	_, body = clientGet(t, s, f.token, "/client/apt?os=linux&codename=noble")
	if !strings.Contains(body, "Suites: noble noble-updates noble-security\n") || strings.Contains(body, "Signed-By:") {
		t.Errorf("noble stanza =\n%s\nwant its two served pockets and no Signed-By:", body)
	}
}

// B144 R1, R6, R7: with two bases and a generated suite served, the refusal
// counts choices, not pockets.
func TestClientAptPlanRefusalListsBasesNotPockets(t *testing.T) {
	s, f := pocketServer(t)
	recs := aptPlanRecords(t, s, f.token, "")
	if len(recs) != 1 || recs[0].Action != planSkip {
		t.Fatalf("plan with no codename = %+v, want one skip", recs)
	}
	if want := "serves 3 apt suites (local, noble, resolute)"; !strings.Contains(recs[0].Reason, want) {
		t.Errorf("reason = %q, want it to contain %q", recs[0].Reason, want)
	}

	// Without the generated suite, the two choices are the two bases.
	s.cfg.AptSuites, s.cfg.AptCodename = nil, ""
	recs = aptPlanRecords(t, s, f.token, "")
	if want := "serves 2 apt suites (noble, resolute)"; len(recs) != 1 || !strings.Contains(recs[0].Reason, want) {
		t.Errorf("plan = %+v, want a skip containing %q", recs, want)
	}

	// One base served needs no codename.
	for c := range s.cfg.AptUpstreams {
		if strings.HasPrefix(c, "noble") {
			delete(s.cfg.AptUpstreams, c)
		}
	}
	recs = aptPlanRecords(t, s, f.token, "")
	if len(recs) == 0 || recs[0].Action != planInstall || recs[0].Path != clientconf.AptSourcesPath {
		t.Errorf("one base served, plan = %+v, want the sources file installed", recs)
	}
}

// B144 R4, R7: a pocket is not a choice of its own, and the reason names the
// base to pass.
func TestClientAptPlanRefusesAPocketCodename(t *testing.T) {
	s, f := pocketServer(t)
	recs := aptPlanRecords(t, s, f.token, "resolute-updates")
	if len(recs) != 1 || recs[0].Action == planInstall {
		t.Fatalf("codename=resolute-updates plan = %+v, want no install", recs)
	}
	for _, want := range []string{"--suite resolute", "--codename resolute", "codename=resolute"} {
		if !strings.Contains(recs[0].Reason, want) {
			t.Errorf("reason = %q, want it to name %s", recs[0].Reason, want)
		}
	}
}

// setupScriptAgainst runs the served setup script as a Linux host against s,
// recording the query of every plan request it makes.
func setupScriptAgainst(t *testing.T, s *Server, token string, env []string, args ...string) (string, []url.Values, error) {
	t.Helper()
	var plans []url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/client/plan") {
			plans = append(plans, r.URL.Query())
		}
		s.Handler().ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	s.cfg.PublicURL = srv.URL

	stub := t.TempDir()
	if err := os.WriteFile(stub+"/uname", []byte("#!/bin/sh\necho Linux\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := t.TempDir() + "/setup.sh"
	if err := os.WriteFile(script, clientSetupScript, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", append([]string{script, "--url", srv.URL, "--allow-plaintext"}, args...)...)
	cmd.Env = append([]string{"HOME=" + t.TempDir(), "PATH=" + stub + ":" + os.Getenv("PATH"), "TMPDIR=" + os.TempDir(), "BODEGA_TOKEN=" + token}, env...)
	out, err := cmd.CombinedOutput()
	return string(out), plans, err
}

// B147 R1, R4: a script user on a server serving several suites names one,
// and the flag wins over BODEGA_CODENAME, which wins over VERSION_CODENAME.
func TestSetupScriptCodenameReachesThePlan(t *testing.T) {
	for _, tool := range []string{"sh", "awk", "diff", "cmp"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not on PATH", tool)
		}
	}
	for _, c := range []struct {
		name string
		env  []string
		args []string
		want string
	}{
		{"flag", nil, []string{"--codename", "noble"}, "noble"},
		{"flag=", nil, []string{"--codename=resolute"}, "resolute"},
		{"variable", []string{"BODEGA_CODENAME=resolute"}, nil, "resolute"},
		{"flag over variable", []string{"BODEGA_CODENAME=resolute"}, []string{"--codename", "noble"}, "noble"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, f := pocketServer(t)
			out, plans, err := setupScriptAgainst(t, s, f.token, c.env, append(c.args, "--systems", "apt")...)
			if err != nil {
				t.Fatalf("sh setup.sh %v: %v\n%s", c.args, err, out)
			}
			if len(plans) != 1 || plans[0].Get("codename") != c.want {
				t.Fatalf("plan requests = %v, want one carrying codename=%s", plans, c.want)
			}
			if strings.Contains(out, "apt suites (") || !strings.Contains(out, "Suites: "+c.want) {
				t.Errorf("the dry run does not configure %s:\n%s", c.want, out)
			}
		})
	}
}

// B147 R1, R4: a value that is no apt suite name stops the script before it
// asks the server anything.
func TestSetupScriptRefusesABadCodename(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not on PATH")
	}
	for _, c := range []struct {
		env  []string
		args []string
		bad  string
	}{
		{nil, []string{"--codename", "Noble"}, "Noble"},
		{[]string{"BODEGA_CODENAME=noble;id"}, nil, "noble;id"},
	} {
		s, f := pocketServer(t)
		out, plans, err := setupScriptAgainst(t, s, f.token, c.env, c.args...)
		if err == nil {
			t.Errorf("sh setup.sh %v %v exited 0, want a refusal:\n%s", c.env, c.args, out)
		}
		if len(plans) != 0 {
			t.Errorf("sh setup.sh %v %v asked for a plan before refusing: %v", c.env, c.args, plans)
		}
		if !strings.Contains(out, "codename "+c.bad+" ") || !strings.Contains(out, "[a-z0-9.+-]") {
			t.Errorf("refusal of %q does not name the value and the accepted pattern:\n%s", c.bad, out)
		}
	}
}

// B144 R3, R7: the generated suite is never grouped, and keeps Signed-By:.
func TestClientAptPlanKeepsAGeneratedSuiteOnItsOwnStanza(t *testing.T) {
	s, f := pocketServer(t)
	s.cfg.AptUpstreams["local-updates"] = []config.AptUpstream{{URL: "https://archive.ubuntu.com/ubuntu"}}
	recs := aptPlanRecords(t, s, f.token, "local")
	if len(recs) != 2 || recs[1].Path != aptsources.ClientKeyringPath {
		t.Fatalf("codename=local plan = %+v, want the stanza and its keyring", recs)
	}
	_, body := clientGet(t, s, f.token, "/client/apt?os=linux&codename=local")
	if !strings.Contains(body, "Suites: local\n") || !strings.Contains(body, "Signed-By: "+aptsources.ClientKeyringPath) {
		t.Errorf("generated stanza =\n%s\nwant Suites: local alone and Signed-By:", body)
	}
}

// B146 R1, R3: whether the plan ships bodega's keyring follows what the stanza
// names. A mirrored stanza names no Signed-By:, so it never needs the keyring
// and never waits on a signing key to serve one. A generated suite with no
// signing key at all renders Trusted: yes and names no keyring either; the
// skip is for a stanza that names the keyring while none can be served.
func TestClientAptPlanShipsTheKeyringOnlyForAGeneratedSuite(t *testing.T) {
	const (
		keyLoaded = iota
		noKey
		noKeyring
	)
	for _, c := range []struct {
		name, codename string
		key            int
		want           []string
	}{
		{"mirrored, no key", "resolute", noKey, []string{clientconf.AptSourcesPath}},
		{"mirrored, key", "resolute", keyLoaded, []string{clientconf.AptSourcesPath}},
		{"mirrored, key with no keyring", "resolute", noKeyring, []string{clientconf.AptSourcesPath}},
		{"generated, key", "local", keyLoaded, []string{clientconf.AptSourcesPath, aptsources.ClientKeyringPath}},
		{"generated, no key", "local", noKey, []string{clientconf.AptSourcesPath}},
		{"generated, key with no keyring", "local", noKeyring, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, f := pocketServer(t)
			switch c.key {
			case noKey:
				s.aptSign.Store(nil)
			case noKeyring:
				sign := *s.aptSign.Load()
				sign.keyring = nil
				s.aptSign.Store(&sign)
			}
			recs := aptPlanRecords(t, s, f.token, c.codename)
			if c.want == nil {
				const reason = "the stanza names bodega's keyring and no apt signing key is loaded to serve it"
				if len(recs) != 1 || recs[0].Action != planSkip || recs[0].Reason != reason {
					t.Fatalf("plan = %+v, want one skip with reason %q", recs, reason)
				}
				return
			}
			var got []string
			for _, r := range recs {
				if r.Action != planInstall {
					t.Fatalf("plan = %+v, want installs only", recs)
				}
				got = append(got, r.Path)
			}
			if strings.Join(got, " ") != strings.Join(c.want, " ") {
				t.Errorf("plan installs %v, want %v", got, c.want)
			}
		})
	}
}

// B146 R4: the served script, run against a mirror-only server with no apt
// signing key, writes the sources file and never asks for the keyring. The
// plan's /etc paths are moved under a temporary root on the way to the script
// so --apply writes without root.
func TestSetupScriptConfiguresAMirroredCodenameWithNoSigningKey(t *testing.T) {
	for _, tool := range []string{"sh", "awk", "diff", "cmp", "curl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not on PATH", tool)
		}
	}
	s, f := pocketServer(t)
	s.aptSign.Store(nil)
	s.cfg.AptSuites, s.cfg.AptCodename = nil, ""
	for c := range s.cfg.AptUpstreams {
		if strings.HasPrefix(c, "noble") {
			delete(s.cfg.AptUpstreams, c)
		}
	}

	root := t.TempDir()
	var mu sync.Mutex
	var fetched []string
	handler := s.Handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fetched = append(fetched, r.URL.Path)
		mu.Unlock()
		if r.URL.Path != "/client/plan.txt" {
			handler.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		w.WriteHeader(rec.Code)
		_, _ = w.Write([]byte(strings.ReplaceAll(rec.Body.String(), "\t/etc/", "\t"+root+"/etc/")))
	}))
	defer srv.Close()
	s.cfg.PublicURL = srv.URL

	stub := t.TempDir()
	if err := os.WriteFile(stub+"/uname", []byte("#!/bin/sh\necho Linux\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := t.TempDir() + "/setup.sh"
	if err := os.WriteFile(script, clientSetupScript, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", script, "--url", srv.URL, "--allow-plaintext", "--systems", "apt", "--codename", "resolute", "--apply")
	cmd.Env = []string{"HOME=" + t.TempDir(), "BODEGA_TOKEN=" + f.token, "PATH=" + stub + ":" + os.Getenv("PATH"), "TMPDIR=" + os.TempDir()}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sh setup.sh --systems apt --codename resolute --apply: %v\n%s", err, out)
	}

	sources, err := os.ReadFile(root + clientconf.AptSourcesPath)
	if err != nil {
		t.Fatalf("the script wrote no sources file: %v\n%s", err, out)
	}
	if !strings.Contains(string(sources), "Suites: resolute ") || strings.Contains(string(sources), "Signed-By:") {
		t.Errorf("sources file =\n%s\nwant the mirrored resolute stanza with no Signed-By:", sources)
	}
	if _, err := os.Stat(root + aptsources.ClientKeyringPath); !os.IsNotExist(err) {
		t.Errorf("the script wrote %s beside a mirrored stanza (stat: %v)", aptsources.ClientKeyringPath, err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, p := range fetched {
		if p == aptsources.KeyringRoute {
			t.Errorf("the script fetched %s for a mirrored codename; requests: %v", p, fetched)
		}
	}
}

// F82: rubygems installs ~/.gemrc and Bundler's mirror, each at a URL that
// serves the bytes the plan's digest names, and an apply under a fixture home
// writes both and backs up the gemrc it replaces.
func TestClientPlanRubygemsInstallsGemrcAndBundlerMirror(t *testing.T) {
	s := hostedServer(t)
	s.cfg.PublicURL = "https://bodega.internal"
	f := bindProfile(t, s, "open", "open-host", nil, nil)
	want := map[string]string{
		"~/.gemrc":         "---\n:sources:\n- https://bodega.internal/rubygems/\n",
		"~/.bundle/config": "---\nBUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: \"https://bodega.internal/rubygems/\"\n",
	}
	wantURL := map[string]string{
		"~/.gemrc":         "https://bodega.internal/client/rubygems?os=linux",
		"~/.bundle/config": "https://bodega.internal/client/rubygems?file=bundler&os=linux",
	}
	home := t.TempDir()
	if err := os.WriteFile(home+"/.gemrc", []byte("---\n:sources:\n- https://rubygems.org/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	recs := planRecordFor(planJSON(t, s, f.token, "os=linux"), manifest.TypeRubygems)
	if len(recs) != len(want) {
		t.Fatalf("rubygems records = %+v, want ~/.gemrc and ~/.bundle/config", recs)
	}
	var changes []clientconf.Change
	for _, rec := range recs {
		if rec.Action != clientconf.PlanInstall || want[rec.Path] == "" || rec.URL != wantURL[rec.Path] {
			t.Fatalf("record %+v, want an install at one of %v from %v", rec, want, wantURL)
		}
		u, _ := url.Parse(rec.URL)
		code, body := clientGet(t, s, f.token, u.RequestURI())
		if code != http.StatusOK || body != want[rec.Path] {
			t.Fatalf("GET %s = %d %q, want %q", u.RequestURI(), code, body, want[rec.Path])
		}
		c, err := clientconf.NewChange(rec, []byte(body), home)
		if err != nil {
			t.Fatalf("NewChange refused the served file: %v", err)
		}
		changes = append(changes, c)
	}
	if _, err := clientconf.Apply(changes, ".bodega-test"); err != nil {
		t.Fatal(err)
	}
	for path, content := range want {
		if got, _ := os.ReadFile(home + "/" + strings.TrimPrefix(path, "~/")); string(got) != content {
			t.Errorf("%s after apply = %q, want %q", path, got, content)
		}
	}
	if got, _ := os.ReadFile(home + "/.gemrc.bodega-test"); !strings.Contains(string(got), "https://rubygems.org/") {
		t.Errorf("backup = %q, want the gemrc it replaced", got)
	}
}

// file=bundler is rubygems' alone, and a profile excluding rubygems refuses
// the companion as it refuses the gemrc.
func TestClientBundlerRouteRefusals(t *testing.T) {
	s := hostedServer(t)
	f := bindProfile(t, s, "open", "open-host", nil, nil)
	for path, want := range map[string]int{
		"/client/npm?os=linux&file=bundler":           http.StatusBadRequest,
		"/client/rubygems?os=linux&file=node-mirror":  http.StatusBadRequest,
		"/client/rubygems?os=freebsd&file=bundler":    http.StatusOK,
		"/client/rubygems?os=linux&file=bundler":      http.StatusOK,
		"/client/rubygems?os=linux&file=bundler-conf": http.StatusBadRequest,
	} {
		if code, body := clientGet(t, s, f.token, path); code != want {
			t.Errorf("GET %s = %d %q, want %d", path, code, body, want)
		}
	}

	closed := bindProfile(t, s, "closed", "closed-host",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeRubygems, audit.VersionFloating, audit.ExpansionBlock)}, nil)
	recs := planRecordFor(planJSON(t, s, closed.token, "os=linux"), manifest.TypeRubygems)
	if len(recs) != 1 || recs[0].Action != planRefuse {
		t.Errorf("rubygems under a closed profile = %+v, want one refusal", recs)
	}
	if code, _ := clientGet(t, s, closed.token, "/client/rubygems?os=linux&file=bundler"); code != http.StatusForbidden {
		t.Errorf("GET the Bundler file under a closed profile = %d, want 403", code)
	}
}

// F82 R3: the served script configures rubygems when --systems names it,
// writing both files into the running user's home.
func TestSetupScriptConfiguresRubygems(t *testing.T) {
	for _, tool := range []string{"sh", "awk", "diff", "cmp", "curl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not on PATH", tool)
		}
	}
	s := hostedServer(t)
	f := bindProfile(t, s, "open", "open-host", nil, nil)
	home := t.TempDir()
	if err := os.WriteFile(home+"/.gemrc", []byte("---\n:sources:\n- https://rubygems.org/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _, err := setupScriptAgainst(t, s, f.token, []string{"HOME=" + home}, "--systems", "rubygems", "--apply")
	if err != nil {
		t.Fatalf("sh setup.sh --systems rubygems --apply: %v\n%s", err, out)
	}
	for _, c := range clientconf.Rubygems(s.cfg.PublicURL) {
		target := home + "/" + strings.TrimPrefix(c.Path(clientconf.OSLinux), "~/")
		if got, _ := os.ReadFile(target); string(got) != c.Content {
			t.Errorf("%s = %q, want %q\n%s", target, got, c.Content, out)
		}
	}
	if backups, _ := filepath.Glob(home + "/.gemrc.bodega-*"); len(backups) != 1 {
		t.Errorf("gemrc backups = %v, want one\n%s", backups, out)
	}
}

// F87: maven installs Maven's settings.xml and Gradle's init script, each at a
// URL serving the bytes the plan's digest names. The settings.xml record
// carries the wrapper note, and an apply merges into an existing settings.xml
// and replaces the init script, backing up both.
func TestClientPlanMavenInstallsSettingsAndGradleInit(t *testing.T) {
	s := hostedServer(t)
	s.cfg.PublicURL = "https://bodega.internal"
	f := bindProfile(t, s, "open", "open-host", nil, nil)
	files := clientconf.Maven("https://bodega.internal", nil)
	want := map[string]string{"~/.m2/settings.xml": files[0].Content, "~/.gradle/init.d/bodega.gradle": files[1].Content}
	wantURL := map[string]string{
		"~/.m2/settings.xml":             "https://bodega.internal/client/maven?os=linux",
		"~/.gradle/init.d/bodega.gradle": "https://bodega.internal/client/maven?file=gradle&os=linux",
	}
	home := t.TempDir()
	existing := "<settings>\n  <servers><server><id>corp</id></server></servers>\n" +
		"  <mirrors>\n    <mirror><id>nexus</id><mirrorOf>central</mirrorOf><url>https://n/</url></mirror>\n  </mirrors>\n" +
		"  <profiles><profile><id>extra</id></profile></profiles>\n</settings>\n"
	for rel, content := range map[string]string{".m2/settings.xml": existing, ".gradle/init.d/bodega.gradle": "// an older bodega.gradle\n"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(home, rel)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, rel), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	recs := planRecordFor(planJSON(t, s, f.token, "os=linux"), manifest.TypeMaven)
	if len(recs) != len(want) {
		t.Fatalf("maven records = %+v, want settings.xml and the init script", recs)
	}
	if !strings.Contains(recs[0].Reason, "distributionUrl=https://bodega.internal/binaries/") || !strings.Contains(recs[0].Reason, "gradle-wrapper.properties") {
		t.Errorf("settings.xml record reason = %q, want the wrapper note", recs[0].Reason)
	}
	var changes []clientconf.Change
	for _, rec := range recs {
		if rec.Action != clientconf.PlanInstall || want[rec.Path] == "" || rec.URL != wantURL[rec.Path] {
			t.Fatalf("record %+v, want an install at one of %v from %v", rec, want, wantURL)
		}
		u, _ := url.Parse(rec.URL)
		code, body := clientGet(t, s, f.token, u.RequestURI())
		if code != http.StatusOK || body != want[rec.Path] {
			t.Fatalf("GET %s = %d %q, want %q", u.RequestURI(), code, body, want[rec.Path])
		}
		c, err := clientconf.NewChange(rec, []byte(body), home)
		if err != nil {
			t.Fatalf("NewChange refused the served file: %v", err)
		}
		changes = append(changes, c)
	}
	if _, err := clientconf.Apply(changes, ".bodega-test"); err != nil {
		t.Fatal(err)
	}
	settings, _ := os.ReadFile(filepath.Join(home, ".m2/settings.xml"))
	for _, keep := range []string{"<id>corp</id>", "<id>extra</id>", "<mirrorOf>*</mirrorOf>", "<url>https://bodega.internal/maven/</url>"} {
		if !strings.Contains(string(settings), keep) {
			t.Errorf("merged settings.xml lacks %s:\n%s", keep, settings)
		}
	}
	if strings.Contains(string(settings), "nexus") {
		t.Errorf("merged settings.xml keeps the second mirror, which takes central around bodega:\n%s", settings)
	}
	if got, _ := os.ReadFile(filepath.Join(home, ".gradle/init.d/bodega.gradle")); string(got) != files[1].Content {
		t.Errorf("init script after apply = %q, want the planned file whole", got)
	}
	for rel, old := range map[string]string{".m2/settings.xml": existing, ".gradle/init.d/bodega.gradle": "// an older bodega.gradle\n"} {
		if got, _ := os.ReadFile(filepath.Join(home, rel+".bodega-test")); string(got) != old {
			t.Errorf("backup of %s = %q, want the file it replaced", rel, got)
		}
	}
}

// file=gradle is maven's alone, and a profile excluding maven refuses the
// init script as it refuses settings.xml.
func TestClientGradleRouteRefusals(t *testing.T) {
	s := hostedServer(t)
	f := bindProfile(t, s, "open", "open-host", nil, nil)
	for path, want := range map[string]int{
		"/client/npm?os=linux&file=gradle":     http.StatusBadRequest,
		"/client/maven?os=linux&file=bundler":  http.StatusBadRequest,
		"/client/maven?os=freebsd&file=gradle": http.StatusOK,
		"/client/maven?os=linux":               http.StatusOK,
	} {
		if code, body := clientGet(t, s, f.token, path); code != want {
			t.Errorf("GET %s = %d %q, want %d", path, code, body, want)
		}
	}

	closed := bindProfile(t, s, "closed", "closed-host",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeMaven, audit.VersionFloating, audit.ExpansionBlock)}, nil)
	recs := planRecordFor(planJSON(t, s, closed.token, "os=linux"), manifest.TypeMaven)
	if len(recs) != 1 || recs[0].Action != planRefuse {
		t.Errorf("maven under a closed profile = %+v, want one refusal", recs)
	}
	if code, _ := clientGet(t, s, closed.token, "/client/maven?os=linux&file=gradle"); code != http.StatusForbidden {
		t.Errorf("GET the init script under a closed profile = %d, want 403", code)
	}
}

// F95 R1, R2: composer installs Composer's global config.json at a URL
// serving the bytes the plan's digest names, the record says it is merged,
// and an apply over a config.json holding an auth key keeps the key and backs
// the file up.
func TestClientPlanComposerInstallsGlobalConfig(t *testing.T) {
	s := hostedServer(t)
	s.cfg.PublicURL = "https://bodega.internal"
	f := bindProfile(t, s, "open", "open-host", nil, nil)
	want := clientconf.Composer("https://bodega.internal")
	recs := planRecordFor(planJSON(t, s, f.token, "os=linux"), manifest.TypeComposer)
	if len(recs) != 1 || recs[0].Action != clientconf.PlanInstall || recs[0].Path != "~/.config/composer/config.json" ||
		recs[0].URL != "https://bodega.internal/client/composer?os=linux" {
		t.Fatalf("composer records = %+v, want one install of ~/.config/composer/config.json from /client/composer", recs)
	}
	if !strings.Contains(recs[0].Reason, "keeps its auth") || !strings.Contains(recs[0].Reason, "COMPOSER_HOME") {
		t.Errorf("reason = %q, want the merge and COMPOSER_HOME notes", recs[0].Reason)
	}
	u, _ := url.Parse(recs[0].URL)
	code, body := clientGet(t, s, f.token, u.RequestURI())
	if code != http.StatusOK || body != want.Content {
		t.Fatalf("GET %s = %d %q, want %q", u.RequestURI(), code, body, want.Content)
	}
	home := t.TempDir()
	target := filepath.Join(home, ".config/composer/config.json")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(`{"config":{"github-oauth":{"github.com":"ghp_operator"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := clientconf.NewChange(recs[0], []byte(body), home)
	if err != nil {
		t.Fatalf("NewChange refused the served file: %v", err)
	}
	if _, err := clientconf.Apply([]clientconf.Change{c}, ".bodega-test"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(target)
	repos, err := clientconf.ReadComposerRepos(got)
	if err != nil || repos.Bodega != "https://bodega.internal/composer" || !repos.PackagistOff || !strings.Contains(string(got), "ghp_operator") {
		t.Errorf("config.json after apply =\n%s\nwant bodega's repository, packagist.org off and the github-oauth key kept (err %v)", got, err)
	}
	if _, err := os.Stat(target + ".bodega-test"); err != nil {
		t.Errorf("no backup beside %s: %v", target, err)
	}
}

// F95: the setup script writes config.json where none exists, in the
// directory Composer reads (COMPOSER_HOME, else an existing XDG or ~/.composer
// home), and leaves an existing one to doctor rather than replace the
// operator's settings with the plan's.
func TestSetupScriptConfiguresComposerWithoutReplacingAConfig(t *testing.T) {
	for _, tool := range []string{"sh", "awk", "diff", "cmp", "curl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not on PATH", tool)
		}
	}
	s := hostedServer(t)
	f := bindProfile(t, s, "open", "open-host", nil, nil)
	composerHome := t.TempDir()
	out, _, err := setupScriptAgainst(t, s, f.token, []string{"COMPOSER_HOME=" + composerHome}, "--systems", "composer", "--apply")
	if err != nil {
		t.Fatalf("sh setup.sh --systems composer --apply: %v\n%s", err, out)
	}
	if got, _ := os.ReadFile(composerHome + "/config.json"); string(got) != clientconf.Composer(s.cfg.PublicURL).Content {
		t.Errorf("$COMPOSER_HOME/config.json = %q, want the planned file\n%s", got, out)
	}

	home := t.TempDir()
	existing := `{"config":{"github-oauth":{"github.com":"ghp_operator"}}}`
	target := home + "/.config/composer/config.json"
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, err = setupScriptAgainst(t, s, f.token, []string{"HOME=" + home, "XDG_CONFIG_HOME=" + home + "/.config"}, "--systems", "composer", "--apply")
	if err != nil {
		t.Fatalf("sh setup.sh over an existing config.json: %v\n%s", err, out)
	}
	if got, _ := os.ReadFile(target); string(got) != existing {
		t.Errorf("%s = %q, want it untouched", target, got)
	}
	if !strings.Contains(out, "skipped    composer") || !strings.Contains(out, "bodega doctor --configure composer") ||
		strings.Contains(out, "every file already matches") {
		t.Errorf("output does not say the file was left to doctor:\n%s", out)
	}

	// An XDG_ variable puts ~/.config/composer first, but Composer reads an
	// existing ~/.composer over a missing XDG directory, so that is the file
	// the script finds and leaves alone.
	home = t.TempDir()
	target = home + "/.composer/config.json"
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, err = setupScriptAgainst(t, s, f.token, []string{"HOME=" + home, "XDG_CONFIG_HOME=" + home + "/.config"}, "--systems", "composer", "--apply")
	if err != nil {
		t.Fatalf("sh setup.sh over an existing ~/.composer: %v\n%s", err, out)
	}
	if got, _ := os.ReadFile(target); string(got) != existing {
		t.Errorf("%s = %q, want it untouched", target, got)
	}
	if _, err := os.Stat(home + "/.config/composer"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("~/.config/composer exists beside ~/.composer (%v), which moves Composer's home away from it\n%s", err, out)
	}
	if !strings.Contains(out, "skipped    composer   "+target) {
		t.Errorf("output does not say %s was left to doctor:\n%s", target, out)
	}

	// With neither directory, Composer creates its first candidate.
	home = t.TempDir()
	out, _, err = setupScriptAgainst(t, s, f.token, []string{"HOME=" + home, "XDG_CONFIG_HOME=" + home + "/.config"}, "--systems", "composer", "--apply")
	if err != nil {
		t.Fatalf("sh setup.sh on a host with no Composer home: %v\n%s", err, out)
	}
	if got, _ := os.ReadFile(home + "/.config/composer/config.json"); string(got) != clientconf.Composer(s.cfg.PublicURL).Content {
		t.Errorf("~/.config/composer/config.json = %q, want the planned file\n%s", got, out)
	}
	if _, err := os.Stat(home + "/.composer"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("~/.composer was created (%v), want only the XDG directory\n%s", err, out)
	}
}

// F99 R1: oci plans every runtime's file from oci_upstreams, each at a URL
// serving the bytes its digest names; FreeBSD gets a skip.
func TestClientPlanOCIServesEachRuntimeFile(t *testing.T) {
	s := hostedServer(t)
	s.cfg.PublicURL = "https://bodega.internal"
	s.cfg.OCIUpstreams = map[string]string{"docker.io": "https://registry-1.docker.io", "quay.io": "https://quay.io"}
	f := bindProfile(t, s, "open", "open-host", nil, nil)
	recs := planRecordFor(planJSON(t, s, f.token, "os=linux"), manifest.TypeOCI)
	want := []string{clientconf.DockerDaemonPath, "/etc/containerd/certs.d/docker.io/hosts.toml", "/etc/containerd/certs.d/quay.io/hosts.toml",
		clientconf.ContainerdConfigPath, clientconf.RegistriesConfDropIn}
	if len(recs) != len(want) {
		t.Fatalf("oci records = %+v, want %v", recs, want)
	}
	for i, r := range recs {
		if r.Path != want[i] || r.Action != clientconf.PlanInstall {
			t.Errorf("record %d = %s %s, want install of %s", i, r.Action, r.Path, want[i])
		}
		u, _ := url.Parse(r.URL)
		code, body := clientGet(t, s, f.token, u.RequestURI())
		sum := sha256.Sum256([]byte(body))
		if code != http.StatusOK || hex.EncodeToString(sum[:]) != r.SHA256 {
			t.Errorf("GET %s = %d, digest does not match the plan's for %s:\n%s", u.RequestURI(), code, r.Path, body)
		}
	}
	if !strings.Contains(recs[0].Reason, "Docker Hub only") {
		t.Errorf("daemon.json reason = %q, want the Docker Hub-only note", recs[0].Reason)
	}
	if code, _ := clientGet(t, s, f.token, "/client/oci?os=linux&file="+clientconf.OCIHostsFileKey("ghcr.io")); code != http.StatusNotFound {
		t.Errorf("hosts.toml for a registry oci_upstreams lacks = %d, want 404", code)
	}
	bsd := planRecordFor(planJSON(t, s, f.token, "os=freebsd"), manifest.TypeOCI)
	if len(bsd) != 1 || bsd[0].Action != clientconf.PlanSkip {
		t.Errorf("oci on freebsd = %+v, want one skip", bsd)
	}
}

// F99: the setup script leaves oci to doctor, which merges daemon.json and
// keeps only the runtimes a host runs, on a bare run and when named.
func TestSetupScriptLeavesOCIToDoctor(t *testing.T) {
	s := hostedServer(t)
	f := bindProfile(t, s, "open", "open-host", nil, nil)
	out, _, err := setupScriptAgainst(t, s, f.token, nil, "--systems", "oci")
	if err == nil || !strings.Contains(out, "bodega doctor --configure oci") {
		t.Errorf("--systems oci = %v:\n%s", err, out)
	}
}

// Reconciliation vouches for exactly the pkg repository names the client
// plan writes into a host's repos file, so the two cannot drift: a hidden
// entry is in neither.
func TestFreeBSDPlanTagsAreThePlanRepositories(t *testing.T) {
	installPkgKey(t, pkgsign.KeyRSA)
	s := proxyingServer(t)
	s.loadPkgSigner()
	addVersion(t, s, manifest.TypeFreeBSD, "latest", manifest.VersionEntry{
		Version: freeBSDABI, URL: "https://pkg.example.org/" + freeBSDABI + "/latest", Mode: manifest.ModeProxy,
	})
	addVersion(t, s, manifest.TypeFreeBSD, "quarterly", manifest.VersionEntry{
		Version: freeBSDABI, URL: "https://pkg.example.org/" + freeBSDABI + "/quarterly", Mode: manifest.ModeProxy, Hidden: true,
	})
	tags, err := s.freeBSDPlanTags(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 1 || tags[0] != pkgrepos.TagPrefix+"latest" {
		t.Fatalf("plan tags = %v, want [%slatest]", tags, pkgrepos.TagPrefix)
	}
	f := webProfile(t, s)
	plan := planRecordFor(planJSON(t, s, f.token, "os=freebsd&abi="+freeBSDABI), manifest.TypeFreeBSD)
	if len(plan) != 1 || plan[0].Action != planInstall {
		t.Fatalf("freebsd plan = %+v, want one install", plan)
	}
	_, body := clientGet(t, s, f.token, "/client/freebsd?os=freebsd&abi="+freeBSDABI)
	if !strings.Contains(body, tags[0]+":") {
		t.Errorf("the plan's repos file does not define %s:\n%s", tags[0], body)
	}
}

// F103 R1, R2: a Rocky 9 host whose server configures BaseOS and AppStream
// and not EPEL gets bodega.repo with two sections, a note naming EPEL, and
// bodega's key from /rpm/bodega.gpg, each digest matching what its URL
// serves. A host the table does not name, or that states nothing, gets a
// skip saying what it read.
func TestClientPlanRpmMapsTheHostsDistribution(t *testing.T) {
	s, f := pocketServer(t)
	s.cfg.RpmUpstreams = map[string]config.RpmUpstream{
		"rocky-baseos":    {URL: "https://dl.rockylinux.org/pub/rocky/$releasever/BaseOS/$basearch/os/"},
		"rocky-appstream": {URL: "https://dl.rockylinux.org/pub/rocky/$releasever/AppStream/$basearch/os/"},
	}
	recs := planRecordFor(planJSON(t, s, f.token, "os=linux&os_id=rocky&os_version_id=9.4"), manifest.TypeRpm)
	if len(recs) != 2 || recs[0].Path != clientconf.RpmRepoPath || recs[1].Path != clientconf.RpmKeyPath {
		t.Fatalf("rpm records = %+v, want bodega.repo then the key", recs)
	}
	if !strings.Contains(recs[0].Reason, "epel is left out") {
		t.Errorf("bodega.repo reason = %q, want it to name epel", recs[0].Reason)
	}
	if recs[1].URL != "http://bodega.example.com:8080/rpm/bodega.gpg" {
		t.Errorf("key URL = %q", recs[1].URL)
	}
	for _, r := range recs {
		u, _ := url.Parse(r.URL)
		code, body := clientGet(t, s, f.token, u.RequestURI())
		sum := sha256.Sum256([]byte(body))
		if code != http.StatusOK || hex.EncodeToString(sum[:]) != r.SHA256 {
			t.Errorf("GET %s = %d, digest does not match the plan's for %s:\n%s", u.RequestURI(), code, r.Path, body)
		}
		if r.Path == clientconf.RpmRepoPath && (!strings.Contains(body, "[bodega-rocky-appstream]") || strings.Contains(body, "epel")) {
			t.Errorf("bodega.repo:\n%s", body)
		}
	}

	for query, want := range map[string]string{
		"os=linux&os_id=ubuntu&os_version_id=24.04": "reads ID=ubuntu VERSION_ID=24.04",
		"os=linux": `os_id="" os_version_id=""`,
		"os=freebsd&os_id=rocky&os_version_id=9.4":  "not freebsd",
		"os=linux&os_id=almalinux&os_version_id=10": "configures none of them",
	} {
		recs := planRecordFor(planJSON(t, s, f.token, query), manifest.TypeRpm)
		if len(recs) != 1 || recs[0].Action != planSkip || !strings.Contains(recs[0].Reason, want) {
			t.Errorf("%s: rpm = %+v, want one skip saying %q", query, recs, want)
		}
	}
	if code, _ := clientGet(t, s, f.token, "/client/plan?os=linux&os_id=Rocky%20Linux"); code != http.StatusBadRequest {
		t.Errorf("a malformed os_id = %d, want 400", code)
	}
}
