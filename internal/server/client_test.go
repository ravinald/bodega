package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
// the way the served setup script reads it, by sh with IFS set to a tab, so a
// field that collapses or shifts under that loop fails here rather than on a
// host.
func TestClientPlanTextAndJSONCarryIdenticalRecords(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh on PATH")
	}
	s := hostedServer(t)
	s.cfg.PublicURL = "https://bodega.internal"
	f := clientProfile(t, s)

	for _, q := range []string{"os=linux", "os=freebsd&abi=" + freeBSDABI} {
		records := planJSON(t, s, f.token, q)
		code, text := clientGet(t, s, f.token, "/client/plan.txt?"+q)
		if code != http.StatusOK {
			t.Fatalf("GET /client/plan.txt?%s = %d: %s", q, code, text)
		}

		loop := `tab=$(printf '\t')
while IFS=$tab read -r identity profile match system action path url sha256 reason; do
  printf '%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\n' \
    "$identity" "$profile" "$match" "$system" "$action" "$path" "$url" "$sha256" "$reason"
done`
		cmd := exec.Command(sh, "-c", loop)
		cmd.Stdin = strings.NewReader(text)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("sh read loop: %v", err)
		}
		var fromText []planRecord
		for _, line := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
			fs := strings.Split(line, "\037")
			if len(fs) != len(planColumns) {
				t.Fatalf("sh read %d fields from %q, want %d", len(fs), line, len(planColumns))
			}
			for i := range fs {
				if fs[i] == planEmpty {
					fs[i] = ""
				}
			}
			fromText = append(fromText, planRecord{fs[0], fs[1], fs[2], fs[3], fs[4], fs[5], fs[6], fs[7], fs[8]})
		}
		if len(fromText) != len(records) {
			t.Fatalf("%s: plan.txt has %d records, the JSON plan %d", q, len(fromText), len(records))
		}
		for i := range records {
			if fromText[i] != records[i] {
				t.Errorf("%s record %d:\n text %+v\n json %+v", q, i, fromText[i], records[i])
			}
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
