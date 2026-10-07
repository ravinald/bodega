package server

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/entitle"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

const pinnedIncident = "0123456789ab"

// pinIncident fixes the incident every refusal built during the test carries,
// so a body can be compared whole.
func pinIncident(t *testing.T) {
	t.Helper()
	prev := newIncident
	newIncident = func() string { return pinnedIncident }
	t.Cleanup(func() { newIncident = prev })
}

// refusalOpensOn reports whether a refusal's reason, the text after the
// summary's "(check, incident ...): ", opens on rule.
func refusalOpensOn(body, rule string) bool {
	first, _, _ := strings.Cut(body, "\n")
	return strings.Contains(first, "): "+rule+":")
}

// refusalIncident asserts the X-Bodega-Refusal header names check and returns
// the incident it carries.
func refusalIncident(t *testing.T, h http.Header, check string) string {
	t.Helper()
	got := h.Get(refusalHeader)
	c, inc, ok := strings.Cut(got, "; incident=")
	if !ok || c != check || len(inc) != 12 {
		t.Fatalf("%s = %q, want %q and a 12-character incident", refusalHeader, got, check+"; incident=<id>")
	}
	return inc
}

// bodyIncident reads the incident out of a refusal body's summary, which has
// to name check.
func bodyIncident(t *testing.T, body, check string) string {
	t.Helper()
	_, rest, ok := strings.Cut(body, "("+check+", incident ")
	if !ok || len(rest) < 13 || rest[12] != ')' {
		t.Fatalf("body names no %s incident:\n%s", check, body)
	}
	return rest[:12]
}

// refusalCase is one check, built through the constructor its site calls,
// with the reason and next step a person refused reads.
type refusalCase struct {
	check  string
	status int
	build  func(typ string) *refusal
	reason func(typ string) string
	next   func(typ string) string
	// subject is what the summary names when it is not typ/left-pad@1.3.0.
	subject func(typ string) string
}

func isPackageRule(typ string) bool {
	return policy.RuleKindForType(typ) == policy.KindPackage || typ == manifest.TypeGomod
}

func refusalCases() []refusalCase {
	return []refusalCase{
		{
			check: checkAllowList, status: http.StatusForbidden,
			build: func(typ string) *refusal { return allowListRefusal(typ, "left-pad", "left-pad", "1.3.0") },
			reason: func(typ string) string {
				if isPackageRule(typ) {
					return typ + ` "left-pad" is not on this server's upstream allow-list.`
				}
				return "the upstream this " + typ + " request needs is not on this server's upstream allow-list."
			},
			next: func(typ string) string {
				if isPackageRule(typ) {
					return "ask an operator to run `bodega policy add " + typ + " left-pad` if it should be."
				}
				return "give an operator incident " + pinnedIncident + "; its audit row names the upstream, and `bodega policy add " +
					typ + " <" + policy.RuleKindForType(typ) + ">` admits it."
			},
		},
		{
			check: checkAge, status: http.StatusForbidden,
			build: func(typ string) *refusal {
				return ageRefusal(typ, "left-pad", "1.3.0", map[string]any{
					"published_at": "2026-10-05T12:00:00Z", "min_age_seconds": int64(7 * 24 * 3600),
				})
			},
			reason: func(string) string {
				return "this version was published 2026-10-05 and this server holds new versions back for 7d."
			},
			next: func(string) string {
				return "the version becomes available on 2026-10-12; pin an older version until then."
			},
		},
		{
			check: checkOSV, status: http.StatusForbidden,
			build: func(typ string) *refusal {
				return osvRefusal(typ, "left-pad", "1.3.0", map[string]any{"vulns": []string{"GHSA-aaaa-bbbb-cccc"}, "count": 1})
			},
			reason: func(string) string { return "this version has known vulnerability records: GHSA-aaaa-bbbb-cccc." },
			next: func(string) string {
				return "pick a version without those records, or ask an operator to review `bodega policy osv list`."
			},
		},
		{
			check: checkProfile, status: http.StatusForbidden,
			build: func(typ string) *refusal {
				p := entitle.New(&audit.ProfileDetail{Profile: audit.Profile{Name: "web"}})
				return profileRefusal(p, typ, "left-pad", "1.3.0", entitle.Decision{Governed: true, Refusal: entitle.RefusalMembership})
			},
			reason: func(typ string) string {
				return `membership: profile "web" does not list ` + typ + "/left-pad at 1.3.0."
			},
			next: func(typ string) string {
				return "ask an operator to add it with `bodega profile add web " + typ + " left-pad`, or to open the type with `bodega profile set web " +
					typ + " --membership open`."
			},
		},
		{
			check: checkHidden, status: http.StatusNotFound,
			build:  func(typ string) *refusal { return hiddenRefusal(typ, "left-pad", "1.3.0") },
			reason: func(string) string { return "an operator has hidden this version on this server." },
			next: func(typ string) string {
				return "ask an operator why; if it should be served again, `bodega pkg hide " + typ + " left-pad 1.3.0` toggles the flag back."
			},
		},
		{
			check: checkFrozen, status: http.StatusForbidden,
			build:   func(typ string) *refusal { return frozenRefusal(typ, "left-pad") },
			subject: func(typ string) string { return typ + "/left-pad" },
			reason:  func(string) string { return "every version of this package is frozen, so it cannot be deleted." },
			next: func(typ string) string {
				return "unfreeze it first with `bodega pkg freeze " + typ + " left-pad`, which toggles the flag."
			},
		},
		{
			check: checkChecksum, status: http.StatusBadGateway,
			build: func(typ string) *refusal {
				return checksumRefusal(typ, manifest.NpmTarballKey("left-pad", "1.3.0"), "left-pad",
					&checksumMismatchError{incident: pinnedIncident, msg: "sha256 mismatch"})
			},
			reason: func(string) string {
				return "the bytes upstream served do not match the SHA-256 this server pinned on first fetch, so the upstream content may have been tampered with."
			},
			next: func(string) string {
				return "do not route around it; give an operator incident " + pinnedIncident + ", whose audit row holds both digests."
			},
		},
		{
			check: checkConstraint, status: http.StatusForbidden,
			build: func(typ string) *refusal { return constraintRefusal(typ, "left-pad", "1.3.0", "~1.2.0") },
			reason: func(string) string {
				return `1.3.0 is outside the version_constraint "~1.2.0" this server holds left-pad to.`
			},
			next: func(typ string) string {
				return "pick a version the constraint allows, or ask an operator to widen it with `bodega pkg edit " + typ + " left-pad`."
			},
		},
	}
}

// TestRefusalBodyPerClientAndCheck renders every check for every client and
// compares the body whole. npm prints the JSON error field, cargo prints the
// body of a failed fetch, go, helm and apt print text, and pip's body is text
// too, with the reason phrase covered by TestPypiRefusalCarriesItInTheStatusLine.
func TestRefusalBodyPerClientAndCheck(t *testing.T) {
	pinIncident(t)
	jsonEsc := func(s string) string { return strings.ReplaceAll(s, `"`, `\"`) }
	clients := []struct {
		typ, client, ctype string
		body               func(oneLine, text string) string
	}{
		{manifest.TypeNpm, "", "application/json", func(l, _ string) string { return `{"error":"` + jsonEsc(l) + "\"}\n" }},
		{manifest.TypeCargo, "", "application/json", func(l, _ string) string { return `{"errors":[{"detail":"` + jsonEsc(l) + "\"}]}\n" }},
		{manifest.TypeGomod, "", "text/plain; charset=utf-8", func(_, x string) string { return x }},
		{manifest.TypeHelm, "", "text/plain; charset=utf-8", func(_, x string) string { return x }},
		{manifest.TypeApt, "", "text/plain; charset=utf-8", func(_, x string) string { return x }},
		{manifest.TypePypi, "", "text/plain; charset=utf-8", func(_, x string) string { return x }},
		{manifest.TypeNpm, refusalClientAPI, "application/json", func(l, _ string) string { return `{"error":"` + jsonEsc(l) + "\"}\n" }},
	}
	for _, c := range clients {
		for _, tc := range refusalCases() {
			t.Run(c.typ+c.client+"/"+tc.check, func(t *testing.T) {
				f := tc.build(c.typ)
				f.client = c.client
				subject := c.typ + "/left-pad@1.3.0"
				if tc.subject != nil {
					subject = tc.subject(c.typ)
				}
				summary := "bodega refused " + subject + " (" + tc.check + ", incident " + pinnedIncident + "): " + tc.reason(c.typ)
				want := c.body(summary+" Next step: "+tc.next(c.typ), summary+"\nNext step: "+tc.next(c.typ)+"\n")

				rec := httptest.NewRecorder()
				f.write(rec, httptest.NewRequest(http.MethodGet, "/", nil))
				if rec.Code != tc.status {
					t.Errorf("status = %d, want %d", rec.Code, tc.status)
				}
				if got := rec.Header().Get(refusalHeader); got != tc.check+"; incident="+pinnedIncident {
					t.Errorf("%s = %q", refusalHeader, got)
				}
				if got := rec.Header().Get("Content-Type"); got != c.ctype {
					t.Errorf("Content-Type = %q, want %q", got, c.ctype)
				}
				if got := rec.Body.String(); got != want {
					t.Errorf("body:\n got %q\nwant %q", got, want)
				}
				if c.ctype == "application/json" && !json.Valid(rec.Body.Bytes()) {
					t.Errorf("body is not JSON: %s", rec.Body.String())
				}
			})
		}
	}
}

// TestRefusalBodiesCarryNoSecrets feeds every check the most revealing input
// its site holds (an upstream URL with userinfo on an internal host, a storage
// key, a bucket, a credential in an error) and asserts none of it reaches any
// client's body or header.
func TestRefusalBodiesCarryNoSecrets(t *testing.T) {
	const (
		cred     = "deploy:hunter2"
		host     = "mirror.corp.internal"
		bucket   = "bodega-prod-artifacts"
		upstream = "https://" + cred + "@" + host + "/debian/pool/main/h/hello/hello_2.10_amd64.deb"
	)
	key := manifest.AptKey("pool/main/h/hello/hello_2.10_amd64.deb")
	leaky := map[string]any{
		"published_at": "2026-10-05T12:00:00Z", "min_age_seconds": int64(86400),
		"queried": upstream, "vulns": []any{"GHSA-aaaa-bbbb-cccc"},
		"object_key": key, "bucket": "s3://" + bucket,
	}
	builds := []struct {
		check string
		build func(typ string) *refusal
	}{
		// The candidate a site passes: the package name for the package-rule
		// types, the upstream URL for the rest.
		{checkAllowList, func(typ string) *refusal {
			return allowListRefusal(typ, policy.CandidateFor(typ, "hello", upstream), "hello", "2.10")
		}},
		{checkAge, func(typ string) *refusal { return ageRefusal(typ, "hello", "2.10", leaky) }},
		{checkOSV, func(typ string) *refusal { return osvRefusal(typ, "hello", "2.10", leaky) }},
		{checkProfile, func(typ string) *refusal {
			p := entitle.New(&audit.ProfileDetail{Profile: audit.Profile{Name: "web"}})
			return profileRefusal(p, typ, "hello", "2.10", entitle.Decision{Governed: true, Refusal: entitle.RefusalConstraint,
				Reason: `profile "web" does not permit ` + typ + "/hello at 2.10: pinned to 2.9"})
		}},
		{checkHidden, func(typ string) *refusal { return hiddenRefusal(typ, "hello", "2.10") }},
		{checkFrozen, func(typ string) *refusal { return frozenRefusal(typ, "hello") }},
		{checkChecksum, func(typ string) *refusal {
			return checksumRefusal(typ, key, "hello", &checksumMismatchError{incident: "0123456789ab",
				msg: fmt.Sprintf("sha256 mismatch for %s in s3://%s fetched from %s", key, bucket, upstream)})
		}},
		// The checksum gate's other failure: the database holding the digest
		// is unreadable, and its error names where it lives.
		{checkChecksum, func(typ string) *refusal {
			return checksumRefusal(typ, key, "", fmt.Errorf("checksum lookup unavailable: open s3://%s/%s: %s", bucket, key, upstream))
		}},
		{checkConstraint, func(typ string) *refusal { return constraintRefusal(typ, "hello", "2.10", "~2.9") }},
		{checkChecksum, func(string) *refusal { return distfileRefusal("hello/2.10.tar.gz") }},
	}
	for _, typ := range []string{manifest.TypeNpm, manifest.TypeCargo, manifest.TypeGomod, manifest.TypeHelm, manifest.TypeApt, manifest.TypePypi, refusalClientAPI} {
		for _, b := range builds {
			check := b.check
			{
				pkgType := typ
				if typ == refusalClientAPI {
					pkgType = manifest.TypeApt
				}
				f := b.build(pkgType)
				if typ == refusalClientAPI {
					f.client = refusalClientAPI
				}
				rec := httptest.NewRecorder()
				f.write(rec, httptest.NewRequest(http.MethodGet, "/", nil))
				out := rec.Body.String() + rec.Header().Get(refusalHeader)
				for _, secret := range []string{cred, "hunter2", host, bucket, "s3://", key, upstream} {
					if strings.Contains(out, secret) {
						t.Errorf("%s/%s: the refusal carries %q:\n%s", typ, check, secret, out)
					}
				}
			}
		}
	}
}

// TestStatusLineClientsGetTheRefusalInThePhrase covers helm and apt, which
// print the status line and nothing else, and go, npm and cargo, which read
// the body and keep the ordinary phrase.
func TestStatusLineClientsGetTheRefusalInThePhrase(t *testing.T) {
	for _, tc := range []struct {
		typ    string
		inLine bool
	}{
		{manifest.TypeHelm, true}, {manifest.TypeApt, true}, {manifest.TypePypi, true},
		{manifest.TypeGomod, false}, {manifest.TypeNpm, false}, {manifest.TypeCargo, false},
	} {
		f := hiddenRefusal(tc.typ, "x", "1.0")
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.write(w, r) }))
		resp, err := http.Get(srv.URL)
		if err != nil {
			t.Fatalf("%s: GET: %v", tc.typ, err)
		}
		_ = resp.Body.Close()
		srv.Close()
		if got := strings.Contains(resp.Status, "(hidden, incident "+f.incident+")"); got != tc.inLine {
			t.Errorf("%s: status %q, want the refusal in the phrase: %v", tc.typ, resp.Status, tc.inLine)
		}
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status code %d, want 404", tc.typ, resp.StatusCode)
		}
	}
}

// TestPypiRefusalCarriesItInTheStatusLine drives pip's case over a raw
// connection, through the wrappers that sit between a pypi refusal and the
// socket: pip prints "403 Client Error: <reason phrase> for url: ...". The
// header and body are still there for anything that reads them.
func TestPypiRefusalCarriesItInTheStatusLine(t *testing.T) {
	pinIncident(t)
	f := allowListRefusal(manifest.TypePypi, "left-pad", "left-pad", "")
	rec := &responseRecorder{statusCode: http.StatusOK}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.ResponseWriter = w
		f.write(&pypiIndexWriter{ResponseWriter: &cacheDirectiveWriter{ResponseWriter: rec}}, r)
	}))
	t.Cleanup(srv.Close)

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	fmt.Fprintf(conn, "GET /pypi/simple/left-pad/ HTTP/1.1\r\nHost: x\r\n\r\n")
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	want := "HTTP/1.1 403 Forbidden - bodega refused pypi/left-pad (allow-list, incident " + pinnedIncident +
		`): pypi "left-pad" is not on this server's upstream allow-list.` + "\r\n"
	if status != want {
		t.Errorf("status line:\n got %q\nwant %q", status, want)
	}
	if rec.statusCode != http.StatusForbidden {
		t.Errorf("the wrapping recorder saw %d, want 403: the request log and the fetch audit would record a success", rec.statusCode)
	}

	resp, err := http.Get(srv.URL + "/pypi/simple/left-pad/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(resp.Status, "allow-list, incident "+pinnedIncident) {
		t.Errorf("status = %q", resp.Status)
	}
	refusalIncident(t, resp.Header, checkAllowList)
	var body strings.Builder
	_, _ = bufio.NewReader(resp.Body).WriteTo(&body)
	if body.String() != f.text() {
		t.Errorf("body = %q, want %q", body.String(), f.text())
	}
}

// TestReasonPhraseIsAValidStatusLine keeps the phrase inside what RFC 9112
// allows, whatever a package name smuggles in.
func TestReasonPhraseIsAValidStatusLine(t *testing.T) {
	f := allowListRefusal(manifest.TypePypi, "evil\r\nSet-Cookie: x=1\u00e9"+strings.Repeat("a", 600), "", "")
	p := f.reasonPhrase()
	if len(p) > maxReasonPhrase {
		t.Errorf("phrase is %d bytes, want at most %d", len(p), maxReasonPhrase)
	}
	for _, c := range []byte(p) {
		if c < 0x20 || c > 0x7e {
			t.Fatalf("phrase carries byte %#x: %q", c, p)
		}
	}
}

// The allow-list refusal on the proxy path, through the real chain: npm reads
// the JSON error field, and the incident there is the one in the row.
func TestAllowListRefusalMatchesItsRow(t *testing.T) {
	s := newDiscoveryServer(t)
	if err := s.store.AddVersion(t.Context(), manifest.TypeNpm, "leftpad", manifest.VersionEntry{
		Version: "1.2.0", Mode: manifest.ModeProxy,
	}); err != nil {
		t.Fatalf("seed manifest: %v", err)
	}
	if err := s.auditDB.InsertPolicy(t.Context(), audit.PolicyInfo{
		ID: "npm-elsewhere", RegistryType: manifest.TypeNpm, RuleKind: policy.KindPackage, Pattern: "rightpad",
	}); err != nil {
		t.Fatalf("insert policy: %v", err)
	}
	s.policy.Invalidate()

	rec := doRequest(s, http.MethodGet, "/npm/leftpad/-/leftpad-1.2.0.tgz", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	inc := refusalIncident(t, rec.Header(), checkAllowList)
	var body struct{ Error string }
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("npm body is not JSON: %v (%s)", err, rec.Body.String())
	}
	if !strings.Contains(body.Error, "(allow-list, incident "+inc+")") || !strings.Contains(body.Error, "bodega policy add npm leftpad") {
		t.Errorf("error = %q", body.Error)
	}
	rows, err := s.auditDB.Query(t.Context(), audit.Filter{EventType: audit.EventCache})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	for _, row := range rows {
		if row.Status == audit.CachePolicyViolation && strings.Contains(row.Details, "incident="+inc) {
			return
		}
	}
	t.Errorf("no policy_violation row carries incident %s: %+v", inc, rows)
}

// A hidden version answers 404, as hiding always has, and now says so and
// writes the row its incident names.
func TestHiddenRefusalMatchesItsRow(t *testing.T) {
	s := newDenialServer(t, []string{"127.0.0.0/8"}, nil)
	if err := s.store.AddVersion(t.Context(), manifest.TypeNpm, "leftpad", manifest.VersionEntry{
		Version: "1.2.0", Hidden: true, Mode: manifest.ModeProxy,
	}); err != nil {
		t.Fatalf("seed manifest: %v", err)
	}
	rec := doRequest(s, http.MethodGet, "/npm/leftpad/-/leftpad-1.2.0.tgz", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (%s)", rec.Code, rec.Body.String())
	}
	inc := refusalIncident(t, rec.Header(), checkHidden)
	details := wantOneDenial(t, s, audit.DenialHidden, "127.0.0.1")
	if details["incident"] != inc {
		t.Errorf("row incident = %q, want %q", details["incident"], inc)
	}
}

// A create the allow-list blocks answers the API's own JSON, naming the check
// and the incident admit wrote into its row.
func TestCreateRefusalMatchesItsRow(t *testing.T) {
	s := newDiscoveryServer(t)
	if err := s.auditDB.InsertPolicy(t.Context(), audit.PolicyInfo{
		ID: "cargo-elsewhere", RegistryType: manifest.TypeCargo, RuleKind: policy.KindPackage, Pattern: "serde",
	}); err != nil {
		t.Fatalf("insert policy: %v", err)
	}
	s.policy.Invalidate()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/packages/cargo",
		strings.NewReader(`{"name":"anyhow","versions":[{"version":"1.0.0"}]}`))
	req.RemoteAddr = "127.0.0.1:33333"
	req.SetPathValue("type", manifest.TypeCargo)
	rec := httptest.NewRecorder()
	s.handleCreateEntry(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	inc := refusalIncident(t, rec.Header(), checkAllowList)
	var body struct{ Error string }
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || !strings.Contains(body.Error, "incident "+inc) {
		t.Errorf("body = %s (%v)", rec.Body.String(), err)
	}
	rows, err := s.auditDB.Query(t.Context(), audit.Filter{EventType: audit.EventCreate})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) == 0 || !strings.Contains(rows[0].Details, "incident="+inc) {
		t.Errorf("create rows do not carry incident %s: %+v", inc, rows)
	}
}

func TestChecksumRefusalKeepsTheMismatchIncident(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", &checksumMismatchError{incident: "feedfacecafe", msg: "x"})
	if f := checksumRefusal(manifest.TypeApt, "", "hello", err); f.incident != "feedfacecafe" {
		t.Errorf("incident = %q, want the one the mismatch row was written under", f.incident)
	}
	if f := checksumRefusal(manifest.TypeApt, "", "hello", errors.New("db down")); f.incident == "" || f.incident == "feedfacecafe" {
		t.Errorf("an unreadable digest got incident %q, want a fresh one", f.incident)
	}
}

// stubAgeGate points the proxy fill's age gate at a registry that answers, for
// every ecosystem it dates, that each version was published an hour ago.
func stubAgeGate(t *testing.T) {
	t.Helper()
	at := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.HasPrefix(p, "/npm/"):
			_, _ = fmt.Fprintf(w, `{"time":{"1.2.0":%q}}`, at)
		case strings.HasPrefix(p, "/pypi/"):
			_, _ = fmt.Fprintf(w, `{"urls":[{"upload_time_iso_8601":%q}]}`, at)
		case strings.HasPrefix(p, "/go/"):
			_, _ = fmt.Fprintf(w, `{"Time":%q}`, at)
		case strings.HasPrefix(p, "/crates/"):
			_, _ = fmt.Fprintf(w, `{"version":{"created_at":%q}}`, at)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(stub.Close)
	prev := fetchCheckers
	fetchCheckers = func(_ *config.Config, adb *audit.DB) []policy.VersionChecker {
		ck := policy.NewAgeChecker(adb)
		ck.NpmRegistry, ck.PypiBase, ck.GoProxy, ck.CratesBase = stub.URL+"/npm", stub.URL, stub.URL+"/go", stub.URL+"/crates"
		ck.HTTP = stub.Client()
		return []policy.VersionChecker{ck}
	}
	t.Cleanup(func() { fetchCheckers = prev })
	// The real upstream guard refuses loopback, where the fixture upstream
	// runs; without this a gate that let the fetch through would still never
	// reach it, and the upstream hit count would prove nothing.
	saved := upstreamGuard
	upstreamGuard = func(rawURL string) error {
		if strings.HasPrefix(rawURL, "http://127.0.0.1:") {
			return nil
		}
		return saved(rawURL)
	}
	t.Cleanup(func() { upstreamGuard = saved })
}

// The age gate on the proxy fill path, through the real chain for each client
// it dates: the version is refused before upstream is contacted, the body is
// the one that client prints, and the incident is the one in the row.
func TestAgeRefusalOnProxyFillMatchesItsRow(t *testing.T) {
	for _, tc := range []struct {
		typ, name, path string
		incident        func(t *testing.T, rec *httptest.ResponseRecorder) string
	}{
		{manifest.TypeNpm, "leftpad", "/npm/leftpad/-/leftpad-1.2.0.tgz", func(t *testing.T, rec *httptest.ResponseRecorder) string {
			var body struct{ Error string }
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("npm body is not JSON: %v (%s)", err, rec.Body.String())
			}
			return bodyIncident(t, body.Error, checkAge)
		}},
		{manifest.TypeCargo, "itoa", "/cargo/itoa/1.2.0/download", func(t *testing.T, rec *httptest.ResponseRecorder) string {
			var body struct{ Errors []struct{ Detail string } }
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || len(body.Errors) != 1 {
				t.Fatalf("cargo body is not one error: %v (%s)", err, rec.Body.String())
			}
			return bodyIncident(t, body.Errors[0].Detail, checkAge)
		}},
		{manifest.TypeGomod, "example.com/mod", "/go/example.com/mod/@v/v1.2.0.info", func(t *testing.T, rec *httptest.ResponseRecorder) string {
			return bodyIncident(t, rec.Body.String(), checkAge)
		}},
		{manifest.TypePypi, "six", "/pypi/wheels/six-1.2.0-py2.py3-none-any.whl", func(t *testing.T, rec *httptest.ResponseRecorder) string {
			return bodyIncident(t, rec.Body.String(), checkAge)
		}},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			stubAgeGate(t)

			var hits atomic.Int32
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				http.NotFound(w, r)
			}))
			t.Cleanup(up.Close)
			s := newDiscoveryServer(t)
			s.cfg.NpmUpstream, s.cfg.PypiUpstream, s.cfg.GomodUpstream, s.cfg.CargoDLUpstream = up.URL, up.URL, up.URL, up.URL
			if tc.typ != manifest.TypeCargo {
				ver := "1.2.0"
				if tc.typ == manifest.TypeGomod {
					ver = "v1.2.0"
				}
				if err := s.store.AddVersion(t.Context(), tc.typ, tc.name, manifest.VersionEntry{Version: ver, Mode: manifest.ModeProxy}); err != nil {
					t.Fatalf("seed manifest: %v", err)
				}
			}
			if err := s.auditDB.SetAgePolicy(t.Context(), audit.AgePolicy{Ecosystem: tc.typ, MinAgeSeconds: 86400, Action: policy.ActionBlock}); err != nil {
				t.Fatalf("set age policy: %v", err)
			}

			rec := doRequest(s, http.MethodGet, tc.path, nil)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (%s)", rec.Code, rec.Body.String())
			}
			inc := refusalIncident(t, rec.Header(), checkAge)
			if got := tc.incident(t, rec); got != inc {
				t.Errorf("body incident %s, header incident %s", got, inc)
			}
			if !strings.Contains(rec.Body.String(), "becomes available on ") {
				t.Errorf("body names no date the version clears the gate:\n%s", rec.Body.String())
			}
			if n := hits.Load(); n != 0 {
				t.Errorf("upstream contacted %d times for a refused version", n)
			}
			rows, err := s.auditDB.Query(t.Context(), audit.Filter{EventType: audit.EventCache})
			if err != nil {
				t.Fatalf("query: %v", err)
			}
			for _, row := range rows {
				if row.Status == audit.CachePolicyViolation && strings.Contains(row.Details, `"incident":"`+inc+`"`) {
					return
				}
			}
			t.Errorf("no policy_violation row carries incident %s: %+v", inc, rows)
		})
	}
}

// A warn on the proxy fill path records and serves: the gate refuses only on
// the action the operator set.
func TestAgeWarnOnProxyFillServes(t *testing.T) {
	stubAgeGate(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "tarball") }))
	t.Cleanup(up.Close)
	s := newDiscoveryServer(t)
	s.cfg.NpmUpstream = up.URL
	if err := s.store.AddVersion(t.Context(), manifest.TypeNpm, "leftpad", manifest.VersionEntry{Version: "1.2.0", Mode: manifest.ModeProxy}); err != nil {
		t.Fatalf("seed manifest: %v", err)
	}
	if err := s.auditDB.SetAgePolicy(t.Context(), audit.AgePolicy{Ecosystem: manifest.TypeNpm, MinAgeSeconds: 86400, Action: policy.ActionWarn}); err != nil {
		t.Fatalf("set age policy: %v", err)
	}
	rec := doRequest(s, http.MethodGet, "/npm/leftpad/-/leftpad-1.2.0.tgz", nil)
	if rec.Code != http.StatusOK || rec.Header().Get(refusalHeader) != "" {
		t.Fatalf("status = %d, %s = %q, want 200 and no refusal (%s)", rec.Code, refusalHeader, rec.Header().Get(refusalHeader), rec.Body.String())
	}
	rows, err := s.auditDB.Query(t.Context(), audit.Filter{EventType: audit.EventCache})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	for _, row := range rows {
		if row.Status == "policy_warn" && row.PkgName == "leftpad" {
			return
		}
	}
	t.Errorf("no policy_warn row for the served version: %+v", rows)
}
