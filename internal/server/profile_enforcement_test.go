package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/entitle"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/storage"
)

// The enforcement tests drive the whole chain: a credential resolves to an
// identity, the identity resolves to a profile, and the profile decides. A
// unit test on entitle.Permits would pass against a tree where no handler
// consults it at all, which is the state F12 left and this item changes.

// profileFixture is one bound host: the credential its client sends and the
// profile the server resolves it to.
type profileFixture struct {
	s     *Server
	token string
}

// bindProfile writes a profile, its markers and its entries, issues a token
// and binds that token to an identity carrying the profile.
func bindProfile(t *testing.T, s *Server, profile, identity string, types []audit.ProfileTypeRule, entries []audit.ProfileEntry) *profileFixture {
	t.Helper()
	ctx := context.Background()
	for i := range types {
		types[i].Profile = profile
	}
	for i := range entries {
		entries[i].Profile = profile
	}
	if err := s.auditDB.CreateProfileWith(ctx, audit.Profile{Name: profile}, types, entries); err != nil {
		t.Fatalf("create profile %s: %v", profile, err)
	}
	token := "bodega_ak_" + profile
	tokenID := "tok-" + profile
	if err := s.auditDB.InsertToken(ctx, tokenID, profile, audit.HashToken(token, s.pepper), "", nil); err != nil {
		t.Fatalf("insert token for %s: %v", profile, err)
	}
	if _, err := s.auditDB.AddIdentityBinding(ctx, audit.IdentityBinding{
		Kind: audit.BindToken, Key: tokenID, Identity: identity,
	}); err != nil {
		t.Fatalf("bind identity %s: %v", identity, err)
	}
	if _, err := s.auditDB.BindProfile(ctx, audit.ProfileBinding{Identity: identity, Profile: profile}); err != nil {
		t.Fatalf("bind profile %s to %s: %v", profile, identity, err)
	}
	s.refreshIdentities(ctx)
	s.refreshProfiles(ctx)
	return &profileFixture{s: s, token: token}
}

// closedRule is the marker most of these tests want: a fixed set that refuses
// what is outside it. The default expansion is warn, so a test asserting a
// refusal has to say block; one that leaves it unset asserts the default.
func closedRule(typ, versionDefault, expansion string) audit.ProfileTypeRule {
	return audit.ProfileTypeRule{
		Type: typ, Membership: audit.MembershipClosed,
		VersionDefault: versionDefault, Expansion: expansion,
	}
}

// get issues one request carrying the fixture's credential, which is what
// makes the server resolve it to a profile.
func (f *profileFixture) get(t *testing.T, path string) (int, string) {
	t.Helper()
	return getWithToken(t, f.s, f.token, path)
}

func getWithToken(t *testing.T, s *Server, token, path string) (int, string) {
	t.Helper()
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+path, nil)
	if err != nil {
		t.Fatalf("build request for %s: %v", path, err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return resp.StatusCode, string(body)
}

// profileDenial returns the one denial row of the given status, failing when
// there is not exactly one.
func profileDenial(t *testing.T, s *Server, status string) audit.StoredEvent {
	t.Helper()
	rows, err := s.auditDB.Query(context.Background(), audit.Filter{EventType: audit.EventDenied})
	if err != nil {
		t.Fatalf("query denials: %v", err)
	}
	var found []audit.StoredEvent
	for _, r := range rows {
		if r.Status == status {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("denial rows with status %q = %d, want 1 (all rows: %+v)", status, len(found), rows)
	}
	return found[0]
}

func denialDetails(t *testing.T, row audit.StoredEvent) map[string]string {
	t.Helper()
	d := map[string]string{}
	if err := json.Unmarshal([]byte(row.Details), &d); err != nil {
		t.Fatalf("details %q is not JSON: %v", row.Details, err)
	}
	return d
}

func seed(t *testing.T, s *Server, typ string, objects map[string]string) {
	t.Helper()
	mem, ok := s.typeStore(typ).(*storage.Memory)
	if !ok {
		t.Fatalf("the %s store is %T, not the in-memory one these tests seed", typ, s.typeStore(typ))
	}
	for k, v := range objects {
		mem.Seed(k, v)
	}
}

func storedKeys(t *testing.T, s *Server, typ, prefix string) []string {
	t.Helper()
	keys, err := s.typeStore(typ).List(context.Background(), prefix)
	if err != nil {
		t.Fatalf("list %s: %v", prefix, err)
	}
	return keys
}

// A package the profile lists, at a version its rule permits, is served. This
// is the case every other assertion here is measured against: an enforcement
// that refuses everything would satisfy the refusal tests alone.
func TestProfilePermitsAListedPackage(t *testing.T) {
	s := proxyingServer(t)
	seed(t, s, manifest.TypePypi, map[string]string{
		"pypi/wheels/requests-2.31.0-py3-none-any.whl": "wheel",
	})
	f := bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypePypi, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{Type: manifest.TypePypi, Name: "requests"}})

	if status, body := f.get(t, "/pypi/wheels/requests-2.31.0-py3-none-any.whl"); status != http.StatusOK {
		t.Fatalf("a listed package at a permitted version answered %d: %s", status, body)
	}
}

// A package outside a closed, blocking set is refused, and the row and the
// body both say membership. The two refusals call for opposite repairs, so an
// operator who cannot tell them apart is guessing which lever to pull.
func TestProfileMembershipRefusalIsDistinguishable(t *testing.T) {
	s := proxyingServer(t)
	seed(t, s, manifest.TypePypi, map[string]string{
		"pypi/wheels/django-5.0.0-py3-none-any.whl": "wheel",
	})
	f := bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypePypi, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{Type: manifest.TypePypi, Name: "requests"}})

	status, body := f.get(t, "/pypi/wheels/django-5.0.0-py3-none-any.whl")
	if status != http.StatusForbidden {
		t.Fatalf("a package outside the closed set answered %d, want 403: %s", status, body)
	}
	for _, want := range []string{"membership", "web", "django", "bodega profile add web pypi django"} {
		if !strings.Contains(body, want) {
			t.Errorf("the refusal body does not mention %q:\n%s", want, body)
		}
	}
	row := profileDenial(t, s, audit.DenialProfileMembership)
	if row.PkgType != manifest.TypePypi || row.PkgName != "django" || row.PkgVersion != "5.0.0" {
		t.Errorf("the row names %s/%s@%s, want pypi/django@5.0.0", row.PkgType, row.PkgName, row.PkgVersion)
	}
	if row.Identity != "web01" {
		t.Errorf("the row names identity %q, want web01", row.Identity)
	}
	details := denialDetails(t, row)
	if details["profile"] != "web" {
		t.Errorf("the row does not name the profile that refused: %v", details)
	}
	if details["rule"] != "membership" {
		t.Errorf("the row does not name the rule that refused: %v", details)
	}
}

// A version outside an entry's constraint is refused under a different status
// and a different body, from the same route the membership refusal came from.
func TestProfileConstraintRefusalIsDistinguishable(t *testing.T) {
	s := proxyingServer(t)
	seed(t, s, manifest.TypePypi, map[string]string{
		"pypi/wheels/requests-2.32.0-py3-none-any.whl": "wheel",
	})
	f := bindProfile(t, s, "db", "db01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypePypi, audit.VersionPinned, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{
			Type: manifest.TypePypi, Name: "requests",
			Constraint: manifest.ConstraintExact, Version: "2.31.0",
		}})

	status, body := f.get(t, "/pypi/wheels/requests-2.32.0-py3-none-any.whl")
	if status != http.StatusForbidden {
		t.Fatalf("a version outside the constraint answered %d, want 403: %s", status, body)
	}
	for _, want := range []string{"constraint", "2.31.0", "bodega profile pin db pypi requests"} {
		if !strings.Contains(body, want) {
			t.Errorf("the refusal body does not mention %q:\n%s", want, body)
		}
	}
	row := profileDenial(t, s, audit.DenialProfileConstraint)
	if row.PkgVersion != "2.32.0" {
		t.Errorf("the row names version %q, want the one that was asked for", row.PkgVersion)
	}
	details := denialDetails(t, row)
	if details["rule"] != "constraint" {
		t.Errorf("the row does not name the rule that refused: %v", details)
	}
	if details["entry_version"] != "2.31.0" {
		t.Errorf("the row does not name the version the entry holds: %v", details)
	}
}

// Requirements 5 and 6 together. The default expansion serves the fetch and
// records the reach, so the detection half works before anyone trusts the
// enforcement half — and the row reads as "this host went outside its class"
// rather than as a catalog gap.
func TestProfileWarnServesAndRecordsTheReach(t *testing.T) {
	s := proxyingServer(t)
	seed(t, s, manifest.TypePypi, map[string]string{
		"pypi/wheels/django-5.0.0-py3-none-any.whl": "wheel",
	})
	f := bindProfile(t, s, "web", "web01",
		// No expansion named: this is the default the column carries.
		[]audit.ProfileTypeRule{{
			Type: manifest.TypePypi, Membership: audit.MembershipClosed,
			VersionDefault: audit.VersionFloating,
		}},
		[]audit.ProfileEntry{{Type: manifest.TypePypi, Name: "requests"}})

	if status, body := f.get(t, "/pypi/wheels/django-5.0.0-py3-none-any.whl"); status != http.StatusOK {
		t.Fatalf("the default expansion refused an unlisted package with %d: %s", status, body)
	}
	rows := waitForDecision(t, s, audit.DecisionDenied, 1)
	if rows[0].PkgName != "django" {
		t.Errorf("the discovery row names %q, want django", rows[0].PkgName)
	}
	if rows[0].LastIdentity != "web01" {
		t.Errorf("the discovery row names identity %q, want web01", rows[0].LastIdentity)
	}
	if !strings.Contains(rows[0].PatternHint, "bodega profile add web pypi django") {
		t.Errorf("the row does not carry the command that closes it: %q", rows[0].PatternHint)
	}
}

// waitForDecision polls until at least want discovery rows carry a decision,
// because the recorder writes off the request goroutine.
func waitForDecision(t *testing.T, s *Server, decision string, want int) []audit.DiscoveryRow {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var rows []audit.DiscoveryRow
	for time.Now().Before(deadline) {
		var err error
		rows, err = s.auditDB.ListDiscovery(context.Background(), audit.DiscoveryFilter{Decision: decision})
		if err != nil {
			t.Fatalf("list discovery: %v", err)
		}
		if len(rows) >= want {
			return rows
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("discovery rows with decision %q = %d, want %d", decision, len(rows), want)
	return nil
}

// The pypi root index names no version, so it is decided at the membership
// level: a host bound to a closed profile sees the packages its profile lists
// and nothing else.
func TestProfileFiltersThePypiRootIndex(t *testing.T) {
	s := proxyingServer(t)
	seed(t, s, manifest.TypePypi, map[string]string{
		"pypi/wheels/requests-2.31.0-py3-none-any.whl": "wheel",
		"pypi/wheels/django-5.0.0-py3-none-any.whl":    "wheel",
	})
	f := bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypePypi, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{Type: manifest.TypePypi, Name: "requests"}})

	status, body := f.get(t, "/pypi/simple/")
	if status != http.StatusOK {
		t.Fatalf("the root index answered %d: %s", status, body)
	}
	if !strings.Contains(body, "requests") {
		t.Errorf("the root index dropped a package the profile lists:\n%s", body)
	}
	if strings.Contains(body, "django") {
		t.Errorf("the root index lists a package outside the closed set:\n%s", body)
	}

	// The same request with no credential resolves to no profile and keeps
	// today's document, which is what makes an install with no profiles free.
	if _, plain := getWithToken(t, s, "", "/pypi/simple/"); !strings.Contains(plain, "django") {
		t.Errorf("an unidentified request was filtered:\n%s", plain)
	}
}

// The per-distribution page carries versions, so it is filtered by the version
// rule: pip is told the versions it may have and picks among them, rather than
// resolving one bodega then refuses mid-install.
func TestProfileFiltersThePypiDistributionPage(t *testing.T) {
	s := proxyingServer(t)
	seed(t, s, manifest.TypePypi, map[string]string{
		"pypi/wheels/requests-2.31.0-py3-none-any.whl": "wheel",
		"pypi/wheels/requests-2.32.0-py3-none-any.whl": "wheel",
	})
	f := bindProfile(t, s, "db", "db01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypePypi, audit.VersionPinned, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{
			Type: manifest.TypePypi, Name: "requests",
			Constraint: manifest.ConstraintExact, Version: "2.31.0",
		}})

	status, body := f.get(t, "/pypi/simple/requests/")
	if status != http.StatusOK {
		t.Fatalf("the distribution page answered %d: %s", status, body)
	}
	if !strings.Contains(body, "requests-2.31.0") {
		t.Errorf("the page dropped the pinned version:\n%s", body)
	}
	if strings.Contains(body, "requests-2.32.0") {
		t.Errorf("the page lists a version the pin refuses:\n%s", body)
	}
}

// A source distribution of the pinned version is the pinned version. Reading
// it as a wheel left the archive suffix on the version ("5.0.0.tar.gz"), which
// matches no constraint an operator can write, so the pin refused the file it
// was written to allow — and for a distribution publishing no wheel that is
// every file on the page.
//
// The page and the artifact are asserted together because they are the index
// and the route for one file: either one disagreeing is a client told one
// thing and served another.
func TestProfilePermitsTheSdistOfThePinnedVersion(t *testing.T) {
	s := proxyingServer(t)
	up := newRecordingUpstream(t)
	const sdist = "django-5.0.0.tar.gz"
	up.route("/simple/django/", fmt.Sprintf(
		`<!DOCTYPE html><html><body>`+
			`<a href="%[1]s/files/django-5.0.0-py3-none-any.whl">django-5.0.0-py3-none-any.whl</a><br/>`+
			`<a href="%[1]s/files/django-5.0.0.tar.gz">django-5.0.0.tar.gz</a><br/>`+
			`<a href="%[1]s/files/django-6.0.0.tar.gz">django-6.0.0.tar.gz</a><br/>`+
			`</body></html>`, up.ts.URL))
	up.route("/files/"+sdist, "sdist bytes")
	s.cfg.PypiUpstream = up.ts.URL
	if err := s.store.SavePackage(t.Context(), &manifest.PackageManifest{
		ConfigVersion: manifest.CurrentConfigVersion,
		Name:          "django",
		Type:          manifest.TypePypi,
		Versions:      []manifest.VersionEntry{{Version: "5.0.0", URL: up.ts.URL, Mode: manifest.ModeProxy}},
	}); err != nil {
		t.Fatalf("seed the django manifest: %v", err)
	}

	f := bindProfile(t, s, "pinned", "pinned01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypePypi, audit.VersionPinned, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{
			Type: manifest.TypePypi, Name: "django",
			Constraint: manifest.ConstraintExact, Version: "5.0.0",
		}})

	status, body := f.get(t, "/pypi/simple/django/")
	if status != http.StatusOK {
		t.Fatalf("the distribution page answered %d: %s", status, body)
	}
	if !strings.Contains(body, sdist) {
		t.Errorf("the page dropped the sdist of the pinned version:\n%s", body)
	}
	if strings.Contains(body, "django-6.0.0.tar.gz") {
		t.Errorf("the page lists an sdist the pin refuses:\n%s", body)
	}

	if status, body := f.get(t, "/pypi/wheels/"+sdist); status != http.StatusOK {
		t.Fatalf("the sdist of the pinned version answered %d, want 200: %s", status, body)
	}
	status, body = f.get(t, "/pypi/wheels/django-6.0.0.tar.gz")
	if status != http.StatusForbidden {
		t.Fatalf("an sdist outside the pin answered %d, want 403: %s", status, body)
	}
	if !strings.Contains(body, "constraint") {
		t.Errorf("the refusal does not name the rule:\n%s", body)
	}
}

// The parse the page filter and the artifact route share. A version that comes
// back carrying an archive suffix is compared to a constraint that can never
// match it, so every row here is a refusal or a hidden file when it is wrong.
func TestWheelIdentityPlacesSdistsAndWheels(t *testing.T) {
	for _, tc := range []struct{ file, dist, version string }{
		{"django-5.0.0-py3-none-any.whl", "django", "5.0.0"},
		{"django-5.0.0.tar.gz", "django", "5.0.0"},
		{"django-5.0.0.zip", "django", "5.0.0"},
		// PEP 625 normalizes the hyphens out of a project name; the files that
		// predate it are still on the index.
		{"backports-abc-0.5.tar.gz", "backports-abc", "0.5"},
		{"foo-1.0-beta1.tar.bz2", "foo", "1.0-beta1"},
		// A hyphen followed by a digit is not a version: python-3parclient is
		// one package on pypi and 3parclient-4.2.10 is no version of another.
		{"python-3parclient-4.2.10.tar.gz", "python-3parclient", "4.2.10"},
		// The same rule read right to left, which is what keeps the numeric
		// tail of a project name out of the version.
		{"sphinxcontrib-2048-0.1.tar.gz", "sphinxcontrib-2048", "0.1"},
		{"py2neo-2021.2.3.tar.gz", "py2neo", "2021.2.3"},
		// Nothing to place: decided on membership alone rather than against a
		// version this could only have guessed at.
		{"django.tar.gz", "django.tar.gz", ""},
	} {
		dist, version := wheelIdentity(tc.file)
		if dist != tc.dist || version != tc.version {
			t.Errorf("wheelIdentity(%q) = %q, %q; want %q, %q", tc.file, dist, version, tc.dist, tc.version)
		}
	}
}

const npmProfilePackument = `{
  "name": "left-pad",
  "dist-tags": {"latest": "1.3.0"},
  "versions": {
    "1.2.0": {"version": "1.2.0", "dist": {"tarball": "%[1]s/left-pad/-/left-pad-1.2.0.tgz"}},
    "1.3.0": {"version": "1.3.0", "dist": {"tarball": "%[1]s/left-pad/-/left-pad-1.3.0.tgz"}}
  }
}`

func TestProfileFiltersTheNpmPackument(t *testing.T) {
	s := proxyingServer(t)
	up := newRecordingUpstream(t)
	up.route("/left-pad", fmt.Sprintf(npmProfilePackument, up.ts.URL))
	s.cfg.NpmUpstream = up.ts.URL

	f := bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeNpm, audit.VersionPinned, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{
			Type: manifest.TypeNpm, Name: "left-pad",
			Constraint: manifest.ConstraintExact, Version: "1.2.0",
		}})

	status, body := f.get(t, "/npm/left-pad")
	if status != http.StatusOK {
		t.Fatalf("the packument answered %d: %s", status, body)
	}
	var doc struct {
		DistTags map[string]string          `json:"dist-tags"`
		Versions map[string]json.RawMessage `json:"versions"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("the filtered packument is not JSON: %v\n%s", err, body)
	}
	if _, ok := doc.Versions["1.2.0"]; !ok {
		t.Errorf("the packument dropped the pinned version:\n%s", body)
	}
	if _, ok := doc.Versions["1.3.0"]; ok {
		t.Errorf("the packument lists a version the pin refuses:\n%s", body)
	}
	// A dist-tag naming a dropped version is npm's instruction to install it,
	// so leaving it behind would resolve exactly what the filter removed.
	if _, ok := doc.DistTags["latest"]; ok {
		t.Errorf("latest still points at a version the profile refuses:\n%s", body)
	}
}

func TestProfileFiltersTheGomodList(t *testing.T) {
	s := proxyingServer(t)
	up := newRecordingUpstream(t)
	up.route("/example.com/mod/@v/list", "v1.0.0\nv1.1.0\nv2.0.0\n")
	s.cfg.GomodUpstream = up.ts.URL
	if err := s.store.SavePackage(t.Context(), &manifest.PackageManifest{
		ConfigVersion: manifest.CurrentConfigVersion,
		Name:          "example.com/mod",
		Type:          manifest.TypeGomod,
		Versions:      []manifest.VersionEntry{{Version: "v1.0.0", Mode: manifest.ModeProxy}},
	}); err != nil {
		t.Fatalf("seed the gomod manifest: %v", err)
	}

	f := bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeGomod, audit.VersionPinned, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{
			Type: manifest.TypeGomod, Name: "example.com/mod",
			Constraint: manifest.ConstraintExact, Version: "v1.1.0",
		}})

	status, body := f.get(t, "/go/example.com/mod/@v/list")
	if status != http.StatusOK {
		t.Fatalf("the module list answered %d: %s", status, body)
	}
	if strings.TrimSpace(body) != "v1.1.0" {
		t.Errorf("the module list is %q, want the pinned version alone", body)
	}
}

func TestProfileFiltersTheCargoIndex(t *testing.T) {
	s := proxyingServer(t)
	up := newRecordingUpstream(t)
	up.route("/se/rd/serde", `{"name":"serde","vers":"1.0.0","cksum":"a"}`+"\n"+
		`{"name":"serde","vers":"2.0.0","cksum":"b"}`+"\n")
	s.cfg.CargoUpstream = up.ts.URL

	f := bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeCargo, audit.VersionPinned, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{
			Type: manifest.TypeCargo, Name: "serde",
			Constraint: manifest.ConstraintExact, Version: "1.0.0",
		}})

	status, body := f.get(t, "/cargo/se/rd/serde")
	if status != http.StatusOK {
		t.Fatalf("the sparse index answered %d: %s", status, body)
	}
	if !strings.Contains(body, `"vers":"1.0.0"`) {
		t.Errorf("the index dropped the pinned release:\n%s", body)
	}
	if strings.Contains(body, `"vers":"2.0.0"`) {
		t.Errorf("the index lists a release the pin refuses:\n%s", body)
	}
}

const helmProfileIndex = `apiVersion: v1
entries:
  cert-manager:
  - name: cert-manager
    version: 1.14.0
    urls:
    - charts/cert-manager-1.14.0.tgz
  - name: cert-manager
    version: 1.15.0
    urls:
    - charts/cert-manager-1.15.0.tgz
  redis:
  - name: redis
    version: 19.0.0
    urls:
    - charts/redis-19.0.0.tgz
generated: "2026-01-01T00:00:00Z"
`

func TestProfileFiltersTheHelmIndex(t *testing.T) {
	s := proxyingServer(t)
	seed(t, s, manifest.TypeHelm, map[string]string{manifest.HelmIndexKey: helmProfileIndex})

	f := bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeHelm, audit.VersionPinned, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{
			Type: manifest.TypeHelm, Name: "cert-manager",
			Constraint: manifest.ConstraintExact, Version: "1.14.0",
		}})

	status, body := f.get(t, "/helm/index.yaml")
	if status != http.StatusOK {
		t.Fatalf("the chart index answered %d: %s", status, body)
	}
	if !strings.Contains(body, "version: 1.14.0") {
		t.Errorf("the index dropped the pinned release:\n%s", body)
	}
	if strings.Contains(body, "version: 1.15.0") {
		t.Errorf("the index lists a release the pin refuses:\n%s", body)
	}
	if strings.Contains(body, "redis") {
		t.Errorf("the index lists a chart outside the closed set:\n%s", body)
	}
	if !strings.Contains(body, "apiVersion: v1") {
		t.Errorf("the filter ate the document header:\n%s", body)
	}
	// `helm repo index` writes generated: after the entries block, where a
	// filter reading every line inside entries as release content drops it
	// with whichever chart came last.
	if !strings.Contains(body, "generated:") {
		t.Errorf("the filter ate a top-level key following the entries block:\n%s", body)
	}
}

// The hazard with no error attached: two host classes, one package, two
// documents. The assertion is on the cached bytes rather than on the two
// response bodies, because a body comparison passes whenever the two profiles
// happen to agree, and it passes just as well against a tree that stores one
// host's filtered document where the other will read it.
//
// What keeps that from happening is that no filtered document is ever stored:
// the filter runs over the buffered response on the way out, so the cache
// holds the upstream's index and one fetch answers every profile.
func TestTwoProfilesGetTwoDocumentsFromOneCachedIndex(t *testing.T) {
	s := proxyingServer(t)
	up := newRecordingUpstream(t)
	const upstreamIndex = `{"name":"serde","vers":"1.0.0","cksum":"a"}` + "\n" +
		`{"name":"serde","vers":"2.0.0","cksum":"b"}` + "\n"
	up.route("/se/rd/serde", upstreamIndex)
	s.cfg.CargoUpstream = up.ts.URL

	held := bindProfile(t, s, "held", "held01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeCargo, audit.VersionPinned, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{
			Type: manifest.TypeCargo, Name: "serde",
			Constraint: manifest.ConstraintExact, Version: "1.0.0",
		}})
	tracking := bindProfile(t, s, "tracking", "tracking01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeCargo, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{Type: manifest.TypeCargo, Name: "serde"}})

	_, heldBody := held.get(t, "/cargo/se/rd/serde")
	_, trackingBody := tracking.get(t, "/cargo/se/rd/serde")
	if strings.Contains(heldBody, `"vers":"2.0.0"`) {
		t.Errorf("the held profile was served the tracking profile's view:\n%s", heldBody)
	}
	if !strings.Contains(trackingBody, `"vers":"2.0.0"`) {
		t.Errorf("the tracking profile lost a release nothing refuses:\n%s", trackingBody)
	}

	base := manifest.CargoIndexKey("se/rd/serde")
	keys := storedKeys(t, s, manifest.TypeCargo, "")
	if len(keys) != 1 || keys[0] != base {
		t.Fatalf("the cargo store holds %v, want the one upstream index at %q", keys, base)
	}
	if got := storedObject(t, s, manifest.TypeCargo, base); got != upstreamIndex {
		t.Errorf("the cached index is a filtered document; served from here a second host class\n"+
			"gets a document that is valid, parseable and wrong about what it may install:\n%s", got)
	}
	if n := len(up.paths()); n != 1 {
		t.Errorf("the upstream index was fetched %d times for 2 profiles: %v", n, up.paths())
	}

	// An unidentified request resolves to no profile, reads the same cached
	// object and is filtered by nothing, so an install with no profiles pays
	// neither a fetch nor a stored copy for this feature.
	if _, body := getWithToken(t, s, "", "/cargo/se/rd/serde"); body != upstreamIndex {
		t.Errorf("an unidentified request was filtered:\n%s", body)
	}
	if keys := storedKeys(t, s, manifest.TypeCargo, ""); len(keys) != 1 {
		t.Errorf("an unidentified request added a cache entry: %v", keys)
	}
}

func storedObject(t *testing.T, s *Server, typ, key string) string {
	t.Helper()
	data, err := s.typeStore(typ).Get(context.Background(), key)
	if err != nil {
		t.Fatalf("read %s: %v", key, err)
	}
	return string(data)
}

// The helm index answers 200 under a profile that permits no chart at all.
//
// A 403 here fails `helm repo add` rather than the install, and helm prints
// neither the profile nor a chart name, so the operator gets "not a valid
// chart repository" for a repository that is valid and a policy they cannot
// see. The empty index sends them to `helm search repo`; the chart pull
// carries the refusal. docs/USAGE.md documents both, and this asserts the
// server still produces what it documents.
func TestHelmIndexIsNotRefusedByAProfile(t *testing.T) {
	s := proxyingServer(t)
	seed(t, s, manifest.TypeHelm, map[string]string{manifest.HelmIndexKey: helmProfileIndex})

	f := bindProfile(t, s, "locked", "locked01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeHelm, audit.VersionFloating, audit.ExpansionBlock)}, nil)

	status, body := f.get(t, "/helm/index.yaml")
	if status != http.StatusOK {
		t.Fatalf("the chart index answered %d under a blocking profile, want 200: %s", status, body)
	}
	if !strings.Contains(body, "apiVersion: v1") {
		t.Errorf("the index is not a chart repository document:\n%s", body)
	}
	for _, gone := range []string{"cert-manager", "redis"} {
		if strings.Contains(body, gone) {
			t.Errorf("the index lists %s, which the closed set does not carry:\n%s", gone, body)
		}
	}
	if !strings.Contains(body, "generated:") {
		t.Errorf("the filter ate a top-level key following the entries block:\n%s", body)
	}
	// The refusal an operator meets is the pull, and that one names the repair.
	status, body = f.get(t, "/helm/charts/cert-manager-1.14.0.tgz")
	if status != http.StatusForbidden {
		t.Fatalf("the chart pull answered %d, want 403: %s", status, body)
	}
}

// Requirement 1, and the thing a per-handler test cannot show: the predicate
// is on every package route for all seven types. A route that never calls it
// serves the artifact and passes every other test in this file.
//
// apt is absent on purpose. Refusing an apt fetch at the pool leaves dpkg
// holding a half-configured transaction, so that control belongs at the index
// and is its own item; a route added here would make the refusal worse than
// no control at all.
func TestProfileGateRunsOnEveryPackageRoute(t *testing.T) {
	s := proxyingServer(t)
	seed(t, s, manifest.TypePypi, map[string]string{
		"pypi/wheels/django-5.0.0-py3-none-any.whl": "wheel",
	})
	seed(t, s, manifest.TypeNpm, map[string]string{
		"npm/left-pad/left-pad-1.3.0.tgz": "tarball",
	})
	seed(t, s, manifest.TypeHelm, map[string]string{
		"charts/redis-19.0.0.tgz": "chart",
	})
	seed(t, s, manifest.TypeGit, map[string]string{
		"repos/netbox/netbox-v4.5.5.bundle": "bundle",
	})
	seed(t, s, manifest.TypeBinary, map[string]string{
		"binaries/awscli-v2/2.0.0/awscli.zip": "binary",
	})

	var types []audit.ProfileTypeRule
	for _, typ := range []string{
		manifest.TypePypi, manifest.TypeNpm, manifest.TypeGomod, manifest.TypeCargo,
		manifest.TypeHelm, manifest.TypeGit, manifest.TypeBinary,
	} {
		types = append(types, closedRule(typ, audit.VersionFloating, audit.ExpansionBlock))
	}
	// A closed set with nothing listed, which is what makes every route below
	// answer the same way for the same reason.
	f := bindProfile(t, s, "locked", "locked01", types, nil)

	for _, tc := range []struct{ typ, path string }{
		{manifest.TypePypi, "/pypi/wheels/django-5.0.0-py3-none-any.whl"},
		{manifest.TypeNpm, "/npm/left-pad/-/left-pad-1.3.0.tgz"},
		{manifest.TypeGomod, "/go/example.com/mod/@v/v1.0.0.info"},
		{manifest.TypeCargo, "/cargo/serde/1.0.0/download"},
		{manifest.TypeHelm, "/helm/charts/redis-19.0.0.tgz"},
		{manifest.TypeGit, "/git/netbox/netbox-v4.5.5.bundle"},
		{manifest.TypeBinary, "/binaries/awscli-v2/2.0.0/awscli.zip"},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			status, body := f.get(t, tc.path)
			if status != http.StatusForbidden {
				t.Fatalf("%s answered %d, want 403 — this route does not consult the profile: %s",
					tc.path, status, body)
			}
			if !strings.Contains(body, "membership") {
				t.Errorf("%s refused without naming the rule:\n%s", tc.path, body)
			}
		})
	}
}

// getHeaderWithToken is getWithToken's header half. The cache assertions below
// are about what a proxy is told, and a second client's body proves nothing on
// a server with no cache in front of it, which is every test server.
func getHeaderWithToken(t *testing.T, s *Server, token, path string) (int, http.Header) {
	t.Helper()
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+path, nil)
	if err != nil {
		t.Fatalf("build request for %s: %v", path, err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, resp.Header
}

// cacheProbeServer seeds one artifact and one index per enforced type and
// binds a profile that permits all of them, so every assertion below is made
// against a 200 rather than against a refusal that happens to carry no header.
func cacheProbeServer(t *testing.T) *profileFixture {
	t.Helper()
	s := proxyingServer(t)

	up := newRecordingUpstream(t)
	up.route("/left-pad", fmt.Sprintf(npmProfilePackument, up.ts.URL))
	up.route("/se/rd/serde", `{"name":"serde","vers":"1.0.0","cksum":"a"}`+"\n")
	up.route("/example.com/mod/@v/list", "v1.0.0\n")
	up.route("/example.com/mod/@v/v1.0.0.info", `{"Version":"v1.0.0"}`)
	s.cfg.NpmUpstream = up.ts.URL
	s.cfg.CargoUpstream = up.ts.URL
	s.cfg.GomodUpstream = up.ts.URL

	seed(t, s, manifest.TypePypi, map[string]string{
		"pypi/wheels/requests-2.31.0-py3-none-any.whl": "wheel",
	})
	seed(t, s, manifest.TypeNpm, map[string]string{
		manifest.NpmTarballKey("left-pad", "1.2.0"): "tarball",
	})
	seed(t, s, manifest.TypeHelm, map[string]string{
		manifest.HelmIndexKey:                           helmProfileIndex,
		manifest.HelmChartKey("cert-manager", "1.14.0"): "chart",
	})
	seed(t, s, manifest.TypeGit, map[string]string{
		manifest.GitKey("repo", "v1.0.0", false): "bundle",
	})
	seed(t, s, manifest.TypeCargo, map[string]string{
		manifest.CargoCrateKey("serde", "1.0.0"): "crate",
	})
	seed(t, s, manifest.TypeBinary, map[string]string{
		manifest.BinaryKey("tool", "1.0.0", "tool.tar.gz"): "binary",
	})
	if err := s.store.AddVersion(t.Context(), manifest.TypeCargo, "serde",
		manifest.VersionEntry{Version: "1.0.0"}); err != nil {
		t.Fatalf("AddVersion serde: %v", err)
	}
	if err := s.store.SavePackage(t.Context(), &manifest.PackageManifest{
		ConfigVersion: manifest.CurrentConfigVersion,
		Name:          "example.com/mod",
		Type:          manifest.TypeGomod,
		Versions:      []manifest.VersionEntry{{Version: "v1.0.0", Mode: manifest.ModeProxy}},
	}); err != nil {
		t.Fatalf("seed the gomod manifest: %v", err)
	}

	rules := []audit.ProfileTypeRule{
		closedRule(manifest.TypePypi, audit.VersionFloating, audit.ExpansionBlock),
		closedRule(manifest.TypeNpm, audit.VersionFloating, audit.ExpansionBlock),
		closedRule(manifest.TypeHelm, audit.VersionFloating, audit.ExpansionBlock),
		closedRule(manifest.TypeGit, audit.VersionFloating, audit.ExpansionBlock),
		closedRule(manifest.TypeCargo, audit.VersionFloating, audit.ExpansionBlock),
		closedRule(manifest.TypeGomod, audit.VersionFloating, audit.ExpansionBlock),
		closedRule(manifest.TypeBinary, audit.VersionFloating, audit.ExpansionBlock),
	}
	entries := []audit.ProfileEntry{
		{Type: manifest.TypePypi, Name: "requests"},
		{Type: manifest.TypeNpm, Name: "left-pad"},
		{Type: manifest.TypeHelm, Name: "cert-manager"},
		{Type: manifest.TypeGit, Name: "repo"},
		{Type: manifest.TypeCargo, Name: "serde"},
		{Type: manifest.TypeGomod, Name: "example.com/mod"},
		{Type: manifest.TypeBinary, Name: "tool"},
	}
	return bindProfile(t, s, "probe", "probe01", rules, entries)
}

// The profile decides what a URL returns, so a shared cache must be kept out
// of every response it decides. Before this, an artifact went out marked
// "public, max-age=31536000, immutable" — one host's wheel stored by an nginx
// in front and handed to a host of another class for a year, with no row
// written and no error raised anywhere. RFC 9111 §3.5 would have withheld
// storage from a request carrying Authorization; "public" is what opted back
// in, and a CIDR-identified host never sent a credential to be covered by that
// clause in the first place.
//
// Asserted on the header rather than on a second client's body: a body
// comparison passes against any server with no cache in front of it.
func TestProfileEnforcedRoutesKeepASharedCacheOut(t *testing.T) {
	f := cacheProbeServer(t)

	t.Run("artifacts", func(t *testing.T) {
		for _, tc := range []struct{ path, want string }{
			{"/pypi/wheels/requests-2.31.0-py3-none-any.whl", cachePrivateImmutable},
			{"/npm/left-pad/-/left-pad-1.2.0.tgz", cachePrivateImmutable},
			{"/helm/charts/cert-manager-1.14.0.tgz", cachePrivateImmutable},
			{"/git/repo/repo-v1.0.0.bundle", cachePrivateImmutable},
			// Neither filename earns a freshness lifetime, and both still
			// answer the separate question of who may store the bytes.
			{"/cargo/serde/1.0.0/download", cachePrivate},
			{"/binaries/tool/1.0.0/tool.tar.gz", cachePrivate},
			{"/go/example.com/mod/@v/v1.0.0.info", cachePrivate},
		} {
			status, hdr := getHeaderWithToken(t, f.s, f.token, tc.path)
			if status != http.StatusOK {
				t.Errorf("GET %s = %d, want 200", tc.path, status)
				continue
			}
			if got := hdr.Get("Cache-Control"); got != tc.want {
				t.Errorf("GET %s Cache-Control = %q, want %q", tc.path, got, tc.want)
			}
		}
	})

	// Every index route, identified and not. Gated on a profile being bound, a
	// cache filled by an unidentified request would still answer a profiled
	// one, which is the same bypass arriving by a longer road.
	t.Run("indexes", func(t *testing.T) {
		for _, path := range []string{
			"/pypi/simple/",
			"/pypi/simple/requests/",
			"/npm/left-pad",
			"/go/example.com/mod/@v/list",
			"/cargo/se/rd/serde",
			"/helm/index.yaml",
		} {
			for _, token := range []string{f.token, ""} {
				status, hdr := getHeaderWithToken(t, f.s, token, path)
				if status != http.StatusOK {
					t.Errorf("GET %s (token %q) = %d, want 200", path, token, status)
					continue
				}
				if got := hdr.Get("Cache-Control"); got != cacheNoStore {
					t.Errorf("GET %s (token %q) Cache-Control = %q, want %q", path, token, got, cacheNoStore)
				}
			}
		}
	})
}

// A project whose name carries a hyphen followed by a digit, which the split
// used to read as a version. All three assertions fail the same way when it
// does: the profile decides about a package nobody named.
func TestProfileDecidesAboutTheWholeHyphenatedName(t *testing.T) {
	const sdist = "python-3parclient-4.2.10.tar.gz"

	listed := proxyingServer(t)
	seed(t, listed, manifest.TypePypi, map[string]string{"pypi/wheels/" + sdist: "sdist bytes"})
	f := bindProfile(t, listed, "ops", "ops01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypePypi, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{
			Type: manifest.TypePypi, Name: "python-3parclient",
			Constraint: manifest.ConstraintAny,
		}})
	if status, body := f.get(t, "/pypi/wheels/"+sdist); status != http.StatusOK {
		t.Fatalf("the listed package answered %d, want 200: %s", status, body)
	}

	// The other direction, and the one that matters more: an entry for
	// "python" entitles a host to python, not to every project whose name
	// starts with it.
	prefix := proxyingServer(t)
	seed(t, prefix, manifest.TypePypi, map[string]string{"pypi/wheels/" + sdist: "sdist bytes"})
	g := bindProfile(t, prefix, "ops", "ops01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypePypi, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{
			Type: manifest.TypePypi, Name: "python",
			Constraint: manifest.ConstraintAny,
		}})
	status, body := g.get(t, "/pypi/wheels/"+sdist)
	if status != http.StatusForbidden {
		t.Fatalf("a package the profile does not list answered %d, want 403: %s", status, body)
	}
	if !strings.Contains(body, "pypi/python-3parclient") {
		t.Errorf("the refusal names a package the operator did not request:\n%s", body)
	}
}

// The index half of the same name. The page knows which distribution it is
// for, so it places the version by stripping that name; guessing dropped every
// anchor and left pip reporting no matching distribution.
func TestProfileKeepsThePinnedSdistOfAHyphenatedName(t *testing.T) {
	s := proxyingServer(t)
	up := newRecordingUpstream(t)
	const sdist = "python-3parclient-4.2.10.tar.gz"
	up.route("/simple/python-3parclient/", fmt.Sprintf(
		`<!DOCTYPE html><html><body>`+
			`<a href="%[1]s/files/python-3parclient-4.2.10.tar.gz">python-3parclient-4.2.10.tar.gz</a><br/>`+
			`<a href="%[1]s/files/python-3parclient-4.2.11.tar.gz">python-3parclient-4.2.11.tar.gz</a><br/>`+
			`</body></html>`, up.ts.URL))
	s.cfg.PypiUpstream = up.ts.URL
	if err := s.store.SavePackage(t.Context(), &manifest.PackageManifest{
		ConfigVersion: manifest.CurrentConfigVersion,
		Name:          "python-3parclient",
		Type:          manifest.TypePypi,
		Versions:      []manifest.VersionEntry{{Version: "4.2.10", URL: up.ts.URL, Mode: manifest.ModeProxy}},
	}); err != nil {
		t.Fatalf("seed the python-3parclient manifest: %v", err)
	}

	f := bindProfile(t, s, "pinned", "pinned01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypePypi, audit.VersionPinned, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{
			Type: manifest.TypePypi, Name: "python-3parclient",
			Constraint: manifest.ConstraintExact, Version: "4.2.10",
		}})

	status, body := f.get(t, "/pypi/simple/python-3parclient/")
	if status != http.StatusOK {
		t.Fatalf("the distribution page answered %d: %s", status, body)
	}
	if !strings.Contains(body, sdist) {
		t.Errorf("the page dropped the sdist of the pinned version:\n%s", body)
	}
	if strings.Contains(body, "python-3parclient-4.2.11.tar.gz") {
		t.Errorf("the page lists a version the pin refuses:\n%s", body)
	}
}

// pypi publishes a project under a spelling the operator never types: the
// capital in Django-4.2.11-py3-none-any.whl, and the underscores PEP 625 puts
// in every sdist. Compared raw against an entry, a listed distribution is
// refused and the repair text names a second entry for a package already
// listed.
func TestProfileDecidesAboutTheNormalizedPypiName(t *testing.T) {
	const (
		wheel = "Django-4.2.11-py3-none-any.whl"
		sdist = "python_3parclient-4.2.10.tar.gz"
	)
	s := proxyingServer(t)
	seed(t, s, manifest.TypePypi, map[string]string{
		"pypi/wheels/" + wheel: "wheel bytes",
		"pypi/wheels/" + sdist: "sdist bytes",
	})
	f := bindProfile(t, s, "ops", "ops01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypePypi, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{
			{Type: manifest.TypePypi, Name: "django", Constraint: manifest.ConstraintAny},
			{Type: manifest.TypePypi, Name: "python-3parclient", Constraint: manifest.ConstraintAny},
		})

	for _, file := range []string{wheel, sdist} {
		if status, body := f.get(t, "/pypi/wheels/"+file); status != http.StatusOK {
			t.Errorf("GET /pypi/wheels/%s = %d, want 200: %s", file, status, body)
		}
	}
}

// The half that matters more: under the warn default a spelling mismatch reads
// as a package outside the set, so Permits returns at membership and the pin is
// never applied. The index hides the release and the artifact route serves it,
// which is the disagreement filterPypiSimplePage exists to prevent.
func TestProfilePinSurvivesThePypiFilenameSpelling(t *testing.T) {
	const (
		pinned = "Django-4.2.11-py3-none-any.whl"
		newer  = "Django-5.0.0-py3-none-any.whl"
	)
	s := proxyingServer(t)
	seed(t, s, manifest.TypePypi, map[string]string{
		"pypi/wheels/" + pinned: "pinned bytes",
		"pypi/wheels/" + newer:  "newer bytes",
	})
	f := bindProfile(t, s, "ops", "ops01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypePypi, audit.VersionPinned, "")},
		[]audit.ProfileEntry{{
			Type: manifest.TypePypi, Name: "django",
			Constraint: manifest.ConstraintExact, Version: "4.2.11",
		}})

	status, body := f.get(t, "/pypi/simple/django/")
	if status != http.StatusOK {
		t.Fatalf("the distribution page answered %d: %s", status, body)
	}
	if !strings.Contains(body, pinned) {
		t.Errorf("the page dropped the pinned wheel:\n%s", body)
	}
	if strings.Contains(body, newer) {
		t.Errorf("the page lists a version the pin refuses:\n%s", body)
	}

	if status, body := f.get(t, "/pypi/wheels/"+pinned); status != http.StatusOK {
		t.Errorf("the pinned wheel answered %d, want 200: %s", status, body)
	}
	status, body = f.get(t, "/pypi/wheels/"+newer)
	if status != http.StatusForbidden {
		t.Fatalf("the version outside the pin answered %d, want 403: %s", status, body)
	}
	if !strings.Contains(body, entitle.RefusalConstraint) {
		t.Errorf("the refusal does not name the constraint rule:\n%s", body)
	}
	row := profileDenial(t, s, audit.DenialProfileConstraint)
	if got := denialDetails(t, row)["rule"]; got != entitle.RefusalConstraint {
		t.Errorf("denial rule = %q, want %q", got, entitle.RefusalConstraint)
	}
}

// wheelIdentity places nothing in a filename opening with a hyphen, and the
// object key is composed from the client's path regardless. Gated only on a
// placeable name, a profile that permits nothing serves the object and records
// neither a refusal nor a reach.
func TestProfileRefusesAnUnplaceableWheelFilename(t *testing.T) {
	s := proxyingServer(t)
	seed(t, s, manifest.TypePypi, map[string]string{"pypi/wheels/-x.whl": "bytes"})
	f := bindProfile(t, s, "ops", "ops01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypePypi, audit.VersionFloating, audit.ExpansionBlock)},
		nil)

	status, body := f.get(t, "/pypi/wheels/-x.whl")
	if status != http.StatusForbidden {
		t.Fatalf("an unplaceable filename answered %d, want 403: %s", status, body)
	}
	if !strings.Contains(body, entitle.RefusalMembership) {
		t.Errorf("the refusal does not name the membership rule:\n%s", body)
	}
}

// helmAnnotatedIndex is the shape `helm repo index` writes for a chart
// carrying Artifact Hub annotations. sigs.k8s.io/yaml sorts mapping keys, so
// annotations opens the release and the opening line is a key with no value
// on it, which is also the shape of a chart key.
const helmAnnotatedIndex = `apiVersion: v1
entries:
  cert-manager:
  - annotations:
      artifacthub.io/category: security
      artifacthub.io/license: Apache-2.0
    apiVersion: v1
    name: cert-manager
    version: 1.14.0
    urls:
    - charts/cert-manager-1.14.0.tgz
  - annotations:
      artifacthub.io/category: security
    apiVersion: v1
    name: cert-manager
    version: 1.15.0
    urls:
    - charts/cert-manager-1.15.0.tgz
  redis:
  - annotations:
      artifacthub.io/category: database
    name: redis
    version: 19.0.0
    urls:
    - charts/redis-19.0.0.tgz
generated: "2026-01-01T00:00:00Z"
`

func TestProfileFiltersAHelmIndexWhoseReleasesOpenOnAMapping(t *testing.T) {
	s := proxyingServer(t)
	seed(t, s, manifest.TypeHelm, map[string]string{manifest.HelmIndexKey: helmAnnotatedIndex})

	f := bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeHelm, audit.VersionPinned, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{
			Type: manifest.TypeHelm, Name: "cert-manager",
			Constraint: manifest.ConstraintExact, Version: "1.14.0",
		}})

	status, body := f.get(t, "/helm/index.yaml")
	if status != http.StatusOK {
		t.Fatalf("the chart index answered %d: %s", status, body)
	}
	// The chart key, not the name field of a release: reading the release's
	// opening line as a chart key drops this one and every release under it,
	// which leaves helm an empty entries map and the operator the wrong
	// repair.
	if !strings.Contains(body, "\n  cert-manager:\n") {
		t.Errorf("the filter dropped the chart key of a covered chart:\n%s", body)
	}
	if !strings.Contains(body, "version: 1.14.0") {
		t.Errorf("the index dropped the pinned release:\n%s", body)
	}
	if !strings.Contains(body, "artifacthub.io/license") {
		t.Errorf("the kept release lost the fields under its opening key:\n%s", body)
	}
	if strings.Contains(body, "version: 1.15.0") {
		t.Errorf("the index lists a release the pin refuses:\n%s", body)
	}
	if strings.Contains(body, "redis") {
		t.Errorf("the index lists a chart outside the closed set:\n%s", body)
	}
}

// The comment on filterHelmIndex promises a document it does not recognize
// comes back as it went in. That only holds if a profile refusing nothing is
// also a no-op, which is the case a Contains assertion on a filtered body
// cannot see: it passes just as well against a reordered document.
func TestHelmIndexFilterLeavesAPermittedDocumentByteForByte(t *testing.T) {
	for name, in := range map[string]string{
		"annotated": helmAnnotatedIndex,
		"plain":     helmProfileIndex,
	} {
		t.Run(name, func(t *testing.T) {
			out := filterHelmIndex([]byte(in), func(string) bool { return true }, nil)
			if string(out) != in {
				t.Errorf("a filter refusing nothing rewrote the document (%d -> %d bytes):\n%s", len(in), len(out), out)
			}
		})
	}
}
