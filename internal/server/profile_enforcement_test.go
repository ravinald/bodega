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
}

// The hazard with no error attached: two host classes, one package, two
// documents. The assertion is on the cache keys rather than on the bodies,
// because a body comparison passes whenever the two profiles happen to agree
// and would have passed against the tree where both wrote the same key.
func TestTwoProfilesGetTwoDocumentsAndTwoCacheKeys(t *testing.T) {
	s := proxyingServer(t)
	up := newRecordingUpstream(t)
	up.route("/se/rd/serde", `{"name":"serde","vers":"1.0.0","cksum":"a"}`+"\n"+
		`{"name":"serde","vers":"2.0.0","cksum":"b"}`+"\n")
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
	for _, want := range []string{profileIndexKey("held", base), profileIndexKey("tracking", base)} {
		if !containsKey(keys, want) {
			t.Errorf("no cache entry at %q; the two profiles share a key and one will be served the other's document\n  keys: %v", want, keys)
		}
	}
	if containsKey(keys, base) {
		t.Errorf("a filtered index was cached under the shared key %q: %v", base, keys)
	}

	// An unidentified request resolves to no profile and keeps today's key, so
	// an install with no profiles pays nothing for this feature.
	if _, body := getWithToken(t, s, "", "/cargo/se/rd/serde"); !strings.Contains(body, `"vers":"2.0.0"`) {
		t.Errorf("an unidentified request was filtered:\n%s", body)
	}
	if !containsKey(storedKeys(t, s, manifest.TypeCargo, ""), base) {
		t.Errorf("an unidentified request did not cache under today's key: %v",
			storedKeys(t, s, manifest.TypeCargo, ""))
	}
}

func containsKey(keys []string, want string) bool {
	for _, k := range keys {
		if k == want {
			return true
		}
	}
	return false
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
