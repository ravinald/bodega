package server

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/entitle"
	"github.com/ravinald/bodega/internal/manifest"
)

// A CIDR binding is the only identity available to a client that sends no
// bearer token, and every read bodega serves requires none. So it is the
// binding an operator reaches for to scope a read-only host — and the one
// whose profile enforced nothing, because the gate feeding identitySet.resolve
// asked whether trusted_proxies had been answered rather than whether this
// request's address came off the connection or out of a header.
//
// Each surface gets its own test. A table would report one failure for eight
// routes, and the eight are decided in eight different handlers.

// cidrLoopback is the address httptest's client connects from, so a binding on
// it is what makes these fixtures resolve without a credential.
const cidrLoopback = "127.0.0.1/32"

// cidrLockedServer seeds one artifact per non-apt surface and binds a profile
// closed over all of them with nothing listed, so every route below refuses
// for the same reason and a route that consults no profile stands out.
func cidrLockedServer(t *testing.T) *profileFixture {
	t.Helper()
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
		"repos/widget/widget-v4.5.5.bundle": "bundle",
	})
	seed(t, s, manifest.TypeBinary, map[string]string{
		"binaries/example-tool-v2/2.0.0/example-tool.zip": "binary",
	})

	var types []audit.ProfileTypeRule
	for _, typ := range []string{
		manifest.TypePypi, manifest.TypeNpm, manifest.TypeGomod, manifest.TypeCargo,
		manifest.TypeHelm, manifest.TypeGit, manifest.TypeBinary,
	} {
		types = append(types, closedRule(typ, audit.VersionFloating, audit.ExpansionBlock))
	}
	return bindProfileByCIDR(t, s, "locked", "locked01", cidrLoopback, types, nil)
}

// refusedByCIDRProfile asserts the one thing every surface test here asserts:
// a request carrying no credential at all was still attributed, and the
// profile that attribution selected refused it by name.
func refusedByCIDRProfile(t *testing.T, f *profileFixture, path string) {
	t.Helper()
	status, body := f.get(t, path)
	if status != http.StatusForbidden {
		t.Fatalf("%s answered %d, want 403: a CIDR-bound host reached this route with no profile: %s",
			path, status, body)
	}
	if !strings.Contains(body, entitle.RefusalMembership) {
		t.Errorf("%s refused without naming the rule:\n%s", path, body)
	}
}

func TestCIDRProfileEnforcesOnCargo(t *testing.T) {
	refusedByCIDRProfile(t, cidrLockedServer(t), "/cargo/serde/1.0.0/download")
}

func TestCIDRProfileEnforcesOnNpm(t *testing.T) {
	refusedByCIDRProfile(t, cidrLockedServer(t), "/npm/left-pad/-/left-pad-1.3.0.tgz")
}

func TestCIDRProfileEnforcesOnPypi(t *testing.T) {
	refusedByCIDRProfile(t, cidrLockedServer(t), "/pypi/wheels/django-5.0.0-py3-none-any.whl")
}

func TestCIDRProfileEnforcesOnGomod(t *testing.T) {
	refusedByCIDRProfile(t, cidrLockedServer(t), "/go/example.com/mod/@v/v1.0.0.info")
}

func TestCIDRProfileEnforcesOnHelm(t *testing.T) {
	refusedByCIDRProfile(t, cidrLockedServer(t), "/helm/charts/redis-19.0.0.tgz")
}

func TestCIDRProfileEnforcesOnGit(t *testing.T) {
	refusedByCIDRProfile(t, cidrLockedServer(t), "/git/widget/widget-v4.5.5.bundle")
}

func TestCIDRProfileEnforcesOnBinary(t *testing.T) {
	refusedByCIDRProfile(t, cidrLockedServer(t), "/binaries/example-tool-v2/2.0.0/example-tool.zip")
}

// apt is the eighth and does not share the fixture above: it needs a mirrored
// archive and a signing key before a filtered codename exists at all. The pool
// predicate is where a profile decides a .deb, so that is the route driven.
func TestCIDRProfileEnforcesOnApt(t *testing.T) {
	s, _ := aptProfileServer(t)
	rule := closedRule(manifest.TypeApt, audit.VersionFloating, audit.ExpansionBlock)
	rule.AptBase = mirroredCodename
	f := bindProfileByCIDR(t, s, "web", "web01", cidrLoopback,
		[]audit.ProfileTypeRule{rule},
		[]audit.ProfileEntry{{Type: manifest.TypeApt, Name: "nginx"}})
	s.rebuildAptSnapshot(context.Background())

	refusedByCIDRProfile(t, f, "/apt/"+profileHtopDeb)

	// The host's own package still serves, which is the difference between an
	// enforced profile and an outage.
	if code, _ := f.get(t, "/apt/"+profileNginxDeb); code != http.StatusOK {
		t.Errorf("the listed package answered %d, want 200", code)
	}
}

// The empty identity column is the symptom the whole item was reported from:
// `bodega identity list` showed the binding and every audit row for the bound
// host named nobody. The row is how an operator confirms a binding without
// re-deriving it, so `--identity` has to return the requests it attributed.
func TestARequestFromABoundAddressIsNamedInTheAuditRow(t *testing.T) {
	ctx := context.Background()
	s := proxyingServer(t)
	seed(t, s, manifest.TypeBinary, map[string]string{
		"binaries/example-tool-v2/2.0.0/example-tool.zip": "binary",
	})
	f := bindProfileByCIDR(t, s, "reader", "probe-host", cidrLoopback,
		[]audit.ProfileTypeRule{closedRule(manifest.TypeBinary, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{Type: manifest.TypeBinary, Name: "example-tool-v2"}})

	if status, body := f.get(t, "/binaries/example-tool-v2/2.0.0/example-tool.zip"); status != http.StatusOK {
		t.Fatalf("the listed artifact answered %d: %s", status, body)
	}

	rows, err := s.auditDB.Query(ctx, audit.Filter{Identity: "probe-host"})
	if err != nil {
		t.Fatalf("query by identity: %v", err)
	}
	if len(rows) == 0 {
		t.Fatalf("bodega audit events --identity probe-host returned nothing; " +
			"the binding resolved for nobody and the profile it carries enforces nothing")
	}
	if rows[0].ClientIP != "127.0.0.1" {
		t.Errorf("the row names client %q, want the address the binding matched", rows[0].ClientIP)
	}
}
