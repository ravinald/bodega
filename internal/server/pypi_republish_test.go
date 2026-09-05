package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// The upstream document these tests republish: one anchor with an absolute
// files-host href, the PEP 503 integrity fragment, and the PEP 658 metadata
// attribute pip 24 reads. Every part of it is what a real pypi simple index
// carries, and each one decides a different assertion below.
func upstreamSimpleIndex(fixtureURL string) string {
	return fmt.Sprintf(
		`<!DOCTYPE html><html><body><a href="%s%s#sha256=deadbeef" data-dist-info-metadata="sha256=cafe" data-requires-python="&gt;=2.7">%s</a><br/></body></html>`,
		fixtureURL, testWheelRel, testWheel)
}

// TestProxiedPypiIndexRepublishesOntoBodega is issue #194. Served verbatim, the
// upstream index sends pip to files.pythonhosted.org: the client resolves
// through bodega and downloads around it, so nothing is cached, the allow-list
// never sees the artifact and no row records the bytes that got installed.
func TestProxiedPypiIndexRepublishesOntoBodega(t *testing.T) {
	s := proxyingServer(t)
	up := newRecordingUpstream(t)
	up.route("/simple/six/", upstreamSimpleIndex(up.ts.URL))
	s.cfg.PypiUpstream = up.ts.URL
	seedProxyPypi(t, s, "six", up.ts.URL)

	status, body := getStatusAndBody(t, s, "/pypi/simple/six/")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", status, body)
	}
	if want := `href="/pypi/wheels/` + testWheel + `#sha256=deadbeef"`; !strings.Contains(body, want) {
		t.Errorf("body = %q, want an href %s: the link has to come back through bodega, fragment intact", body, want)
	}
	if strings.Contains(body, up.ts.URL) {
		t.Errorf("body = %q, still names the upstream %s: pip would fetch the wheel around bodega", body, up.ts.URL)
	}
	// pip reads the attribute as a promise that "<href>.metadata" is fetchable.
	// Only the upstream file host publishes that, so republishing it points pip
	// at a bodega path that 404s on every install.
	if strings.Contains(body, "metadata") {
		t.Errorf("body = %q, still advertises PEP 658 metadata bodega does not serve", body)
	}
	// Everything the rewrite has no business touching survives it.
	if !strings.Contains(body, `data-requires-python="&gt;=2.7"`) {
		t.Errorf("body = %q, dropped data-requires-python: pip uses it to skip a release", body)
	}
	if !strings.Contains(body, ">"+testWheel+"<") {
		t.Errorf("body = %q, dropped the anchor text", body)
	}
}

// The republished link has to be one the wheel route answers. Following it is
// the assertion: an href that reads correctly and 404s closes nothing.
func TestRepublishedIndexLinkResolvesThroughTheWheelRoute(t *testing.T) {
	s := proxyingServer(t)
	up := newRecordingUpstream(t)
	up.route("/simple/six/", upstreamSimpleIndex(up.ts.URL))
	up.route(testWheelRel, wheelBytes)
	s.cfg.PypiUpstream = up.ts.URL
	seedProxyPypi(t, s, "six", up.ts.URL)

	_, index := getStatusAndBody(t, s, "/pypi/simple/six/")
	m := pypiHrefPattern.FindStringSubmatch(index)
	if m == nil {
		t.Fatalf("republished index carries no href: %q", index)
	}
	href, _, _ := strings.Cut(m[1], "#")

	status, body := getStatusAndBody(t, s, href)
	if status != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200 (body %q); upstream saw %v", href, status, body, up.paths())
	}
	if body != wheelBytes {
		t.Errorf("body = %q, want the fixture's wheel bytes", body)
	}
	if !up.sawPath(testWheelRel) {
		t.Errorf("upstream saw %v, want a fetch of %s through the proxy", up.paths(), testWheelRel)
	}
	// The point of the whole item: the bytes a client installed are now in
	// bodega's own storage rather than only in pip's cache.
	if _, err := s.typeStore(manifest.TypePypi).Head(t.Context(), manifest.PypiWheelPrefix+testWheel); err != nil {
		t.Errorf("head cached wheel: %v", err)
	}
}

// TestPypiDeniedDistributionNeverReachesTheIndex is issue #196, and pins for
// pypi what TestObserveRecordsEveryDecisionAndStillEnforces pins for binary.
// The resolver for a wheel is itself a read of <pypi_upstream>/simple/{dist}/,
// so a verdict taken after it has already put the denied name on the wire. The
// reproduction in the issue shows `upstream saw [/simple/six/]`.
func TestPypiDeniedDistributionNeverReachesTheIndex(t *testing.T) {
	s := proxyingServer(t)
	up := newRecordingUpstream(t)
	up.route("/simple/six/", upstreamSimpleIndex(up.ts.URL))
	up.route(testWheelRel, wheelBytes)
	s.cfg.PypiUpstream = up.ts.URL
	seedProxyPypi(t, s, "six", up.ts.URL)

	// Rules exist for pypi and none of them names six, which is what makes the
	// candidate a violation rather than an unchecked one.
	if err := s.auditDB.InsertPolicy(t.Context(), audit.PolicyInfo{
		ID:           "pypi-allow-elsewhere",
		RegistryType: manifest.TypePypi,
		RuleKind:     policy.KindPackage,
		Pattern:      "flask",
	}); err != nil {
		t.Fatalf("insert policy: %v", err)
	}
	s.policy.Invalidate()

	status, body := getStatusAndBody(t, s, "/pypi/wheels/"+testWheel)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %q)", status, body)
	}
	if got := up.paths(); len(got) != 0 {
		t.Errorf("upstream saw %v, want nothing at all: a denied distribution's name must not reach the index host", got)
	}
	waitForBinaryRows(t, s, audit.DecisionDenied, 1)
}

// The records the pre-B14 ordering kept. The index read is an upstream contact
// and gets a row; a wheel the index does not list 404s from inside the resolver
// and, before this, left discovery with no trace that anything was asked for.
func TestPypiIndexReadIsRecorded(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		wantStatus int
	}{
		{"listed", "/pypi/wheels/" + testWheel, http.StatusOK},
		{"not listed", "/pypi/wheels/six-9.9.9-py2.py3-none-any.whl", http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := proxyingServer(t)
			up := newRecordingUpstream(t)
			up.route("/simple/six/", upstreamSimpleIndex(up.ts.URL))
			up.route(testWheelRel, wheelBytes)
			s.cfg.PypiUpstream = up.ts.URL
			seedProxyPypi(t, s, "six", up.ts.URL)

			if status, body := getStatusAndBody(t, s, tc.path); status != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", status, tc.wantStatus, body)
			}
			// No rules configured, so the verdict on a permitted fetch is
			// no_policy — the column says what the allow-list knows, and the
			// row's presence is the assertion.
			rows := waitForBinaryRows(t, s, audit.DecisionNoPolicy, 1)
			if rows[0].PkgName != "six" {
				t.Errorf("pkg_name = %q, want six (%+v)", rows[0].PkgName, rows[0])
			}
		})
	}
}

// A proxy-mode distribution republishes the upstream index for as long as it
// stays proxy mode. Gated on an empty cache, the first wheel this item causes
// to be stored flips the distribution onto bodega's own listing, which carries
// only what has been fetched — so `six==1.16.0` installs, and every other
// version of six upstream stops existing for that client.
func TestRepublishedIndexSurvivesTheFirstCachedWheel(t *testing.T) {
	const (
		olderWheel = "six-1.15.0-py2.py3-none-any.whl"
		olderRel   = "/files/aa/bb/cc/" + olderWheel
	)
	s := proxyingServer(t)
	up := newRecordingUpstream(t)
	up.route("/simple/six/", fmt.Sprintf(
		`<!DOCTYPE html><html><body><a href="%s%s#sha256=deadbeef">%s</a><br/><a href="%s%s#sha256=feedface">%s</a><br/></body></html>`,
		up.ts.URL, testWheelRel, testWheel, up.ts.URL, olderRel, olderWheel))
	up.route(testWheelRel, wheelBytes)
	up.route(olderRel, wheelBytes)
	s.cfg.PypiUpstream = up.ts.URL
	seedProxyPypi(t, s, "six", up.ts.URL)

	if status, body := getStatusAndBody(t, s, "/pypi/wheels/"+testWheel); status != http.StatusOK {
		t.Fatalf("caching fetch = %d, want 200 (body %q)", status, body)
	}
	if _, err := s.typeStore(manifest.TypePypi).Head(t.Context(), manifest.PypiWheelPrefix+testWheel); err != nil {
		t.Fatalf("the first wheel did not cache, so this test proves nothing: %v", err)
	}

	status, body := getStatusAndBody(t, s, "/pypi/simple/six/")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", status, body)
	}
	for _, want := range []string{
		`href="/pypi/wheels/` + testWheel + `#sha256=deadbeef"`,
		`href="/pypi/wheels/` + olderWheel + `#sha256=feedface"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body = %q, want %s: a cached wheel must not shrink the index to what the cache holds", body, want)
		}
	}

	// Republishing upstream does not send the cached wheel back to the network:
	// /pypi/wheels/ answers from storage before it resolves anything.
	before := len(up.paths())
	if status, got := getStatusAndBody(t, s, "/pypi/wheels/"+testWheel); status != http.StatusOK || got != wheelBytes {
		t.Fatalf("second fetch = %d %q, want 200 and the wheel bytes", status, got)
	}
	if after := up.paths(); len(after) != before {
		t.Errorf("upstream saw %v, want nothing after %d: the cached wheel must serve from storage", after[before:], before)
	}
}
