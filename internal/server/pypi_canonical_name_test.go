package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

const (
	corsDist     = "django-cors-headers"
	corsWheel    = "django_cors_headers-4.9.0-py3-none-any.whl"
	corsWheelRel = "/files/ab/cd/ef/" + corsWheel
)

// B75 R2: PEP 427 spells the distribution field of a wheel filename with
// underscores where PEP 503 spells the name with hyphens, so the wheel route
// looked its manifest up under a name no catalog holds. Every hyphenated
// distribution served its own simple index and 404d every wheel that index
// listed — 40 of the 101 in a widget install.
func TestPypiProxyEntrySpelledWithHyphensServesTheUnderscoredWheel(t *testing.T) {
	s := proxyingServer(t)
	up := newRecordingUpstream(t)
	up.route("/simple/"+corsDist+"/", fmt.Sprintf(
		`<!DOCTYPE html><html><body><a href="%s%s">%s</a></body></html>`,
		up.ts.URL, corsWheelRel, corsWheel))
	up.route(corsWheelRel, wheelBytes)
	s.cfg.PypiUpstream = up.ts.URL
	addVersion(t, s, manifest.TypePypi, corsDist, manifest.VersionEntry{
		Version: "4.9.0", URL: up.ts.URL, Mode: manifest.ModeProxy,
	})

	status, body := getStatusAndBody(t, s, "/pypi/wheels/"+corsWheel)
	if status != http.StatusOK {
		t.Fatalf("GET the wheel its own simple index lists = %d, want 200 (body %q); upstream saw %v",
			status, body, up.paths())
	}
	if body != wheelBytes {
		t.Errorf("body = %q, want the fixture's wheel bytes", body)
	}
}

// B75 R3: `bodega pkg convert pypi` writes the `name` field `pip list
// --format=json` reported, which carries the distribution's own spelling, and
// the store read composed the PEP 503 one. A catalog built the documented way
// held entries no client could reach, and the version pin on them applied to
// nothing.
//
// The dot rather than the capital: two of the three normalizers this replaced
// disagreed on `.`, and a case-insensitive filesystem cannot tell
// pypi/Django/manifest.json from pypi/django/manifest.json at all.
func TestPypiEntryWrittenWithADotFiltersTheCanonicalIndex(t *testing.T) {
	s := hostedServer(t)
	addVersion(t, s, manifest.TypePypi, "zope.interface", manifest.VersionEntry{Version: "7.2"})
	seed(t, s, manifest.TypePypi, map[string]string{
		"pypi/wheels/zope_interface-7.2-py3-none-any.whl": "wheel",
		"pypi/wheels/zope_interface-8.0-py3-none-any.whl": "wheel",
	})

	status, body := getStatusAndBody(t, s, "/pypi/simple/zope-interface/")
	if status != http.StatusOK {
		t.Fatalf("GET /pypi/simple/zope-interface/ = %d: %s", status, body)
	}
	if !strings.Contains(body, "zope_interface-7.2-py3-none-any.whl") {
		t.Errorf("the index dropped the version the entry names:\n%s", body)
	}
	if strings.Contains(body, "zope_interface-8.0") {
		t.Errorf("the entry stored as zope.interface filtered nothing, so pip resolves a version nobody approved:\n%s", body)
	}
}
