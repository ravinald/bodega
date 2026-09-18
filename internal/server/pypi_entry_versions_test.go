package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// R5 (#363): the per-package index is built from stored keys, so a wheel the
// manifest stopped naming stays installable. The build directory is flat and
// nothing prunes it, so a re-pin from 1.17.0 to 1.16.0 publishes both links and
// pip takes the newer one — the substitution B57 closed on the fetch path,
// reopened on the serve path.
func TestPypiSimpleIndexCarriesOnlyTheVersionsTheEntryNames(t *testing.T) {
	s := hostedServer(t)
	addVersion(t, s, manifest.TypePypi, "six", manifest.VersionEntry{Version: "1.16.0"})
	seed(t, s, manifest.TypePypi, map[string]string{
		"pypi/wheels/six-1.16.0-py2.py3-none-any.whl": "wheel",
		"pypi/wheels/six-1.17.0-py2.py3-none-any.whl": "wheel",
	})

	status, body := getStatusAndBody(t, s, "/pypi/simple/six/")
	if status != http.StatusOK {
		t.Fatalf("GET /pypi/simple/six/ = %d: %s", status, body)
	}
	if !strings.Contains(body, "six-1.16.0-py2.py3-none-any.whl") {
		t.Errorf("the index dropped the version the entry names:\n%s", body)
	}
	if strings.Contains(body, "six-1.17.0") {
		t.Errorf("pip can still resolve 1.17.0 through the index:\n%s", body)
	}
	if got := strings.Count(body, "<a href="); got != 1 {
		t.Errorf("the index publishes %d links, want the one the entry names:\n%s", got, body)
	}
}

// A distribution with no entry of its own arrives as somebody else's
// transitive dependency, pinned by the resolved closure rather than here.
// Filtering it against an empty set would empty the index.
func TestPypiSimpleIndexIsUnfilteredWithNoEntry(t *testing.T) {
	s := hostedServer(t)
	seed(t, s, manifest.TypePypi, map[string]string{
		"pypi/wheels/six-1.16.0-py2.py3-none-any.whl": "wheel",
		"pypi/wheels/six-1.17.0-py2.py3-none-any.whl": "wheel",
	})

	status, body := getStatusAndBody(t, s, "/pypi/simple/six/")
	if status != http.StatusOK {
		t.Fatalf("GET /pypi/simple/six/ = %d: %s", status, body)
	}
	for _, want := range []string{"six-1.16.0", "six-1.17.0"} {
		if !strings.Contains(body, want) {
			t.Errorf("an unnamed distribution lost %s from its index:\n%s", want, body)
		}
	}
}

// A constraint is honored through the same filter the fetch resolves pins
// with, so an entry that deliberately admits a range keeps admitting it.
func TestPypiSimpleIndexHonorsAVersionConstraint(t *testing.T) {
	s := hostedServer(t)
	addVersion(t, s, manifest.TypePypi, "six", manifest.VersionEntry{
		Version: "1.16.0", VersionConstraint: manifest.ConstraintCompatible,
	})
	seed(t, s, manifest.TypePypi, map[string]string{
		"pypi/wheels/six-1.15.0-py2.py3-none-any.whl": "wheel",
		"pypi/wheels/six-1.16.0-py2.py3-none-any.whl": "wheel",
		"pypi/wheels/six-1.17.0-py2.py3-none-any.whl": "wheel",
	})

	_, body := getStatusAndBody(t, s, "/pypi/simple/six/")
	if strings.Contains(body, "six-1.15.0") {
		t.Errorf("a compatible constraint admitted a version below its base:\n%s", body)
	}
	for _, want := range []string{"six-1.16.0", "six-1.17.0"} {
		if !strings.Contains(body, want) {
			t.Errorf("a compatible constraint dropped %s:\n%s", want, body)
		}
	}
}
