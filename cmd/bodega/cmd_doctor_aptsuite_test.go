package main

import (
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/aptsources"
)

// aptStatusWith builds the half of GET /api/v1/status this command reads, the
// way the server builds it: one rendered stanza per codename, generated ones
// first. Rendering through aptsources rather than hand-writing a stanza is the
// point — the test would otherwise pass against a selection that returns a
// stanza the server never emitted.
func aptStatusWith(generated, mirrored []string) aptClientStatus {
	out := aptClientStatus{Signed: true, Suites: generated, Mirrored: mirrored}
	base := aptsources.State{PublicURL: "https://bodega.internal", Signed: true}
	for _, suite := range generated {
		one := base
		one.Suites = []string{suite}
		out.Sources = append(out.Sources, aptsources.Render(one))
	}
	for _, codename := range mirrored {
		one := base
		one.Suites = []string{codename}
		one.Mirrored = true
		out.Sources = append(out.Sources, aptsources.Render(one))
	}
	return out
}

func TestAptSuiteChoicePicksTheNamedCodename(t *testing.T) {
	st := aptStatusWith([]string{"noble"}, []string{"resolute", "resolute-updates"})
	got, err := aptSuiteChoice(st, "resolute-updates")
	if err != nil {
		t.Fatalf("aptSuiteChoice: %v", err)
	}
	if got.Suite != "resolute-updates" {
		t.Fatalf("picked %s; a host installs the codename the operator named and no other", got.Suite)
	}
	if !got.Mirrored || strings.Contains(got.Deb822, "Signed-By") {
		t.Errorf("a mirrored codename was handed bodega's trust half:\n%s", got.Deb822)
	}
}

func TestAptSuiteChoiceKeepsTheGeneratedStanzaSigned(t *testing.T) {
	st := aptStatusWith([]string{"noble"}, []string{"resolute"})
	got, err := aptSuiteChoice(st, "noble")
	if err != nil {
		t.Fatalf("aptSuiteChoice: %v", err)
	}
	if !strings.Contains(got.Deb822, "Signed-By: "+aptsources.ClientKeyringPath) {
		t.Errorf("the generated codename's stanza names no keyring:\n%s", got.Deb822)
	}
}

// The codename has to exist on this instance. A stanza for one that does not
// installs cleanly and fails at the next apt update, on a host whose sources
// were working a moment earlier.
func TestAptSuiteChoiceRefusesACodenameThisInstanceDoesNotServe(t *testing.T) {
	st := aptStatusWith([]string{"noble"}, []string{"resolute"})
	_, err := aptSuiteChoice(st, "jammy")
	if err == nil {
		t.Fatal("returned a stanza for a codename this bodega does not serve")
	}
	for _, want := range []string{"jammy", "noble", "resolute"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q, so the operator cannot choose: %v", want, err)
		}
	}
}

// A profile scopes apt precisely to narrow what its hosts are told exists, and
// the unfiltered base is in the same list. Taking the flag here would hand the
// host an unfiltered index for the packages the profile filters.
func TestAptSuiteChoiceRefusesWhenAProfileScopesApt(t *testing.T) {
	st := aptStatusWith([]string{"noble"}, []string{"resolute"})
	st.Profile = "web"
	_, err := aptSuiteChoice(st, "resolute")
	if err == nil {
		t.Fatal("a profiled host was pointed at the codename its profile filters")
	}
	if !strings.Contains(err.Error(), "web") || !strings.Contains(err.Error(), "bodega profile set") {
		t.Errorf("the refusal does not name the profile or the command that changes it: %v", err)
	}
}

func TestAptSuiteChoiceOnAnInstanceServingNoApt(t *testing.T) {
	_, err := aptSuiteChoice(aptClientStatus{}, "noble")
	if err == nil {
		t.Fatal("returned a stanza from an instance serving no apt suite")
	}
	if !strings.Contains(err.Error(), "no apt suite") {
		t.Errorf("unhelpful refusal: %v", err)
	}
}
