package entitle

import (
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// profile assembles a detail the way the store hands one back, so the tests
// exercise the same indexing the CLI and the serve path will.
func profile(name string, types []audit.ProfileTypeRule, entries []audit.ProfileEntry) *Profile {
	return New(&audit.ProfileDetail{
		Profile: audit.Profile{Name: name},
		Types:   types,
		Entries: entries,
	})
}

func rule(typ, membership, versionDefault string) audit.ProfileTypeRule {
	return audit.ProfileTypeRule{Type: typ, Membership: membership, VersionDefault: versionDefault}
}

// TestOpenTypeWithOnePinnedPackage is the ordinary case the third level exists
// for: everything of a type tracks, except the one package held because a
// newer major breaks something.
func TestOpenTypeWithOnePinnedPackage(t *testing.T) {
	p := profile("web",
		[]audit.ProfileTypeRule{rule(manifest.TypeApt, audit.MembershipOpen, audit.VersionFloating)},
		[]audit.ProfileEntry{{
			Type: manifest.TypeApt, Name: "postgresql", Constraint: manifest.ConstraintExact,
			Version: "14.11", Reason: "15 breaks the config",
		}})

	if d := p.Permits(manifest.TypeApt, "nginx", "1.24.0"); !d.Permitted {
		t.Errorf("an open type refused a package it does not list: %s", d.Reason)
	}
	if d := p.Permits(manifest.TypeApt, "postgresql", "14.11"); !d.Permitted {
		t.Errorf("the pinned version was refused: %s", d.Reason)
	}
	d := p.Permits(manifest.TypeApt, "postgresql", "15.2")
	if d.Permitted {
		t.Fatal("the pin did not hold: 15.2 was permitted for a package pinned to 14.11")
	}
	if !d.Governed {
		t.Error("a refusal by a profile rule reported itself ungoverned")
	}
	if d.Entry == nil || d.Entry.Version != "14.11" {
		t.Error("the decision does not name the entry that produced it, so a caller cannot log why")
	}
	if !strings.Contains(d.Reason, "14.11") {
		t.Errorf("the reason does not name the held version: %s", d.Reason)
	}
}

// TestClosedTypeWithFloatingVersions is the other ordinary case: a fixed set
// of packages, each tracking upstream.
func TestClosedTypeWithFloatingVersions(t *testing.T) {
	p := profile("db",
		[]audit.ProfileTypeRule{rule(manifest.TypePypi, audit.MembershipClosed, audit.VersionFloating)},
		[]audit.ProfileEntry{
			{Type: manifest.TypePypi, Name: "requests"},
			{Type: manifest.TypePypi, Name: "psycopg2"},
		})

	for _, version := range []string{"2.31.0", "2.32.5", "3.0.0"} {
		if d := p.Permits(manifest.TypePypi, "requests", version); !d.Permitted {
			t.Errorf("a floating default refused requests %s: %s", version, d.Reason)
		}
	}
	d := p.Permits(manifest.TypePypi, "django", "5.0")
	if d.Permitted {
		t.Fatal("a closed type permitted a package it does not list")
	}
	if !strings.Contains(d.Reason, "closed") || !strings.Contains(d.Reason, "django") {
		t.Errorf("the refusal names neither the membership nor the package: %s", d.Reason)
	}
}

// TestClosedAndEmptyPermitsNothing is the state the CLI refuses without
// --force. It is reachable, so the predicate has to answer it the way the
// refusal text promises.
func TestClosedAndEmptyPermitsNothing(t *testing.T) {
	p := profile("locked",
		[]audit.ProfileTypeRule{rule(manifest.TypeHelm, audit.MembershipClosed, audit.VersionFloating)},
		nil)

	d := p.Permits(manifest.TypeHelm, "anything", "1.0.0")
	if d.Permitted {
		t.Fatal("a closed type with no entries permitted something")
	}
	if !d.Governed {
		t.Error("the refusal reported itself ungoverned, so a caller would fall through to the fleet-wide controls")
	}
}

// TestEntryOverridesTypeDefaultInBothDirections is the third level doing the
// work the first two cannot: one held package inside a floating type, and one
// tracking package inside a pinned one.
func TestEntryOverridesTypeDefaultInBothDirections(t *testing.T) {
	floating := profile("f",
		[]audit.ProfileTypeRule{rule(manifest.TypeNpm, audit.MembershipClosed, audit.VersionFloating)},
		[]audit.ProfileEntry{
			{Type: manifest.TypeNpm, Name: "lodash"},
			{Type: manifest.TypeNpm, Name: "express", Constraint: manifest.ConstraintExact, Version: "4.18.2"},
		})
	if d := floating.Permits(manifest.TypeNpm, "lodash", "4.17.21"); !d.Permitted {
		t.Errorf("the type default did not float: %s", d.Reason)
	}
	if d := floating.Permits(manifest.TypeNpm, "express", "5.0.0"); d.Permitted {
		t.Error("an exact entry inside a floating type did not hold")
	}

	pinned := profile("p",
		[]audit.ProfileTypeRule{rule(manifest.TypeNpm, audit.MembershipClosed, audit.VersionPinned)},
		[]audit.ProfileEntry{
			{Type: manifest.TypeNpm, Name: "lodash", Version: "4.17.21"},
			{Type: manifest.TypeNpm, Name: "express", Constraint: manifest.ConstraintAny},
		})
	if d := pinned.Permits(manifest.TypeNpm, "lodash", "4.17.22"); d.Permitted {
		t.Error("the pinned type default did not hold a package carrying no constraint of its own")
	}
	if d := pinned.Permits(manifest.TypeNpm, "lodash", "4.17.21"); !d.Permitted {
		t.Errorf("the pinned type default refused the version its entry names: %s", d.Reason)
	}
	if d := pinned.Permits(manifest.TypeNpm, "express", "5.0.0"); !d.Permitted {
		t.Errorf("an 'any' entry inside a pinned type did not float: %s", d.Reason)
	}
}

// TestTypeWithNoMarkerIsUngoverned is why the marker table exists. "No entries
// for this type" is two answers, and only one of them is a refusal.
func TestTypeWithNoMarkerIsUngoverned(t *testing.T) {
	p := profile("web",
		[]audit.ProfileTypeRule{rule(manifest.TypeApt, audit.MembershipClosed, audit.VersionFloating)},
		[]audit.ProfileEntry{{Type: manifest.TypeApt, Name: "nginx"}})

	d := p.Permits(manifest.TypeHelm, "cert-manager", "1.14.0")
	if !d.Permitted {
		t.Fatalf("a type the profile states no rule for was refused: %s", d.Reason)
	}
	if d.Governed {
		t.Error("an ungoverned permit reported itself governed; the caller would skip the fleet-wide controls")
	}

	closed := profile("web",
		[]audit.ProfileTypeRule{rule(manifest.TypeHelm, audit.MembershipClosed, audit.VersionFloating)}, nil)
	if closed.Permits(manifest.TypeHelm, "cert-manager", "1.14.0").Permitted {
		t.Error("the same absence of entries answered the same way with a marker present, so the marker records nothing")
	}
}

// TestNilProfileIsTheUnprofiledHost. Every host is in this state before the
// first profile is written, and a refusal here would make `bodega profile
// create` a fleet-wide outage.
func TestNilProfileIsTheUnprofiledHost(t *testing.T) {
	var p *Profile
	d := p.Permits(manifest.TypeApt, "nginx", "1.24.0")
	if !d.Permitted || d.Governed {
		t.Errorf("an unbound host was not permitted ungoverned: %+v", d)
	}
	if p.Name() != "" {
		t.Errorf("the nil profile named itself %q", p.Name())
	}
}

// TestRangeConstraintsUseTheOneImplementation checks that compatible and patch
// mean here what they mean everywhere else in bodega.
func TestRangeConstraintsUseTheOneImplementation(t *testing.T) {
	p := profile("r",
		[]audit.ProfileTypeRule{rule(manifest.TypeGomod, audit.MembershipClosed, audit.VersionFloating)},
		[]audit.ProfileEntry{
			{Type: manifest.TypeGomod, Name: "compat", Constraint: manifest.ConstraintCompatible, Version: "5.2.0"},
			{Type: manifest.TypeGomod, Name: "patched", Constraint: manifest.ConstraintPatch, Version: "1.26.4"},
		})

	cases := []struct {
		name, version string
		want          bool
	}{
		{"compat", "5.2.0", true},
		{"compat", "5.9.1", true},
		{"compat", "6.0.0", false},
		{"compat", "5.1.9", false},
		{"patched", "1.26.4", true},
		{"patched", "1.26.9", true},
		{"patched", "1.27.0", false},
	}
	for _, tc := range cases {
		if got := p.Permits(manifest.TypeGomod, tc.name, tc.version).Permitted; got != tc.want {
			t.Errorf("%s %s: permitted=%v, want %v", tc.name, tc.version, got, tc.want)
		}
	}
}

// TestARangeConstraintRefusesWhatItCannotPlace. An apt version carries an
// epoch and a Debian revision, so "^" has nothing to compare. Refusing names
// the version; permitting would let a range constraint mean "any" on the one
// ecosystem where versions are least comparable.
func TestARangeConstraintRefusesWhatItCannotPlace(t *testing.T) {
	p := profile("a",
		[]audit.ProfileTypeRule{rule(manifest.TypeApt, audit.MembershipClosed, audit.VersionFloating)},
		[]audit.ProfileEntry{
			{Type: manifest.TypeApt, Name: "openssl", Constraint: manifest.ConstraintCompatible, Version: "3.0.2"},
		})
	d := p.Permits(manifest.TypeApt, "openssl", "1:3.0.2-0ubuntu1.15")
	if d.Permitted {
		t.Fatal("a range constraint permitted a version it cannot place")
	}
	if !strings.Contains(d.Reason, "semantic version") {
		t.Errorf("the refusal does not say why it could not compare: %s", d.Reason)
	}
}

// TestExactMatchesByString keeps the apt and git cases working: an epoch, a
// Debian revision or a git ref is equal to itself whether or not it parses as
// semver.
func TestExactMatchesByString(t *testing.T) {
	p := profile("a",
		[]audit.ProfileTypeRule{rule(manifest.TypeApt, audit.MembershipClosed, audit.VersionFloating)},
		[]audit.ProfileEntry{
			{Type: manifest.TypeApt, Name: "openssl", Constraint: manifest.ConstraintExact, Version: "1:3.0.2-0ubuntu1.15"},
		})
	if d := p.Permits(manifest.TypeApt, "openssl", "1:3.0.2-0ubuntu1.15"); !d.Permitted {
		t.Errorf("an exact pin refused the version it names: %s", d.Reason)
	}
	if p.Permits(manifest.TypeApt, "openssl", "1:3.0.2-0ubuntu1.16").Permitted {
		t.Error("an exact pin permitted a different Debian revision")
	}
}

// TestOpenAndPinnedNamesWhatItCannotAnswer. An open type whose default pins
// every version has nothing to pin an unlisted package to, and saying so beats
// permitting it.
func TestOpenAndPinnedNamesWhatItCannotAnswer(t *testing.T) {
	p := profile("op",
		[]audit.ProfileTypeRule{rule(manifest.TypeCargo, audit.MembershipOpen, audit.VersionPinned)}, nil)
	d := p.Permits(manifest.TypeCargo, "serde", "1.0.0")
	if d.Permitted {
		t.Fatal("a pinned default permitted a package no entry names a version for")
	}
	if !strings.Contains(d.Reason, "names none") {
		t.Errorf("the refusal does not explain the state that produced it: %s", d.Reason)
	}
}
