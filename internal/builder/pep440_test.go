package builder

import (
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// A semver filter drops every PEP 440 form it cannot parse, and dropping a
// candidate is indistinguishable from the candidate not existing: against
// 1.16.0 and 1.16.0.post1, all three floating constraints resolved to 1.16.0
// with no error, naming a release older than the one the index says is newest.
func TestFilterPypiVersionsTakesPostReleases(t *testing.T) {
	available := []string{"1.16.0", "1.16.0.post1"}
	for _, constraint := range []string{
		manifest.ConstraintAny, manifest.ConstraintPatch, manifest.ConstraintCompatible,
	} {
		got := FilterPypiVersions(available, constraint, "1.16.0")
		if len(got) == 0 || got[len(got)-1] != "1.16.0.post1" {
			t.Errorf("%s resolved to %v, want 1.16.0.post1 last", constraint, got)
		}
	}
}

// Exact matches the release PEP 440 says was named, not the string that was
// typed: 1.16 and 1.16.0 are the same release, and rc spellings normalize.
func TestFilterPypiVersionsExactNormalizes(t *testing.T) {
	for _, tc := range []struct {
		available []string
		want      string
		match     string
	}{
		{[]string{"1.16.0"}, "1.16", "1.16.0"},
		{[]string{"1.16"}, "1.16.0.0", "1.16"},
		{[]string{"2.0.0rc1"}, "2.0.0-rc-1", "2.0.0rc1"},
		{[]string{"2.0.0rc1"}, "2.0.0c1", "2.0.0rc1"},
		{[]string{"1.0.post1"}, "1.0-1", "1.0.post1"},
		{[]string{"1!2.0"}, "1!2.0.0", "1!2.0"},
		{[]string{"1.0.dev1"}, "1.0dev1", "1.0.dev1"},
	} {
		got := FilterPypiVersions(tc.available, manifest.ConstraintExact, tc.want)
		if len(got) != 1 || got[0] != tc.match {
			t.Errorf("exact %q against %v resolved to %v, want [%s]", tc.want, tc.available, got, tc.match)
		}
	}
}

// The PEP 440 ordering the constraints are resolved against, ascending.
// https://packaging.python.org/en/latest/specifications/version-specifiers/
func TestSortPyVersionsOrdering(t *testing.T) {
	want := []string{
		"1.0.dev1", "1.0a1", "1.0a2", "1.0b1", "1.0rc1", "1.0", "1.0.post1",
		"1.0.post2.dev1", "1.0.post2", "1.0.1", "1.1", "2.0", "1!0.1",
	}
	got := append([]string(nil), want...)
	// Reverse first, so a sort that does nothing cannot pass.
	for i, j := 0, len(got)-1; i < j; i, j = i+1, j-1 {
		got[i], got[j] = got[j], got[i]
	}
	SortPyVersions(got)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("ordering is\n  %v\nwant\n  %v", got, want)
	}
}

// A floating constraint takes a pre-release only when the version the entry
// names is itself one. Otherwise publishing 2.0.0rc1 moves every "any" entry
// onto a release candidate nobody approved.
func TestFilterPypiVersionsPreReleasePolicy(t *testing.T) {
	available := []string{"1.16.0", "2.0.0rc1"}

	if got := FilterPypiVersions(available, manifest.ConstraintAny, "1.16.0"); len(got) == 0 || got[len(got)-1] != "1.16.0" {
		t.Errorf("any on a release resolved to %v, want 1.16.0 last", got)
	}
	if got := FilterPypiVersions(available, manifest.ConstraintAny, "1.0.0rc1"); len(got) == 0 || got[len(got)-1] != "2.0.0rc1" {
		t.Errorf("any on a pre-release resolved to %v, want 2.0.0rc1 last", got)
	}
	if got := FilterPypiVersions(available, manifest.ConstraintExact, "2.0.0rc1"); len(got) != 1 {
		t.Errorf("exact on a pre-release resolved to %v, want it taken", got)
	}
}

// A version outside the scheme still resolves, by literal match. pytz shipped
// "2011k", which no parser will order.
func TestParsePyVersionRejectsLegacyForms(t *testing.T) {
	for _, s := range []string{"2011k", "", "1.0.0-beta.2+x y", "nightly"} {
		if _, ok := ParsePyVersion(s); ok {
			t.Errorf("%q parsed as PEP 440", s)
		}
	}
}
