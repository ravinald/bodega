package policy

import (
	"slices"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// mavenComparableVersionOrder is the two ascending lists in Maven's own
// ComparableVersionTest (VERSIONS_QUALIFIER and VERSIONS_NUMBER), so every
// adjacent pair is one Maven itself asserts.
var mavenComparableVersionOrder = [][]string{
	{"1-alpha2snapshot", "1-alpha2", "1-alpha-123", "1-beta-2", "1-beta123", "1-m2", "1-m11", "1-rc", "1-cr2",
		"1-rc123", "1-SNAPSHOT", "1", "1-sp", "1-sp2", "1-sp123", "1-abc", "1-def", "1-pom-1", "1-1-snapshot",
		"1-1", "1-2", "1-123"},
	{"2.0", "2.0.a", "2-1", "2.0.2", "2.0.123", "2.1.0", "2.1-a", "2.1b", "2.1-c", "2.1-1", "2.1.0.1", "2.2",
		"2.123", "11.a2", "11.a11", "11.b2", "11.b11", "11.m2", "11.m11", "11", "11.a", "11b", "11c", "11m"},
}

func TestCompareVersions_Maven(t *testing.T) {
	for _, list := range mavenComparableVersionOrder {
		for i := 1; i < len(list); i++ {
			lo, hi := list[i-1], list[i]
			if got, ok := CompareVersions(manifest.TypeMaven, lo, hi); !ok || got != -1 {
				t.Errorf("CompareVersions(maven, %q, %q) = %d, %v; want -1", lo, hi, got, ok)
			}
			if got, ok := CompareVersions(manifest.TypeMaven, hi, lo); !ok || got != 1 {
				t.Errorf("CompareVersions(maven, %q, %q) = %d, %v; want 1", hi, lo, got, ok)
			}
		}
	}
	for _, tc := range []struct{ a, b string }{
		{"1.0", "1.0.0"},
		{"1", "1-ga"},
		{"1", "1-final"},
		{"1", "1-release"},
		{"1-cr1", "1-rc1"},
		{"1-a1", "1-alpha1"},
		{"1-b1", "1-beta1"},
		{"1-m1", "1-milestone1"},
	} {
		if got, ok := CompareVersions(manifest.TypeMaven, tc.a, tc.b); !ok || got != 0 {
			t.Errorf("CompareVersions(maven, %q, %q) = %d, %v; want 0", tc.a, tc.b, got, ok)
		}
	}
	if _, ok := CompareVersions(manifest.TypeMaven, "1.0 junk", "1.0"); ok {
		t.Error("a Maven version holding whitespace was ordered")
	}
}

func TestCompareVersions_RubyGems(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.0.0.pre", "1.0.0", -1},
		{"2.0.0.pre", "2.0.0", -1},
		{"2.0.0.rc1", "2.0.0.pre", 1},
		{"1.0.0.a", "1.0.0.b", -1},
		{"1.0.0.a", "1.0.0.1", -1},
		{"1.10", "1.9", 1},
		{"1.0", "1", 0},
		{"1.0.0", "1", 0},
		{"1.2.3", "1.2.4", -1},
		{"0.9.9", "1.0.0.pre", -1},
		{"1.0.0.beta2", "1.0.0.beta10", -1},
		{"1.0.0-pre", "1.0.0", -1},
	} {
		if got, ok := CompareVersions(manifest.TypeRubygems, tc.a, tc.b); !ok || got != tc.want {
			t.Errorf("CompareVersions(rubygems, %q, %q) = %d, %v; want %d", tc.a, tc.b, got, ok, tc.want)
		}
	}
	if _, ok := CompareVersions(manifest.TypeRubygems, "not a version", "1.0"); ok {
		t.Error("a version Gem::Version refuses was ordered")
	}
}

func TestCompareVersions_Semver(t *testing.T) {
	for _, typ := range []string{manifest.TypeNpm, manifest.TypeCargo, manifest.TypeGomod} {
		for _, tc := range []struct {
			a, b string
			want int
		}{
			{"1.10.0", "1.9.0", 1},
			{"2.0.0", "1.9.0", 1},
			{"1.0.0-rc.1", "1.0.0", -1},
			{"1.2.3", "1.2.3", 0},
		} {
			if got, ok := CompareVersions(typ, tc.a, tc.b); !ok || got != tc.want {
				t.Errorf("CompareVersions(%s, %q, %q) = %d, %v; want %d", typ, tc.a, tc.b, got, ok, tc.want)
			}
		}
		if _, ok := CompareVersions(typ, "latest", "1.0.0"); ok {
			t.Errorf("%s: a non-version was ordered", typ)
		}
	}
	if got, ok := CompareVersions(manifest.TypeGomod, "v2.0.0+incompatible", "v1.9.0"); !ok || got != 1 {
		t.Errorf("gomod +incompatible = %d, %v; want 1", got, ok)
	}
	if _, ok := CompareVersions(manifest.TypeApt, "1.0", "1.0"); ok {
		t.Error("a type with no range ordering was ordered")
	}
}

func TestReleaseSegments(t *testing.T) {
	for _, tc := range []struct {
		typ, v string
		want   []int
	}{
		{manifest.TypeNpm, "1.9.5", []int{1, 9, 5}},
		{manifest.TypeGomod, "v2.0.0+incompatible", []int{2, 0, 0}},
		{manifest.TypeMaven, "2.0-beta9", []int{2}},
		{manifest.TypeMaven, "1.9.5", []int{1, 9, 5}},
		{manifest.TypeMaven, "2.1b", []int{2, 1}},
		{manifest.TypeRubygems, "1.0.0.pre", []int{1}},
		{manifest.TypeRubygems, "1.9.5", []int{1, 9, 5}},
	} {
		got, ok := ReleaseSegments(tc.typ, tc.v)
		if !ok || !slices.Equal(got, tc.want) {
			t.Errorf("ReleaseSegments(%s, %q) = %v, %v; want %v", tc.typ, tc.v, got, ok, tc.want)
		}
	}
}
