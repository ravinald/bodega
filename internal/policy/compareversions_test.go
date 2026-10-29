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

// Cases from rpm's own tests/rpmvercmp.at.
func TestCompareVersionsRpm(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.0-1", "1.0-1", 0},
		{"1.0-1", "2.0-1", -1},
		{"2.0.1-1", "2.0-1", 1},
		{"5.5p1-1", "5.5p2-1", -1},
		{"5.5p10-1", "5.5p1-1", 1},
		{"10xyz-1", "10.1xyz-1", -1},
		{"xyz.4-1", "8-1", -1},
		{"1.0010-1", "1.9-1", 1},
		{"1.05-1", "1.5-1", 0},
		{"1.0~rc1-1", "1.0-1", -1},
		{"1.0~rc1-1", "1.0~rc2-1", -1},
		{"1.0^-1", "1.0-1", 1},
		{"1.0^git1-1", "1.0^git2-1", -1},
		{"1.0^git1-1", "1.01-1", -1},
		{"1:1.0-1", "2.0-1", 1},
		{"1.20.1-20.el9", "1.20.1-14.el9", 1},
		{"2:1.20.1-20.el9", "1:1.22.1-1.el9", 1},
	} {
		got, ok := CompareVersions(manifest.TypeRpm, tc.a, tc.b)
		if !ok || got != tc.want {
			t.Errorf("CompareVersions(rpm, %q, %q) = %d, %v, want %d", tc.a, tc.b, got, ok, tc.want)
		}
	}
}

// rpm's own tests/rpmvercmp.at, every RPMVERCMP line, run against rpmvercmp
// directly: the version and release comparison, with no epoch to split off.
func TestRpmvercmpVectors(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0}, {"1.0", "2.0", -1}, {"2.0", "1.0", 1},
		{"2.0.1", "2.0.1", 0}, {"2.0", "2.0.1", -1}, {"2.0.1", "2.0", 1},
		{"2.0.1a", "2.0.1a", 0}, {"2.0.1a", "2.0.1", 1}, {"2.0.1", "2.0.1a", -1},
		{"5.5p1", "5.5p1", 0}, {"5.5p1", "5.5p2", -1}, {"5.5p2", "5.5p1", 1},
		{"5.5p10", "5.5p10", 0}, {"5.5p1", "5.5p10", -1}, {"5.5p10", "5.5p1", 1},
		{"10xyz", "10.1xyz", -1}, {"10.1xyz", "10xyz", 1},
		{"xyz10", "xyz10", 0}, {"xyz10", "xyz10.1", -1}, {"xyz10.1", "xyz10", 1},
		{"xyz.4", "xyz.4", 0}, {"xyz.4", "8", -1}, {"8", "xyz.4", 1}, {"xyz.4", "2", -1}, {"2", "xyz.4", 1},
		{"5.5p2", "5.6p1", -1}, {"5.6p1", "5.5p2", 1}, {"5.6p1", "6.5p1", -1}, {"6.5p1", "5.6p1", 1},
		{"6.0.rc1", "6.0", 1}, {"6.0", "6.0.rc1", -1},
		{"10b2", "10a1", 1}, {"10a2", "10b2", -1},
		{"1.0aa", "1.0aa", 0}, {"1.0a", "1.0aa", -1}, {"1.0aa", "1.0a", 1},
		{"10.0001", "10.0001", 0}, {"10.0001", "10.1", 0}, {"10.1", "10.0001", 0},
		{"10.0001", "10.0039", -1}, {"10.0039", "10.0001", 1},
		{"4.999.9", "5.0", -1}, {"5.0", "4.999.9", 1},
		{"20101121", "20101121", 0}, {"20101121", "20101122", -1}, {"20101122", "20101121", 1},
		{"2_0", "2_0", 0}, {"2.0", "2_0", 0}, {"2_0", "2.0", 0},
		{"a", "a", 0}, {"a+", "a+", 0}, {"a+", "a_", 0}, {"a_", "a+", 0},
		{"+a", "+a", 0}, {"+a", "_a", 0}, {"_a", "+a", 0},
		{"+_", "+_", 0}, {"_+", "+_", 0}, {"_+", "_", 0}, {"+", "_", 0}, {"_", "+", 0},
		{"1.0~rc1", "1.0~rc1", 0}, {"1.0~rc1", "1.0", -1}, {"1.0", "1.0~rc1", 1},
		{"1.0~rc1", "1.0~rc2", -1}, {"1.0~rc2", "1.0~rc1", 1},
		{"1.0~rc1~git123", "1.0~rc1~git123", 0}, {"1.0~rc1~git123", "1.0~rc1", -1}, {"1.0~rc1", "1.0~rc1~git123", 1},
		{"1.0^", "1.0^", 0}, {"1.0^", "1.0", 1}, {"1.0", "1.0^", -1},
		{"1.0^git1", "1.0^git1", 0}, {"1.0^git1", "1.0", 1}, {"1.0", "1.0^git1", -1},
		{"1.0^git1", "1.0^git2", -1}, {"1.0^git2", "1.0^git1", 1},
		{"1.0^git1", "1.01", -1}, {"1.01", "1.0^git1", 1},
		{"1.0^20160101", "1.0^20160101", 0}, {"1.0^20160101", "1.0.1", -1}, {"1.0.1", "1.0^20160101", 1},
		{"1.0^20160101^git1", "1.0^20160101^git1", 0},
		{"1.0^20160102", "1.0^20160101^git1", 1}, {"1.0^20160101^git1", "1.0^20160102", -1},
		{"1.0~rc1^git1", "1.0~rc1^git1", 0}, {"1.0~rc1^git1", "1.0~rc1", 1}, {"1.0~rc1", "1.0~rc1^git1", -1},
		{"1.0^git1~pre", "1.0^git1~pre", 0}, {"1.0^git1", "1.0^git1~pre", 1}, {"1.0^git1~pre", "1.0^git1", -1},
		// rpm keeps these to document behavior it calls arguably buggy: a
		// letter run after a number compares with the next segment's letters.
		{"1b.fc17", "1b.fc17", 0}, {"1b.fc17", "1.fc17", -1}, {"1.fc17", "1b.fc17", 1},
		{"1g.fc17", "1g.fc17", 0}, {"1g.fc17", "1.fc17", 1}, {"1.fc17", "1g.fc17", -1},
	} {
		if got := rpmvercmp(tc.a, tc.b); got != tc.want {
			t.Errorf("rpmvercmp(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// The epoch outranks the version and release whatever they hold, an absent
// epoch is 0, and a release is compared only when both sides carry one.
func TestCompareRpmEVREpoch(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1:1.0-1", "1.0-1", 1},
		{"0:1.0-1", "1.0-1", 0},
		{"1:1.0-1", "2:0.1-1", -1},
		{"1:3.0.7-27.el9", "3.5.1-1.el9", 1},
		{"1:1.0~rc1-1", "1:1.0-1", -1},
		{"1:1.0^git1-1", "1:1.0-1", 1},
		{"1.0", "1.0-5", 0},
		{"1.0-1.el9_5", "1.0-1.el9_5.1", -1},
	} {
		got, ok := compareRpmEVR(tc.a, tc.b)
		if !ok || got != tc.want {
			t.Errorf("compareRpmEVR(%q, %q) = %d, %v, want %d", tc.a, tc.b, got, ok, tc.want)
		}
	}
	if _, ok := compareRpmEVR("x:1.0-1", "1.0-1"); ok {
		t.Error("an epoch that is not a number orders against nothing")
	}
}
