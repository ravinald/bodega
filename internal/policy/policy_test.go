package policy

import (
	"context"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// fakeStore lets tests seed rules without a real SQLite instance.
type fakeStore struct {
	byType map[string][]Rule
	calls  int
}

func (f *fakeStore) GetPoliciesByType(_ context.Context, t string) ([]Rule, error) {
	f.calls++
	return f.byType[t], nil
}

func newChecker(rules ...Rule) (*Checker, *fakeStore) {
	store := &fakeStore{byType: make(map[string][]Rule)}
	for _, r := range rules {
		store.byType[r.RegistryType] = append(store.byType[r.RegistryType], r)
	}
	return NewChecker(store), store
}

func rule(t, pattern string) Rule {
	return audit.PolicyInfo{
		RegistryType: t,
		RuleKind:     RuleKindForType(t),
		Pattern:      pattern,
	}
}

func TestEmptyAllowList(t *testing.T) {
	// No rules at all for a type → allow everything (opt-in).
	c, _ := newChecker()
	if err := c.Check(context.Background(), manifest.TypePypi, "anything"); err != nil {
		t.Fatalf("empty policy should allow, got: %v", err)
	}
}

func TestNilChecker(t *testing.T) {
	var c *Checker
	if err := c.Check(context.Background(), manifest.TypePypi, "anything"); err != nil {
		t.Fatalf("nil checker should allow, got: %v", err)
	}
}

func TestMatchers(t *testing.T) {
	cases := []struct {
		name      string
		rules     []Rule
		regType   string
		candidate string
		wantAllow bool
	}{
		// apt (host)
		{"apt host exact", []Rule{rule("apt", "archive.ubuntu.com")}, "apt", "http://archive.ubuntu.com/ubuntu/pool/main/p/pkg.deb", true},
		{"apt host mismatch", []Rule{rule("apt", "archive.ubuntu.com")}, "apt", "http://evil.example.com/ubuntu/x.deb", false},
		{"apt host case insensitive", []Rule{rule("apt", "Archive.Ubuntu.Com")}, "apt", "http://archive.ubuntu.com/x.deb", true},

		// git (org prefix)
		{"git prefix match", []Rule{rule("git", "example.com/example-corp/")}, "git", "https://example.com/example-corp/widget.git", true},
		{"git prefix no scheme", []Rule{rule("git", "example.com/example-corp/")}, "git", "git@example.com/example-corp/widget-sdk.git", false},
		{"git wrong org", []Rule{rule("git", "example.com/example-corp/")}, "git", "https://github.com/attacker/widget.git", false},
		{"git multiple rules second matches", []Rule{rule("git", "example.com/example-corp/"), rule("git", "example.com/example-corp/")}, "git", "https://example.com/example-corp/widget.git", true},

		// pypi (normalized name)
		{"pypi exact", []Rule{rule("pypi", "django")}, "pypi", "django", true},
		{"pypi dashes to underscores", []Rule{rule("pypi", "zope.interface")}, "pypi", "zope.interface", true},
		{"pypi upper vs lower", []Rule{rule("pypi", "Django")}, "pypi", "django", true},
		{"pypi dash-underscore equiv", []Rule{rule("pypi", "my_package")}, "pypi", "my-package", true},
		{"pypi mismatch", []Rule{rule("pypi", "django")}, "pypi", "requests", false},

		// npm (exact + @scope/*)
		{"npm exact", []Rule{rule("npm", "lodash")}, "npm", "lodash", true},
		{"npm scope wildcard match", []Rule{rule("npm", "@example-cloud/*")}, "npm", "@example-cloud/client-storage", true},
		{"npm scope wildcard no match other scope", []Rule{rule("npm", "@example-cloud/*")}, "npm", "@evil/payload", false},
		{"npm scope exact without wildcard", []Rule{rule("npm", "@example-cloud/client-storage")}, "npm", "@example-cloud/client-dynamodb", false},

		// gomod (prefix on module path)
		{"gomod prefix match", []Rule{rule("gomod", "example.com/example-corp/")}, "gomod", "example.com/example-corp/widget-sdk", true},
		{"gomod prefix match v2", []Rule{rule("gomod", "example.com/example-corp/")}, "gomod", "example.com/example-corp/widget-sdk", true},
		{"gomod prefix mismatch", []Rule{rule("gomod", "example.com/example-corp/")}, "gomod", "example.com/attacker/widget-sdk", false},

		// helm (prefix)
		{"helm prefix match", []Rule{rule("helm", "https://kubernetes.github.io/ingress-nginx/")}, "helm", "https://kubernetes.github.io/ingress-nginx/charts/ingress-1.0.0.tgz", true},
		{"helm prefix mismatch", []Rule{rule("helm", "https://kubernetes.github.io/")}, "helm", "https://evil.example.com/chart.tgz", false},

		// binary (prefix)
		{"binary prefix match", []Rule{rule("binary", "https://downloads.example.com/")}, "binary", "https://downloads.example.com/widget-tool/1.7.0/widget-tool_1.7.0_darwin_amd64.zip", true},
		{"binary prefix wrong host", []Rule{rule("binary", "https://downloads.example.com/")}, "binary", "https://mirror.example.com/widget-tool.zip", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newChecker(tc.rules...)
			err := c.Check(context.Background(), tc.regType, tc.candidate)
			if tc.wantAllow && err != nil {
				t.Fatalf("want allow, got violation: %v", err)
			}
			if !tc.wantAllow && !IsViolation(err) {
				t.Fatalf("want violation, got: %v", err)
			}
		})
	}
}

func TestCandidateFor(t *testing.T) {
	pkgName, url := "django", "https://pypi.org/simple/django/"
	if got := CandidateFor(manifest.TypePypi, pkgName, url); got != pkgName {
		t.Errorf("pypi: want %q got %q", pkgName, got)
	}
	if got := CandidateFor(manifest.TypeGit, "widget", "https://github.com/x/y.git"); got != "https://github.com/x/y.git" {
		t.Errorf("git: want URL got %q", got)
	}
	if got := CandidateFor(manifest.TypeGomod, "example.com/example-corp/widget-sdk", "https://proxy.golang.org/..."); got != "example.com/example-corp/widget-sdk" {
		t.Errorf("gomod: want module path got %q", got)
	}
}

func TestRuleKindForType(t *testing.T) {
	cases := map[string]string{
		manifest.TypeApt:    KindHost,
		manifest.TypeGit:    KindOrg,
		manifest.TypePypi:   KindPackage,
		manifest.TypeNpm:    KindPackage,
		manifest.TypeGomod:  KindPrefix,
		manifest.TypeHelm:   KindPrefix,
		manifest.TypeBinary: KindPrefix,
		"unknown":           "",
	}
	for typ, want := range cases {
		if got := RuleKindForType(typ); got != want {
			t.Errorf("RuleKindForType(%q): want %q got %q", typ, want, got)
		}
	}
}

func TestValidateType(t *testing.T) {
	if err := ValidateType(manifest.TypePypi); err != nil {
		t.Errorf("pypi should be valid: %v", err)
	}
	if err := ValidateType("bogus"); err == nil {
		t.Error("bogus should be rejected")
	}
}

func TestCacheHitsStore(t *testing.T) {
	c, store := newChecker(rule("pypi", "django"))
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_ = c.Check(ctx, manifest.TypePypi, "django")
	}
	if store.calls != 1 {
		t.Errorf("store should be hit once (cached), got %d", store.calls)
	}

	// Different type → separate cache entry.
	_ = c.Check(ctx, manifest.TypeGit, "https://github.com/x/y.git")
	if store.calls != 2 {
		t.Errorf("new type should hit store, got %d", store.calls)
	}
}

func TestInvalidateForcesReload(t *testing.T) {
	c, store := newChecker(rule("pypi", "django"))
	ctx := context.Background()
	_ = c.Check(ctx, manifest.TypePypi, "django")
	_ = c.Check(ctx, manifest.TypePypi, "django")
	c.Invalidate()
	_ = c.Check(ctx, manifest.TypePypi, "django")
	if store.calls != 2 {
		t.Errorf("Invalidate should force reload, got %d store calls", store.calls)
	}
}

func TestViolationErrorFields(t *testing.T) {
	c, _ := newChecker(rule("pypi", "django"))
	err := c.Check(context.Background(), manifest.TypePypi, "evilpkg")
	if !IsViolation(err) {
		t.Fatalf("expected violation, got %v", err)
	}
	ve := err.(*ViolationError)
	if ve.RegistryType != manifest.TypePypi {
		t.Errorf("RegistryType = %q", ve.RegistryType)
	}
	if ve.Candidate != "evilpkg" {
		t.Errorf("Candidate = %q", ve.Candidate)
	}
}

// B75 R1: the allow-list is one of four callers of the PEP 503 rule, and the
// copy it used to hold collapsed `_` alone. A rule written `zope.interface`
// matched nothing the route spelled `zope-interface`, so the two allow-lists in
// this tree disagreed about which distribution a rule names.
func TestPypiAllowListMatchesEverySpellingOfOneDistribution(t *testing.T) {
	spellings := map[string][]string{
		"django":              {"Django", "django", "DJANGO"},
		"zope-interface":      {"zope.interface", "zope_interface", "Zope.Interface"},
		"ruamel-yaml":         {"ruamel.yaml", "ruamel-yaml", "RUAMEL_YAML"},
		"django-cors-headers": {"django_cors_headers", "django-cors-headers", "Django.Cors_Headers"},
		"a-b":                 {"a__b", "a.b", "a-b"},
		"a-b-c":               {"A.B_c", "a.b.c", "a-b-c", "A_B_C"},
	}
	for canonical, forms := range spellings {
		for _, pattern := range forms {
			c, _ := newChecker(rule("pypi", pattern))
			for _, candidate := range append(forms, canonical) {
				if err := c.Check(context.Background(), manifest.TypePypi, candidate); err != nil {
					t.Errorf("rule %q refused %q, the same distribution: %v", pattern, candidate, err)
				}
			}
		}
	}
}

// Every caller reaches one function, so a name canonicalizes to the same key
// through the allow-list, the OSV index and the manifest store alike.
func TestPypiCanonicalFormIsTheSameThroughEveryPolicyCaller(t *testing.T) {
	cases := map[string]string{
		"Django":              "django",
		"zope.interface":      "zope-interface",
		"ruamel.yaml":         "ruamel-yaml",
		"django_cors_headers": "django-cors-headers",
		"a__b":                "a-b",
		"A.B_c":               "a-b-c",
	}
	for in, want := range cases {
		if got := manifest.CanonicalPypiName(in); got != want {
			t.Errorf("CanonicalPypiName(%q) = %q, want %q", in, got, want)
		}
		if got := SuggestPattern(manifest.TypePypi, "pypi.org", "/simple/"+in+"/", in); got != want {
			t.Errorf("SuggestPattern(pypi, %q) = %q, want %q", in, got, want)
		}
		if got := osvPackageKey("PyPI", in); got != want {
			t.Errorf("osvPackageKey(PyPI, %q) = %q, want %q", in, got, want)
		}
	}
}
