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
		{"git prefix match", []Rule{rule("git", "github.com/netbox-community/")}, "git", "https://github.com/netbox-community/netbox.git", true},
		{"git prefix no scheme", []Rule{rule("git", "github.com/aws/")}, "git", "git@github.com/aws/aws-sdk-go.git", false},
		{"git wrong org", []Rule{rule("git", "github.com/netbox-community/")}, "git", "https://github.com/attacker/netbox.git", false},
		{"git multiple rules second matches", []Rule{rule("git", "github.com/aws/"), rule("git", "github.com/netbox-community/")}, "git", "https://github.com/netbox-community/netbox.git", true},

		// pypi (normalized name)
		{"pypi exact", []Rule{rule("pypi", "django")}, "pypi", "django", true},
		{"pypi dashes to underscores", []Rule{rule("pypi", "zope.interface")}, "pypi", "zope.interface", true},
		{"pypi upper vs lower", []Rule{rule("pypi", "Django")}, "pypi", "django", true},
		{"pypi dash-underscore equiv", []Rule{rule("pypi", "my_package")}, "pypi", "my-package", true},
		{"pypi mismatch", []Rule{rule("pypi", "django")}, "pypi", "requests", false},

		// npm (exact + @scope/*)
		{"npm exact", []Rule{rule("npm", "lodash")}, "npm", "lodash", true},
		{"npm scope wildcard match", []Rule{rule("npm", "@aws-sdk/*")}, "npm", "@aws-sdk/client-s3", true},
		{"npm scope wildcard no match other scope", []Rule{rule("npm", "@aws-sdk/*")}, "npm", "@evil/payload", false},
		{"npm scope exact without wildcard", []Rule{rule("npm", "@aws-sdk/client-s3")}, "npm", "@aws-sdk/client-dynamodb", false},

		// gomod (prefix on module path)
		{"gomod prefix match", []Rule{rule("gomod", "github.com/aws/")}, "gomod", "github.com/aws/aws-sdk-go", true},
		{"gomod prefix match v2", []Rule{rule("gomod", "github.com/aws/")}, "gomod", "github.com/aws/aws-sdk-go-v2", true},
		{"gomod prefix mismatch", []Rule{rule("gomod", "github.com/aws/")}, "gomod", "github.com/attacker/aws-sdk-go", false},

		// helm (prefix)
		{"helm prefix match", []Rule{rule("helm", "https://kubernetes.github.io/ingress-nginx/")}, "helm", "https://kubernetes.github.io/ingress-nginx/charts/ingress-1.0.0.tgz", true},
		{"helm prefix mismatch", []Rule{rule("helm", "https://kubernetes.github.io/")}, "helm", "https://evil.example.com/chart.tgz", false},

		// binary (prefix)
		{"binary prefix match", []Rule{rule("binary", "https://releases.hashicorp.com/")}, "binary", "https://releases.hashicorp.com/terraform/1.7.0/terraform_1.7.0_darwin_amd64.zip", true},
		{"binary prefix wrong host", []Rule{rule("binary", "https://releases.hashicorp.com/")}, "binary", "https://mirror.example.com/terraform.zip", false},
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
	if got := CandidateFor(manifest.TypeGit, "netbox", "https://github.com/x/y.git"); got != "https://github.com/x/y.git" {
		t.Errorf("git: want URL got %q", got)
	}
	if got := CandidateFor(manifest.TypeGomod, "github.com/aws/aws-sdk-go", "https://proxy.golang.org/..."); got != "github.com/aws/aws-sdk-go" {
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

func TestNormalizePyPI(t *testing.T) {
	cases := map[string]string{
		"Django":          "django",
		"my_package":      "my-package",
		"my-package":      "my-package",
		"Mixed_Case_Name": "mixed-case-name",
	}
	for in, want := range cases {
		if got := normalizePyPI(in); got != want {
			t.Errorf("normalizePyPI(%q) = %q, want %q", in, got, want)
		}
	}
}
