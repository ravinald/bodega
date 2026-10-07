package policy

import (
	"context"
	"strings"
	"testing"
	"time"

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

		// distfiles (host)
		{"distfiles host match", []Rule{rule("distfiles", "distcache.FreeBSD.org")}, "distfiles", "http://distcache.freebsd.org/ports-distfiles/pcpustat/1.6.tar.bz2", true},
		{"distfiles host mismatch", []Rule{rule("distfiles", "distcache.FreeBSD.org")}, "distfiles", "https://mirror.example.com/ports-distfiles/pcpustat/1.6.tar.bz2", false},
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

// ValidateType admits every manifest type, so a type with no rule kind is one
// `bodega policy add` accepts by name and then refuses, and whose fetchers the
// allow-list can never reach.
func TestEveryTypeHasARuleKind(t *testing.T) {
	for _, typ := range manifest.AllTypes {
		if RuleKindForType(typ) == "" {
			t.Errorf("%s has no rule kind: register it in RuleKindForType, matchRule and SuggestPattern", typ)
		}
		if SuggestPattern(typ, "host.example", "/a/b", "name") == "" {
			t.Errorf("%s has no suggested pattern", typ)
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

// digestStore is the four listings Digest reads, held in memory.
type digestStore struct {
	rules   []audit.PolicyInfo
	ages    []audit.AgePolicy
	osvs    []audit.OSVPolicy
	malware []audit.OSVMalwarePolicy
}

func (d *digestStore) ListPolicies(context.Context) ([]audit.PolicyInfo, error) { return d.rules, nil }
func (d *digestStore) ListAgePolicies(context.Context) ([]audit.AgePolicy, error) {
	return d.ages, nil
}
func (d *digestStore) ListOSVPolicies(context.Context) ([]audit.OSVPolicy, error) {
	return d.osvs, nil
}
func (d *digestStore) ListOSVMalwarePolicies(context.Context) ([]audit.OSVMalwarePolicy, error) {
	return d.malware, nil
}

// TestDigestTracksPolicyContent pins the two properties an admission row's
// policy_digest is cited for: decisions under unchanged policy share it, and
// any edit that could change a verdict changes it.
func TestDigestTracksPolicyContent(t *testing.T) {
	base := func() *digestStore {
		return &digestStore{
			rules: []audit.PolicyInfo{
				{ID: "1", RegistryType: "npm", RuleKind: KindPackage, Pattern: "lodash", Comment: "c", CreatedBy: "ravi"},
				{ID: "2", RegistryType: "apt", RuleKind: KindHost, Pattern: "archive.ubuntu.com"},
			},
			ages:    []audit.AgePolicy{{Ecosystem: "npm", MinAgeSeconds: 604800, Action: ActionBlock}},
			osvs:    []audit.OSVPolicy{{Ecosystem: "pypi", Action: ActionWarn}},
			malware: []audit.OSVMalwarePolicy{{Ecosystem: "npm", Action: ActionWarn, Reason: "r"}},
		}
	}
	digest := func(s *digestStore) string {
		t.Helper()
		d, err := Digest(context.Background(), s)
		if err != nil {
			t.Fatalf("Digest: %v", err)
		}
		return d
	}
	want := digest(base())
	if !strings.HasPrefix(want, "sha256:") || len(want) != len("sha256:")+64 {
		t.Fatalf("digest %q is not sha256:<64 hex>", want)
	}

	same := map[string]func(*digestStore){
		"unchanged":                    func(*digestStore) {},
		"rows_listed_in_another_order": func(s *digestStore) { s.rules[0], s.rules[1] = s.rules[1], s.rules[0] },
		"rule_removed_and_re_added": func(s *digestStore) {
			s.rules[0].ID, s.rules[0].Comment, s.rules[0].CreatedBy = "9", "", "someone"
			s.rules[0].CreatedAt = time.Now()
		},
		"policy_row_touched_without_change": func(s *digestStore) { s.ages[0].UpdatedAt = time.Now() },
		"malware_reason_reworded":           func(s *digestStore) { s.malware[0].Reason = "other" },
	}
	for name, edit := range same {
		s := base()
		edit(s)
		if got := digest(s); got != want {
			t.Errorf("%s: digest moved to %s under the same policy", name, got)
		}
	}

	changed := map[string]func(*digestStore){
		"rule_pattern_edited": func(s *digestStore) { s.rules[0].Pattern = "lodash-es" },
		"rule_added": func(s *digestStore) {
			s.rules = append(s.rules, audit.PolicyInfo{RegistryType: "npm", RuleKind: KindPackage, Pattern: "left-pad"})
		},
		"rule_removed":           func(s *digestStore) { s.rules = s.rules[:1] },
		"rule_moved_to_a_type":   func(s *digestStore) { s.rules[0].RegistryType = "cargo" },
		"age_minimum_edited":     func(s *digestStore) { s.ages[0].MinAgeSeconds = 86400 },
		"age_action_edited":      func(s *digestStore) { s.ages[0].Action = ActionWarn },
		"age_policy_removed":     func(s *digestStore) { s.ages = nil },
		"osv_action_edited":      func(s *digestStore) { s.osvs[0].Action = ActionBlock },
		"malware_action_edited":  func(s *digestStore) { s.malware[0].Action = ActionIgnore },
		"malware_policy_removed": func(s *digestStore) { s.malware = nil },
		"osv_policy_added": func(s *digestStore) {
			s.osvs = append(s.osvs, audit.OSVPolicy{Ecosystem: "npm", Action: ActionBlock})
		},
	}
	seen := map[string]string{want: "base"}
	for name, edit := range changed {
		s := base()
		edit(s)
		got := digest(s)
		if prior, dup := seen[got]; dup {
			t.Errorf("%s: digest %s is the same as %s's", name, got, prior)
		}
		seen[got] = name
	}
}
