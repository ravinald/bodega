package policy

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

func TestDamerauLevenshtein(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"requests", "requests", 0},
		{"requests", "reqeusts", 1}, // adjacent swap
		{"requests", "request", 1},  // deletion
		{"requests", "rrequests", 1},
		{"requests", "requezts", 1},
		{"lodash", "lodahs", 1},
		{"ca", "abc", 2}, // unrestricted: the restricted form says 3
		{"colorama", "colourama", 1},
		{"abc", "", 3},
		{"kitten", "sitting", 3},
	}
	for _, c := range cases {
		if got := damerauLevenshtein(c.a, c.b); got != c.want {
			t.Errorf("damerauLevenshtein(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := damerauLevenshtein(c.b, c.a); got != c.want {
			t.Errorf("damerauLevenshtein(%q, %q) = %d, want %d (not symmetric)", c.b, c.a, got, c.want)
		}
	}
}

func list(t *testing.T, eco string, names ...string) PopularNames {
	t.Helper()
	p, err := ParsePopularNames(eco, []byte("# source: test\n# date: 2026-10-13\n"+strings.Join(names, "\n")+"\n"))
	if err != nil {
		t.Fatalf("ParsePopularNames: %v", err)
	}
	return p
}

// A hit names the nearest popular name and the distance; a name equal to a
// popular one after normalization, or further than two edits, is not one.
func TestNearHitsAndMisses(t *testing.T) {
	pypi := list(t, manifest.TypePypi, "requests", "python-dateutil", "numpy")
	npm := list(t, manifest.TypeNpm, "lodash", "@types/node", "express")
	cargo := list(t, manifest.TypeCargo, "serde_json", "tokio")
	cases := []struct {
		name    string
		list    PopularNames
		cand    string
		popular string
		dist    int
	}{
		{"pypi swap", pypi, "reqeusts", "requests", 1},
		{"pypi missing letter", pypi, "reqests", "requests", 1},
		{"pypi two edits", pypi, "reqeust", "requests", 2},
		{"pep503 case and separators", pypi, "Python_DateUtill", "python-dateutil", 1},
		{"pep503 dot run", pypi, "python..dateutl", "python-dateutil", 1},
		{"npm uppercase", npm, "Lodahs", "lodash", 1},
		{"npm scope typo", npm, "@typse/node", "@types/node", 1},
		{"npm scoped name typo", npm, "@types/nodee", "@types/node", 1},
		{"npm scope and name", npm, "@type/nod", "@types/node", 2},
		{"npm one-letter scope on an unscoped name", npm, "@a/lodash", "lodash", 1},
		{"npm two-letter scope on an unscoped name", npm, "@ab/lodash", "lodash", 2},
		{"cargo separator is not an edit", cargo, "Serde-Jsno", "serde_json", 1},
		{"cargo", cargo, "tokioo", "tokio", 1},
	}
	for _, c := range cases {
		popular, dist, ok := c.list.Near(c.cand)
		if !ok || popular != c.popular || dist != c.dist {
			t.Errorf("%s: Near(%q) = %q, %d, %v; want %q, %d, true", c.name, c.cand, popular, dist, ok, c.popular, c.dist)
		}
	}

	misses := []struct {
		name string
		list PopularNames
		cand string
	}{
		{"pypi equal", pypi, "requests"},
		{"pep503 equal", pypi, "Python_DateUtil"},
		{"pep503 dots equal", pypi, "python.dateutil"},
		{"far", pypi, "bodega-internal-widget"},
		{"three edits", pypi, "rekwestz"},
		{"npm equal scoped", npm, "@Types/Node"},
		// The scope distances add to the name's: `@evil` against no scope is
		// 4, so `@evil/lodash` is 4 from `lodash`, while `@a/lodash` is 1.
		{"npm foreign scope", npm, "@evil/lodash"},
		{"npm unscoped against scoped", npm, "types-node"},
		{"cargo equal after separator", cargo, "serde-json"},
	}
	for _, c := range misses {
		if popular, dist, ok := c.list.Near(c.cand); ok {
			t.Errorf("%s: Near(%q) = %q at %d, want no hit", c.name, c.cand, popular, dist)
		}
	}
}

// A scope is compared with the other name's scope, so one the popular name
// lacks costs its length and no more: the `@` and `/` are not edits.
func TestNearScopedAgainstUnscopedEmbedded(t *testing.T) {
	npm, _ := EmbeddedPopularNames(manifest.TypeNpm)
	if popular, dist, ok := npm.Near("@a/yaml"); !ok || popular != "yaml" || dist != 1 {
		t.Errorf("Near(%q) = %q, %d, %v; want %q, 1, true", "@a/yaml", popular, dist, ok, "yaml")
	}
}

// Nearest skips names it can prove are no closer than the best so far; the
// skip must never change the answer. Every candidate gets the name and the
// distance a scan of the whole list returns, ties going to the more popular.
// The scan is quadratic in the list, so a sample of names seeds candidates,
// denser for npm, whose floor splits the scope and so is not the textbook
// length bound pypi and cargo use.
func TestNearestMatchesBruteForce(t *testing.T) {
	for _, eco := range SimilarityEcosystems() {
		p, _ := EmbeddedPopularNames(eco)
		stride := 50
		if eco == manifest.TypeNpm {
			stride = 17
		}
		var cands []string
		for i, n := range p.Names {
			if i%stride != 0 {
				continue
			}
			cands = append(cands, n, n+"x", n[1:])
			if eco == manifest.TypeMaven {
				group, artifact := splitMavenName(n)
				cands = append(cands, "io.github.someone:"+artifact, group+"x:"+artifact, group+":"+artifact[1:])
				continue
			}
			if eco != manifest.TypeNpm {
				continue
			}
			if scope, bare := splitNpmScope(n); scope == "" {
				cands = append(cands, "@a/"+n, "@ab/"+n)
			} else {
				cands = append(cands, bare, "@"+scope[1:]+"/"+bare)
			}
		}
		for _, c := range cands {
			key := NormalizeName(eco, c)
			want, wantD := "", -1
			for i, k := range p.keys {
				if d := nameDistance(eco, key, k, p.sharedArtifacts); wantD < 0 || d < wantD {
					want, wantD = p.Names[i], d
				}
			}
			if got, gotD, _ := p.Nearest(c); got != want || gotD != wantD {
				t.Errorf("%s: Nearest(%q) = %q at %d; the whole list says %q at %d", eco, c, got, gotD, want, wantD)
			}
		}
	}
}

func TestParsePopularNames(t *testing.T) {
	p, err := ParsePopularNames(manifest.TypePypi, []byte("# Top things\n# source: https://example.test/top.json\n# n: 3\n# date: 2026-10-01\nrequests\n\nRequests\nnumpy\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Source != "https://example.test/top.json" || p.Date != "2026-10-01" {
		t.Errorf("header = %q, %q", p.Source, p.Date)
	}
	if strings.Join(p.Names, ",") != "requests,numpy" {
		t.Errorf("Names = %v, want the duplicate dropped after normalization", p.Names)
	}
	if !strings.HasPrefix(p.SHA256, "sha256:") {
		t.Errorf("SHA256 = %q", p.SHA256)
	}
	if _, err := ParsePopularNames(manifest.TypePypi, []byte("# only a header\n")); err == nil {
		t.Error("an empty list parsed")
	}
	if _, err := ParsePopularNames(manifest.TypePypi, []byte("requests 2.0\n")); err == nil {
		t.Error("a line with a space parsed as a name")
	}
}

// Every shipped list records N and the source date in its header, and N is
// what it holds.
func TestEmbeddedListsRecordTheirHeader(t *testing.T) {
	for _, eco := range SimilarityEcosystems() {
		data, err := popularFS.ReadFile("popular/" + eco + ".txt")
		if err != nil {
			t.Fatal(err)
		}
		var n int
		for _, line := range strings.Split(string(data), "\n") {
			if v, ok := strings.CutPrefix(line, "# n: "); ok {
				n, _ = strconv.Atoi(v)
			}
		}
		p, ok := EmbeddedPopularNames(eco)
		if !ok {
			t.Fatalf("%s: no embedded list", eco)
		}
		if n == 0 || len(p.Names) != n {
			t.Errorf("%s: header n=%d, list holds %d", eco, n, len(p.Names))
		}
		if _, err := time.Parse("2006-01-02", p.Date); err != nil || p.Source == "" {
			t.Errorf("%s: header date %q source %q", eco, p.Date, p.Source)
		}
	}
	if _, ok := EmbeddedPopularNames(manifest.TypeGomod); ok {
		t.Error("gomod has an embedded list")
	}
	if p, _ := EmbeddedPopularNames(manifest.TypePypi); !p.Contains("requests") {
		t.Error("the pypi list does not hold requests")
	}
}

// similarityStore is the check's reads, held in memory.
type similarityStore struct {
	action   string
	loaded   *audit.PopularList
	rules    []Rule
	taken    bool
	baseline map[string]bool
	err      error
}

func (s *similarityStore) GetSimilarityPolicy(_ context.Context, eco string) (audit.SimilarityPolicy, error) {
	if s.err != nil {
		return audit.SimilarityPolicy{}, s.err
	}
	if s.action == "" {
		return audit.SimilarityPolicy{}, audit.ErrSimilarityPolicyNotFound
	}
	return audit.SimilarityPolicy{Ecosystem: eco, Action: s.action}, nil
}
func (s *similarityStore) GetPopularList(context.Context, string) (audit.PopularList, error) {
	if s.loaded == nil {
		return audit.PopularList{}, audit.ErrPopularListNotFound
	}
	return *s.loaded, nil
}
func (s *similarityStore) GetPoliciesByType(context.Context, string) ([]Rule, error) {
	return s.rules, nil
}
func (s *similarityStore) NameBaseline(context.Context) (audit.NameBaselineState, error) {
	return audit.NameBaselineState{Taken: s.taken, TakenAt: time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC), Packages: len(s.baseline)}, nil
}
func (s *similarityStore) InNameBaseline(_ context.Context, typ, key string) (bool, error) {
	return s.baseline[typ+"/"+key], nil
}

func checkName(t *testing.T, store SimilarityStore, typ, name string) Result {
	t.Helper()
	pm := &manifest.PackageManifest{Type: typ, Name: name, Versions: []manifest.VersionEntry{{Version: "1.0.0"}}}
	return NewNameSimilarityChecker(store).Check(t.Context(), pm, &pm.Versions[0])
}

func TestNameSimilarityCheckerActions(t *testing.T) {
	r := checkName(t, &similarityStore{}, manifest.TypePypi, "reqeusts")
	if r.Check != audit.CheckNameSimilarity || r.Action != ActionWarn {
		t.Fatalf("default = %+v, want a warn", r)
	}
	if !strings.Contains(r.Reason, "requests") || !strings.Contains(r.Reason, "distance 1") {
		t.Errorf("reason %q does not name the popular name and the distance", r.Reason)
	}
	if r.Details["nearest"] != "requests" || r.Details["distance"] != 1 {
		t.Errorf("details = %v", r.Details)
	}
	if r := checkName(t, &similarityStore{action: ActionBlock}, manifest.TypePypi, "reqeusts"); r.Action != ActionBlock {
		t.Errorf("block = %+v", r)
	}
	if r := checkName(t, &similarityStore{action: ActionIgnore}, manifest.TypePypi, "reqeusts"); r.Action != ActionIgnore || !strings.Contains(r.Reason, "requests") {
		t.Errorf("ignore = %+v, want ignore still naming the near name", r)
	}
	if r := checkName(t, &similarityStore{action: ActionBlock}, manifest.TypePypi, "requests"); r.Action != ActionPass {
		t.Errorf("a popular name = %+v, want a pass", r)
	}
	if r := checkName(t, &similarityStore{action: ActionBlock}, manifest.TypePypi, "bodega-internal-widget"); r.Action != ActionPass {
		t.Errorf("a far name = %+v, want a pass", r)
	}
	if r := checkName(t, &similarityStore{action: ActionBlock}, manifest.TypeGomod, "github.com/gorila/mux"); r.Action != ActionNotEvaluated {
		t.Errorf("gomod = %+v, want not_evaluated", r)
	}
	if r := checkName(t, nil, manifest.TypePypi, "reqeusts"); r.Action != ActionNotEvaluated {
		t.Errorf("no store = %+v, want not_evaluated", r)
	}
	if r := checkName(t, &similarityStore{err: errors.New("disk")}, manifest.TypePypi, "reqeusts"); r.Action != ActionWarn {
		t.Errorf("policy read failure = %+v, want a warn", r)
	}
}

// Names an exact rule names, or that the store held when the baseline was
// taken, pass under block; a wildcard rule exempts nothing.
func TestNameSimilarityExemptions(t *testing.T) {
	exact := &similarityStore{action: ActionBlock, rules: []Rule{{RegistryType: manifest.TypePypi, Pattern: "Reqeusts"}}}
	if r := checkName(t, exact, manifest.TypePypi, "reqeusts"); r.Action != ActionPass || !strings.Contains(r.Reason, "exact rule") {
		t.Errorf("exact rule = %+v, want an exempt pass", r)
	}
	wildcard := &similarityStore{action: ActionBlock, rules: []Rule{{RegistryType: manifest.TypeNpm, Pattern: "@typse/*"}}}
	if r := checkName(t, wildcard, manifest.TypeNpm, "@typse/node"); r.Action != ActionBlock {
		t.Errorf("wildcard rule = %+v, want a block", r)
	}
	scopedExact := &similarityStore{action: ActionBlock, rules: []Rule{{RegistryType: manifest.TypeNpm, Pattern: "@typse/node"}}}
	if r := checkName(t, scopedExact, manifest.TypeNpm, "@typse/node"); r.Action != ActionPass {
		t.Errorf("scoped exact rule = %+v, want a pass", r)
	}

	// The baseline is keyed by the store's safe name, so a scoped npm name
	// is found the way the store lists it.
	inUse := &similarityStore{action: ActionBlock, taken: true, baseline: map[string]bool{
		"npm/" + NormalizeName(manifest.TypeNpm, manifest.SafeName("@typse/node")): true,
		"pypi/reqeusts": true,
	}}
	if r := checkName(t, inUse, manifest.TypeNpm, "@Typse/Node"); r.Action != ActionPass || !strings.Contains(r.Reason, "baseline") {
		t.Errorf("baseline npm = %+v, want an exempt pass", r)
	}
	if r := checkName(t, inUse, manifest.TypePypi, "Reqeusts"); r.Action != ActionPass {
		t.Errorf("baseline pypi under PEP 503 = %+v, want a pass", r)
	}
	if r := checkName(t, inUse, manifest.TypePypi, "reqests"); r.Action != ActionBlock {
		t.Errorf("a name outside the baseline = %+v, want a block", r)
	}
}

// A loaded list replaces the embedded one whole.
func TestLoadedListReplacesEmbedded(t *testing.T) {
	text := "# source: internal mirror\nacme-core\n"
	p, _ := ParsePopularNames(manifest.TypePypi, []byte(text))
	store := &similarityStore{action: ActionBlock, loaded: &audit.PopularList{Ecosystem: manifest.TypePypi, Names: text, SHA256: p.SHA256}}
	if r := checkName(t, store, manifest.TypePypi, "acme-cor"); r.Action != ActionBlock || !strings.Contains(r.Reason, "loaded list") {
		t.Errorf("near a loaded name = %+v", r)
	}
	if r := checkName(t, store, manifest.TypePypi, "reqeusts"); r.Action != ActionPass {
		t.Errorf("near an embedded name after a load = %+v, want a pass", r)
	}
}

func TestTakeNameBaselineOnce(t *testing.T) {
	adb, err := audit.Open(t.TempDir() + "/audit.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = adb.Close() })
	ctx := t.Context()
	took, err := TakeNameBaseline(ctx, adb, map[string][]string{manifest.TypePypi: {"Reqeusts"}, manifest.TypeNpm: {"@typse--node"}})
	if err != nil || !took {
		t.Fatalf("first take = %v, %v", took, err)
	}
	took, err = TakeNameBaseline(ctx, adb, map[string][]string{manifest.TypePypi: {"reqests"}})
	if err != nil || took {
		t.Fatalf("second take = %v, %v, want no second baseline", took, err)
	}
	r := checkName(t, adb, manifest.TypePypi, "reqeusts")
	if r.Action != ActionPass {
		t.Errorf("baseline name = %+v", r)
	}
	if r := checkName(t, adb, manifest.TypeNpm, "@typse/node"); r.Action != ActionPass {
		t.Errorf("baseline scoped name = %+v", r)
	}
	if r := checkName(t, adb, manifest.TypePypi, "reqests"); r.Action != ActionWarn {
		t.Errorf("name offered to the second take = %+v, want a warn", r)
	}
	if st, _ := adb.NameBaseline(ctx); !st.Taken || st.Packages != 2 || st.Admitted != 0 {
		t.Errorf("NameBaseline = %+v", st)
	}
}

// RubyGems keeps `-` and `_` apart: `rest_client` is its own gem, one edit
// from `rest-client`, which is the shape the 2020 atlas-client/atlas_client
// squat took. Folding the separator, as pypi and cargo do, would read it as
// the popular gem itself and pass it.
func TestNameSimilarityRubygemsSeparatorIsAnEdit(t *testing.T) {
	if NormalizeName(manifest.TypeRubygems, "rest_client") == NormalizeName(manifest.TypeRubygems, "rest-client") {
		t.Fatal("rubygems folds _ into -; the two are distinct gems")
	}
	if NormalizeName(manifest.TypeRubygems, "Rails") != "rails" {
		t.Error("rubygems.org refuses a name differing only in case, so case is folded")
	}
	r := checkName(t, &similarityStore{action: ActionBlock}, manifest.TypeRubygems, "rest_client")
	if r.Action != ActionBlock || r.Details["nearest"] != "rest-client" || r.Details["distance"] != 1 {
		t.Errorf("rest_client = %+v, want a block naming rest-client at distance 1", r)
	}
	if r := checkName(t, &similarityStore{action: ActionBlock}, manifest.TypeRubygems, "rest-client"); r.Action != ActionPass {
		t.Errorf("the popular gem itself = %+v, want a pass", r)
	}
	exact := &similarityStore{action: ActionBlock, rules: []Rule{{RegistryType: manifest.TypeRubygems, Pattern: "rest_client"}}}
	if r := checkName(t, exact, manifest.TypeRubygems, "rest_client"); r.Action != ActionPass {
		t.Errorf("an exact rubygems rule exempts its own name; got %+v", r)
	}
}

// Maven's squat is a lookalike groupId over the real artifactId:
// org.fasterxml.jackson.core:jackson-databind, reported by Socket in March
// 2025 posing as com.fasterxml.jackson.core:jackson-databind. com to org is
// three edits, so it is caught by the artifactId alone, compared across
// groupIds. Within one groupId the artifactId is compared by edits, and a
// near groupId with a near artifactId by their sum.
func TestNameSimilarityMavenLookalikeGroupID(t *testing.T) {
	for _, tc := range []struct {
		name, nearest string
		distance      int
	}{
		{"org.fasterxml.jackson.core:jackson-databind", "com.fasterxml.jackson.core:jackson-databind", 1},
		{"io.github.someone:jackson-databind", "com.fasterxml.jackson.core:jackson-databind", 1},
		{"com.google.guava:guawa", "com.google.guava:guava", 1},
		{"com.googie.guava:guavaa", "com.google.guava:guava", 2},
	} {
		r := checkName(t, &similarityStore{action: ActionBlock}, manifest.TypeMaven, tc.name)
		if r.Action != ActionBlock || r.Details["nearest"] != tc.nearest || r.Details["distance"] != tc.distance {
			t.Errorf("%s = %+v, want a block naming %s at distance %d", tc.name, r, tc.nearest, tc.distance)
		}
	}
	for _, name := range []string{"com.fasterxml.jackson.core:jackson-databind", "com.example.internal:billing-service"} {
		if r := checkName(t, &similarityStore{action: ActionBlock}, manifest.TypeMaven, name); r.Action != ActionPass {
			t.Errorf("%s = %+v, want a pass", name, r)
		}
	}
	exact := &similarityStore{action: ActionBlock, rules: []Rule{{RegistryType: manifest.TypeMaven, Pattern: "org.fasterxml.jackson.core:jackson-databind"}}}
	if r := checkName(t, exact, manifest.TypeMaven, "org.fasterxml.jackson.core:jackson-databind"); r.Action != ActionPass {
		t.Errorf("an exact maven rule exempts its own name; got %+v", r)
	}
	group := &similarityStore{action: ActionBlock, rules: []Rule{{RegistryType: manifest.TypeMaven, Pattern: "org.fasterxml.jackson.core:*"}}}
	if r := checkName(t, group, manifest.TypeMaven, "org.fasterxml.jackson.core:jackson-databind"); r.Action != ActionBlock {
		t.Errorf("a <groupId>:* rule names no one artifact and exempts none; got %+v", r)
	}
}

// An artifactId the popular list carries under more than one groupId names
// nothing in particular, so the cross-groupId case skips it: every AWS SDK v2
// module depends on software.amazon.awssdk:annotations, and that is no squat
// on org.jetbrains:annotations.
func TestNameSimilarityMavenSharedArtifactID(t *testing.T) {
	for _, name := range []string{"software.amazon.awssdk:annotations", "com.android.tools:annotations", "com.example:core"} {
		if r := checkName(t, &similarityStore{action: ActionBlock}, manifest.TypeMaven, name); r.Action != ActionPass {
			t.Errorf("%s = %+v, want a pass", name, r)
		}
	}
}

// A shared artifactId that a carrier's groupId names keeps the cross-groupId
// case: guava is com.google.guava's, whoever else republishes it. One that no
// carrier's groupId names stays shared, which is where hibernate-validator
// (org.hibernate, org.hibernate.validator) and jersey-server
// (org.glassfish.jersey.core, com.sun.jersey) land.
func TestNameSimilarityMavenSharedArtifactNamedByGroupID(t *testing.T) {
	p, ok := EmbeddedPopularNames(manifest.TypeMaven)
	if !ok {
		t.Fatal("no embedded maven list")
	}
	for _, tc := range []struct {
		name string
		near bool
	}{
		{"io.github.someone:guava", true},
		{"org.google.guava:guava", true},
		{"io.evil:okhttp", true},
		{"io.github.x:postgresql", true},
		{"io.github.x:commons-io", true},
		{"io.github.x:rxjava", true},
		{"io.github.x:hibernate-validator", false},
		{"io.github.x:jersey-server", false},
	} {
		if got, d, near := p.Near(tc.name); near != tc.near {
			t.Errorf("%s: near = %v (%s at %d), want %v", tc.name, near, got, d, tc.near)
		}
	}
}

func TestSharedMavenArtifactsFromList(t *testing.T) {
	p, err := ParsePopularNames(manifest.TypeMaven, []byte("org.jetbrains:annotations\ncom.google.code.findbugs:annotations\ncom.fasterxml.jackson.core:jackson-databind\n"))
	if err != nil {
		t.Fatalf("ParsePopularNames: %v", err)
	}
	if !p.sharedArtifacts["annotations"] || p.sharedArtifacts["jackson-databind"] || len(p.sharedArtifacts) != 1 {
		t.Errorf("shared = %v, want annotations alone", p.sharedArtifacts)
	}
	if _, d, _ := p.Nearest("software.amazon.awssdk:annotations"); d <= MaxSimilarityDistance {
		t.Errorf("a shared artifactId under another groupId is %d away, want the summed distance", d)
	}
	if got, d, _ := p.Nearest("org.fasterxml.jackson.core:jackson-databind"); got != "com.fasterxml.jackson.core:jackson-databind" || d != 1 {
		t.Errorf("a distinctive artifactId under another groupId = %s at %d, want jackson-databind at 1", got, d)
	}
}

// Packagist's squat is a lookalike vendor over a real package name, since
// anyone may claim an unused vendor. A popular package name under another
// vendor is distance 1, the vendor replaced whole; within a vendor, and for a
// near vendor with a near package, the edits are summed.
func TestNameSimilarityComposerLookalikeVendor(t *testing.T) {
	for _, tc := range []struct {
		name, nearest string
		distance      int
	}{
		{"guzzle-http/guzzle", "guzzlehttp/guzzle", 1},
		{"acme/guzzle", "guzzlehttp/guzzle", 1},
		{"symfont/console", "symfony/console", 1},
		{"symfony/consoel", "symfony/console", 1},
		{"monolog/monologg", "monolog/monolog", 1},
	} {
		r := checkName(t, &similarityStore{action: ActionBlock}, manifest.TypeComposer, tc.name)
		if r.Action != ActionBlock || r.Details["nearest"] != tc.nearest || r.Details["distance"] != tc.distance {
			t.Errorf("%s = %+v, want a block naming %s at distance %d", tc.name, r, tc.nearest, tc.distance)
		}
	}
	for _, name := range []string{"guzzlehttp/guzzle", "symfony/console", "acme/billing-service"} {
		if r := checkName(t, &similarityStore{action: ActionBlock}, manifest.TypeComposer, name); r.Action != ActionPass {
			t.Errorf("%s = %+v, want a pass", name, r)
		}
	}
	exact := &similarityStore{action: ActionBlock, rules: []Rule{{RegistryType: manifest.TypeComposer, Pattern: "acme/guzzle"}}}
	if r := checkName(t, exact, manifest.TypeComposer, "acme/guzzle"); r.Action != ActionPass {
		t.Errorf("an exact composer rule exempts its own name; got %+v", r)
	}
}

// A package name the list carries under more than one vendor skips the
// cross-vendor case only when no carrier's vendor names it, by a label split
// at "-", "_" and ".". psr7 (guzzlehttp, nyholm, slim) and console (symfony,
// illuminate) name nothing in particular; parsedown is erusev's and
// parsedown's, and laravel is laravel's, so a lookalike vendor over either is
// still near.
func TestNameSimilarityComposerSharedPackageNamedByVendor(t *testing.T) {
	p, ok := EmbeddedPopularNames(manifest.TypeComposer)
	if !ok {
		t.Fatal("no embedded composer list")
	}
	for _, tc := range []struct {
		name string
		near bool
	}{
		{"acme/psr7", false},
		{"acme/console", false},
		{"acme/parsedown", true},
		{"acme/laravel", true},
	} {
		if got, d, near := p.Near(tc.name); near != tc.near {
			t.Errorf("%s: near = %v (%s at %d), want %v", tc.name, near, got, d, tc.near)
		}
	}
	shared := sharedComposerPackages([]string{"erusev/parsedown", "parsedown/parsedown", "guzzlehttp/psr7", "nyholm/psr7",
		"php-http/discovery", "acme/discovery", "php-http/http", "acme/http"})
	if !shared["psr7"] || !shared["discovery"] || shared["parsedown"] || shared["http"] {
		t.Errorf("shared = %v, want psr7 and discovery; parsedown and http (a label of php-http) are named", shared)
	}
}

// An rpm name a character or two from one a stock EL9 host installs is held,
// and the name itself is not.
func TestNameSimilarityRpm(t *testing.T) {
	for _, tc := range []struct {
		name, nearest string
		distance      int
	}{
		{"openssl-lib", "openssl-libs", 1},
		{"sytemd", "systemd", 1},
		{"curll", "curl", 1},
	} {
		r := checkName(t, &similarityStore{action: ActionBlock}, manifest.TypeRpm, tc.name)
		if r.Action != ActionBlock || r.Details["nearest"] != tc.nearest || r.Details["distance"] != tc.distance {
			t.Errorf("%s = %+v, want a block naming %s at distance %d", tc.name, r, tc.nearest, tc.distance)
		}
	}
	for _, name := range []string{"openssl-libs", "NetworkManager", "acme-billing-agent"} {
		if r := checkName(t, &similarityStore{action: ActionBlock}, manifest.TypeRpm, name); r.Action != ActionPass {
			t.Errorf("%s = %+v, want a pass", name, r)
		}
	}
}
