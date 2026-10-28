package policy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

type fakeAgeStore struct {
	policies map[string]audit.AgePolicy
}

func (f *fakeAgeStore) GetAgePolicy(_ context.Context, ecosystem string) (audit.AgePolicy, error) {
	p, ok := f.policies[ecosystem]
	if !ok {
		return audit.AgePolicy{}, audit.ErrAgePolicyNotFound
	}
	return p, nil
}

// stubNpm replies to /{pkg} with a packument carrying one version's time.
func stubNpm(t *testing.T, pkg, version string, publishedAt time.Time) *httptest.Server {
	t.Helper()
	body := fmt.Sprintf(`{"time":{"%s":%q}}`, version, publishedAt.UTC().Format(time.RFC3339Nano))
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/"+pkg {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		fmt.Fprint(w, body)
	}))
}

func TestAgePolicy_NoPolicy(t *testing.T) {
	ck := NewAgeChecker(&fakeAgeStore{})
	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "lodash", Type: manifest.TypeNpm},
		&manifest.VersionEntry{Version: "4.17.21"})
	if r.Action != ActionPass {
		t.Errorf("no policy should short-circuit pass, got %+v", r)
	}
}

func TestAgePolicy_BlocksTooNew(t *testing.T) {
	published := time.Now().Add(-12 * time.Hour)
	srv := stubNpm(t, "left-pad", "0.0.1", published)
	defer srv.Close()

	store := &fakeAgeStore{policies: map[string]audit.AgePolicy{
		manifest.TypeNpm: {Ecosystem: manifest.TypeNpm, MinAgeSeconds: int64((7 * 24 * time.Hour).Seconds()), Action: ActionBlock},
	}}
	ck := NewAgeChecker(store)
	ck.NpmRegistry = srv.URL

	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "left-pad", Type: manifest.TypeNpm},
		&manifest.VersionEntry{Version: "0.0.1"})
	if r.Action != ActionBlock {
		t.Errorf("expected block for 12h-old vs 7d policy, got %+v", r)
	}
	if r.Details["min_age_seconds"] == nil {
		t.Error("block result missing structured details")
	}
}

func TestAgePolicy_PassesWhenOldEnough(t *testing.T) {
	published := time.Now().Add(-30 * 24 * time.Hour)
	srv := stubNpm(t, "pkg", "1.0.0", published)
	defer srv.Close()

	store := &fakeAgeStore{policies: map[string]audit.AgePolicy{
		manifest.TypeNpm: {Ecosystem: manifest.TypeNpm, MinAgeSeconds: int64((7 * 24 * time.Hour).Seconds()), Action: ActionBlock},
	}}
	ck := NewAgeChecker(store)
	ck.NpmRegistry = srv.URL

	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "pkg", Type: manifest.TypeNpm},
		&manifest.VersionEntry{Version: "1.0.0"})
	if r.Action != ActionPass {
		t.Errorf("30d old vs 7d policy should pass, got %+v", r)
	}
}

func TestAgePolicy_WarnDoesNotBlock(t *testing.T) {
	published := time.Now().Add(-1 * time.Hour)
	srv := stubNpm(t, "fresh", "1.0.0", published)
	defer srv.Close()

	store := &fakeAgeStore{policies: map[string]audit.AgePolicy{
		manifest.TypeNpm: {Ecosystem: manifest.TypeNpm, MinAgeSeconds: int64((24 * time.Hour).Seconds()), Action: ActionWarn},
	}}
	ck := NewAgeChecker(store)
	ck.NpmRegistry = srv.URL

	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "fresh", Type: manifest.TypeNpm},
		&manifest.VersionEntry{Version: "1.0.0"})
	if r.Action != ActionWarn {
		t.Errorf("1h old + warn policy should warn, got %+v", r)
	}
}

// Ecosystems without an upstream-time endpoint short-circuit to pass even
// when a policy row exists for them.
func TestAgePolicy_UnsupportedEcosystem(t *testing.T) {
	store := &fakeAgeStore{policies: map[string]audit.AgePolicy{
		manifest.TypeApt: {Ecosystem: manifest.TypeApt, MinAgeSeconds: 86400, Action: ActionBlock},
	}}
	ck := NewAgeChecker(store)
	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "bash", Type: manifest.TypeApt},
		&manifest.VersionEntry{Version: "5.2.21"})
	// Unsupported ecosystem => publishedAt errors => warn (not block).
	// The operator sees "upstream timestamp unavailable" in the audit.
	if r.Action == ActionBlock {
		t.Errorf("unsupported ecosystem should not block; got %+v", r)
	}
}

func TestRunChecks_CombinesResults(t *testing.T) {
	passChecker := stubChecker{name: "pass-one", action: ActionPass}
	warnChecker := stubChecker{name: "warn-one", action: ActionWarn, reason: "stale"}
	blockChecker := stubChecker{name: "block-one", action: ActionBlock, reason: "cve"}

	combined := RunChecks(context.Background(), nil, nil, passChecker, warnChecker, blockChecker)
	if !combined.Blocked() {
		t.Error("expected Blocked true")
	}
	if len(combined.Blocks) != 1 || len(combined.Warns) != 1 {
		t.Errorf("buckets wrong: blocks=%d warns=%d", len(combined.Blocks), len(combined.Warns))
	}
	reasons := combined.Reasons()
	if !contains(reasons, "cve") || !contains(reasons, "stale") {
		t.Errorf("Reasons() dropped context: %q", reasons)
	}
}

type stubChecker struct{ name, action, reason string }

func (s stubChecker) Check(_ context.Context, _ *manifest.PackageManifest, _ *manifest.VersionEntry) Result {
	return Result{Check: s.name, Action: s.action, Reason: s.reason}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func TestAgePolicy_CargoDatedFromCratesIO(t *testing.T) {
	published := time.Now().Add(-3 * time.Hour)
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		fmt.Fprintf(w, `{"version":{"num":"0.1.44","created_at":%q}}`,
			published.UTC().Format(time.RFC3339Nano))
	}))
	defer srv.Close()

	store := &fakeAgeStore{policies: map[string]audit.AgePolicy{
		manifest.TypeCargo: {Ecosystem: manifest.TypeCargo, MinAgeSeconds: int64((7 * 24 * time.Hour).Seconds()), Action: ActionBlock},
	}}
	ck := NewAgeChecker(store)
	ck.CratesBase = srv.URL

	r := ck.Check(context.Background(),
		&manifest.PackageManifest{Name: "time", Type: manifest.TypeCargo},
		&manifest.VersionEntry{Version: "0.1.44"})
	if r.Action != ActionBlock {
		t.Fatalf("3h-old crate under a 7d policy blocks; got %+v", r)
	}
	if gotPath != "/api/v1/crates/time/0.1.44" {
		t.Errorf("crates.io version endpoint, got %q", gotPath)
	}
}

// A gem is dated from the versions API, which lists every build of every
// version in one document: the build the gem file names is the one whose
// number and platform both match, and a build the document does not list is
// not dated at all.
func TestAgePolicy_GemDatedFromVersionsAPI(t *testing.T) {
	now := time.Now()
	stamp := func(d time.Duration) string { return now.Add(-d).UTC().Format(time.RFC3339Nano) }
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path != "/api/v1/versions/nokogiri.json" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, `[
			{"number":"1.16.7","platform":"x86_64-linux","created_at":%q},
			{"number":"1.16.7","platform":"ruby","created_at":%q},
			{"number":"1.16.6","platform":"ruby","created_at":%q}
		]`, stamp(2*time.Hour), stamp(30*24*time.Hour), stamp(60*24*time.Hour))
	}))
	defer srv.Close()

	store := &fakeAgeStore{policies: map[string]audit.AgePolicy{
		manifest.TypeRubygems: {Ecosystem: manifest.TypeRubygems, MinAgeSeconds: int64((7 * 24 * time.Hour).Seconds()), Action: ActionBlock},
	}}
	for _, tc := range []struct {
		version string
		action  string
		reason  string
	}{
		{"1.16.7-x86_64-linux", ActionBlock, "nokogiri@1.16.7-x86_64-linux is 2h old"},
		{"1.16.7", ActionPass, ""},
		{"1.16.5", ActionWarn, "does not list nokogiri 1.16.5 for platform ruby"},
		{"1.16.6-java", ActionWarn, "does not list nokogiri 1.16.6 for platform java"},
	} {
		ck := NewAgeChecker(store)
		ck.RubygemsBase = srv.URL
		ck.HTTP = srv.Client()
		r := ck.Check(context.Background(),
			&manifest.PackageManifest{Name: "nokogiri", Type: manifest.TypeRubygems},
			&manifest.VersionEntry{Version: tc.version})
		if r.Action != tc.action || !strings.Contains(r.Reason, tc.reason) {
			t.Errorf("%s: got %s %q, want %s containing %q", tc.version, r.Action, r.Reason, tc.action, tc.reason)
		}
	}
	for _, p := range paths {
		if p != "/api/v1/versions/nokogiri.json" {
			t.Errorf("versions API path, got %q", p)
		}
	}
}

// Two checks of one gem version under one ShareLookups context read the versions API
// once, as two checks of one crate version read crates.io once.
func TestAgePolicy_GemLookupIsShared(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		fmt.Fprintf(w, `[{"number":"3.1.0","platform":"ruby","created_at":%q}]`,
			time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano))
	}))
	defer srv.Close()
	store := &fakeAgeStore{policies: map[string]audit.AgePolicy{
		manifest.TypeRubygems: {Ecosystem: manifest.TypeRubygems, MinAgeSeconds: 86400, Action: ActionBlock},
	}}
	ctx := ShareLookups(context.Background())
	for range 2 {
		ck := NewAgeChecker(store)
		ck.RubygemsBase = srv.URL
		if r := ck.Check(ctx, &manifest.PackageManifest{Name: "rack", Type: manifest.TypeRubygems},
			&manifest.VersionEntry{Version: "3.1.0"}); r.Action != ActionBlock {
			t.Fatalf("1h-old gem under a 1d policy blocks; got %+v", r)
		}
	}
	if hits != 1 {
		t.Errorf("versions API read %d times, want 1", hits)
	}
}

// A Maven version is dated by its POM's Last-Modified, read with a HEAD at the
// repository path the coordinate names. A POM answered with no such header is
// not dated, and neither is one the repository does not hold: both warn, as an
// unknown crate version does.
func TestAgePolicy_MavenDatedFromPOMLastModified(t *testing.T) {
	now := time.Now()
	stamp := func(d time.Duration) string { return now.Add(-d).UTC().Format(http.TimeFormat) }
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/org/apache/logging/log4j/log4j-core/2.24.3/log4j-core-2.24.3.pom":
			w.Header().Set("Last-Modified", stamp(30*24*time.Hour))
		case "/org/apache/logging/log4j/log4j-core/2.25.0/log4j-core-2.25.0.pom":
			w.Header().Set("Last-Modified", stamp(2*time.Hour))
		case "/org/apache/logging/log4j/log4j-core/2.25.1/log4j-core-2.25.1.pom":
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	store := &fakeAgeStore{policies: map[string]audit.AgePolicy{
		manifest.TypeMaven: {Ecosystem: manifest.TypeMaven, MinAgeSeconds: int64((7 * 24 * time.Hour).Seconds()), Action: ActionBlock},
	}}
	for _, tc := range []struct {
		name, version string
		action        string
		reason        string
	}{
		{"org.apache.logging.log4j:log4j-core", "2.24.3", ActionPass, ""},
		{"org.apache.logging.log4j:log4j-core", "2.25.0", ActionBlock, "org.apache.logging.log4j:log4j-core@2.25.0 is 2h old"},
		{"org.apache.logging.log4j:log4j-core", "2.25.1", ActionWarn, "no Last-Modified"},
		{"org.apache.logging.log4j:log4j-core", "9.9.9", ActionWarn, "HTTP 404"},
		{"log4j-core", "2.24.3", ActionWarn, "names no POM"},
		{"org.apache..log4j:log4j-core", "2.24.3", ActionWarn, "names no POM"},
	} {
		ck := NewAgeChecker(store)
		ck.MavenBases = []string{srv.URL}
		ck.HTTP = srv.Client()
		r := ck.Check(context.Background(),
			&manifest.PackageManifest{Name: tc.name, Type: manifest.TypeMaven},
			&manifest.VersionEntry{Version: tc.version})
		if r.Action != tc.action || !strings.Contains(r.Reason, tc.reason) {
			t.Errorf("%s@%s: got %s %q, want %s containing %q", tc.name, tc.version, r.Action, r.Reason, tc.action, tc.reason)
		}
	}
	for _, s := range seen {
		if !strings.HasPrefix(s, "HEAD /org/apache/logging/log4j/log4j-core/") {
			t.Errorf("a POM is read with HEAD at its repository path; got %q", s)
		}
	}
}

// The POM is dated by the repository /maven/ would serve it from: a 404 passes
// to the next, the first 200 ends the walk, and a failure ahead of a 404 is
// the reason reported.
func TestAgePolicy_MavenDatedAcrossUpstreamsInOrder(t *testing.T) {
	const pom = "/com/example/plugin/1.0/plugin-1.0.pom"
	repo := func(status int, modified time.Duration) (*httptest.Server, *int) {
		hits := new(int)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != pom {
				http.NotFound(w, r)
				return
			}
			*hits++
			if status == http.StatusOK {
				w.Header().Set("Last-Modified", time.Now().Add(-modified).UTC().Format(http.TimeFormat))
			}
			w.WriteHeader(status)
		}))
		t.Cleanup(srv.Close)
		return srv, hits
	}
	store := &fakeAgeStore{policies: map[string]audit.AgePolicy{
		manifest.TypeMaven: {Ecosystem: manifest.TypeMaven, MinAgeSeconds: 86400, Action: ActionBlock},
	}}
	check := func(bases ...string) Result {
		ck := NewAgeChecker(store)
		ck.MavenBases = bases
		return ck.Check(context.Background(), &manifest.PackageManifest{Name: "com.example:plugin", Type: manifest.TypeMaven},
			&manifest.VersionEntry{Version: "1.0"})
	}

	missing, _ := repo(http.StatusNotFound, 0)
	fresh, freshHits := repo(http.StatusOK, time.Hour)
	old, oldHits := repo(http.StatusOK, 30*24*time.Hour)
	if r := check(missing.URL, fresh.URL, old.URL); r.Action != ActionBlock || *freshHits != 1 || *oldHits != 0 {
		t.Errorf("404 then a 1h-old POM: %+v, asked second %d third %d; want a block from the second alone", r, *freshHits, *oldHits)
	}
	down, _ := repo(http.StatusBadGateway, 0)
	if r := check(down.URL, missing.URL); r.Action != ActionWarn || !strings.Contains(r.Reason, "HTTP 502") {
		t.Errorf("502 then 404: %+v; want the 502 reported", r)
	}
}

// Two checks of one Maven version under one ShareLookups context read its POM
// once, as two checks of one crate version read crates.io once.
func TestAgePolicy_MavenLookupIsShared(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.Header().Set("Last-Modified", time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat))
	}))
	defer srv.Close()
	store := &fakeAgeStore{policies: map[string]audit.AgePolicy{
		manifest.TypeMaven: {Ecosystem: manifest.TypeMaven, MinAgeSeconds: 86400, Action: ActionBlock},
	}}
	ctx := ShareLookups(context.Background())
	for range 2 {
		ck := NewAgeChecker(store)
		ck.MavenBases = []string{srv.URL}
		if r := ck.Check(ctx, &manifest.PackageManifest{Name: "com.google.guava:guava", Type: manifest.TypeMaven},
			&manifest.VersionEntry{Version: "33.4.0-jre"}); r.Action != ActionBlock {
			t.Fatalf("1h-old artifact under a 1d policy blocks; got %+v", r)
		}
	}
	if hits != 1 {
		t.Errorf("POM read %d times, want 1", hits)
	}
}

// A Composer version is dated by the time Packagist's p2 metadata lists for
// it. The document is minified, so a version carrying no time key inherits
// the one before it and "__unset" removes it; a branch is read from
// ~dev.json; a version is found with or without its leading "v".
func TestAgePolicy_ComposerDatedFromPackagistMetadata(t *testing.T) {
	now := time.Now()
	stamp := func(d time.Duration) string { return now.Add(-d).UTC().Format(time.RFC3339) }
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/p2/firebase/php-jwt.json":
			fmt.Fprintf(w, `{"minified":"composer/2.0","packages":{"firebase/php-jwt":[
				{"name":"firebase/php-jwt","version":"v7.0.1","time":%q},
				{"version":"v7.0.0","time":%q},
				{"version":"v6.11.1"},
				{"version":"v6.11.0","time":"__unset"}
			]}}`, stamp(2*time.Hour), stamp(30*24*time.Hour))
		case "/p2/firebase/php-jwt~dev.json":
			fmt.Fprintf(w, `{"minified":"composer/2.0","packages":{"firebase/php-jwt":[
				{"name":"firebase/php-jwt","version":"dev-main","time":%q}
			]}}`, stamp(time.Hour))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	store := &fakeAgeStore{policies: map[string]audit.AgePolicy{
		manifest.TypeComposer: {Ecosystem: manifest.TypeComposer, MinAgeSeconds: int64((7 * 24 * time.Hour).Seconds()), Action: ActionBlock},
	}}
	for _, tc := range []struct {
		version string
		action  string
		reason  string
	}{
		{"v7.0.1", ActionBlock, "firebase/php-jwt@v7.0.1 is 2h old"},
		{"7.0.1", ActionBlock, "firebase/php-jwt@7.0.1 is 2h old"},
		{"v7.0.0", ActionPass, ""},
		{"6.11.1", ActionPass, ""},
		{"v6.11.0", ActionWarn, "lists firebase/php-jwt v6.11.0 with no readable time"},
		{"v5.0.0", ActionWarn, "does not list firebase/php-jwt v5.0.0"},
		{"dev-main", ActionBlock, "firebase/php-jwt@dev-main is 1h old"},
	} {
		ck := NewAgeChecker(store)
		ck.ComposerBase = srv.URL
		ck.HTTP = srv.Client()
		r := ck.Check(context.Background(),
			&manifest.PackageManifest{Name: "firebase/php-jwt", Type: manifest.TypeComposer},
			&manifest.VersionEntry{Version: tc.version})
		if r.Action != tc.action || !strings.Contains(r.Reason, tc.reason) {
			t.Errorf("%s: got %s %q, want %s containing %q", tc.version, r.Action, r.Reason, tc.action, tc.reason)
		}
	}
	for _, p := range paths {
		if p != "/p2/firebase/php-jwt.json" && p != "/p2/firebase/php-jwt~dev.json" {
			t.Errorf("packagist metadata path, got %q", p)
		}
	}
}

// Two checks of one Composer version under one ShareLookups context read the
// p2 document once, as two checks of one gem version read the versions API
// once.
func TestAgePolicy_ComposerLookupIsShared(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		fmt.Fprintf(w, `{"packages":{"monolog/monolog":[{"version":"3.8.0","time":%q}]}}`,
			time.Now().Add(-time.Hour).UTC().Format(time.RFC3339))
	}))
	defer srv.Close()
	store := &fakeAgeStore{policies: map[string]audit.AgePolicy{
		manifest.TypeComposer: {Ecosystem: manifest.TypeComposer, MinAgeSeconds: 86400, Action: ActionBlock},
	}}
	ctx := ShareLookups(context.Background())
	for range 2 {
		ck := NewAgeChecker(store)
		ck.ComposerBase = srv.URL
		if r := ck.Check(ctx, &manifest.PackageManifest{Name: "monolog/monolog", Type: manifest.TypeComposer},
			&manifest.VersionEntry{Version: "3.8.0"}); r.Action != ActionBlock {
			t.Fatalf("1h-old version under a 1d policy blocks; got %+v", r)
		}
	}
	if hits != 1 {
		t.Errorf("p2 metadata read %d times, want 1", hits)
	}
}

// An rpm package is dated by the time /rpm/ read from its repository's
// primary and recorded on the entry, build or file, never by a lookup. A
// package one day old under a seven-day minimum is refused naming which time
// dated it; one that primary dated by neither warns rather than passing.
func TestAgePolicy_RpmDatedFromPrimary(t *testing.T) {
	now := time.Now()
	store := &fakeAgeStore{policies: map[string]audit.AgePolicy{
		manifest.TypeRpm: {Ecosystem: manifest.TypeRpm, MinAgeSeconds: int64((7 * 24 * time.Hour).Seconds()), Action: ActionBlock},
	}}
	dated := func(age time.Duration, by string) *manifest.VersionEntry {
		return &manifest.VersionEntry{Version: "1:3.0.7-27.el9", PublishedAt: now.Add(-age).UTC().Format(time.RFC3339),
			Metadata: map[string]string{RpmDatedByKey: by}}
	}
	for _, tc := range []struct {
		label  string
		ve     *manifest.VersionEntry
		action string
		reason string
	}{
		{"one day by build", dated(24*time.Hour, RpmDatedByBuild), ActionBlock, "openssl@1:3.0.7-27.el9 is 1d old, policy requires 7d (dated by the build time primary gives the package)"},
		{"one day by file", dated(24*time.Hour, RpmDatedByFile), ActionBlock, "(dated by the file time primary gives the package: its build time is 0)"},
		{"thirty days by build", dated(30*24*time.Hour, RpmDatedByBuild), ActionPass, "dated by the build time"},
		{"undated", &manifest.VersionEntry{Version: "1:3.0.7-27.el9"}, ActionWarn, "carries neither"},
		{"a time with no source", &manifest.VersionEntry{Version: "1:3.0.7-27.el9", PublishedAt: now.UTC().Format(time.RFC3339)}, ActionWarn, "carries neither"},
	} {
		r := NewAgeChecker(store).Check(t.Context(), &manifest.PackageManifest{Name: "openssl", Type: manifest.TypeRpm}, tc.ve)
		if r.Action != tc.action || !strings.Contains(r.Reason, tc.reason) {
			t.Errorf("%s: got %s %q, want %s containing %q", tc.label, r.Action, r.Reason, tc.action, tc.reason)
		}
	}
	if slices.Contains(LookupDatedEcosystems(), manifest.TypeRpm) {
		t.Error("rpm is dated as /rpm/ serves it, and no lookup by name and version can record a time for it")
	}
}

func TestAgeEcosystems_MatchesDispatch(t *testing.T) {
	want := []string{manifest.TypeCargo, manifest.TypeComposer, manifest.TypeGomod, manifest.TypeMaven, manifest.TypeNpm, manifest.TypeOCI, manifest.TypePypi, manifest.TypeRpm, manifest.TypeRubygems}
	got := AgeEcosystems()
	if len(got) != len(want) {
		t.Fatalf("AgeEcosystems() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("AgeEcosystems() = %v, want %v", got, want)
		}
	}
	// An ecosystem `policy age set` refuses must also be one publishedAt
	// cannot date, or the refusal and the gate disagree.
	_, err := (&AgeChecker{}).PublishedAt(context.Background(), manifest.TypeApt, "bash", "5.2")
	if err == nil || !strings.Contains(err.Error(), "no upstream timestamp source") {
		t.Errorf("apt has no timestamp source; got err=%v", err)
	}
}

// B75 R8: an entry pinning nothing cannot be dated, and the gate used to try
// anyway: https://pypi.org/pypi/<dist>/*/json 404s, so cataloging 146
// distributions warned 146 times against entries that were correct, which reads
// as an import that half failed. Every ecosystem the gate dates, because the
// URL composition that makes "*" unanswerable is the same in all four.
func TestAgePolicyPassesAnEntryThatPinsNothing(t *testing.T) {
	reached := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		http.NotFound(w, nil)
	}))
	defer srv.Close()

	for _, eco := range AgeEcosystems() {
		for _, version := range []string{"", "*", manifest.ConstraintAny, " * "} {
			store := &fakeAgeStore{policies: map[string]audit.AgePolicy{
				eco: {Ecosystem: eco, MinAgeSeconds: int64((7 * 24 * time.Hour).Seconds()), Action: ActionBlock},
			}}
			ck := NewAgeChecker(store)
			ck.NpmRegistry, ck.PypiBase, ck.GoProxy, ck.CratesBase, ck.RubygemsBase, ck.MavenBases = srv.URL, srv.URL, srv.URL, srv.URL, srv.URL, []string{srv.URL}
			ck.ComposerBase = srv.URL

			r := ck.Check(context.Background(),
				&manifest.PackageManifest{Name: "thing", Type: eco},
				&manifest.VersionEntry{Version: version})
			if r.Action != ActionPass {
				t.Errorf("%s version %q: action = %q, want pass — nothing here can be dated: %+v", eco, version, r.Action, r)
			}
			if strings.Contains(r.Reason, "unavailable") {
				t.Errorf("%s version %q: warned about an upstream it should never have asked: %s", eco, version, r.Reason)
			}
		}
	}
	if reached {
		t.Error("the gate queried an upstream for a version that pins nothing")
	}
}
