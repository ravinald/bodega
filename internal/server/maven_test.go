package server

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // G505: the checksum Maven compares, recomputed to check the one served.
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

const (
	mavenWidgetDir  = "/maven2/org/example/core/widget/"
	mavenNativeDir  = "/maven2/org/example/native/"
	mavenWidgetName = "org.example.core:widget"
)

// mavenUpstream is a repository in Maven Central's layout: org.example.core:widget
// with a jar, pom, Gradle module and checksums, org.example:native whose jar
// carries a classifier, artifact metadata, and a deployed SNAPSHOT.
func mavenUpstream(t *testing.T, s *Server) *recordingUpstream {
	t.Helper()
	up := newRecordingUpstream(t)
	for p, body := range map[string]string{
		mavenWidgetDir + "1.2.0/widget-1.2.0.jar":                            "widget jar 1.2.0",
		mavenWidgetDir + "1.2.0/widget-1.2.0.jar.sha1":                       "widget jar sha1",
		mavenWidgetDir + "1.2.0/widget-1.2.0.pom":                            "<project>widget 1.2.0</project>",
		mavenWidgetDir + "1.2.0/widget-1.2.0.module":                         `{"formatVersion":"1.1"}`,
		mavenWidgetDir + "1.1.0/widget-1.1.0.jar":                            "widget jar 1.1.0",
		mavenWidgetDir + "1.3.0/widget-1.3.0.jar":                            "widget jar 1.3.0",
		mavenWidgetDir + "maven-metadata.xml":                                "<metadata>v1</metadata>",
		mavenWidgetDir + "maven-metadata.xml.sha1":                           "metadata sha1 v1",
		mavenWidgetDir + "1.3.0-SNAPSHOT/widget-1.3.0-20261001.120000-1.jar": "snapshot build 1",
		mavenWidgetDir + "1.3.0-SNAPSHOT/maven-metadata.xml":                 "<metadata>snapshot v1</metadata>",
		mavenNativeDir + "2.0/native-2.0-linux-x86_64.jar":                   "native linux jar",
		"/maven2/org/other/thing/1.0/thing-1.0.jar":                          "thing jar",
	} {
		up.route(p, body)
	}
	s.cfg.MavenUpstreams = []string{up.ts.URL + "/maven2"}
	return up
}

func mavenServer(t *testing.T) (*Server, *recordingUpstream) {
	t.Helper()
	s := proxyingServer(t)
	return s, mavenUpstream(t, s)
}

func getMaven(t *testing.T, s *Server, p string) (int, string, http.Header) {
	t.Helper()
	rec := doRequest(s, http.MethodGet, "/maven/"+p, nil)
	return rec.Code, rec.Body.String(), rec.Header()
}

func upstreamSaw(up *recordingUpstream, suffix string) int {
	n := 0
	for _, p := range up.paths() {
		if strings.HasSuffix(p, suffix) {
			n++
		}
	}
	return n
}

func TestMavenPathIdentity(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path string
		want manifest.MavenPath
	}{
		{"org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar",
			manifest.MavenPath{GroupID: "org.apache.commons", ArtifactID: "commons-lang3", Version: "3.14.0", Extension: "jar"}},
		{"com/google/guava/guava/33.0.0-jre/guava-33.0.0-jre.module",
			manifest.MavenPath{GroupID: "com.google.guava", ArtifactID: "guava", Version: "33.0.0-jre", Extension: "module"}},
		{"org/example/native/2.0/native-2.0-linux-x86_64.jar.sha256",
			manifest.MavenPath{GroupID: "org.example", ArtifactID: "native", Version: "2.0", Classifier: "linux-x86_64", Extension: "jar", Companion: "sha256"}},
		{"org/example/core/widget/1.2.0/widget-1.2.0.pom.asc",
			manifest.MavenPath{GroupID: "org.example.core", ArtifactID: "widget", Version: "1.2.0", Extension: "pom", Companion: "asc"}},
		{"junit/junit/4.13.2/junit-4.13.2-sources.jar",
			manifest.MavenPath{GroupID: "junit", ArtifactID: "junit", Version: "4.13.2", Classifier: "sources", Extension: "jar"}},
		{"org/example/core/widget/maven-metadata.xml.md5",
			manifest.MavenPath{GroupID: "org.example.core", ArtifactID: "widget", Companion: "md5", Metadata: true, GroupLevelID: "org.example.core.widget"}},
		{"org/example/core/widget/1.3.0-SNAPSHOT/maven-metadata.xml",
			manifest.MavenPath{GroupID: "org.example.core", ArtifactID: "widget", Version: "1.3.0-SNAPSHOT", Metadata: true}},
		{"org/example/core/widget/1.3.0-SNAPSHOT/widget-1.3.0-20261001.120000-1.jar",
			manifest.MavenPath{GroupID: "org.example.core", ArtifactID: "widget", Version: "1.3.0-SNAPSHOT", Extension: "jar"}},
		{"org/example/core/widget/1.3.0-SNAPSHOT/widget-1.3.0-SNAPSHOT-tests.jar",
			manifest.MavenPath{GroupID: "org.example.core", ArtifactID: "widget", Version: "1.3.0-SNAPSHOT", Classifier: "tests", Extension: "jar"}},
	}
	for _, c := range cases {
		got, ok := manifest.ParseMavenPath(c.path)
		if !ok || got != c.want {
			t.Errorf("ParseMavenPath(%q) = %+v, %v; want %+v", c.path, got, ok, c.want)
		}
	}
	// Every companion of one version reads back as one identity.
	a, _ := manifest.ParseMavenPath("org/example/core/widget/1.2.0/widget-1.2.0.jar")
	b, _ := manifest.ParseMavenPath("org/example/core/widget/1.2.0/widget-1.2.0.pom.sha512")
	if a.Name() != mavenWidgetName || a.Name() != b.Name() || a.Version != b.Version {
		t.Errorf("jar and pom.sha512 identities = %s@%s, %s@%s; want one %s@1.2.0", a.Name(), a.Version, b.Name(), b.Version, mavenWidgetName)
	}
}

// A path outside the layout names no identity the allow-list could judge, so
// it is answered without the upstream ever seeing it.
func TestMavenMalformedPath404sOffline(t *testing.T) {
	s, up := mavenServer(t)
	for _, p := range []string{
		"widget/maven-metadata.xml",                      // no groupId
		"org/example/core/widget/1.2.0/other-1.2.0.jar",  // file names another artifact
		"org/example/core/widget/1.2.0/widget-1.2.1.jar", // file names another version
		"org/example/core/widget/1.2.0/widget-1.2.0",     // no extension
		"org/example/core/widget/1.2.0/widget-1.2.0.jar.sha1.sha1",
		"org/example/core/widget/1.3.0-SNAPSHOT/widget-1.3.0-latest.jar",
		"org/.hidden/widget/1.2.0/widget-1.2.0.jar",
		"org/example/core/widget/1.2.0/",
	} {
		if code, body, _ := getMaven(t, s, p); code != http.StatusNotFound {
			t.Errorf("GET /maven/%s = %d %q, want 404", p, code, body)
		}
	}
	if seen := up.paths(); len(seen) != 0 {
		t.Errorf("upstream saw %v; a malformed path must not leave bodega", seen)
	}
}

func TestMavenProxiesTheLayoutByteForByte(t *testing.T) {
	s, _ := mavenServer(t)
	for p, want := range map[string]string{
		"org/example/core/widget/1.2.0/widget-1.2.0.jar":      "widget jar 1.2.0",
		"org/example/core/widget/1.2.0/widget-1.2.0.jar.sha1": "widget jar sha1",
		"org/example/core/widget/1.2.0/widget-1.2.0.pom":      "<project>widget 1.2.0</project>",
		"org/example/core/widget/1.2.0/widget-1.2.0.module":   `{"formatVersion":"1.1"}`,
		"org/example/native/2.0/native-2.0-linux-x86_64.jar":  "native linux jar",
		"org/example/core/widget/maven-metadata.xml":          "<metadata>v1</metadata>",
	} {
		if code, body, _ := getMaven(t, s, p); code != http.StatusOK || body != want {
			t.Errorf("GET /maven/%s = %d %q, want 200 %q", p, code, body, want)
		}
	}
}

// A release version's files never change under their name, so a cached copy
// is served forever; metadata and SNAPSHOT files are redeployed in place and
// are refetched once metadata_ttl passes.
func TestMavenCachingClasses(t *testing.T) {
	s, up := mavenServer(t)
	const (
		jar      = "org/example/core/widget/1.2.0/widget-1.2.0.jar"
		sha1     = "org/example/core/widget/1.2.0/widget-1.2.0.jar.sha1"
		meta     = "org/example/core/widget/maven-metadata.xml"
		metaSha1 = "org/example/core/widget/maven-metadata.xml.sha1"
		snapJar  = "org/example/core/widget/1.3.0-SNAPSHOT/widget-1.3.0-20261001.120000-1.jar"
		snapMeta = "org/example/core/widget/1.3.0-SNAPSHOT/maven-metadata.xml"
	)
	first := map[string]string{}
	for _, p := range []string{jar, sha1, meta, metaSha1, snapJar, snapMeta} {
		code, body, h := getMaven(t, s, p)
		if code != http.StatusOK {
			t.Fatalf("GET /maven/%s = %d %q", p, code, body)
		}
		first[p] = body
		immutable := strings.Contains(h.Get("Cache-Control"), "immutable")
		if wantImmutable := p == jar || p == sha1; immutable != wantImmutable {
			t.Errorf("%s Cache-Control = %q, immutable want %v", p, h.Get("Cache-Control"), wantImmutable)
		}
		up.route("/maven2/"+p, "redeployed "+p)
	}

	// Within the TTL nothing is refetched.
	for p, want := range first {
		if _, body, _ := getMaven(t, s, p); body != want {
			t.Errorf("%s within metadata_ttl = %q, want the cached %q", p, body, want)
		}
	}

	s.cache.MetadataTTL = time.Nanosecond
	time.Sleep(time.Millisecond)
	for _, p := range []string{jar, sha1} {
		if _, body, _ := getMaven(t, s, p); body != first[p] {
			t.Errorf("release artifact %s refetched after metadata_ttl: %q, want the immutable %q", p, body, first[p])
		}
	}
	for _, p := range []string{meta, metaSha1, snapJar, snapMeta} {
		if _, body, _ := getMaven(t, s, p); body != "redeployed "+p {
			t.Errorf("mutable %s past metadata_ttl = %q, want the redeployed copy", p, body)
		}
	}
	if n := upstreamSaw(up, "/1.2.0/widget-1.2.0.jar"); n != 1 {
		t.Errorf("upstream fetched the release jar %d times, want 1", n)
	}
}

// The wrapper downloads the Maven distribution from the repository layout, so
// an extension outside jar and pom is served, cached as immutable and
// recorded under its coordinate like any other release file.
func TestMavenServesEveryReleaseExtension(t *testing.T) {
	s, up := mavenServer(t)
	const (
		dir     = "org/apache/maven/apache-maven/3.9.16/"
		tarball = dir + "apache-maven-3.9.16-bin.tar.gz"
		sha512  = tarball + ".sha512"
	)
	up.route("/maven2/"+tarball, "maven distribution")
	up.route("/maven2/"+sha512, "distribution sha512")
	for p, want := range map[string]string{tarball: "maven distribution", sha512: "distribution sha512"} {
		code, body, h := getMaven(t, s, p)
		if code != http.StatusOK || body != want {
			t.Fatalf("GET /maven/%s = %d %q, want 200 %q", p, code, body, want)
		}
		if cc := h.Get("Cache-Control"); !strings.Contains(cc, "immutable") {
			t.Errorf("%s Cache-Control = %q, want immutable", p, cc)
		}
		up.route("/maven2/"+p, "redeployed "+p)
	}
	s.cache.MetadataTTL = time.Nanosecond
	time.Sleep(time.Millisecond)
	if _, body, _ := getMaven(t, s, tarball); body != "maven distribution" {
		t.Errorf("release distribution refetched after metadata_ttl: %q, want the cached copy", body)
	}
	if n := upstreamSaw(up, "-bin.tar.gz"); n != 1 {
		t.Errorf("upstream fetched the distribution %d times, want 1", n)
	}
	rows := mavenDiscoveryRowsCounting(t, s, 3)
	if len(rows) != 1 || rows[0].PkgName != "org.apache.maven:apache-maven" || rows[0].PkgVersion != "3.9.16" {
		t.Errorf("discovery rows = %+v, want one for org.apache.maven:apache-maven@3.9.16", rows)
	}
}

func mavenDiscoveryRows(t *testing.T, s *Server) []audit.DiscoveryRow {
	t.Helper()
	return mavenDiscoveryRowsCounting(t, s, 3)
}

// mavenDiscoveryRowsCounting waits until the rows count at least want requests.
func mavenDiscoveryRowsCounting(t *testing.T, s *Server, want int64) []audit.DiscoveryRow {
	t.Helper()
	var rows []audit.DiscoveryRow
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		rows, err = s.auditDB.ListDiscovery(context.Background(), audit.DiscoveryFilter{RegistryType: manifest.TypeMaven})
		if err != nil {
			t.Fatalf("list discovery: %v", err)
		}
		var total int64
		for _, r := range rows {
			total += r.RequestCount
		}
		if total >= want {
			return rows
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("maven discovery rows after 3s: %+v", rows)
	return nil
}

// A resolver asks for the jar, its checksum and the POM of one version; all
// three are one identity and one row.
func TestMavenDiscoveryRowPerVersion(t *testing.T) {
	s, _ := mavenServer(t)
	for _, p := range []string{
		"org/example/core/widget/1.2.0/widget-1.2.0.jar",
		"org/example/core/widget/1.2.0/widget-1.2.0.jar.sha1",
		"org/example/core/widget/1.2.0/widget-1.2.0.pom",
	} {
		if code, body, _ := getMaven(t, s, p); code != http.StatusOK {
			t.Fatalf("GET /maven/%s = %d %q", p, code, body)
		}
	}
	rows := mavenDiscoveryRows(t, s)
	if len(rows) != 1 {
		t.Fatalf("discovery rows = %+v, want one for the version", rows)
	}
	r := rows[0]
	if r.PkgName != mavenWidgetName || r.PkgVersion != "1.2.0" || r.PatternHint != mavenWidgetName || r.RequestCount != 3 {
		t.Errorf("row = %+v, want %s@1.2.0 hinted as itself, counted 3 times", r, mavenWidgetName)
	}
}

func allowMaven(t *testing.T, s *Server, pattern string) {
	t.Helper()
	if err := s.auditDB.InsertPolicy(t.Context(), audit.PolicyInfo{ID: "m-" + pattern, RegistryType: manifest.TypeMaven,
		RuleKind: policy.KindPackage, Pattern: pattern}); err != nil {
		t.Fatalf("InsertPolicy: %v", err)
	}
	s.policy.Invalidate()
}

func TestMavenAllowListRefusal(t *testing.T) {
	s, up := mavenServer(t)
	allowMaven(t, s, mavenWidgetName)
	allowMaven(t, s, "org.example:*")

	for _, p := range []string{
		"org/example/core/widget/1.2.0/widget-1.2.0.jar",
		"org/example/native/2.0/native-2.0-linux-x86_64.jar",
	} {
		if code, body, _ := getMaven(t, s, p); code != http.StatusOK {
			t.Errorf("listed %s = %d %q, want 200", p, code, body)
		}
	}
	code, body, h := getMaven(t, s, "org/other/thing/1.0/thing-1.0.jar")
	if code != http.StatusForbidden {
		t.Fatalf("unlisted artifact = %d %q, want the allow-list's 403", code, body)
	}
	refusalIncident(t, h, checkAllowList)
	if !strings.Contains(body, "bodega policy add maven org.other:thing") {
		t.Errorf("refusal body %q does not name the rule that admits it", body)
	}
	if n := upstreamSaw(up, "thing-1.0.jar"); n != 0 {
		t.Errorf("upstream saw the refused artifact %d times", n)
	}
	// The exact rule admits every version of its artifact, not only the one
	// fetched first. Whether org.example:* stays out of org.example.core is
	// not observable here, because the exact rule admits widget either way.
	if code, _, _ := getMaven(t, s, "org/example/core/widget/1.1.0/widget-1.1.0.jar"); code != http.StatusOK {
		t.Errorf("exact rule stopped admitting %s: %d", mavenWidgetName, code)
	}
	if policy.KeysByName(manifest.TypeMaven) != true {
		t.Error("maven allow-list must rule on the coordinate, not the upstream URL")
	}
}

func TestMavenHiddenVersionRefused(t *testing.T) {
	s, up := mavenServer(t)
	addVersion(t, s, manifest.TypeMaven, mavenWidgetName, manifest.VersionEntry{Version: "1.2.0", Mode: manifest.ModeProxy, Hidden: true})
	addVersion(t, s, manifest.TypeMaven, mavenWidgetName, manifest.VersionEntry{Version: "1.1.0", Mode: manifest.ModeProxy})

	for _, p := range []string{
		"org/example/core/widget/1.2.0/widget-1.2.0.jar",
		"org/example/core/widget/1.2.0/widget-1.2.0.pom.sha1",
	} {
		code, body, h := getMaven(t, s, p)
		if code != http.StatusNotFound {
			t.Errorf("hidden %s = %d %q, want 404", p, code, body)
		}
		refusalIncident(t, h, checkHidden)
	}
	if code, _, _ := getMaven(t, s, "org/example/core/widget/1.1.0/widget-1.1.0.jar"); code != http.StatusOK {
		t.Errorf("visible version = %d, want 200", code)
	}
	if n := upstreamSaw(up, "/1.2.0/widget-1.2.0.jar") + upstreamSaw(up, "/1.2.0/widget-1.2.0.pom.sha1"); n != 0 {
		t.Errorf("upstream saw the hidden version %d times", n)
	}

	// Every version hidden hides the package, metadata included.
	pm, err := s.store.GetPackage(t.Context(), manifest.TypeMaven, mavenWidgetName)
	if err != nil || pm == nil {
		t.Fatalf("get %s: %v", mavenWidgetName, err)
	}
	for i := range pm.Versions {
		pm.Versions[i].Hidden = true
	}
	if err := s.store.SavePackage(t.Context(), pm); err != nil {
		t.Fatalf("save: %v", err)
	}
	if code, _, _ := getMaven(t, s, "org/example/core/widget/maven-metadata.xml"); code != http.StatusNotFound {
		t.Errorf("metadata of a hidden package = %d, want 404", code)
	}
}

func TestMavenVersionConstraintRefused(t *testing.T) {
	s, up := mavenServer(t)
	addVersion(t, s, manifest.TypeMaven, mavenWidgetName, manifest.VersionEntry{Version: "1.2.0",
		Mode: manifest.ModeProxy, VersionConstraint: manifest.ConstraintExact})

	code, body, h := getMaven(t, s, "org/example/core/widget/1.3.0/widget-1.3.0.jar")
	if code != http.StatusForbidden {
		t.Fatalf("version outside the constraint = %d %q, want 403", code, body)
	}
	refusalIncident(t, h, checkConstraint)
	if n := upstreamSaw(up, "widget-1.3.0.jar"); n != 0 {
		t.Errorf("upstream saw the refused version %d times", n)
	}
	if code, _, _ := getMaven(t, s, "org/example/core/widget/1.2.0/widget-1.2.0.jar"); code != http.StatusOK {
		t.Errorf("the pinned version = %d, want 200", code)
	}
	// Artifact-level metadata names no version, so the constraint does not
	// refuse it: Maven reads it to find the pinned version.
	if code, _, _ := getMaven(t, s, "org/example/core/widget/maven-metadata.xml"); code != http.StatusOK {
		t.Errorf("metadata under a constraint = %d, want 200", code)
	}
}

// B156 on the maven route: an upstream that accepts and never answers does not
// hold maven-metadata.xml past stale_grace when a cached copy exists.
func TestMavenMetadataStaleCopyDuringOutage(t *testing.T) {
	s, _ := mavenServer(t)
	const meta = "org/example/core/widget/maven-metadata.xml"
	if code, body, _ := getMaven(t, s, meta); code != http.StatusOK || body != "<metadata>v1</metadata>" {
		t.Fatalf("seed fetch = %d %q", code, body)
	}

	silent := newSilentUpstream(t)
	s.cfg.MavenUpstreams = []string{strings.TrimSuffix(silent.url, "/simple/colorama/")}
	s.cache = CacheConfig{Enabled: true, MetadataTTL: time.Nanosecond, StaleGrace: staleGraceForTest}
	time.Sleep(time.Millisecond)

	start := time.Now()
	code, body, _ := getMaven(t, s, meta)
	elapsed := time.Since(start)
	if code != http.StatusOK || body != "<metadata>v1</metadata>" {
		t.Fatalf("during the outage = %d %q, want the cached copy", code, body)
	}
	if elapsed > staleGraceForTest+time.Second {
		t.Errorf("stale copy took %s, want within stale_grace (%s) plus 1s", elapsed, staleGraceForTest)
	}
	waitFor(t, func() bool { return silent.hits.Load() == 1 })
	silent.release()
	waitFor(t, refreshIdle(s, manifest.MavenKey(meta)))
}

// A typed read token reaches Maven only when its type is maven: before the
// route had a scope type, read:npm read every artifact.
func TestMavenReadScope(t *testing.T) {
	s, _ := mavenServer(t)
	if s.pepper == "" {
		s.pepper = "maven-scope-pepper"
	}
	//nolint:gosec // G101: test fixtures, not credentials.
	const npmToken, mavenToken = "bodega_ak_readnpm", "bodega_ak_readmaven"
	for id, tok := range map[string]struct{ secret, scope string }{
		"npm":   {npmToken, "read:npm"},
		"maven": {mavenToken, "read:maven"},
	} {
		if err := s.auditDB.InsertScopedToken(t.Context(), id, id, audit.HashToken(tok.secret, s.pepper), "", tok.scope, "test", nil); err != nil {
			t.Fatal(err)
		}
	}
	const p = "/maven/org/example/core/widget/1.2.0/widget-1.2.0.jar"
	bearer := func(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }
	if rec := doRequest(s, http.MethodGet, p, bearer(npmToken)); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "read:maven") {
		t.Errorf("read:npm on a Maven artifact = %d %q, want 403 naming read:maven", rec.Code, rec.Body)
	}
	if rec := doRequest(s, http.MethodGet, p, bearer(mavenToken)); rec.Code != http.StatusOK {
		t.Errorf("read:maven on a Maven artifact = %d %q, want 200", rec.Code, rec.Body)
	}
}

// A served artifact writes the serve_fetch event every package route writes,
// under the same identity as its discovery row.
func TestMavenFetchWritesServeFetch(t *testing.T) {
	s, _ := mavenServer(t)
	if code, body, _ := getMaven(t, s, "org/example/core/widget/1.2.0/widget-1.2.0.pom"); code != http.StatusOK {
		t.Fatalf("GET pom = %d %q", code, body)
	}
	events := waitForServeFetch(t, s, 1)
	for _, ev := range events {
		if ev.PkgType == manifest.TypeMaven && ev.PkgName == mavenWidgetName && ev.PkgVersion == "1.2.0" {
			return
		}
	}
	t.Errorf("no serve_fetch event for maven %s at 1.2.0; events carry %v", mavenWidgetName, eventIdentities(events))
}

// gateMaven runs the proxy fill's real admission checks with the maven OSV
// gate blocking, answered from a database holding one advisory against
// org.example.core:widget releases before 1.2.0. The index filter is rebuilt
// so it reads the same database.
func gateMaven(t *testing.T, s *Server) {
	t.Helper()
	prev := fetchCheckers
	fetchCheckers = admit.VersionCheckers
	t.Cleanup(func() { fetchCheckers = prev })
	rec := map[string]any{
		"id": "GHSA-test-mvn1",
		"affected": []map[string]any{{
			"package": map[string]string{"name": mavenWidgetName, "ecosystem": "Maven"},
			"ranges": []map[string]any{{"type": "ECOSYSTEM",
				"events": []map[string]string{{"introduced": "0"}, {"fixed": "1.2.0"}}}},
		}},
	}
	export := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		f, _ := zw.Create("GHSA-test-mvn1.json")
		_ = json.NewEncoder(f).Encode(rec)
		_ = zw.Close()
		_, _ = w.Write(buf.Bytes())
	}))
	t.Cleanup(export.Close)
	s.cfg.OSVDBDir = t.TempDir()
	db := policy.NewOSVDatabase(s.cfg.OSVDBDir)
	db.ExportBase = export.URL
	if _, err := db.Sync(t.Context(), "Maven"); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if err := s.auditDB.SetOSVPolicy(t.Context(), audit.OSVPolicy{Ecosystem: manifest.TypeMaven, Action: policy.ActionBlock}); err != nil {
		t.Fatalf("set osv policy: %v", err)
	}
	s.indexFilter = policy.NewIndexFilter(s.auditDB, admit.OSVChecker(s.cfg, s.auditDB))
}

// A vulnerable version is refused at the artifact route before upstream is
// asked for it, for its jar and its POM alike, and the refusal names the
// advisory.
func TestMavenArtifactRefusedByOSV(t *testing.T) {
	s, up := mavenServer(t)
	gateMaven(t, s)
	for _, p := range []string{"widget-1.1.0.jar", "widget-1.1.0.pom"} {
		code, body, hdr := getMaven(t, s, "org/example/core/widget/1.1.0/"+p)
		if code != http.StatusForbidden {
			t.Fatalf("%s: status %d, want 403 (%s)", p, code, body)
		}
		refusalIncident(t, hdr, checkOSV)
		if !strings.Contains(body, "GHSA-test-mvn1") {
			t.Errorf("%s: refusal does not name the advisory:\n%s", p, body)
		}
		if n := upstreamSaw(up, "/1.1.0/"+p); n != 0 {
			t.Errorf("%s: upstream asked %d times for a refused artifact", p, n)
		}
	}
	if code, body, _ := getMaven(t, s, "org/example/core/widget/1.2.0/widget-1.2.0.jar"); code != http.StatusOK {
		t.Errorf("the fixed version: %d %s", code, body)
	}
}

// With the index filter on, the filter's own refusal answers the artifact
// route before the version gate does, and it still has to name the advisory.
// The age gate's "wait out the window" advice is wrong for an OSV block.
func TestMavenArtifactRefusedByOSVWithIndexFilter(t *testing.T) {
	s, up := mavenServer(t)
	gateMaven(t, s)
	if err := s.auditDB.SetIndexFilter(t.Context(), audit.IndexFilter{Ecosystem: manifest.TypeMaven, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"widget-1.1.0.jar", "widget-1.1.0.pom"} {
		code, body, _ := getMaven(t, s, "org/example/core/widget/1.1.0/"+p)
		if code != http.StatusForbidden {
			t.Fatalf("%s: status %d, want 403 (%s)", p, code, body)
		}
		if !strings.Contains(body, "GHSA-test-mvn1") {
			t.Errorf("%s: refusal does not name the advisory:\n%s", p, body)
		}
		if strings.Contains(body, "wait out the window") {
			t.Errorf("%s: OSV refusal gives the age gate's advice:\n%s", p, body)
		}
		if n := upstreamSaw(up, "/1.1.0/"+p); n != 0 {
			t.Errorf("%s: upstream asked %d times for a refused artifact", p, n)
		}
	}
}

// With the index filter on, the vulnerable version is absent from the
// artifact's maven-metadata.xml, and <latest> and <release> are recomputed
// when they named it. The checksum served beside the document is the one of
// the filtered bytes, which is what Maven and Gradle verify.
func TestMavenMetadataWithholdsOSVBlockedVersion(t *testing.T) {
	s, up := mavenServer(t)
	up.route(mavenWidgetDir+"maven-metadata.xml", `<metadata>
  <groupId>org.example.core</groupId>
  <artifactId>widget</artifactId>
  <versioning>
    <latest>1.1.0</latest>
    <release>1.1.0</release>
    <versions>
      <version>1.2.0</version>
      <version>1.1.0</version>
    </versions>
  </versioning>
</metadata>
`)
	gateMaven(t, s)
	if err := s.auditDB.SetIndexFilter(t.Context(), audit.IndexFilter{Ecosystem: manifest.TypeMaven, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	code, body, hdr := getMaven(t, s, "org/example/core/widget/maven-metadata.xml")
	if code != http.StatusOK {
		t.Fatalf("status %d (%s)", code, body)
	}
	if strings.Contains(body, "1.1.0") || !strings.Contains(body, "<version>1.2.0</version>") ||
		!strings.Contains(body, "<latest>1.2.0</latest>") || !strings.Contains(body, "<release>1.2.0</release>") {
		t.Errorf("filtered metadata:\n%s", body)
	}
	if got := hdr.Get(filteredHeader); got != "1; osv=1" {
		t.Errorf("%s = %q, want \"1; osv=1\"", filteredHeader, got)
	}
	if n := len(filterRows(t, s, manifest.TypeMaven, mavenWidgetName)); n != 1 {
		t.Errorf("index_filtered rows = %d, want 1", n)
	}
	sum := sha1.Sum([]byte(body)) //nolint:gosec // G401: see the import.
	if code, got, _ := getMaven(t, s, "org/example/core/widget/maven-metadata.xml.sha1"); code != http.StatusOK || got != hex.EncodeToString(sum[:]) {
		t.Errorf("metadata sha1 = %d %q, want the filtered document's %s", code, got, hex.EncodeToString(sum[:]))
	}

	if err := s.auditDB.SetIndexFilter(t.Context(), audit.IndexFilter{Ecosystem: manifest.TypeMaven, Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if _, body, _ := getMaven(t, s, "org/example/core/widget/maven-metadata.xml"); !strings.Contains(body, "<version>1.1.0</version>") {
		t.Errorf("the filter off serves the upstream's document; got\n%s", body)
	}
}

// The age gate dates a Maven artifact by its POM's Last-Modified at
// maven_upstream, the host the artifact is fetched from, and refuses one too
// new before fetching it.
func TestMavenArtifactRefusedByAge(t *testing.T) {
	s := proxyingServer(t)
	var mu sync.Mutex
	var seen []string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if r.URL.Path == "/maven2/org/example/core/widget/1.2.0/widget-1.2.0.pom" {
			w.Header().Set("Last-Modified", time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat))
			_, _ = w.Write([]byte("<project/>"))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(up.Close)
	s.cfg.MavenUpstreams = []string{up.URL + "/maven2"}
	gateMaven(t, s)
	if err := s.auditDB.SetAgePolicy(t.Context(), audit.AgePolicy{Ecosystem: manifest.TypeMaven, MinAgeSeconds: 86400, Action: policy.ActionBlock}); err != nil {
		t.Fatalf("set age policy: %v", err)
	}
	code, body, hdr := getMaven(t, s, "org/example/core/widget/1.2.0/widget-1.2.0.jar")
	if code != http.StatusForbidden {
		t.Fatalf("status %d, want 403 (%s)", code, body)
	}
	refusalIncident(t, hdr, checkAge)
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(seen, ",") != "HEAD /maven2/org/example/core/widget/1.2.0/widget-1.2.0.pom" {
		t.Errorf("upstream saw %v, want the one HEAD of the POM and no fetch", seen)
	}
}

// mavenPluginGroupMetadata is the groupId-level file Maven reads to resolve
// the prefix in `mvn dependency:tree`.
const mavenPluginGroupMetadata = `<metadata><plugins><plugin><name>Apache Maven Dependency Plugin</name>` +
	`<prefix>dependency</prefix><artifactId>maven-dependency-plugin</artifactId></plugin></plugins></metadata>`

const mavenPluginGroupPath = "org/apache/maven/plugins/maven-metadata.xml"

func mavenPluginGroupServer(t *testing.T) (*Server, *recordingUpstream) {
	t.Helper()
	s, up := mavenServer(t)
	up.route("/maven2/"+mavenPluginGroupPath, mavenPluginGroupMetadata)
	up.route("/maven2/"+mavenPluginGroupPath+".sha1", "plugin group sha1")
	up.route("/maven2/com/example/maven-metadata.xml", "<metadata><plugins/></metadata>")
	return s, up
}

// A groupId-level maven-metadata.xml is admitted on its group-level reading,
// which the artifact reading one directory up (org.apache.maven:plugins) would
// never be.
func TestMavenGroupLevelMetadataAllowList(t *testing.T) {
	for _, rule := range []string{"org.apache.maven.plugins:*", "org.apache.maven.plugins:maven-dependency-plugin"} {
		t.Run(rule, func(t *testing.T) {
			s, up := mavenPluginGroupServer(t)
			allowMaven(t, s, rule)
			if code, body, _ := getMaven(t, s, mavenPluginGroupPath); code != http.StatusOK || body != mavenPluginGroupMetadata {
				t.Errorf("plugin group metadata under %s = %d %q, want the upstream document", rule, code, body)
			}
			if code, body, _ := getMaven(t, s, mavenPluginGroupPath+".sha1"); code != http.StatusOK || body != "plugin group sha1" {
				t.Errorf("its .sha1 under %s = %d %q, want 200", rule, code, body)
			}

			code, body, h := getMaven(t, s, "com/example/maven-metadata.xml")
			if code != http.StatusForbidden {
				t.Fatalf("unrelated metadata = %d %q, want the allow-list's 403", code, body)
			}
			refusalIncident(t, h, checkAllowList)
			for _, want := range []string{"com/example/maven-metadata.xml", "com:example", "com.example", "bodega policy add maven com.example:*"} {
				if !strings.Contains(body, want) {
					t.Errorf("refusal %q does not name %q", body, want)
				}
			}
			if n := upstreamSaw(up, "/com/example/maven-metadata.xml"); n != 0 {
				t.Errorf("upstream saw the refused metadata %d times", n)
			}
		})
	}
}

// Metadata is recorded under the reading that names something real: the
// plugin group under <groupId>:*, never under the artifact one directory up,
// and a real artifact's metadata on that artifact's own row, never under a
// groupId made of its directories.
func TestMavenGroupLevelMetadataDiscoveryRow(t *testing.T) {
	s, _ := mavenPluginGroupServer(t)
	for _, p := range []string{mavenPluginGroupPath, mavenPluginGroupPath + ".sha1",
		"org/example/core/widget/1.2.0/widget-1.2.0.pom", "org/example/core/widget/1.2.0/widget-1.2.0.jar",
		"org/example/core/widget/maven-metadata.xml"} {
		if code, body, _ := getMaven(t, s, p); code != http.StatusOK {
			t.Fatalf("GET /maven/%s = %d %q", p, code, body)
		}
	}
	rows := mavenDiscoveryRowsCounting(t, s, 5)
	var widget int64
	for _, r := range rows {
		switch r.PkgName {
		case "org.apache.maven:plugins", "org.example.core.widget:*":
			t.Errorf("discovery recorded a reading nothing depends on: %+v", r)
		case "org.apache.maven.plugins:*":
			if r.PatternHint != "org.apache.maven.plugins:*" || r.RequestCount != 2 {
				t.Errorf("group row = %+v, want org.apache.maven.plugins:* hinted as itself, counted twice", r)
			}
		case mavenWidgetName:
			if r.PatternHint != mavenWidgetName {
				t.Errorf("artifact row = %+v, want hinted as %s", r, mavenWidgetName)
			}
			widget += r.RequestCount
		default:
			t.Errorf("unexpected discovery row %+v", r)
		}
	}
	if widget != 3 {
		t.Errorf("%s rows count %d requests, want the pom, the jar and the metadata: %+v", mavenWidgetName, widget, rows)
	}

	// A restarted process has seen no jar request, and the table answers.
	s.mavenArtifacts = mavenArtifactSet{}
	if code, body, _ := getMaven(t, s, "org/example/core/widget/maven-metadata.xml"); code != http.StatusOK {
		t.Fatalf("metadata after restart = %d %q", code, body)
	}
	for _, r := range mavenDiscoveryRowsCounting(t, s, 6) {
		if r.PkgName == "org.example.core.widget:*" {
			t.Errorf("metadata after restart recorded under the group reading: %+v", r)
		}
	}
}

// Under listed mode the artifact reading is the one a rule admits, so the
// metadata row names it and says allowed; the group reading matched no rule.
func TestMavenArtifactMetadataRowUnderListedMode(t *testing.T) {
	s, _ := mavenServer(t)
	allowMaven(t, s, mavenWidgetName)
	for _, p := range []string{"org/example/core/widget/maven-metadata.xml",
		"org/example/core/widget/maven-metadata.xml.sha1", "org/example/core/widget/1.2.0/widget-1.2.0.pom"} {
		if code, body, _ := getMaven(t, s, p); code != http.StatusOK {
			t.Fatalf("GET /maven/%s = %d %q", p, code, body)
		}
	}
	for _, r := range mavenDiscoveryRows(t, s) {
		if r.PkgName != mavenWidgetName || r.Decision != audit.DecisionAllowed {
			t.Errorf("row = %+v, want %s allowed", r, mavenWidgetName)
		}
	}
}

// A refused metadata path whose artifact a jar request named is refused,
// recorded and queued under that artifact, so approving it adds the rule that
// admits the jar too. With no such request it falls to the group reading.
func TestMavenMetadataRefusalNamesKnownArtifact(t *testing.T) {
	s, _ := mavenPluginGroupServer(t)
	allowMaven(t, s, "org.example:*")
	if code, _, _ := getMaven(t, s, "org/other/thing/1.0/thing-1.0.jar"); code != http.StatusForbidden {
		t.Fatalf("unlisted jar = %d, want 403", code)
	}
	code, body, _ := getMaven(t, s, "org/other/thing/maven-metadata.xml")
	if code != http.StatusForbidden {
		t.Fatalf("unlisted metadata = %d %q, want 403", code, body)
	}
	for _, want := range []string{"maven/org.other:thing", "org.other.thing"} {
		if !strings.Contains(body, want) {
			t.Errorf("refusal %q does not name %q", body, want)
		}
	}
	if code, _, _ := getMaven(t, s, "com/example/maven-metadata.xml"); code != http.StatusForbidden {
		t.Fatalf("unrelated metadata = %d, want 403", code)
	}

	queued, err := s.auditDB.ListQueue(t.Context(), audit.QueueFilter{State: audit.QueueOpen})
	if err != nil {
		t.Fatalf("ListQueue: %v", err)
	}
	patterns := map[string]bool{}
	for _, q := range queued {
		if q.PkgName != q.Pattern {
			t.Errorf("queue row %+v names %s but proposes %s", q, q.PkgName, q.Pattern)
		}
		patterns[q.Pattern] = true
	}
	if !patterns["org.other:thing"] || !patterns["com.example:*"] || patterns["org.other.thing:*"] || len(patterns) != 2 {
		t.Errorf("queued patterns = %v, want org.other:thing and com.example:*", patterns)
	}
	for _, r := range mavenDiscoveryRowsCounting(t, s, 3) {
		if r.PkgName == "org.other.thing:*" || r.PkgName == "com:example" {
			t.Errorf("discovery recorded a reading nothing depends on: %+v", r)
		}
	}
}

// orderedRepo is one entry of maven_upstreams for the ordering tests: it
// serves files, answers fail with a status of its own, and 404s the rest.
type orderedRepo struct {
	*recordingUpstream
	failMu sync.Mutex
	fail   map[string]int
}

func newOrderedRepo(t *testing.T, files map[string]string) *orderedRepo {
	t.Helper()
	o := &orderedRepo{recordingUpstream: &recordingUpstream{routes: map[string]string{}}, fail: map[string]int{}}
	o.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		o.seen = append(o.seen, r.URL.Path)
		body, ok := o.routes[r.URL.Path]
		o.mu.Unlock()
		o.failMu.Lock()
		status := o.fail[r.URL.Path]
		o.failMu.Unlock()
		switch {
		case status != 0:
			http.Error(w, "upstream fault", status)
		case !ok:
			http.NotFound(w, r)
		default:
			_, _ = w.Write([]byte(body))
		}
	}))
	t.Cleanup(o.ts.Close)
	for p, body := range files {
		o.route("/m2/"+p, body)
	}
	return o
}

func (o *orderedRepo) failWith(p string, status int) {
	o.failMu.Lock()
	defer o.failMu.Unlock()
	o.fail["/m2/"+p] = status
}

func (o *orderedRepo) asked(p string) int { return upstreamSaw(o.recordingUpstream, "/m2/"+p) }

func orderedMavenServer(t *testing.T, repos ...*orderedRepo) *Server {
	t.Helper()
	s := proxyingServer(t)
	s.cfg.MavenUpstreams = nil
	for _, r := range repos {
		s.cfg.MavenUpstreams = append(s.cfg.MavenUpstreams, r.ts.URL+"/m2")
	}
	return s
}

const (
	orderedJar  = "org/example/core/widget/1.2.0/widget-1.2.0.jar"
	orderedSha1 = orderedJar + ".sha1"
)

// The artifact only the second repository publishes is served from it and
// cached under the key a single repository would have used, so the next
// request asks neither.
func TestMavenUpstreamsFallThroughA404(t *testing.T) {
	first := newOrderedRepo(t, nil)
	second := newOrderedRepo(t, map[string]string{orderedJar: "second's jar"})
	s := orderedMavenServer(t, first, second)

	if code, body, _ := getMaven(t, s, orderedJar); code != http.StatusOK || body != "second's jar" {
		t.Fatalf("GET %s = %d %q, want 200 from the second repository", orderedJar, code, body)
	}
	if first.asked(orderedJar) != 1 || second.asked(orderedJar) != 1 {
		t.Errorf("asked first %d, second %d times; want each once", first.asked(orderedJar), second.asked(orderedJar))
	}
	st, err := s.typeStore(manifest.TypeMaven).Head(context.Background(), manifest.MavenKey(orderedJar))
	if err != nil || st == nil || !st.Exists {
		t.Fatalf("cache at %s = %+v, %v; want the served jar stored", manifest.MavenKey(orderedJar), st, err)
	}
	if code, body, _ := getMaven(t, s, orderedJar); code != http.StatusOK || body != "second's jar" {
		t.Errorf("second GET = %d %q, want the cached jar", code, body)
	}
	if first.asked(orderedJar) != 1 || second.asked(orderedJar) != 1 {
		t.Errorf("a cached jar reached upstream again: first %d, second %d", first.asked(orderedJar), second.asked(orderedJar))
	}
}

func TestMavenUpstreamsAll404Is404(t *testing.T) {
	first, second := newOrderedRepo(t, nil), newOrderedRepo(t, nil)
	s := orderedMavenServer(t, first, second)
	if code, body, _ := getMaven(t, s, orderedJar); code != http.StatusNotFound {
		t.Errorf("GET %s = %d %q, want 404", orderedJar, code, body)
	}
	if first.asked(orderedJar) != 1 || second.asked(orderedJar) != 1 {
		t.Errorf("asked first %d, second %d times; want both asked once", first.asked(orderedJar), second.asked(orderedJar))
	}
}

func TestMavenUpstreamsFirstAnswerEndsTheWalk(t *testing.T) {
	first := newOrderedRepo(t, map[string]string{orderedJar: "first's jar"})
	second := newOrderedRepo(t, map[string]string{orderedJar: "second's jar"})
	s := orderedMavenServer(t, first, second)
	if code, body, _ := getMaven(t, s, orderedJar); code != http.StatusOK || body != "first's jar" {
		t.Errorf("GET %s = %d %q, want 200 from the first repository", orderedJar, code, body)
	}
	if seen := second.paths(); len(seen) != 0 {
		t.Errorf("second repository saw %v; the first answered", seen)
	}
}

// The first repository fails the jar and publishes a checksum of other bytes;
// the second serves the jar. Its .sha1 has to come from the second, or the
// client's check of the jar it holds fails.
func TestMavenUpstreamsCompanionFollowsItsArtifact(t *testing.T) {
	first := newOrderedRepo(t, map[string]string{orderedJar: "first's jar", orderedSha1: "first's sha1"})
	first.failWith(orderedJar, http.StatusServiceUnavailable)
	second := newOrderedRepo(t, map[string]string{orderedJar: "second's jar", orderedSha1: "second's sha1"})
	s := orderedMavenServer(t, first, second)

	if code, body, _ := getMaven(t, s, orderedJar); code != http.StatusOK || body != "second's jar" {
		t.Fatalf("GET %s = %d %q, want 200 from the second repository", orderedJar, code, body)
	}
	if code, body, _ := getMaven(t, s, orderedSha1); code != http.StatusOK || body != "second's sha1" {
		t.Errorf("GET %s = %d %q, want the second repository's checksum", orderedSha1, code, body)
	}
	if n := first.asked(orderedSha1); n != 0 {
		t.Errorf("first repository asked for the companion %d times; it did not serve the jar", n)
	}
}

// A 5xx is the answer that tells the operator something, so a later 404 does
// not replace it.
func TestMavenUpstreamsFailureOutranksA404(t *testing.T) {
	first := newOrderedRepo(t, nil)
	first.failWith(orderedJar, http.StatusInternalServerError)
	second := newOrderedRepo(t, nil)
	s := orderedMavenServer(t, first, second)
	if code, body, _ := getMaven(t, s, orderedJar); code != http.StatusBadGateway {
		t.Errorf("GET %s = %d %q, want the 502 a failed single-repository fetch answers", orderedJar, code, body)
	}
	if second.asked(orderedJar) != 1 {
		t.Errorf("second repository asked %d times, want 1", second.asked(orderedJar))
	}
}
