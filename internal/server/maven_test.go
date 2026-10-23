package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

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
	s.cfg.MavenUpstream = up.ts.URL + "/maven2"
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
			manifest.MavenPath{GroupID: "org.example.core", ArtifactID: "widget", Companion: "md5", Metadata: true}},
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
		"org/example/core/widget/1.2.0/widget-1.2.0.exe", // not an artifact extension
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

func mavenDiscoveryRows(t *testing.T, s *Server) []audit.DiscoveryRow {
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
		if total >= 3 {
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
	s.cfg.MavenUpstream = strings.TrimSuffix(silent.url, "/simple/colorama/")
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
