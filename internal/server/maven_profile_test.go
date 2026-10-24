package server

import (
	"crypto/md5"  //nolint:gosec // G501: the repository layout's own checksum.
	"crypto/sha1" //nolint:gosec // G505: the repository layout's own checksum.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"net/http"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// mavenProfileMetadata is widget's artifact metadata as Maven Central writes
// it: versions in deploy order, latest naming the SNAPSHOT deployed last and
// release the last release.
const mavenProfileMetadata = `<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>org.example.core</groupId>
  <artifactId>widget</artifactId>
  <versioning>
    <latest>1.3.0-SNAPSHOT</latest>
    <release>1.3.0</release>
    <versions>
      <version>1.1.0</version>
      <version>1.2.0</version>
      <version>1.3.0</version>
      <version>1.3.0-SNAPSHOT</version>
    </versions>
    <lastUpdated>20261001120000</lastUpdated>
  </versioning>
</metadata>
`

func mavenProfileServer(t *testing.T) (*Server, *recordingUpstream) {
	t.Helper()
	s, up := mavenServer(t)
	up.route(mavenWidgetDir+"maven-metadata.xml", mavenProfileMetadata)
	up.route("/maven2/org/other/thing/maven-metadata.xml", "<metadata><versioning><versions><version>1.0</version></versions></versioning></metadata>")
	return s, up
}

// metadataVersions reads the <version> list back out of a served document.
func metadataVersions(body string) []string {
	block := mavenVersionsBlock.FindString(body)
	var out []string
	for _, m := range mavenVersionElement.FindAllStringSubmatch(block, -1) {
		out = append(out, m[1])
	}
	return out
}

func metadataField(body, tag string) string {
	_, rest, ok := strings.Cut(body, "<"+tag+">")
	if !ok {
		return ""
	}
	v, _, _ := strings.Cut(rest, "</"+tag+">")
	return v
}

// assertMetadataChecksums fetches every checksum companion and compares it
// with the document the same host was handed, which is the comparison Maven
// and Gradle make.
func assertMetadataChecksums(t *testing.T, f *profileFixture, path, served string) {
	t.Helper()
	for ext, h := range map[string]func() hash.Hash{"md5": md5.New, "sha1": sha1.New, "sha256": sha256.New, "sha512": sha512.New} {
		sum := h()
		sum.Write([]byte(served))
		want := hex.EncodeToString(sum.Sum(nil))
		if status, got := f.get(t, path+"."+ext); status != http.StatusOK || got != want {
			t.Errorf("GET %s.%s = %d %q, want the %s of the filtered document %q", path, ext, status, got, ext, want)
		}
	}
}

const mavenWidgetMetadataPath = "/maven/org/example/core/widget/maven-metadata.xml"

func TestMavenClosedProfileAtBlock(t *testing.T) {
	s, up := mavenProfileServer(t)
	f := bindProfile(t, s, "ci", "ci01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeMaven, audit.VersionPinned, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{Type: manifest.TypeMaven, Name: mavenWidgetName, Version: "1.2.0"}})

	t.Run("an unlisted artifact is refused", func(t *testing.T) {
		if status, body := f.get(t, "/maven/org/other/thing/1.0/thing-1.0.jar"); status != http.StatusForbidden || !strings.Contains(body, "membership") {
			t.Errorf("thing-1.0.jar = %d, want a 403 naming membership: %s", status, body)
		}
		if n := upstreamSaw(up, "thing-1.0.jar"); n != 0 {
			t.Errorf("the refused artifact reached the upstream %d times", n)
		}
		for _, row := range waitForDecision(t, s, audit.DecisionDenied, 1) {
			if row.PatternHint != "bodega profile add ci maven org.other:thing" {
				t.Errorf("the denied row's pattern_hint = %q, want the command that closes it", row.PatternHint)
			}
		}
	})

	t.Run("a listed artifact is served at its pin", func(t *testing.T) {
		if status, body := f.get(t, "/maven/org/example/core/widget/1.2.0/widget-1.2.0.jar"); status != http.StatusOK || body != "widget jar 1.2.0" {
			t.Errorf("the pinned widget jar answered %d: %q", status, body)
		}
		if status, _ := f.get(t, "/maven/org/example/core/widget/1.3.0/widget-1.3.0.jar"); status != http.StatusForbidden {
			t.Errorf("widget 1.3.0, past the pin, answered %d, want 403", status)
		}
	})

	t.Run("metadata answers 404 for an excluded artifact", func(t *testing.T) {
		for _, p := range []string{"/maven/org/other/thing/maven-metadata.xml", "/maven/org/other/thing/maven-metadata.xml.sha1"} {
			if status, body := f.get(t, p); status != http.StatusNotFound {
				t.Errorf("GET %s = %d, want 404: %s", p, status, body)
			}
		}
	})

	t.Run("metadata lists only the pin, with matching checksums", func(t *testing.T) {
		status, body := f.get(t, mavenWidgetMetadataPath)
		if status != http.StatusOK {
			t.Fatalf("widget metadata = %d: %s", status, body)
		}
		if got := strings.Join(metadataVersions(body), ","); got != "1.2.0" {
			t.Errorf("metadata lists %q, want only the pinned 1.2.0:\n%s", got, body)
		}
		if metadataField(body, "latest") != "1.2.0" || metadataField(body, "release") != "1.2.0" {
			t.Errorf("latest/release were not recomputed from what remains:\n%s", body)
		}
		if !strings.Contains(body, "<lastUpdated>20261001120000</lastUpdated>") || !strings.Contains(body, "<groupId>org.example.core</groupId>") {
			t.Errorf("the filter rewrote elements it does not rule on:\n%s", body)
		}
		assertMetadataChecksums(t, f, mavenWidgetMetadataPath, body)
		if status, _ := f.get(t, mavenWidgetMetadataPath+".asc"); status != http.StatusNotFound {
			t.Errorf("the upstream signature of the unfiltered metadata answered %d, want 404", status)
		}
	})

	t.Run("the cache holds the upstream document", func(t *testing.T) {
		key := manifest.MavenKey("org/example/core/widget/maven-metadata.xml")
		if got := storedObject(t, s, manifest.TypeMaven, key); got != mavenProfileMetadata {
			t.Errorf("the cached metadata is a filtered document:\n%s", got)
		}
		if _, hdr := getHeaderWithToken(t, s, f.token, mavenWidgetMetadataPath); hdr.Get("Cache-Control") != cacheNoStore {
			t.Errorf("filtered metadata Cache-Control = %q, want %q", hdr.Get("Cache-Control"), cacheNoStore)
		}
		if _, body := getWithToken(t, s, "", mavenWidgetMetadataPath); body != mavenProfileMetadata {
			t.Errorf("an unidentified request was filtered:\n%s", body)
		}
	})
}

// A groupId-wide entry admits every artifact of its groupId and none of a
// parent or nested groupId, and an entry naming one artifact of that groupId
// still sets its own version rule.
func TestMavenGroupWideEntry(t *testing.T) {
	s, _ := mavenProfileServer(t)
	f := bindProfile(t, s, "ci", "ci01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeMaven, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{Type: manifest.TypeMaven, Name: "org.other:*"}})

	if status, body := f.get(t, "/maven/org/other/thing/1.0/thing-1.0.jar"); status != http.StatusOK || body != "thing jar" {
		t.Errorf("an artifact under the groupId-wide entry answered %d: %q", status, body)
	}
	if status, _ := f.get(t, "/maven/org/example/native/2.0/native-2.0-linux-x86_64.jar"); status != http.StatusForbidden {
		t.Errorf("org.example:native, outside org.other:*, answered %d, want 403", status)
	}

	writeProfile(t, s, "pinned", []audit.ProfileTypeRule{closedRule(manifest.TypeMaven, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{
			{Type: manifest.TypeMaven, Name: "org.example.core:*"},
			{Type: manifest.TypeMaven, Name: mavenWidgetName, Constraint: manifest.ConstraintExact, Version: "1.1.0"},
		})
	bindProfileTo(t, s, "pinned", "ci01")
	if status, _ := f.get(t, "/maven/org/example/core/widget/1.2.0/widget-1.2.0.jar"); status != http.StatusForbidden {
		t.Errorf("widget 1.2.0 answered %d; its own exact entry should override the floating groupId-wide one", status)
	}
	if got := metadataVersions(func() string { _, b := f.get(t, mavenWidgetMetadataPath); return b }()); strings.Join(got, ",") != "1.1.0" {
		t.Errorf("metadata under the overriding entry lists %v, want [1.1.0]", got)
	}
}

func TestMavenWarnServesAndRecordsTheReach(t *testing.T) {
	s, _ := mavenProfileServer(t)
	f := bindProfile(t, s, "ci", "ci01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypeMaven, audit.VersionFloating, audit.ExpansionWarn)},
		[]audit.ProfileEntry{{Type: manifest.TypeMaven, Name: mavenWidgetName}})

	if status, body := f.get(t, "/maven/org/other/thing/1.0/thing-1.0.jar"); status != http.StatusOK || body != "thing jar" {
		t.Fatalf("warn refused an unlisted artifact: %d %q", status, body)
	}
	rows := waitForDecision(t, s, audit.DecisionDenied, 1)
	if rows[0].PkgName != "org.other:thing" || rows[0].PatternHint != "bodega profile add ci maven org.other:thing" {
		t.Errorf("the reach row = %s with hint %q", rows[0].PkgName, rows[0].PatternHint)
	}
	if _, body := f.get(t, "/maven/org/other/thing/maven-metadata.xml"); !strings.Contains(body, "<version>1.0</version>") {
		t.Errorf("warn filtered the metadata of an artifact it permits by expansion:\n%s", body)
	}
}

// A pin inside an open, floating type holds one artifact and nothing else.
func TestMavenPinnedVersion(t *testing.T) {
	s, up := mavenProfileServer(t)
	f := bindProfile(t, s, "ci", "ci01",
		[]audit.ProfileTypeRule{{Type: manifest.TypeMaven, Membership: audit.MembershipOpen, VersionDefault: audit.VersionFloating}},
		[]audit.ProfileEntry{{Type: manifest.TypeMaven, Name: mavenWidgetName, Constraint: manifest.ConstraintExact, Version: "1.1.0", Reason: "1.2 drops Java 11"}})

	if status, body := f.get(t, "/maven/org/example/core/widget/1.1.0/widget-1.1.0.jar"); status != http.StatusOK || body != "widget jar 1.1.0" {
		t.Errorf("the pinned version answered %d: %q", status, body)
	}
	status, body := f.get(t, "/maven/org/example/core/widget/1.2.0/widget-1.2.0.jar")
	if status != http.StatusForbidden || !strings.Contains(body, "1.1.0") {
		t.Errorf("widget 1.2.0 = %d, want a 403 naming the pin: %s", status, body)
	}
	if n := upstreamSaw(up, "widget-1.2.0.jar"); n != 0 {
		t.Errorf("the refused version reached the upstream %d times", n)
	}

	_, meta := f.get(t, mavenWidgetMetadataPath)
	if got := strings.Join(metadataVersions(meta), ","); got != "1.1.0" {
		t.Errorf("metadata lists %q, want [1.1.0]:\n%s", got, meta)
	}
	assertMetadataChecksums(t, f, mavenWidgetMetadataPath, meta)

	if status, body := f.get(t, "/maven/org/other/thing/1.0/thing-1.0.jar"); status != http.StatusOK || body != "thing jar" {
		t.Errorf("an unpinned artifact in the open type answered %d: %q", status, body)
	}
}

func TestFilterMavenMetadata(t *testing.T) {
	t.Parallel()
	only := func(vs ...string) func(string) bool {
		return func(v string) bool {
			for _, w := range vs {
				if v == w {
					return true
				}
			}
			return false
		}
	}
	if got := filterMavenMetadata([]byte(mavenProfileMetadata), nil); string(got) != mavenProfileMetadata {
		t.Errorf("a nil predicate changed the document:\n%s", got)
	}

	got := string(filterMavenMetadata([]byte(mavenProfileMetadata), only("1.1.0", "1.3.0-SNAPSHOT")))
	if v := strings.Join(metadataVersions(got), ","); v != "1.1.0,1.3.0-SNAPSHOT" {
		t.Errorf("versions = %q", v)
	}
	if metadataField(got, "latest") != "1.3.0-SNAPSHOT" || metadataField(got, "release") != "1.1.0" {
		t.Errorf("latest is the last version left and release the last non-SNAPSHOT:\n%s", got)
	}
	if strings.Contains(got, "\n\n") {
		t.Errorf("dropped versions left blank lines:\n%s", got)
	}

	none := string(filterMavenMetadata([]byte(mavenProfileMetadata), only()))
	if strings.Contains(none, "<latest>") || strings.Contains(none, "<release>") || len(metadataVersions(none)) != 0 {
		t.Errorf("with every version refused, latest and release must go with them:\n%s", none)
	}

	inline := `<metadata><versioning><release>2.0</release><versions><version>1.0</version><version>2.0</version></versions></versioning></metadata>`
	if got := string(filterMavenMetadata([]byte(inline), only("1.0"))); got != `<metadata><versioning><release>1.0</release><versions><version>1.0</version></versions></versioning></metadata>` {
		t.Errorf("one-line metadata = %s", got)
	}

	unlisted := `<metadata><versioning><latest>2.0</latest><release>1.0</release></versioning></metadata>`
	if got := string(filterMavenMetadata([]byte(unlisted), only("1.0"))); got != `<metadata><versioning><release>1.0</release></versioning></metadata>` {
		t.Errorf("with no versions list, only a refused latest/release is dropped: %s", got)
	}
}
